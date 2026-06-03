module mcp.auth.client;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;

import mcp.protocol.errors;
import mcp.auth.oauth;

@safe:

/// A production OAuth 2.1 client for MCP: drives protected-resource and
/// authorization-server metadata discovery (RFC 9728 / RFC 8414), Dynamic Client
/// Registration (RFC 7591), and the token endpoint (authorization-code + PKCE,
/// client-credentials, refresh) with RFC 8707 resource indicators.
///
/// The interactive authorization-code redirect (opening a browser / running a
/// loopback listener) is supplied by the host application via an
/// `authorizeCallback`; everything else is handled here.
final class OAuthClient
{
	/// The canonical resource indicator (the MCP server URL). MANDATORY for the
	/// MCP authorization/token flows: per RFC 8707 the `resource` indicator MUST
	/// be sent on the authorization and token requests regardless of whether the
	/// authorization server advertises support, so `authorizationUrl`,
	/// `exchangeCode`, `refresh`, and `clientCredentials` reject an empty value.
	/// `useOAuth` sets this to the canonical MCP server URI automatically.
	string resource;
	/// The client's redirect URI for the auth-code flow.
	string redirectUri = "http://localhost:8765/callback";
	/// How to authenticate at the token endpoint.
	TokenEndpointAuthMethod authMethod = TokenEndpointAuthMethod.none;
	/// EC private key (PKCS#8 PEM) for `private_key_jwt` client assertions.
	string privateKeyPem;
	/// SEP-991: this client's OAuth Client ID Metadata Document URL — an
	/// HTTPS URL (with a path component) at which the client hosts its metadata
	/// document. When set and the authorization server advertises
	/// `client_id_metadata_document_supported`, this URL is used directly as the
	/// `client_id` (no Dynamic Client Registration needed).
	string clientIdMetadataUrl;

	/// Build the `client_assertion_type` + `client_assertion` form fields for
	/// `private_key_jwt` token-endpoint authentication (RFC 7523), or "".
	private string clientAssertionParams(string clientId, string audience) @safe
	{
		import std.uri : encodeComponent;
		import std.datetime.systime : Clock;
		import mcp.auth.jwt : makeClientAssertion, jwtBearerAssertionType;

		if (authMethod != TokenEndpointAuthMethod.privateKeyJwt || privateKeyPem.length == 0)
			return "";
		const now = () @trusted { return Clock.currTime().toUnixTime(); }();
		const jwt = makeClientAssertion(clientId, audience, privateKeyPem, now);
		return "&client_assertion_type=" ~ encodeComponent(
				jwtBearerAssertionType) ~ "&client_assertion=" ~ encodeComponent(jwt);
	}

	/// Discover the protected-resource metadata for an MCP endpoint, using the
	/// `resource_metadata` URL from a `WWW-Authenticate` header when present, else
	/// the RFC 9728 well-known URLs in order.
	ProtectedResourceMetadata discoverProtectedResource(string mcpEndpoint,
			string wwwAuthenticateHeader = "") @safe
	{
		string[] urls;
		if (wwwAuthenticateHeader.length)
		{
			const w = parseWwwAuthenticate(wwwAuthenticateHeader);
			// RFC 9728: the attacker-influenced resource_metadata URL from the
			// WWW-Authenticate challenge must be HTTPS (or loopback for dev), must
			// not target an internal/link-local address, and its origin MUST match
			// the MCP endpoint's origin before we fetch it.
			if (w.resourceMetadata.length && isSecureFetchUrl(w.resourceMetadata)
					&& originOf(w.resourceMetadata) == originOf(mcpEndpoint))
				urls ~= w.resourceMetadata;
		}
		urls ~= protectedResourceMetadataUrls(mcpEndpoint);

		foreach (u; urls)
		{
			Json j;
			if (tryGetJson(u, j))
				return ProtectedResourceMetadata.fromJson(j);
		}
		throw internalError("Could not discover protected-resource metadata");
	}

	/// Discover authorization-server metadata for an issuer, trying the RFC 8414
	/// and OpenID Connect Discovery well-known locations in order.
	///
	/// `enforceIssuerMatch` selects how a discovered metadata document's `issuer`
	/// is treated. On the modern RFC 8414 / RFC 9728 path the issuer is the value
	/// an RFC 9728 protected-resource-metadata document named as its authorization
	/// server, so the discovered document MUST self-assert that same issuer
	/// (RFC 8414 Section 3.3): a missing or mismatched `issuer` fails closed so the
	/// recorded issuer stays the AS's authenticated self-assertion that RFC 9207
	/// mix-up detection anchors on. On the 2025-03-26 backcompat path the issuer is
	/// merely the MCP server origin (no protected-resource-metadata document named
	/// the AS), so a document served from a sub-path may legitimately self-assert a
	/// different issuer; there the discovered value is accepted as-is and a missing
	/// one is synthesized from the requested issuer. `resolveIssuer`'s
	/// `fromProtectedResourceMetadata` out-parameter reports which path applies.
	AuthorizationServerMetadata discoverAuthServer(string issuer, bool enforceIssuerMatch = true) @safe
	{
		foreach (u; authServerMetadataCandidates(issuer))
		{
			Json j;
			if (tryGetJson(u, j))
				return bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
						issuer, enforceIssuerMatch);
		}
		// 2025-03-26 fallback: no metadata document — use default endpoints
		// derived from the issuer.
		import std.string : endsWith;

		auto base = issuer.endsWith("/") ? issuer[0 .. $ - 1] : issuer;
		AuthorizationServerMetadata m;
		m.issuer = issuer;
		m.authorizationEndpoint = base ~ "/authorize";
		m.tokenEndpoint = base ~ "/token";
		m.registrationEndpoint = base ~ "/register";
		return m;
	}

	/// Bind a discovered authorization-server metadata document to the requested
	/// issuer. When `enforceIssuerMatch` is set (the modern RFC 8414 / RFC 9728
	/// path) the document MUST self-assert an `issuer` equal to the requested one
	/// (RFC 8414 Section 3.3); a missing or mismatched value fails closed rather
	/// than being synthesized, keeping the recorded issuer the AS's authenticated
	/// self-assertion that RFC 9207 mix-up detection anchors on. On the lenient
	/// 2025-03-26 backcompat path a missing `issuer` is synthesized from the
	/// request and a sub-path document's own assertion is accepted as-is.
	private static AuthorizationServerMetadata bindDiscoveredIssuer(
			AuthorizationServerMetadata m, string issuer, bool enforceIssuerMatch) @safe
	{
		if (enforceIssuerMatch)
		{
			if (m.issuer.length == 0 || m.issuer != issuer)
				throw internalError("Authorization server metadata issuer mismatch");
		}
		else if (m.issuer.length == 0)
		{
			m.issuer = issuer;
		}
		return m;
	}

	/// Discover protected-resource metadata, falling back to treating the MCP
	/// server's origin as the issuer when no PRM document exists (the pre-RFC-9728
	/// 2025-03-26 behavior). Returns the issuer to use for AS discovery, and sets
	/// `fromProtectedResourceMetadata` to true when the issuer came from an RFC 9728
	/// protected-resource-metadata document (the modern path, for which the
	/// discovered AS document's issuer must match), or false for the 2025-03-26
	/// origin fallback (the lenient backcompat path).
	string resolveIssuer(string mcpEndpoint,
			out bool fromProtectedResourceMetadata, string wwwAuthenticateHeader = "") @safe
	{
		try
		{
			auto prm = discoverProtectedResource(mcpEndpoint, wwwAuthenticateHeader);
			if (prm.authorizationServers.length)
			{
				fromProtectedResourceMetadata = true;
				return prm.authorizationServers[0];
			}
		}
		catch (Exception)
		{
		}
		// Backcompat: no PRM -> the MCP server origin is the authorization server.
		fromProtectedResourceMetadata = false;
		return originOf(mcpEndpoint);
	}

	/// Convenience overload that discards the discovery-source signal.
	string resolveIssuer(string mcpEndpoint, string wwwAuthenticateHeader = "") @safe
	{
		bool fromPrm;
		return resolveIssuer(mcpEndpoint, fromPrm, wwwAuthenticateHeader);
	}

	private static string originOf(string url) @safe
	{
		import std.string : indexOf;

		const schemeEnd = url.indexOf("://");
		if (schemeEnd < 0)
			return url;
		const afterScheme = schemeEnd + 3;
		const slash = url[afterScheme .. $].indexOf('/');
		return (slash < 0) ? url : url[0 .. afterScheme + slash];
	}

	/// Register a client dynamically (RFC 7591) at the AS registration endpoint.
	RegisteredClient register(AuthorizationServerMetadata as_, string clientName,
			string scopeStr = "") @safe
	{
		if (as_.registrationEndpoint.length == 0)
			throw internalError("Authorization server does not support Dynamic Client Registration");
		ClientRegistration reg;
		reg.redirectUris = [redirectUri];
		reg.clientName = clientName;
		reg.scope_ = scopeStr;
		reg.tokenEndpointAuthMethod = cast(string) authMethod;
		auto resp = postJson(as_.registrationEndpoint, reg.toJson());
		return RegisteredClient.fromJson(resp);
	}

	/// Select the client-registration approach for an authorization server,
	/// per the spec priority order ("Client Registration Approaches"):
	/// pre-registration, then Client ID Metadata Documents (SEP-991), then
	/// Dynamic Client Registration, then prompting the user. `havePreRegistered`
	/// indicates the caller already holds a `client_id` for this AS.
	ClientRegistrationApproach registrationApproach(AuthorizationServerMetadata as_,
			bool havePreRegistered = false) @safe
	{
		return selectClientRegistrationApproach(as_, havePreRegistered, clientIdMetadataUrl);
	}

	/// Use this client's configured OAuth Client ID Metadata Document URL
	/// (SEP-991) as the `client_id` for the authorization and token requests.
	/// The returned `RegisteredClient` carries the HTTPS-URL `client_id` and no
	/// secret, so it can be passed to `authorizationUrl`, `exchangeCode`,
	/// `refresh`, etc. exactly like a registered or pre-registered client.
	///
	/// Throws when the authorization server does not advertise
	/// `client_id_metadata_document_supported`, or when no valid HTTPS-URL
	/// `client_id` (with a path component) is configured.
	RegisteredClient clientIdMetadataClient(AuthorizationServerMetadata as_) @safe
	{
		if (!as_.clientIdMetadataDocumentSupported)
			throw internalError(
					"Authorization server does not support OAuth Client ID Metadata Documents");
		if (!isValidClientIdMetadataUrl(clientIdMetadataUrl))
			throw internalError("clientIdMetadataUrl must be an https URL with a path component");
		return RegisteredClient(clientIdMetadataUrl, "");
	}

	/// Build the OAuth Client ID Metadata Document (SEP-991) this client should
	/// host at its `clientIdMetadataUrl`. The document's `client_id` is the URL
	/// itself and `redirect_uris` is the configured `redirectUri`.
	ClientIdMetadataDocument clientIdMetadataDocument(string clientName = "", string scopeStr = "") @safe
	{
		ClientIdMetadataDocument d;
		d.clientId = clientIdMetadataUrl;
		d.clientName = clientName;
		d.redirectUris = [redirectUri];
		d.tokenEndpointAuthMethod = cast(string) authMethod;
		d.scope_ = scopeStr;
		return d;
	}

	/// Exchange an authorization code for tokens (PKCE auth-code grant).
	TokenSet exchangeCode(AuthorizationServerMetadata as_,
			RegisteredClient client, string code, string codeVerifier) @safe
	{
		requirePkceSupport(as_);
		requireResource();
		const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
		auto form = buildAuthCodeTokenForm(code, redirectUri, codeVerifier,
				client.clientId, resource, post ? client.clientSecret : "") ~ clientAssertionParams(
				client.clientId, as_.issuer.length ? as_.issuer : as_.tokenEndpoint);
		return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
	}

	/// Obtain a token via the client-credentials grant (service-to-service).
	TokenSet clientCredentials(AuthorizationServerMetadata as_,
			RegisteredClient client, string scopeStr = "") @safe
	{
		requireResource();
		const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
		auto form = buildClientCredentialsForm(client.clientId, scopeStr,
				resource, post ? client.clientSecret : "") ~ clientAssertionParams(client.clientId,
				as_.issuer.length ? as_.issuer : as_.tokenEndpoint);
		return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
	}

	/// RFC 8693 token exchange: swap a subject token (e.g. an IdP id_token) for
	/// a requested token type (e.g. an ID-JAG assertion) at `tokenEndpoint`.
	TokenSet tokenExchange(string tokenEndpoint, string subjectToken,
			string subjectTokenType, string requestedTokenType, string audience, string clientId) @safe
	{
		auto form = buildTokenExchangeForm(subjectToken, subjectTokenType,
				requestedTokenType, audience, resource, clientId);
		return TokenSet.fromJson(postForm(tokenEndpoint, form, RegisteredClient(clientId, "")));
	}

	/// RFC 7523 JWT-bearer grant: exchange an assertion JWT for an access token.
	TokenSet jwtBearerGrant(AuthorizationServerMetadata as_,
			RegisteredClient client, string assertion, string scopeStr) @safe
	{
		auto form = buildJwtBearerForm(assertion, scopeStr, resource, client.clientId);
		return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
	}

	/// Refresh an access token.
	TokenSet refresh(AuthorizationServerMetadata as_, RegisteredClient client, string refreshToken) @safe
	{
		requireResource();
		auto form = buildRefreshTokenForm(refreshToken, client.clientId, resource);
		return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
	}

	/// Build the authorization-request URL the host should open (browser/loopback).
	string authorizationUrl(AuthorizationServerMetadata as_,
			RegisteredClient client, PkcePair pkce, string scopeStr, string state) @safe
	{
		requirePkceSupport(as_);
		requireResource();
		// SSRF guard at the source: the authorization endpoint comes from discovered
		// AS metadata; reject a plaintext-http (non-loopback) or internal/link-local
		// endpoint before constructing a URL any consumer might fetch.
		requireSecureUrl(as_.authorizationEndpoint);
		return buildAuthorizationUrl(as_.authorizationEndpoint, client.clientId,
				redirectUri, pkce.challenge, scopeStr, resource, state);
	}

	/// Enforce that the RFC 8707 `resource` indicator (the canonical MCP server
	/// URI) is set before an MCP authorization/token request. The MCP
	/// authorization spec requires the `resource` parameter be sent regardless of
	/// whether the AS advertises support, so a missing value is a configuration
	/// error rather than something to silently omit.
	private void requireResource() @safe
	{
		if (resource.length == 0)
			throw invalidRequest(
					"OAuthClient.resource (RFC 8707 resource indicator) must be set to the canonical "
					~ "MCP server URI before authorization/token requests");
	}

	/// Enforce the MCP authorization MUST around PKCE support. Per the spec
	/// ("Authorization Code Protection"): MCP clients MUST verify PKCE support
	/// before proceeding with authorization, relying on authorization-server
	/// metadata. "If `code_challenge_methods_supported` is absent, the
	/// authorization server does not support PKCE and MCP clients MUST refuse to
	/// proceed" (and the OIDC variant mandates the same). Therefore, when the AS
	/// metadata was discovered from a real RFC 8414 / OpenID Connect Discovery
	/// document (`metadataDocumentDiscovered`), the client refuses unless that
	/// document advertises S256 — covering both the absent-field case and the
	/// present-but-non-S256 case.
	///
	/// The sole exception is the 2025-03-26 endpoint-fallback flow, where NO
	/// metadata document was discovered at all and `discoverAuthServer`
	/// synthesizes default endpoints; there `metadataDocumentDiscovered` is false
	/// and absence is not a signal that PKCE is unsupported, so the client
	/// proceeds and uses S256 regardless. This guards the public authorization
	/// path (`authorizationUrl`/`exchangeCode`) against both proceeding past a
	/// discovered document that lacks PKCE support and silently downgrading to an
	/// explicitly non-S256 method.
	private static void requirePkceSupport(AuthorizationServerMetadata as_) @safe
	{
		if (as_.metadataDocumentDiscovered && !as_.supportsS256())
			throw invalidRequest("Authorization server metadata does not advertise S256 PKCE "
					~ "support (code_challenge_methods_supported); MCP clients MUST refuse to proceed");
		if (as_.codeChallengeMethodsSupported.length && !as_.supportsS256())
			throw invalidRequest("Authorization server advertises PKCE methods without S256 "
					~ "(code_challenge_methods_supported); MCP clients MUST refuse to proceed");
	}

	/// POST a minimal request to the MCP endpoint (optionally with a bearer
	/// token); if it returns 401, return the `WWW-Authenticate` header value
	/// (else empty). Used to trigger discovery and detect step-up challenges.
	string probeUnauthorized(string mcpEndpoint, string bearer = "") @safe
	{
		string www;
		() @trusted {
			try
			{
				requestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
					req.method = HTTPMethod.POST;
					req.contentType = "application/json";
					req.headers["Accept"] = "application/json, text/event-stream";
					if (bearer.length)
						req.headers["Authorization"] = "Bearer " ~ bearer;
					req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`);
				}, (scope HTTPClientResponse res) {
					if (res.statusCode == 401 || res.statusCode == 403)
						www = res.headers.get("WWW-Authenticate", "");
					res.dropBody();
				});
			}
			catch (Exception)
			{
			}
		}();
		return www;
	}

	/// POST a `tools/list` request with a bearer token; if the server challenges
	/// with 401/403 (insufficient scope), return the `WWW-Authenticate` header.
	/// Used to detect step-up authorization requirements.
	string probeOperation(string mcpEndpoint, string bearer) @safe
	{
		string www;
		() @trusted {
			try
			{
				requestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
					req.method = HTTPMethod.POST;
					req.contentType = "application/json";
					req.headers["Accept"] = "application/json, text/event-stream";
					if (bearer.length)
						req.headers["Authorization"] = "Bearer " ~ bearer;
					req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"step-up","arguments":{}}}`);
				}, (scope HTTPClientResponse res) {
					if (res.statusCode == 401 || res.statusCode == 403)
						www = res.headers.get("WWW-Authenticate", "");
					res.dropBody();
				});
			}
			catch (Exception)
			{
			}
		}();
		return www;
	}

	/// GET an authorization URL (without following redirects) and extract the
	/// `code` query parameter from the `Location` response header.
	///
	/// When `expectedState` is non-empty, the `state` parameter returned in the
	/// redirect is verified against it (MCP authorization "Open Redirection":
	/// "MCP clients SHOULD use and verify state parameters in the authorization
	/// code flow and discard any results that do not include or have a mismatch
	/// with the original state"). The authorization code is NOT returned (empty
	/// string) when the returned state is missing or does not match. Passing an
	/// empty `expectedState` (the default) skips state verification.
	string authorizeAndGetCode(string authzUrl, string expectedState = "") @safe
	{
		// SSRF guard: never issue the outbound GET to a plaintext-http (non-loopback)
		// or internal/link-local authorization endpoint.
		requireSecureUrl(authzUrl);
		string code, state;
		() @trusted {
			requestHTTP(authzUrl, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.GET;
			}, (scope HTTPClientResponse res) {
				const loc = res.headers.get("Location", "");
				code = extractQueryParam(loc, "code");
				state = extractQueryParam(loc, "state");
				res.dropBody();
			});
		}();
		if (!validateAuthorizationResponseState(state, expectedState))
			return "";
		return code;
	}

	/// GET an authorization URL (without following redirects), extract the
	/// `code` from the redirect `Location` header, and validate the RFC 9207
	/// `iss` authorization-response parameter against the selected authorization
	/// server's recorded issuer (mix-up attack protection required by the MCP
	/// 2025-11-25 / draft authorization spec). Throws when `iss` is missing while
	/// `authorization_response_iss_parameter_supported` is true, or when it does
	/// not match the recorded issuer (simple string comparison, no
	/// normalization). The authorization code is NOT returned on rejection.
	/// When `expectedState` is non-empty, the redirect `state` parameter is also
	/// verified against it and the authorization code is discarded (a throw)
	/// when it is missing or mismatched, per the MCP "Open Redirection" guidance
	/// ("MCP clients SHOULD use and verify state parameters ... and discard any
	/// results that do not include or have a mismatch with the original state").
	/// Passing an empty `expectedState` (the default) skips state verification.
	string authorizeAndGetCode(AuthorizationServerMetadata as_, string authzUrl,
			string expectedState = "") @safe
	{
		// SSRF guard: never issue the outbound GET to a plaintext-http (non-loopback)
		// or internal/link-local authorization endpoint.
		requireSecureUrl(authzUrl);
		string code, iss, state;
		() @trusted {
			requestHTTP(authzUrl, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.GET;
			}, (scope HTTPClientResponse res) {
				const loc = res.headers.get("Location", "");
				code = extractQueryParam(loc, "code");
				iss = extractQueryParam(loc, "iss");
				state = extractQueryParam(loc, "state");
				res.dropBody();
			});
		}();
		if (!validateAuthorizationResponseIss(iss, as_.issuer,
				as_.authorizationResponseIssParameterSupported))
			throw invalidRequest(
					"Authorization response failed RFC 9207 'iss' validation (possible mix-up attack)");
		if (!validateAuthorizationResponseState(state, expectedState))
			throw invalidRequest(
					"Authorization response failed 'state' validation (missing or mismatched state)");
		return code;
	}

	// --- HTTP helpers --------------------------------------------------------

	private bool tryGetJson(string url, out Json result) @safe
	{
		// Never fetch a discovery URL that is not HTTPS (or loopback for dev) or
		// that targets an internal/link-local address (SSRF mitigation).
		if (!isSecureFetchUrl(url))
			return false;
		bool ok;
		Json parsed;
		() @trusted {
			try
			{
				requestHTTP(url, (scope HTTPClientRequest req) {
					req.method = HTTPMethod.GET;
					req.headers["Accept"] = "application/json";
				}, (scope HTTPClientResponse res) {
					auto body = res.bodyReader.readAllUTF8();
					if (res.statusCode / 100 == 2 && body.length)
					{
						parsed = parseJsonString(body);
						ok = true;
					}
				});
			}
			catch (Exception)
				ok = false;
		}();
		result = parsed;
		return ok;
	}

	private Json postJson(string url, Json payload) @safe
	{
		requireSecureUrl(url);
		Json result;
		() @trusted {
			requestHTTP(url, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.contentType = "application/json";
				req.headers["Accept"] = "application/json";
				req.writeBody(cast(const(ubyte)[]) payload.toString());
			}, (scope HTTPClientResponse res) {
				auto body = res.bodyReader.readAllUTF8();
				result = body.length ? parseJsonString(body) : Json.emptyObject;
			});
		}();
		return result;
	}

	private Json postForm(string url, string form, RegisteredClient client) @safe
	{
		requireSecureUrl(url);
		Json result;
		const useBasic = authMethod == TokenEndpointAuthMethod.clientSecretBasic
			&& client.clientSecret.length;
		const auth = useBasic ? basicAuthHeader(client.clientId, client.clientSecret) : "";
		() @trusted {
			requestHTTP(url, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.contentType = "application/x-www-form-urlencoded";
				req.headers["Accept"] = "application/json";
				if (auth.length)
					req.headers["Authorization"] = auth;
				req.writeBody(cast(const(ubyte)[]) form);
			}, (scope HTTPClientResponse res) {
				auto body = res.bodyReader.readAllUTF8();
				result = body.length ? parseJsonString(body) : Json.emptyObject;
			});
		}();
		return result;
	}
}

unittest  // CIMD client uses the configured HTTPS-URL client_id when advertised
{
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	auto rc = c.clientIdMetadataClient(as_);
	assert(rc.clientId == "https://app.example.com/oauth/client.json");
	assert(rc.clientSecret.length == 0);
}

unittest  // CIMD client refuses when the AS does not advertise support
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
	AuthorizationServerMetadata as_; // clientIdMetadataDocumentSupported == false
	assertThrown(c.clientIdMetadataClient(as_));
}

unittest  // CIMD client refuses an invalid (non-https / pathless) client_id URL
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com"; // no path component
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	assertThrown(c.clientIdMetadataClient(as_));
}

unittest  // registrationApproach prefers CIMD over DCR when advertised
{
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	as_.registrationEndpoint = "https://as.example.com/register";
	assert(c.registrationApproach(as_) == ClientRegistrationApproach.clientIdMetadataDocument);
	// Pre-registration still wins when the caller already has a client_id.
	assert(c.registrationApproach(as_, true) == ClientRegistrationApproach.preRegistered);
}

unittest  // the CIMD authorization URL carries the URL client_id verbatim
{
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
	c.redirectUri = "http://localhost:8765/callback";
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto rc = c.clientIdMetadataClient(as_);
	auto pkce = makePkce(new ubyte[32]);
	auto url = c.authorizationUrl(as_, rc, pkce, "mcp:read", "state1");
	import std.algorithm : canFind;
	import std.uri : encodeComponent;

	assert(url.canFind("client_id=" ~ encodeComponent("https://app.example.com/oauth/client.json")));
}

unittest  // clientIdMetadataDocument builds a hostable document for the URL
{
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
	c.redirectUri = "http://localhost:8765/callback";
	auto d = c.clientIdMetadataDocument("dlang-mcp", "mcp:read");
	assert(d.clientId == "https://app.example.com/oauth/client.json");
	assert(d.clientName == "dlang-mcp");
	assert(d.redirectUris == ["http://localhost:8765/callback"]);
	assert(d.tokenEndpointAuthMethod == "none");
	auto j = d.toJson();
	assert(j["client_id"].get!string == "https://app.example.com/oauth/client.json");
}

unittest  // authorizationUrl proceeds when the AS advertises no PKCE methods (absent)
{
	import std.algorithm : canFind;

	// 2025-03-26 endpoint-fallback: an older AS advertises no
	// code_challenge_methods_supported at all. Absence is NOT a signal that PKCE
	// is unsupported, so the client proceeds and uses S256 regardless.
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	// No code_challenge_methods_supported advertised.
	auto pkce = makePkce(new ubyte[32]);
	auto url = c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st");
	assert(url.canFind("code_challenge_method=S256"));
}

unittest  // authorizationUrl refuses when only non-S256 PKCE methods are advertised
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["plain"]; // S256 not offered
	auto pkce = makePkce(new ubyte[32]);
	assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // authorizationUrl proceeds when the AS advertises S256 PKCE support
{
	import std.algorithm : canFind;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto pkce = makePkce(new ubyte[32]);
	auto url = c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st");
	assert(url.canFind("code_challenge_method=S256"));
}

unittest  // exchangeCode refuses when the AS advertises non-S256 PKCE methods only
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	as_.codeChallengeMethodsSupported = ["plain"]; // S256 not offered -> MUST refuse.
	assertThrown(c.exchangeCode(as_, RegisteredClient("cid", ""), "code", "verifier"));
}

unittest  // discoverAuthServer no-metadata fallback proceeds (absence allows S256)
{
	import std.algorithm : canFind;

	// The 2025-03-26 fallback fabricates default endpoints and advertises no
	// PKCE methods. Absence must NOT block the public authorization path; the
	// client proceeds and uses S256, matching the endpoint-fallback scenario.
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	// codeChallengeMethodsSupported left empty, mirroring the fallback.
	assert(!as_.supportsS256());
	auto pkce = makePkce(new ubyte[32]);
	auto url = c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "", "");
	assert(url.canFind("code_challenge_method=S256"));
}

unittest  // modern path: discovered AS document whose issuer matches is accepted
{
	import vibe.data.json : parseJsonString;

	auto j = parseJsonString(`{"issuer":"https://as.example.com",`
			~ `"authorization_endpoint":"https://as.example.com/authorize",`
			~ `"code_challenge_methods_supported":["S256"]}`);
	auto m = OAuthClient.bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
			"https://as.example.com", true);
	assert(m.issuer == "https://as.example.com");
}

unittest  // modern path: discovered AS document whose issuer mismatches is rejected
{
	import std.exception : assertThrown;
	import vibe.data.json : parseJsonString;

	// RFC 8414 Section 3.3: the document asserts a different issuer than the one
	// it was fetched for, so on the modern RFC 9728 path it MUST be rejected
	// rather than trusted as the RFC 9207 mix-up anchor.
	auto j = parseJsonString(`{"issuer":"https://evil.example.com",`
			~ `"authorization_endpoint":"https://as.example.com/authorize"}`);
	assertThrown(OAuthClient.bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
			"https://as.example.com", true));
}

unittest  // modern path: discovered AS document with no issuer fails closed (no synthesis)
{
	import std.exception : assertThrown;
	import vibe.data.json : parseJsonString;

	// On the modern path a fetched document missing `issuer` must not have one
	// synthesized from the request; the AS must self-assert its issuer.
	auto j = parseJsonString(`{"authorization_endpoint":"https://as.example.com/authorize"}`);
	assertThrown(OAuthClient.bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
			"https://as.example.com", true));
}

unittest  // 2025-03-26 backcompat path: a sub-path issuer mismatch is tolerated
{
	import vibe.data.json : parseJsonString;

	// No protected-resource-metadata document named this AS; the requested issuer
	// is only the MCP server origin, while the document served from a sub-path
	// legitimately self-asserts a prefixed issuer. The lenient path keeps the
	// document's own assertion rather than failing closed.
	auto j = parseJsonString(`{"issuer":"https://mcp.example.com/oauth",`
			~ `"authorization_endpoint":"https://mcp.example.com/oauth/authorize"}`);
	auto m = OAuthClient.bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
			"https://mcp.example.com", false);
	assert(m.issuer == "https://mcp.example.com/oauth");
}

unittest  // 2025-03-26 backcompat path: a missing issuer is synthesized from the request
{
	import vibe.data.json : parseJsonString;

	auto j = parseJsonString(`{"authorization_endpoint":"https://mcp.example.com/authorize"}`);
	auto m = OAuthClient.bindDiscoveredIssuer(AuthorizationServerMetadata.fromJson(j),
			"https://mcp.example.com", false);
	assert(m.issuer == "https://mcp.example.com");
}

unittest  // discovered AS document missing code_challenge_methods_supported -> refuse (authorizationUrl)
{
	import std.exception : assertThrown;

	// 2025-11-25 "Authorization Code Protection": when a real RFC 8414 / OIDC
	// metadata document was discovered but omits code_challenge_methods_supported,
	// the AS does not support PKCE and MCP clients MUST refuse to proceed.
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.metadataDocumentDiscovered = true; // came from a discovered document
	// codeChallengeMethodsSupported intentionally absent.
	auto pkce = makePkce(new ubyte[32]);
	assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // discovered AS document missing code_challenge_methods_supported -> refuse (exchangeCode)
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	as_.metadataDocumentDiscovered = true;
	// codeChallengeMethodsSupported intentionally absent.
	assertThrown(c.exchangeCode(as_, RegisteredClient("cid", ""), "code", "verifier"));
}

unittest  // AuthorizationServerMetadata.fromJson on a document lacking PKCE -> refuse
{
	import std.exception : assertThrown;
	import vibe.data.json : parseJsonString;

	// A genuine discovered document that omits code_challenge_methods_supported
	// must be rejected: fromJson marks it discovered, so requirePkceSupport throws.
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	auto j = parseJsonString(`{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/authorize"}`);
	auto as_ = AuthorizationServerMetadata.fromJson(j);
	assert(as_.metadataDocumentDiscovered);
	assert(!as_.supportsS256());
	auto pkce = makePkce(new ubyte[32]);
	assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // discovered AS document advertising S256 -> proceeds
{
	import std.algorithm : canFind;
	import vibe.data.json : parseJsonString;

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	auto j = parseJsonString(`{"issuer":"https://as.example.com",`
			~ `"authorization_endpoint":"https://as.example.com/authorize",`
			~ `"code_challenge_methods_supported":["S256"]}`);
	auto as_ = AuthorizationServerMetadata.fromJson(j);
	assert(as_.metadataDocumentDiscovered);
	auto pkce = makePkce(new ubyte[32]);
	auto url = c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st");
	assert(url.canFind("code_challenge_method=S256"));
}

unittest  // authorizationUrl refuses when the RFC 8707 resource indicator is unset
{
	import std.exception : assertThrown;

	// The MCP authorization spec requires the `resource` indicator be sent on the
	// authorization request regardless of AS support; an unset resource is a
	// configuration error that must be rejected.
	auto c = new OAuthClient();
	// c.resource left empty.
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto pkce = makePkce(new ubyte[32]);
	assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // exchangeCode refuses when the RFC 8707 resource indicator is unset
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	// c.resource left empty.
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	as_.codeChallengeMethodsSupported = ["S256"];
	assertThrown(c.exchangeCode(as_, RegisteredClient("cid", ""), "code", "verifier"));
}

unittest  // refresh refuses when the RFC 8707 resource indicator is unset
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	// c.resource left empty.
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	assertThrown(c.refresh(as_, RegisteredClient("cid", ""), "rt"));
}

unittest  // clientCredentials refuses when the RFC 8707 resource indicator is unset
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	// c.resource left empty.
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	assertThrown(c.clientCredentials(as_, RegisteredClient("cid", ""), "scope"));
}

unittest  // authorizationUrl refuses an internal/plaintext authorization endpoint (SSRF)
{
	import std.exception : assertThrown;

	// A metadata-derived authorization_endpoint pointing at the cloud metadata
	// service must be rejected before a URL is constructed or any GET is issued.
	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "http://169.254.169.254/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto pkce = makePkce(new ubyte[32]);
	assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));

	// Plaintext http to a non-loopback host is likewise rejected.
	AuthorizationServerMetadata as2;
	as2.authorizationEndpoint = "http://as.example.com/authorize";
	as2.codeChallengeMethodsSupported = ["S256"];
	assertThrown(c.authorizationUrl(as2, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // authorizeAndGetCode refuses an internal/plaintext authorize URL before GET (SSRF)
{
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	// Both overloads must guard the outbound GET.
	assertThrown(c.authorizeAndGetCode("http://169.254.169.254/authorize?x=1"));
	assertThrown(c.authorizeAndGetCode("http://as.example.com/authorize?x=1"));
	assertThrown(c.authorizeAndGetCode("https://[fd00::1]/authorize?x=1"));

	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	assertThrown(c.authorizeAndGetCode(as_, "http://169.254.169.254/authorize?x=1"));
	assertThrown(c.authorizeAndGetCode(as_, "https://[::ffff:10.0.0.1]/authorize?x=1"));
}

unittest  // discoverProtectedResource ignores a cross-origin resource_metadata URL
{
	// RFC 9728: a resource_metadata URL from WWW-Authenticate whose origin does
	// not match the MCP endpoint origin must not be fetched. With no reachable
	// well-known document either, discovery fails (rather than fetching the
	// attacker-supplied URL).
	import std.exception : assertThrown;

	auto c = new OAuthClient();
	const www = `Bearer resource_metadata="https://evil.example.com/.well-known/oauth-protected-resource"`;
	// The MCP endpoint origin (loopback) differs from the challenge's origin, and
	// the loopback well-known URLs are unreachable in the test, so discovery throws.
	assertThrown(c.discoverProtectedResource("http://127.0.0.1:1/mcp", www));
}
