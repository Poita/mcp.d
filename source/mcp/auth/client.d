module mcp.auth.client;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;

import mcp.protocol.errors;
import mcp.auth.oauth;

@safe:

/// Thrown when protected-resource-metadata discovery establishes the document is
/// genuinely ABSENT — every candidate location was reachable but reported no
/// document (a 404 / empty body). This is the only outcome that licenses the
/// lenient 2025-03-26 origin-issuer fallback. A fetch FAILURE (SSRF block, TLS,
/// DNS, network error, or a malformed body) is a different, non-absent outcome
/// and must not be downgraded onto that lenient path.
class PrmAbsentException : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

/// The outcome of a discovery fetch: `ok` (2xx with a parseable JSON body),
/// `notFound` (reachable but no usable document — a non-2xx or empty 2xx), or
/// `error` (the fetch itself failed: SSRF block, TLS/DNS/network error, or a
/// malformed body). The `error`/`notFound` split is what keeps a fetch failure
/// from masquerading as a genuinely-absent document.
enum FetchResult
{
	ok,
	notFound,
	error
}

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
	/// `exchangeCode`, `refresh`, `clientCredentials`, `tokenExchange`, and
	/// `jwtBearerGrant` reject an empty value.
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

		bool anyError;
		foreach (u; urls)
		{
			Json j;
			final switch (tryGetJson(u, j))
			{
			case FetchResult.ok:
				return ProtectedResourceMetadata.fromJson(j);
			case FetchResult.error:
				anyError = true;
				break;
			case FetchResult.notFound:
				break;
			}
		}
		throwPrmDiscoveryFailure(anyError);
		assert(0); // throwPrmDiscoveryFailure never returns
	}

	/// Signal exhausted protected-resource-metadata discovery. A genuine absence
	/// (no candidate errored) throws `PrmAbsentException`, which alone licenses the
	/// lenient origin-issuer fallback; a fetch error throws a generic failure so it
	/// can never be silently downgraded onto that path.
	private static void throwPrmDiscoveryFailure(bool anyError) @safe
	{
		if (anyError)
			throw internalError("Protected-resource metadata discovery failed (a candidate could "
					~ "not be fetched); refusing to downgrade to the lenient origin issuer");
		throw new PrmAbsentException("No protected-resource metadata document");
	}

	/// Discover authorization-server metadata for an issuer, trying the RFC 8414
	/// and OpenID Connect Discovery well-known locations in order.
	///
	/// `enforceIssuerMatch` selects how a discovered document's `issuer` is treated;
	/// the issuer enforcement rule is documented on `bindDiscoveredIssuer`.
	AuthorizationServerMetadata discoverAuthServer(string issuer, bool enforceIssuerMatch = true) @safe
	{
		foreach (u; authServerMetadataCandidates(issuer))
		{
			Json j;
			// Both a not-found and a fetch error fall through to the next candidate
			// and then to the 2025-03-26 default-endpoint fallback below; the
			// synthesized endpoints derive from the already-validated issuer, not
			// from attacker-influenced data, so the lenient fallback is safe here.
			if (tryGetJson(u, j) == FetchResult.ok)
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
	/// `fromProtectedResourceMetadata` to true on the modern RFC 9728 path or false
	/// on the 2025-03-26 origin fallback (the issuer enforcement implications of each
	/// path are documented on `bindDiscoveredIssuer`).
	string resolveIssuer(string mcpEndpoint,
			out bool fromProtectedResourceMetadata, string wwwAuthenticateHeader = "") @safe
	{
		return resolveIssuerFrom(() => discoverProtectedResource(mcpEndpoint,
				wwwAuthenticateHeader), mcpEndpoint, fromProtectedResourceMetadata);
	}

	/// Decide the issuer from a protected-resource-metadata discovery, with the
	/// discovery itself injected so the security-critical downgrade rule is unit
	/// testable. Only a genuinely-absent document (`PrmAbsentException`) downgrades
	/// to the 2025-03-26 origin-issuer fallback; any other failure (a fetch error,
	/// an SSRF/insecure-URL rejection, a malformed document) propagates so the flow
	/// fails closed rather than silently relaxing issuer binding.
	private static string resolveIssuerFrom(scope ProtectedResourceMetadata delegate() @safe discover,
			string mcpEndpoint, out bool fromProtectedResourceMetadata) @safe
	{
		try
		{
			auto prm = discover();
			if (prm.authorizationServers.length)
			{
				fromProtectedResourceMetadata = true;
				return prm.authorizationServers[0];
			}
		}
		catch (PrmAbsentException)
		{
			// Genuine pre-RFC-9728 server: no PRM document at all -> origin fallback.
		}
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
	/// Rejects an empty `resource` — see the class docstring for the rationale.
	TokenSet tokenExchange(string tokenEndpoint, string subjectToken,
			string subjectTokenType, string requestedTokenType, string audience, string clientId) @safe
	{
		requireResource();
		auto form = buildTokenExchangeForm(subjectToken, subjectTokenType,
				requestedTokenType, audience, resource, clientId);
		return TokenSet.fromJson(postForm(tokenEndpoint, form, RegisteredClient(clientId, "")));
	}

	/// RFC 7523 JWT-bearer grant: exchange an assertion JWT for an access token.
	TokenSet jwtBearerGrant(AuthorizationServerMetadata as_,
			RegisteredClient client, string assertion, string scopeStr) @safe
	{
		requireResource();
		auto form = buildJwtBearerForm(assertion, scopeStr, resource, client.clientId);
		return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
	}

	/// Refresh an access token.
	TokenSet refresh(AuthorizationServerMetadata as_, RegisteredClient client, string refreshToken) @safe
	{
		requireResource();
		const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
		auto form = buildRefreshTokenForm(refreshToken, client.clientId,
				resource, post ? client.clientSecret : "") ~ clientAssertionParams(client.clientId,
				as_.issuer.length ? as_.issuer : as_.tokenEndpoint);
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
		try
		{
			secureRequestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
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
		return www;
	}

	/// POST a `tools/list` request with a bearer token; if the server challenges
	/// with 401/403 (insufficient scope), return the `WWW-Authenticate` header.
	/// Used to detect step-up authorization requirements.
	string probeOperation(string mcpEndpoint, string bearer) @safe
	{
		string www;
		try
		{
			secureRequestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
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
		// or internal/link-local authorization endpoint; the connect is pinned to a
		// pre-vetted resolved address.
		string code, state;
		secureRequestHTTP(authzUrl, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.GET;
		}, (scope HTTPClientResponse res) {
			const loc = res.headers.get("Location", "");
			code = extractQueryParam(loc, "code");
			state = extractQueryParam(loc, "state");
			res.dropBody();
		});
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
		// SSRF guard (see overload above); the connect is pinned to a pre-vetted
		// resolved address.
		string code, iss, state;
		secureRequestHTTP(authzUrl, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.GET;
		}, (scope HTTPClientResponse res) {
			const loc = res.headers.get("Location", "");
			code = extractQueryParam(loc, "code");
			iss = extractQueryParam(loc, "iss");
			state = extractQueryParam(loc, "state");
			res.dropBody();
		});
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

	private FetchResult tryGetJson(string url, out Json result) @safe
	{
		// Never fetch a discovery URL that is not HTTPS (or loopback for dev) or
		// that targets an internal/link-local address — including a hostname that
		// resolves to one (DNS-rebinding SSRF mitigation, pinned at connect time).
		Json parsed;
		// A reachable response that is not a usable 2xx-with-body means "no document
		// here"; an exception (SSRF block, TLS/DNS/network failure, or a malformed
		// 2xx body) is a fetch error, tracked distinctly so it cannot be mistaken
		// for a genuinely-absent document.
		auto outcome = FetchResult.notFound;
		try
		{
			secureRequestHTTP(url, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.GET;
				req.headers["Accept"] = "application/json";
			}, (scope HTTPClientResponse res) {
				auto body = res.bodyReader.readAllUTF8();
				if (res.statusCode / 100 == 2 && body.length)
				{
					parsed = parseJsonString(body); // a throw here is a fetch error, caught below
					outcome = FetchResult.ok;
				}
			});
		}
		catch (Exception e)
		{
			import vibe.core.log : logDiagnostic;

			logDiagnostic("Discovery fetch of %s failed (not treated as document-absent): %s",
					url, e.msg);
			outcome = FetchResult.error;
		}
		result = parsed;
		return outcome;
	}

	// Secure POST a body to `url` with the given content type, optionally adding
	// an Authorization header, and parse the response as JSON (empty body -> {}).
	// Throws when the response status is not 2xx, surfacing the error body if
	// present (consistent with tryGetJson which guards status the same way).
	private Json postParse(string url, string contentType,
			scope const(ubyte)[] payload, string authHeader = null) @safe
	{
		import std.conv : to;

		Json result;
		secureRequestHTTP(url, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.POST;
			req.contentType = contentType;
			req.headers["Accept"] = "application/json";
			if (authHeader.length)
				req.headers["Authorization"] = authHeader;
			req.writeBody(payload);
		}, (scope HTTPClientResponse res) {
			auto body = res.bodyReader.readAllUTF8();
			if (res.statusCode / 100 != 2)
				throw internalError("Token endpoint returned HTTP " ~ res.statusCode.to!string ~ (
					body.length ? ": " ~ body : ""));
			result = body.length ? parseJsonString(body) : Json.emptyObject;
		});
		return result;
	}

	private Json postJson(string url, Json payload) @safe
	{
		return postParse(url, "application/json", cast(const(ubyte)[]) payload.toString());
	}

	private Json postForm(string url, string form, RegisteredClient client) @safe
	{
		const useBasic = authMethod == TokenEndpointAuthMethod.clientSecretBasic
			&& client.clientSecret.length;
		const auth = useBasic ? basicAuthHeader(client.clientId, client.clientSecret) : "";
		return postParse(url, "application/x-www-form-urlencoded", cast(const(ubyte)[]) form, auth);
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

unittest  // exhausted PRM discovery distinguishes genuine absence from a fetch error
{
	import std.exception : assertThrown, collectException;

	// All candidates reported the document absent (reachable 404 / empty): the
	// lenient origin-issuer downgrade is licensed.
	assertThrown!PrmAbsentException(OAuthClient.throwPrmDiscoveryFailure(false));

	// A candidate failed to fetch (SSRF block / TLS / DNS / malformed body): this
	// must NOT be classified as document-absent, or the downgrade would be granted
	// to an attacker who can merely make the PRM fetch fail.
	auto e = collectException(OAuthClient.throwPrmDiscoveryFailure(true));
	assert(e !is null);
	assert(cast(PrmAbsentException) e is null, "a fetch error must not be treated as absence");
}

unittest  // resolveIssuerFrom downgrades to the origin only when the PRM document is genuinely absent
{
	bool fromPrm;
	const issuer = OAuthClient.resolveIssuerFrom(() @safe {
		throw new PrmAbsentException("no PRM");
		return ProtectedResourceMetadata.init;
	}, "https://mcp.example.com/sse", fromPrm);
	assert(!fromPrm);
	assert(issuer == "https://mcp.example.com");
}

unittest  // resolveIssuerFrom does NOT silently downgrade on a fetch/security error — it propagates
{
	import std.exception : assertThrown;

	bool fromPrm;
	assertThrown!McpException(OAuthClient.resolveIssuerFrom(() @safe {
			throw internalError("Refusing to fetch URL with no parseable host");
			return ProtectedResourceMetadata.init;
		}, "https://mcp.example.com/sse", fromPrm));
}

unittest  // resolveIssuerFrom returns the PRM-advertised authorization server on the modern path
{
	bool fromPrm;
	const issuer = OAuthClient.resolveIssuerFrom(() @safe {
		ProtectedResourceMetadata prm;
		prm.authorizationServers = ["https://as.example.com"];
		return prm;
	}, "https://mcp.example.com/sse", fromPrm);
	assert(fromPrm);
	assert(issuer == "https://as.example.com");
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

unittest  // jwtBearerGrant refuses when the RFC 8707 resource indicator is unset
{
	import mcp.protocol.errors : McpException;
	import std.exception : assertThrown;
	import std.string : indexOf;

	auto c = new OAuthClient();
	// c.resource left empty.
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = "https://as.example.com/token";
	bool caught;
	try
		c.jwtBearerGrant(as_, RegisteredClient("cid", ""), "assertion", "scope");
	catch (McpException e)
	{
		caught = e.msg.indexOf("resource indicator") >= 0;
	}
	catch (Exception)
	{
		// Any non-McpException means requireResource() was not called first.
	}
	assert(caught, "jwtBearerGrant must throw McpException mentioning 'resource indicator' when resource is unset");
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

unittest  // postParse treats a non-2xx token-endpoint response as an error
{
	import std.conv : to;
	import std.exception : assertThrown;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	// Spin up a loopback server that always returns 400 with an OAuth error body.
	auto settings = new HTTPServerSettings();
	settings.bindAddresses = ["127.0.0.1"];
	settings.port = 0;
	auto listener = () @trusted {
		return listenHTTP(settings, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
			res.statusCode = 400;
			res.writeBody(`{"error":"invalid_client","error_description":"bad credentials"}`,
				"application/json");
		});
	}();
	scope (exit)
		() @trusted { listener.stopListening(); }();

	const port = listener.bindAddresses[0].port;
	const tokenUrl = "http://127.0.0.1:" ~ port.to!string ~ "/token";

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = tokenUrl;
	// A non-2xx response from the token endpoint must surface as an exception,
	// not silently return an empty TokenSet.
	assertThrown(c.refresh(as_, RegisteredClient("cid", ""), "rt"));
}

unittest  // tokenExchange refuses when the RFC 8707 resource indicator is unset
{
	import mcp.protocol.errors : McpException;
	import std.exception : assertThrown;
	import std.string : indexOf;

	auto c = new OAuthClient();
	// c.resource left empty.
	bool caught;
	try
		c.tokenExchange("https://as.example.com/token", "subj_token",
				"urn:ietf:params:oauth:token-type:id_token",
				"urn:ietf:params:oauth:token-type:access_token", "aud", "cid");
	catch (McpException e)
	{
		caught = e.msg.indexOf("resource indicator") >= 0;
	}
	catch (Exception)
	{
		// Any non-McpException means requireResource() was not called first.
	}
	assert(caught, "tokenExchange must throw McpException mentioning 'resource indicator' when resource is unset");
}

unittest  // refresh() sends client_secret in the POST body for client_secret_post auth
{
	import std.algorithm : canFind;
	import std.conv : to;
	import std.exception : assertThrown;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	// Capture the raw POST body sent by refresh() so we can assert it contains
	// client_secret when the auth method is client_secret_post.
	string capturedBody;
	auto settings = new HTTPServerSettings();
	settings.bindAddresses = ["127.0.0.1"];
	settings.port = 0;
	auto listener = () @trusted {
		return listenHTTP(settings, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
			capturedBody = req.bodyReader.readAllUTF8();
			res.statusCode = 200;
			res.writeBody(`{"access_token":"at","token_type":"bearer"}`, "application/json");
		});
	}();
	scope (exit)
		() @trusted { listener.stopListening(); }();

	const port = listener.bindAddresses[0].port;
	const tokenUrl = "http://127.0.0.1:" ~ port.to!string ~ "/token";

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.authMethod = TokenEndpointAuthMethod.clientSecretPost;
	AuthorizationServerMetadata as_;
	as_.tokenEndpoint = tokenUrl;
	c.refresh(as_, RegisteredClient("cid", "mysecret"), "myrefreshtoken");
	// The POST body must include the client_secret for client_secret_post auth.
	assert(capturedBody.canFind("client_secret=mysecret"),
			"refresh() must include client_secret in POST body for client_secret_post; got: "
			~ capturedBody);
}

// ===========================================================================
// Loopback-server tests for the HTTP-network discovery / registration / token /
// probe / redirect paths. secureRequestHTTP permits a loopback (127.0.0.1) host
// over plaintext http for local development, so a bound `listenHTTP` on
// 127.0.0.1 exercises the real fetch/parse code that pure in-memory tests cannot.
// ===========================================================================

version (unittest)
{
	import vibe.http.server : HTTPListener, HTTPServerRequest,
		HTTPServerResponse, HTTPServerSettings, listenHTTP;

	// A loopback HTTP server bound to an ephemeral port, driving the supplied
	// request handler. `stop()` releases the listener (call via scope(exit)).
	private struct LoopbackServer
	{
		HTTPListener listener;
		ushort port;
		void stop() @safe
		{
			() @trusted { listener.stopListening(); }();
		}
		// The loopback base URL ("http://127.0.0.1:<port>").
		string base() @safe const
		{
			import std.conv : to;

			return "http://127.0.0.1:" ~ port.to!string;
		}
	}

	private LoopbackServer startLoopback(void delegate(scope HTTPServerRequest,
			scope HTTPServerResponse) @safe handler) @safe
	{
		auto settings = new HTTPServerSettings();
		settings.bindAddresses = ["127.0.0.1"];
		settings.port = 0;
		auto l = () @trusted { return listenHTTP(settings, handler); }();
		return LoopbackServer(l, l.bindAddresses[0].port);
	}
}

unittest  // discovery: protected-resource (well-known + same-origin WWW-Authenticate) and AS metadata
{
	import std.algorithm : canFind;

	// One router: RFC 9728 PRM for any protected-resource path (well-known or the
	// challenge-named /custom-prm), and RFC 8414 AS metadata for authorization-server
	// / openid paths. The AS document self-asserts the loopback issuer so the modern
	// enforce-issuer-match path accepts it.
	LoopbackServer srv;
	srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		if (req.path.canFind("oauth-protected-resource") || req.path == "/custom-prm")
		{
			res.writeBody(
				`{"resource":"` ~ srv.base ~ `/mcp",` ~ `"authorization_servers":["` ~ srv.base ~ `"]}`,
				"application/json");
		}
		else if (req.path.canFind("authorization-server") || req.path.canFind("openid"))
		{
			res.writeBody(`{"issuer":"http://` ~ req.host ~ `",` ~ `"authorization_endpoint":"`
				~ srv.base ~ `/authorize",` ~ `"token_endpoint":"` ~ srv.base ~ `/token",`
				~ `"code_challenge_methods_supported":["S256"]}`, "application/json");
		}
		else
		{
			res.statusCode = 404;
			res.writeBody("", "text/plain");
		}
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	const endpoint = srv.base ~ "/mcp";

	// Well-known RFC 9728 discovery (no WWW-Authenticate hint).
	auto prm = c.discoverProtectedResource(endpoint);
	assert(prm.authorizationServers == [srv.base]);

	// A same-origin resource_metadata URL from the WWW-Authenticate challenge is
	// fetched (RFC 9728 origin check passes for the loopback origin).
	const www = `Bearer resource_metadata="` ~ srv.base ~ `/custom-prm"`;
	auto prm2 = c.discoverProtectedResource(endpoint, www);
	assert(prm2.resource == endpoint);

	// RFC 8414 AS metadata discovery with the default enforce-issuer-match path.
	auto as_ = c.discoverAuthServer(srv.base);
	assert(as_.issuer == srv.base);
	assert(as_.tokenEndpoint == srv.base ~ "/token");
	assert(as_.metadataDocumentDiscovered);

	// resolveIssuer: the modern path returns the PRM-advertised authorization server.
	bool fromPrm;
	const issuer = c.resolveIssuer(endpoint, fromPrm);
	assert(fromPrm);
	assert(issuer == srv.base);
	// Convenience overload discards the discovery-source signal.
	assert(c.resolveIssuer(endpoint) == srv.base);
}

unittest  // discoverAuthServer falls back to synthesized endpoints when no document exists
{
	// Every AS metadata candidate is reachable but reports no document (404), so
	// discoverAuthServer takes the 2025-03-26 endpoint-fallback path and derives
	// default endpoints from the (trailing-slash-stripped) issuer.
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		res.statusCode = 404;
		res.writeBody("", "text/plain");
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	auto as_ = c.discoverAuthServer(srv.base ~ "/");
	assert(as_.issuer == srv.base ~ "/");
	assert(as_.authorizationEndpoint == srv.base ~ "/authorize");
	assert(as_.tokenEndpoint == srv.base ~ "/token");
	assert(as_.registrationEndpoint == srv.base ~ "/register");
	assert(!as_.metadataDocumentDiscovered);
}

unittest  // register() POSTs an RFC 7591 request and parses the returned credentials
{
	import std.algorithm : canFind;

	string captured;
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		captured = req.bodyReader.readAllUTF8();
		res.writeBody(`{"client_id":"generated-id","client_secret":"generated-secret"}`,
			"application/json");
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	c.redirectUri = "http://localhost:8765/callback";
	AuthorizationServerMetadata as_;
	as_.registrationEndpoint = srv.base ~ "/register";
	auto rc = c.register(as_, "dlang-mcp", "mcp:read");
	assert(rc.clientId == "generated-id");
	assert(rc.clientSecret == "generated-secret");
	// The request carried the configured redirect URI and client name.
	assert(captured.canFind("dlang-mcp"));
	assert(captured.canFind("http://localhost:8765/callback"));

	// An AS without a registration endpoint refuses DCR before any request.
	import std.exception : assertThrown;

	AuthorizationServerMetadata none;
	assertThrown(c.register(none, "x"));
}

unittest  // token grants POST their forms and parse the token response (loopback)
{
	import std.algorithm : canFind;

	string lastForm;
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		lastForm = req.bodyReader.readAllUTF8();
		res.writeBody(`{"access_token":"at-123","token_type":"bearer","expires_in":3600,`
			~ `"refresh_token":"rt-123","scope":"mcp:read"}`, "application/json");
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.tokenEndpoint = srv.base ~ "/token";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto client = RegisteredClient("cid", "");

	auto t1 = c.exchangeCode(as_, client, "the-code", "the-verifier");
	assert(t1.accessToken == "at-123");
	assert(t1.expiresIn == 3600);
	assert(lastForm.canFind("grant_type=authorization_code"));
	assert(lastForm.canFind("code=the-code"));

	auto t2 = c.clientCredentials(as_, client, "mcp:read");
	assert(t2.accessToken == "at-123");
	assert(lastForm.canFind("grant_type=client_credentials"));

	auto t3 = c.refresh(as_, client, "the-refresh");
	assert(t3.refreshToken == "rt-123");
	assert(lastForm.canFind("grant_type=refresh_token"));

	auto t4 = c.jwtBearerGrant(as_, client, "the-assertion", "mcp:read");
	assert(t4.accessToken == "at-123");
	assert(lastForm.canFind("assertion=the-assertion"));

	auto t5 = c.tokenExchange(srv.base ~ "/token", "subj", "urn:t:id_token",
			"urn:t:access_token", "aud", "cid");
	assert(t5.accessToken == "at-123");
	assert(lastForm.canFind(
			"grant_type=" ~ "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"));

	// client_secret_basic puts the credentials in the Authorization header rather
	// than the form body, exercising the basic-auth branch of postForm/postParse.
	c.authMethod = TokenEndpointAuthMethod.clientSecretBasic;
	auto t6 = c.clientCredentials(as_, RegisteredClient("cid", "shh"), "mcp:read");
	assert(t6.accessToken == "at-123");
	assert(!lastForm.canFind("client_secret="));
}

unittest  // private_key_jwt: token requests carry a client_assertion (RFC 7523)
{
	import std.algorithm : canFind;

	string lastForm;
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		lastForm = req.bodyReader.readAllUTF8();
		res.writeBody(`{"access_token":"at","token_type":"bearer"}`, "application/json");
	});
	scope (exit)
		srv.stop();

	// A throwaway P-256 PKCS#8 key (shared with the jwt module's own test).
	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";

	auto c = new OAuthClient();
	c.resource = "https://mcp.example.com/mcp";
	c.authMethod = TokenEndpointAuthMethod.privateKeyJwt;
	c.privateKeyPem = pem;
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.tokenEndpoint = srv.base ~ "/token";
	as_.codeChallengeMethodsSupported = ["S256"];

	c.exchangeCode(as_, RegisteredClient("cid", ""), "code", "verifier");
	assert(lastForm.canFind("client_assertion_type="));
	assert(lastForm.canFind("client_assertion="));
}

unittest  // probeUnauthorized / probeOperation return the WWW-Authenticate challenge on 401
{
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		res.statusCode = 401;
		res.headers["WWW-Authenticate"] = `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`;
		res.writeBody("", "application/json");
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	const endpoint = srv.base ~ "/mcp";
	const w1 = c.probeUnauthorized(endpoint);
	assert(w1
			== `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`);
	// The bearer-bearing probe sets an Authorization header on the request.
	const w1b = c.probeUnauthorized(endpoint, "an-access-token");
	assert(w1b == w1);
	const w2 = c.probeOperation(endpoint, "some-bearer");
	assert(w2 == w1);
}

unittest  // authorizeAndGetCode extracts the code from the redirect Location header
{
	// The server answers the authorization GET with a 302 whose Location carries
	// the authorization code (plus state / RFC 9207 iss for the validating overload).
	auto srv = startLoopback((scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
		res.statusCode = 302;
		res.headers["Location"]
			= "http://localhost:8765/callback?code=auth-code-xyz&state=st-1&iss="
			~ "https%3A%2F%2Fas.example.com";
		res.writeBody("", "text/plain");
	});
	scope (exit)
		srv.stop();

	auto c = new OAuthClient();
	const authzUrl = srv.base ~ "/authorize?client_id=cid";

	// Overload 1: state is verified when expectedState is non-empty.
	assert(c.authorizeAndGetCode(authzUrl, "st-1") == "auth-code-xyz");
	// A mismatched expected state discards the code.
	assert(c.authorizeAndGetCode(authzUrl, "wrong") == "");

	// Overload 2: validates the RFC 9207 iss against the recorded issuer.
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = true;
	assert(c.authorizeAndGetCode(as_, authzUrl, "st-1") == "auth-code-xyz");

	import std.exception : assertThrown;

	// A redirect whose iss does not match the recorded issuer is a possible mix-up
	// attack and must be rejected (RFC 9207).
	AuthorizationServerMetadata wrongIss;
	wrongIss.issuer = "https://attacker.example.com";
	wrongIss.authorizationResponseIssParameterSupported = true;
	assertThrown(c.authorizeAndGetCode(wrongIss, authzUrl, "st-1"));
	// A state mismatch on the validating overload is likewise rejected.
	assertThrown(c.authorizeAndGetCode(as_, authzUrl, "wrong-state"));
}
