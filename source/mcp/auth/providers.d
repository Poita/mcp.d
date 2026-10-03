/// Turnkey server-side auth presets for common identity providers, the D
/// analogue of FastMCP's provider integrations. Each preset is a thin wrapper
/// that fills in the IdP's well-known issuer / JWKS URI / endpoints / default
/// audience + scopes, so an MCP server author writes one line instead of
/// hand-wiring discovery.
///
/// Two buckets:
///
/// $(UL
///   $(LI JWT-based (JWKS) presets build on `jwtVerifier`: the IdP issues
///        JWT access tokens with a published JWKS, and the preset pins the
///        issuer, JWKS URI, and audience. Each returns a `ResourceServerConfig`
///        whose `validator` is a preconfigured `jwtVerifier`.)
///   $(LI Non-DCR / opaque-token presets build on `OAuthProxy`: the IdP
///        lacks Dynamic Client Registration and/or issues opaque tokens, so the
///        preset supplies the upstream authorize/token endpoints. Each returns an
///        `OAuthProxyConfig`.)
/// )
module mcp.auth.providers;

import std.exception : enforce;
import std.string : endsWith;

import vibe.data.json : Json;

import mcp.auth.jwt_verifier : JwtVerifierConfig, jwtVerifier;
import mcp.auth.oauth : TokenEndpointAuthMethod;
import mcp.auth.oauth_proxy : IssueTokenHook, OAuthProxyConfig;
import mcp.auth.reference_token : ReferenceTokenStore;
import mcp.auth.resource_server : ResourceServerConfig, TokenInfo, TokenValidator;

@safe:

// ===========================================================================
// Small helpers
// ===========================================================================

private string stripTrailingSlash(string s) @safe
{
	return s.endsWith("/") ? s[0 .. $ - 1] : s;
}

/// Settings shared by the JWT/JWKS presets. `resource` and `audience` are
/// distinct: `resource` is what the protected-resource metadata publishes and
/// MCP clients match against the URL they connect to, while `audience` is the
/// `aud` value the IdP stamps in access tokens, which for many IdPs is an API
/// identifier (an App ID URI, a client id) rather than the MCP server URL.
struct JwtPresetOptions
{
	/// The canonical MCP server URL (e.g. `https://mcp.example.com/mcp`),
	/// published as the RFC 9728 `resource`. Required.
	string resource;
	/// The JWT audience tokens must carry. Defaults to `resource` when empty,
	/// for IdPs that honor the RFC 8707 resource indicator; the Entra ID presets
	/// require it.
	string audience;
	/// Scopes required on every token, also advertised as `scopes_supported`.
	string[] scopes;
}

/// Build a `ResourceServerConfig` for a JWT/JWKS IdP in one call: pins `issuer` +
/// `jwksUri` + the audience on a `jwtVerifier`, requires `opts.scopes` on every
/// request (403 `insufficient_scope` when one is missing), and fills the
/// public metadata fields (`resource`, `authorizationServers`, `scopesSupported`)
/// from the same options. The result is the single `auth` object the transport
/// accepts (`StreamableHttpOptions.auth` / `mountMcp`), the D analogue of
/// FastMCP's `auth=JWTVerifier(...)`.
ResourceServerConfig jwtResourceServer(string issuer, string jwksUri, JwtPresetOptions opts) @safe
{
	JwtVerifierConfig vc;
	vc.issuer = issuer;
	vc.jwksUri = jwksUri;
	vc.audience = opts.audience.length ? opts.audience : opts.resource;
	vc.requiredScopes = opts.scopes.dup;
	return resourceServer(vc, opts.resource);
}

/// Build a `ResourceServerConfig` directly from a `JwtVerifierConfig`, so a
/// hand-tuned verifier (custom clock skew, pinned PEM keys, extra scopes) flows
/// through the single `auth` entry. `resource` is the canonical MCP server URL
/// published in the protected-resource metadata; `authorizationServers` comes
/// from `vc.issuer` and `scopesSupported` from `vc.requiredScopes`.
///
/// `vc.requiredScopes` move to `ResourceServerConfig.requiredScopes`, so a valid
/// token missing one is answered with 403 `insufficient_scope` (prompting the
/// client to step up) rather than being rejected by the verifier as invalid.
///
/// When `vc.audience` is set the verifier enforces it, so a token that passes is
/// also bound to `resource` (see `bindResourceAudience`); this lets an IdP whose
/// `aud` is an API identifier rather than the MCP URL pass `authorize`'s RFC 8707
/// resource check. With no `vc.audience`, tokens must name `resource` itself.
ResourceServerConfig resourceServer(JwtVerifierConfig vc, string resource) @safe
{
	import mcp.auth.resource_server : bindResourceAudience;

	enforce(resource.length > 0,
			"resourceServer: resource (the canonical MCP server URL) must be set.");
	ResourceServerConfig cfg;
	cfg.requiredScopes = vc.requiredScopes.dup;
	cfg.scopesSupported = vc.requiredScopes.dup;
	vc.requiredScopes = null;
	cfg.validator = vc.audience.length ? bindResourceAudience(jwtVerifier(vc),
			resource) : jwtVerifier(vc);
	cfg.resource = resource;
	if (vc.issuer.length)
		cfg.authorizationServers = [vc.issuer];
	return cfg;
}

// ===========================================================================
// Bucket A — JWT-based (JWKS) presets -> ResourceServerConfig
// ===========================================================================

/// Microsoft Entra ID (Azure AD). Pins the v2.0 issuer
/// `https://login.microsoftonline.com/{tenant}/v2.0` and the matching JWKS
/// (`/discovery/v2.0/keys`).
///
/// `opts.audience` is required: it is the application (client) id GUID of the
/// API's own app registration, which Entra stamps as `aud` in every v2.0 access
/// token for that API (never the MCP server URL, so it cannot default to
/// `opts.resource`). The preset pins the v2.0 issuer, so the API's app
/// registration manifest must set `"accessTokenAcceptedVersion": 2`
/// (`requestedAccessTokenVersion` in the Microsoft Graph application object);
/// with the default `null`/`1`, Entra issues v1.0 tokens whose `iss` is
/// `https://sts.windows.net/{tenant}/` and every token is rejected.
///
/// Register the MCP server as its own API application rather than
/// reusing the registration a client signs users in with: an OIDC `id_token`
/// is issued for the signing-in client's id, so a shared registration makes
/// id_tokens carry the API's audience. As a second line of defence the preset
/// accepts only tokens bearing the access-token-only `scp` (delegated) or
/// `roles` (app-only) claim, which Entra never puts in an id_token.
///
/// `tenant` must be a concrete tenant GUID or a registered domain name.
/// The pseudo-tenants `"common"`, `"organizations"`, and `"consumers"` are
/// rejected because Entra ID never stamps them in the `iss` claim of a real
/// token — every token would fail the issuer check at runtime. For a
/// multi-tenant app, list the tenants it serves with `entraIdTenants`.
ResourceServerConfig entraId(string tenant, JwtPresetOptions opts) @safe
{
	requireConcreteEntraTenant(tenant, "entraId");
	requireEntraAudience(opts, "entraId");
	const issuer = "https://login.microsoftonline.com/" ~ tenant ~ "/v2.0";
	const jwks = "https://login.microsoftonline.com/" ~ tenant ~ "/discovery/v2.0/keys";
	JwtVerifierConfig vc;
	vc.issuer = issuer;
	vc.jwksUri = jwks;
	vc.audience = opts.audience;
	vc.requiredScopes = opts.scopes.dup;
	return entraResourceServer(vc, opts.resource);
}

/// `resourceServer` for an Entra issuer, additionally requiring the `scp` or
/// `roles` claim that distinguishes an Entra access token from an id_token.
private ResourceServerConfig entraResourceServer(JwtVerifierConfig vc, string resource) @safe
{
	import mcp.auth.resource_server : TokenInfo, TokenValidator;

	auto cfg = resourceServer(vc, resource);
	TokenValidator inner = cfg.validator;
	cfg.validator = (string token) @safe {
		auto info = inner(token);
		if (info.valid && !hasEntraAccessTokenClaim(info.claims))
			return TokenInfo.invalid();
		return info;
	};
	return cfg;
}

/// Whether `claims` carries a non-empty `scp` string or `roles` array.
private bool hasEntraAccessTokenClaim(Json claims) @safe
{
	if (claims.type != Json.Type.object)
		return false;
	const scp = claims["scp"];
	if (scp.type == Json.Type.string && scp.get!string.length)
		return true;
	const roles = claims["roles"];
	return roles.type == Json.Type.array && roles.length > 0;
}

/// Microsoft Entra ID for a multi-tenant app: accepts tokens from any of the
/// allowed `tenants` (GUIDs or registered domain names) and no other. Each
/// tenant's v2.0 issuer is pinned as in `entraId`, and a token is valid when it
/// verifies against one of them, so the `iss` check is never dropped — with
/// audience binding alone, a token minted by any Entra tenant for the same
/// audience would be accepted.
ResourceServerConfig entraIdTenants(string[] tenants, JwtPresetOptions opts) @safe
{
	import mcp.auth.resource_server : TokenInfo, TokenValidator;

	enforce(tenants.length > 0, "entraIdTenants: list at least one allowed tenant.");
	requireEntraAudience(opts, "entraIdTenants");
	TokenValidator[] validators;
	string[] issuers;
	foreach (tenant; tenants)
	{
		requireConcreteEntraTenant(tenant, "entraIdTenants");
		auto one = entraId(tenant, opts);
		validators ~= one.validator;
		issuers ~= one.authorizationServers;
	}
	ResourceServerConfig cfg;
	cfg.validator = (string token) @safe {
		foreach (v; validators)
		{
			auto info = v(token);
			if (info.valid)
				return info;
		}
		return TokenInfo.invalid();
	};
	enforce(opts.resource.length > 0,
			"entraIdTenants: resource (the canonical MCP server URL) must be set.");
	cfg.resource = opts.resource;
	cfg.authorizationServers = issuers;
	cfg.scopesSupported = opts.scopes.dup;
	cfg.requiredScopes = opts.scopes.dup;
	return cfg;
}

private void requireEntraAudience(JwtPresetOptions opts, string fn) @safe
{
	enforce(opts.audience.length > 0,
			fn ~ ": set JwtPresetOptions.audience to the API app registration's "
			~ "application (client) id. Entra v2.0 access tokens carry that GUID as aud, "
			~ "not the MCP server URL, so defaulting to resource would reject every token.");
}

private void requireConcreteEntraTenant(string tenant, string fn) @safe
{
	enforce(tenant.length > 0,
			fn ~ ": tenant must be a concrete tenant GUID or domain name, not an empty string.");
	enforce(tenant != "common" && tenant != "organizations" && tenant != "consumers",
			fn ~ ": pseudo-tenants (\"common\", \"organizations\", \"consumers\") are not "
			~ "supported — Entra ID never stamps them in the iss claim, so every token "
			~ "would be rejected. Pass a concrete tenant GUID or domain; for a multi-tenant "
			~ "app, list the tenants it serves with entraIdTenants.");
}

/// Auth0. Pins the issuer `https://{domain}/` (Auth0 issuers carry the trailing
/// slash) and JWKS `https://{domain}/.well-known/jwks.json`.
ResourceServerConfig auth0(string domain, JwtPresetOptions opts) @safe
{
	const d = stripTrailingSlash(domain);
	const issuer = "https://" ~ d ~ "/";
	const jwks = "https://" ~ d ~ "/.well-known/jwks.json";
	return jwtResourceServer(issuer, jwks, opts);
}

/// WorkOS AuthKit. The `issuer` is the AuthKit domain
/// (e.g. `https://your-app.authkit.app`); JWKS is at `{issuer}/oauth2/jwks`.
ResourceServerConfig workosAuthKit(string issuer, JwtPresetOptions opts) @safe
{
	const iss = stripTrailingSlash(issuer);
	const jwks = iss ~ "/oauth2/jwks";
	return jwtResourceServer(iss, jwks, opts);
}

/// Descope. The issuer is `https://api.descope.com/{projectId}`; JWKS is at
/// `https://api.descope.com/{projectId}/.well-known/jwks.json`.
ResourceServerConfig descope(string projectId, JwtPresetOptions opts) @safe
{
	const issuer = "https://api.descope.com/" ~ projectId;
	const jwks = issuer ~ "/.well-known/jwks.json";
	return jwtResourceServer(issuer, jwks, opts);
}

/// Scalekit. The `envUrl` is the environment's issuer
/// (e.g. `https://your-env.scalekit.dev`); JWKS is at `{envUrl}/keys`.
ResourceServerConfig scalekit(string envUrl, JwtPresetOptions opts) @safe
{
	const iss = stripTrailingSlash(envUrl);
	const jwks = iss ~ "/keys";
	return jwtResourceServer(iss, jwks, opts);
}

// ===========================================================================
// Bucket B — Non-DCR / opaque-token presets -> OAuthProxyConfig
// ===========================================================================

/// Switch a proxy preset into ISSUE-OWN-TOKEN (broker) mode: the proxy mints the
/// MCP server's OWN opaque token for the client and keeps the upstream token
/// server-side in `store` (reachable from the validated `TokenInfo.claims`),
/// instead of relaying the upstream token to the client (passthrough). A
/// self-brokering server — one that calls a downstream API with the issued token
/// — should chain this onto a preset, e.g. `github(...).brokered(hook, store)`.
OAuthProxyConfig brokered(OAuthProxyConfig cfg, IssueTokenHook issueToken,
		ReferenceTokenStore store) @safe
in (issueToken !is null)
in (store !is null)
{
	cfg.issueToken = issueToken;
	cfg.tokenStore = store;
	return cfg;
}

/// GitHub OAuth app. Fills in GitHub's fixed authorize/token endpoints; the IdP
/// has no DCR and issues opaque tokens, so the proxy fronts it. The author still
/// supplies a `baseUrl`/`resource` for the proxy surface. Defaults to
/// passthrough; a server that calls GitHub's API with the issued token should
/// chain `.brokered(...)` to switch to issue-own-token mode.
///
/// GitHub tokens carry no audience, so the preset sets
/// `verifierBindsResource`: every token the `tokenVerifier` accepts is treated as
/// issued for `resource`. The preset therefore installs `githubTokenVerifier`,
/// which confirms the token belongs to this OAuth app. A replacement verifier
/// must do the same, not merely check that it is a live GitHub token
/// (`GET /user` accepts a token granted to any app).
OAuthProxyConfig github(string clientId, string clientSecret, string[] scopes = [
]) @safe
{
	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = clientId;
	cfg.upstreamClientSecret = clientSecret;
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;
	cfg.scopesSupported = scopes.dup;
	cfg.verifierBindsResource = true;
	cfg.tokenVerifier = githubTokenVerifier(clientId, clientSecret);
	return cfg;
}

/// Google. Fills in Google's fixed authorize/token endpoints; Google has no DCR,
/// so the proxy fronts it. The author supplies the proxy `baseUrl`/`resource`.
/// Defaults to passthrough; a server that calls Google's API with the issued
/// token should chain `.brokered(...)` to switch to issue-own-token mode.
///
/// Google access tokens are opaque to the resource server, so the preset sets
/// `verifierBindsResource`: every token the `tokenVerifier` accepts is treated as
/// issued for `resource`. The preset therefore installs `googleTokenVerifier`,
/// which confirms the token was issued to `clientId`. A replacement verifier
/// must do the same, not merely check that it is a live Google token.
OAuthProxyConfig google(string clientId, string clientSecret, string[] scopes = [
]) @safe
{
	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
	cfg.upstreamTokenEndpoint = "https://oauth2.googleapis.com/token";
	cfg.upstreamClientId = clientId;
	cfg.upstreamClientSecret = clientSecret;
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;
	cfg.scopesSupported = scopes.dup;
	cfg.verifierBindsResource = true;
	cfg.tokenVerifier = googleTokenVerifier(clientId);
	return cfg;
}

// ===========================================================================
// Client-binding verifiers for the opaque-token presets
// ===========================================================================

/// An HTTP request issued by a provider token verifier.
package struct ProviderHttpRequest
{
	string method;
	string url;
	/// The `Authorization` header value; empty sends none.
	string authorization;
	/// The request body; empty sends none.
	string body;
	/// The body's `Content-Type`.
	string contentType = "application/json";
}

/// The status and body of a provider verifier's HTTP response.
package struct ProviderHttpResponse
{
	int status;
	string body;
}

/// Performs a provider verifier's HTTP request. The default is the
/// SSRF-guarded HTTPS client; tests script it.
package alias ProviderHttp = ProviderHttpResponse delegate(ProviderHttpRequest) @safe;

/// Upper bound on a provider verifier response body.
private enum size_t maxProviderResponseBytes = 64 * 1024;

private ProviderHttpResponse providerHttp(ProviderHttpRequest r) @trusted
{
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.http.common : HTTPMethod;
	import vibe.stream.operations : readAllUTF8;
	import mcp.auth.oauth : secureRequestHTTP;
	import mcp.protocol.ssrf : SsrfPolicy;

	ProviderHttpResponse out_;
	secureRequestHTTP(r.url, SsrfPolicy.allowLoopback, (scope HTTPClientRequest req) {
		req.method = r.method == "POST" ? HTTPMethod.POST : HTTPMethod.GET;
		req.headers["Accept"] = "application/json";
		req.headers["User-Agent"] = "mcp-d";
		if (r.authorization.length)
			req.headers["Authorization"] = r.authorization;
		if (r.body.length)
		{
			req.headers["Content-Type"] = r.contentType;
			req.writeBody(cast(const(ubyte)[]) r.body);
		}
	}, (scope HTTPClientResponse res) {
		out_.status = res.statusCode;
		if (out_.status / 100 == 2)
			out_.body = res.bodyReader.readAllUTF8(false, maxProviderResponseBytes);
		else
			res.dropBody();
	});
	return out_;
}

/// Run `check` fail-closed, logging a failed provider call.
private TokenInfo providerCheck(string provider, TokenInfo delegate() @safe check) @safe
{
	try
		return check();
	catch (Exception e)
	{
		import vibe.core.log : logWarn;

		logWarn("%s token verification failed; rejecting the token: %s", provider, e.msg);
		return TokenInfo.invalid();
	}
}

/// A `TokenValidator` for GitHub OAuth-app tokens that accepts only tokens
/// issued to the OAuth app `clientId`. Each call asks GitHub's check-token API
/// (`POST https://api.github.com/applications/{client_id}/token`,
/// authenticated with the app's `clientId:clientSecret`), which answers 404
/// for a token granted to any other app, so a live token from another app
/// cannot be replayed here. The subject is the GitHub login, the scopes are
/// the token's granted scopes, and `claims` is GitHub's response minus the
/// echoed token. The `github` preset installs this by default.
///
/// Every validation makes one HTTPS request to GitHub, which counts against
/// the app's API rate limit.
TokenValidator githubTokenVerifier(string clientId, string clientSecret) @safe
{
	return githubTokenVerifierWith(clientId, clientSecret,
			(ProviderHttpRequest r) @safe => providerHttp(r));
}

/// `githubTokenVerifier` over an arbitrary HTTP call.
package TokenValidator githubTokenVerifierWith(string clientId,
		string clientSecret, ProviderHttp http) @safe
{
	import std.base64 : Base64;
	import std.uri : encodeComponent;
	import mcp.protocol.jsonrpc : parseUntrustedJson;

	enforce(clientId.length > 0, "githubTokenVerifier: clientId must be set.");
	const url = "https://api.github.com/applications/" ~ encodeComponent(clientId) ~ "/token";
	const string authorization = "Basic " ~ Base64.encode(
			cast(const(ubyte)[])(clientId ~ ":" ~ clientSecret)).idup;
	return (string token) @safe {
		if (token.length == 0)
			return TokenInfo.invalid();
		return providerCheck("GitHub", () @safe {
			Json req = Json.emptyObject;
			req["access_token"] = token;
			const res = http(ProviderHttpRequest("POST", url, authorization, req.toString()));
			if (res.status != 200)
				return TokenInfo.invalid();
			auto doc = parseUntrustedJson(res.body);
			if (doc.type != Json.Type.object || jsonString(doc["app"], "client_id") != clientId)
				return TokenInfo.invalid();
			TokenInfo ti;
			ti.valid = true;
			ti.subject = jsonString(doc["user"], "login");
			auto scopes = doc["scopes"];
			if (scopes.type == Json.Type.array)
				foreach (s; ()@trusted { return scopes.get!(Json[]); }())
					if (s.type == Json.Type.string)
						ti.scopes ~= s.get!string;
			doc.remove("token");
			ti.claims = doc;
			return ti;
		});
	};
}

/// A `TokenValidator` for Google OAuth access tokens that accepts only tokens
/// issued to the OAuth client `clientId`. Each call POSTs the token as a form
/// field to Google's tokeninfo endpoint (`https://oauth2.googleapis.com/tokeninfo`),
/// keeping it out of the URL and so out of logged request errors, and requires its `aud`
/// or `azp` to equal `clientId` and its `exp` to be in the future, so a live
/// token granted to another client cannot be replayed here. The subject is the
/// Google account id (`sub`), the scopes are the token's granted scopes, and
/// `claims` is the tokeninfo response. The `google` preset installs this by
/// default.
///
/// Every validation makes one HTTPS request to Google.
TokenValidator googleTokenVerifier(string clientId) @safe
{
	return googleTokenVerifierWith(clientId, (ProviderHttpRequest r) @safe => providerHttp(r));
}

/// `googleTokenVerifier` over an arbitrary HTTP call.
package TokenValidator googleTokenVerifierWith(string clientId, ProviderHttp http) @safe
{
	import std.array : split;
	import std.conv : to;
	import std.datetime.systime : Clock;
	import std.uri : encodeComponent;
	import mcp.protocol.jsonrpc : parseUntrustedJson;

	enforce(clientId.length > 0, "googleTokenVerifier: clientId must be set.");
	return (string token) @safe {
		if (token.length == 0)
			return TokenInfo.invalid();
		return providerCheck("Google", () @safe {
			const res = http(ProviderHttpRequest("POST",
				"https://oauth2.googleapis.com/tokeninfo", null,
				"access_token=" ~ encodeComponent(token), "application/x-www-form-urlencoded"));
			if (res.status != 200)
				return TokenInfo.invalid();
			auto doc = parseUntrustedJson(res.body);
			if (doc.type != Json.Type.object)
				return TokenInfo.invalid();
			if (jsonString(doc, "aud") != clientId && jsonString(doc, "azp") != clientId)
				return TokenInfo.invalid();
			const exp = jsonString(doc, "exp");
			if (exp.length == 0 || exp.to!long <= Clock.currTime.toUnixTime)
				return TokenInfo.invalid();
			TokenInfo ti;
			ti.valid = true;
			ti.subject = jsonString(doc, "sub");
			foreach (s; jsonString(doc, "scope").split(' '))
				if (s.length)
					ti.scopes ~= s;
			ti.claims = doc;
			return ti;
		});
	};
}

/// The string member `key` of `obj`, or empty when `obj` is not an object or
/// the member is absent or not a string.
private string jsonString(Json obj, string key) @safe
{
	if (obj.type != Json.Type.object)
		return null;
	auto v = obj[key];
	return v.type == Json.Type.string ? v.get!string : null;
}

// ===========================================================================
// Tests — per-provider known constants, no live network.
// ===========================================================================

version (unittest) private enum mcpUrl = "https://mcp.example.com/mcp";

unittest  // a preset publishes the MCP server URL as resource while pinning a distinct audience
{
	auto cfg = auth0("tenant.auth0.com", JwtPresetOptions(mcpUrl, "https://api.example.com"));
	assert(cfg.resource == mcpUrl);
}

unittest  // a preset refuses to build without the MCP server URL as resource
{
	import std.exception : assertThrown;

	assertThrown(auth0("tenant.auth0.com", JwtPresetOptions("", "https://api.example.com")));
}

unittest  // Entra ID pins the v2.0 issuer, the discovery JWKS, and audience/scopes
{
	auto cfg = entraId("11111111-2222-3333-4444-555555555555",
			JwtPresetOptions(mcpUrl, "api://my-mcp-server", ["mcp.read"]));
	assert(cfg.enabled);
	assert(cfg.resource == mcpUrl);
	assert(cfg.authorizationServers
			== [
				"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
	]);
	assert(cfg.scopesSupported == ["mcp.read"]);
}

unittest  // Auth0 pins the trailing-slash issuer and the /.well-known/jwks.json URI
{
	auto cfg = auth0("my-tenant.us.auth0.com", JwtPresetOptions(mcpUrl,
			"https://api.example.com"));
	assert(cfg.enabled);
	assert(cfg.resource == mcpUrl);
	assert(cfg.authorizationServers == ["https://my-tenant.us.auth0.com/"]);
}

unittest  // Auth0 tolerates a domain supplied with a trailing slash
{
	auto cfg = auth0("my-tenant.us.auth0.com/", JwtPresetOptions(mcpUrl));
	assert(cfg.authorizationServers == ["https://my-tenant.us.auth0.com/"]);
}

unittest  // WorkOS AuthKit uses the AuthKit domain as the issuer
{
	auto cfg = workosAuthKit("https://example.authkit.app",
			JwtPresetOptions(mcpUrl, "client-abc", ["openid"]));
	assert(cfg.enabled);
	assert(cfg.resource == mcpUrl);
	assert(cfg.authorizationServers == ["https://example.authkit.app"]);
	assert(cfg.scopesSupported == ["openid"]);
}

unittest  // Descope builds the api.descope.com project issuer
{
	auto cfg = descope("P2abc123", JwtPresetOptions(mcpUrl, "my-audience"));
	assert(cfg.enabled);
	assert(cfg.authorizationServers == ["https://api.descope.com/P2abc123"]);
	assert(cfg.resource == mcpUrl);
}

unittest  // Scalekit uses the environment URL as the issuer
{
	auto cfg = scalekit("https://myenv.scalekit.dev", JwtPresetOptions(mcpUrl, "skc_audience"));
	assert(cfg.enabled);
	assert(cfg.authorizationServers == ["https://myenv.scalekit.dev"]);
	assert(cfg.resource == mcpUrl);
}

unittest  // GitHub fills in the fixed OAuth-app endpoints + credentials
{
	auto cfg = github("Iv1.client", "ghsecret", ["read:user", "repo"]);
	assert(cfg.upstreamAuthorizationEndpoint == "https://github.com/login/oauth/authorize");
	assert(cfg.upstreamTokenEndpoint == "https://github.com/login/oauth/access_token");
	assert(cfg.upstreamClientId == "Iv1.client");
	assert(cfg.upstreamClientSecret == "ghsecret");
	assert(cfg.scopesSupported == ["read:user", "repo"]);
	assert(cfg.tokenEndpointAuthMethod == TokenEndpointAuthMethod.clientSecretPost);
}

unittest  // Google fills in its fixed authorize/token endpoints + credentials
{
	auto cfg = google("client.apps.googleusercontent.com", "gsecret", [
		"openid", "email"
	]);
	assert(cfg.upstreamAuthorizationEndpoint == "https://accounts.google.com/o/oauth2/v2/auth");
	assert(cfg.upstreamTokenEndpoint == "https://oauth2.googleapis.com/token");
	assert(cfg.upstreamClientId == "client.apps.googleusercontent.com");
	assert(cfg.upstreamClientSecret == "gsecret");
	assert(cfg.scopesSupported == ["openid", "email"]);
}

unittest  // entraId and entraIdTenants require an explicit audience instead of defaulting to the MCP URL
{
	import std.algorithm : canFind;
	import std.exception : collectExceptionMsg;

	const one = collectExceptionMsg(entraId("tenant-a", JwtPresetOptions(mcpUrl)));
	assert(one.canFind("audience"), one);
	const many = collectExceptionMsg(entraIdTenants(["tenant-a"], JwtPresetOptions(mcpUrl)));
	assert(many.canFind("audience"), many);
}

unittest  // entraId rejects pseudo-tenant "common" at call time to prevent silent failures
{
	import std.exception : assertThrown;

	assertThrown(entraId("common", JwtPresetOptions(mcpUrl, "api://my-app")));
}

unittest  // entraId rejects pseudo-tenant "organizations" at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("organizations", JwtPresetOptions(mcpUrl, "api://my-app")));
}

unittest  // entraId rejects pseudo-tenant "consumers" at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("consumers", JwtPresetOptions(mcpUrl, "api://my-app")));
}

unittest  // entraId's pseudo-tenant error points at an issuer-checked multi-tenant option, not an empty issuer
{
	import std.algorithm : canFind;
	import std.exception : collectExceptionMsg;

	const msg = collectExceptionMsg(entraId("common", JwtPresetOptions(mcpUrl, "api://my-app")));
	assert(!msg.canFind("empty issuer"));
	assert(msg.canFind("entraIdTenants"));
}

unittest  // entraIdTenants pins one v2.0 issuer per allowed tenant
{
	auto cfg = entraIdTenants(["tenant-a", "tenant-b"],
			JwtPresetOptions(mcpUrl, "api://my-mcp-server", ["mcp.read"]));
	assert(cfg.enabled);
	assert(cfg.resource == mcpUrl);
	assert(cfg.authorizationServers == [
		"https://login.microsoftonline.com/tenant-a/v2.0",
		"https://login.microsoftonline.com/tenant-b/v2.0"
	]);
	assert(cfg.scopesSupported == ["mcp.read"]);
	assert(!cfg.validator("not-a-jwt").valid);
}

unittest  // entraIdTenants rejects an empty allowlist and pseudo-tenants
{
	import std.exception : assertThrown;

	assertThrown(entraIdTenants([], JwtPresetOptions(mcpUrl)));
	assertThrown(entraIdTenants(["tenant-a", "common"], JwtPresetOptions(mcpUrl, "api://my-app")));
}

unittest  // entraId rejects an empty tenant string at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("", JwtPresetOptions(mcpUrl, "api://my-app")));
}

unittest  // BROKER: github(...).brokered(...) reaches issue-own-token mode through the preset
{
	import mcp.auth.oauth : TokenSet;
	import mcp.auth.reference_token : IssuedToken, ReferenceTokenStore;

	auto store = new ReferenceTokenStore();
	auto cfg = github("Iv1.client", "ghsecret", ["read:user"]).brokered((TokenSet u) @safe {
		IssuedToken t;
		t.subject = "octocat";
		t.expiresAt = long.max;
		return t;
	}, store);
	// The preset endpoints survive; broker mode is now enabled.
	assert(cfg.upstreamTokenEndpoint == "https://github.com/login/oauth/access_token");
	assert(cfg.issueToken !is null);
	assert(cfg.tokenStore is store);
}

unittest  // BROKER: google(...).brokered(...) reaches issue-own-token mode through the preset
{
	import mcp.auth.oauth : TokenSet;
	import mcp.auth.reference_token : IssuedToken, ReferenceTokenStore;

	auto store = new ReferenceTokenStore();
	auto cfg = google("client.apps.googleusercontent.com", "gsecret").brokered((TokenSet u) @safe {
		IssuedToken t;
		t.expiresAt = long.max;
		return t;
	}, store);
	assert(cfg.upstreamTokenEndpoint == "https://oauth2.googleapis.com/token");
	assert(cfg.issueToken !is null);
	assert(cfg.tokenStore is store);
}

unittest  // a JWT preset wires a working validator that rejects garbage tokens
{
	// No live network: the validator parses the bearer and fails closed on junk.
	auto cfg = entraId("tenant", JwtPresetOptions(mcpUrl, "api://x"));
	assert(cfg.validator !is null);
	assert(!cfg.validator("not-a-jwt").valid);
}

unittest  // resourceServer(JwtVerifierConfig) bundles validator + metadata in one place
{
	JwtVerifierConfig vc;
	vc.issuer = "https://as.example.com";
	vc.jwksUri = "https://as.example.com/jwks";
	vc.audience = "https://mcp.example.com/mcp";
	vc.requiredScopes = ["mcp:read", "mcp:write"];

	auto cfg = resourceServer(vc, "https://mcp.example.com/mcp");
	assert(cfg.enabled);
	assert(cfg.resource == "https://mcp.example.com/mcp");
	assert(cfg.authorizationServers == ["https://as.example.com"]);
	assert(cfg.scopesSupported == ["mcp:read", "mcp:write"]);
	// validator is live and fails closed on junk.
	assert(!cfg.validator("not-a-jwt").valid);
}

unittest  // resourceServer omits authorizationServers when no issuer is pinned
{
	JwtVerifierConfig vc;
	vc.allowAnyIssuer = true;
	vc.audience = "api://x";
	vc.staticPublicKeysPem = [presetEcPubPem];
	auto cfg = resourceServer(vc, mcpUrl);
	assert(cfg.enabled);
	assert(cfg.resource == mcpUrl);
	assert(cfg.authorizationServers.length == 0);
}

unittest  // the public jwtResourceServer one-liner produces a protected config
{
	auto cfg = jwtResourceServer("https://issuer.example",
			"https://issuer.example/jwks", JwtPresetOptions(mcpUrl, "", [
				"mcp:read"
	]));
	assert(cfg.enabled);
	assert(cfg.resource == "https://mcp.example.com/mcp");
	assert(cfg.authorizationServers == ["https://issuer.example"]);
	assert(cfg.scopesSupported == ["mcp:read"]);
	assert(cfg.validator !is null);
}

version (unittest)
{
	// Throwaway P-256 key pair for end-to-end preset tests.
	private enum presetEcPrivPem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy5nLkurotTseFLEh\n"
		~ "TcetOpmlWQKsY10kx9Dcg6b7m02hRANCAARdpXuunF3oDfCSUKOtGkybZPpwLUPF\n"
		~ "lCYgn/nxuirfH7L2jXQ/brpaEHPPPTMZgp6p33PDD6VGlbXVXCchEIe0\n"
		~ "-----END PRIVATE KEY-----\n";

	private enum presetEcPubPem = "-----BEGIN PUBLIC KEY-----\n"
		~ "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXaV7rpxd6A3wklCjrRpMm2T6cC1D\n"
		~ "xZQmIJ/58boq3x+y9o10P266WhBzzz0zGYKeqd9zww+lRpW11VwnIRCHtA==\n"
		~ "-----END PUBLIC KEY-----\n";

	private enum entraIssuer = "https://login.microsoftonline.com/tenant-1/v2.0";

	/// A preset-shaped config (Entra issuer, App ID URI audience) that verifies
	/// against the pinned test key instead of fetching a JWKS.
	private ResourceServerConfig entraStyleConfig(string[] scopes = null) @safe
	{
		JwtVerifierConfig vc;
		vc.issuer = entraIssuer;
		vc.staticPublicKeysPem = [presetEcPubPem];
		vc.audience = "api://my-mcp-server";
		vc.requiredScopes = scopes;
		return resourceServer(vc, mcpUrl);
	}

	private string presetToken(string aud, string scope_ = "") @safe
	{
		import std.datetime.systime : Clock;
		import mcp.auth.jwt : JwtClaims, mintJwtEs256;

		JwtClaims c;
		c.iss = entraIssuer;
		c.aud = aud;
		c.sub = "user-1";
		c.scope_ = scope_;
		c.exp = Clock.currTime.toUnixTime + 3600;
		return mintJwtEs256(presetEcPrivPem, c);
	}
}

unittest  // a preset with a distinct audience authorizes a token carrying that audience
{
	import mcp.auth.resource_server : AuthFailure, TokenInfo, authorize;

	TokenInfo info;
	assert(authorize(entraStyleConfig(),
			"Bearer " ~ presetToken("api://my-mcp-server"), info) == AuthFailure.none);
	assert(info.subject == "user-1");
}

unittest  // a preset with a distinct audience still rejects a token minted for another audience
{
	import mcp.auth.resource_server : AuthFailure, TokenInfo, authorize;

	TokenInfo info;
	assert(authorize(entraStyleConfig(),
			"Bearer " ~ presetToken("api://other-api"), info) == AuthFailure.invalidToken);
}

unittest  // a preset answers a token missing a required scope with insufficient_scope (step-up)
{
	import mcp.auth.resource_server : AuthFailure, TokenInfo, authorize;

	auto cfg = entraStyleConfig(["mcp.read", "mcp.write"]);
	TokenInfo info;
	assert(authorize(cfg, "Bearer " ~ presetToken("api://my-mcp-server",
			"mcp.read"), info) == AuthFailure.insufficientScope);
	assert(authorize(cfg, "Bearer " ~ presetToken("api://my-mcp-server",
			"mcp.read mcp.write"), info) == AuthFailure.none);
}

version (unittest)
{
	import mcp.auth.resource_server : TokenInfo;

	/// An upstream verifier for opaque tokens: it resolves the subject but, like a
	/// GitHub `/user` lookup, knows no audience.
	private TokenInfo opaqueUpstreamLookup(string token) @safe
	{
		TokenInfo ti;
		ti.valid = token == "gho_valid";
		ti.subject = "octocat";
		return ti;
	}

	private OAuthProxyConfig withProxySurface(OAuthProxyConfig cfg) @safe
	{
		cfg.baseUrl = "https://mcp.example.com";
		cfg.resource = mcpUrl;
		cfg.tokenVerifier = (string t) @safe => opaqueUpstreamLookup(t);
		return cfg;
	}
}

unittest  // the GitHub passthrough preset authorizes an opaque upstream token its verifier accepts
{
	import mcp.auth.resource_server : AuthFailure, authorize;

	auto rs = withProxySurface(github("Iv1.client", "ghsecret")).toResourceServer();
	TokenInfo info;
	assert(authorize(rs, "Bearer gho_valid", info) == AuthFailure.none);
	assert(info.subject == "octocat");
	assert(authorize(rs, "Bearer gho_forged", info) == AuthFailure.invalidToken);
}

unittest  // the Google passthrough preset authorizes an opaque upstream token its verifier accepts
{
	import mcp.auth.resource_server : AuthFailure, authorize;

	auto rs = withProxySurface(google("client.apps.googleusercontent.com", "gsecret"))
		.toResourceServer();
	TokenInfo info;
	assert(authorize(rs, "Bearer gho_valid", info) == AuthFailure.none);
}

version (unittest)
{
	private enum entraApiClientId = "11111111-2222-3333-4444-555555555555";

	/// The Entra preset's validation, verifying against the pinned test key.
	private ResourceServerConfig entraPinnedConfig() @safe
	{
		JwtVerifierConfig vc;
		vc.issuer = entraIssuer;
		vc.staticPublicKeysPem = [presetEcPubPem];
		vc.audience = entraApiClientId;
		return entraResourceServer(vc, mcpUrl);
	}

	/// An ES256 JWT from the Entra test issuer for the API's client id, with
	/// `extraClaims` (a JSON object fragment, possibly empty) merged in.
	private string entraToken(string extraClaims) @safe
	{
		import std.conv : to;
		import std.datetime.systime : Clock;
		import mcp.auth.jwt : signEs256;
		import mcp.auth.oauth : base64UrlNoPad;

		const payload = `{"iss":"` ~ entraIssuer ~ `","aud":"` ~ entraApiClientId
			~ `","sub":"user-1","exp":` ~ (Clock.currTime.toUnixTime + 3600)
				.to!string ~ (extraClaims.length ? "," ~ extraClaims : "") ~ "}";
		const si = base64UrlNoPad(cast(const(ubyte)[]) `{"alg":"ES256","typ":"JWT"}`)
			~ "." ~ base64UrlNoPad(cast(const(ubyte)[]) payload);
		return si ~ "." ~ base64UrlNoPad(signEs256(presetEcPrivPem, cast(const(ubyte)[]) si));
	}
}

unittest  // ENTRA: an id_token issued to the API's own client id is not accepted as an access token
{
	import mcp.auth.resource_server : AuthFailure, authorize;

	TokenInfo info;
	assert(authorize(entraPinnedConfig(), "Bearer " ~ entraToken(""),
			info) == AuthFailure.invalidToken);
}

unittest  // ENTRA: a delegated access token (scp) is accepted
{
	import mcp.auth.resource_server : AuthFailure, authorize;

	TokenInfo info;
	assert(authorize(entraPinnedConfig(),
			"Bearer " ~ entraToken(`"scp":"mcp.read"`), info) == AuthFailure.none);
}

unittest  // ENTRA: an app-only access token (roles) is accepted
{
	import mcp.auth.resource_server : AuthFailure, authorize;

	TokenInfo info;
	assert(authorize(entraPinnedConfig(),
			"Bearer " ~ entraToken(`"roles":["Mcp.Invoke"]`), info) == AuthFailure.none);
}

unittest  // the GitHub and Google presets ship a client-binding token verifier by default
{
	assert(github("Iv1.client", "ghsecret").tokenVerifier !is null);
	assert(google("client.apps.googleusercontent.com", "gsecret").tokenVerifier !is null);
}

version (unittest)
{
	/// A scripted provider endpoint recording the last request it answered.
	private final class FakeProviderHttp
	{
		ProviderHttpRequest last;
		int calls;
		ProviderHttpResponse delegate(ProviderHttpRequest) @safe answer;

		ProviderHttp call() @safe
		{
			return (ProviderHttpRequest req) @safe {
				++calls;
				last = req;
				return answer(req);
			};
		}
	}
}

unittest  // GITHUB: the verifier asks GitHub's check-token API, authenticated as this OAuth app
{
	import std.algorithm : canFind;

	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"token":"gho_valid","scopes":["read:user","repo"],"app":{"client_id":"Iv1.client"},`
			~ `"user":{"login":"octocat","id":1}}`);
	auto v = githubTokenVerifierWith("Iv1.client", "ghsecret", fake.call());

	auto info = v("gho_valid");
	assert(info.valid);
	assert(info.subject == "octocat");
	assert(info.scopes == ["read:user", "repo"]);
	assert(fake.last.method == "POST");
	assert(fake.last.url == "https://api.github.com/applications/Iv1.client/token");
	assert(fake.last.authorization == "Basic SXYxLmNsaWVudDpnaHNlY3JldA==");
	assert(fake.last.body.canFind(`"access_token":"gho_valid"`));
	assert(info.claims["token"].type == Json.Type.undefined,
			"the echoed token must not be exposed in the claims");
}

unittest  // GITHUB: a live token issued to another OAuth app is rejected
{
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(404,
			`{"message":"Not Found"}`);
	auto v = githubTokenVerifierWith("Iv1.client", "ghsecret", fake.call());
	assert(!v("gho_other_app").valid);

	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"app":{"client_id":"Iv1.other"},"user":{"login":"octocat"}}`);
	assert(!v("gho_other_app").valid);
}

unittest  // GITHUB: a check-token response nested past the depth cap rejects the token
{
	import std.array : replicate;

	const deep = "[".replicate(1000) ~ "]".replicate(1000);
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"app":{"client_id":"Iv1.client"},"user":{"login":"octocat"},"x":` ~ deep ~ `}`);
	auto v = githubTokenVerifierWith("Iv1.client", "ghsecret", fake.call());
	assert(!v("gho_valid").valid);
}

unittest  // GOOGLE: a tokeninfo response nested past the depth cap rejects the token
{
	import std.array : replicate;
	import std.conv : to;
	import std.datetime.systime : Clock;

	const exp = (Clock.currTime.toUnixTime + 3600).to!string;
	const deep = "[".replicate(1000) ~ "]".replicate(1000);
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"aud":"client.apps.googleusercontent.com","sub":"1234","exp":"`
			~ exp ~ `","x":` ~ deep ~ `}`);
	auto v = googleTokenVerifierWith("client.apps.googleusercontent.com", fake.call());
	assert(!v("ya29.valid").valid);
}

unittest  // GITHUB: a failed check-token call rejects the token without throwing
{
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe {
		throw new Exception("network down");
		return ProviderHttpResponse.init;
	};
	auto v = githubTokenVerifierWith("Iv1.client", "ghsecret", fake.call());
	assert(!v("gho_valid").valid);
	assert(!v("").valid);
	assert(fake.calls == 1, "an empty token is rejected without a call");
}

unittest  // GOOGLE: the verifier accepts a token whose tokeninfo aud or azp is this client
{
	import std.conv : to;
	import std.datetime.systime : Clock;

	const exp = (Clock.currTime.toUnixTime + 3600).to!string;
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"aud":"client.apps.googleusercontent.com","azp":"client.apps.googleusercontent.com",`
			~ `"sub":"1234","scope":"openid email","exp":"` ~ exp ~ `"}`);
	auto v = googleTokenVerifierWith("client.apps.googleusercontent.com", fake.call());

	auto info = v("ya29.valid");
	assert(info.valid);
	assert(info.subject == "1234");
	assert(info.scopes == ["openid", "email"]);
}

unittest  // GOOGLE: the token is POSTed as a form body, never placed in the tokeninfo URL
{
	import std.algorithm : canFind;
	import std.conv : to;
	import std.datetime.systime : Clock;

	const exp = (Clock.currTime.toUnixTime + 3600).to!string;
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"aud":"client.apps.googleusercontent.com","sub":"1234","exp":"` ~ exp ~ `"}`);
	auto v = googleTokenVerifierWith("client.apps.googleusercontent.com", fake.call());

	assert(v("ya29.valid/+=").valid);
	assert(fake.last.method == "POST");
	assert(fake.last.url == "https://oauth2.googleapis.com/tokeninfo");
	assert(fake.last.contentType == "application/x-www-form-urlencoded");
	assert(fake.last.body == "access_token=ya29.valid%2F%2B%3D");
	assert(!fake.last.url.canFind("ya29"));
}

unittest  // GOOGLE: a live token issued to another client, or an expired one, is rejected
{
	import std.conv : to;
	import std.datetime.systime : Clock;

	const now = Clock.currTime.toUnixTime;
	auto fake = new FakeProviderHttp;
	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"aud":"other.apps.googleusercontent.com","azp":"other.apps.googleusercontent.com",`
			~ `"sub":"1234","exp":"` ~ (now + 3600).to!string ~ `"}`);
	auto v = googleTokenVerifierWith("client.apps.googleusercontent.com", fake.call());
	assert(!v("ya29.other").valid);

	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(200,
			`{"aud":"client.apps.googleusercontent.com","sub":"1234","exp":"` ~ (now - 10)
				.to!string ~ `"}`);
	assert(!v("ya29.expired").valid);

	fake.answer = (ProviderHttpRequest req) @safe => ProviderHttpResponse(400,
			`{"error":"invalid_token"}`);
	assert(!v("ya29.revoked").valid);
}
