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

import mcp.auth.jwt_verifier : JwtVerifierConfig, jwtVerifier;
import mcp.auth.oauth : TokenEndpointAuthMethod;
import mcp.auth.oauth_proxy : OAuthProxyConfig;
import mcp.auth.resource_server : ResourceServerConfig;

@safe:

// ===========================================================================
// Small helpers
// ===========================================================================

private string stripTrailingSlash(string s) @safe
{
	return s.endsWith("/") ? s[0 .. $ - 1] : s;
}

/// Build a `ResourceServerConfig` for a JWT/JWKS IdP in one call: pins `issuer` +
/// `jwksUri` + `audience` + `requiredScopes` on a `jwtVerifier`, and mirrors the
/// public metadata fields (`resource`, `authorizationServers`, `scopesSupported`)
/// so the audience/resource/scopes are never re-typed. The result is the single
/// `auth` object the transport accepts (`StreamableHttpOptions.auth` /
/// `mountMcp`), the D analogue of FastMCP's `auth=JWTVerifier(...)`.
ResourceServerConfig jwtResourceServer(string issuer, string jwksUri,
		string audience, string[] scopes = []) @safe
{
	JwtVerifierConfig vc;
	vc.issuer = issuer;
	vc.jwksUri = jwksUri;
	vc.audience = audience;
	vc.requiredScopes = scopes.dup;
	return resourceServer(vc);
}

/// Build a `ResourceServerConfig` directly from a `JwtVerifierConfig`, so a
/// hand-tuned verifier (custom clock skew, pinned PEM keys, extra scopes) flows
/// through the single `auth` entry without re-typing its `audience`/`issuer`/
/// `requiredScopes` as the resource-server metadata. Derives `resource` from
/// `vc.audience`, `authorizationServers` from `vc.issuer`, and `scopesSupported`
/// from `vc.requiredScopes`.
ResourceServerConfig resourceServer(JwtVerifierConfig vc) @safe
{
	ResourceServerConfig cfg;
	cfg.validator = jwtVerifier(vc);
	cfg.resource = vc.audience;
	if (vc.issuer.length)
		cfg.authorizationServers = [vc.issuer];
	cfg.scopesSupported = vc.requiredScopes.dup;
	return cfg;
}

// ===========================================================================
// Bucket A — JWT-based (JWKS) presets -> ResourceServerConfig
// ===========================================================================

/// Microsoft Entra ID (Azure AD). Pins the v2.0 issuer
/// `https://login.microsoftonline.com/{tenant}/v2.0` and the matching JWKS
/// (`/discovery/v2.0/keys`). `audience` is the API's App ID URI or client id.
///
/// `tenant` must be a concrete tenant GUID or a registered domain name.
/// The pseudo-tenants `"common"`, `"organizations"`, and `"consumers"` are
/// rejected because Entra ID never stamps them in the `iss` claim of a real
/// token — every token would fail the issuer check at runtime. For multi-tenant
/// validation without a pinned issuer, use `jwtResourceServer` with an empty
/// `issuer` and rely on `audience` binding alone.
ResourceServerConfig entraId(string tenant, string audience, string[] scopes = [
]) @safe
{
	enforce(tenant.length > 0,
			"entraId: tenant must be a concrete tenant GUID or domain name, not an empty string.");
	enforce(tenant != "common" && tenant != "organizations" && tenant != "consumers",
			"entraId: pseudo-tenants (\"common\", \"organizations\", \"consumers\") are not "
			~ "supported — Entra ID never stamps them in the iss claim, so every token "
			~ "would be rejected. Pass a concrete tenant GUID or domain, or use "
			~ "jwtResourceServer with an empty issuer for multi-tenant validation.");
	const issuer = "https://login.microsoftonline.com/" ~ tenant ~ "/v2.0";
	const jwks = "https://login.microsoftonline.com/" ~ tenant ~ "/discovery/v2.0/keys";
	return jwtResourceServer(issuer, jwks, audience, scopes);
}

/// Auth0. Pins the issuer `https://{domain}/` (Auth0 issuers carry the trailing
/// slash) and JWKS `https://{domain}/.well-known/jwks.json`.
ResourceServerConfig auth0(string domain, string audience, string[] scopes = []) @safe
{
	const d = stripTrailingSlash(domain);
	const issuer = "https://" ~ d ~ "/";
	const jwks = "https://" ~ d ~ "/.well-known/jwks.json";
	return jwtResourceServer(issuer, jwks, audience, scopes);
}

/// WorkOS AuthKit. The `issuer` is the AuthKit domain
/// (e.g. `https://your-app.authkit.app`); JWKS is at `{issuer}/oauth2/jwks`.
ResourceServerConfig workosAuthKit(string issuer, string audience, string[] scopes = [
]) @safe
{
	const iss = stripTrailingSlash(issuer);
	const jwks = iss ~ "/oauth2/jwks";
	return jwtResourceServer(iss, jwks, audience, scopes);
}

/// Descope. The issuer is `https://api.descope.com/{projectId}`; JWKS is at
/// `https://api.descope.com/{projectId}/.well-known/jwks.json`.
ResourceServerConfig descope(string projectId, string audience, string[] scopes = [
]) @safe
{
	const issuer = "https://api.descope.com/" ~ projectId;
	const jwks = issuer ~ "/.well-known/jwks.json";
	return jwtResourceServer(issuer, jwks, audience, scopes);
}

/// Scalekit. The `envUrl` is the environment's issuer
/// (e.g. `https://your-env.scalekit.dev`); JWKS is at `{envUrl}/keys`.
ResourceServerConfig scalekit(string envUrl, string audience, string[] scopes = [
]) @safe
{
	const iss = stripTrailingSlash(envUrl);
	const jwks = iss ~ "/keys";
	return jwtResourceServer(iss, jwks, audience, scopes);
}

// ===========================================================================
// Bucket B — Non-DCR / opaque-token presets -> OAuthProxyConfig
// ===========================================================================

/// GitHub OAuth app. Fills in GitHub's fixed authorize/token endpoints; the IdP
/// has no DCR and issues opaque tokens, so the proxy fronts it. The author still
/// supplies a `tokenVerifier` (e.g. one that maps `/user` -> subject) and a
/// `baseUrl`/`resource` for the proxy surface.
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
	return cfg;
}

/// Google. Fills in Google's fixed authorize/token endpoints; Google has no DCR,
/// so the proxy fronts it. The author supplies a `tokenVerifier` plus the proxy
/// `baseUrl`/`resource`.
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
	return cfg;
}

// ===========================================================================
// Tests — per-provider known constants, no live network.
// ===========================================================================

unittest  // Entra ID pins the v2.0 issuer, the discovery JWKS, and audience/scopes
{
	auto cfg = entraId("11111111-2222-3333-4444-555555555555", "api://my-mcp-server", [
		"mcp.read"
	]);
	assert(cfg.enabled);
	assert(cfg.resource == "api://my-mcp-server");
	assert(cfg.authorizationServers
			== [
				"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
	]);
	assert(cfg.scopesSupported == ["mcp.read"]);
}

unittest  // Auth0 pins the trailing-slash issuer and the /.well-known/jwks.json URI
{
	auto cfg = auth0("my-tenant.us.auth0.com", "https://api.example.com");
	assert(cfg.enabled);
	assert(cfg.resource == "https://api.example.com");
	assert(cfg.authorizationServers == ["https://my-tenant.us.auth0.com/"]);
}

unittest  // Auth0 tolerates a domain supplied with a trailing slash
{
	auto cfg = auth0("my-tenant.us.auth0.com/", "https://api.example.com");
	assert(cfg.authorizationServers == ["https://my-tenant.us.auth0.com/"]);
}

unittest  // WorkOS AuthKit uses the AuthKit domain as the issuer
{
	auto cfg = workosAuthKit("https://example.authkit.app", "client-abc", [
		"openid"
	]);
	assert(cfg.enabled);
	assert(cfg.resource == "client-abc");
	assert(cfg.authorizationServers == ["https://example.authkit.app"]);
	assert(cfg.scopesSupported == ["openid"]);
}

unittest  // Descope builds the api.descope.com project issuer
{
	auto cfg = descope("P2abc123", "my-audience");
	assert(cfg.enabled);
	assert(cfg.authorizationServers == ["https://api.descope.com/P2abc123"]);
	assert(cfg.resource == "my-audience");
}

unittest  // Scalekit uses the environment URL as the issuer
{
	auto cfg = scalekit("https://myenv.scalekit.dev", "skc_audience");
	assert(cfg.enabled);
	assert(cfg.authorizationServers == ["https://myenv.scalekit.dev"]);
	assert(cfg.resource == "skc_audience");
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

unittest  // entraId rejects pseudo-tenant "common" at call time to prevent silent failures
{
	import std.exception : assertThrown;

	assertThrown(entraId("common", "api://my-app"));
}

unittest  // entraId rejects pseudo-tenant "organizations" at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("organizations", "api://my-app"));
}

unittest  // entraId rejects pseudo-tenant "consumers" at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("consumers", "api://my-app"));
}

unittest  // entraId rejects an empty tenant string at call time
{
	import std.exception : assertThrown;

	assertThrown(entraId("", "api://my-app"));
}

unittest  // a JWT preset wires a working validator that rejects garbage tokens
{
	// No live network: the validator parses the bearer and fails closed on junk.
	auto cfg = entraId("tenant", "api://x");
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

	auto cfg = resourceServer(vc);
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
	vc.audience = "api://x";
	auto cfg = resourceServer(vc);
	assert(cfg.enabled);
	assert(cfg.resource == "api://x");
	assert(cfg.authorizationServers.length == 0);
}

unittest  // the public jwtResourceServer one-liner produces a protected config
{
	auto cfg = jwtResourceServer("https://issuer.example",
			"https://issuer.example/jwks", "https://mcp.example.com/mcp", [
				"mcp:read"
	]);
	assert(cfg.enabled);
	assert(cfg.resource == "https://mcp.example.com/mcp");
	assert(cfg.authorizationServers == ["https://issuer.example"]);
	assert(cfg.scopesSupported == ["mcp:read"]);
	assert(cfg.validator !is null);
}
