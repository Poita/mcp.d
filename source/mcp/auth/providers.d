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
import mcp.auth.oauth_proxy : IssueTokenHook, OAuthProxyConfig;
import mcp.auth.reference_token : ReferenceTokenStore;
import mcp.auth.resource_server : ResourceServerConfig;

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
	/// for IdPs that honor the RFC 8707 resource indicator.
	string audience;
	/// Scopes required on every token, also advertised as `scopes_supported`.
	string[] scopes;
}

/// Build a `ResourceServerConfig` for a JWT/JWKS IdP in one call: pins `issuer` +
/// `jwksUri` + the audience + required scopes on a `jwtVerifier`, and fills the
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
	cfg.validator = vc.audience.length ? bindResourceAudience(jwtVerifier(vc),
			resource) : jwtVerifier(vc);
	cfg.resource = resource;
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
/// (`/discovery/v2.0/keys`). `opts.audience` is typically the API's App ID URI
/// or client id.
///
/// `tenant` must be a concrete tenant GUID or a registered domain name.
/// The pseudo-tenants `"common"`, `"organizations"`, and `"consumers"` are
/// rejected because Entra ID never stamps them in the `iss` claim of a real
/// token — every token would fail the issuer check at runtime. For a
/// multi-tenant app, list the tenants it serves with `entraIdTenants`.
ResourceServerConfig entraId(string tenant, JwtPresetOptions opts) @safe
{
	requireConcreteEntraTenant(tenant, "entraId");
	const issuer = "https://login.microsoftonline.com/" ~ tenant ~ "/v2.0";
	const jwks = "https://login.microsoftonline.com/" ~ tenant ~ "/discovery/v2.0/keys";
	return jwtResourceServer(issuer, jwks, opts);
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
	return cfg;
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
/// supplies a `tokenVerifier` and a `baseUrl`/`resource` for the proxy surface.
/// Defaults to passthrough; a server that calls GitHub's API with the issued
/// token should chain `.brokered(...)` to switch to issue-own-token mode.
///
/// GitHub tokens carry no audience, so the preset sets
/// `verifierBindsResource`: every token the `tokenVerifier` accepts is treated as
/// issued for `resource`. The verifier must therefore confirm the token belongs
/// to this OAuth app (`POST /applications/{client_id}/token`), not merely that
/// it is a live GitHub token (`GET /user` accepts any user's token).
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
	return cfg;
}

/// Google. Fills in Google's fixed authorize/token endpoints; Google has no DCR,
/// so the proxy fronts it. The author supplies a `tokenVerifier` plus the proxy
/// `baseUrl`/`resource`. Defaults to passthrough; a server that calls Google's
/// API with the issued token should chain `.brokered(...)` to switch to
/// issue-own-token mode.
///
/// Google access tokens are opaque to the resource server, so the preset sets
/// `verifierBindsResource`: every token the `tokenVerifier` accepts is treated as
/// issued for `resource`. The verifier must therefore confirm the token was
/// issued to `clientId` (the `aud`/`azp` returned by Google's tokeninfo
/// endpoint), not merely that it is a live Google token.
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
	return cfg;
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
	assertThrown(entraIdTenants(["tenant-a", "common"], JwtPresetOptions(mcpUrl)));
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
	vc.audience = "api://x";
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
