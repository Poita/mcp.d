/// A server-side OAuth provider that fronts an upstream OAuth identity provider
/// which does NOT support Dynamic Client Registration (GitHub, Google, Azure,
/// etc.). It is the D analogue of FastMCP's `OAuthProxy`.
///
/// The proxy presents a full DCR-capable OAuth surface to MCP clients — RFC 9728
/// Protected Resource Metadata, RFC 8414 Authorization Server Metadata, and an
/// RFC 7591 Dynamic Client Registration endpoint — while transparently using a
/// single set of fixed upstream client credentials with the real IdP. MCP
/// clients (including this SDK's own `OAuthClient`, which insists on DCR) can
/// therefore complete an authorization-code + PKCE flow against an upstream that
/// has no DCR support at all.
///
/// Concretely the proxy:
///   * advertises its own `/authorize`, `/token`, and `/register` endpoints in
///     the AS metadata it publishes (RFC 8414), so clients discover the proxy
///     rather than the upstream;
///   * answers DCR (`/register`) by handing every client the same fixed upstream
///     `client_id` (RFC 7591 §3.2.1), recording the client's dynamic redirect
///     URI so it can be honoured after the upstream round-trip;
///   * proxies `/authorize` by redirecting to the upstream authorization
///     endpoint with the fixed upstream `client_id` and the proxy's own fixed
///     callback URL (`base_url` + `redirect_path`);
///   * proxies `/token` by exchanging the code at the upstream token endpoint
///     using the fixed upstream credentials;
///   * maps the upstream access token to a `TokenInfo` via a configured
///     `TokenValidator` (e.g. `introspectionVerifier`, `jwtVerifier`, or
///     `staticVerifier`), so it plugs into `ResourceServerConfig.validator`.
///
/// The pure builders (`registrationResponseJson`, `authorizationServerMetadata`,
/// `proxyAuthorizeUrl`, `proxyTokenForm`) carry no HTTP or clock state so they
/// are unit-testable with a mocked upstream.
module mcp.auth.oauth_proxy;

import std.string : endsWith, startsWith;

import vibe.data.json : Json;

import mcp.auth.oauth : AuthorizationServerMetadata, ProtectedResourceMetadata, RegisteredClient,
	TokenEndpointAuthMethod, basicAuthHeader, buildAuthCodeTokenForm, buildAuthorizationUrl;
import mcp.auth.resource_server : TokenInfo, TokenValidator;

@safe:

// ===========================================================================
// Configuration
// ===========================================================================

/// Configuration for an `OAuthProxy`.
struct OAuthProxyConfig
{
	/// The upstream IdP's authorization endpoint (e.g.
	/// `https://github.com/login/oauth/authorize`). Clients are redirected here.
	string upstreamAuthorizationEndpoint;

	/// The upstream IdP's token endpoint (e.g.
	/// `https://github.com/login/oauth/access_token`). The proxy exchanges codes
	/// here using the fixed upstream credentials.
	string upstreamTokenEndpoint;

	/// The fixed upstream `client_id` of the OAuth application pre-registered
	/// with the IdP. Handed to every MCP client at DCR time.
	string upstreamClientId;

	/// The fixed upstream `client_secret`. May be empty for public PKCE clients.
	string upstreamClientSecret;

	/// How the proxy authenticates to the upstream token endpoint. Defaults to
	/// `client_secret_post` (credentials in the form body); set to
	/// `client_secret_basic` to send them via the HTTP Basic header.
	TokenEndpointAuthMethod tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;

	/// The proxy's own public base URL, including any mount path
	/// (e.g. `https://mcp.example.com`). Used to construct the proxy's fixed
	/// callback URL and as the issuer in the AS metadata it publishes.
	string baseUrl;

	/// The path on the proxy at which the upstream redirects back after
	/// authorization. Combined with `baseUrl` to form the fixed upstream
	/// redirect URI. Defaults to `/auth/callback`.
	string redirectPath = "/auth/callback";

	/// The path on the proxy at which the user-consent screen is served and the
	/// consent-approval action is handled (confused-deputy mitigation). A
	/// dynamically-registered client is not forwarded to the upstream until the
	/// user approves it here. Defaults to `/consent`.
	string consentPath = "/consent";

	/// The scopes advertised in the metadata documents the proxy publishes.
	string[] scopesSupported;

	/// Validates an upstream access token, mapping it to a `TokenInfo`. Plug in
	/// `introspectionVerifier`, `jwtVerifier`, or `staticVerifier`. Required to
	/// enforce auth on incoming MCP requests.
	TokenValidator tokenVerifier;

	/// The RFC 8707 canonical resource identifier of the MCP server, advertised
	/// in the PRM document and forwarded to the upstream as the `resource`
	/// parameter so issued tokens are audience-bound to this server.
	string resource;

	/// The proxy's fixed upstream redirect URI (`baseUrl` + `redirectPath`),
	/// registered with the IdP.
	string callbackUrl() const @safe
	{
		string b = baseUrl;
		if (b.endsWith("/"))
			b = b[0 .. $ - 1];
		string p = redirectPath;
		if (p.length && !p.startsWith("/"))
			p = "/" ~ p;
		return b ~ p;
	}

	/// The proxy's own authorization endpoint (what it advertises to clients).
	string authorizeEndpoint() const @safe
	{
		return joinUrl(baseUrl, "/authorize");
	}

	/// The proxy's own token endpoint.
	string tokenEndpoint() const @safe
	{
		return joinUrl(baseUrl, "/token");
	}

	/// The proxy's own DCR registration endpoint.
	string registrationEndpoint() const @safe
	{
		return joinUrl(baseUrl, "/register");
	}

	/// The proxy's own consent endpoint (the confused-deputy consent screen +
	/// approval action). Not advertised in OAuth metadata; used by the HTTP mount.
	string consentEndpoint() const @safe
	{
		string cp = consentPath;
		if (cp.length && !cp.startsWith("/"))
			cp = "/" ~ cp;
		return joinUrl(baseUrl, cp);
	}
}

private string joinUrl(string base, string path) @safe
{
	auto b = base;
	if (b.endsWith("/"))
		b = b[0 .. $ - 1];
	return b ~ path;
}

// ===========================================================================
// Metadata surface presented to MCP clients
// ===========================================================================

/// The RFC 8414 Authorization Server Metadata the proxy publishes. It advertises
/// the proxy's own `/authorize`, `/token`, and `/register` endpoints (NOT the
/// upstream's), mandates PKCE S256, and lists the supported scopes. Because a
/// `registration_endpoint` is present, MCP clients select Dynamic Client
/// Registration and obtain the fixed upstream credentials transparently.
AuthorizationServerMetadata authorizationServerMetadata(const OAuthProxyConfig cfg) @safe
{
	AuthorizationServerMetadata m;
	m.issuer = stripTrailingSlash(cfg.baseUrl);
	m.authorizationEndpoint = cfg.authorizeEndpoint();
	m.tokenEndpoint = cfg.tokenEndpoint();
	m.registrationEndpoint = cfg.registrationEndpoint();
	m.codeChallengeMethodsSupported = ["S256"];
	m.scopesSupported = cfg.scopesSupported.dup;
	m.grantTypesSupported = ["authorization_code", "refresh_token"];
	m.tokenEndpointAuthMethodsSupported = ["none"];
	return m;
}

/// The RFC 9728 Protected Resource Metadata the proxy publishes: it names the
/// proxy itself as the sole authorization server for the MCP resource.
ProtectedResourceMetadata protectedResourceMetadata(const OAuthProxyConfig cfg) @safe
{
	ProtectedResourceMetadata m;
	m.resource = cfg.resource;
	m.authorizationServers = [stripTrailingSlash(cfg.baseUrl)];
	m.scopesSupported = cfg.scopesSupported.dup;
	return m;
}

/// Serialize the RFC 8414 AS metadata document the proxy serves at
/// `/.well-known/oauth-authorization-server`. Emits the proxy endpoints,
/// `code_challenge_methods_supported`, `grant_types_supported`,
/// `token_endpoint_auth_methods_supported`, and (when non-empty)
/// `scopes_supported`.
Json authorizationServerMetadataJson(const OAuthProxyConfig cfg) @safe
{
	auto m = authorizationServerMetadata(cfg);
	Json j = Json.emptyObject;
	j["issuer"] = m.issuer;
	j["authorization_endpoint"] = m.authorizationEndpoint;
	j["token_endpoint"] = m.tokenEndpoint;
	j["registration_endpoint"] = m.registrationEndpoint;
	j["code_challenge_methods_supported"] = strArray(m.codeChallengeMethodsSupported);
	j["grant_types_supported"] = strArray(m.grantTypesSupported);
	j["token_endpoint_auth_methods_supported"] = strArray(m.tokenEndpointAuthMethodsSupported);
	if (m.scopesSupported.length)
		j["scopes_supported"] = strArray(m.scopesSupported);
	return j;
}

private Json strArray(const string[] xs) @safe
{
	Json a = Json.emptyArray;
	foreach (x; xs)
		a ~= Json(x);
	return a;
}

private string stripTrailingSlash(string s) @safe
{
	return s.endsWith("/") ? s[0 .. $ - 1] : s;
}

// ===========================================================================
// Dynamic Client Registration (RFC 7591) — fixed-credential response
// ===========================================================================

/// Build the RFC 7591 §3.2.1 registration result for a DCR request: the proxy
/// returns the SAME fixed upstream `client_id` to every client. The proxy never
/// discloses the upstream secret — clients act as public PKCE clients.
RegisteredClient registrationResult(const OAuthProxyConfig cfg) @safe
{
	RegisteredClient c;
	c.clientId = cfg.upstreamClientId;
	c.clientSecret = null;
	return c;
}

/// Serialize the DCR registration response document (RFC 7591 §3.2.1). Always
/// carries `client_id` and echoes the requested `redirect_uris` and
/// `token_endpoint_auth_method=none` (public client).
Json registrationResponseJson(const OAuthProxyConfig cfg, const string[] requestedRedirectUris) @safe
{
	Json j = Json.emptyObject;
	j["client_id"] = cfg.upstreamClientId;
	j["token_endpoint_auth_method"] = "none";
	Json ru = Json.emptyArray;
	foreach (u; requestedRedirectUris)
		ru ~= Json(u);
	j["redirect_uris"] = ru;
	Json gt = Json.emptyArray;
	gt ~= Json("authorization_code");
	gt ~= Json("refresh_token");
	j["grant_types"] = gt;
	Json rt = Json.emptyArray;
	rt ~= Json("code");
	j["response_types"] = rt;
	return j;
}

// ===========================================================================
// Authorize proxying
// ===========================================================================

/// Build the upstream authorization redirect URL for a proxied `/authorize`
/// request. The proxy substitutes its OWN fixed upstream `client_id` and fixed
/// callback URL, forwarding the client-supplied PKCE `code_challenge`, scope,
/// state, and (RFC 8707) resource. The client's real `redirect_uri` is NOT sent
/// upstream — the proxy receives the code at its fixed callback and relays it.
string proxyAuthorizeUrl(const OAuthProxyConfig cfg, string codeChallenge,
		string scopeStr, string state) @safe
{
	return buildAuthorizationUrl(cfg.upstreamAuthorizationEndpoint, cfg.upstreamClientId,
			cfg.callbackUrl(), codeChallenge, scopeStr, cfg.resource, state);
}

// ===========================================================================
// Token proxying
// ===========================================================================

/// Build the `application/x-www-form-urlencoded` body for the upstream
/// authorization-code token exchange. Uses the proxy's fixed upstream
/// `client_id`, fixed callback `redirect_uri`, the client-supplied PKCE
/// `code_verifier`, and (RFC 8707) `resource`. For `client_secret_post` the
/// upstream secret is appended to the body; for `client_secret_basic` it is sent
/// via `proxyTokenAuthHeader` instead.
string proxyTokenForm(const OAuthProxyConfig cfg, string code, string codeVerifier) @safe
{
	const secretForPost = cfg.tokenEndpointAuthMethod
		== TokenEndpointAuthMethod.clientSecretPost ? cfg.upstreamClientSecret : "";
	return buildAuthCodeTokenForm(code, cfg.callbackUrl(), codeVerifier,
			cfg.upstreamClientId, cfg.resource, secretForPost);
}

/// The HTTP `Authorization` header value to use for the upstream token request,
/// or null when no Basic auth applies (i.e. the method is not
/// `client_secret_basic`, or no secret is configured).
string proxyTokenAuthHeader(const OAuthProxyConfig cfg) @safe
{
	if (cfg.tokenEndpointAuthMethod == TokenEndpointAuthMethod.clientSecretBasic
			&& cfg.upstreamClientSecret.length)
		return basicAuthHeader(cfg.upstreamClientId, cfg.upstreamClientSecret);
	return null;
}

// ===========================================================================
// Consent gate (confused-deputy mitigation)
// ===========================================================================

/// Records that a user has approved a particular dynamically-registered client
/// to be forwarded to the upstream identity provider, and answers whether a
/// given client has already been approved.
///
/// Because the proxy hands every DCR client the SAME fixed upstream
/// `client_id`, the upstream IdP can see only one client and may auto-skip its
/// own consent screen for that already-trusted application. The MCP
/// authorization spec (2025-06-18 / 2025-11-25 §Security Considerations >
/// Confused Deputy Problem) therefore requires:
///
///   "MCP proxy servers using static client IDs MUST obtain user consent for
///    each dynamically registered client before forwarding to third-party
///    authorization servers (which may require additional consent)."
///
/// The proxy distinguishes dynamically-registered clients by their
/// client-supplied `redirect_uri` (the only per-client identity it holds, since
/// the `client_id` is shared). An integrator records consent for a
/// `redirect_uri` once the user has approved that client on the proxy's own
/// consent screen; `OAuthProxy.authorize` then refuses to build the upstream
/// redirect until consent for that `redirect_uri` is present.
interface ConsentStore
{
	bool hasConsent(string clientRedirectUri) @safe;

	void grantConsent(string clientRedirectUri) @safe;
}

/// A simple in-memory `ConsentStore`. Suitable for a single-process proxy; for
/// a multi-process deployment back it with shared storage instead.
final class InMemoryConsentStore : ConsentStore
{
	private bool[string] approved;

	override bool hasConsent(string clientRedirectUri) @safe
	{
		return (clientRedirectUri in approved) !is null;
	}

	override void grantConsent(string clientRedirectUri) @safe
	{
		approved[clientRedirectUri] = true;
	}
}

/// Thrown by `OAuthProxy.authorize` when the dynamically-registered client
/// (identified by its `redirect_uri`) has not yet been granted user consent.
/// The integrator must present a consent screen, record approval via
/// `OAuthProxy.grantConsent`, and only then build the upstream redirect. This
/// enforces the confused-deputy MUST: consent is obtained for each dynamically
/// registered client before forwarding to the upstream authorization server.
class ConsentRequiredException : Exception
{
	string clientRedirectUri;

	this(string clientRedirectUri, string file = __FILE__, size_t line = __LINE__) @safe
	{
		super("user consent required before forwarding client '" ~ clientRedirectUri
				~ "' to the upstream authorization server (confused-deputy mitigation)", file, line);
		this.clientRedirectUri = clientRedirectUri;
	}
}

// ===========================================================================
// The proxy provider
// ===========================================================================

/// A reusable OAuth proxy provider. Construct it from an `OAuthProxyConfig`, then
/// read the metadata surface to publish, drive the authorize/token proxying, and
/// obtain a `TokenValidator` for `ResourceServerConfig.validator`.
final class OAuthProxy
{
	private OAuthProxyConfig cfg;
	private ConsentStore consentStore;

	this(OAuthProxyConfig cfg) @safe
	{
		this(cfg, new InMemoryConsentStore());
	}

	/// Construct with an explicit `ConsentStore` (e.g. a shared-storage backed
	/// store for a multi-process deployment). The store records which
	/// dynamically-registered clients (keyed by their `redirect_uri`) the user
	/// has approved, so `authorize` can enforce the confused-deputy consent MUST.
	this(OAuthProxyConfig cfg, ConsentStore consentStore) @safe
	in (consentStore !is null)
	{
		this.cfg = cfg;
		this.consentStore = consentStore;
	}

	/// The proxy's configuration.
	const(OAuthProxyConfig) config() const @safe
	{
		return cfg;
	}

	/// The RFC 8414 AS metadata document to serve at the well-known path.
	Json metadataJson() const @safe
	{
		return authorizationServerMetadataJson(cfg);
	}

	/// The RFC 9728 PRM document to serve at the protected-resource well-known.
	ProtectedResourceMetadata resourceMetadata() const @safe
	{
		return protectedResourceMetadata(cfg);
	}

	/// Handle a DCR (`/register`) request: return the registration response for
	/// the given client `redirect_uris`.
	Json register(const string[] requestedRedirectUris) const @safe
	{
		return registrationResponseJson(cfg, requestedRedirectUris);
	}

	/// Whether the dynamically-registered client identified by its
	/// `clientRedirectUri` has already been granted user consent to be forwarded
	/// to the upstream identity provider.
	bool hasConsent(string clientRedirectUri) @safe
	{
		return consentStore.hasConsent(clientRedirectUri);
	}

	/// Record that the user has approved the dynamically-registered client
	/// identified by its `clientRedirectUri`. Call this once the user approves on
	/// the proxy's own consent screen; subsequent `authorize` calls for that
	/// client will then be allowed to forward to the upstream IdP.
	void grantConsent(string clientRedirectUri) @safe
	{
		consentStore.grantConsent(clientRedirectUri);
	}

	/// Build the upstream authorization redirect for a proxied `/authorize`,
	/// gated on per-client user consent (confused-deputy mitigation).
	///
	/// The MCP authorization spec requires that a proxy using a static upstream
	/// `client_id` obtain user consent for EACH dynamically-registered client
	/// before forwarding it to the third-party authorization server. This
	/// overload enforces that: it throws `ConsentRequiredException` unless the
	/// client (identified by its `clientRedirectUri`, the per-client identity the
	/// proxy holds since the `client_id` is shared) has been approved via
	/// `grantConsent`. The integrator presents a consent screen, records approval,
	/// then retries.
	string authorize(string clientRedirectUri, string codeChallenge, string scopeStr, string state) @safe
	{
		if (!consentStore.hasConsent(clientRedirectUri))
			throw new ConsentRequiredException(clientRedirectUri);
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Build the upstream authorization redirect WITHOUT a per-client consent
	/// gate. Provided for flows that do their own consent enforcement (or a
	/// fixed, non-DCR client). For dynamically-registered clients prefer the
	/// four-argument `authorize` overload, which enforces the confused-deputy
	/// consent MUST.
	string authorize(string codeChallenge, string scopeStr, string state) const @safe
	{
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Build the upstream token-exchange form for a proxied `/token`.
	string tokenForm(string code, string codeVerifier) const @safe
	{
		return proxyTokenForm(cfg, code, codeVerifier);
	}

	/// The optional Basic-auth header for the upstream token request.
	string tokenAuthHeader() const @safe
	{
		return proxyTokenAuthHeader(cfg);
	}

	/// A `TokenValidator` that validates an incoming MCP bearer token (an
	/// upstream access token) via the configured `tokenVerifier`. Plug into
	/// `ResourceServerConfig.validator`.
	TokenValidator validator() @safe
	{
		auto verifier = cfg.tokenVerifier;
		if (verifier is null)
			return (string t) => TokenInfo.invalid();
		return verifier;
	}
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	private OAuthProxyConfig sampleConfig() @safe
	{
		OAuthProxyConfig cfg;
		cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
		cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
		cfg.upstreamClientId = "Iv1.upstream";
		cfg.upstreamClientSecret = "upstream-secret";
		cfg.baseUrl = "https://mcp.example.com";
		cfg.scopesSupported = ["read:user", "repo"];
		cfg.resource = "https://mcp.example.com/mcp";
		return cfg;
	}
}

unittest  // callback URL joins base_url and the default redirect path
{
	auto cfg = sampleConfig();
	assert(cfg.callbackUrl() == "https://mcp.example.com/auth/callback");
}

unittest  // callback URL normalizes trailing slash on base + missing leading slash on path
{
	OAuthProxyConfig cfg;
	cfg.baseUrl = "https://mcp.example.com/";
	cfg.redirectPath = "cb";
	assert(cfg.callbackUrl() == "https://mcp.example.com/cb");
}

unittest  // AS metadata advertises the PROXY endpoints, not the upstream's
{
	auto cfg = sampleConfig();
	auto m = authorizationServerMetadata(cfg);
	assert(m.issuer == "https://mcp.example.com");
	assert(m.authorizationEndpoint == "https://mcp.example.com/authorize");
	assert(m.tokenEndpoint == "https://mcp.example.com/token");
	assert(m.registrationEndpoint == "https://mcp.example.com/register");
}

unittest  // AS metadata mandates PKCE S256
{
	auto cfg = sampleConfig();
	assert(authorizationServerMetadata(cfg).supportsS256);
}

unittest  // AS metadata JSON carries the proxy endpoints + PKCE + scopes
{
	auto cfg = sampleConfig();
	auto j = authorizationServerMetadataJson(cfg);
	assert(j["issuer"].get!string == "https://mcp.example.com");
	assert(j["authorization_endpoint"].get!string == "https://mcp.example.com/authorize");
	assert(j["token_endpoint"].get!string == "https://mcp.example.com/token");
	assert(j["registration_endpoint"].get!string == "https://mcp.example.com/register");
	assert(j["code_challenge_methods_supported"][0].get!string == "S256");
	assert(j["scopes_supported"].length == 2);
}

unittest  // AS metadata JSON omits scopes_supported when none configured
{
	OAuthProxyConfig cfg;
	cfg.baseUrl = "https://mcp.example.com";
	auto j = authorizationServerMetadataJson(cfg);
	assert("scopes_supported" !in j);
}

unittest  // PRM names the proxy itself as the authorization server
{
	auto cfg = sampleConfig();
	auto m = protectedResourceMetadata(cfg);
	assert(m.resource == "https://mcp.example.com/mcp");
	assert(m.authorizationServers == ["https://mcp.example.com"]);
}

unittest  // DCR returns the FIXED upstream client_id to every client (no secret)
{
	auto cfg = sampleConfig();
	auto c = registrationResult(cfg);
	assert(c.clientId == "Iv1.upstream");
	assert(c.clientSecret is null);
}

unittest  // DCR response JSON echoes the client's redirect_uris and is a public client
{
	auto cfg = sampleConfig();
	auto j = registrationResponseJson(cfg, ["http://localhost:5000/callback"]);
	assert(j["client_id"].get!string == "Iv1.upstream");
	assert(j["token_endpoint_auth_method"].get!string == "none");
	assert(j["redirect_uris"][0].get!string == "http://localhost:5000/callback");
	assert(j["grant_types"][0].get!string == "authorization_code");
}

unittest  // proxied /authorize redirects to the UPSTREAM with the fixed client_id + callback
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto url = proxyAuthorizeUrl(cfg, "CHALLENGE", "read:user", "state-123");
	assert(url.startsWith("https://github.com/login/oauth/authorize?"));
	assert(url.canFind("client_id=Iv1.upstream"));
	assert(url.canFind("redirect_uri=https%3A%2F%2Fmcp.example.com%2Fauth%2Fcallback"));
	assert(url.canFind("code_challenge=CHALLENGE"));
	assert(url.canFind("code_challenge_method=S256"));
	assert(url.canFind("scope=read%3Auser"));
	assert(url.canFind("state=state-123"));
	assert(url.canFind("resource=https%3A%2F%2Fmcp.example.com%2Fmcp"));
}

unittest  // proxied /token exchanges the code upstream with fixed creds (client_secret_post)
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;
	auto form = proxyTokenForm(cfg, "AUTHCODE", "VERIFIER");
	assert(form.canFind("grant_type=authorization_code"));
	assert(form.canFind("code=AUTHCODE"));
	assert(form.canFind("code_verifier=VERIFIER"));
	assert(form.canFind("client_id=Iv1.upstream"));
	assert(form.canFind("redirect_uri=https%3A%2F%2Fmcp.example.com%2Fauth%2Fcallback"));
	assert(form.canFind("client_secret=upstream-secret"));
	assert(proxyTokenAuthHeader(cfg) is null);
}

unittest  // for client_secret_basic the secret goes in the header, not the body
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretBasic;
	auto form = proxyTokenForm(cfg, "AUTHCODE", "VERIFIER");
	assert(!form.canFind("client_secret="));
	auto hdr = proxyTokenAuthHeader(cfg);
	assert(hdr !is null);
	assert(hdr.startsWith("Basic "));
	assert(hdr == basicAuthHeader("Iv1.upstream", "upstream-secret"));
}

unittest  // a public PKCE upstream (no secret) sends neither body secret nor Basic header
{
	auto cfg = sampleConfig();
	cfg.upstreamClientSecret = "";
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretBasic;
	assert(proxyTokenAuthHeader(cfg) is null);
}

unittest  // the proxy maps a validated upstream token to TokenInfo via tokenVerifier
{
	auto cfg = sampleConfig();
	cfg.tokenVerifier = (string t) {
		TokenInfo ti;
		ti.valid = t == "good-upstream-token";
		ti.subject = "octocat";
		ti.scopes = ["read:user"];
		ti.audience = ["https://mcp.example.com/mcp"];
		return ti;
	};
	auto proxy = new OAuthProxy(cfg);
	auto v = proxy.validator();
	assert(v !is null);
	auto ok = v("good-upstream-token");
	assert(ok.valid);
	assert(ok.subject == "octocat");
	assert(ok.hasScope("read:user"));
	assert(!v("bad-token").valid);
}

unittest  // with no tokenVerifier configured the proxy rejects every token
{
	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	auto v = proxy.validator();
	assert(v !is null);
	assert(!v("anything").valid);
}

unittest  // the OAuthProxy class exposes the full client-facing surface end to end
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);

	auto md = proxy.metadataJson();
	assert(md["registration_endpoint"].get!string == "https://mcp.example.com/register");
	auto reg = proxy.register(["http://127.0.0.1:8765/cb"]);
	assert(reg["client_id"].get!string == "Iv1.upstream");

	auto authUrl = proxy.authorize("CH", "read:user", "S");
	assert(authUrl.startsWith("https://github.com/login/oauth/authorize?"));

	auto form = proxy.tokenForm("CODE", "VER");
	assert(form.canFind("client_id=Iv1.upstream"));
}

unittest  // CONFUSED DEPUTY: gated authorize refuses to forward an un-consented client
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	// No consent recorded yet for this dynamically-registered client.
	assertThrown!ConsentRequiredException(
			proxy.authorize("http://localhost:5000/callback", "CH", "read:user", "S"));
}

unittest  // CONFUSED DEPUTY: after grantConsent the gated authorize forwards upstream
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.grantConsent("http://localhost:5000/callback");
	auto url = proxy.authorize("http://localhost:5000/callback", "CH", "read:user", "S");
	assert(url.startsWith("https://github.com/login/oauth/authorize?"));
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // CONFUSED DEPUTY: consent is per-client (one approval does not cover another)
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.grantConsent("http://localhost:5000/callback");
	assert(proxy.hasConsent("http://localhost:5000/callback"));
	assert(!proxy.hasConsent("http://localhost:6000/callback"));
	assertThrown!ConsentRequiredException(
			proxy.authorize("http://localhost:6000/callback", "CH", "read:user", "S"));
}

unittest  // CONFUSED DEPUTY: the exception names the client redirect_uri needing consent
{
	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	bool threw = false;
	try
		proxy.authorize("http://localhost:7000/cb", "CH", "s", "S");
	catch (ConsentRequiredException e)
	{
		threw = true;
		assert(e.clientRedirectUri == "http://localhost:7000/cb");
	}
	assert(threw);
}

unittest  // InMemoryConsentStore records and reports per-redirect-uri consent
{
	ConsentStore store = new InMemoryConsentStore();
	assert(!store.hasConsent("http://a/cb"));
	store.grantConsent("http://a/cb");
	assert(store.hasConsent("http://a/cb"));
	assert(!store.hasConsent("http://b/cb"));
}

unittest  // a custom ConsentStore can be injected and is consulted by authorize
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto store = new InMemoryConsentStore();
	store.grantConsent("http://localhost:9000/cb");
	auto proxy = new OAuthProxy(cfg, store);
	auto url = proxy.authorize("http://localhost:9000/cb", "CH", "read:user", "S");
	assert(url.canFind("client_id=Iv1.upstream"));
}
