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

import std.string : endsWith, indexOf, startsWith;

import vibe.data.json : Json;

import mcp.auth.oauth : AuthorizationServerMetadata, ProtectedResourceMetadata,
	RegisteredClient, TokenEndpointAuthMethod,
	basicAuthHeader, buildAuthCodeTokenForm,
	buildAuthorizationUrl, buildRefreshTokenForm, requireSecureUrl;
import mcp.auth.resource_server : ResourceServerConfig, TokenInfo, TokenValidator;

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

	/// Collapse this proxy config into the single `auth` object the transport
	/// accepts (`StreamableHttpOptions.auth` / `mountMcp`), so an `OAuthProxy`
	/// preset flows through the same one entry point as `jwtResourceServer` and
	/// the JWKS presets — no re-typing of resource/scopes. The `validator` is the
	/// configured `tokenVerifier` (fails closed when none is set); the proxy's own
	/// `baseUrl` is advertised as the sole authorization server (it fronts the
	/// upstream IdP), and `resource`/`scopesSupported` are mirrored.
	ResourceServerConfig toResourceServer() const @safe
	{
		ResourceServerConfig rs;
		rs.validator = tokenVerifier !is null ? tokenVerifier : (string t) => TokenInfo.invalid();
		rs.resource = resource;
		if (baseUrl.length)
			rs.authorizationServers = [stripTrailingSlash(baseUrl)];
		rs.scopesSupported = scopesSupported.dup;
		return rs;
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
	m.responseTypesSupported = ["code"];
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
/// `response_types_supported` (RFC 8414 §2 REQUIRED when
/// `authorization_endpoint` is present), `code_challenge_methods_supported`,
/// `grant_types_supported`, `token_endpoint_auth_methods_supported`, and
/// (when non-empty) `scopes_supported`.
Json authorizationServerMetadataJson(const OAuthProxyConfig cfg) @safe
{
	auto m = authorizationServerMetadata(cfg);
	Json j = Json.emptyObject;
	j["issuer"] = m.issuer;
	j["authorization_endpoint"] = m.authorizationEndpoint;
	j["token_endpoint"] = m.tokenEndpoint;
	j["registration_endpoint"] = m.registrationEndpoint;
	j["code_challenge_methods_supported"] = strArray(m.codeChallengeMethodsSupported);
	j["response_types_supported"] = strArray(m.responseTypesSupported);
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

/// Build the `application/x-www-form-urlencoded` body for an upstream
/// refresh-token exchange (OAuth 2.1 §4.3 / RFC 6749 §6). Carries
/// `grant_type=refresh_token`, the client-relayed `refresh_token`, the proxy's
/// fixed upstream `client_id`, and (RFC 8707) `resource`. For
/// `client_secret_post` the upstream secret is appended to the body; for
/// `client_secret_basic` it is sent via `proxyTokenAuthHeader` instead.
string proxyRefreshTokenForm(const OAuthProxyConfig cfg, string refreshToken) @safe
{
	const secretForPost = cfg.tokenEndpointAuthMethod
		== TokenEndpointAuthMethod.clientSecretPost ? cfg.upstreamClientSecret : "";
	return buildRefreshTokenForm(refreshToken, cfg.upstreamClientId, cfg.resource, secretForPost);
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
// Redirect-URI registration + validation (RFC 6749 §3.1.2.2 / §10.6, RFC 8252)
// ===========================================================================

/// Whether a client `redirect_uri` uses a scheme the proxy is willing to relay an
/// authorization code to. `https` is always allowed; plain `http` is allowed only
/// for loopback hosts (`127.0.0.1`, `[::1]`, `localhost`) per RFC 8252 §7.3. All
/// other schemes (including `http` to a non-loopback host, and custom/private-use
/// schemes) are rejected so the upstream code can never be relayed over an
/// open-redirect-prone or interceptable channel.
bool isAllowedRedirectScheme(string redirectUri) @safe
{
	if (redirectUri.startsWith("https://"))
		return true;
	if (redirectUri.startsWith("http://"))
	{
		const host = hostOf(redirectUri["http://".length .. $]);
		return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
	}
	return false;
}

private string hostOf(string authorityAndRest) @safe
{
	auto s = authorityAndRest;
	const slash = s.indexOf('/');
	if (slash >= 0)
		s = s[0 .. slash];
	const at = s.indexOf('@');
	if (at >= 0)
		s = s[at + 1 .. $];
	if (s.startsWith("["))
	{
		const close = s.indexOf(']');
		if (close >= 0)
			return s[0 .. close + 1];
		return s;
	}
	const colon = s.indexOf(':');
	if (colon >= 0)
		s = s[0 .. colon];
	return s;
}

/// Records the exact set of `redirect_uris` a dynamically-registered client
/// presented at `/register`, keyed by a server-issued registration handle, and
/// answers whether a given `redirect_uri` is an exact member of that set. This is
/// the allowlist the proxy enforces at `/authorize` before relaying an upstream
/// authorization code.
/// Upper bound on the number of `redirect_uris` a single `/register` request may
/// register. An unauthenticated DCR request carrying more than this is truncated
/// to the first `maxRedirectUrisPerRegistration` entries so one request cannot
/// inflate the registry without bound.
enum size_t maxRedirectUrisPerRegistration = 10;

interface RedirectUriRegistry
{
	/// Persist the exact `redirect_uris` registered under `registrationHandle`.
	void register(string registrationHandle, const string[] redirectUris) @safe;

	/// Whether `redirectUri` is an exact-string member of ANY registered set.
	bool isRegistered(string redirectUri) @safe;
}

/// A simple in-memory `RedirectUriRegistry` bounded against unauthenticated
/// growth: each `/register` call is scoped under its server-issued
/// `registrationHandle`, and when the number of live registrations exceeds the
/// cap the oldest registration (and all its redirect URIs) is evicted as a unit.
/// The cap is what keeps an unauthenticated `POST /register` flood from growing
/// process memory without bound.
///
/// NOTE: even bounded, the unbounded-default in-memory backing is unsuitable for
/// an internet-exposed multi-process proxy: state is per-process and lost on
/// restart. Back it with shared, bounded storage (and gate `/register` behind the
/// integrator's auth or a rate limiter) for such deployments.
final class InMemoryRedirectUriRegistry : RedirectUriRegistry
{
	/// Maximum number of live registrations (one per `/register` call). When
	/// exceeded on `register`, the oldest registration is evicted as a whole.
	enum size_t defaultMaxRegistrations = 10_000;

	private string[][string] byHandle;
	private string[] order;
	private size_t[string] refCount;
	private const size_t maxRegistrations;

	this() @safe
	{
		this(defaultMaxRegistrations);
	}

	/// Construct with an explicit registration cap (used by tests to drive
	/// oldest-first eviction deterministically).
	this(size_t maxRegistrations) @safe
	{
		this.maxRegistrations = maxRegistrations;
	}

	override void register(string registrationHandle, const string[] redirectUris) @safe
	{
		string[] uris;
		foreach (u; redirectUris)
			uris ~= u;
		byHandle[registrationHandle] = uris;
		order ~= registrationHandle;
		foreach (u; uris)
			refCount[u] = (u in refCount ? refCount[u] : 0) + 1;
		enforceCap();
	}

	override bool isRegistered(string redirectUri) @safe
	{
		return (redirectUri in refCount) !is null;
	}

	private void enforceCap() @safe
	{
		while (order.length > maxRegistrations)
		{
			const oldest = order[0];
			order = order[1 .. $];
			if (auto p = oldest in byHandle)
			{
				foreach (u; *p)
				{
					if (auto c = u in refCount)
					{
						if (*c <= 1)
							refCount.remove(u);
						else
							*c = *c - 1;
					}
				}
				byHandle.remove(oldest);
			}
		}
	}
}

/// Thrown by `OAuthProxy.authorize` when the client-supplied `redirect_uri` is not
/// an exact match against a previously-registered `redirect_uri` (RFC 6749
/// §3.1.2.2 / §10.6) or uses a scheme that is not allowed (RFC 8252 §7.3). The
/// proxy fails closed: it neither mints proxy state nor forwards the request
/// upstream. An HTTP mount maps this to a `400 invalid_request`.
class InvalidRedirectUriException : Exception
{
	string redirectUri;

	this(string redirectUri, string reason, string file = __FILE__, size_t line = __LINE__) @safe
	{
		super("invalid redirect_uri '" ~ redirectUri ~ "': " ~ reason, file, line);
		this.redirectUri = redirectUri;
	}
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

/// A simple in-memory `ConsentStore` bounded against unauthenticated growth: the
/// number of approved clients is capped, evicting the oldest approval first when
/// the cap is reached, so the (otherwise insert-only) consent map cannot grow
/// process memory without bound.
///
/// NOTE: even bounded, this in-memory default is unsuitable for an
/// internet-exposed multi-process proxy: consent is per-process and lost on
/// restart. Back it with shared, bounded storage (and consider a consent TTL) for
/// such deployments.
final class InMemoryConsentStore : ConsentStore
{
	/// Maximum number of approved clients retained. When exceeded on
	/// `grantConsent`, the oldest approval is evicted.
	enum size_t defaultMaxApprovals = 10_000;

	private bool[string] approved;
	private string[] order;
	private const size_t maxApprovals;

	this() @safe
	{
		this(defaultMaxApprovals);
	}

	/// Construct with an explicit approval cap (used by tests to drive
	/// oldest-first eviction deterministically).
	this(size_t maxApprovals) @safe
	{
		this.maxApprovals = maxApprovals;
	}

	override bool hasConsent(string clientRedirectUri) @safe
	{
		return (clientRedirectUri in approved) !is null;
	}

	override void grantConsent(string clientRedirectUri) @safe
	{
		if (clientRedirectUri in approved)
			return;
		approved[clientRedirectUri] = true;
		order ~= clientRedirectUri;
		while (order.length > maxApprovals)
		{
			const oldest = order[0];
			order = order[1 .. $];
			approved.remove(oldest);
		}
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
	private RedirectUriRegistry redirectRegistry;

	this(OAuthProxyConfig cfg) @safe
	{
		this(cfg, new InMemoryConsentStore(), new InMemoryRedirectUriRegistry());
	}

	/// Construct with an explicit `ConsentStore` (e.g. a shared-storage backed
	/// store for a multi-process deployment). The store records which
	/// dynamically-registered clients (keyed by their `redirect_uri`) the user
	/// has approved, so `authorize` can enforce the confused-deputy consent MUST.
	this(OAuthProxyConfig cfg, ConsentStore consentStore) @safe
	in (consentStore !is null)
	{
		this(cfg, consentStore, new InMemoryRedirectUriRegistry());
	}

	/// Construct with explicit `ConsentStore` and `RedirectUriRegistry`. The
	/// registry records the exact `redirect_uris` each client presents at
	/// `/register` so `authorize` can reject any `redirect_uri` that was never
	/// registered (RFC 6749 §3.1.2.2 / §10.6).
	this(OAuthProxyConfig cfg, ConsentStore consentStore, RedirectUriRegistry redirectRegistry) @safe
	in (consentStore !is null)
	in (redirectRegistry !is null)
	{
		requireSecureUrl(cfg.upstreamAuthorizationEndpoint);
		requireSecureUrl(cfg.upstreamTokenEndpoint);
		this.cfg = cfg;
		this.consentStore = consentStore;
		this.redirectRegistry = redirectRegistry;
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

	/// Handle a DCR (`/register`) request: persist the exact client
	/// `redirect_uris` into the registry (so a later `/authorize` can be checked
	/// against them) and return the registration response. The fixed upstream
	/// `client_id` is shared across clients, so the registry is keyed by a
	/// server-issued registration handle rather than that shared id.
	Json register(const string[] requestedRedirectUris) @safe
	{
		import std.uuid : randomUUID;

		const handle = () @trusted { return randomUUID().toString(); }();
		const capped = requestedRedirectUris.length > maxRedirectUrisPerRegistration
			? requestedRedirectUris[0 .. maxRedirectUrisPerRegistration] : requestedRedirectUris;
		redirectRegistry.register(handle, capped);
		return registrationResponseJson(cfg, capped);
	}

	/// Reject a client `redirect_uri` that is not safe to relay an authorization
	/// code to. Fails closed by throwing `InvalidRedirectUriException` when the
	/// `redirect_uri` is empty, uses a disallowed scheme (RFC 8252 §7.3), or is
	/// not an exact match against any previously-registered `redirect_uri` (RFC
	/// 6749 §3.1.2.2 / §10.6). Called by both `authorize` overloads before any
	/// proxy state is minted or the request is forwarded upstream.
	void validateRedirectUri(string clientRedirectUri) @safe
	{
		if (clientRedirectUri.length == 0)
			throw new InvalidRedirectUriException(clientRedirectUri, "redirect_uri is required");
		if (!isAllowedRedirectScheme(clientRedirectUri))
			throw new InvalidRedirectUriException(clientRedirectUri,
					"scheme not allowed (https, or http for loopback only)");
		if (!redirectRegistry.isRegistered(clientRedirectUri))
			throw new InvalidRedirectUriException(clientRedirectUri,
					"redirect_uri is not registered for any client");
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
		validateRedirectUri(clientRedirectUri);
		if (!consentStore.hasConsent(clientRedirectUri))
			throw new ConsentRequiredException(clientRedirectUri);
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Build the upstream authorization redirect WITHOUT the per-client consent
	/// gate, for flows that do their own consent enforcement. The
	/// `clientRedirectUri` is still validated against the registered allowlist and
	/// scheme rules (RFC 6749 §3.1.2.2 / RFC 8252) — the ungated path cannot relay
	/// a code to an unregistered redirect_uri. For dynamically-registered clients
	/// prefer the consent-gated `authorize` overload, which additionally enforces
	/// the confused-deputy consent MUST.
	string authorizeWithoutConsent(string clientRedirectUri,
			string codeChallenge, string scopeStr, string state) @safe
	{
		validateRedirectUri(clientRedirectUri);
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Build the upstream token-exchange form for a proxied `/token`.
	string tokenForm(string code, string codeVerifier) const @safe
	{
		return proxyTokenForm(cfg, code, codeVerifier);
	}

	/// Build the upstream refresh-token-exchange form for a proxied `/token`
	/// request carrying `grant_type=refresh_token`. Relays the client-supplied
	/// `refresh_token` to the upstream token endpoint with the fixed upstream
	/// credentials and (RFC 8707) resource, so a client that obtained a refresh
	/// token via the proxy can refresh through it — matching the
	/// `refresh_token` grant the proxy advertises in its AS metadata.
	string refreshTokenForm(string refreshToken) const @safe
	{
		return proxyRefreshTokenForm(cfg, refreshToken);
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

unittest  // AS metadata JSON carries response_types_supported as required by RFC 8414 §2
{
	auto cfg = sampleConfig();
	auto j = authorizationServerMetadataJson(cfg);
	assert("response_types_supported" in j);
	assert(j["response_types_supported"].length == 1);
	assert(j["response_types_supported"][0].get!string == "code");
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

unittest  // proxied /token relays a refresh-token grant upstream with fixed creds (client_secret_post)
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;
	auto form = proxyRefreshTokenForm(cfg, "REFRESH-TOKEN");
	assert(form.canFind("grant_type=refresh_token"));
	assert(form.canFind("refresh_token=REFRESH-TOKEN"));
	assert(form.canFind("client_id=Iv1.upstream"));
	assert(form.canFind("resource=https%3A%2F%2Fmcp.example.com%2Fmcp"));
	assert(form.canFind("client_secret=upstream-secret"));
	assert(!form.canFind("grant_type=authorization_code"));
	assert(proxyTokenAuthHeader(cfg) is null);
}

unittest  // refresh-token grant: for client_secret_basic the secret goes in the header, not the body
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretBasic;
	auto form = proxyRefreshTokenForm(cfg, "REFRESH-TOKEN");
	assert(form.canFind("grant_type=refresh_token"));
	assert(!form.canFind("client_secret="));
	auto hdr = proxyTokenAuthHeader(cfg);
	assert(hdr !is null && hdr.startsWith("Basic "));
}

unittest  // the OAuthProxy class exposes refreshTokenForm so the mount can handle grant_type=refresh_token
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	auto form = proxy.refreshTokenForm("RT-123");
	assert(form.canFind("grant_type=refresh_token"));
	assert(form.canFind("refresh_token=RT-123"));
	assert(form.canFind("client_id=Iv1.upstream"));
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

	auto authUrl = proxy.authorizeWithoutConsent("http://127.0.0.1:8765/cb",
			"CH", "read:user", "S");
	assert(authUrl.startsWith("https://github.com/login/oauth/authorize?"));

	auto form = proxy.tokenForm("CODE", "VER");
	assert(form.canFind("client_id=Iv1.upstream"));
}

unittest  // CONFUSED DEPUTY: gated authorize refuses to forward an un-consented client
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/callback"]);
	// No consent recorded yet for this dynamically-registered client.
	assertThrown!ConsentRequiredException(
			proxy.authorize("http://localhost:5000/callback", "CH", "read:user", "S"));
}

unittest  // CONFUSED DEPUTY: after grantConsent the gated authorize forwards upstream
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/callback"]);
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
	proxy.register([
		"http://localhost:5000/callback", "http://localhost:6000/callback"
	]);
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
	proxy.register(["http://localhost:7000/cb"]);
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
	proxy.register(["http://localhost:9000/cb"]);
	auto url = proxy.authorize("http://localhost:9000/cb", "CH", "read:user", "S");
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // REDIRECT VALIDATION: gated authorize rejects an unregistered redirect_uri
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.grantConsent("https://attacker.example/cb");
	// Consent alone must not let an unregistered redirect_uri through.
	assertThrown!InvalidRedirectUriException(
			proxy.authorize("https://attacker.example/cb", "CH", "read:user", "S"));
}

unittest  // REDIRECT VALIDATION: ungated authorizeWithoutConsent rejects an unregistered redirect_uri
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	assertThrown!InvalidRedirectUriException(proxy.authorizeWithoutConsent(
			"https://attacker.example/cb", "CH", "read:user", "S"));
}

unittest  // REDIRECT VALIDATION: a registered redirect_uri passes the ungated path
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["https://app.example.com/cb"]);
	auto url = proxy.authorizeWithoutConsent("https://app.example.com/cb", "CH", "read:user", "S");
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // REDIRECT VALIDATION: an empty redirect_uri is rejected (fail closed)
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	assertThrown!InvalidRedirectUriException(proxy.validateRedirectUri(""));
}

unittest  // REDIRECT VALIDATION: a registered redirect_uri with an unrelated one is exact-matched
{
	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["https://app.example.com/cb"]);
	// Exact match passes; a near-miss (different path) is rejected.
	proxy.validateRedirectUri("https://app.example.com/cb");
}

unittest  // REDIRECT VALIDATION: a near-miss of a registered redirect_uri is rejected
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["https://app.example.com/cb"]);
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("https://app.example.com/cb/extra"));
}

unittest  // SCHEME ALLOWLIST: https is accepted
{
	assert(isAllowedRedirectScheme("https://app.example.com/cb"));
}

unittest  // SCHEME ALLOWLIST: http to loopback is accepted (RFC 8252)
{
	assert(isAllowedRedirectScheme("http://127.0.0.1:8765/cb"));
	assert(isAllowedRedirectScheme("http://localhost:5000/callback"));
	assert(isAllowedRedirectScheme("http://[::1]:9000/cb"));
}

unittest  // SCHEME ALLOWLIST: bare (unbracketed) IPv6 loopback is rejected; RFC 3986 §3.2.2 requires brackets
{
	assert(!isAllowedRedirectScheme("http://::1/cb"));
	assert(!isAllowedRedirectScheme("http://::1:8080/cb"));
}

unittest  // SCHEME ALLOWLIST: http to a non-loopback host is rejected
{
	assert(!isAllowedRedirectScheme("http://app.example.com/cb"));
	assert(!isAllowedRedirectScheme("http://evil.test/cb"));
}

unittest  // SCHEME ALLOWLIST: a custom/private-use scheme is rejected
{
	assert(!isAllowedRedirectScheme("com.example.app:/oauth/cb"));
	assert(!isAllowedRedirectScheme("javascript:alert(1)"));
	assert(!isAllowedRedirectScheme(""));
}

unittest  // SCHEME ALLOWLIST: a registered scheme is still scheme-checked (registered http non-loopback rejected)
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	// Even if such a URI were registered, the scheme gate rejects it.
	proxy.register(["http://app.example.com/cb"]);
	assertThrown!InvalidRedirectUriException(proxy.validateRedirectUri("http://app.example.com/cb"));
}

unittest  // REDIRECT REGISTRY: InMemoryRedirectUriRegistry exact-matches across registrations
{
	RedirectUriRegistry reg = new InMemoryRedirectUriRegistry();
	assert(!reg.isRegistered("https://a/cb"));
	reg.register("h1", ["https://a/cb"]);
	reg.register("h2", ["https://b/cb"]);
	assert(reg.isRegistered("https://a/cb"));
	assert(reg.isRegistered("https://b/cb"));
	assert(!reg.isRegistered("https://c/cb"));
}

unittest  // REDIRECT REGISTRY: the registry caps live registrations, evicting the oldest as a unit
{
	auto reg = new InMemoryRedirectUriRegistry(2);
	reg.register("h1", ["https://a/cb"]);
	reg.register("h2", ["https://b/cb"]);
	// Third registration exceeds the cap of 2: the oldest ("h1") is evicted whole.
	reg.register("h3", ["https://c/cb"]);
	assert(!reg.isRegistered("https://a/cb"));
	assert(reg.isRegistered("https://b/cb"));
	assert(reg.isRegistered("https://c/cb"));
}

unittest  // REDIRECT REGISTRY: a redirect_uri shared by two registrations survives evicting one
{
	auto reg = new InMemoryRedirectUriRegistry(2);
	reg.register("h1", ["https://shared/cb"]);
	reg.register("h2", ["https://shared/cb"]);
	// Evict h1 by overflowing the cap; the shared URI is still held by h2.
	reg.register("h3", ["https://other/cb"]);
	assert(reg.isRegistered("https://shared/cb"));
	assert(reg.isRegistered("https://other/cb"));
}

unittest  // REDIRECT REGISTRY: an oversized redirect_uris array is truncated at register time
{
	auto cfg = sampleConfig();
	auto reg = new InMemoryRedirectUriRegistry();
	auto proxy = new OAuthProxy(cfg, new InMemoryConsentStore(), reg);
	string[] many;
	foreach (i; 0 .. maxRedirectUrisPerRegistration + 5)
		many ~= "https://app.example.com/cb" ~ cast(char)('0' + cast(int)(i % 10));
	auto resp = proxy.register(many);
	// The response echoes only the capped subset (RFC 7591 §3.2.1).
	assert(resp["redirect_uris"].length == maxRedirectUrisPerRegistration);
}

unittest  // CONSENT STORE: the consent store caps approvals, evicting the oldest first
{
	auto store = new InMemoryConsentStore(2);
	store.grantConsent("http://a/cb");
	store.grantConsent("http://b/cb");
	// Third approval exceeds the cap of 2: the oldest ("a") is evicted.
	store.grantConsent("http://c/cb");
	assert(!store.hasConsent("http://a/cb"));
	assert(store.hasConsent("http://b/cb"));
	assert(store.hasConsent("http://c/cb"));
}

unittest  // CONSENT STORE: re-granting an existing consent does not consume cap headroom
{
	auto store = new InMemoryConsentStore(2);
	store.grantConsent("http://a/cb");
	store.grantConsent("http://a/cb"); // duplicate: no new slot used
	store.grantConsent("http://b/cb");
	// "a" must still be present: the duplicate did not push it out of the cap.
	assert(store.hasConsent("http://a/cb"));
	assert(store.hasConsent("http://b/cb"));
}

unittest  // REDIRECT REGISTRY: a custom registry can be injected and is consulted by authorize
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto registry = new InMemoryRedirectUriRegistry();
	registry.register("pre", ["https://app.example.com/cb"]);
	auto proxy = new OAuthProxy(cfg, new InMemoryConsentStore(), registry);
	auto url = proxy.authorizeWithoutConsent("https://app.example.com/cb", "CH", "read:user", "S");
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // OAuthProxyConfig.toResourceServer flows the proxy through the single auth entry
{
	OAuthProxyConfig cfg;
	cfg.baseUrl = "https://mcp.example.com/";
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.scopesSupported = ["read:user"];
	cfg.tokenVerifier = (string t) {
		TokenInfo ti;
		ti.valid = t == "good";
		ti.audience = ["https://mcp.example.com/mcp"];
		return ti;
	};

	auto rs = cfg.toResourceServer();
	assert(rs.enabled);
	assert(rs.resource == "https://mcp.example.com/mcp");
	assert(rs.authorizationServers == ["https://mcp.example.com"]); // trailing slash stripped
	assert(rs.scopesSupported == ["read:user"]);
	assert(rs.validator("good").valid);
	assert(!rs.validator("bad").valid);
}

unittest  // toResourceServer fails closed when the proxy has no tokenVerifier
{
	OAuthProxyConfig cfg;
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto rs = cfg.toResourceServer();
	assert(rs.enabled); // validator is non-null (rejects everything)
	assert(!rs.validator("anything").valid);
}
