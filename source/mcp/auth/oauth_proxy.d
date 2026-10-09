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

import core.time : days, Duration, hours, minutes, MonoTime, seconds;
import std.string : endsWith, indexOf, startsWith;

import vibe.data.json : Json;

import mcp.auth.oauth : AuthorizationServerMetadata, ClientIdMetadataDocument,
	RegisteredClient, TokenEndpointAuthMethod, TokenSet, basicAuthHeader,
	buildAuthCodeTokenForm, buildAuthorizationUrl, buildRefreshTokenForm,
	isValidClientIdMetadataUrl, requireSecureUrl, secureRequestHTTP;
import mcp.auth.reference_token : IssuedToken, ReferenceTokenStore, referenceTokenValidator;
import mcp.protocol.ssrf : SsrfPolicy;
import mcp.auth.resource_server : ResourceServerConfig, TokenInfo,
	TokenValidator, bindResourceAudience;
import mcp.transport.session : BoundedExpiringMap;

@safe:

// ===========================================================================
// Configuration
// ===========================================================================

/// Mints the MCP server's OWN token for the client from the upstream token
/// response. Called in issue-own-token (broker) mode after the proxy exchanges
/// the code upstream: it receives the upstream `TokenSet` and returns the
/// `IssuedToken` the proxy stores and hands the client. The returned token's
/// `subject`/`scopes`/`audience`/`claims` become the client principal; the proxy
/// stashes the upstream token alongside it so the server can call downstream
/// APIs with it. Always set the returned `IssuedToken.expiresAt` — an unset, zero
/// value is already expired.
///
/// The hook runs synchronously on the `/token` request fiber, so any work it does
/// to derive the principal — e.g. an upstream userinfo/tokeninfo call to resolve
/// the subject or email — happens inline there (wrap such a network call in
/// `@trusted` as the call site requires). Keep it bounded; it blocks that fiber.
alias IssueTokenHook = IssuedToken delegate(TokenSet upstream) @safe;

/// Configuration for an `OAuthProxy`.
///
/// By default the proxy operates in PASSTHROUGH mode: its `/token` endpoint
/// relays the upstream token exchange verbatim and the client presents the
/// UPSTREAM token as its MCP bearer. A self-brokering server — one that calls a
/// downstream API with the issued token — should instead set `issueToken` +
/// `tokenStore` to switch to ISSUE-OWN-TOKEN (broker) mode, where the proxy mints
/// its own opaque MCP token for the client and keeps the upstream token
/// server-side (reachable from the validated `TokenInfo.claims`).
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

	/// The upstream IdP's issuer identifier. When set, an upstream authorization
	/// response carrying an RFC 9207 `iss` parameter is relayed only when `iss`
	/// equals it, defending against mix-up attacks; empty skips the check.
	string upstreamIssuer;

	/// The fixed upstream `client_secret`. May be empty for public PKCE clients.
	string upstreamClientSecret;

	/// How the proxy authenticates to the upstream token endpoint. Defaults to
	/// `client_secret_post` (credentials in the form body); set to
	/// `client_secret_basic` to send them via the HTTP Basic header.
	TokenEndpointAuthMethod tokenEndpointAuthMethod = TokenEndpointAuthMethod.clientSecretPost;

	/// The SSRF policy applied to the upstream authorization and token
	/// endpoints. The default requires `https` to a public host (plain `http`
	/// only to loopback); an IdP on a private network (e.g. `keycloak.internal`
	/// resolving to `10.x`) needs `SsrfPolicy.allowUserConfigured`.
	SsrfPolicy upstreamSsrfPolicy = SsrfPolicy.allowLoopback;

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

	/// The scopes advertised in the metadata documents the proxy publishes. When
	/// set, these are also the only scopes `/authorize` forwards upstream; any
	/// other requested scope is dropped (`forwardedScopes`).
	string[] scopesSupported;

	/// The `grant_types_supported` advertised in the published RFC 8414 AS
	/// metadata. Defaults to the grants the proxy's own `/token` handles
	/// (`authorization_code` + `refresh_token`); an integrator who overrides
	/// `/token` and drops refresh support can narrow this so the metadata stays
	/// honest about what the deployed token endpoint accepts.
	string[] grantTypesSupported = ["authorization_code", "refresh_token"];

	/// Validates an upstream access token, mapping it to a `TokenInfo`. Plug in
	/// `introspectionVerifier`, `jwtVerifier`, or `staticVerifier`. Required to
	/// enforce auth on incoming MCP requests.
	TokenValidator tokenVerifier;

	/// In passthrough mode, treat every token `tokenVerifier` accepts as issued
	/// for `resource` (see `bindResourceAudience`). Upstreams such as GitHub and
	/// Google issue opaque tokens with no `aud`, which `authorize`'s RFC 8707
	/// resource check would otherwise reject; their presets set this. With it
	/// set, `tokenVerifier` carries the audience guarantee and MUST confirm the
	/// token was issued to this proxy's `upstreamClientId`, not merely that it
	/// is a live upstream token; the presets install `githubTokenVerifier` and
	/// `googleTokenVerifier`, which do.
	bool verifierBindsResource;

	/// The RFC 8707 canonical resource identifier of the MCP server, advertised
	/// in the PRM document and forwarded to the upstream as the `resource`
	/// parameter so issued tokens are audience-bound to this server. Required:
	/// `OAuthProxy` refuses a config without it.
	string resource;

	/// In ISSUE-OWN-TOKEN (broker) mode, mints the MCP server's own token for the
	/// client from the upstream token response. Set together with `tokenStore` to
	/// switch the proxy out of passthrough: the proxy then NEVER hands the client
	/// the upstream token. Null (the default) leaves the proxy in passthrough.
	IssueTokenHook issueToken;

	/// In ISSUE-OWN-TOKEN (broker) mode, stores the minted client token and the
	/// upstream token stashed alongside it, and validates issued tokens by lookup
	/// (`referenceTokenValidator`). Set together with `issueToken`. Null (the
	/// default) leaves the proxy in passthrough.
	ReferenceTokenStore tokenStore;

	/// Opt-in: advertise and accept OAuth Client ID Metadata Documents (SEP-991).
	/// When set, the proxy publishes `client_id_metadata_document_supported: true`
	/// in its AS metadata and accepts URL-formatted `client_id`s at `/authorize`,
	/// fetching and validating the hosted document instead of requiring DCR. DCR
	/// remains advertised as the deprecated fallback. CIMD is the spec-recommended
	/// registration mechanism; DCR is deprecated.
	bool clientIdMetadataDocumentSupported;

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
	/// the JWKS presets — no re-typing of resource/scopes. In broker mode the
	/// client presents the server's own opaque reference token, so the `validator`
	/// is `referenceTokenValidator` over `tokenStore`; otherwise it is the
	/// configured `tokenVerifier` for the upstream/passthrough token (failing
	/// closed when none is set). The proxy's own `baseUrl` is advertised as the
	/// sole authorization server (it fronts the upstream IdP), and
	/// `resource`/`scopesSupported` are mirrored.
	ResourceServerConfig toResourceServer() @safe
	{
		ResourceServerConfig rs;
		if (issueToken !is null && tokenStore !is null)
			rs.validator = referenceTokenValidator(tokenStore, resource);
		else if (tokenVerifier is null)
			rs.validator = (string t) => TokenInfo.invalid();
		else if (verifierBindsResource)
			rs.validator = bindResourceAudience(tokenVerifier, resource);
		else
			rs.validator = tokenVerifier;
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
	m.grantTypesSupported = cfg.grantTypesSupported.dup;
	// Broker mode issues non-refreshable opaque tokens, so it never honours a
	// refresh_token grant; don't advertise one.
	if (cfg.issueToken !is null && cfg.tokenStore !is null)
	{
		import std.algorithm : filter;
		import std.array : array;

		m.grantTypesSupported = m.grantTypesSupported.filter!(g => g != "refresh_token").array;
	}
	m.tokenEndpointAuthMethodsSupported = ["none"];
	m.responseTypesSupported = ["code"];
	m.clientIdMetadataDocumentSupported = cfg.clientIdMetadataDocumentSupported;
	return m;
}

/// Serialize the RFC 8414 AS metadata document the proxy serves at
/// `/.well-known/oauth-authorization-server`. Emits the proxy endpoints,
/// `response_types_supported` (RFC 8414 §2 REQUIRED when
/// `authorization_endpoint` is present), `code_challenge_methods_supported`,
/// `grant_types_supported`, `token_endpoint_auth_methods_supported`,
/// (when non-empty) `scopes_supported`, and the RFC 9207
/// `authorization_response_iss_parameter_supported` flag.
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
	if (m.clientIdMetadataDocumentSupported)
		j["client_id_metadata_document_supported"] = true;
	// The HTTP mount adds the RFC 9207 `iss` parameter to every authorization
	// response it relays to a client.
	j["authorization_response_iss_parameter_supported"] = true;
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
/// `token_endpoint_auth_method=none` (public client). `grant_types` matches
/// the `grant_types_supported` the AS metadata advertises.
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
	foreach (g; authorizationServerMetadata(cfg).grantTypesSupported)
		gt ~= Json(g);
	j["grant_types"] = gt;
	Json rt = Json.emptyArray;
	rt ~= Json("code");
	j["response_types"] = rt;
	return j;
}

// ===========================================================================
// Authorize proxying
// ===========================================================================

/// Upper bound on the number of distinct scopes one authorization request may
/// name. `/authorize` is unauthenticated, so this bounds the work and the
/// consent state a single request can cause.
enum size_t maxScopesPerRequest = 64;

/// Thrown when an authorization request or consent approval names more scopes
/// than the proxy accepts (`maxScopesPerRequest`,
/// `ConsentStoreOptions.maxScopesPerApproval`). An HTTP mount maps this to the
/// RFC 6749 §4.1.2.1 `invalid_scope` error.
class InvalidScopeException : Exception
{
	this(string reason, string file = __FILE__, size_t line = __LINE__) @safe
	{
		super(reason, file, line);
	}
}

/// The scopes from the space-delimited `scopeStr` that the proxy forwards
/// upstream: each distinct requested scope, restricted to `cfg.scopesSupported`
/// when that is set, so a client cannot reach upstream scopes the proxy does not
/// advertise under the proxy's own upstream `client_id`. Dropping the rest is a
/// partial grant RFC 6749 §3.3 permits. Throws `InvalidScopeException` when
/// `scopeStr` names more than `maxScopesPerRequest` distinct scopes, supported
/// or not.
string[] forwardedScopes(const OAuthProxyConfig cfg, string scopeStr) @safe
{
	import std.algorithm : splitter;

	bool[string] supported;
	foreach (sc; cfg.scopesSupported)
		supported[sc] = true;
	bool[string] seen;
	string[] scopes;
	foreach (sc; scopeStr.splitter(' '))
	{
		if (sc.length == 0 || sc in seen)
			continue;
		if (seen.length == maxScopesPerRequest)
			throw new InvalidScopeException("too many scopes requested");
		seen[sc] = true;
		if (supported.length && sc !in supported)
			continue;
		scopes ~= sc;
	}
	return scopes;
}

/// Build the upstream authorization redirect URL for a proxied `/authorize`
/// request. The proxy substitutes its OWN fixed upstream `client_id` and fixed
/// callback URL, forwarding the client-supplied PKCE `code_challenge`, the
/// requested scopes it permits (`forwardedScopes`), state, and (RFC 8707)
/// resource. The client's real `redirect_uri` is NOT sent upstream — the proxy
/// receives the code at its fixed callback and relays it.
string proxyAuthorizeUrl(const OAuthProxyConfig cfg, string codeChallenge,
		string scopeStr, string state) @safe
{
	import std.array : join;

	return buildAuthorizationUrl(cfg.upstreamAuthorizationEndpoint, cfg.upstreamClientId,
			cfg.callbackUrl(), codeChallenge, forwardedScopes(cfg, scopeStr)
				.join(" "), cfg.resource, state);
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

/// The result of minting a client-facing token in issue-own-token (broker) mode:
/// the opaque MCP `token` the proxy hands the client, and the `issued` record
/// (subject/scopes/audience/expiry) stored under it.
struct BrokeredToken
{
	string token; /// the opaque MCP bearer the proxy returns to the client
	IssuedToken issued; /// the stored principal the token resolves to
	/// Seconds until `token` expires, measured by the token store's clock, for
	/// the token response's `expires_in`. 0 when the token never expires
	/// (`expiresAt == long.max`) or is already dead.
	long expiresIn;
}

/// The `TokenInfo.claims` key under which the proxy stashes the upstream access
/// token in broker mode, so a server handler can read it back from the validated
/// token to call the upstream API on the user's behalf.
enum string upstreamAccessTokenClaim = "upstream_access_token";

/// The `TokenInfo.claims` key under which the proxy stashes the upstream refresh
/// token in broker mode (present only when the upstream returned one).
enum string upstreamRefreshTokenClaim = "upstream_refresh_token";

// ===========================================================================
// Redirect-URI registration + validation (RFC 6749 §3.1.2.2 / §10.6, RFC 8252)
// ===========================================================================

/// Whether a client `redirect_uri` is one the proxy is willing to relay an
/// authorization code to. `https` is always allowed; plain `http` is allowed only
/// for loopback hosts (`127.0.0.1`, `[::1]`, `localhost`) per RFC 8252 §7.3. All
/// other schemes (including `http` to a non-loopback host, and custom/private-use
/// schemes) are rejected so the upstream code can never be relayed over an
/// open-redirect-prone or interceptable channel. The URI must also parse
/// strictly: printable ASCII only (no whitespace, control characters or
/// backslash), a non-empty host, no userinfo, a numeric port if any, and no
/// fragment (RFC 6749 §3.1.2).
bool isAllowedRedirectUri(string redirectUri) @safe
{
	import std.algorithm : all, any;
	import std.ascii : isDigit;
	import std.string : indexOfAny, representation;

	if (redirectUri.representation.any!(c => c <= ' ' || c >= 0x7f || c == '\\' || c == '#'))
		return false;
	string rest;
	bool https;
	if (redirectUri.startsWith("https://"))
	{
		https = true;
		rest = redirectUri["https://".length .. $];
	}
	else if (redirectUri.startsWith("http://"))
		rest = redirectUri["http://".length .. $];
	else
		return false;
	const end = rest.indexOfAny("/?");
	const authority = end < 0 ? rest : rest[0 .. end];
	if (authority.indexOf('@') >= 0)
		return false;
	string host = authority;
	string port;
	if (authority.startsWith("["))
	{
		const close = authority.indexOf(']');
		if (close < 0)
			return false;
		host = authority[0 .. close + 1];
		const after = authority[close + 1 .. $];
		if (after.length && after[0] != ':')
			return false;
		port = after.length ? after[1 .. $] : "";
	}
	else
	{
		const colon = authority.indexOf(':');
		if (colon >= 0)
		{
			host = authority[0 .. colon];
			port = authority[colon + 1 .. $];
		}
	}
	if (host.length == 0 || host == "[]" || !port.representation.all!isDigit)
		return false;
	return https || host == "127.0.0.1" || host == "localhost" || host == "[::1]";
}

/// The form of `redirectUri` that registration and validation compare. For an
/// `http` loopback IP-literal URI (`127.0.0.1`, `[::1]`) the port is removed,
/// since a native client binds an ephemeral port per sign-in and RFC 8252 §7.3
/// requires the authorization server to allow any port there; every other URI
/// (including `localhost`) is compared as the exact string.
string redirectUriMatchKey(string redirectUri) @safe
{
	import std.string : indexOfAny, lastIndexOf;

	enum prefix = "http://";
	if (!redirectUri.startsWith(prefix))
		return redirectUri;
	const rest = redirectUri[prefix.length .. $];
	const host = hostOf(rest);
	if (host != "127.0.0.1" && host != "[::1]")
		return redirectUri;
	const end = rest.indexOfAny("/?#\\");
	const authorityEnd = end < 0 ? rest.length : end;
	// The authority is `[userinfo@]host[:port]`; keep everything up to the host.
	const at = rest[0 .. authorityEnd].lastIndexOf('@');
	const hostEnd = (at < 0 ? 0 : at + 1) + host.length;
	return prefix ~ rest[0 .. hostEnd] ~ rest[authorityEnd .. $];
}

/// The host of the authority that begins `authorityAndRest` (the text after
/// `scheme://`). The authority ends at the first `/`, `?` or `#` (RFC 3986 §3.2),
/// or `\`, which browsers treat as a path separator in http URLs, so an `@` in
/// the path, query or fragment is never mistaken for a userinfo delimiter.
private string hostOf(string authorityAndRest) @safe
{
	import std.string : indexOfAny, lastIndexOf;

	auto s = authorityAndRest;
	const end = s.indexOfAny("/?#\\");
	if (end >= 0)
		s = s[0 .. end];
	const at = s.lastIndexOf('@');
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
	/// A pure lookup: it does not change how the registration is retained.
	bool isRegistered(string redirectUri) @safe;

	/// Record that an authorization for a client holding `redirectUri` is in
	/// progress (the proxy minted pending state for it at `/authorize`). A
	/// registry should retain such registrations for the life of that
	/// authorization rather than evict them ahead of idle ones.
	void markPending(string redirectUri) @safe;

	/// Record that a client holding `redirectUri` completed a sign-in (the
	/// proxy relayed it an authorization code, which happens only after user
	/// consent). A registry may retain such registrations ahead of ones that
	/// never got that far.
	void markUsed(string redirectUri) @safe;
}

/// Bounds for an `InMemoryRedirectUriRegistry`.
struct RedirectUriRegistryOptions
{
	import core.time : MonoTime, hours, minutes;

	/// Maximum number of live registrations (one per `/register` call). When
	/// exceeded on `register`, one registration is evicted as a whole.
	size_t maxRegistrations = 10_000;

	/// How long a registration that has never completed a sign-in stays live.
	/// A registration marked used (see `RedirectUriRegistry.markUsed`) does not
	/// expire.
	Duration unusedTtl = 1.hours;

	/// How long `markPending` shields an unused registration from expiry and
	/// from eviction ahead of idle registrations; it matches the life of a
	/// pending authorization in the HTTP mount.
	Duration pendingTtl = 10.minutes;

	/// Injectable monotonic clock (tests drive expiry with it). Null uses
	/// `MonoTime.currTime`.
	MonoTime delegate() @safe clock;
}

/// A simple in-memory `RedirectUriRegistry` bounded against unauthenticated
/// growth: each `/register` call is scoped under its server-issued
/// `registrationHandle`, and when the number of live registrations exceeds the
/// cap one registration (and all its redirect URIs) is evicted as a unit. The cap
/// is what keeps an unauthenticated `POST /register` flood from growing process
/// memory without bound.
///
/// A registration counts as used once `markUsed` names one of its redirect URIs,
/// which the proxy does only when it relays an authorization code (after the
/// user consented and signed in upstream). Merely presenting a redirect URI at
/// `/authorize` does not, so an anonymous client cannot make its registration
/// sticky; it marks the registration pending instead, which shields it for
/// `pendingTtl` (after which it counts as freshly registered). Unused
/// registrations expire after `unusedTtl`, and eviction prefers the oldest
/// unused registration that has no authorization pending, falling back to the
/// oldest registration only when there is none. A flood of anonymous
/// registrations therefore displaces other idle registrations before a client
/// whose user is mid-sign-in or that is actually signing users in.
///
/// NOTE: even bounded, the unbounded-default in-memory backing is unsuitable for
/// an internet-exposed multi-process proxy: state is per-process and lost on
/// restart. Back it with shared, bounded storage (and gate `/register` behind the
/// integrator's auth or a rate limiter) for such deployments.
final class InMemoryRedirectUriRegistry : RedirectUriRegistry
{
	import core.time : MonoTime;

	private enum Status
	{
		unused,
		pending,
		used,
	}

	/// One registration, linked into the all-registrations list (oldest first)
	/// and, unless used, into the unused or the pending list (oldest first), so
	/// lookup, removal and eviction are constant time.
	private static final class Registration
	{
		string handle;
		string[] uris;
		MonoTime registeredAt;
		MonoTime pendingUntil;
		Status status;
		Registration prevAll, nextAll, prev, next;
	}

	private static struct List
	{
		Registration head, tail;

		void append(Registration r) @safe
		{
			r.prev = tail;
			r.next = null;
			if (tail !is null)
				tail.next = r;
			else
				head = r;
			tail = r;
		}

		void unlink(Registration r) @safe
		{
			if (r.prev !is null)
				r.prev.next = r.next;
			else
				head = r.next;
			if (r.next !is null)
				r.next.prev = r.prev;
			else
				tail = r.prev;
			r.prev = r.next = null;
		}
	}

	private Registration[string] byHandle;
	private Registration allHead, allTail;
	private List unused, pending;
	private bool[string][string] handlesByUri;
	private const RedirectUriRegistryOptions opts;

	this() @safe
	{
		this(RedirectUriRegistryOptions.init);
	}

	this(RedirectUriRegistryOptions opts) @safe
	{
		this.opts = opts;
	}

	override void register(string registrationHandle, const string[] redirectUris) @safe
	{
		// Re-registering a handle replaces its URIs and gives it a fresh slot at the
		// back of the eviction order.
		if (auto r = registrationHandle in byHandle)
			removeRegistration(*r);
		sweep();
		auto r = new Registration;
		r.handle = registrationHandle;
		r.uris = redirectUris.dup;
		r.registeredAt = now();
		byHandle[registrationHandle] = r;
		linkAll(r);
		unused.append(r);
		foreach (u; r.uris)
			handlesByUri[u][registrationHandle] = true;
		enforceCap();
	}

	/// Whether `redirectUri` belongs to a live registration: one marked used or
	/// pending, or an unused one younger than `unusedTtl`.
	override bool isRegistered(string redirectUri) @safe
	{
		sweepPending();
		auto hs = redirectUri in handlesByUri;
		if (hs is null)
			return false;
		foreach (h; (*hs).byKey)
			if (!isExpired(byHandle[h]))
				return true;
		return false;
	}

	override void markPending(string redirectUri) @safe
	{
		sweepPending();
		auto hs = redirectUri in handlesByUri;
		if (hs is null)
			return;
		foreach (h; (*hs).byKey)
		{
			auto r = byHandle[h];
			if (r.status == Status.used || isExpired(r))
				continue;
			detach(r);
			r.status = Status.pending;
			r.pendingUntil = now() + opts.pendingTtl;
			pending.append(r);
		}
	}

	override void markUsed(string redirectUri) @safe
	{
		sweepPending();
		auto hs = redirectUri in handlesByUri;
		if (hs is null)
			return;
		foreach (h; (*hs).byKey)
		{
			auto r = byHandle[h];
			if (!isExpired(r))
			{
				detach(r);
				r.status = Status.used;
			}
		}
	}

	private MonoTime now() @safe
	{
		return opts.clock !is null ? opts.clock() : MonoTime.currTime;
	}

	private bool isExpired(Registration r) @safe
	{
		return r.status == Status.unused && now() - r.registeredAt >= opts.unusedTtl;
	}

	private void sweep() @safe
	{
		sweepPending();
		// The unused list is oldest first, so the sweep stops at the first
		// registration that is still live.
		while (unused.head !is null && isExpired(unused.head))
			removeRegistration(unused.head);
	}

	// Return registrations whose pending authorization has lapsed to the unused
	// list, as if registered when it lapsed. The pending list is ordered by
	// `pendingUntil`, so this stops at the first one still pending.
	private void sweepPending() @safe
	{
		const t = now();
		while (pending.head !is null && pending.head.pendingUntil <= t)
		{
			auto r = pending.head;
			pending.unlink(r);
			r.status = Status.unused;
			r.registeredAt = r.pendingUntil;
			unused.append(r);
		}
	}

	private void removeRegistration(Registration r) @safe
	{
		foreach (u; r.uris)
		{
			if (auto hs = u in handlesByUri)
			{
				(*hs).remove(r.handle);
				if ((*hs).length == 0)
					handlesByUri.remove(u);
			}
		}
		byHandle.remove(r.handle);
		unlinkAll(r);
		detach(r);
	}

	// Unlink `r` from the unused or pending list it is on.
	private void detach(Registration r) @safe
	{
		final switch (r.status)
		{
		case Status.unused:
			unused.unlink(r);
			break;
		case Status.pending:
			pending.unlink(r);
			break;
		case Status.used:
			break;
		}
	}

	private void enforceCap() @safe
	{
		while (byHandle.length > opts.maxRegistrations)
		{
			// Evict the oldest idle registration. The newest registration is
			// exempt, so a registry full of in-use or pending clients still admits
			// a new one (evicting the oldest).
			removeRegistration(unused.head !is null && unused.head !is allTail ? unused.head
					: allHead);
		}
	}

	private void linkAll(Registration r) @safe
	{
		r.prevAll = allTail;
		if (allTail !is null)
			allTail.nextAll = r;
		else
			allHead = r;
		allTail = r;
	}

	private void unlinkAll(Registration r) @safe
	{
		if (r.prevAll !is null)
			r.prevAll.nextAll = r.nextAll;
		else
			allHead = r.nextAll;
		if (r.nextAll !is null)
			r.nextAll.prevAll = r.prevAll;
		else
			allTail = r.prevAll;
		r.prevAll = r.nextAll = null;
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
// Client ID Metadata Documents (SEP-991) — server (AS) side
// ===========================================================================

/// Thrown when a URL-formatted `client_id` or its fetched OAuth Client ID
/// Metadata Document (SEP-991) fails the AS-side validation the spec requires
/// before an authorization request may be honoured: the `client_id` URL must be
/// https with a path component, the document's `client_id` MUST equal that URL
/// exactly, the document MUST be valid JSON carrying the required fields, and the
/// requested `redirect_uri` MUST be an exact, scheme-allowed member of the
/// document's `redirect_uris`. The proxy fails closed by throwing — it neither
/// mints proxy state nor forwards upstream. An HTTP mount maps this to a
/// `400 invalid_client` / `invalid_request`.
class InvalidClientIdMetadataException : Exception
{
	string clientId;

	this(string clientId, string reason, string file = __FILE__, size_t line = __LINE__) @safe
	{
		super("invalid client_id metadata '" ~ clientId ~ "': " ~ reason, file, line);
		this.clientId = clientId;
	}
}

/// Validate a fetched OAuth Client ID Metadata Document against the URL
/// `client_id` it was fetched from and the `redirect_uri` presented in the
/// authorization request, enforcing the SEP-991 AS-side MUSTs:
///   * `clientIdUrl` is https with a path component (`isValidClientIdMetadataUrl`);
///   * the document's `client_id` equals `clientIdUrl` exactly;
///   * the document carries the required fields (`client_id`, `client_name`, `redirect_uris`);
///   * `redirectUri` is an exact-string member of the document's `redirect_uris`
///     (ignoring a loopback IP literal's port, `redirectUriMatchKey`);
///   * `redirectUri` uses a scheme the proxy will relay a code to (RFC 8252).
/// Pure (no HTTP): the SSRF-guarded fetch is performed by
/// `OAuthProxy.fetchClientIdMetadata`; this carries the validation logic so it is
/// unit-testable against a document obtained any way. Throws
/// `InvalidClientIdMetadataException` on the first failed check (fail closed).
void validateClientIdMetadata(string clientIdUrl,
		const ClientIdMetadataDocument doc, string redirectUri) @safe
{
	import std.algorithm : canFind;

	if (!isValidClientIdMetadataUrl(clientIdUrl))
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"client_id must be an https URL with a path component (SEP-991)");
	if (doc.clientId.length == 0)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document is missing the required client_id field");
	if (doc.clientId != clientIdUrl)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document client_id does not match the document URL exactly");
	if (doc.clientName.length == 0)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document is missing the required client_name field");
	if (doc.redirectUris.length == 0)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document is missing the required redirect_uris field");
	const key = redirectUriMatchKey(redirectUri);
	if (!doc.redirectUris.canFind!(u => redirectUriMatchKey(u) == key))
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"redirect_uri is not listed in the metadata document");
	if (!isAllowedRedirectUri(redirectUri))
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"redirect_uri not allowed (https, or http for loopback only; no fragment or userinfo)");
}

/// Upper bound on the size of a fetched Client ID Metadata Document. A document
/// larger than this is rejected rather than buffered, so an attacker-supplied
/// `client_id` URL cannot make the proxy buffer an unbounded response (SSRF
/// amplification). Mirrors the introspection/JWKS body caps elsewhere.
package enum size_t maxClientIdMetadataBytes = 256 * 1024;

/// Parse a fetched Client ID Metadata Document body (SEP-991). The body MUST be
/// a JSON object; a non-JSON or non-object body throws
/// `InvalidClientIdMetadataException` (the spec MUST that the AS validate the
/// document is valid JSON). Field-level requirements (`client_id`,
/// `redirect_uris`, exact-match checks) are enforced separately by
/// `validateClientIdMetadata`. Pure: no HTTP, so it is unit-testable on a body
/// string obtained any way.
ClientIdMetadataDocument parseClientIdMetadataDocument(string clientIdUrl, string body) @safe
{
	import mcp.protocol.jsonrpc : parseUntrustedJson;

	Json j;
	try
		j = parseUntrustedJson(body);
	catch (Exception e)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document is not valid JSON");
	if (j.type != Json.Type.object)
		throw new InvalidClientIdMetadataException(clientIdUrl,
				"metadata document is not a JSON object");
	return ClientIdMetadataDocument.fromJson(j);
}

// ===========================================================================
// Consent gate (confused-deputy mitigation)
// ===========================================================================

/// Records that a user, in one particular browser, has approved a particular
/// client to be forwarded to the upstream identity provider with a particular
/// set of scopes, and answers whether that browser has already approved that
/// client for a requested scope set.
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
/// Consent is keyed on two parts:
///   * `consentSession` — an unguessable per-browser identifier the HTTP mount
///     keeps in a cookie. Binding consent to it means an approval recorded in one
///     browser (e.g. an attacker approving their own redirect_uri) never lets a
///     different browser skip the consent screen.
///   * `client` — the per-client identity: the `redirectUriMatchKey` of the
///     client-supplied `redirect_uri` for a DCR client (the `client_id` is
///     shared; a loopback IP literal's port is not part of it), or the stable
///     `client_id` URL for a SEP-991 CIMD client.
///
/// Each approval also records the scopes the user saw and approved, so a later
/// request for broader access re-prompts rather than riding on the earlier
/// approval. An empty `consentSession` never has consent.
interface ConsentStore
{
	/// Whether the browser approved `client` for every scope in `scopes`.
	bool hasConsent(string consentSession, string client, const(string)[] scopes) @safe;

	/// Record the browser's approval of `client` for `scopes`, adding them to any
	/// scopes it already approved for that client. An implementation bounding the
	/// scopes it keeps may refuse an oversized set with `InvalidScopeException`.
	void grantConsent(string consentSession, string client, const(string)[] scopes) @safe;
}

/// Bounds for an `InMemoryConsentStore`.
struct ConsentStoreOptions
{
	/// Maximum number of approvals retained. When exceeded on `grantConsent`,
	/// the oldest approval is evicted.
	size_t maxApprovals = 10_000;

	/// Maximum number of approvals retained for one client (across browsers).
	/// When exceeded, that client's oldest approval is evicted, so a flood of
	/// approvals for one client churns only its own entries rather than
	/// pushing other clients' approvals out of `maxApprovals`. A client shared by
	/// many users (a CIMD `client_id`, or a common DCR `redirect_uri`) re-prompts
	/// its least recent users for consent past this many; raise it for such a
	/// deployment.
	size_t maxApprovalsPerClient = 1_000;

	/// Maximum number of scopes retained for one approval. `grantConsent` refuses
	/// a grant of more than this with `InvalidScopeException`; a grant that would
	/// grow an existing approval past it replaces that approval's scopes instead,
	/// so a client cannot accumulate scopes without bound.
	size_t maxScopesPerApproval = 4 * maxScopesPerRequest;
}

/// A simple in-memory `ConsentStore` bounded against unauthenticated growth: the
/// number of approvals, overall and per client, is capped, evicting the oldest
/// approval first when a cap is reached, so the (otherwise insert-only) consent
/// map cannot grow process memory without bound. Eviction is amortized O(1).
///
/// NOTE: even bounded, this in-memory default is unsuitable for an
/// internet-exposed multi-process proxy: consent is per-process and lost on
/// restart, and an attacker registering many clients can still cycle the overall
/// cap. Back it with shared, bounded storage (and consider a consent TTL) for
/// such deployments.
final class InMemoryConsentStore : ConsentStore
{
	private static struct Key
	{
		string consentSession;
		string client;
	}

	// One grant of `key`; `serial` tells it apart from a later re-grant of the
	// same key after eviction, whose older queue slot must not evict it.
	private static struct Slot
	{
		Key key;
		ulong serial;
	}

	// Oldest-first grants, consumed from `head`; slots whose grant is gone are
	// skipped, and the array is compacted once they dominate it.
	private static struct SlotQueue
	{
		Slot[] slots;
		size_t head;
	}

	private ulong[Key] approved; // key -> serial of its live grant
	private bool[string][Key] approvedScopes; // key -> the set of scopes approved under it
	private SlotQueue order;
	private SlotQueue[string] orderByClient;
	private size_t[string] countByClient;
	private ulong nextSerial;
	private const ConsentStoreOptions opts;

	this() @safe
	{
		this(ConsentStoreOptions.init);
	}

	/// A store bounded by `opts`.
	this(ConsentStoreOptions opts) @safe
	{
		this.opts = opts;
	}

	override bool hasConsent(string consentSession, string client, const(string)[] scopes) @safe
	{
		import std.algorithm : all;

		if (consentSession.length == 0)
			return false;
		auto granted = Key(consentSession, client) in approvedScopes;
		return granted !is null && scopes.all!(sc => (sc in *granted) !is null);
	}

	/// Throws `InvalidScopeException` when `scopes` holds more than
	/// `ConsentStoreOptions.maxScopesPerApproval` distinct scopes.
	override void grantConsent(string consentSession, string client, const(string)[] scopes) @safe
	{
		bool[string] grant;
		foreach (sc; scopes)
			grant[sc] = true;
		if (grant.length > opts.maxScopesPerApproval)
			throw new InvalidScopeException("too many scopes in one approval");
		if (consentSession.length == 0)
			return;
		const k = Key(consentSession, client);
		if (auto granted = k in approvedScopes)
		{
			size_t added;
			foreach (sc; grant.byKey)
				if (sc !in *granted)
					++added;
			if ((*granted).length + added > opts.maxScopesPerApproval)
				*granted = grant;
			else
				foreach (sc; grant.byKey)
					(*granted)[sc] = true;
			return;
		}
		const slot = Slot(k, nextSerial++);
		approved[k] = slot.serial;
		approvedScopes[k] = grant;
		order.slots ~= slot;
		orderByClient.require(client).slots ~= slot;
		const perClient = ++countByClient.require(client);
		if (perClient > opts.maxApprovalsPerClient)
			evictOldest(orderByClient[client]);
		while (approved.length > opts.maxApprovals)
			if (!evictOldest(order))
				break;
	}

	private bool live(const Slot s) const @safe
	{
		auto p = s.key in approved;
		return p !is null && *p == s.serial;
	}

	// Remove the oldest live grant in `q`, returning false when it holds none.
	private bool evictOldest(ref SlotQueue q) @safe
	{
		while (q.head < q.slots.length)
		{
			const s = q.slots[q.head++];
			if (!live(s))
				continue;
			remove(s.key);
			return true;
		}
		return false;
	}

	private void remove(const Key k) @safe
	{
		approved.remove(k);
		approvedScopes.remove(k);
		auto n = k.client in countByClient;
		if (--*n == 0)
		{
			countByClient.remove(k.client);
			orderByClient.remove(k.client);
		}
		else
			compact(orderByClient[k.client], *n);
		compact(order, approved.length);
	}

	// Drop the skipped and stale slots once they outnumber `liveCount`, keeping
	// the queue proportional to the grants it can still evict.
	private void compact(ref SlotQueue q, size_t liveCount) @safe
	{
		if (q.slots.length - q.head <= 2 * liveCount + 16)
			return;
		Slot[] kept;
		foreach (s; q.slots[q.head .. $])
			if (live(s))
				kept ~= s;
		q.slots = kept;
		q.head = 0;
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

/// What an authorization code the proxy relayed to a client is bound to: the
/// client's PKCE S256 `code_challenge`, the client `redirect_uri` the code was
/// delivered to, and the SEP-991 CIMD `client_id` URL (empty for a DCR client,
/// whose `client_id` is the shared upstream one). `OAuthProxy.redeemCode`
/// checks a `/token` request against it.
struct RelayedCodeBinding
{
	string codeChallenge; /// the client's PKCE S256 `code_challenge`
	string clientRedirectUri; /// the client `redirect_uri` the code was relayed to
	string clientId; /// the CIMD `client_id` URL; empty for a DCR client
}

/// A fetched Client ID Metadata Document and when it is next due a refetch.
private struct CachedClientIdMetadata
{
	ClientIdMetadataDocument doc;
	MonoTime freshUntil;
}

/// Why a Client ID Metadata Document fetch failed, and until when that failure
/// is reported without fetching again.
private struct FailedClientIdMetadata
{
	string reason;
	MonoTime expiresAt;
}

/// The Client ID Metadata Document fetches made to one host in the current
/// rate-limit window.
private struct HostFetchWindow
{
	MonoTime start;
	size_t count;
}

/// How long to cache a Client ID Metadata Document fetched with the
/// `Cache-Control` header value `cacheControl`: its `max-age`, else
/// `OAuthProxy.cimdCacheDefaultTtl`, clamped to `OAuthProxy.cimdCacheMinTtl` ..
/// `OAuthProxy.cimdCacheMaxTtl`. `no-store`/`no-cache` select the minimum.
package Duration cimdCacheTtl(string cacheControl) @safe
{
	import std.algorithm : clamp;
	import std.array : split;
	import std.conv : to;
	import std.string : strip, toLower;

	enum minS = OAuthProxy.cimdCacheMinTtl.total!"seconds";
	enum maxS = OAuthProxy.cimdCacheMaxTtl.total!"seconds";
	foreach (directive; cacheControl.toLower.split(','))
	{
		const d = directive.strip;
		if (d == "no-store" || d == "no-cache")
			return OAuthProxy.cimdCacheMinTtl;
		if (d.startsWith("max-age="))
		{
			try
				return d["max-age=".length .. $].to!long.clamp(minS, maxS).seconds;
			catch (Exception)
				return OAuthProxy.cimdCacheDefaultTtl;
		}
	}
	return OAuthProxy.cimdCacheDefaultTtl;
}

/// Fetches and parses the OAuth Client ID Metadata Document (SEP-991) hosted at a
/// URL-formatted `client_id`. The default fetcher is the SSRF-guarded HTTP fetch
/// (`OAuthProxy.fetchClientIdMetadata`); inject a custom one (e.g. one backed by
/// storage shared across processes, or a test stub) via
/// `OAuthProxy.clientIdMetadataFetcher`.
alias ClientIdMetadataFetcher = ClientIdMetadataDocument delegate(string clientIdUrl) @safe;

/// A reusable OAuth proxy provider. Construct it from an `OAuthProxyConfig`, then
/// read the metadata surface to publish, drive the authorize/token proxying, and
/// obtain a `TokenValidator` for `ResourceServerConfig.validator`.
///
/// The proxy defaults to PASSTHROUGH: the client presents the upstream token as
/// its MCP bearer. A self-brokering server — one that calls a downstream API with
/// the issued token — should set `OAuthProxyConfig.issueToken` + `tokenStore` to
/// switch to ISSUE-OWN-TOKEN (broker) mode, where the proxy mints its own opaque
/// MCP token for the client and keeps the upstream token server-side.
///
/// The proxy and its default in-memory stores do no locking: like the rest of
/// the server, they are used from the fibers of one vibe.d event-loop thread.
/// Serving the router with `HTTPServerOption.distribute` or worker threads is
/// unsupported.
final class OAuthProxy
{
	private OAuthProxyConfig cfg;
	private ConsentStore consentStore;
	private RedirectUriRegistry redirectRegistry;
	private ClientIdMetadataFetcher cimdFetcher;
	private MonoTime delegate() @safe cimdClock;
	private BoundedExpiringMap!RelayedCodeBinding relayedCodes = BoundedExpiringMap!RelayedCodeBinding(
			relayedCodeTtl, maxRelayedCodes, null);

	// Validated Client ID Metadata Documents by client_id URL, so the /consent
	// leg and repeated /authorize requests reuse one fetch. Kept apart from
	// `cimdFailures` so failed fetches can never evict a working client's entry.
	private BoundedExpiringMap!CachedClientIdMetadata cimdCache = BoundedExpiringMap!CachedClientIdMetadata(
			cimdCacheMaxTtl + cimdStaleTtl, maxCachedClientIdMetadata, null);

	// Recently failed fetches by client_id URL.
	private BoundedExpiringMap!FailedClientIdMetadata cimdFailures = BoundedExpiringMap!FailedClientIdMetadata(
			cimdCacheMinTtl, maxCachedClientIdMetadata, null);

	/// How much longer than `cimdCacheMaxTtl` after its last successful fetch a
	/// cached document keeps being served while refetching it fails.
	enum Duration cimdStaleTtl = 1.hours;

	/// How long a fetched Client ID Metadata Document is reused when its
	/// response carries no usable `Cache-Control: max-age`.
	enum Duration cimdCacheDefaultTtl = 5.minutes;

	/// The shortest a fetched document is cached, even under `no-store` or
	/// `max-age=0`: the document host is attacker-chosen, so it must not be able
	/// to make every request trigger a fresh fetch.
	enum Duration cimdCacheMinTtl = 1.minutes;

	/// The longest a fetched document is cached, whatever its `max-age`, so an
	/// edited document is picked up within this window.
	enum Duration cimdCacheMaxTtl = 1.hours;

	/// Maximum number of cached Client ID Metadata Documents.
	enum size_t maxCachedClientIdMetadata = 1_000;

	/// Maximum number of Client ID Metadata Document fetches to one host per
	/// `cimdCacheMinTtl` window. Each distinct `client_id` URL is its own cache
	/// entry, so without this an unauthenticated `/authorize` with random paths
	/// on one host would make the proxy fetch from that host once per request.
	enum size_t maxClientIdMetadataFetchesPerHost = 10;

	// Fetch counts per client_id host, for `maxClientIdMetadataFetchesPerHost`.
	private BoundedExpiringMap!HostFetchWindow cimdFetchesByHost = BoundedExpiringMap!HostFetchWindow(
			cimdCacheMinTtl, maxCachedClientIdMetadata, null);

	/// How long a relayed authorization code stays redeemable at `/token`.
	enum Duration relayedCodeTtl = 10.minutes;

	/// Maximum number of relayed-but-unredeemed codes retained.
	enum size_t maxRelayedCodes = 10_000;

	// SHA-256 digests of the refresh tokens relayed to clients in passthrough
	// mode; only these are forwarded upstream under the proxy's credentials.
	private BoundedExpiringMap!bool relayedRefreshTokens = BoundedExpiringMap!bool(
			relayedRefreshTokenTtl, maxRelayedRefreshTokens, null);

	/// How long a relayed refresh token stays redeemable at `/token` without use.
	enum Duration relayedRefreshTokenTtl = 90.days;

	/// Maximum number of relayed refresh tokens retained; the least recently
	/// recorded is forgotten first.
	enum size_t maxRelayedRefreshTokens = 100_000;

	this(OAuthProxyConfig cfg) @safe
	{
		this(cfg, new InMemoryConsentStore(), new InMemoryRedirectUriRegistry());
	}

	/// Construct with an explicit `ConsentStore` (e.g. a shared-storage backed
	/// store for a multi-process deployment). The store records which clients
	/// each browser has approved, so `authorize` can enforce the confused-deputy
	/// consent MUST.
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
		import std.exception : enforce;

		enforce(cfg.resource.length > 0,
				"OAuthProxy: resource (the canonical MCP server URL) must be set; "
				~ "every token would otherwise fail the audience check.");
		requireSecureUrl(cfg.upstreamAuthorizationEndpoint, cfg.upstreamSsrfPolicy);
		requireSecureUrl(cfg.upstreamTokenEndpoint, cfg.upstreamSsrfPolicy);
		requireSecureUrl(cfg.callbackUrl(), SsrfPolicy.allowLoopback);
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

	/// Handle a DCR (`/register`) request: persist the exact client
	/// `redirect_uris` into the registry (so a later `/authorize` can be checked
	/// against them) and return the registration response. The fixed upstream
	/// `client_id` is shared across clients, so the registry is keyed by a
	/// server-issued registration handle rather than that shared id.
	///
	/// Throws `InvalidRedirectUriException` (registering nothing) when any URI
	/// is one `/authorize` would refuse (`isAllowedRedirectUri`), so a
	/// client learns at registration rather than mid-sign-in. Registered URIs
	/// are stored by `redirectUriMatchKey`, so a loopback IP-literal URI later
	/// matches on any port.
	Json register(const string[] requestedRedirectUris) @safe
	{
		import std.uuid : randomUUID;

		const handle = () @trusted { return randomUUID().toString(); }();
		const capped = requestedRedirectUris.length > maxRedirectUrisPerRegistration
			? requestedRedirectUris[0 .. maxRedirectUrisPerRegistration] : requestedRedirectUris;
		string[] keys;
		foreach (uri; capped)
		{
			if (!isAllowedRedirectUri(uri))
				throw new InvalidRedirectUriException(uri, "not an acceptable redirect URI (https, or http for loopback only; no fragment or userinfo)");
			keys ~= redirectUriMatchKey(uri);
		}
		redirectRegistry.register(handle, keys);
		return registrationResponseJson(cfg, capped);
	}

	/// Reject a client `redirect_uri` that is not safe to relay an authorization
	/// code to. Fails closed by throwing `InvalidRedirectUriException` when the
	/// `redirect_uri` is empty, uses a disallowed scheme (RFC 8252 §7.3), or is
	/// not an exact match against any previously-registered `redirect_uri` (RFC
	/// 6749 §3.1.2.2 / §10.6), ignoring only the port of a loopback IP literal
	/// (RFC 8252 §7.3, `redirectUriMatchKey`). Called by both `authorize` overloads before any
	/// proxy state is minted or the request is forwarded upstream.
	void validateRedirectUri(string clientRedirectUri) @safe
	{
		if (clientRedirectUri.length == 0)
			throw new InvalidRedirectUriException(clientRedirectUri, "redirect_uri is required");
		if (!isAllowedRedirectUri(clientRedirectUri))
			throw new InvalidRedirectUriException(clientRedirectUri, "not an acceptable redirect URI (https, or http for loopback only; no fragment or userinfo)");
		if (!redirectRegistry.isRegistered(redirectUriMatchKey(clientRedirectUri)))
			throw new InvalidRedirectUriException(clientRedirectUri,
					"redirect_uri is not registered for any client");
	}

	/// Whether the browser identified by `consentSession` has already approved
	/// `client` (a DCR client's `redirect_uri`, or a CIMD `client_id` URL) to be
	/// forwarded to the upstream identity provider with every scope in `scopes`.
	/// A client is identified by its `redirectUriMatchKey`, so an approval of a
	/// loopback IP-literal redirect_uri holds for any port, as registration does.
	bool hasConsent(string consentSession, string client, const(string)[] scopes) @safe
	{
		return consentStore.hasConsent(consentSession, redirectUriMatchKey(client), scopes);
	}

	/// The scopes of the space-delimited `scopeStr` this proxy forwards upstream
	/// (see the free function `forwardedScopes`): the set a consent screen shows
	/// and `grantConsent` records.
	string[] forwardedScopes(string scopeStr) const @safe
	{
		return .forwardedScopes(cfg, scopeStr);
	}

	/// Record that the user in the browser identified by `consentSession` has
	/// approved `client` (a DCR client's `redirect_uri`, or a CIMD `client_id`
	/// URL). Call this once the user approves on the proxy's own consent screen,
	/// after verifying the approval came from that browser; subsequent
	/// `authorize` calls from that browser for that client are then forwarded to
	/// the upstream IdP for `scopes` (as `forwardedScopes` yields them). Other
	/// browsers, and requests for scopes not yet approved, still see the consent
	/// screen. The approval is recorded under `redirectUriMatchKey(client)`.
	void grantConsent(string consentSession, string client, const(string)[] scopes) @safe
	{
		consentStore.grantConsent(consentSession, redirectUriMatchKey(client), scopes);
		// A CIMD client a user approved keeps its cached document ahead of ones
		// only ever fetched by anonymous requests.
		cimdCache.markUsed(client);
	}

	/// Build the upstream authorization redirect for a proxied `/authorize`,
	/// gated on per-client user consent (confused-deputy mitigation).
	///
	/// The MCP authorization spec requires that a proxy using a static upstream
	/// `client_id` obtain user consent for EACH dynamically-registered client
	/// before forwarding it to the third-party authorization server. This
	/// overload enforces that: it throws `ConsentRequiredException` unless the
	/// browser identified by `consentSession` has approved the client (identified
	/// by its `clientRedirectUri`, the per-client identity the proxy holds since
	/// the `client_id` is shared) via `grantConsent` for every scope it would
	/// forward (`forwardedScopes`), so a request for broader access than was
	/// approved re-prompts. The integrator presents a consent screen, records
	/// approval, then retries.
	///
	/// Once `clientRedirectUri` validates, its registration is marked pending
	/// (`RedirectUriRegistry.markPending`), so a `/register` flood does not evict
	/// it while the user is signing in.
	string authorize(string consentSession, string clientRedirectUri,
			string codeChallenge, string scopeStr, string state) @safe
	{
		validateRedirectUri(clientRedirectUri);
		redirectRegistry.markPending(redirectUriMatchKey(clientRedirectUri));
		if (!hasConsent(consentSession, clientRedirectUri, forwardedScopes(scopeStr)))
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
		redirectRegistry.markPending(redirectUriMatchKey(clientRedirectUri));
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Install a custom Client ID Metadata Document fetcher (e.g. one backed by
	/// storage shared across processes, or a test stub), replacing the default
	/// SSRF-guarded HTTP fetch. The fail-fast enabled/URL checks and the
	/// per-`client_id` cache in `fetchClientIdMetadata` still apply; a document
	/// it returns is cached for `cimdCacheDefaultTtl`.
	void clientIdMetadataFetcher(ClientIdMetadataFetcher fetcher) @safe
	{
		cimdFetcher = fetcher;
	}

	/// Drive the Client ID Metadata Document cache and fetch budget from
	/// `clock` instead of `MonoTime.currTime` (tests), discarding what they hold.
	package(mcp) void setCimdClock(MonoTime delegate() @safe clock) @safe
	{
		cimdClock = clock;
		cimdCache = BoundedExpiringMap!CachedClientIdMetadata(cimdCacheMaxTtl + cimdStaleTtl,
				maxCachedClientIdMetadata, clock);
		cimdFailures = BoundedExpiringMap!FailedClientIdMetadata(cimdCacheMinTtl,
				maxCachedClientIdMetadata, clock);
		cimdFetchesByHost = BoundedExpiringMap!HostFetchWindow(cimdCacheMinTtl,
				maxCachedClientIdMetadata, clock);
	}

	private MonoTime cimdNow() @safe
	{
		return cimdClock !is null ? cimdClock() : MonoTime.currTime;
	}

	/// Fetch and parse the OAuth Client ID Metadata Document (SEP-991) hosted at a
	/// URL-formatted `client_id`. Fails fast (no network) when CIMD is not enabled
	/// on this proxy or `clientIdUrl` is not a valid https-with-path URL, then
	/// fetches the document via the injected `clientIdMetadataFetcher` if set, else
	/// through the SSRF-guarded connector (`secureRequestHTTP` with the
	/// block-internal policy: resolve + pin, reject internal/link-local targets),
	/// capping the response at `maxClientIdMetadataBytes`. The returned document is
	/// NOT yet validated against the request — pass it to
	/// `authorizeWithClientIdMetadata`, which enforces the SEP-991 MUSTs. Throws
	/// `InvalidClientIdMetadataException` on any fail-fast, fetch, or parse error.
	///
	/// A fetched document is cached per `client_id` for its `Cache-Control`
	/// `max-age` bounded by `cimdCacheMinTtl` .. `cimdCacheMaxTtl` (default
	/// `cimdCacheDefaultTtl`), and a failed fetch for `cimdCacheMinTtl`, so the
	/// `/consent` leg and repeated `/authorize` requests for one client do not
	/// refetch an attacker-chosen URL. Fetches of a `client_id` with no cached
	/// document are further limited to `maxClientIdMetadataFetchesPerHost` per
	/// host per `cimdCacheMinTtl`, so distinct `client_id` paths on one host
	/// cannot each trigger a fetch; past the limit such a `client_id` fails
	/// without a fetch. A cached document is refetched once stale regardless of
	/// that budget, and when the refetch fails the cached copy keeps being served
	/// (retrying every `cimdCacheMinTtl`) until `cimdCacheMaxTtl + cimdStaleTtl`
	/// after its last successful fetch, so neither a
	/// flood of requests for other paths nor an outage of the host locks out a
	/// client already in use. Failed fetches are cached apart from documents and
	/// cannot evict them.
	ClientIdMetadataDocument fetchClientIdMetadata(string clientIdUrl) @safe
	{
		if (!cfg.clientIdMetadataDocumentSupported)
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"Client ID Metadata Documents are not enabled on this proxy");
		if (!isValidClientIdMetadataUrl(clientIdUrl))
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"client_id must be an https URL with a path component (SEP-991)");

		const now = cimdNow();
		auto known = cimdCache.get(clientIdUrl, false);
		if (known !is null && now < known.freshUntil)
			return known.doc;
		if (known is null)
		{
			if (auto failed = cimdFailures.get(clientIdUrl, false))
				if (now < failed.expiresAt)
					throw new InvalidClientIdMetadataException(clientIdUrl, failed.reason);
			// Only a URL with no validated document draws on its host's budget, so
			// requests for other paths on a host cannot block a known client's refetch.
			chargeClientIdMetadataFetch(clientIdUrl, now);
		}

		ClientIdMetadataDocument doc;
		Duration ttl = cimdCacheDefaultTtl;
		try
		{
			if (cimdFetcher !is null)
				doc = cimdFetcher(clientIdUrl);
			else
				doc = fetchClientIdMetadataOverHttp(clientIdUrl, ttl);
		}
		catch (InvalidClientIdMetadataException e)
		{
			if (known !is null)
			{
				known.freshUntil = now + cimdCacheMinTtl;
				return known.doc;
			}
			cimdFailures.put(clientIdUrl, FailedClientIdMetadata(e.msg, now + cimdCacheMinTtl));
			throw e;
		}
		cimdFailures.remove(clientIdUrl);
		cimdCache.put(clientIdUrl, CachedClientIdMetadata(doc, now + ttl));
		return doc;
	}

	// Count a fetch against the client_id host's budget for the current window,
	// throwing when the budget is spent.
	private void chargeClientIdMetadataFetch(string clientIdUrl, MonoTime now) @safe
	{
		import std.uni : toLower;

		const host = hostOf(clientIdUrl["https://".length .. $]).toLower;
		auto w = cimdFetchesByHost.get(host, false);
		if (w is null || now - w.start >= cimdCacheMinTtl)
		{
			cimdFetchesByHost.put(host, HostFetchWindow(now, 1));
			return;
		}
		if (w.count >= maxClientIdMetadataFetchesPerHost)
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"too many metadata document fetches for this host; try again later");
		++w.count;
	}

	// The SSRF-guarded fetch behind `fetchClientIdMetadata`; `ttl` receives the
	// cache lifetime the response's Cache-Control allows.
	private ClientIdMetadataDocument fetchClientIdMetadataOverHttp(string clientIdUrl,
			out Duration ttl) @safe
	{
		import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
		import vibe.http.common : HTTPMethod;
		import vibe.stream.operations : readAllUTF8;

		string responseBody;
		string cacheControl;
		bool ok = false;
		try
		{
			secureRequestHTTP(clientIdUrl, SsrfPolicy.blockInternal, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.GET;
				req.headers["Accept"] = "application/json";
			}, (scope HTTPClientResponse res) {
				if (res.statusCode >= 200 && res.statusCode < 300)
				{
					responseBody = () @trusted {
						return res.bodyReader.readAllUTF8(false, maxClientIdMetadataBytes);
					}();
					cacheControl = res.headers.get("Cache-Control", "");
					ok = true;
				}
				else
					res.dropBody();
			});
		}
		catch (Exception e)
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"failed to fetch metadata document: " ~ e.msg);
		if (!ok)
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"metadata document endpoint did not return a success status");
		ttl = cimdCacheTtl(cacheControl);
		return parseClientIdMetadataDocument(clientIdUrl, responseBody);
	}

	/// Build the upstream authorization redirect for a proxied `/authorize` whose
	/// `client_id` is an OAuth Client ID Metadata Document URL (SEP-991), using an
	/// already-fetched `doc` (fetch it SSRF-safely via `fetchClientIdMetadata`).
	///
	/// The document and `clientRedirectUri` are validated against the SEP-991
	/// AS-side MUSTs (`validateClientIdMetadata`) before anything is forwarded;
	/// the request is then gated on the browser's consent for the client — keyed
	/// on the stable `client_id` URL rather than the redirect_uri, since CIMD
	/// gives the client a durable identity — to satisfy the confused-deputy MUST
	/// (the proxy still collapses every client onto one upstream `client_id`).
	/// Throws `InvalidClientIdMetadataException` when CIMD is not enabled on this
	/// proxy or the document fails validation, and `ConsentRequiredException` when
	/// the browser identified by `consentSession` has not approved the client_id
	/// URL via `grantConsent`.
	string authorizeWithClientIdMetadata(string consentSession,
			string clientIdUrl, const ClientIdMetadataDocument doc,
			string clientRedirectUri, string codeChallenge, string scopeStr, string state) @safe
	{
		if (!cfg.clientIdMetadataDocumentSupported)
			throw new InvalidClientIdMetadataException(clientIdUrl,
					"Client ID Metadata Documents are not enabled on this proxy");
		validateClientIdMetadata(clientIdUrl, doc, clientRedirectUri);
		if (!hasConsent(consentSession, clientIdUrl, forwardedScopes(scopeStr)))
			throw new ConsentRequiredException(clientIdUrl);
		return proxyAuthorizeUrl(cfg, codeChallenge, scopeStr, state);
	}

	/// Record that the upstream authorization `code` is being relayed to a client
	/// under `binding`. Call this at the upstream callback, before redirecting the
	/// code to the client, so a later `/token` can be checked by `redeemCode`.
	void recordRelayedCode(string code, RelayedCodeBinding binding) @safe
	{
		relayedCodes.put(code, binding);
		// A DCR client that got this far has consented and signed in, so its
		// registration is retained ahead of never-used ones.
		if (binding.clientId.length == 0)
			redirectRegistry.markUsed(redirectUriMatchKey(binding.clientRedirectUri));
	}

	/// Record that `refreshToken` is being relayed to a client in an upstream
	/// token response (passthrough mode), so a later `refresh_token` grant
	/// presenting it is forwarded upstream. Only a digest is retained.
	void recordRelayedRefreshToken(string refreshToken) @safe
	{
		if (refreshToken.length == 0)
			return;
		relayedRefreshTokens.put(refreshTokenKey(refreshToken), true);
	}

	/// Consume the record of a relayed `refreshToken`, returning whether this
	/// proxy relayed it. A refresh grant presenting any other token is refused
	/// before it reaches the upstream, so the proxy's confidential client
	/// credentials never back a refresh token obtained elsewhere. The caller
	/// re-records the token (or its rotation) once the upstream answers.
	///
	/// The record is in memory: after a restart, or on another instance of a
	/// multi-process deployment, clients must sign in again to refresh.
	bool takeRelayedRefreshToken(string refreshToken) @safe
	{
		if (refreshToken.length == 0)
			return false;
		bool found;
		cast(void) relayedRefreshTokens.take(refreshTokenKey(refreshToken), found);
		return found;
	}

	private static string refreshTokenKey(string refreshToken) @safe
	{
		import std.digest.sha : sha256Of;
		import mcp.auth.oauth : base64UrlNoPad;

		return base64UrlNoPad(sha256Of(refreshToken)[]);
	}

	/// Check an authorization-code `/token` request against the binding recorded
	/// by `recordRelayedCode`, consuming it (a code is redeemable once, and a
	/// failed attempt burns it). Returns true only when the code was relayed by
	/// this proxy and not yet redeemed, `codeVerifier` satisfies the recorded
	/// S256 `code_challenge` (RFC 7636 §4.6), `redirectUri` equals the one the code
	/// was delivered to (RFC 6749 §4.1.3), and `clientId` is the client that
	/// started the flow (the CIMD `client_id` URL, or the shared upstream
	/// `client_id` for a DCR client). The proxy enforces this itself so the code
	/// stays bound to its client even when the upstream ignores PKCE.
	bool redeemCode(string code, string codeVerifier, string clientId, string redirectUri) @safe
	{
		import std.digest.sha : sha256Of;
		import mcp.auth.oauth : base64UrlNoPad, constantTimeEquals;

		if (code.length == 0 || codeVerifier.length == 0)
			return false;
		bool found;
		RelayedCodeBinding binding;
		binding = relayedCodes.take(code, found);
		if (!found || binding.codeChallenge.length == 0)
			return false;
		const expectedClientId = binding.clientId.length ? binding.clientId : cfg.upstreamClientId;
		if (clientId != expectedClientId || redirectUri != binding.clientRedirectUri)
			return false;
		const challenge = base64UrlNoPad(sha256Of(cast(const(ubyte)[]) codeVerifier)[]);
		return constantTimeEquals(challenge, binding.codeChallenge);
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

	/// Whether the proxy is in ISSUE-OWN-TOKEN (broker) mode: it mints its own
	/// token for the client and keeps the upstream token server-side rather than
	/// relaying the upstream token (passthrough). True only when both `issueToken`
	/// and `tokenStore` are configured.
	bool brokerEnabled() @safe
	{
		return cfg.issueToken !is null && cfg.tokenStore !is null;
	}

	/// Mint the MCP server's OWN token for the client from the `upstream` token
	/// response, stash the upstream access (and refresh, when present) token in the
	/// issued token's claims so the server can call the upstream API on the user's
	/// behalf, store it, and return the opaque token to hand the client. The
	/// audience is bound to the proxy's `resource` so the issued token validates
	/// against this server. Only valid in broker mode (`brokerEnabled`). Throws
	/// when `upstream` carries no access token, so a failed upstream exchange can
	/// never yield a client token.
	BrokeredToken issueClientToken(TokenSet upstream) @safe
	in (cfg.issueToken !is null && cfg.tokenStore !is null)
	{
		import std.algorithm : canFind;
		import std.exception : enforce;

		enforce(upstream.accessToken.length,
				"upstream token response carries no access_token; refusing to mint a client token");
		auto issued = cfg.issueToken(upstream);
		if (cfg.resource.length && !issued.audience.canFind(cfg.resource))
			issued.audience ~= cfg.resource;
		Json claims = issued.claims.type == Json.Type.object ? issued.claims : Json.emptyObject;
		claims[upstreamAccessTokenClaim] = upstream.accessToken;
		if (upstream.refreshToken.length)
			claims[upstreamRefreshTokenClaim] = upstream.refreshToken;
		issued.claims = claims;
		const token = cfg.tokenStore.issue(issued);
		const now = cfg.tokenStore.now();
		const expiresIn = issued.expiresAt == long.max || issued.expiresAt <= now
			? 0 : issued.expiresAt - now;
		return BrokeredToken(token, issued, expiresIn);
	}

	/// A `TokenValidator` for the MCP bearer token clients present: in broker
	/// mode the proxy's own reference token (looked up in `tokenStore`),
	/// otherwise the upstream access token (via `tokenVerifier`, rejecting every
	/// token when none is set). Plug into `ResourceServerConfig.validator`.
	TokenValidator validator() @safe
	{
		return cfg.toResourceServer().validator;
	}
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	import mcp.auth.oauth : ClientIdMetadataDocument;

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

	private ClientIdMetadataDocument sampleCimdDoc() @safe
	{
		ClientIdMetadataDocument d;
		d.clientId = "https://app.example.com/oauth/client.json";
		d.clientName = "Example MCP Client";
		d.redirectUris = ["http://127.0.0.1:8765/callback"];
		return d;
	}
}

unittest  // OAuthProxy refuses a config with no resource, which would reject every request after login
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.resource = "";
	assertThrown(new OAuthProxy(cfg));
}

unittest  // an upstream IdP on a private network is accepted only under a policy that permits it
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.upstreamAuthorizationEndpoint = "https://10.0.0.5/authorize";
	cfg.upstreamTokenEndpoint = "https://10.0.0.5/token";
	assertThrown(new OAuthProxy(cfg));
	cfg.upstreamSsrfPolicy = SsrfPolicy.allowUserConfigured;
	assert(new OAuthProxy(cfg).config.upstreamTokenEndpoint == "https://10.0.0.5/token");
}

unittest  // CIMD ADVERTISE: AS metadata sets client_id_metadata_document_supported when enabled
{
	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto m = authorizationServerMetadata(cfg);
	assert(m.clientIdMetadataDocumentSupported);
	auto j = authorizationServerMetadataJson(cfg);
	assert(j["client_id_metadata_document_supported"].get!bool == true);
	// DCR stays advertised as the deprecated fallback (spec retains it).
	assert(j["registration_endpoint"].get!string == "https://mcp.example.com/register");
}

unittest  // CIMD ADVERTISE: AS metadata omits client_id_metadata_document_supported by default
{
	auto cfg = sampleConfig();
	assert(!cfg.clientIdMetadataDocumentSupported);
	auto j = authorizationServerMetadataJson(cfg);
	assert("client_id_metadata_document_supported" !in j);
}

unittest  // CIMD VALIDATE: a well-formed document whose client_id matches the URL and lists the redirect_uri passes
{
	auto doc = sampleCimdDoc();
	// Must not throw.
	validateClientIdMetadata("https://app.example.com/oauth/client.json", doc,
			"http://127.0.0.1:8765/callback");
}

unittest  // CIMD VALIDATE: the client_id URL must be https with a path component (SEP-991)
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"http://app.example.com/oauth/client.json", doc, "http://127.0.0.1:8765/callback"));
}

unittest  // CIMD VALIDATE: the document's client_id MUST equal the URL exactly
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	doc.clientId = "https://app.example.com/oauth/OTHER.json";
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"https://app.example.com/oauth/client.json", doc, "http://127.0.0.1:8765/callback"));
}

unittest  // CIMD VALIDATE: a document missing client_id (required field) is rejected
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	doc.clientId = "";
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata("",
			doc, "http://127.0.0.1:8765/callback"));
}

unittest  // CIMD VALIDATE: a document with no redirect_uris (required field) is rejected
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	doc.redirectUris = [];
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"https://app.example.com/oauth/client.json", doc, "http://127.0.0.1:8765/callback"));
}

unittest  // CIMD VALIDATE: a document missing client_name (required field) is rejected
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	doc.clientName = "";
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"https://app.example.com/oauth/client.json", doc, "http://127.0.0.1:8765/callback"));
}

unittest  // CIMD VALIDATE: the requested redirect_uri MUST be an exact member of the document's list
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"https://app.example.com/oauth/client.json", doc,
			"http://127.0.0.1:8765/callback/extra"));
}

unittest  // CIMD VALIDATE: a redirect_uri using a disallowed scheme is rejected even if listed
{
	import std.exception : assertThrown;

	auto doc = sampleCimdDoc();
	doc.redirectUris = ["http://evil.example.com/cb"];
	assertThrown!InvalidClientIdMetadataException(validateClientIdMetadata(
			"https://app.example.com/oauth/client.json", doc, "http://evil.example.com/cb"));
}

unittest  // CIMD VALIDATE: the exception names the offending client_id URL
{
	auto doc = sampleCimdDoc();
	doc.clientId = "https://app.example.com/oauth/mismatch.json";
	bool threw = false;
	try
		validateClientIdMetadata("https://app.example.com/oauth/client.json",
				doc, "http://127.0.0.1:8765/callback");
	catch (InvalidClientIdMetadataException e)
	{
		threw = true;
		assert(e.clientId == "https://app.example.com/oauth/client.json");
	}
	assert(threw);
}

unittest  // CIMD AUTHORIZE: with a valid doc + consent on the client_id URL, forwards upstream with the fixed client_id
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto doc = sampleCimdDoc();
	proxy.grantConsent("browser-1", "https://app.example.com/oauth/client.json", [
		"read:user"
	]);
	auto url = proxy.authorizeWithClientIdMetadata("browser-1",
			"https://app.example.com/oauth/client.json",
			doc, "http://127.0.0.1:8765/callback", "CH", "read:user", "S");
	assert(url.startsWith("https://github.com/login/oauth/authorize?"));
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // CIMD AUTHORIZE: confused-deputy gate — an un-consented client_id is refused
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto doc = sampleCimdDoc();
	assertThrown!ConsentRequiredException(proxy.authorizeWithClientIdMetadata("browser-1",
			"https://app.example.com/oauth/client.json",
			doc, "http://127.0.0.1:8765/callback", "CH", "read:user", "S"));
}

unittest  // CIMD AUTHORIZE: an invalid document is rejected before the consent gate is consulted
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto doc = sampleCimdDoc();
	doc.clientId = "https://app.example.com/oauth/OTHER.json"; // mismatch
	proxy.grantConsent("browser-1", "https://app.example.com/oauth/client.json", [
		"read:user"
	]);
	assertThrown!InvalidClientIdMetadataException(proxy.authorizeWithClientIdMetadata("browser-1",
			"https://app.example.com/oauth/client.json",
			doc, "http://127.0.0.1:8765/callback", "CH", "read:user", "S"));
}

unittest  // CIMD AUTHORIZE: refused when the proxy is not configured to support CIMD
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig(); // clientIdMetadataDocumentSupported defaults to false
	auto proxy = new OAuthProxy(cfg);
	auto doc = sampleCimdDoc();
	proxy.grantConsent("browser-1", "https://app.example.com/oauth/client.json", [
		"read:user"
	]);
	assertThrown!InvalidClientIdMetadataException(proxy.authorizeWithClientIdMetadata("browser-1",
			"https://app.example.com/oauth/client.json",
			doc, "http://127.0.0.1:8765/callback", "CH", "read:user", "S"));
}

unittest  // CIMD PARSE: a valid JSON document body parses into a ClientIdMetadataDocument
{
	auto doc = parseClientIdMetadataDocument("https://app.example.com/oauth/client.json",
			`{"client_id":"https://app.example.com/oauth/client.json",`
			~ `"client_name":"Example","redirect_uris":["http://127.0.0.1:8765/callback"]}`);
	assert(doc.clientId == "https://app.example.com/oauth/client.json");
	assert(doc.clientName == "Example");
	assert(doc.redirectUris == ["http://127.0.0.1:8765/callback"]);
}

unittest  // CIMD PARSE: a non-JSON body is rejected (MUST validate document is valid JSON)
{
	import std.exception : assertThrown;

	assertThrown!InvalidClientIdMetadataException(parseClientIdMetadataDocument(
			"https://app.example.com/oauth/client.json", "this is not json"));
}

unittest  // CIMD PARSE: a JSON body that is not an object is rejected
{
	import std.exception : assertThrown;

	assertThrown!InvalidClientIdMetadataException(parseClientIdMetadataDocument(
			"https://app.example.com/oauth/client.json", `["not","an","object"]`));
}

unittest  // CIMD PARSE: a document nested past the depth cap is rejected
{
	import std.array : replicate;
	import std.exception : assertThrown;

	const deep = "[".replicate(1000) ~ "]".replicate(1000);
	assertThrown!InvalidClientIdMetadataException(
			parseClientIdMetadataDocument("https://app.example.com/oauth/client.json",
			`{"client_id":"https://app.example.com/oauth/client.json",`
			~ `"redirect_uris":["http://127.0.0.1:8765/callback"],"x":` ~ deep ~ `}`));
}

unittest  // CIMD FETCH: an injected fetcher is consulted instead of the network
{
	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto doc = sampleCimdDoc();
	bool called = false;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		called = true;
		assert(url == "https://app.example.com/oauth/client.json");
		return doc;
	};
	auto got = proxy.fetchClientIdMetadata("https://app.example.com/oauth/client.json");
	assert(called);
	assert(got.clientId == doc.clientId);
}

unittest  // CIMD CACHE: a document fetched at /authorize is reused for the same client_id
{
	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	int fetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		++fetches;
		return sampleCimdDoc();
	};
	foreach (i; 0 .. 3)
		cast(void) proxy.fetchClientIdMetadata("https://app.example.com/oauth/client.json");
	assert(fetches == 1);
	cast(void) proxy.fetchClientIdMetadata("https://other.example.com/oauth/client.json");
	assert(fetches == 2);
}

unittest  // CIMD CACHE: a failed fetch is cached, so a repeated client_id does not refetch
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	int fetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		++fetches;
		if (url.length)
			throw new InvalidClientIdMetadataException(url, "unreachable");
		return sampleCimdDoc();
	};
	foreach (i; 0 .. 3)
		assertThrown!InvalidClientIdMetadataException(
				proxy.fetchClientIdMetadata("https://app.example.com/oauth/client.json"));
	assert(fetches == 1);
}

unittest  // CIMD FETCH: fetches per host are rate limited, so random client_id paths cannot fan out
{
	import std.conv : to;
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	int fetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		++fetches;
		if (url.length)
			throw new InvalidClientIdMetadataException(url, "unreachable");
		return sampleCimdDoc();
	};
	foreach (i; 0 .. OAuthProxy.maxClientIdMetadataFetchesPerHost * 3)
		assertThrown!InvalidClientIdMetadataException(
				proxy.fetchClientIdMetadata("https://victim.example/" ~ i.to!string));
	assert(fetches == OAuthProxy.maxClientIdMetadataFetchesPerHost);
	// Another host has its own budget.
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("https://other.example/client.json"));
	assert(fetches == OAuthProxy.maxClientIdMetadataFetchesPerHost + 1);
}

unittest  // CIMD FETCH: the per-host fetch budget is case-insensitive in the host
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	int fetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		++fetches;
		return sampleCimdDoc();
	};
	foreach (i; 0 .. OAuthProxy.maxClientIdMetadataFetchesPerHost)
		cast(void) proxy.fetchClientIdMetadata("https://victim.example/" ~ cast(char)('a' + i));
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("https://VICTIM.example/other"));
}

unittest  // CIMD FETCH: a host's spent fetch budget does not lock out a client whose document is already cached
{
	import core.time : minutes;
	import std.conv : to;
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto t = MonoTime.currTime;
	proxy.setCimdClock(() @safe => t);
	const legit = "https://app.example.com/oauth/client.json";
	int legitFetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		if (url != legit)
			throw new InvalidClientIdMetadataException(url, "not found");
		++legitFetches;
		return sampleCimdDoc();
	};
	cast(void) proxy.fetchClientIdMetadata(legit);
	t += OAuthProxy.cimdCacheDefaultTtl + 1.minutes;
	// Unauthenticated requests for other paths on the same host spend its budget.
	foreach (i; 0 .. OAuthProxy.maxClientIdMetadataFetchesPerHost * 2)
		assertThrown!InvalidClientIdMetadataException(
				proxy.fetchClientIdMetadata("https://app.example.com/x" ~ i.to!string));
	assert(proxy.fetchClientIdMetadata(legit).clientId == legit);
	assert(legitFetches == 2);
}

unittest  // CIMD CACHE: a failed refetch of a validated document keeps serving the cached copy
{
	import core.time : minutes;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	auto t = MonoTime.currTime;
	proxy.setCimdClock(() @safe => t);
	bool up = true;
	int fetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		++fetches;
		if (!up)
			throw new InvalidClientIdMetadataException(url, "unreachable");
		return sampleCimdDoc();
	};
	const url = "https://app.example.com/oauth/client.json";
	cast(void) proxy.fetchClientIdMetadata(url);
	up = false;
	t += OAuthProxy.cimdCacheDefaultTtl + 1.minutes;
	assert(proxy.fetchClientIdMetadata(url).clientId == url);
	assert(fetches == 2);
	// The failed refetch backs off rather than retrying on every request.
	assert(proxy.fetchClientIdMetadata(url).clientId == url);
	assert(fetches == 2);
}

unittest  // CIMD CACHE: a flood of failed fetches cannot evict a validated document
{
	import std.conv : to;
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	const legit = "https://app.example.com/oauth/client.json";
	int legitFetches;
	proxy.clientIdMetadataFetcher = (string url) @safe {
		if (url != legit)
			throw new InvalidClientIdMetadataException(url, "not found");
		++legitFetches;
		return sampleCimdDoc();
	};
	cast(void) proxy.fetchClientIdMetadata(legit);
	foreach (h; 0 .. OAuthProxy.maxCachedClientIdMetadata
			/ OAuthProxy.maxClientIdMetadataFetchesPerHost + 2)
		foreach (i; 0 .. OAuthProxy.maxClientIdMetadataFetchesPerHost)
			assertThrown!InvalidClientIdMetadataException(proxy.fetchClientIdMetadata(
					"https://h" ~ h.to!string ~ ".example/" ~ i.to!string));
	cast(void) proxy.fetchClientIdMetadata(legit);
	assert(legitFetches == 1);
}

unittest  // CIMD CACHE: Cache-Control max-age sets the cache lifetime within fixed bounds
{
	import core.time : hours, minutes, seconds;

	assert(cimdCacheTtl("") == OAuthProxy.cimdCacheDefaultTtl);
	assert(cimdCacheTtl("public, max-age=600") == 600.seconds);
	assert(cimdCacheTtl("Max-Age=120") == 120.seconds);
	// An attacker-hosted document cannot opt out of caching or pin it for long.
	assert(cimdCacheTtl("no-store") == OAuthProxy.cimdCacheMinTtl);
	assert(cimdCacheTtl("max-age=0") == OAuthProxy.cimdCacheMinTtl);
	assert(cimdCacheTtl("max-age=31536000") == OAuthProxy.cimdCacheMaxTtl);
	assert(cimdCacheTtl("max-age=bogus") == OAuthProxy.cimdCacheDefaultTtl);
}

unittest  // CIMD FETCH: even with an injected fetcher, a malformed client_id URL fails fast
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	proxy.clientIdMetadataFetcher = (string url) @safe { return sampleCimdDoc(); };
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("http://app.example.com/oauth/client.json"));
}

unittest  // CIMD FETCH: fails fast (no network) when CIMD is not enabled on the proxy
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("https://app.example.com/oauth/client.json"));
}

unittest  // CIMD FETCH: fails fast (no network) on a non-https client_id URL
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("http://app.example.com/oauth/client.json"));
}

unittest  // CIMD FETCH: fails fast (no network) on an https client_id URL with no path component
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	cfg.clientIdMetadataDocumentSupported = true;
	auto proxy = new OAuthProxy(cfg);
	assertThrown!InvalidClientIdMetadataException(
			proxy.fetchClientIdMetadata("https://app.example.com"));
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

unittest  // AS metadata advertises the default grant types when not overridden
{
	auto cfg = sampleConfig();
	auto j = authorizationServerMetadataJson(cfg);
	assert(j["grant_types_supported"].length == 2);
	assert(j["grant_types_supported"][0].get!string == "authorization_code");
	assert(j["grant_types_supported"][1].get!string == "refresh_token");
}

unittest  // a custom grant_types_supported override flows into the published AS metadata
{
	auto cfg = sampleConfig();
	cfg.grantTypesSupported = ["authorization_code"];
	auto j = authorizationServerMetadataJson(cfg);
	assert(j["grant_types_supported"].length == 1);
	assert(j["grant_types_supported"][0].get!string == "authorization_code");
}

unittest  // PRM names the proxy itself as the authorization server
{
	auto cfg = sampleConfig();
	auto m = cfg.toResourceServer().metadata();
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

unittest  // proxied /authorize forwards only the scopes listed in scopesSupported
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig(); // scopesSupported: read:user, repo
	auto url = proxyAuthorizeUrl(cfg, "CHALLENGE", "read:user admin:org repo", "S");
	assert(url.canFind("scope=read%3Auser%20repo&"), url);
	assert(!url.canFind("admin"), url);
}

unittest  // with no scopesSupported configured, the requested scopes are forwarded as-is
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	cfg.scopesSupported = null;
	auto url = proxyAuthorizeUrl(cfg, "CHALLENGE", "read:user admin:org", "S");
	assert(url.canFind("admin%3Aorg"), url);
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
	assertThrown!ConsentRequiredException(proxy.authorize("browser-1",
			"http://localhost:5000/callback", "CH", "read:user", "S"));
}

unittest  // CONFUSED DEPUTY: after grantConsent the gated authorize forwards upstream
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/callback"]);
	proxy.grantConsent("browser-1", "http://localhost:5000/callback", [
		"read:user"
	]);
	auto url = proxy.authorize("browser-1", "http://localhost:5000/callback",
			"CH", "read:user", "S");
	assert(url.startsWith("https://github.com/login/oauth/authorize?"));
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // CONFUSED DEPUTY: consent for some scopes does not cover a request for broader ones
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["http://localhost:5000/callback"]);
	proxy.grantConsent("browser-1", "http://localhost:5000/callback", [
		"read:user"
	]);
	assertThrown!ConsentRequiredException(proxy.authorize("browser-1",
			"http://localhost:5000/callback", "CH", "read:user repo", "S"));
	cast(void) proxy.authorize("browser-1", "http://localhost:5000/callback",
			"CH", "read:user", "S");
}

unittest  // CONFUSED DEPUTY: a scope the proxy would not forward needs no consent
{
	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["http://localhost:5000/callback"]);
	proxy.grantConsent("browser-1", "http://localhost:5000/callback", [
		"read:user"
	]);
	cast(void) proxy.authorize("browser-1", "http://localhost:5000/callback",
			"CH", "read:user admin:org", "S");
}

unittest  // CONSENT STORE: a later grant adds scopes to the client's existing approval
{
	auto store = new InMemoryConsentStore();
	store.grantConsent("b", "http://a/cb", ["read"]);
	store.grantConsent("b", "http://a/cb", ["write"]);
	assert(store.hasConsent("b", "http://a/cb", ["read", "write"]));
	assert(store.hasConsent("b", "http://a/cb", []));
	assert(!store.hasConsent("b", "http://a/cb", ["admin"]));
}

unittest  // CONSENT STORE: an evicted approval takes its scopes with it
{
	auto store = new InMemoryConsentStore(ConsentStoreOptions(1, 1));
	store.grantConsent("b", "http://a/cb", ["read"]);
	store.grantConsent("b", "http://c/cb", ["read"]); // evicts a
	store.grantConsent("b", "http://a/cb", []);
	assert(!store.hasConsent("b", "http://a/cb", ["read"]));
}

unittest  // CONFUSED DEPUTY: consent is per-client (one approval does not cover another)
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register([
		"http://localhost:5000/callback", "http://localhost:6000/callback"
	]);
	proxy.grantConsent("browser-1", "http://localhost:5000/callback", [
		"read:user"
	]);
	assert(proxy.hasConsent("browser-1", "http://localhost:5000/callback", null));
	assert(!proxy.hasConsent("browser-1", "http://localhost:6000/callback", null));
	assertThrown!ConsentRequiredException(proxy.authorize("browser-1",
			"http://localhost:6000/callback", "CH", "read:user", "S"));
}

unittest  // CONSENT: approval of a loopback IP-literal redirect_uri covers the same client on another port
{
	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["http://127.0.0.1:5000/callback"]);
	proxy.grantConsent("browser-1", "http://127.0.0.1:5000/callback", [
		"read:user"
	]);
	assert(proxy.hasConsent("browser-1", "http://127.0.0.1:61234/callback", [
		"read:user"
	]));
	cast(void) proxy.authorize("browser-1", "http://127.0.0.1:61234/callback",
			"CH", "read:user", "S");
}

unittest  // CONSENT: approval of a loopback redirect_uri does not cover a different path
{
	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["http://127.0.0.1:5000/callback"]);
	proxy.grantConsent("browser-1", "http://127.0.0.1:5000/callback", [
		"read:user"
	]);
	assert(!proxy.hasConsent("browser-1", "http://127.0.0.1:5000/other", [
		"read:user"
	]));
}

unittest  // CONFUSED DEPUTY: the exception names the client redirect_uri needing consent
{
	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:7000/cb"]);
	bool threw = false;
	try
		proxy.authorize("browser-1", "http://localhost:7000/cb", "CH", "s", "S");
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
	assert(!store.hasConsent("browser-1", "http://a/cb", null));
	store.grantConsent("browser-1", "http://a/cb", null);
	assert(store.hasConsent("browser-1", "http://a/cb", null));
	assert(!store.hasConsent("browser-1", "http://b/cb", null));
}

unittest  // CODE BINDING: a DCR client redeems a relayed code with its verifier, the shared client_id and its redirect_uri
{
	import mcp.auth.oauth : makePkce;

	auto proxy = new OAuthProxy(sampleConfig());
	const pkce = makePkce(cast(const(ubyte)[]) "0123456789abcdef0123456789abcdef");
	proxy.recordRelayedCode("CODE", RelayedCodeBinding(pkce.challenge,
			"http://localhost:5000/cb", ""));
	assert(proxy.redeemCode("CODE", pkce.verifier, "Iv1.upstream", "http://localhost:5000/cb"));
	assert(!proxy.redeemCode("CODE", pkce.verifier, "Iv1.upstream", "http://localhost:5000/cb"));
}

unittest  // CODE BINDING: a CIMD code must be redeemed by the client_id URL that started the flow
{
	import mcp.auth.oauth : makePkce;

	auto proxy = new OAuthProxy(sampleConfig());
	const pkce = makePkce(cast(const(ubyte)[]) "0123456789abcdef0123456789abcdef");
	const cimd = "https://app.example.com/oauth/client.json";
	proxy.recordRelayedCode("A", RelayedCodeBinding(pkce.challenge,
			"http://127.0.0.1:8765/cb", cimd));
	assert(!proxy.redeemCode("A", pkce.verifier, "Iv1.upstream", "http://127.0.0.1:8765/cb"));
	proxy.recordRelayedCode("B", RelayedCodeBinding(pkce.challenge,
			"http://127.0.0.1:8765/cb", cimd));
	assert(proxy.redeemCode("B", pkce.verifier, cimd, "http://127.0.0.1:8765/cb"));
}

unittest  // CODE BINDING: a failed redemption burns the code
{
	import mcp.auth.oauth : makePkce;

	auto proxy = new OAuthProxy(sampleConfig());
	const pkce = makePkce(cast(const(ubyte)[]) "0123456789abcdef0123456789abcdef");
	proxy.recordRelayedCode("CODE", RelayedCodeBinding(pkce.challenge,
			"http://localhost:5000/cb", ""));
	assert(!proxy.redeemCode("CODE", "guess", "Iv1.upstream", "http://localhost:5000/cb"));
	assert(!proxy.redeemCode("CODE", pkce.verifier, "Iv1.upstream", "http://localhost:5000/cb"));
}

unittest  // CONFUSED DEPUTY: consent granted in one browser does not cover another browser
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["https://evil.example/cb"]);
	proxy.grantConsent("attacker-browser", "https://evil.example/cb", [
		"read:user"
	]);
	assert(!proxy.hasConsent("victim-browser", "https://evil.example/cb", null));
	assertThrown!ConsentRequiredException(proxy.authorize("victim-browser",
			"https://evil.example/cb", "CH", "read:user", "S"));
}

unittest  // InMemoryConsentStore never records or reports consent for an empty browser session
{
	ConsentStore store = new InMemoryConsentStore();
	store.grantConsent("", "http://a/cb", null);
	assert(!store.hasConsent("", "http://a/cb", null));
}

unittest  // a custom ConsentStore can be injected and is consulted by authorize
{
	import std.algorithm : canFind;

	auto cfg = sampleConfig();
	auto store = new InMemoryConsentStore();
	store.grantConsent("browser-1", "http://localhost:9000/cb", ["read:user"]);
	auto proxy = new OAuthProxy(cfg, store);
	proxy.register(["http://localhost:9000/cb"]);
	auto url = proxy.authorize("browser-1", "http://localhost:9000/cb", "CH", "read:user", "S");
	assert(url.canFind("client_id=Iv1.upstream"));
}

unittest  // REDIRECT VALIDATION: gated authorize rejects an unregistered redirect_uri
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	auto proxy = new OAuthProxy(cfg);
	proxy.grantConsent("browser-1", "https://attacker.example/cb", ["read:user"]);
	// Consent alone must not let an unregistered redirect_uri through.
	assertThrown!InvalidRedirectUriException(proxy.authorize("browser-1",
			"https://attacker.example/cb", "CH", "read:user", "S"));
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
	assert(isAllowedRedirectUri("https://app.example.com/cb"));
}

unittest  // SCHEME ALLOWLIST: http to loopback is accepted (RFC 8252)
{
	assert(isAllowedRedirectUri("http://127.0.0.1:8765/cb"));
	assert(isAllowedRedirectUri("http://localhost:5000/callback"));
	assert(isAllowedRedirectUri("http://[::1]:9000/cb"));
}

unittest  // SCHEME ALLOWLIST: bare (unbracketed) IPv6 loopback is rejected; RFC 3986 §3.2.2 requires brackets
{
	assert(!isAllowedRedirectUri("http://::1/cb"));
	assert(!isAllowedRedirectUri("http://::1:8080/cb"));
}

unittest  // SCHEME ALLOWLIST: http to a non-loopback host is rejected
{
	assert(!isAllowedRedirectUri("http://app.example.com/cb"));
	assert(!isAllowedRedirectUri("http://evil.test/cb"));
}

unittest  // SCHEME ALLOWLIST: userinfo after a fragment, query or backslash does not make a host loopback
{
	assert(!isAllowedRedirectUri("http://evil.example#@127.0.0.1/cb"));
	assert(!isAllowedRedirectUri("http://evil.example?@localhost/cb"));
	assert(!isAllowedRedirectUri("http://evil.example\\@localhost/cb"));
	assert(!isAllowedRedirectUri("http://evil.example?x=@[::1]"));
}

unittest  // SCHEME ALLOWLIST: a redirect URI carrying a fragment is rejected (RFC 6749 §3.1.2)
{
	assert(!isAllowedRedirectUri("https://app.example.com/cb#frag"));
	assert(!isAllowedRedirectUri("http://127.0.0.1:8765/cb#"));
}

unittest  // REDIRECT URI: a URI carrying userinfo is rejected
{
	assert(!isAllowedRedirectUri("http://user@127.0.0.1:8765/cb?x=1"));
	assert(!isAllowedRedirectUri("http://127.0.0.1@evil.example/cb"));
	assert(!isAllowedRedirectUri("https://user:pw@app.example.com/cb"));
	assert(!isAllowedRedirectUri("https://@app.example.com/cb"));
	// An '@' after the authority is not userinfo.
	assert(isAllowedRedirectUri("https://app.example.com/cb?who=a@b"));
}

unittest  // REDIRECT URI: a URI with an empty host or a malformed port is rejected
{
	assert(!isAllowedRedirectUri("https://"));
	assert(!isAllowedRedirectUri("https:///cb"));
	assert(!isAllowedRedirectUri("https://:443/cb"));
	assert(!isAllowedRedirectUri("https://?x=1"));
	assert(!isAllowedRedirectUri("https://[]/cb"));
	assert(!isAllowedRedirectUri("https://app.example.com:44x/cb"));
	assert(!isAllowedRedirectUri("https://[::1]x/cb"));
	assert(isAllowedRedirectUri("https://app.example.com:8443/cb"));
	assert(isAllowedRedirectUri("https://app.example.com"));
}

unittest  // REDIRECT URI: whitespace, control characters, backslashes and non-ASCII are rejected
{
	assert(!isAllowedRedirectUri("https://app.example.com/c b"));
	assert(!isAllowedRedirectUri("https://app.example.com/cb\r\nSet-Cookie: x=1"));
	assert(!isAllowedRedirectUri("https://app.example.com/cb\t"));
	assert(!isAllowedRedirectUri("https://app.example.com/cb\x7f"));
	assert(!isAllowedRedirectUri("https://app.example.com\\cb"));
	assert(!isAllowedRedirectUri("https://app.exämple.com/cb"));
}

unittest  // SCHEME ALLOWLIST: a custom/private-use scheme is rejected
{
	assert(!isAllowedRedirectUri("com.example.app:/oauth/cb"));
	assert(!isAllowedRedirectUri("javascript:alert(1)"));
	assert(!isAllowedRedirectUri(""));
}

unittest  // SCHEME ALLOWLIST: a registered scheme is still scheme-checked (registered http non-loopback rejected)
{
	import std.exception : assertThrown;

	auto cfg = sampleConfig();
	// Even if a registry held such a URI, the scheme gate rejects it.
	auto reg = new InMemoryRedirectUriRegistry();
	reg.register("h", ["http://app.example.com/cb"]);
	auto proxy = new OAuthProxy(cfg, new InMemoryConsentStore(), reg);
	assertThrown!InvalidRedirectUriException(proxy.validateRedirectUri("http://app.example.com/cb"));
}

unittest  // REGISTER: a redirect_uri /authorize would never accept is refused at registration
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(sampleConfig());
	assertThrown!InvalidRedirectUriException(proxy.register([
		"com.example.app:/oauth/cb"
	]));
	assertThrown!InvalidRedirectUriException(proxy.register([
		"https://app.example.com/cb", "http://app.example.com/cb"
	]));
	assertThrown!InvalidRedirectUriException(proxy.register([
		"https://app.example.com/cb#frag"
	]));
	// Nothing from a refused registration is retained.
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("https://app.example.com/cb"));
}

unittest  // LOOPBACK: a loopback IP-literal redirect_uri matches on any port (RFC 8252 §7.3)
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["http://127.0.0.1/callback", "http://[::1]:5000/callback"]);
	proxy.validateRedirectUri("http://127.0.0.1:61234/callback");
	proxy.validateRedirectUri("http://127.0.0.1/callback");
	proxy.validateRedirectUri("http://[::1]:49152/callback");
	// Path, query and host still match exactly.
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("http://127.0.0.1:61234/other"));
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("http://127.0.0.1:61234/callback?x=1"));
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("http://127.0.0.2:61234/callback"));
}

unittest  // LOOPBACK: a non-loopback redirect_uri still matches its port exactly
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(sampleConfig());
	proxy.register(["https://app.example.com/cb", "http://localhost:5000/cb"]);
	assertThrown!InvalidRedirectUriException(
			proxy.validateRedirectUri("https://app.example.com:8443/cb"));
	assertThrown!InvalidRedirectUriException(proxy.validateRedirectUri("http://localhost:6000/cb"));
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

unittest  // REDIRECT REGISTRY: a registration with a pending authorization is evicted after idle ones
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("h1", ["https://a/cb"]);
	reg.register("h2", ["https://b/cb"]);
	reg.markPending("https://a/cb");
	reg.register("h3", ["https://c/cb"]);
	assert(reg.isRegistered("https://a/cb"));
	assert(!reg.isRegistered("https://b/cb"));
	assert(reg.isRegistered("https://c/cb"));
}

unittest  // REDIRECT REGISTRY: a pending authorization keeps an unused registration past its unused TTL
{
	import core.time : minutes;

	auto t = MonoTime.currTime;
	RedirectUriRegistryOptions opts;
	opts.clock = () @safe => t;
	auto reg = new InMemoryRedirectUriRegistry(opts);
	reg.register("h1", ["https://a/cb"]);
	t += opts.unusedTtl - 1.minutes;
	reg.markPending("https://a/cb");
	t += 2.minutes;
	assert(reg.isRegistered("https://a/cb"));
	t += opts.pendingTtl + opts.unusedTtl;
	assert(!reg.isRegistered("https://a/cb"));
}

unittest  // REDIRECT REGISTRY: an authorization in progress keeps its registration through a /register flood
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	auto proxy = new OAuthProxy(sampleConfig(), new InMemoryConsentStore(), reg);
	proxy.register(["https://a.example/cb"]);
	try
		cast(void) proxy.authorize("browser-1", "https://a.example/cb", "CH", "read:user", "S");
	catch (ConsentRequiredException)
	{
	}
	proxy.register(["https://b.example/cb"]);
	proxy.register(["https://c.example/cb"]);
	proxy.validateRedirectUri("https://a.example/cb");
}

unittest  // REDIRECT REGISTRY: the registry caps live registrations, evicting the oldest as a unit
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("h1", ["https://a/cb"]);
	reg.register("h2", ["https://b/cb"]);
	// Third registration exceeds the cap of 2: the oldest ("h1") is evicted whole.
	reg.register("h3", ["https://c/cb"]);
	assert(!reg.isRegistered("https://a/cb"));
	assert(reg.isRegistered("https://b/cb"));
	assert(reg.isRegistered("https://c/cb"));
}

unittest  // REDIRECT REGISTRY: a /register flood evicts never-used registrations before one in use
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("legit", ["https://app.example/cb"]);
	// The legitimate client goes on to sign a user in with its redirect_uri.
	reg.markUsed("https://app.example/cb");
	// Anonymous registrations flood past the cap.
	foreach (i; 0 .. 5)
		reg.register("flood-" ~ cast(char)('0' + i),
				["https://flood.example/cb" ~ cast(char)('0' + i)]);
	assert(reg.isRegistered("https://app.example/cb"));
	assert(reg.isRegistered("https://flood.example/cb4"));
	assert(!reg.isRegistered("https://flood.example/cb0"));
}

unittest  // REDIRECT REGISTRY: when every registration is in use the oldest is evicted
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("h1", ["https://a/cb"]);
	reg.register("h2", ["https://b/cb"]);
	reg.markUsed("https://a/cb");
	reg.markUsed("https://b/cb");
	reg.register("h3", ["https://c/cb"]);
	assert(!reg.isRegistered("https://a/cb"));
	assert(reg.isRegistered("https://b/cb"));
	assert(reg.isRegistered("https://c/cb"));
}

unittest  // REDIRECT REGISTRY: a redirect_uri shared by two registrations survives evicting one
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
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

unittest  // CONSENT STORE: a flood of approvals for one client cannot evict another client's consent
{
	ConsentStoreOptions opts;
	opts.maxApprovals = 3;
	opts.maxApprovalsPerClient = 2;
	auto store = new InMemoryConsentStore(opts);
	store.grantConsent("real-browser", "http://real/cb", null);
	foreach (i; 0 .. 50)
	{
		import std.conv : to;

		store.grantConsent("flood-" ~ i.to!string, "http://attacker/cb", null);
	}
	assert(store.hasConsent("real-browser", "http://real/cb", null));
	// The flooding client keeps only its newest approvals.
	assert(store.hasConsent("flood-49", "http://attacker/cb", null));
	assert(store.hasConsent("flood-48", "http://attacker/cb", null));
	assert(!store.hasConsent("flood-47", "http://attacker/cb", null));
}

unittest  // CONSENT STORE: an approval evicted and granted again is not evicted early by its old slot
{
	ConsentStoreOptions opts;
	opts.maxApprovals = 2;
	auto store = new InMemoryConsentStore(opts);
	store.grantConsent("b1", "http://a/cb", null);
	store.grantConsent("b1", "http://b/cb", null);
	store.grantConsent("b1", "http://c/cb", null); // evicts a
	store.grantConsent("b1", "http://a/cb", null); // evicts b; a is now the newest
	store.grantConsent("b1", "http://d/cb", null); // evicts c, not a
	assert(store.hasConsent("b1", "http://a/cb", null));
	assert(!store.hasConsent("b1", "http://c/cb", null));
	assert(store.hasConsent("b1", "http://d/cb", null));
}

unittest  // SCOPE CAP: a request naming more than maxScopesPerRequest distinct scopes is refused
{
	import std.array : join;
	import std.conv : to;
	import std.exception : assertNotThrown, assertThrown;
	import std.range : iota;
	import std.algorithm : map;

	auto cfg = sampleConfig();
	cfg.scopesSupported = null;
	const atCap = iota(maxScopesPerRequest).map!(i => "s" ~ i.to!string).join(" ");
	assert(assertNotThrown(forwardedScopes(cfg, atCap ~ " s0")).length == maxScopesPerRequest);
	assertThrown!InvalidScopeException(forwardedScopes(cfg, atCap ~ " extra"));
	// Unsupported scopes count too: the cap bounds the work, not just the result.
	assertThrown!InvalidScopeException(forwardedScopes(sampleConfig(), atCap ~ " extra"));
}

unittest  // SCOPE CAP: a consent store refuses an approval of more than maxScopesPerApproval scopes
{
	import std.exception : assertThrown;

	ConsentStoreOptions opts;
	opts.maxScopesPerApproval = 2;
	auto store = new InMemoryConsentStore(opts);
	assertThrown!InvalidScopeException(store.grantConsent("browser-1",
			"http://a/cb", ["a", "b", "c"]));
	assert(!store.hasConsent("browser-1", "http://a/cb", null));
}

unittest  // SCOPE CAP: an approval that would outgrow maxScopesPerApproval replaces the earlier scopes
{
	ConsentStoreOptions opts;
	opts.maxScopesPerApproval = 3;
	auto store = new InMemoryConsentStore(opts);
	store.grantConsent("browser-1", "http://a/cb", ["a", "b"]);
	store.grantConsent("browser-1", "http://a/cb", ["b", "c"]);
	assert(store.hasConsent("browser-1", "http://a/cb", ["a", "b", "c"]));
	store.grantConsent("browser-1", "http://a/cb", ["d", "e"]);
	assert(store.hasConsent("browser-1", "http://a/cb", ["d", "e"]));
	assert(!store.hasConsent("browser-1", "http://a/cb", ["a"]));
}

unittest  // CONSENT STORE: the consent store caps approvals, evicting the oldest first
{
	ConsentStoreOptions opts;
	opts.maxApprovals = 2;
	auto store = new InMemoryConsentStore(opts);
	store.grantConsent("browser-1", "http://a/cb", null);
	store.grantConsent("browser-1", "http://b/cb", null);
	// Third approval exceeds the cap of 2: the oldest ("a") is evicted.
	store.grantConsent("browser-1", "http://c/cb", null);
	assert(!store.hasConsent("browser-1", "http://a/cb", null));
	assert(store.hasConsent("browser-1", "http://b/cb", null));
	assert(store.hasConsent("browser-1", "http://c/cb", null));
}

unittest  // CONSENT STORE: re-granting an existing consent does not consume cap headroom
{
	ConsentStoreOptions opts;
	opts.maxApprovals = 2;
	auto store = new InMemoryConsentStore(opts);
	store.grantConsent("browser-1", "http://a/cb", null);
	store.grantConsent("browser-1", "http://a/cb", null); // duplicate: no new slot used
	store.grantConsent("browser-1", "http://b/cb", null);
	// "a" must still be present: the duplicate did not push it out of the cap.
	assert(store.hasConsent("browser-1", "http://a/cb", null));
	assert(store.hasConsent("browser-1", "http://b/cb", null));
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

unittest  // CONSTRUCTOR SECURITY: a plaintext (http) baseUrl over a non-loopback host is rejected
{
	import std.exception : assertThrown;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "client-id";
	cfg.baseUrl = "http://mcp.example.com"; // insecure non-loopback base URL
	cfg.resource = cfg.baseUrl ~ "/mcp";
	assertThrown(new OAuthProxy(cfg));
}

unittest  // CONSTRUCTOR SECURITY: a loopback http baseUrl is accepted for local development
{
	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "client-id";
	cfg.baseUrl = "http://127.0.0.1:8080"; // loopback dev config is allowed
	cfg.resource = cfg.baseUrl ~ "/mcp";
	auto proxy = new OAuthProxy(cfg); // must not throw
	assert(proxy !is null);
}

unittest  // REDIRECT REGISTRY: re-registering the same handle drops its old URIs
{
	// A duplicate-handle registration must drop the old URIs before overwriting
	// the handle entry, so that isRegistered never returns true for a URI whose
	// registration no longer exists.
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("same-handle", ["https://old.example.com/cb"]);
	reg.register("same-handle", ["https://new.example.com/cb"]);
	// Force eviction of the (now phantom) duplicate order entry by adding a third handle.
	reg.register("h3", ["https://h3.example.com/cb"]);
	// The old URI is no longer part of any live registration.
	assert(!reg.isRegistered("https://old.example.com/cb"));
	// The new URI and h3 URI remain registered.
	assert(reg.isRegistered("https://new.example.com/cb"));
	assert(reg.isRegistered("https://h3.example.com/cb"));
}

unittest  // REDIRECT REGISTRY: looking a registration up does not shield it from eviction
{
	// A flood of registrations that are each looked up at /authorize, without
	// ever completing a sign-in, must not displace a client that has.
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("legit", ["https://app.example/cb"]);
	reg.markUsed("https://app.example/cb");
	foreach (i; 0 .. 5)
	{
		const uri = "https://flood.example/cb" ~ cast(char)('0' + i);
		reg.register("flood-" ~ cast(char)('0' + i), [uri]);
		assert(reg.isRegistered(uri));
	}
	assert(reg.isRegistered("https://app.example/cb"));
}

unittest  // REDIRECT REGISTRY: a /register flood at the cap evicts in constant time per registration
{
	import core.time : seconds;
	import std.conv : to;
	import std.datetime.stopwatch : AutoStart, StopWatch;

	// Every flood registration names the same URI, so one handle list and the
	// eviction order both sit at the cap; a linear-cost eviction makes this
	// quadratic and blows well past the bound.
	auto reg = new InMemoryRedirectUriRegistry();
	auto sw = StopWatch(AutoStart.yes);
	foreach (i; 0 .. 60_000)
		reg.register("flood-" ~ i.to!string, ["https://flood.example/cb"]);
	assert(sw.peek < 5.seconds);
	assert(reg.isRegistered("https://flood.example/cb"));
}

unittest  // REDIRECT REGISTRY: an evicted registration's URI stays registered via a newer one
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	reg.register("a", ["https://shared.example/cb", "https://a.example/cb"]);
	reg.register("b", ["https://shared.example/cb"]);
	reg.register("c", ["https://c.example/cb"]); // evicts a
	assert(!reg.isRegistered("https://a.example/cb"));
	assert(reg.isRegistered("https://shared.example/cb"));
	reg.register("d", ["https://d.example/cb"]); // evicts b
	assert(!reg.isRegistered("https://shared.example/cb"));
}

unittest  // REDIRECT REGISTRY: an unused registration expires after the unused TTL
{
	import core.time : MonoTime, hours, minutes;

	auto now = MonoTime.currTime;
	RedirectUriRegistryOptions opts;
	opts.unusedTtl = 1.hours;
	opts.clock = () @safe => now;
	auto reg = new InMemoryRedirectUriRegistry(opts);
	reg.register("unused", ["https://unused.example/cb"]);
	reg.register("used", ["https://used.example/cb"]);
	reg.markUsed("https://used.example/cb");

	now += 59.minutes;
	assert(reg.isRegistered("https://unused.example/cb"));
	now += 2.minutes;
	assert(!reg.isRegistered("https://unused.example/cb"));
	// A registration that completed a sign-in does not expire.
	assert(reg.isRegistered("https://used.example/cb"));
}

unittest  // REDIRECT REGISTRY: relaying a code marks the DCR client's registration as used
{
	auto reg = new InMemoryRedirectUriRegistry(RedirectUriRegistryOptions(2));
	auto proxy = new OAuthProxy(sampleConfig(), new InMemoryConsentStore(), reg);
	proxy.register(["https://app.example.com/cb"]);
	proxy.recordRelayedCode("C", RelayedCodeBinding("CH", "https://app.example.com/cb", ""));
	foreach (i; 0 .. 5)
		proxy.register(["https://flood.example.com/cb" ~ cast(char)('0' + i)]);
	proxy.validateRedirectUri("https://app.example.com/cb");
}

version (unittest)
{
	import mcp.auth.oauth : TokenSet;
	import mcp.auth.reference_token : IssuedToken, ReferenceTokenStore, referenceTokenValidator;

	// A broker-mode proxy config: after the upstream exchange the proxy mints its
	// OWN token for the client and stashes the upstream token server-side.
	private OAuthProxyConfig brokerConfig() @safe
	{
		auto cfg = sampleConfig();
		cfg.tokenStore = new ReferenceTokenStore();
		cfg.issueToken = (TokenSet upstream) @safe {
			IssuedToken t;
			t.subject = "octocat";
			t.scopes = ["read:user"];
			t.expiresAt = long.max;
			return t;
		};
		return cfg;
	}
}

unittest  // BROKER: a config with both issueToken and tokenStore is in broker mode
{
	auto proxy = new OAuthProxy(brokerConfig());
	assert(proxy.brokerEnabled());
}

unittest  // BROKER: passthrough remains the default (no issueToken, no tokenStore)
{
	auto proxy = new OAuthProxy(sampleConfig());
	assert(!proxy.brokerEnabled());
}

unittest  // BROKER: issuing a client token does NOT return the upstream token
{
	auto proxy = new OAuthProxy(brokerConfig());
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);
	assert(issued.token.length > 0);
	assert(issued.token != "gho_upstream_secret");
}

unittest  // BROKER: an upstream response without an access token mints nothing
{
	import std.exception : assertThrown;

	auto proxy = new OAuthProxy(brokerConfig());
	TokenSet upstream;
	assertThrown(proxy.issueClientToken(upstream));
}

unittest  // BROKER: the resource server accepts the issued token, rejects the raw upstream token
{
	auto cfg = brokerConfig();
	auto proxy = new OAuthProxy(cfg);
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);

	auto validate = referenceTokenValidator(cfg.tokenStore, cfg.resource);
	assert(validate(issued.token).valid);
	assert(!validate("gho_upstream_secret").valid);
}

unittest  // BROKER: the stashed upstream token is retrievable from the validated TokenInfo claims
{
	auto cfg = brokerConfig();
	auto proxy = new OAuthProxy(cfg);
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);

	auto validate = referenceTokenValidator(cfg.tokenStore, cfg.resource);
	auto info = validate(issued.token);
	assert(info.valid);
	assert(info.claims["upstream_access_token"].get!string == "gho_upstream_secret");
}

unittest  // BROKER: the issued token is audience-bound to the proxy's own resource
{
	auto cfg = brokerConfig();
	auto proxy = new OAuthProxy(cfg);
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);

	auto validate = referenceTokenValidator(cfg.tokenStore, cfg.resource);
	assert(validate(issued.token).hasAudience(cfg.resource));
}

unittest  // BROKER: toResourceServer validates the issued opaque token, not the upstream token
{
	auto cfg = brokerConfig();
	auto proxy = new OAuthProxy(cfg);
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);

	// In broker mode the client presents the server's own opaque reference
	// token; the resource server must validate it by store lookup, not via the
	// upstream tokenVerifier (which only knows upstream-issued tokens).
	auto rs = cfg.toResourceServer();
	assert(rs.validator(issued.token).valid);
	assert(!rs.validator("gho_upstream_secret").valid);
}

unittest  // BROKER: AS metadata omits the refresh_token grant (opaque tokens are non-refreshable)
{
	import std.algorithm : canFind;

	auto cfg = brokerConfig();
	auto m = authorizationServerMetadata(cfg);
	assert(m.grantTypesSupported.canFind("authorization_code"));
	assert(!m.grantTypesSupported.canFind("refresh_token"));
}

unittest  // BROKER: OAuthProxy.validator accepts the issued opaque token, rejects the upstream token
{
	auto cfg = brokerConfig();
	cfg.tokenVerifier = (string t) {
		TokenInfo ti;
		ti.valid = t == "gho_upstream_secret";
		return ti;
	};
	auto proxy = new OAuthProxy(cfg);
	TokenSet upstream;
	upstream.accessToken = "gho_upstream_secret";
	const issued = proxy.issueClientToken(upstream);

	auto v = proxy.validator();
	assert(v(issued.token).valid);
	assert(!v("gho_upstream_secret").valid);
}

unittest  // BROKER: the DCR response grants only what the AS metadata advertises (no refresh_token)
{
	import std.algorithm : canFind, map;
	import std.array : array;

	auto j = registrationResponseJson(brokerConfig(), [
		"http://localhost:5000/callback"
	]);
	auto grants = j["grant_types"].get!(Json[])
		.map!(g => g.get!string)
		.array;
	assert(grants.canFind("authorization_code"));
	assert(!grants.canFind("refresh_token"));
}
