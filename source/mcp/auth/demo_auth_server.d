/// A self-contained DEMO OAuth 2.1 authorization server for MCP servers that
/// have no identity provider at all — the D analogue of the embedded demo AS
/// the official `example-server.modelcontextprotocol.io` deployment runs.
///
/// The MCP server acts as its OWN authorization server: it publishes RFC 8414
/// AS metadata naming itself as the issuer, answers RFC 7591 Dynamic Client
/// Registration, runs the OAuth 2.1 authorization-code + PKCE (S256) flow with
/// an approve screen instead of a login (there is no identity to check — the
/// user just picks the subject name the token will carry), and mints/validates
/// its own opaque reference tokens (`ReferenceTokenStore`). OAuth-only MCP
/// clients can therefore complete the whole discovery → DCR → authorize →
/// token dance with no external IdP anywhere.
///
/// SECURITY: this is a DEMO. It authenticates nobody — anyone who can reach
/// `/authorize` can approve themselves as any subject. What it does provide is
/// real protocol mechanics (PKCE S256 enforced, single-use expiring codes,
/// exact-match redirect URIs, rotating refresh tokens, audience-bound opaque
/// access tokens) and stable per-subject principals, which is enough for demo
/// deployments and for exercising OAuth-only clients. For production, use
/// `jwtVerifier`/`introspectionVerifier` against a real IdP, or `OAuthProxy`.
///
/// This module is the pure logic; `mcp.transport.demo_auth_mount` wires it
/// onto a vibe.d `URLRouter` next to `mountMcp`.
module mcp.auth.demo_auth_server;

import core.time : Duration, days, hours, minutes;
import std.algorithm : canFind;
import std.string : endsWith, startsWith, strip;

import vibe.data.json : Json;

import mcp.auth.oauth : base64UrlNoPad;
import mcp.auth.csprng : cryptoRandomBytes;
import mcp.auth.reference_token : IssuedToken, ReferenceTokenStore, referenceTokenValidator;
import mcp.auth.resource_server : ResourceServerConfig, TokenValidator;
import mcp.auth.oauth_proxy : InMemoryRedirectUriRegistry, RedirectUriRegistry,
	maxRedirectUrisPerRegistration;
import mcp.transport.session : BoundedExpiringMap;

@safe:

/// Configuration for the embedded demo authorization server.
struct DemoAuthServerConfig
{
	/// The server's own public base URL (e.g. `https://my-app.fly.dev`). It is
	/// the OAuth issuer, and the `/authorize`, `/token`, and `/register`
	/// endpoints are derived from it. Required.
	string baseUrl;

	/// The RFC 8707 canonical resource identifier of the MCP endpoint (e.g.
	/// `https://my-app.fly.dev/mcp`). Minted tokens are audience-bound to it.
	/// Required.
	string resource;

	/// Scopes advertised in the AS metadata and granted by default when a
	/// client requests none.
	string[] scopesSupported = ["mcp"];

	/// The path serving the approve screen's form action (relative to
	/// `baseUrl`). The HTTP mount registers its consent handler here.
	string consentPath = "/consent";

	/// Lifetime of an authorization code (single-use regardless).
	Duration codeTtl = 5.minutes;

	/// Lifetime of a minted access token.
	Duration accessTokenTtl = 1.hours;

	/// Lifetime of a refresh token (each refresh rotates it).
	Duration refreshTokenTtl = 30.days;

	/// Injectable unix-seconds clock (null => the system clock), so expiry is
	/// unit-testable.
	long delegate() @safe nowUnixSeconds;

	/// The advertised authorization endpoint.
	string authorizeEndpoint() const
	{
		return joinUrl(baseUrl, "/authorize");
	}

	/// The advertised token endpoint.
	string tokenEndpoint() const
	{
		return joinUrl(baseUrl, "/token");
	}

	/// The advertised DCR registration endpoint.
	string registrationEndpoint() const
	{
		return joinUrl(baseUrl, "/register");
	}

	/// The approve screen's form-action endpoint (not advertised in metadata).
	string consentEndpoint() const
	{
		string cp = consentPath;
		if (cp.length && !cp.startsWith("/"))
			cp = "/" ~ cp;
		return joinUrl(baseUrl, cp);
	}
}

/// The outcome of a `/token` exchange: the HTTP status to answer with and the
/// RFC 6749 JSON body (a token response on 200, an error document otherwise).
struct TokenOutcome
{
	int status;
	Json body;
}

/// The embedded demo authorization server: DCR, authorization codes, PKCE
/// verification, and opaque token minting/validation, all in-process.
final class DemoAuthServer
{
	private DemoAuthServerConfig cfg_;
	private RedirectUriRegistry registry_;
	private ReferenceTokenStore tokens_;
	private BoundedExpiringMap!PendingCode codes_;
	private BoundedExpiringMap!RefreshGrant refreshes_;

	/// A pending single-use authorization code.
	private struct PendingCode
	{
		string clientId;
		string redirectUri;
		string codeChallenge;
		string scope_;
		string subject;
		long expiresAt; /// absolute unix seconds
	}

	/// A live refresh token (rotated on every use).
	private struct RefreshGrant
	{
		string clientId;
		string subject;
		string scope_;
		long expiresAt; /// absolute unix seconds
	}

	/// Caps on the unauthenticated-growth stores (codes / refresh grants).
	private enum size_t maxPendingCodes = 10_000;
	private enum size_t maxRefreshGrants = 100_000;

	this(DemoAuthServerConfig cfg, RedirectUriRegistry registry = null,
			ReferenceTokenStore tokens = null)
	in (cfg.baseUrl.length > 0, "DemoAuthServerConfig.baseUrl is required")
	in (cfg.resource.length > 0, "DemoAuthServerConfig.resource is required")
	{
		cfg_ = cfg;
		if (cfg_.nowUnixSeconds is null)
			cfg_.nowUnixSeconds = () => systemNowUnixSeconds();
		registry_ = registry !is null ? registry : new InMemoryRedirectUriRegistry();
		tokens_ = tokens !is null ? tokens : new ReferenceTokenStore(cfg_.accessTokenTtl,
				maxRefreshGrants, null);
		codes_ = BoundedExpiringMap!PendingCode(cfg_.codeTtl, maxPendingCodes, null);
		refreshes_ = BoundedExpiringMap!RefreshGrant(cfg_.refreshTokenTtl, maxRefreshGrants, null);
	}

	/// The (defaulted) configuration this server runs with.
	DemoAuthServerConfig config()
	{
		return cfg_;
	}

	/// The RFC 8414 Authorization Server Metadata document this server
	/// publishes: itself as issuer, its own three endpoints, PKCE S256 only,
	/// public clients only (`token_endpoint_auth_methods_supported: ["none"]`).
	Json metadataJson() const
	{
		Json j = Json.emptyObject;
		j["issuer"] = stripTrailingSlash(cfg_.baseUrl);
		j["authorization_endpoint"] = cfg_.authorizeEndpoint();
		j["token_endpoint"] = cfg_.tokenEndpoint();
		j["registration_endpoint"] = cfg_.registrationEndpoint();
		j["response_types_supported"] = strArray(["code"]);
		j["grant_types_supported"] = strArray([
			"authorization_code", "refresh_token"
		]);
		j["code_challenge_methods_supported"] = strArray(["S256"]);
		j["token_endpoint_auth_methods_supported"] = strArray(["none"]);
		if (cfg_.scopesSupported.length)
			j["scopes_supported"] = strArray(cfg_.scopesSupported);
		return j;
	}

	/// Collapse into the transport's `auth` config: this server's own opaque
	/// tokens are the only bearer credential, validated by store lookup with
	/// the audience bound to `resource`, and `baseUrl` is the sole advertised
	/// authorization server.
	ResourceServerConfig toResourceServer()
	{
		ResourceServerConfig rs;
		rs.validator = validator();
		rs.resource = cfg_.resource;
		rs.authorizationServers = [stripTrailingSlash(cfg_.baseUrl)];
		rs.scopesSupported = cfg_.scopesSupported.dup;
		return rs;
	}

	/// The `TokenValidator` for tokens this server minted.
	TokenValidator validator()
	{
		return referenceTokenValidator(tokens_, cfg_.resource);
	}

	/// Answer an RFC 7591 DCR request: mint a fresh `client_id`, record the
	/// requested `redirect_uris` (capped at `maxRedirectUrisPerRegistration`)
	/// against it, and return the registration document for a public PKCE
	/// client. Every client gets its own id — unlike `OAuthProxy` there is no
	/// fixed upstream credential to share.
	Json register(const string[] requestedRedirectUris)
	{
		const clientId = "demo-client-" ~ base64UrlNoPad(cryptoRandomBytes(12));
		auto capped = requestedRedirectUris.dup;
		if (capped.length > maxRedirectUrisPerRegistration)
			capped = capped[0 .. maxRedirectUrisPerRegistration];
		registry_.register(clientId, capped);

		Json j = Json.emptyObject;
		j["client_id"] = clientId;
		j["token_endpoint_auth_method"] = "none";
		j["redirect_uris"] = strArray(capped);
		j["grant_types"] = strArray(["authorization_code", "refresh_token"]);
		j["response_types"] = strArray(["code"]);
		return j;
	}

	/// Validate an incoming `/authorize` request. Returns null when the request
	/// may proceed to the approve screen, else a human-readable reason the
	/// mount maps to an RFC 6749 `invalid_request` (the redirect URI is not yet
	/// trusted at this point, so errors are answered directly, not redirected).
	string validateAuthorize(string redirectUri, string responseType,
			string codeChallenge, string codeChallengeMethod)
	{
		if (responseType.length && responseType != "code")
			return "response_type must be code";
		if (redirectUri.length == 0)
			return "redirect_uri is required";
		if (!registry_.isRegistered(redirectUri))
			return "redirect_uri is not registered (register the client first)";
		if (codeChallenge.length == 0)
			return "code_challenge is required";
		if (codeChallengeMethod.length && codeChallengeMethod != "S256")
			return "code_challenge_method must be S256";
		return null;
	}

	/// Mint a single-use authorization code for an approved request, bound to
	/// the client, redirect URI, PKCE challenge, scope, and the approved
	/// `subject` (the principal the eventual token will carry).
	string issueCode(string clientId, string redirectUri, string codeChallenge,
			string scope_, string subject)
	{
		const code = base64UrlNoPad(cryptoRandomBytes(32));
		codes_.put(code, PendingCode(clientId, redirectUri, codeChallenge, scope_,
				subject, cfg_.nowUnixSeconds() + cfg_.codeTtl.total!"seconds"));
		return code;
	}

	/// Redeem an authorization code (OAuth 2.1 §4.1.3): the code must be live
	/// and unspent, the PKCE `code_verifier` must hash (S256) to the stored
	/// challenge, and `redirectUri`/`clientId` must match the authorize-time
	/// values when the stored ones are set. On success mints an access token +
	/// rotating refresh token. The code is consumed even on failure, so a
	/// guessed-verifier retry needs a whole new authorization.
	TokenOutcome exchangeAuthorizationCode(string code, string codeVerifier,
			string redirectUri, string clientId)
	{
		bool found;
		auto pc = codes_.take(code, found);
		if (!found || cfg_.nowUnixSeconds() >= pc.expiresAt)
			return tokenError(400, "invalid_grant", "unknown or expired code");
		if (codeVerifier.length == 0 || s256ChallengeOf(codeVerifier) != pc.codeChallenge)
			return tokenError(400, "invalid_grant", "PKCE verification failed");
		if (pc.redirectUri.length && redirectUri != pc.redirectUri)
			return tokenError(400, "invalid_grant", "redirect_uri mismatch");
		if (clientId.length && pc.clientId.length && clientId != pc.clientId)
			return tokenError(400, "invalid_client", "client_id mismatch");
		return TokenOutcome(200, mintTokens(pc.clientId, pc.subject, pc.scope_));
	}

	/// Redeem a refresh token (OAuth 2.1 §4.3): single-use — a successful
	/// refresh rotates it, invalidating the presented one.
	TokenOutcome exchangeRefreshToken(string refreshToken, string clientId)
	{
		bool found;
		auto rg = refreshes_.take(refreshToken, found);
		if (!found || cfg_.nowUnixSeconds() >= rg.expiresAt)
			return tokenError(400, "invalid_grant", "unknown or expired refresh_token");
		if (clientId.length && rg.clientId.length && clientId != rg.clientId)
			return tokenError(400, "invalid_client", "client_id mismatch");
		return TokenOutcome(200, mintTokens(rg.clientId, rg.subject, rg.scope_));
	}

	// Mint the access + refresh pair for a grant and build the RFC 6749 §5.1
	// token response.
	private Json mintTokens(string clientId, string subject, string scope_)
	{
		import std.string : join;

		const now = cfg_.nowUnixSeconds();
		const grantedScope = scope_.length ? scope_ : cfg_.scopesSupported.join(" ");

		IssuedToken t;
		t.subject = subject;
		t.scopes = splitScopes(grantedScope);
		t.audience = [cfg_.resource];
		t.expiresAt = now + cfg_.accessTokenTtl.total!"seconds";
		const access = tokens_.issue(t);

		const refresh = base64UrlNoPad(cryptoRandomBytes(32));
		refreshes_.put(refresh, RefreshGrant(clientId, subject, grantedScope,
				now + cfg_.refreshTokenTtl.total!"seconds"));

		Json j = Json.emptyObject;
		j["access_token"] = access;
		j["token_type"] = "Bearer";
		j["expires_in"] = cast(long) cfg_.accessTokenTtl.total!"seconds";
		j["refresh_token"] = refresh;
		j["scope"] = grantedScope;
		return j;
	}
}

/// The S256 PKCE challenge for a verifier: `base64url(sha256(verifier))`,
/// no padding (RFC 7636 §4.2).
string s256ChallengeOf(string verifier)
{
	import std.digest.sha : sha256Of;

	return base64UrlNoPad(sha256Of(cast(const(ubyte)[]) verifier)[]);
}

/// Normalize the subject a user typed on the approve screen into a stable
/// principal name: trimmed, `[A-Za-z0-9._-]` only (others become `-`), capped
/// at 64 chars, falling back to "demo-user" when nothing usable remains.
string sanitizeSubject(string raw)
{
	import std.ascii : isAlphaNum;

	string s;
	foreach (ch; raw.strip)
	{
		if (s.length >= 64)
			break;
		s ~= (isAlphaNum(ch) || ch == '.' || ch == '_' || ch == '-') ? ch : '-';
	}
	// All-separator input (e.g. "///") carries no identity; use the fallback.
	bool meaningful;
	foreach (ch; s)
		if (ch != '-')
			meaningful = true;
	return meaningful ? s : "demo-user";
}

/// An RFC 6749 §5.2 token-endpoint error outcome.
private TokenOutcome tokenError(int status, string error, string description)
{
	Json j = Json.emptyObject;
	j["error"] = error;
	j["error_description"] = description;
	return TokenOutcome(status, j);
}

private string[] splitScopes(string s)
{
	import std.algorithm : filter, splitter;
	import std.array : array;

	string[] result;
	foreach (part; s.splitter(' '))
		if (part.length)
			result ~= part;
	return result;
}

private Json strArray(const string[] xs)
{
	Json a = Json.emptyArray;
	foreach (x; xs)
		a ~= Json(x);
	return a;
}

private string stripTrailingSlash(string s)
{
	return s.endsWith("/") ? s[0 .. $ - 1] : s;
}

private string joinUrl(string base, string path)
{
	string b = stripTrailingSlash(base);
	string p = path.startsWith("/") ? path : "/" ~ path;
	return b ~ p;
}

private long systemNowUnixSeconds()
{
	import std.datetime.systime : Clock;

	return Clock.currTime.toUnixTime;
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	private DemoAuthServer testServer(long delegate() @safe clock = null)
	{
		DemoAuthServerConfig cfg;
		cfg.baseUrl = "https://demo.example.com";
		cfg.resource = "https://demo.example.com/mcp";
		cfg.scopesSupported = ["mcp"];
		// Default to the real clock: `referenceTokenValidator` checks expiry
		// against system time, so a fake epoch would make every minted token
		// read as expired. Tests that drive expiry inject their own clock (and
		// stay off the validator).
		cfg.nowUnixSeconds = clock;
		return new DemoAuthServer(cfg);
	}

	private string registeredClient(DemoAuthServer as, string redirectUri)
	{
		return as.register([redirectUri])["client_id"].get!string;
	}
}

unittest  // metadata: the server names itself as issuer with its own endpoints
{
	auto j = testServer().metadataJson();
	assert(j["issuer"].get!string == "https://demo.example.com");
	assert(j["authorization_endpoint"].get!string == "https://demo.example.com/authorize");
	assert(j["token_endpoint"].get!string == "https://demo.example.com/token");
	assert(j["registration_endpoint"].get!string == "https://demo.example.com/register");
}

unittest  // metadata: PKCE S256-only, code response type, public clients only
{
	auto j = testServer().metadataJson();
	assert(j["code_challenge_methods_supported"][0].get!string == "S256");
	assert(j["response_types_supported"][0].get!string == "code");
	assert(j["token_endpoint_auth_methods_supported"][0].get!string == "none");
	assert(j["grant_types_supported"].length == 2);
}

unittest  // DCR: each registration mints a distinct client_id and echoes the URIs
{
	auto as = testServer();
	auto a = as.register(["http://localhost:1234/cb"]);
	auto b = as.register(["http://localhost:5678/cb"]);
	assert(a["client_id"].get!string != b["client_id"].get!string);
	assert(a["redirect_uris"][0].get!string == "http://localhost:1234/cb");
	assert(a["token_endpoint_auth_method"].get!string == "none");
}

unittest  // validateAuthorize: a registered redirect + S256 challenge passes
{
	auto as = testServer();
	registeredClient(as, "http://localhost:1234/cb");
	assert(as.validateAuthorize("http://localhost:1234/cb", "code", "chal", "S256") is null);
	assert(as.validateAuthorize("http://localhost:1234/cb", "", "chal", "") is null);
}

unittest  // validateAuthorize: unregistered redirect_uri is refused
{
	auto as = testServer();
	assert(as.validateAuthorize("http://evil.example.com/cb", "code", "chal", "S256") !is null);
}

unittest  // validateAuthorize: missing code_challenge / wrong method are refused
{
	auto as = testServer();
	registeredClient(as, "http://localhost:1234/cb");
	assert(as.validateAuthorize("http://localhost:1234/cb", "code", "", "S256") !is null);
	assert(as.validateAuthorize("http://localhost:1234/cb", "code", "chal", "plain") !is null);
	assert(as.validateAuthorize("http://localhost:1234/cb", "token", "chal", "S256") !is null);
}

unittest  // code exchange: happy path mints an audience-bound Bearer token
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const verifier = "test-verifier-test-verifier-test-verifier-1";
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf(verifier), "mcp", "alice");
	auto o = as.exchangeAuthorizationCode(code, verifier, "http://localhost:1234/cb", cid);
	assert(o.status == 200);
	assert(o.body["token_type"].get!string == "Bearer");
	assert(o.body["scope"].get!string == "mcp");
	assert(o.body["refresh_token"].get!string.length > 0);

	auto info = as.validator()(o.body["access_token"].get!string);
	assert(info.valid && info.subject == "alice");
	assert(info.hasAudience("https://demo.example.com/mcp"));
	assert(info.hasScope("mcp"));
}

unittest  // code exchange: a wrong PKCE verifier is invalid_grant
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("right-verifier"), "mcp", "alice");
	auto o = as.exchangeAuthorizationCode(code, "wrong-verifier", "http://localhost:1234/cb", cid);
	assert(o.status == 400 && o.body["error"].get!string == "invalid_grant");
}

unittest  // code exchange: a code is single-use, even after a failed attempt
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("v-v-v-v-v-v-v-v-v-v-v-v-v-v"), "mcp", "alice");
	cast(void) as.exchangeAuthorizationCode(code, "wrong", "http://localhost:1234/cb", cid);
	auto again = as.exchangeAuthorizationCode(code,
			"v-v-v-v-v-v-v-v-v-v-v-v-v-v", "http://localhost:1234/cb", cid);
	assert(again.status == 400 && again.body["error"].get!string == "invalid_grant");
}

unittest  // code exchange: an expired code is invalid_grant
{
	long now = 1_000_000;
	auto as = testServer(() @safe => now);
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("v-v-v-v-v-v-v-v-v-v-v-v-v-v"), "mcp", "alice");
	now += 5 * 60 + 1; // past codeTtl
	auto o = as.exchangeAuthorizationCode(code, "v-v-v-v-v-v-v-v-v-v-v-v-v-v",
			"http://localhost:1234/cb", cid);
	assert(o.status == 400 && o.body["error"].get!string == "invalid_grant");
}

unittest  // code exchange: redirect_uri and client_id must match the grant
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const mk = () @safe => as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("v-v-v-v-v-v-v-v-v-v-v-v-v-v"), "mcp", "alice");
	auto bad1 = as.exchangeAuthorizationCode(mk(),
			"v-v-v-v-v-v-v-v-v-v-v-v-v-v", "http://other.example.com/cb", cid);
	assert(bad1.status == 400 && bad1.body["error"].get!string == "invalid_grant");
	auto bad2 = as.exchangeAuthorizationCode(mk(), "v-v-v-v-v-v-v-v-v-v-v-v-v-v",
			"http://localhost:1234/cb", "some-other-client");
	assert(bad2.status == 400 && bad2.body["error"].get!string == "invalid_client");
}

unittest  // refresh: rotates the token and invalidates the presented one
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("v-v-v-v-v-v-v-v-v-v-v-v-v-v"), "mcp", "alice");
	auto first = as.exchangeAuthorizationCode(code,
			"v-v-v-v-v-v-v-v-v-v-v-v-v-v", "http://localhost:1234/cb", cid);
	const rt = first.body["refresh_token"].get!string;

	auto second = as.exchangeRefreshToken(rt, cid);
	assert(second.status == 200);
	assert(second.body["refresh_token"].get!string != rt);
	assert(as.validator()(second.body["access_token"].get!string).subject == "alice");

	auto replay = as.exchangeRefreshToken(rt, cid);
	assert(replay.status == 400 && replay.body["error"].get!string == "invalid_grant");
}

unittest  // an empty requested scope is granted the configured default scopes
{
	auto as = testServer();
	const cid = registeredClient(as, "http://localhost:1234/cb");
	const code = as.issueCode(cid, "http://localhost:1234/cb",
			s256ChallengeOf("v-v-v-v-v-v-v-v-v-v-v-v-v-v"), "", "bob");
	auto o = as.exchangeAuthorizationCode(code, "v-v-v-v-v-v-v-v-v-v-v-v-v-v",
			"http://localhost:1234/cb", cid);
	assert(o.status == 200 && o.body["scope"].get!string == "mcp");
}

unittest  // toResourceServer: audience-bound validator + self as the sole AS
{
	auto as = testServer();
	auto rs = as.toResourceServer();
	assert(rs.resource == "https://demo.example.com/mcp");
	assert(rs.authorizationServers == ["https://demo.example.com"]);
	assert(!rs.validator("not-a-token").valid);
}

unittest  // s256ChallengeOf: RFC 7636 appendix B known-answer test
{
	assert(s256ChallengeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
			== "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

unittest  // sanitizeSubject: trims, filters, caps, and falls back
{
	assert(sanitizeSubject("  alice  ") == "alice");
	assert(sanitizeSubject("bob@laptop!") == "bob-laptop-");
	assert(sanitizeSubject("") == "demo-user");
	assert(sanitizeSubject("///") == "demo-user");
	assert(sanitizeSubject("p.eter_1-x") == "p.eter_1-x");
}
