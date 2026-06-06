/// HTTP mount for an `OAuthProxy` (basic/authorization §Authorization Server
/// Discovery + §Dynamic Client Registration; RFC 8414 / RFC 7591 / RFC 9728).
///
/// `OAuthProxy` (mcp.auth.oauth_proxy) implements the full client-facing OAuth
/// surface as pure builders, but those builders were not reachable through any
/// public transport API — a server author using the `github()`/`google()`
/// presets had to hand-write every vibe.d route plus the upstream callback
/// relay. `mountOAuthProxy` closes that gap: it registers, on a vibe.d
/// `URLRouter`, the complete DCR-capable OAuth surface the proxy advertises:
///
///   * `GET  /.well-known/oauth-authorization-server` — RFC 8414 AS metadata
///     (`proxy.metadataJson`), advertising the proxy's own endpoints + PKCE S256.
///   * `GET  /.well-known/oauth-protected-resource` — RFC 9728 PRM document
///     (`proxy.resourceMetadata.toJson`).
///   * `POST /register` — RFC 7591 DCR, echoing the request's `redirect_uris`
///     and handing back the fixed upstream `client_id` (`proxy.register`).
///   * `GET  /authorize` — gated on the confused-deputy consent MUST: persists
///     the client's dynamic `redirect_uri`, `state`, PKCE `code_challenge` and
///     `scope` under a freshly minted proxy `state`, then calls the GATED
///     `proxy.authorize`. For an already-consented client it 302s to the upstream
///     authorization endpoint; for an un-consented dynamically-registered client
///     it instead renders the proxy's own consent screen (no upstream forward).
///   * `POST /consent` — the consent-approval action reached from the consent
///     screen's form submission: records user consent for the pending client
///     (`proxy.grantConsent`) and resumes the upstream authorize 302 with the
///     stored PKCE `code_challenge` + `scope`. A POST (not GET) so a state-changing
///     grant cannot be auto-fired by link prefetch/preload.
///   * the fixed callback path (default `/auth/callback`) — receives the upstream
///     `code` + proxy `state`, looks up the stored client `redirect_uri`, and
///     302s the upstream code straight back to the client (transparent PKCE: the
///     client's `code_challenge` was forwarded upstream, so the client redeems
///     the relayed code with its own `code_verifier`).
///   * `POST /token` — exchanges the (relayed upstream) `code` + the client's
///     `code_verifier` at the upstream token endpoint using the fixed upstream
///     credentials (`proxy.tokenForm`/`proxy.tokenAuthHeader`), relaying the
///     upstream token response back to the client verbatim.
///
/// The pure relay helpers (`buildClientCallbackRedirect`, `redirectUrisFrom`,
/// `ProxyStateStore`, `consentScreenHtml`) carry no HTTP state and are unit-tested
/// directly; the `mountOAuthProxy` wiring threads them onto the router.
module mcp.transport.oauth_proxy_mount;

import std.string : startsWith, indexOf;
import std.uri : encodeComponent;

import vibe.data.json : Json, parseJsonString;
import vibe.http.server : HTTPServerRequest, HTTPServerResponse, HTTPStatus;
import vibe.http.router : URLRouter;
import vibe.http.common : HTTPMethod;

import mcp.auth.oauth_proxy : ConsentRequiredException,
	InvalidRedirectUriException, OAuthProxy, OAuthProxyConfig;

@safe:

// ===========================================================================
// Pure relay helpers
// ===========================================================================

private string enc(string s) @safe
{
	return encodeComponent(s);
}

/// Append `code` (and, when present, the client's original `state`) as query
/// parameters to the client's dynamic `redirect_uri`, producing the Location the
/// proxy 302s to once the upstream callback fires. The client supplied the
/// `redirect_uri` at `/authorize`; the proxy relays the upstream authorization
/// `code` to it so the client can redeem it (with its own PKCE `code_verifier`)
/// at the proxy `/token` endpoint.
string buildClientCallbackRedirect(string clientRedirectUri, string code, string clientState) @safe
{
	auto url = clientRedirectUri;
	url ~= (clientRedirectUri.indexOf('?') < 0) ? "?" : "&";
	url ~= "code=" ~ enc(code);
	if (clientState.length)
		url ~= "&state=" ~ enc(clientState);
	return url;
}

/// Append an RFC 6749 §4.1.2.1 authorization error (and, when present, the
/// client's original `state`) as query parameters to the client's dynamic
/// `redirect_uri`, producing the Location the proxy 302s to when the upstream
/// authorization server redirects back with an `error` instead of a `code`.
/// `error` is mandatory; `errorDescription` and `errorUri` are appended only
/// when non-empty. Symmetric to `buildClientCallbackRedirect`.
string buildClientCallbackError(string clientRedirectUri, string error,
		string errorDescription, string errorUri, string clientState) @safe
{
	auto url = clientRedirectUri;
	url ~= (clientRedirectUri.indexOf('?') < 0) ? "?" : "&";
	url ~= "error=" ~ enc(error);
	if (errorDescription.length)
		url ~= "&error_description=" ~ enc(errorDescription);
	if (errorUri.length)
		url ~= "&error_uri=" ~ enc(errorUri);
	if (clientState.length)
		url ~= "&state=" ~ enc(clientState);
	return url;
}

/// Build the RFC 6749 §5.2 `invalid_request` error document returned (with HTTP
/// 400) when a client presents a `redirect_uri` that is not registered or uses a
/// disallowed scheme. The offending code is never relayed.
Json invalidRequestJson(string description) @safe
{
	Json j = Json.emptyObject;
	j["error"] = "invalid_request";
	j["error_description"] = description;
	return j;
}

/// Extract the `redirect_uris` array from a parsed RFC 7591 DCR request body,
/// returning an empty array when the field is absent or malformed. The number of
/// URIs collected is capped at `maxRedirectUrisPerRegistration` so an
/// unauthenticated `POST /register` carrying an oversized array cannot force an
/// unbounded allocation here before the proxy's own registration cap applies.
string[] redirectUrisFrom(Json body_) @safe
{
	import mcp.auth.oauth_proxy : maxRedirectUrisPerRegistration;

	string[] uris;
	if (body_.type == Json.Type.object && "redirect_uris" in body_
			&& body_["redirect_uris"].type == Json.Type.array)
	{
		auto arr = body_["redirect_uris"];
		foreach (i; 0 .. arr.length)
		{
			if (uris.length >= maxRedirectUrisPerRegistration)
				break;
			if (arr[i].type == Json.Type.string)
				uris ~= arr[i].get!string;
		}
	}
	return uris;
}

/// The per-authorization state the proxy persists between `/authorize` and the
/// upstream callback: the client's dynamic `redirect_uri` and the client's own
/// `state`, keyed by a freshly minted opaque proxy `state` that is the only
/// `state` value sent upstream. The client's PKCE `code_challenge` and `scope`
/// are also retained so the upstream authorize redirect can be (re)built after a
/// consent-approval round-trip (confused-deputy mitigation).
struct ProxyAuthState
{
	string clientRedirectUri; /// the client's dynamic redirect URI (RFC 7591)
	string clientState; /// the client's original OAuth `state`, relayed back verbatim
	string codeChallenge; /// the client's PKCE S256 `code_challenge`, forwarded upstream
	string scope_; /// the client's requested `scope`, forwarded upstream
}

/// Build the minimal HTML consent screen presented when a dynamically-registered
/// client (identified by its `clientRedirectUri`) has not yet been approved to be
/// forwarded to the upstream authorization server. The MCP authorization spec
/// (Â§Security Considerations > Confused Deputy Problem) requires a proxy using a
/// static upstream `client_id` to obtain user consent for EACH dynamically
/// registered client before forwarding it upstream. The screen offers a single
/// approval action: a `<form method="POST">` targeting `consentPath` and carrying
/// the opaque proxy `state` as a hidden field. Posting it records consent and
/// resumes the upstream redirect. Using a form POST (rather than a hyperlink GET)
/// means link prefetch/preload cannot auto-fire the state-changing grant and the
/// opaque `state` is not carried in a URL that could leak via Referer/history/logs.
string consentScreenHtml(string clientRedirectUri, string consentPath, string proxyState) @safe
{
	const safeUri = htmlEscape(clientRedirectUri);
	const safeAction = htmlEscape(consentPath);
	const safeState = htmlEscape(proxyState);
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" ~ "<meta name=\"referrer\" content=\"no-referrer\">" ~ "<title>Authorize application</title></head><body>" ~ "<h1>Authorize application</h1>" ~ "<p>An application is requesting to sign in via this server and be" ~ " forwarded to the upstream identity provider.</p>" ~ "<p>Redirect URI: <code>" ~ safeUri ~ "</code></p>" ~ "<form method=\"post\" action=\"" ~ safeAction ~ "\">" ~ "<input type=\"hidden\" name=\"state\" value=\"" ~ safeState ~ "\">" ~ "<button type=\"submit\">Approve and continue</button></form>" ~ "</body></html>";
}

private string htmlEscape(string s) @safe
{
	import std.array : replace;

	return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
		.replace("\"", "&quot;");
}

/// A thread-safe in-memory store mapping a proxy `state` to the client's
/// pending-authorization details. Entries are consumed (single use) on lookup so
/// a relayed callback cannot be replayed.
///
/// The store is bounded so the unauthenticated `/authorize` route cannot grow
/// process memory without limit: each entry carries an insertion timestamp, and
/// every `put`/`take` sweeps entries older than the authorization-flow TTL and
/// caps the live entry count, evicting the oldest by insertion time when the cap
/// is reached. The clock is injectable so the bounds are unit-testable.
final class ProxyStateStore
{
	import core.time : Duration, MonoTime, minutes;
	import mcp.transport.session : BoundedExpiringMap;

	/// Lifetime of a pending authorization (authorize -> consent -> callback). An
	/// abandoned or un-consented flow is swept after this elapses.
	enum Duration defaultTtl = 10.minutes;

	/// Maximum number of live pending authorizations. When reached on `put`, the
	/// oldest entries are evicted so a flood cannot exhaust memory inside the TTL.
	enum size_t defaultMaxEntries = 10_000;

	// `synchronized(this)` serializes access; the container itself does no locking.
	private BoundedExpiringMap!ProxyAuthState entries;

	this() @safe
	{
		this(defaultTtl, defaultMaxEntries, null);
	}

	/// Construct with explicit bounds and an optional injectable clock (used by
	/// tests to drive TTL expiry deterministically). A null clock uses `MonoTime.currTime`.
	this(Duration ttl, size_t maxEntries, MonoTime delegate() @safe clock) @safe
	{
		entries = BoundedExpiringMap!ProxyAuthState(ttl, maxEntries, clock);
	}

	/// Record the client's authorization details under the proxy `state`.
	void put(string proxyState, ProxyAuthState st) @safe
	{
		synchronized (this)
			entries.put(proxyState, st);
	}

	/// Consume and return the details for `proxyState`, setting `found`.
	ProxyAuthState take(string proxyState, out bool found) @safe
	{
		synchronized (this)
			return entries.take(proxyState, found);
	}

	/// Number of live pending authorizations (test/diagnostic use).
	size_t length() @safe
	{
		synchronized (this)
			return entries.length;
	}
}

/// Mint a fresh, unguessable proxy `state` value (the only `state` sent
/// upstream). The bytes come from the OS CSPRNG -- this `state` is the CSRF /
/// authorization-response mix-up defense and MUST be unpredictable. Throws
/// `CsprngException` if the OS CSPRNG is unavailable.
private string mintState() @safe
{
	import mcp.auth.csprng : cryptoRandomFill;
	import mcp.auth.oauth : base64UrlNoPad;

	ubyte[32] buf;
	cryptoRandomFill(buf[]);
	return base64UrlNoPad(buf[]);
}

// ===========================================================================
// The mount
// ===========================================================================

/// Mount the full client-facing OAuth surface of an `OAuthProxy` onto a vibe.d
/// `URLRouter`. Registers the AS-metadata + PRM well-known documents, the RFC
/// 7591 `/register` endpoint, the `/authorize` -> upstream redirect (persisting
/// the client's dynamic redirect URI), the fixed callback that relays the
/// upstream code back to the client, and the `/token` endpoint that exchanges the
/// relayed code at the upstream with the fixed credentials. Paths are derived
/// from the proxy's own configured endpoints so they line up exactly with the AS
/// metadata it publishes.
void mountOAuthProxy(URLRouter router, OAuthProxy proxy) @safe
{
	auto cfg = proxy.config();
	auto store = new ProxyStateStore;

	const authorizePath = pathOf(cfg.authorizeEndpoint());
	const tokenPath = pathOf(cfg.tokenEndpoint());
	const registerPath = pathOf(cfg.registrationEndpoint());
	const callbackPath = cfg.redirectPath;
	const consentPath = pathOf(cfg.consentEndpoint());
	const upstreamTokenEndpoint = cfg.upstreamTokenEndpoint;

	// RFC 8414 Authorization Server Metadata (the proxy advertises ITSELF as the
	// AS, so this lives at the proxy's own well-known path).
	router.get("/.well-known/oauth-authorization-server",
			(HTTPServerRequest req, HTTPServerResponse res) @safe {
		res.statusCode = HTTPStatus.ok;
		res.writeJsonBody(proxy.metadataJson());
	});

	// RFC 9728 Protected Resource Metadata.
	router.get("/.well-known/oauth-protected-resource", (HTTPServerRequest req,
			HTTPServerResponse res) @safe {
		res.statusCode = HTTPStatus.ok;
		res.writeJsonBody(proxy.resourceMetadata().toJson());
	});

	// RFC 7591 Dynamic Client Registration: echo the requested redirect_uris and
	// hand back the fixed upstream client_id (public PKCE client).
	router.post(registerPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		auto body_ = readJsonBody(req);
		const uris = redirectUrisFrom(body_);
		res.statusCode = HTTPStatus.created;
		res.writeJsonBody(proxy.register(uris));
	});

	// /authorize: persist the client's dynamic redirect_uri + state (and PKCE
	// code_challenge + scope) under a fresh proxy state, then forward to the
	// upstream authorization endpoint with the client's PKCE code_challenge
	// (transparent PKCE) — BUT ONLY after the confused-deputy consent gate.
	//
	// Because every dynamically-registered client receives the SAME fixed upstream
	// client_id, the upstream may auto-skip its own consent screen. The MCP
	// authorization spec therefore requires the proxy to obtain user consent for
	// EACH dynamically-registered client (identified by its redirect_uri) before
	// forwarding upstream. The gated `proxy.authorize` throws
	// `ConsentRequiredException` for an un-consented client; we then render the
	// proxy's own consent screen instead of forwarding.
	router.get(authorizePath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const codeChallenge = req.query.get("code_challenge", "");
		const codeChallengeMethod = req.query.get("code_challenge_method", "");
		const scope_ = req.query.get("scope", "");
		const clientRedirect = req.query.get("redirect_uri", "");
		const clientState = req.query.get("state", "");

		// Reject an unregistered or disallowed-scheme redirect_uri BEFORE minting any
		// proxy state or rendering the consent screen (RFC 6749 §3.1.2.2 / §10.6,
		// RFC 8252). Failing closed here means the upstream code can never be relayed
		// to a URI the client never registered.
		try
			proxy.validateRedirectUri(clientRedirect);
		catch (InvalidRedirectUriException)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson("invalid redirect_uri"));
			return;
		}

		// Enforce PKCE on the proxy->upstream leg. The proxy advertises S256-only
		// support, so a missing code_challenge — or a code_challenge_method other
		// than S256 — is refused with RFC 6749 §5.2 invalid_request rather than
		// forwarding a non-PKCE / malformed-PKCE request upstream.
		if (codeChallenge.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson("code_challenge is required"));
			return;
		}
		if (codeChallengeMethod.length && codeChallengeMethod != "S256")
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson("code_challenge_method must be S256"));
			return;
		}

		const proxyState = mintState();
		store.put(proxyState, ProxyAuthState(clientRedirect, clientState, codeChallenge, scope_));

		try
		{
			const location = proxy.authorize(clientRedirect, codeChallenge, scope_, proxyState);
			res.redirect(location, HTTPStatus.found);
		}
		catch (ConsentRequiredException)
		{
			// Un-consented dynamically-registered client: present the consent screen
			// rather than forwarding to the upstream authorization server. The screen's
			// approval control is a form POST, and the opaque proxy state is carried in
			// a hidden field rather than a URL, so it cannot leak via Referer/history
			// and cannot be auto-fired by link prefetch/preload.
			res.headers["Cache-Control"] = "no-store";
			res.headers["Referrer-Policy"] = "no-referrer";
			res.statusCode = HTTPStatus.ok;
			res.writeBody(consentScreenHtml(clientRedirect, consentPath,
				proxyState), "text/html; charset=utf-8");
		}
	});

	// /consent: the confused-deputy consent-approval action. The user reaches this
	// from the consent screen; it records consent for the pending client (keyed by
	// its redirect_uri) and resumes the upstream authorize redirect with the stored
	// PKCE code_challenge + scope. The pending entry is re-stored under the same
	// proxy state so the eventual upstream callback can still relay the code.
	//
	// Registered as POST (not GET): granting consent is a state change, so it is
	// driven by the consent screen's form submission. A GET cannot trigger it, which
	// keeps link prefetch/preload from auto-firing the grant and keeps the opaque
	// proxy state out of the URL (no Referer/history/log leakage).
	router.post(consentPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const form = readFormString(req);
		const proxyState = formField(form, "state");
		bool found;
		auto st = store.take(proxyState, found);
		if (!found || st.clientRedirectUri.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody("Unknown or expired authorization state", "text/plain");
			return;
		}
		// Validate the redirect_uri before committing any state: the registry may
		// have evicted it under cap pressure since the /authorize request.
		try
			proxy.validateRedirectUri(st.clientRedirectUri);
		catch (InvalidRedirectUriException)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson("invalid redirect_uri"));
			return;
		}
		proxy.grantConsent(st.clientRedirectUri);
		// Re-store the pending authorization so the upstream callback can relay it.
		store.put(proxyState, st);
		const location = proxy.authorize(st.clientRedirectUri,
			st.codeChallenge, st.scope_, proxyState);
		res.redirect(location, HTTPStatus.found);
	});

	// The fixed upstream callback: look up the client's redirect_uri by the proxy
	// state and relay the upstream code straight back to the client.
	router.get(callbackPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const code = req.query.get("code", "");
		const upstreamError = req.query.get("error", "");
		const proxyState = req.query.get("state", "");
		bool found;
		auto st = store.take(proxyState, found);
		if (!found || st.clientRedirectUri.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody("Unknown or expired authorization state", "text/plain");
			return;
		}
		// Relay an upstream authorization failure (RFC 6749 §4.1.2.1) to the client
		// rather than forwarding an empty code. Branch when the upstream sent an
		// `error`, or defensively when no `code` was returned at all.
		if (upstreamError.length || code.length == 0)
		{
			const error = upstreamError.length ? upstreamError : "access_denied";
			const location = buildClientCallbackError(st.clientRedirectUri, error,
				req.query.get("error_description",
				""), req.query.get("error_uri", ""), st.clientState);
			res.redirect(location, HTTPStatus.found);
			return;
		}
		const location = buildClientCallbackRedirect(st.clientRedirectUri, code, st.clientState);
		res.redirect(location, HTTPStatus.found);
	});

	// /token: exchange the relayed code + the client's code_verifier at the
	// upstream token endpoint with the fixed credentials, relaying the upstream
	// token response back to the client.
	router.post(tokenPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const form = readFormString(req);
		// Branch on the OAuth grant the client requests. The proxy advertises both
		// `authorization_code` and `refresh_token` in its AS metadata, so the /token
		// endpoint MUST honour either: an authorization_code exchange (default, also
		// when grant_type is omitted, for backward compatibility) and a
		// refresh_token exchange (OAuth 2.1 §4.3), relaying the refresh token to the
		// upstream token endpoint with the fixed upstream credentials.
		const grantType = formField(form, "grant_type");
		string upstreamBody;
		if (grantType == "refresh_token")
		{
			const refreshToken = formField(form, "refresh_token");
			upstreamBody = proxy.refreshTokenForm(refreshToken);
		}
		else
		{
			const code = formField(form, "code");
			const verifier = formField(form, "code_verifier");
			upstreamBody = proxy.tokenForm(code, verifier);
		}
		const authHeader = proxy.tokenAuthHeader();
		string responseBody;
		int status;
		exchangeUpstream(upstreamTokenEndpoint, upstreamBody, authHeader, responseBody, status);
		res.statusCode = cast(HTTPStatus) status;
		res.writeBody(responseBody.length ? responseBody : "{}", "application/json");
	});
}

// ===========================================================================
// HTTP glue (impure, untested directly)
// ===========================================================================

private string pathOf(string url) @safe
{
	auto rest = url;
	const sep = rest.indexOf("://");
	if (sep >= 0)
		rest = rest[sep + 3 .. $];
	const slash = rest.indexOf('/');
	return slash >= 0 ? rest[slash .. $] : "/";
}

private Json readJsonBody(scope HTTPServerRequest req) @safe
{
	import vibe.stream.operations : readAllUTF8;

	const payload = req.bodyReader.readAllUTF8();
	if (payload.length == 0)
		return Json.emptyObject;
	try
		return parseJsonString(payload);
	catch (Exception)
		return Json.emptyObject;
}

private string readFormString(scope HTTPServerRequest req) @safe
{
	import vibe.stream.operations : readAllUTF8;

	return req.bodyReader.readAllUTF8();
}

/// Extract a single field value from an `application/x-www-form-urlencoded`
/// body (the field is URL-decoded). Returns "" when absent.
private string formField(string form, string name) @safe
{
	import std.array : split;
	import std.uri : decodeComponent;

	foreach (pair; form.split("&"))
	{
		const eq = pair.indexOf('=');
		if (eq < 0)
			continue;
		if (pair[0 .. eq] == name)
			return () @trusted { return decodeComponent(pair[eq + 1 .. $]); }();
	}
	return "";
}

private void exchangeUpstream(string endpoint, string body_, string authHeader,
		out string responseBody, out int status) @trusted
{
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.stream.operations : readAllUTF8;
	import mcp.auth.oauth : secureRequestHTTP;

	// Refuse to exchange over an insecure transport (must be https, or http to a
	// loopback host for dev) or against an internal/link-local address. The connect
	// is pinned to a pre-vetted resolved address (DNS-rebinding mitigation);
	// secureRequestHTTP throws on an unsafe or unresolvable host, so the upstream
	// client_secret cannot be steered to a rebinding-chosen internal target.
	int st = 502;
	string rb;
	secureRequestHTTP(endpoint, (scope HTTPClientRequest creq) {
		creq.method = HTTPMethod.POST;
		creq.headers["Content-Type"] = "application/x-www-form-urlencoded";
		creq.headers["Accept"] = "application/json";
		if (authHeader.length)
			creq.headers["Authorization"] = authHeader;
		creq.writeBody(cast(const(ubyte)[]) body_);
	}, (scope HTTPClientResponse cres) {
		st = cres.statusCode;
		rb = cres.bodyReader.readAllUTF8();
	});
	status = st;
	responseBody = rb;
}

// ===========================================================================
// Tests
// ===========================================================================

unittest  // the relay redirect appends code (and state) to the client redirect_uri
{
	import std.algorithm : canFind;

	const url = buildClientCallbackRedirect("http://localhost:5000/callback",
			"UPSTREAM-CODE", "cs-1");
	assert(url.startsWith("http://localhost:5000/callback?"));
	assert(url.canFind("code=UPSTREAM-CODE"));
	assert(url.canFind("state=cs-1"));
}

unittest  // the relay redirect uses & when the client redirect_uri already has a query
{
	import std.algorithm : canFind;

	const url = buildClientCallbackRedirect("http://localhost/cb?x=1", "C", "");
	assert(url.canFind("?x=1&code=C"));
	// no state appended when the client supplied none
	assert(!url.canFind("state="));
}

unittest  // the error relay appends error (+ description/uri/state) to the client redirect_uri
{
	import std.algorithm : canFind;

	const url = buildClientCallbackError("http://localhost:5000/cb",
			"access_denied", "the user said no", "https://err.example", "cs-1");
	assert(url.startsWith("http://localhost:5000/cb?"));
	assert(url.canFind("error=access_denied"));
	assert(url.canFind("error_description=the%20user%20said%20no"));
	assert(url.canFind("error_uri=https"));
	assert(url.canFind("state=cs-1"));
	// No code is relayed on an error.
	assert(!url.canFind("code="));
}

unittest  // the error relay omits absent optional params and uses & with an existing query
{
	import std.algorithm : canFind;

	const url = buildClientCallbackError("http://localhost/cb?x=1", "server_error", "", "", "");
	assert(url.canFind("?x=1&error=server_error"));
	assert(!url.canFind("error_description="));
	assert(!url.canFind("error_uri="));
	assert(!url.canFind("state="));
}

unittest  // redirectUrisFrom pulls the array out of a DCR request body
{
	auto body_ = parseJsonString(
			`{"redirect_uris":["http://localhost:1/cb","http://localhost:2/cb"],"client_name":"x"}`);
	auto uris = redirectUrisFrom(body_);
	assert(uris.length == 2);
	assert(uris[0] == "http://localhost:1/cb");
	assert(uris[1] == "http://localhost:2/cb");
}

unittest  // redirectUrisFrom tolerates a missing/!array field
{
	assert(redirectUrisFrom(parseJsonString(`{"client_name":"x"}`)).length == 0);
	assert(redirectUrisFrom(parseJsonString(`{"redirect_uris":"oops"}`)).length == 0);
	assert(redirectUrisFrom(Json.emptyObject).length == 0);
}

unittest  // redirectUrisFrom caps an oversized redirect_uris array (DoS bound)
{
	import mcp.auth.oauth_proxy : maxRedirectUrisPerRegistration;
	import std.array : appender;

	auto a = appender!string;
	a.put(`{"redirect_uris":[`);
	foreach (i; 0 .. maxRedirectUrisPerRegistration + 50)
	{
		if (i)
			a.put(',');
		a.put(`"http://localhost/cb`);
		a.put(cast(char)('0' + cast(int)(i % 10)));
		a.put('"');
	}
	a.put(`]}`);
	auto uris = redirectUrisFrom(parseJsonString(a.data));
	assert(uris.length == maxRedirectUrisPerRegistration);
}

unittest  // the proxy state store round-trips and is single-use (consumed on take)
{
	auto store = new ProxyStateStore;
	store.put("S1", ProxyAuthState("http://localhost/cb", "client-state"));
	bool found;
	auto st = store.take("S1", found);
	assert(found);
	assert(st.clientRedirectUri == "http://localhost/cb");
	assert(st.clientState == "client-state");
	// second take fails: the entry was consumed (no replay)
	store.take("S1", found);
	assert(!found);
}

unittest  // an unknown proxy state is not found
{
	auto store = new ProxyStateStore;
	bool found;
	store.take("nope", found);
	assert(!found);
}

unittest  // the store sweeps entries older than the TTL on the next put/take
{
	import core.time : MonoTime, minutes;

	auto clk = MonoTime.currTime;
	auto store = new ProxyStateStore(10.minutes, 10_000, () @safe => clk);
	store.put("old", ProxyAuthState("http://localhost/cb", "s"));
	assert(store.length == 1);

	// Advance past the TTL: the stale entry is swept on the next put.
	clk += 11.minutes;
	store.put("fresh", ProxyAuthState("http://localhost/cb2", "s2"));
	assert(store.length == 1);
	bool found;
	store.take("old", found);
	assert(!found);
	store.take("fresh", found);
	assert(found);
}

unittest  // the store caps live entries, evicting the oldest by insertion time
{
	import core.time : MonoTime, minutes, seconds;

	auto clk = MonoTime.currTime;
	auto store = new ProxyStateStore(10.minutes, 2, () @safe => clk);
	store.put("a", ProxyAuthState("http://localhost/a", ""));
	clk += 1.seconds;
	store.put("b", ProxyAuthState("http://localhost/b", ""));
	clk += 1.seconds;
	// Third put exceeds the cap of 2: the oldest ("a") is evicted.
	store.put("c", ProxyAuthState("http://localhost/c", ""));
	assert(store.length == 2);
	bool found;
	store.take("a", found);
	assert(!found);
	store.take("b", found);
	assert(found);
	store.take("c", found);
	assert(found);
}

unittest  // formField URL-decodes a value and returns "" for an absent field
{
	assert(formField("grant_type=authorization_code&code=ab%20cd&code_verifier=V",
			"code") == "ab cd");
	assert(formField("grant_type=authorization_code&code=X", "code_verifier") == "");
}

unittest  // the /token dispatch reads grant_type + refresh_token from a refresh request body
{
	// A client following the advertised refresh_token grant POSTs this body. The
	// mount handler keys off grant_type and forwards refresh_token upstream.
	const form = "grant_type=refresh_token&refresh_token=RT%2D123&resource=https%3A%2F%2Fmcp.example.com%2Fmcp";
	assert(formField(form, "grant_type") == "refresh_token");
	assert(formField(form, "refresh_token") == "RT-123");
	// authorization_code-only fields are absent on a refresh request.
	assert(formField(form, "code") == "");
}

unittest  // pathOf strips scheme+host, leaving the path the routes register on
{
	assert(pathOf("https://mcp.example.com/authorize") == "/authorize");
	assert(pathOf("https://mcp.example.com/token") == "/token");
	assert(pathOf("https://mcp.example.com") == "/");
}

unittest  // mountOAuthProxy registers the full client-facing OAuth surface
{
	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.upstreamClientSecret = "secret";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.scopesSupported = ["read:user"];

	auto proxy = new OAuthProxy(cfg);
	auto router = new URLRouter;
	// Must wire without throwing; the routes are exercised end-to-end by the
	// transport conformance harness.
	mountOAuthProxy(router, proxy);
}

unittest  // mintState yields unique, non-empty values
{
	const a = mintState();
	const b = mintState();
	assert(a.length > 0);
	assert(a != b);
}

unittest  // mintState's entropy source is the OS CSPRNG, not the default rndGen
{
	import mcp.auth.oauth : base64UrlNoPad;
	import std.random : rndGen, uniform;

	auto gen = rndGen;
	ubyte[32] predictable;
	foreach (ref x; predictable)
		x = cast(ubyte) uniform(0, 256, gen);
	const predictableState = base64UrlNoPad(predictable[]);

	assert(mintState() != predictableState);
}

unittest  // exchangeUpstream refuses a plaintext (non-loopback) upstream endpoint
{
	import std.exception : assertThrown;

	string rb;
	int st;
	assertThrown(exchangeUpstream("http://upstream.example.com/token", "grant_type=x", "", rb, st));
}

unittest  // exchangeUpstream fails CLOSED for an https host that cannot be resolved
{
	import std.exception : assertThrown;

	// A lexical-only guard accepts this https host; the resolve-and-pin connector
	// rejects it because it does not resolve, so the upstream client_secret is
	// never sent to an un-vetted target.
	string rb;
	int st;
	assertThrown(exchangeUpstream("https://nonexistent-host.invalid/token",
			"grant_type=x", "Basic c2VjcmV0", rb, st));
}

unittest  // constructing a proxy with a plaintext upstream endpoint fails closed
{
	import std.exception : assertThrown;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "http://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";
	assertThrown(new OAuthProxy(cfg));
}

unittest  // CONSENT SCREEN: HTML names the client redirect_uri and a POST approve form
{
	import std.algorithm : canFind;

	const html = consentScreenHtml("http://localhost:5000/cb", "/consent", "abc");
	assert(html.canFind("Authorize application"));
	assert(html.canFind("http://localhost:5000/cb"));
	assert(html.canFind("method=\"post\""));
	assert(html.canFind("action=\"/consent\""));
	assert(html.canFind("name=\"state\" value=\"abc\""));
}

unittest  // CONSENT SCREEN: the approve control is a form POST, not a GET hyperlink
{
	import std.algorithm : canFind;

	const html = consentScreenHtml("http://localhost:5000/cb", "/consent", "abc");
	// No hyperlink that link prefetch/preload could auto-fire as a GET grant, and the
	// opaque state is in a hidden field rather than a URL that could leak.
	assert(!html.canFind("<a href"));
	assert(!html.canFind("/consent?state="));
}

unittest  // CONSENT SCREEN: the untrusted client redirect_uri and proxy state are HTML-escaped
{
	import std.algorithm : canFind;

	const html = consentScreenHtml(`http://x/cb?a=1&b="<script>`, "/consent", `"><b>`);
	assert(html.canFind("&amp;"));
	assert(html.canFind("&lt;script&gt;"));
	assert(html.canFind("&quot;"));
	assert(!html.canFind("<script>"));
	// The proxy state is escaped before being placed in the hidden field value.
	assert(!html.canFind("value=\"\"><b>\""));
}

unittest  // CONFUSED DEPUTY: an un-consented client gets the consent screen, NOT a 302 upstream
{
	import std.algorithm : canFind;
	import std.array : appender;
	import vibe.core.stream : OutputStream;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	const body_ = () @trusted { return cast(string) sink.data; }();
	// The body is the consent screen, NOT a redirect to the upstream IdP.
	assert(body_.canFind("Authorize application"));
	assert(body_.canFind("http://localhost:5000/cb"));
	// The client has NOT been forwarded upstream yet.
	assert(!proxy.hasConsent("http://localhost:5000/cb"));
}

unittest  // CONFUSED DEPUTY: after the user approves, POST /consent records consent + 302s upstream
{
	import std.algorithm : canFind, startsWith;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.common : HTTPMethod;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream, createMemoryStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	// 1) /authorize renders the consent screen and stashes the pending auth under a
	//    proxy state we can read back from the form's hidden state field.
	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);
	const html = () @trusted { return cast(string) sink.data; }();

	// Extract the hidden state value (name="state" value="...").
	import std.string : indexOf;

	const stateMark = `name="state" value="`;
	const hi = html.indexOf(stateMark);
	assert(hi >= 0);
	const rest = html[hi + stateMark.length .. $];
	const close = rest.indexOf('"');
	const proxyState = rest[0 .. close];
	assert(proxyState.length > 0);

	// 2) POSTing the form to /consent grants consent and 302s to the upstream authorize.
	auto res2 = createTestHTTPServerResponse(null, null, TestHTTPResponseMode.bodyOnly);
	auto formBody = () @trusted { return cast(ubyte[])("state=" ~ proxyState).dup; }();
	auto req2 = createTestHTTPServerRequest(URL("https://mcp.example.com/consent"),
			HTTPMethod.POST, createMemoryStream(formBody, false));
	req2.headers["Content-Type"] = "application/x-www-form-urlencoded";
	router.handleRequest(req2, res2);

	assert(proxy.hasConsent("http://localhost:5000/cb"));
	assert(res2.statusCode == 302);
	assert(res2.headers["Location"].startsWith("https://github.com/login/oauth/authorize?"));
	assert(res2.headers["Location"].canFind("client_id=Iv1.upstream"));
	assert(res2.headers["Location"].canFind("code_challenge=CH"));
}

unittest  // CONSENT HARDENING: a GET to /consent cannot grant consent (no auto-fire by prefetch)
{
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	// Drive /authorize to mint a proxy state and stash the pending authorization.
	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);
	const html = () @trusted { return cast(string) sink.data; }();

	import std.string : indexOf;

	const stateMark = `name="state" value="`;
	const hi = html.indexOf(stateMark);
	assert(hi >= 0);
	const rest = html[hi + stateMark.length .. $];
	const close = rest.indexOf('"');
	const proxyState = rest[0 .. close];

	// A GET to /consent (e.g. fired by link prefetch/preload) is not routed to the
	// consent handler, so consent is NOT granted.
	auto res2 = createTestHTTPServerResponse(null, null, TestHTTPResponseMode.bodyOnly);
	auto req2 = createTestHTTPServerRequest(
			URL("https://mcp.example.com/consent?state=" ~ proxyState));
	router.handleRequest(req2, res2);

	assert(!proxy.hasConsent("http://localhost:5000/cb"));
}

unittest  // CONSENT HARDENING: the consent screen sets no-store + no-referrer headers
{
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	assert(res.headers["Cache-Control"] == "no-store");
	assert(res.headers["Referrer-Policy"] == "no-referrer");
}

unittest  // UPSTREAM ERROR: /callback relays an upstream error to the client, not an empty code
{
	import std.algorithm : canFind, startsWith;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	proxy.grantConsent("http://localhost:5000/cb");
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	// Drive /authorize to mint a proxy state and stash the pending authorization.
	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);
	assert(res.statusCode == 302);

	// Read the proxy state the proxy forwarded upstream.
	import std.string : indexOf;

	const loc = res.headers["Location"];
	const mark = "state=";
	const si = loc.indexOf(mark);
	assert(si >= 0);
	const proxyState = loc[si + mark.length .. $];

	// The upstream redirects back with an error and no code.
	auto res2 = createTestHTTPServerResponse(null, null, TestHTTPResponseMode.bodyOnly);
	auto req2 = createTestHTTPServerRequest(URL("https://mcp.example.com/auth/callback?error=access_denied&error_description=denied&state=" ~ proxyState));
	router.handleRequest(req2, res2);

	assert(res2.statusCode == 302);
	const clientLoc = res2.headers["Location"];
	assert(clientLoc.startsWith("http://localhost:5000/cb?"));
	assert(clientLoc.canFind("error=access_denied"));
	assert(clientLoc.canFind("state=cs"));
	// The client must NOT receive an empty code.
	assert(!clientLoc.canFind("code="));
}

unittest  // invalidRequestJson carries the RFC 6749 invalid_request error shape
{
	auto j = invalidRequestJson("invalid redirect_uri");
	assert(j["error"].get!string == "invalid_request");
	assert(j["error_description"].get!string == "invalid redirect_uri");
}

unittest  // OPEN REDIRECT: /authorize 400s an unregistered redirect_uri and does NOT render consent
{
	import std.algorithm : canFind;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	// Note: no /register for the attacker's redirect_uri.
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	const body_ = () @trusted { return cast(string) sink.data; }();
	assert(res.statusCode == 400);
	assert(body_.canFind("invalid_request"));
	// The consent screen is NOT rendered for an unregistered redirect_uri.
	assert(!body_.canFind("Authorize application"));
	assert(!proxy.hasConsent("https://attacker.example/cb"));
}

unittest  // OPEN REDIRECT: /authorize 400s an http non-loopback redirect_uri even if registered
{
	import std.algorithm : canFind;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://app.example.com/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Fapp.example.com%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	const body_ = () @trusted { return cast(string) sink.data; }();
	assert(res.statusCode == 400);
	assert(body_.canFind("invalid_request"));
}

unittest  // PKCE: /authorize 400s a request with a missing code_challenge
{
	import std.algorithm : canFind;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	const body_ = () @trusted { return cast(string) sink.data; }();
	assert(res.statusCode == 400);
	assert(body_.canFind("invalid_request"));
	assert(body_.canFind("code_challenge"));
	// The client was never forwarded upstream / asked to consent.
	assert(!body_.canFind("Authorize application"));
}

unittest  // PKCE: /authorize 400s a non-S256 code_challenge_method
{
	import std.algorithm : canFind;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&code_challenge_method=plain&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);

	const body_ = () @trusted { return cast(string) sink.data; }();
	assert(res.statusCode == 400);
	assert(body_.canFind("invalid_request"));
	assert(body_.canFind("S256"));
}

unittest  // CONSENT: evicted redirect_uri between /authorize and POST /consent yields 400 not 500
{
	// When the InMemoryRedirectUriRegistry evicts the client's redirect_uri under
	// cap pressure between the /authorize request and the user's /consent POST,
	// proxy.authorize throws InvalidRedirectUriException. The handler must catch it
	// and return 400 (matching the /authorize handler) rather than leaking a 500.
	import std.algorithm : canFind;
	import mcp.auth.oauth_proxy : InMemoryConsentStore, InMemoryRedirectUriRegistry;
	import vibe.http.common : HTTPMethod;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream, createMemoryStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	// Registry with cap=1: registering a second client evicts the first.
	auto reg = new InMemoryRedirectUriRegistry(1);
	auto proxy = new OAuthProxy(cfg, new InMemoryConsentStore(), reg);
	proxy.register(["http://localhost:5000/cb"]);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	// /authorize for the client's redirect_uri: returns the consent screen.
	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);
	const html = () @trusted { return cast(string) sink.data; }();
	assert(html.canFind("Authorize application"), "expected consent screen");

	// Extract the hidden proxy state from the consent screen form.
	import std.string : indexOf;

	const stateMark = `name="state" value="`;
	const hi = html.indexOf(stateMark);
	assert(hi >= 0);
	const rest = html[hi + stateMark.length .. $];
	const proxyState = rest[0 .. rest.indexOf('"')];
	assert(proxyState.length > 0);

	// Evict the client's redirect_uri from the registry by registering a second
	// client (cap=1 causes the first registration to be discarded).
	proxy.register(["http://localhost:9999/other"]);

	// POST /consent: with the redirect_uri evicted, proxy.authorize throws
	// InvalidRedirectUriException. The handler must catch it and return 400.
	auto formBody = () @trusted { return cast(ubyte[])("state=" ~ proxyState).dup; }();
	auto req2 = createTestHTTPServerRequest(URL("https://mcp.example.com/consent"),
			HTTPMethod.POST, createMemoryStream(formBody, false));
	req2.headers["Content-Type"] = "application/x-www-form-urlencoded";
	auto sink2 = createMemoryOutputStream();
	auto res2 = createTestHTTPServerResponse(sink2, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req2, res2);

	assert(res2.statusCode == 400, "expected 400 for evicted redirect_uri");
	const body2 = () @trusted { return cast(string) sink2.data; }();
	assert(body2.canFind("invalid_request"), "expected invalid_request error body");
}
