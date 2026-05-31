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
///   * `GET  /consent` — the consent-approval action reached from the consent
///     screen: records user consent for the pending client (`proxy.grantConsent`)
///     and resumes the upstream authorize 302 with the stored PKCE
///     `code_challenge` + `scope`.
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
/// `ProxyStateStore`, `consentScreenHtml`, `consentApproveUrl`) carry no HTTP
/// state and are unit-tested directly; the `mountOAuthProxy` wiring threads them
/// onto the router.
module mcp.transport.oauth_proxy_mount;

import std.string : startsWith, indexOf;
import std.uri : encodeComponent;

import vibe.data.json : Json, parseJsonString;
import vibe.http.server : HTTPServerRequest, HTTPServerResponse, HTTPStatus;
import vibe.http.router : URLRouter;
import vibe.http.common : HTTPMethod;

import mcp.auth.oauth_proxy : ConsentRequiredException, OAuthProxy, OAuthProxyConfig;

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

/// Extract the `redirect_uris` array from a parsed RFC 7591 DCR request body,
/// returning an empty array when the field is absent or malformed.
string[] redirectUrisFrom(Json body_) @safe
{
	string[] uris;
	if (body_.type == Json.Type.object && "redirect_uris" in body_
			&& body_["redirect_uris"].type == Json.Type.array)
	{
		auto arr = body_["redirect_uris"];
		foreach (i; 0 .. arr.length)
			if (arr[i].type == Json.Type.string)
				uris ~= arr[i].get!string;
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
/// approval action: a `GET` to `approveUrl` (the proxy's consent route, carrying
/// the opaque proxy `state`) which records consent and resumes the upstream
/// redirect.
string consentScreenHtml(string clientRedirectUri, string approveUrl) @safe
{
	const safeUri = htmlEscape(clientRedirectUri);
	const safeApprove = htmlEscape(approveUrl);
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
		~ "<title>Authorize application</title></head><body>" ~ "<h1>Authorize application</h1>"
		~ "<p>An application is requesting to sign in via this server and be"
		~ " forwarded to the upstream identity provider.</p>"
		~ "<p>Redirect URI: <code>" ~ safeUri ~ "</code></p>" ~ "<p><a href=\""
		~ safeApprove ~ "\">Approve and continue</a></p>" ~ "</body></html>";
}

private string htmlEscape(string s) @safe
{
	import std.array : replace;

	return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
		.replace("\"", "&quot;");
}

/// Build the proxy's consent-approval URL: the consent route path plus the opaque
/// proxy `state` identifying the pending authorization. Visiting it records user
/// consent for the pending client and resumes the upstream authorize redirect.
string consentApproveUrl(string consentPath, string proxyState) @safe
{
	return consentPath ~ "?state=" ~ enc(proxyState);
}

/// A thread-safe in-memory store mapping a proxy `state` to the client's
/// pending-authorization details. Entries are consumed (single use) on lookup so
/// a relayed callback cannot be replayed.
final class ProxyStateStore
{
	private ProxyAuthState[string] entries;

	/// Record the client's authorization details under the proxy `state`.
	void put(string proxyState, ProxyAuthState st) @safe
	{
		synchronized (this)
			entries[proxyState] = st;
	}

	/// Consume and return the details for `proxyState`, setting `found`.
	ProxyAuthState take(string proxyState, out bool found) @safe
	{
		synchronized (this)
		{
			if (auto p = proxyState in entries)
			{
				found = true;
				auto v = *p;
				entries.remove(proxyState);
				return v;
			}
		}
		found = false;
		return ProxyAuthState.init;
	}
}

/// Mint a fresh, unguessable proxy `state` value (the only `state` sent
/// upstream).
private string mintState() @trusted
{
	import std.uuid : randomUUID;

	return randomUUID().toString();
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
		const scope_ = req.query.get("scope", "");
		const clientRedirect = req.query.get("redirect_uri", "");
		const clientState = req.query.get("state", "");

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
			// rather than forwarding to the upstream authorization server.
			const approve = consentApproveUrl(consentPath, proxyState);
			res.statusCode = HTTPStatus.ok;
			res.writeBody(consentScreenHtml(clientRedirect, approve), "text/html; charset=utf-8");
		}
	});

	// /consent: the confused-deputy consent-approval action. The user reaches this
	// from the consent screen; it records consent for the pending client (keyed by
	// its redirect_uri) and resumes the upstream authorize redirect with the stored
	// PKCE code_challenge + scope. The pending entry is re-stored under the same
	// proxy state so the eventual upstream callback can still relay the code.
	router.get(consentPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const proxyState = req.query.get("state", "");
		bool found;
		auto st = store.take(proxyState, found);
		if (!found || st.clientRedirectUri.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody("Unknown or expired authorization state", "text/plain");
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
		const proxyState = req.query.get("state", "");
		bool found;
		auto st = store.take(proxyState, found);
		if (!found || st.clientRedirectUri.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody("Unknown or expired authorization state", "text/plain");
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
		const code = formField(form, "code");
		const verifier = formField(form, "code_verifier");

		const upstreamBody = proxy.tokenForm(code, verifier);
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
	import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
	import vibe.stream.operations : readAllUTF8;

	int st = 502;
	string rb;
	requestHTTP(endpoint, (scope HTTPClientRequest creq) {
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

unittest  // formField URL-decodes a value and returns "" for an absent field
{
	assert(formField("grant_type=authorization_code&code=ab%20cd&code_verifier=V",
			"code") == "ab cd");
	assert(formField("grant_type=authorization_code&code=X", "code_verifier") == "");
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

unittest  // CONSENT SCREEN: HTML names the client redirect_uri and the approve link
{
	import std.algorithm : canFind;

	const html = consentScreenHtml("http://localhost:5000/cb", "/consent?state=abc");
	assert(html.canFind("Authorize application"));
	assert(html.canFind("http://localhost:5000/cb"));
	assert(html.canFind("href=\"/consent?state=abc\""));
}

unittest  // CONSENT SCREEN: the untrusted client redirect_uri is HTML-escaped
{
	import std.algorithm : canFind;

	const html = consentScreenHtml(`http://x/cb?a=1&b="<script>`, "/consent?state=s");
	assert(html.canFind("&amp;"));
	assert(html.canFind("&lt;script&gt;"));
	assert(html.canFind("&quot;"));
	assert(!html.canFind("<script>"));
}

unittest  // consentApproveUrl joins the consent path and the url-encoded proxy state
{
	assert(consentApproveUrl("/consent", "ab cd") == "/consent?state=ab%20cd");
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

unittest  // CONFUSED DEPUTY: after the user approves, /consent records consent + 302s upstream
{
	import std.algorithm : canFind, startsWith;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.common : HTTPMethod;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream;

	OAuthProxyConfig cfg;
	cfg.upstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize";
	cfg.upstreamTokenEndpoint = "https://github.com/login/oauth/access_token";
	cfg.upstreamClientId = "Iv1.upstream";
	cfg.baseUrl = "https://mcp.example.com";
	cfg.resource = "https://mcp.example.com/mcp";

	auto proxy = new OAuthProxy(cfg);
	auto router = new URLRouter;
	mountOAuthProxy(router, proxy);

	// 1) /authorize renders the consent screen and stashes the pending auth under a
	//    proxy state we can read back from the approve link.
	auto sink = createMemoryOutputStream();
	auto req = createTestHTTPServerRequest(URL("https://mcp.example.com/authorize?code_challenge=CH&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs"));
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	router.handleRequest(req, res);
	const html = () @trusted { return cast(string) sink.data; }();

	// Extract the consent approve URL (href="/consent?state=...").
	import std.string : indexOf;

	const hrefMark = `href="`;
	const hi = html.indexOf(hrefMark);
	assert(hi >= 0);
	const rest = html[hi + hrefMark.length .. $];
	const close = rest.indexOf('"');
	const approveUrl = rest[0 .. close];
	assert(approveUrl.startsWith("/consent?state="));

	// 2) Visiting /consent grants consent and 302s to the upstream authorize.
	auto res2 = createTestHTTPServerResponse(null, null, TestHTTPResponseMode.bodyOnly);
	auto req2 = createTestHTTPServerRequest(URL("https://mcp.example.com" ~ approveUrl));
	router.handleRequest(req2, res2);

	assert(proxy.hasConsent("http://localhost:5000/cb"));
	assert(res2.statusCode == 302);
	assert(res2.headers["Location"].startsWith("https://github.com/login/oauth/authorize?"));
	assert(res2.headers["Location"].canFind("client_id=Iv1.upstream"));
	assert(res2.headers["Location"].canFind("code_challenge=CH"));
}
