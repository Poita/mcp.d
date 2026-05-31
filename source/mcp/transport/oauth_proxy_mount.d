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
///   * `GET  /authorize` — 302 to the upstream authorization endpoint
///     (`proxy.authorize`), persisting the client's dynamic `redirect_uri` and
///     `state` keyed by a freshly minted proxy `state`, so they can be honoured
///     after the upstream round-trip.
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
/// `ProxyStateStore`) carry no HTTP state and are unit-tested directly; the
/// `mountOAuthProxy` wiring threads them onto the router.
module mcp.transport.oauth_proxy_mount;

import std.string : startsWith, indexOf;
import std.uri : encodeComponent;

import vibe.data.json : Json, parseJsonString;
import vibe.http.server : HTTPServerRequest, HTTPServerResponse, HTTPStatus;
import vibe.http.router : URLRouter;
import vibe.http.common : HTTPMethod;

import mcp.auth.oauth_proxy : OAuthProxy, OAuthProxyConfig;

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
/// `state` value sent upstream.
struct ProxyAuthState
{
	string clientRedirectUri; /// the client's dynamic redirect URI (RFC 7591)
	string clientState; /// the client's original OAuth `state`, relayed back verbatim
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

	// /authorize: persist the client's dynamic redirect_uri + state under a fresh
	// proxy state, then 302 to the upstream authorization endpoint with the
	// client's PKCE code_challenge forwarded (transparent PKCE).
	router.get(authorizePath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const codeChallenge = req.query.get("code_challenge", "");
		const scope_ = req.query.get("scope", "");
		const clientRedirect = req.query.get("redirect_uri", "");
		const clientState = req.query.get("state", "");

		const proxyState = mintState();
		store.put(proxyState, ProxyAuthState(clientRedirect, clientState));

		const location = proxy.authorize(codeChallenge, scope_, proxyState);
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
