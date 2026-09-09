/// HTTP mount for the embedded demo authorization server
/// (`mcp.auth.demo_auth_server`) — the self-contained OAuth 2.1 surface an
/// MCP server publishes when it is its OWN authorization server, like the
/// official `example-server.modelcontextprotocol.io` deployment.
///
/// `mountDemoAuthServer` registers, on a vibe.d `URLRouter`:
///
///   * `GET  /.well-known/oauth-authorization-server` — RFC 8414 AS metadata
///     naming this server as issuer (`as.metadataJson`).
///   * `POST /register` — RFC 7591 DCR: mints a per-client `client_id` and
///     records the client's `redirect_uris` (`as.register`).
///   * `GET  /authorize` — validates the request (registered redirect_uri,
///     PKCE S256 challenge) and renders the approve screen. The demo AS
///     authenticates nobody, so the screen replaces a login: the user types
///     the subject name the token will carry and approves (or denies). The
///     pending request is held under an unguessable single-use `state` in a
///     bounded `ProxyStateStore`.
///   * `POST /consent` — the approve screen's form action: on approve, mints
///     the single-use authorization code and 302s it back to the client's
///     `redirect_uri`; on deny, 302s `error=access_denied`.
///   * `POST /token` — redeems `authorization_code` (with PKCE verification)
///     and `refresh_token` grants for the server's own opaque tokens
///     (`as.exchangeAuthorizationCode` / `as.exchangeRefreshToken`).
///
/// The RFC 9728 Protected Resource Metadata document is served by `mountMcp`
/// from `as.toResourceServer()` — pass that as `StreamableHttpOptions.auth` so
/// the 401 challenge, audience binding, and PRM document all line up.
module mcp.transport.demo_auth_mount;

import std.uri : encodeComponent;

import vibe.data.json : Json, parseJsonString;
import vibe.http.common : HTTPMethod;
import vibe.http.router : URLRouter;
import vibe.http.server : HTTPServerRequest, HTTPServerResponse, HTTPStatus;

import mcp.auth.demo_auth_server : DemoAuthServer, sanitizeSubject, TokenOutcome;
import mcp.transport.oauth_proxy_mount : invalidRequestJson,
	invalidClientMetadataJson, redirectUrisFrom, ProxyAuthState, ProxyStateStore;

@safe:

/// The well-known path for RFC 8414 AS metadata.
enum string AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server";

/// Build the approve screen: because the demo AS has no identity provider,
/// this page stands in for the login — a `subject` text input names the
/// principal the token will carry, and Approve/Deny submit to `consentPath`
/// with the opaque pending `state` in hidden+POST form (never a URL, so it
/// cannot leak via Referer/history and cannot be fired by link prefetch).
///
/// The subject defaults to a RANDOM per-browser id persisted in localStorage
/// (edits are saved back), mirroring the official example server's mock IdP:
/// the same browser keeps its principal across re-authorizations, different
/// browsers/devices get distinct principals, and nobody collides on a shared
/// default name. With scripting unavailable the field submits empty and the
/// consent handler mints a random subject server-side.
string demoApproveScreenHtml(string clientRedirectUri, string consentPath, string state)
{
	const safeUri = htmlEscape(clientRedirectUri);
	const safeAction = htmlEscape(consentPath);
	const safeState = htmlEscape(state);
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" ~ "<meta name=\"referrer\" content=\"no-referrer\">" ~ "<title>Demo authorization</title></head><body>" ~ "<h1>Demo authorization</h1>" ~ "<p>This is a DEMO authorization server: it verifies no identity." ~ " The name below is this browser's identity — edit it to act as someone else." ~ " Different browsers (or incognito windows) get their own identity.</p>" ~ "<p>Redirect URI: <code>" ~ safeUri ~ "</code></p>" ~ "<form method=\"post\" action=\"" ~ safeAction ~ "\" " ~ "onsubmit=\"try{localStorage.setItem('mcpDemoSubject',document.getElementById('subject').value)}catch(e){}\">" ~ "<input type=\"hidden\" name=\"state\" value=\"" ~ safeState ~ "\">" ~ "<label>Your name: <input type=\"text\" name=\"subject\" id=\"subject\" value=\"\"></label> " ~ "<button type=\"submit\" name=\"action\" value=\"approve\">Approve</button> " ~ "<button type=\"submit\" name=\"action\" value=\"deny\">Deny</button>" ~ "</form>" ~ "<script>(function(){var el=document.getElementById('subject');" ~ "var id='';try{id=localStorage.getItem('mcpDemoSubject')||''}catch(e){}" ~ "if(!id){id='user-'+Math.random().toString(36).slice(2,8);" ~ "try{localStorage.setItem('mcpDemoSubject',id)}catch(e){}}" ~ "el.value=id;})();</script>" ~ "</body></html>";
}

/// Append OAuth response parameters to a client redirect URI, respecting any
/// query string it already carries.
string appendQueryParams(string url, const string[2][] params)
{
	import std.algorithm : canFind;

	string sep = url.canFind('?') ? "&" : "?";
	string result = url;
	foreach (p; params)
	{
		result ~= sep ~ p[0] ~ "=" ~ encodeComponent(p[1]);
		sep = "&";
	}
	return result;
}

/// Mount the complete demo-AS OAuth surface (metadata + DCR + authorize +
/// consent + token) onto `router`. The optional `store` override is for tests;
/// the default holds pending authorizations for 10 minutes, bounded.
void mountDemoAuthServer(URLRouter router, DemoAuthServer as, ProxyStateStore store = null)
in (as !is null)
{
	if (store is null)
		store = new ProxyStateStore();
	const cfg = as.config();
	const authorizePath = pathOf(cfg.authorizeEndpoint());
	const tokenPath = pathOf(cfg.tokenEndpoint());
	const registerPath = pathOf(cfg.registrationEndpoint());
	const consentPath = pathOf(cfg.consentEndpoint());

	router.get(AuthorizationServerMetadataPath, (HTTPServerRequest req,
			HTTPServerResponse res) @safe {
		res.statusCode = HTTPStatus.ok;
		res.writeJsonBody(as.metadataJson());
	});

	router.post(registerPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		Json body_;
		if (!tryReadJsonBody(req, body_))
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidClientMetadataJson("request body is not valid JSON"));
			return;
		}
		const uris = redirectUrisFrom(body_);
		if (uris.length == 0)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidClientMetadataJson(
				"redirect_uris is required and must contain at least one usable URI"));
			return;
		}
		res.statusCode = HTTPStatus.created;
		res.writeJsonBody(as.register(uris));
	});

	router.get(authorizePath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const redirectUri = req.query.get("redirect_uri", "");
		const clientState = req.query.get("state", "");
		const clientId = req.query.get("client_id", "");
		const codeChallenge = req.query.get("code_challenge", "");
		const method = req.query.get("code_challenge_method", "");
		const scope_ = req.query.get("scope", "");
		const responseType = req.query.get("response_type", "");

		// The redirect URI is untrusted until validated, so failures answer the
		// browser directly rather than redirecting an error to it.
		const reason = as.validateAuthorize(redirectUri, responseType, codeChallenge, method);
		if (reason !is null)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson(reason));
			return;
		}

		const pending = mintPendingState();
		store.put(pending, ProxyAuthState(redirectUri, clientState,
			codeChallenge, scope_, clientId));
		res.headers["Cache-Control"] = "no-store";
		res.headers["Referrer-Policy"] = "no-referrer";
		res.statusCode = HTTPStatus.ok;
		res.writeBody(demoApproveScreenHtml(redirectUri, consentPath, pending),
			"text/html; charset=utf-8");
	});

	router.post(consentPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const pending = req.form.get("state", "");
		bool found;
		auto st = store.take(pending, found);
		if (!found)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(invalidRequestJson("unknown or expired authorization request"));
			return;
		}

		if (req.form.get("action", "approve") == "deny")
		{
			string[2][] params = [["error", "access_denied"]];
			if (st.clientState.length)
				params ~= ["state", st.clientState];
			res.redirect(appendQueryParams(st.clientRedirectUri, params));
			return;
		}

		// An empty or unusable subject (no-script client, or the field
		// cleared) gets a random one rather than a shared default, so distinct
		// callers never silently collapse into one principal.
		const subject = sanitizeSubject(req.form.get("subject", ""), randomSubject());
		const code = as.issueCode(st.clientId, st.clientRedirectUri,
			st.codeChallenge, st.scope_, subject);
		string[2][] params = [["code", code]];
		if (st.clientState.length)
			params ~= ["state", st.clientState];
		res.redirect(appendQueryParams(st.clientRedirectUri, params));
	});

	router.post(tokenPath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const grantType = req.form.get("grant_type", "authorization_code");
		TokenOutcome outcome;
		if (grantType == "refresh_token")
			outcome = as.exchangeRefreshToken(req.form.get("refresh_token",
				""), req.form.get("client_id", ""));
		else if (grantType == "authorization_code")
			outcome = as.exchangeAuthorizationCode(req.form.get("code", ""),
				req.form.get("code_verifier", ""), req.form.get("redirect_uri",
				""), req.form.get("client_id", ""));
		else
		{
			Json err = Json.emptyObject;
			err["error"] = "unsupported_grant_type";
			res.statusCode = HTTPStatus.badRequest;
			res.writeJsonBody(err);
			return;
		}
		// RFC 6749 §5.1: token responses (which carry credentials) must not be
		// cached; error responses get the same treatment for uniformity.
		res.headers["Cache-Control"] = "no-store";
		res.statusCode = outcome.status;
		res.writeJsonBody(outcome.body);
	});
}

private string htmlEscape(string s)
{
	import std.array : replace;

	return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
		.replace("\"", "&quot;");
}

private string pathOf(string url)
{
	import std.string : indexOf, startsWith;

	auto s = url;
	const scheme = s.indexOf("://");
	if (scheme >= 0)
	{
		s = s[scheme + 3 .. $];
		const slash = s.indexOf('/');
		s = slash >= 0 ? s[slash .. $] : "/";
	}
	return s.startsWith("/") ? s : "/" ~ s;
}

/// Mint a random subject for a consent POST that carried no usable name, so
/// no two anonymous approvals share a principal.
private string randomSubject()
{
	import mcp.auth.csprng : cryptoRandomBytes;
	import mcp.auth.oauth : base64UrlNoPad;

	return "user-" ~ base64UrlNoPad(cryptoRandomBytes(4));
}

/// Mint the unguessable single-use pending-authorization key (CSPRNG; it is
/// the CSRF defense for the consent POST).
private string mintPendingState()
{
	import mcp.auth.csprng : cryptoRandomBytes;
	import mcp.auth.oauth : base64UrlNoPad;

	return base64UrlNoPad(cryptoRandomBytes(32));
}

private bool tryReadJsonBody(scope HTTPServerRequest req, out Json body_)
{
	import vibe.stream.operations : readAllUTF8;

	try
	{
		body_ = parseJsonString(readAllUTF8(req.bodyReader));
		return true;
	}
	catch (Exception)
		return false;
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	import std.algorithm : canFind;
	import std.string : indexOf;
	import vibe.http.server : createTestHTTPServerRequest,
		createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryOutputStream, createMemoryStream;
	import mcp.auth.demo_auth_server : DemoAuthServerConfig, s256ChallengeOf;

	private struct TestAs
	{
		DemoAuthServer as;
		URLRouter router;
	}

	private TestAs mountedTestAs()
	{
		DemoAuthServerConfig cfg;
		cfg.baseUrl = "https://demo.example.com";
		cfg.resource = "https://demo.example.com/mcp";
		auto as = new DemoAuthServer(cfg);
		auto router = new URLRouter;
		mountDemoAuthServer(router, as);
		return TestAs(as, router);
	}

	// GET `path` on the router, returning the response body (status via `res`).
	private string routerGet(URLRouter router, string url, out int status)
	{
		auto sink = createMemoryOutputStream();
		auto req = createTestHTTPServerRequest(URL(url));
		auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
		router.handleRequest(req, res);
		status = res.statusCode;
		return () @trusted { return cast(string) sink.data; }();
	}

	// POST a body to `path`, returning the response body; Location comes back
	// via `location`.
	private string routerPost(URLRouter router, string url, string body_,
			string contentType, out int status, out string location)
	{
		auto sink = createMemoryOutputStream();
		auto data = () @trusted { return cast(ubyte[]) body_.dup; }();
		auto req = createTestHTTPServerRequest(URL(url), HTTPMethod.POST,
				createMemoryStream(data, false));
		req.headers["Content-Type"] = contentType;
		auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
		router.handleRequest(req, res);
		status = res.statusCode;
		location = res.headers.get("Location", "");
		return () @trusted { return cast(string) sink.data; }();
	}

	// Pull a query-parameter value out of a redirect Location.
	private string queryParam(string url, string name)
	{
		const mark = name ~ "=";
		auto q = url.indexOf('?');
		if (q < 0)
			return "";
		foreach (part; splitAmp(url[q + 1 .. $]))
			if (part.startsWith(mark))
				return part[mark.length .. $];
		return "";
	}

	private string[] splitAmp(string s)
	{
		import std.algorithm : splitter;
		import std.array : array;

		string[] parts;
		foreach (p; s.splitter('&'))
			parts ~= p;
		return parts;
	}

	private bool startsWith(string s, string prefix)
	{
		return s.length >= prefix.length && s[0 .. prefix.length] == prefix;
	}

	// Extract the hidden pending-state value from the approve screen HTML.
	private string pendingStateOf(string html)
	{
		const stateMark = `name="state" value="`;
		const hi = html.indexOf(stateMark);
		assert(hi >= 0, "approve screen should carry the hidden state field");
		const rest = html[hi + stateMark.length .. $];
		return rest[0 .. rest.indexOf('"')];
	}
}

unittest  // the AS metadata well-known names this server as its own issuer
{
	auto t = mountedTestAs();
	int status;
	const body_ = routerGet(t.router,
			"https://demo.example.com/.well-known/oauth-authorization-server", status);
	assert(status == 200);
	auto j = parseJsonString(body_);
	assert(j["issuer"].get!string == "https://demo.example.com");
	assert(j["token_endpoint"].get!string == "https://demo.example.com/token");
}

unittest  // FULL FLOW: DCR -> authorize -> approve -> token -> validated principal
{
	auto t = mountedTestAs();
	int status;
	string location;

	// 1) DCR registers the client's redirect URI and mints a client_id.
	const reg = routerPost(t.router, "https://demo.example.com/register",
			`{"redirect_uris":["http://localhost:5000/cb"]}`, "application/json", status, location);
	assert(status == 201);
	const clientId = parseJsonString(reg)["client_id"].get!string;
	assert(clientId.length > 0);

	// 2) /authorize renders the approve screen (no identity: it asks for a name).
	const verifier = "e2e-verifier-e2e-verifier-e2e-verifier-42";
	const html = routerGet(t.router, "https://demo.example.com/authorize?client_id="
			~ clientId ~ "&response_type=code&code_challenge=" ~ s256ChallengeOf(
				verifier) ~ "&code_challenge_method=S256&scope=mcp"
			~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=cs-123", status);
	assert(status == 200);
	assert(html.canFind("Demo authorization"));
	const pending = pendingStateOf(html);

	// 3) Approving with a subject mints the code and 302s it to the client.
	routerPost(t.router, "https://demo.example.com/consent",
			"state=" ~ pending ~ "&subject=alice&action=approve",
			"application/x-www-form-urlencoded", status, location);
	assert(status == 302);
	assert(location.startsWith("http://localhost:5000/cb?"));
	assert(queryParam(location, "state") == "cs-123");
	const code = queryParam(location, "code");
	assert(code.length > 0);

	// 4) The token endpoint redeems the code with the PKCE verifier.
	const tokenBody = routerPost(t.router,
			"https://demo.example.com/token",
			"grant_type=authorization_code&code=" ~ code ~ "&code_verifier="
			~ verifier ~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&client_id=" ~ clientId,
			"application/x-www-form-urlencoded", status, location);
	assert(status == 200);
	auto tok = parseJsonString(tokenBody);
	assert(tok["token_type"].get!string == "Bearer");

	// 5) The minted token validates to the approved subject, audience-bound.
	auto info = t.as.validator()(tok["access_token"].get!string);
	assert(info.valid && info.subject == "alice");
	assert(info.hasAudience("https://demo.example.com/mcp"));

	// 6) The refresh grant rotates.
	const refreshBody = routerPost(t.router, "https://demo.example.com/token",
			"grant_type=refresh_token&refresh_token=" ~ tok["refresh_token"].get!string
			~ "&client_id=" ~ clientId, "application/x-www-form-urlencoded", status, location);
	assert(status == 200);
	assert(t.as.validator()(parseJsonString(refreshBody)["access_token"].get!string)
			.subject == "alice");
}

unittest  // /authorize refuses an unregistered redirect_uri without redirecting
{
	auto t = mountedTestAs();
	int status;
	const body_ = routerGet(t.router, "https://demo.example.com/authorize?client_id=x"
			~ "&code_challenge=CH&redirect_uri=http%3A%2F%2Fevil.example.com%2Fcb", status);
	assert(status == 400);
	assert(parseJsonString(body_)["error"].get!string == "invalid_request");
}

unittest  // deny: the client gets error=access_denied, no code is minted
{
	auto t = mountedTestAs();
	int status;
	string location;
	routerPost(t.router, "https://demo.example.com/register",
			`{"redirect_uris":["http://localhost:5000/cb"]}`, "application/json", status, location);
	const html = routerGet(t.router, "https://demo.example.com/authorize?code_challenge=CH"
			~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb&state=s1", status);
	routerPost(t.router, "https://demo.example.com/consent", "state=" ~ pendingStateOf(
			html) ~ "&action=deny", "application/x-www-form-urlencoded", status, location);
	assert(status == 302);
	assert(queryParam(location, "error") == "access_denied");
	assert(queryParam(location, "code").length == 0);
}

unittest  // the pending state is single-use: a replayed consent POST is refused
{
	auto t = mountedTestAs();
	int status;
	string location;
	routerPost(t.router, "https://demo.example.com/register",
			`{"redirect_uris":["http://localhost:5000/cb"]}`, "application/json", status, location);
	const html = routerGet(t.router, "https://demo.example.com/authorize?code_challenge=CH"
			~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb", status);
	const pending = pendingStateOf(html);
	routerPost(t.router, "https://demo.example.com/consent",
			"state=" ~ pending ~ "&subject=a&action=approve",
			"application/x-www-form-urlencoded", status, location);
	assert(status == 302);
	routerPost(t.router, "https://demo.example.com/consent",
			"state=" ~ pending ~ "&subject=a&action=approve",
			"application/x-www-form-urlencoded", status, location);
	assert(status == 400);
}

unittest  // an empty subject gets a RANDOM principal, not a shared default
{
	import mcp.auth.demo_auth_server : s256ChallengeOf;

	auto t = mountedTestAs();
	int status;
	string location;
	routerPost(t.router, "https://demo.example.com/register",
			`{"redirect_uris":["http://localhost:5000/cb"]}`, "application/json", status, location);

	// Run the approve->token flow twice with no subject; the two minted tokens
	// must carry distinct random subjects (no cross-caller collapse).
	string subjectOf(string verifier) @safe
	{
		int st;
		string loc;
		const html = routerGet(t.router,
				"https://demo.example.com/authorize?code_challenge=" ~ s256ChallengeOf(
					verifier) ~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb", st);
		routerPost(t.router, "https://demo.example.com/consent",
				"state=" ~ pendingStateOf(html) ~ "&action=approve",
				"application/x-www-form-urlencoded", st, loc);
		const tokenBody = routerPost(t.router, "https://demo.example.com/token",
				"grant_type=authorization_code&code=" ~ queryParam(loc,
					"code") ~ "&code_verifier="
				~ verifier ~ "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcb",
				"application/x-www-form-urlencoded", st, loc);
		return t.as.validator()(parseJsonString(tokenBody)["access_token"].get!string).subject;
	}

	const a = subjectOf("anon-verifier-anon-verifier-anon-verifier-1");
	const b = subjectOf("anon-verifier-anon-verifier-anon-verifier-2");
	assert(a.startsWith("user-") && b.startsWith("user-"));
	assert(a != b);
}

unittest  // an unsupported grant_type is refused per RFC 6749 §5.2
{
	auto t = mountedTestAs();
	int status;
	string location;
	const body_ = routerPost(t.router, "https://demo.example.com/token",
			"grant_type=client_credentials", "application/x-www-form-urlencoded", status, location);
	assert(status == 400);
	assert(parseJsonString(body_)["error"].get!string == "unsupported_grant_type");
}

unittest  // appendQueryParams respects an existing query string
{
	assert(appendQueryParams("http://x/cb", [["code", "a b"]]) == "http://x/cb?code=a%20b");
	assert(appendQueryParams("http://x/cb?k=v", [["code", "c"], ["state",
				"s"]]) == "http://x/cb?k=v&code=c&state=s");
}

unittest  // the approve screen HTML-escapes attacker-controlled values
{
	// The page carries its own legitimate inline script (the localStorage
	// subject default), so assert the INJECTED sequences stay escaped rather
	// than banning script tags wholesale.
	const html = demoApproveScreenHtml(`http://x/cb?"><script>`, "/consent", `"><b>`);
	assert(!html.canFind(`"><script>`));
	assert(html.canFind("&quot;&gt;&lt;script&gt;"));
	assert(!html.canFind(`value=""><b>`));
}
