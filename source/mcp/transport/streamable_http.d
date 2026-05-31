module mcp.transport.streamable_http;

import vibe.http.server;
import vibe.http.router : URLRouter;
import vibe.stream.operations : readAllUTF8;
import vibe.data.json : Json;

import mcp.server.server;
import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.draft;
import mcp.transport.sse_context;
import mcp.transport.session;
import mcp.auth.resource_server;

/// The HTTP header carrying the session id (basic/transports §Session Management).
enum SessionHeader = "Mcp-Session-Id";

/// Configuration for the Streamable HTTP server transport.
struct StreamableHttpOptions
{
	string path = "/mcp"; /// the single MCP endpoint path
	string[] bindAddresses = ["127.0.0.1"]; /// addresses to bind

	/// DNS-rebinding protection: reject requests whose Host/Origin is not a
	/// recognized localhost value (or in the explicit allow-lists below). On by
	/// default per the MCP transport security guidance; disable when fronting
	/// the server with a trusted reverse proxy.
	bool validateOrigin = true;
	string[] allowedHosts = []; /// extra Host header values to accept
	string[] allowedOrigins = []; /// extra Origin header values to accept

	/// Enable stateful session management (basic/transports §Session Management).
	/// When true, the server assigns a cryptographically-secure `Mcp-Session-Id`
	/// on the response carrying the `InitializeResult`, requires that header on
	/// every subsequent request (HTTP 400 when absent, HTTP 404 when unknown or
	/// terminated), and honours client-driven termination via HTTP DELETE
	/// (HTTP 404 for an unknown session). When false (the default) the transport
	/// is stateless and never issues or checks a session id.
	bool enableSessions = false;

	/// OAuth 2.1 Resource Server enforcement (basic/authorization). When
	/// `auth.validator` is set, every MCP request must present a valid
	/// `Authorization: Bearer` token: the transport validates it (and its RFC 8707
	/// audience), returns `401` with a `WWW-Authenticate: Bearer` header carrying
	/// the `resource_metadata` URL on failure, returns `403 insufficient_scope`
	/// when a required scope is missing, and serves the RFC 9728 Protected
	/// Resource Metadata document at `/.well-known/oauth-protected-resource`.
	/// Validated token info is surfaced to handlers via `RequestContext.auth`.
	/// When unset (the default) the transport performs no token checks.
	ResourceServerConfig auth;
}

/// The well-known path (RFC 9728 §3) at which a protected resource server
/// publishes its OAuth 2.0 Protected Resource Metadata document.
enum ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource";

/// Mount an `McpServer` onto a vibe.d `URLRouter` at the configured path,
/// implementing the modern Streamable HTTP transport (single endpoint):
///   - POST: a JSON-RPC message/batch; returns `application/json` for requests,
///     or `202 Accepted` with no body when the payload needs no reply.
///   - GET:  on the stable revisions, opens a standalone server->client SSE
///     stream wired to the server-push channel (`McpServer.notify`); on the
///     draft, which drops the standalone stream, GET -> 405.
///   - DELETE: the draft has no protocol-level sessions to tear down -> 405.
void mountMcp(URLRouter router, McpServer server,
		StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
	auto coord = new StreamCoordinator;
	auto sessions = opts.enableSessions ? new SessionManager : null;

	// basic/authorization (RFC 9728 §3): publish the Protected Resource Metadata
	// document so clients can discover the authorization server(s). Served
	// unauthenticated (it is the discovery hook the 401 points clients to).
	if (opts.auth.enabled)
	{
		router.get(ProtectedResourceMetadataPath, (HTTPServerRequest req,
				HTTPServerResponse res) @safe {
			res.statusCode = HTTPStatus.ok;
			res.writeJsonBody(opts.auth.metadata().toJson());
		});
	}

	router.post(opts.path, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		handlePost(server, coord, sessions, token, req, res);
	});
	auto push = server.serverPushChannel(coord);
	router.get(opts.path, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		handleGet(server, push, sessions, req, res);
	});
	router.match(HTTPMethod.DELETE, opts.path, (HTTPServerRequest req,
			HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		if (sessions !is null && deleteTerminatesSession(server.negotiatedVersion))
		{
			// Session Management: a client signals it no longer needs the
			// session via DELETE with the Mcp-Session-Id header. Terminate it
			// and reply 204; an absent header is 400, an unknown/already-
			// terminated session is 404. The draft removed protocol-level
			// sessions, so this branch is version-gated: a draft-negotiated
			// server falls through to the 405 below even when sessions are
			// enabled (mirroring the GET getOpensSseStream gate).
			const sid = req.headers.get(SessionHeader, "");
			if (sid.length == 0)
			{
				res.statusCode = HTTPStatus.badRequest;
				res.writeBody("Missing Mcp-Session-Id header", "text/plain");
				return;
			}
			if (!sessions.terminate(sid))
			{
				res.statusCode = HTTPStatus.notFound;
				res.writeBody("Unknown or terminated session", "text/plain");
				return;
			}
			res.statusCode = HTTPStatus.noContent;
			res.writeBody("", "text/plain");
			return;
		}
		// No protocol-level session to tear down (stateless mode, or a
		// draft-negotiated session which removed sessions entirely): per the
		// backward-compatibility rules, DELETE -> 405. The Allow header MUST list
		// every method the endpoint actually supports (RFC 9110 §10.2.1): on the
		// stable revisions that is GET (the standalone SSE stream) and POST, while
		// the draft drops the GET stream so only POST remains.
		res.statusCode = HTTPStatus.methodNotAllowed;
		res.headers["Allow"] = allowedMethodsHeader(server.negotiatedVersion);
		res.writeBody("", "text/plain");
	});
}

/// Enforce DNS-rebinding protection. Returns true if the request may proceed;
/// otherwise writes a `403 Forbidden` and returns false.
private bool guardOrigin(scope HTTPServerRequest req, scope HTTPServerResponse res,
		StreamableHttpOptions opts) @safe
{
	if (!opts.validateOrigin)
		return true;

	const host = req.headers.get("Host", "");
	const origin = req.headers.get("Origin", "");

	if (host.length && !hostAllowed(host, opts.allowedHosts))
	{
		res.statusCode = HTTPStatus.forbidden;
		res.writeBody("Forbidden: Host not allowed", "text/plain");
		return false;
	}
	if (origin.length && !originAllowed(origin, opts.allowedOrigins))
	{
		res.statusCode = HTTPStatus.forbidden;
		res.writeBody("Forbidden: Origin not allowed", "text/plain");
		return false;
	}
	return true;
}

/// Enforce OAuth 2.1 Resource Server authorization (basic/authorization). When
/// `opts.auth` is enabled, validate the request's `Authorization: Bearer` token
/// and, on failure, write the spec-mandated response: `401` with a
/// `WWW-Authenticate: Bearer` header carrying the `resource_metadata` URL for a
/// missing/invalid token, or `403` with `error="insufficient_scope"` when a
/// required scope is absent. Returns true (with `token` populated) when the
/// request may proceed; false when a failure response was written.
private bool guardAuth(scope HTTPServerRequest req, scope HTTPServerResponse res,
		StreamableHttpOptions opts, out TokenInfo token) @safe
{
	if (!opts.auth.enabled)
		return true;

	const failure = authorize(opts.auth, req.headers.get("Authorization", ""), token);
	if (failure == AuthFailure.none)
		return true;

	const metaUrl = resourceMetadataUrl(req, opts);
	res.headers["WWW-Authenticate"] = wwwAuthenticate(failure, metaUrl, opts.auth.requiredScope);
	if (failure == AuthFailure.insufficientScope)
	{
		res.statusCode = HTTPStatus.forbidden;
		res.writeBody("Forbidden: insufficient scope", "text/plain");
	}
	else
	{
		res.statusCode = HTTPStatus.unauthorized;
		res.writeBody("Unauthorized", "text/plain");
	}
	return false;
}

/// The absolute URL of this server's Protected Resource Metadata document. Built
/// from the request's scheme + Host so clients reach the same origin they called;
/// falls back to the configured `resource` origin when the Host header is absent.
private string resourceMetadataUrl(scope HTTPServerRequest req, StreamableHttpOptions opts) @safe
{
	import std.string : startsWith;

	const host = req.headers.get("Host", "");
	if (host.length)
	{
		const scheme = req.headers.get("X-Forwarded-Proto",
				isLoopbackHostname(stripPort(host)) ? "http" : "https");
		return scheme ~ "://" ~ host ~ ProtectedResourceMetadataPath;
	}
	// No Host header: derive the origin from the configured resource identifier.
	auto r = opts.auth.resource;
	if (r.length)
	{
		const sep = () @safe {
			import std.string : indexOf;

			return r.indexOf("://");
		}();
		if (sep >= 0)
		{
			import std.string : indexOf;

			auto rest = r[sep + 3 .. $];
			const slash = rest.indexOf('/');
			const origin = slash >= 0 ? r[0 .. sep + 3 + slash] : r;
			return origin ~ ProtectedResourceMetadataPath;
		}
	}
	return ProtectedResourceMetadataPath;
}

/// Decide how to answer an HTTP GET to the MCP endpoint
/// (basic/transports §Listening for Messages from the Server): the server "MUST
/// either return Content-Type: text/event-stream in response to this HTTP GET,
/// or else return HTTP 405 Method Not Allowed".
///
/// Returns true when the GET should open a standalone server->client SSE stream,
/// false when it must be answered with 405. The standalone stream is offered for
/// the stable revisions (2025-03-26 / 2025-06-18 / 2025-11-25); on the draft,
/// which drops the standalone GET stream in favour of POST-response SSE, GET ->
/// 405 is the correct answer.
bool getOpensSseStream(ProtocolVersion negotiated) @safe
{
	return !negotiated.isDraft;
}

unittest  // stable revisions open the GET SSE stream; the draft does not
{
	assert(getOpensSseStream(ProtocolVersion.v2025_11_25));
	assert(getOpensSseStream(ProtocolVersion.v2025_06_18));
	assert(getOpensSseStream(ProtocolVersion.v2025_03_26));
	assert(!getOpensSseStream(ProtocolVersion.draft));
}

/// Decide how to answer an HTTP DELETE to the MCP endpoint
/// (basic/transports §Session Management / §Backward Compatibility). The stable
/// revisions (2025-03-26 / 2025-06-18 / 2025-11-25) carry protocol-level sessions
/// a client tears down via DELETE + `Mcp-Session-Id`. The draft removed
/// protocol-level sessions ("Removal of protocol-level sessions"), so there is
/// nothing to terminate: a draft-negotiated server "SHOULD respond as follows:
/// HTTP GET or DELETE to the MCP endpoint: respond with 405 Method Not Allowed."
///
/// Returns true when DELETE should drive session termination (stable revisions),
/// false when it must be answered with 405 (the draft) — mirroring the version
/// gate `getOpensSseStream` already applies to GET.
bool deleteTerminatesSession(ProtocolVersion negotiated) @safe
{
	return !negotiated.isDraft;
}

unittest  // stable revisions terminate sessions on DELETE; the draft answers 405
{
	assert(deleteTerminatesSession(ProtocolVersion.v2025_11_25));
	assert(deleteTerminatesSession(ProtocolVersion.v2025_06_18));
	assert(deleteTerminatesSession(ProtocolVersion.v2025_03_26));
	assert(!deleteTerminatesSession(ProtocolVersion.draft));
}

/// The value of the `Allow` header a 405 Method Not Allowed response must carry
/// at the MCP endpoint. Per RFC 9110 §10.2.1 the `Allow` header MUST enumerate
/// the set of methods the resource actually supports. On the stable revisions
/// (2025-03-26 / 2025-06-18 / 2025-11-25) the single MCP endpoint "supports both
/// POST and GET methods" (basic/transports §Streamable HTTP) — the standalone
/// server->client SSE stream is mounted on GET (getOpensSseStream is true) — so a
/// 405 (e.g. to a DELETE the server does not honour) MUST advertise `GET, POST`.
/// On the draft the standalone GET stream and protocol-level DELETE are both
/// dropped, leaving POST as the only supported method, so the header is `POST`.
string allowedMethodsHeader(ProtocolVersion negotiated) @safe
{
	return getOpensSseStream(negotiated) ? "GET, POST" : "POST";
}

unittest  // 405 Allow header enumerates every supported method (RFC 9110 §10.2.1)
{
	// Stable revisions mount both GET (standalone SSE stream) and POST on the MCP
	// endpoint, so a 405 there MUST advertise both — not just POST.
	assert(allowedMethodsHeader(ProtocolVersion.v2025_11_25) == "GET, POST");
	assert(allowedMethodsHeader(ProtocolVersion.v2025_06_18) == "GET, POST");
	assert(allowedMethodsHeader(ProtocolVersion.v2025_03_26) == "GET, POST");
	// The draft drops the standalone GET stream and protocol-level DELETE, so POST
	// is the only supported method and the 405 advertises only POST.
	assert(allowedMethodsHeader(ProtocolVersion.draft) == "POST");
}

private void handleGet(McpServer server, ServerPushChannel push,
		SessionManager sessions, HTTPServerRequest req, HTTPServerResponse res) @safe
{
	// Per the transport: the server MUST either open a text/event-stream or
	// answer 405. The draft drops the standalone GET stream (server->client
	// traffic rides the POST-response SSE), so it keeps the 405 alternative.
	if (!getOpensSseStream(server.negotiatedVersion))
	{
		res.statusCode = HTTPStatus.methodNotAllowed;
		res.headers["Allow"] = "POST";
		res.writeBody("", "text/plain");
		return;
	}

	// Session Management (basic/transports §Session Management): the GET that
	// opens the standalone server->client stream is a "subsequent HTTP request",
	// so when sessions are enabled the client MUST present its Mcp-Session-Id.
	// Mirror the POST/DELETE branches: a missing header SHOULD be 400, an
	// unknown/terminated session MUST be 404 — never open the 200 stream without
	// a valid id.
	if (sessions !is null)
	{
		const sid = req.headers.get(SessionHeader, "");
		const status = sessionStatus(sessions, sid);
		if (status != 0)
		{
			res.statusCode = cast(HTTPStatus) status;
			res.writeBody(status == 400
					? "Missing Mcp-Session-Id header" : "Unknown or terminated session",
					"text/plain");
			return;
		}
	}

	// Open a long-lived SSE stream wired to the server-push channel, so the
	// server can deliver unsolicited notifications/requests outside any POST.
	import vibe.core.core : sleep;
	import core.time : seconds;

	res.contentType = "text/event-stream";
	// The standalone GET stream is offered only on the stable revisions
	// (getOpensSseStream gated above); the X-Accel-Buffering: no SHOULD is a
	// draft-only rule, so it is not emitted here.
	applySseStreamHeaders(res, false);

	const listenerId = push.addListener((string frame) @safe {
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frame);
			res.bodyWriter.flush();
		}();
	});
	// Drop the listener when the stream ends so the channel self-heals.
	scope (exit)
		push.removeListener(listenerId);

	// Hold the connection open, emitting an SSE comment heartbeat so a write
	// failure (client disconnect) is observed and the loop terminates.
	while (true)
	{
		sleep(15.seconds);
		try
			() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) ": ping\n\n");
			res.bodyWriter.flush();
		}();
		catch (Exception)
			break;
	}
}

/// Serve a draft `subscriptions/listen` request as a long-lived SSE notification
/// stream (draft basic/transports / basic/utilities/subscriptions): "subscriptions/
/// listen opens a long-lived notification stream from the server to the client ...
/// the stream stays open and delivers notifications until the client cancels it."
///
/// The request is first routed through `server.handle` so the server records the
/// opted-in change-notification filters. The response is then upgraded to
/// `text/event-stream`; the leading event is
/// `notifications/subscriptions/acknowledged` carrying the agreed-upon subset, and
/// the stream is registered as a listener on the server-push channel so the
/// existing `notify*` / `notifyResourceUpdated` APIs deliver opted-in change
/// notifications onto it. The connection is held open (with SSE comment
/// heartbeats) until the client disconnects.
private void handleListenStream(McpServer server, StreamCoordinator coord,
		Message msg, HTTPServerResponse res) @safe
{
	import vibe.core.core : sleep;
	import core.time : seconds;

	// Record the opted-in filters (route -> doSubscribeListen). The one-shot
	// JSON result is discarded: on this path the acknowledgement is delivered as
	// the first SSE event instead.
	server.handle(msg);

	res.contentType = "text/event-stream";
	// subscriptions/listen is a draft-only stream; emit the draft SHOULD header
	// X-Accel-Buffering: no alongside Cache-Control (basic/transports
	// §Receiving Messages).
	applySseStreamHeaders(res, true);

	auto push = server.serverPushChannel(coord);
	// The listen request's id becomes the stream's subscriptionId: every
	// notification delivered to this listener (including the leading
	// acknowledgement) is stamped with it in
	// `params._meta["io.modelcontextprotocol/subscriptionId"]` (draft
	// basic/utilities/subscriptions).
	const listenerId = push.addListener((string frame) @safe {
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frame);
			res.bodyWriter.flush();
		}();
	}, rpcIdString(msg.id), server.lastListenFilter());
	// Drop the listener when the stream ends so the channel self-heals.
	scope (exit)
		push.removeListener(listenerId);

	// First event: acknowledge with the agreed-upon subset, delivered only to
	// this stream (not broadcast to any other open listen stream). It is stamped
	// with the subscriptionId by the push channel, so it carries the listen id in
	// `_meta` like every subsequent notification on the stream.
	push.emitTo(listenerId,
			subscriptionsAcknowledgedNotification(server.acknowledgedListenSubset()));

	// Hold the connection open, emitting an SSE comment heartbeat so a write
	// failure (client disconnect) is observed and the loop terminates.
	while (true)
	{
		sleep(15.seconds);
		try
			() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) ": ping\n\n");
			res.bodyWriter.flush();
		}();
		catch (Exception)
			break;
	}
}

private void handlePost(McpServer server, StreamCoordinator coord,
		SessionManager sessions, TokenInfo token, HTTPServerRequest req, HTTPServerResponse res) @safe
{
	const payload = req.bodyReader.readAllUTF8();

	ParsedInput input;
	try
		input = parseAny(payload);
	catch (McpException e)
	{
		res.writeBody(makeErrorResponse(Json(null), e).toString(), "application/json");
		return;
	}
	catch (Exception e)
	{
		res.writeBody(makeErrorResponse(Json(null), parseError(e.msg))
				.toString(), "application/json");
		return;
	}

	// Session Management: when enabled, the very first request MUST be an
	// `initialize` (which receives a freshly-minted Mcp-Session-Id); every
	// later request MUST carry that id (400 when absent, 404 when unknown or
	// terminated). The id is also issued for the InitializeResult below.
	if (sessions !is null)
	{
		const isInit = !input.isBatch && input.messages.length == 1
			&& input.messages[0].method == "initialize";
		if (!isInit)
		{
			const sid = req.headers.get(SessionHeader, "");
			const status = sessionStatus(sessions, sid);
			if (status != 0)
			{
				res.statusCode = cast(HTTPStatus) status;
				res.writeBody(status == 400
						? "Missing Mcp-Session-Id header" : "Unknown or terminated session",
						"text/plain");
				return;
			}
		}
	}

	// JSON-RPC batching (an array body) was introduced in 2025-03-26 and removed
	// in every later revision: 2025-06-18 / 2025-11-25 / draft all require the
	// POST body to be a SINGLE request, notification, or response
	// (basic/transports §Sending Messages). The MCP-Protocol-Version header is
	// first validated by postProtocolVersionGate (so an invalid/unsupported
	// version on a batch is still rejected with 400), then the effective version
	// decides batch acceptance: only 2025-03-26 keeps the legacy batch path.
	if (input.isBatch)
	{
		if (auto verErr = postProtocolVersionGate(req.headers.get(HttpHeader.protocolVersion, "")))
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(Json(null), verErr).toString(), "application/json");
			return;
		}
		const ver = effectivePostVersion(req.headers.get(HttpHeader.protocolVersion,
				""), server.negotiatedVersion);
		if (!streamableBatchAllowed(ver))
		{
			// Single-message-only: reject the array body with -32600 on HTTP 400.
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(Json(null),
					invalidRequest("JSON-RPC batching is not supported on protocol version "
					~ ver.toWire ~ "; the POST body must be a single message"))
					.toString(), "application/json");
			return;
		}
		// 2025-03-26 back-compat: the non-streaming batch path (no in-flight
		// server->client traffic).
		const txt = server.handleRaw(payload);
		if (txt.length == 0)
		{
			res.statusCode = HTTPStatus.accepted;
			res.writeBody("", "text/plain");
		}
		else
			res.writeBody(txt, "application/json");
		return;
	}

	auto msg = input.messages[0];

	// Spec (2025-06-18 / 2025-11-25 Transports §Protocol Version Header): an
	// invalid or unsupported MCP-Protocol-Version header MUST be rejected with
	// 400 on EVERY POST to the MCP endpoint, including notification/response
	// bodies (which otherwise take the 202 path below). Run the gate before the
	// per-kind switch so all branches are covered. A notification/response error
	// body carries no id (basic/transports: "a JSON-RPC error response that has
	// no id"); a request error echoes the request id.
	if (auto verErr = postProtocolVersionGate(req.headers.get(HttpHeader.protocolVersion, "")))
	{
		const errId = (msg.kind == MessageKind.request) ? msg.id : Json(null);
		res.statusCode = HTTPStatus.badRequest;
		res.writeBody(makeErrorResponse(errId, verErr).toString(), "application/json");
		return;
	}

	final switch (msg.kind)
	{
	case MessageKind.response:
	case MessageKind.errorResponse:
		// A client's reply to a server->client request: route it to the waiter.
		coord.resolve(msg.id, msg.result, msg.error);
		res.statusCode = HTTPStatus.accepted;
		res.writeBody("", "text/plain");
		return;
	case MessageKind.notification:
		// Draft basic/transports Standard Request Headers: Mcp-Method is
		// REQUIRED for "All requests and notifications". A draft client POSTing
		// a notification (e.g. notifications/initialized, notifications/cancelled)
		// with a missing or mismatched Mcp-Method MUST be rejected with 400 and a
		// -32001 HeaderMismatch error. The error body carries no id (a
		// notification has none). Pre-draft versions skip this (header undefined).
		if (auto noteErr = validateDraftHeaders(req.headers.get(HttpHeader.protocolVersion,
				""), req.headers.get(HttpHeader.method, ""),
				req.headers.get(HttpHeader.name, ""), msg))
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(Json(null), noteErr).toString(), "application/json");
			return;
		}
		server.handle(msg);
		res.statusCode = HTTPStatus.accepted;
		res.writeBody("", "text/plain");
		return;
	case MessageKind.request:
		// Session Management: assign a session id on the InitializeResult so the
		// client can echo it on subsequent requests. Set before writing the body.
		if (sessions !is null
				&& msg.method == "initialize")
			res.headers[SessionHeader] = sessions.create();
		// The MCP-Protocol-Version header was already validated by
		// postProtocolVersionGate above (it gates every POST kind).
		// Draft: validate the standard request headers against the body.
		auto hdrErr = validateDraftHeaders(req.headers.get(HttpHeader.protocolVersion,
				""), req.headers.get(HttpHeader.method, ""),
				req.headers.get(HttpHeader.name, ""), msg);
		if (hdrErr !is null)
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(msg.id, hdrErr).toString(), "application/json");
			return;
		}
		// Draft x-mcp-header: validate Mcp-Param-* headers against the tool's
		// declared header parameters and the body arguments.
		if (msg.method == "tools/call" && tryDraft(req.headers.get(HttpHeader.protocolVersion, "")))
		{
			const tname = ("name" in msg.params && msg.params["name"].type == Json.Type.string) ? msg
				.params["name"].get!string : "";
			auto schema = server.toolInputSchema(tname);
			auto args = ("arguments" in msg.params) ? msg.params["arguments"] : Json.emptyObject;
			auto perr = validateParamHeaders(schema, args, (string h) => req.headers.get(h, ""));
			if (perr !is null)
			{
				res.statusCode = HTTPStatus.badRequest;
				res.writeBody(makeErrorResponse(msg.id, perr).toString(), "application/json");
				return;
			}
		}
		// Draft subscriptions/listen: the response is itself a long-lived SSE
		// stream that stays open and delivers change notifications until the
		// client closes it (draft basic/transports / basic/utilities/
		// subscriptions). Record the opted-in filters, open the stream, send the
		// acknowledgement as the first event, then hold it open — wired to the
		// server-push channel so notify*/notifyResourceUpdated reach it.
		const isDraftReq = tryDraft(req.headers.get(HttpHeader.protocolVersion, ""))
			|| tryDraft(RequestMeta.fromParams(msg.params).protocolVersion);
		if (opensListenStream(msg.method, isDraftReq))
		{
			handleListenStream(server, coord, msg, res);
			return;
		}
		// The effective version for this POST decides whether a server-initiated
		// SSE stream must lead with the 2025-11-25 priming event (event id + empty
		// data field; basic/transports §Sending Messages item 6).
		const effVersion = effectivePostVersion(req.headers.get(HttpHeader.protocolVersion,
				""), server.negotiatedVersion);
		auto ctx = new HttpStreamContext(res, coord, server.clientCapabilities,
				extractProgressToken(msg.params), token, isDraftReq, effVersion);
		auto resp = server.handle(msg, ctx);
		if (ctx.streaming)
			ctx.finishWith(resp.get);
		else
		{
			// Map reserved JSON-RPC errors onto their required HTTP statuses
			// (400 for unsupported-version/header-mismatch, draft 404 for
			// method-not-found); everything else rides on 200.
			auto j = resp.get;
			const isDraft = tryDraft(req.headers.get(HttpHeader.protocolVersion, ""))
				|| tryDraft(RequestMeta.fromParams(msg.params).protocolVersion);
			res.statusCode = httpStatusForResponse(j, isDraft);
			res.writeBody(j.toString(), "application/json");
		}
		return;
	}
}

/// Decide the HTTP status for a non-initialize request when session management is
/// enabled (basic/transports §Session Management):
///   - `0`   — the session id is present and active; proceed.
///   - `400` — no `Mcp-Session-Id` header was supplied ("Servers that require a
///             session ID SHOULD respond to requests without an Mcp-Session-Id
///             header (other than initialization) with HTTP 400 Bad Request").
///   - `404` — the id names an unknown or already-terminated session ("after
///             [termination] it MUST respond ... with HTTP 404 Not Found").
int sessionStatus(SessionManager sessions, string sessionId) @safe
{
	if (sessionId.length == 0)
		return 400;
	if (!sessions.isActive(sessionId))
		return 404;
	return 0;
}

unittest  // missing session id -> 400, unknown -> 404, active -> 0
{
	auto mgr = new SessionManager;
	const id = mgr.create();
	assert(sessionStatus(mgr, "") == 400);
	assert(sessionStatus(mgr, "bogus") == 404);
	assert(sessionStatus(mgr, id) == 0);
	mgr.terminate(id);
	assert(sessionStatus(mgr, id) == 404);
}

unittest  // the standalone GET SSE stream uses the same session gate as POST/DELETE
{
	// basic/transports §Session Management: a GET to open the standalone
	// server->client stream is a "subsequent HTTP request". With sessions
	// enabled the transport MUST gate it via sessionStatus — opening the 200
	// text/event-stream only for an active id, answering 400 when the header is
	// absent and 404 for an unknown/terminated session (mirroring the POST and
	// DELETE branches). Before the fix, handleGet took no SessionManager and so
	// always returned 200 regardless of the id.
	auto mgr = new SessionManager;
	const id = mgr.create();
	// absent header -> 400 (SHOULD): do not open the stream
	assert(sessionStatus(mgr, "") == 400);
	// unknown id -> 404 (MUST)
	assert(sessionStatus(mgr, "no-such-session") == 404);
	// active id -> 0: the GET may open the stream
	assert(sessionStatus(mgr, id) == 0);
	// after termination the same id MUST become 404, not a 200 stream
	mgr.terminate(id);
	assert(sessionStatus(mgr, id) == 404);
}

/// Map a JSON-RPC response to the HTTP status the Streamable HTTP transport must
/// surface. Successful results and ordinary application errors ride on `200`.
/// The draft reserves specific statuses so intermediaries — and clients probing
/// modern-vs-legacy servers — can act without parsing the body:
///   - `UnsupportedProtocolVersionError` (-32004) -> `400` (all modern versions),
///   - `HeaderMismatch` (-32001) -> `400`,
///   - `Method not found` (-32601) -> `404` on draft requests, which lets a client
///     tell a modern MCP endpoint apart from a legacy HTTP+SSE `404`. Pre-draft
///     versions keep the legacy JSON-RPC-error-over-`200` shape.
int httpStatusForResponse(Json resp, bool isDraft) @safe
{
	if ("error" !in resp || resp["error"].type != Json.Type.object)
		return 200;
	auto err = resp["error"];
	if ("code" !in err || err["code"].type != Json.Type.int_)
		return 200;
	const code = err["code"].get!int;
	if (code == ErrorCode.unsupportedProtocolVersion || code == ErrorCode.headerMismatch)
		return 400;
	if (isDraft && code == ErrorCode.methodNotFound)
		return 404;
	return 200;
}

/// Validate the draft Streamable HTTP request headers against the JSON-RPC body.
/// Returns a `HeaderMismatch` (-32001) exception on failure, or null when the
/// request is valid — or when the protocol version is pre-draft (older versions
/// did not define these headers, so they are not enforced).
McpException validateDraftHeaders(string protoHeader, string methodHeader,
		string nameHeader, Message msg) @safe
{
	ProtocolVersion pv;
	if (!tryParseVersion(protoHeader, pv) || !pv.isDraft)
		return null; // not a draft request: do not enforce draft headers

	if (methodHeader.length == 0)
		return new McpException(ErrorCode.headerMismatch, "Missing Mcp-Method header");
	if (methodHeader != msg.method)
		return new McpException(ErrorCode.headerMismatch,
				"Mcp-Method header '" ~ methodHeader
				~ "' does not match body method '" ~ msg.method ~ "'");

	// Header protocol version must match the body's _meta protocol version.
	auto bodyMeta = RequestMeta.fromParams(msg.params);
	if (bodyMeta.protocolVersion.length && bodyMeta.protocolVersion != protoHeader)
		return new McpException(ErrorCode.headerMismatch,
				"MCP-Protocol-Version header does not match body _meta");

	// Mcp-Name mirrors params.name (tools/call, prompts/get) or params.uri
	// (resources/read).
	string bodyName;
	switch (msg.method)
	{
	case "tools/call":
	case "prompts/get":
		if ("name" in msg.params && msg.params["name"].type == Json.Type.string)
			bodyName = msg.params["name"].get!string;
		break;
	case "resources/read":
		if ("uri" in msg.params && msg.params["uri"].type == Json.Type.string)
			bodyName = msg.params["uri"].get!string;
		break;
	default:
		return null; // no Mcp-Name requirement for other methods
	}
	if (nameHeader.length == 0)
		return new McpException(ErrorCode.headerMismatch, "Missing Mcp-Name header");
	if (nameHeader != bodyName)
		return new McpException(ErrorCode.headerMismatch,
				"Mcp-Name header '" ~ nameHeader ~ "' does not match body value '" ~ bodyName ~ "'");
	return null;
}

/// Validate the HTTP `MCP-Protocol-Version` header for a request. Per the
/// 2025-06-18 / 2025-11-25 transport ("Protocol Version Header"): if the header
/// is present but carries an invalid or unsupported version, the server MUST
/// respond with `400 Bad Request`. Returns an `UnsupportedProtocolVersionError`
/// (-32004, which the transport maps to HTTP 400) in that case, else null.
///
/// An absent header is permitted: older clients omit it, and the request then
/// proceeds under the previously negotiated version.
McpException validateProtocolVersionHeader(string protoHeader) @safe
{
	if (protoHeader.length == 0)
		return null; // header optional; fall back to negotiated version
	ProtocolVersion pv;
	if (tryParseVersion(protoHeader, pv))
		return null; // a known, supported version
	Json data = Json.emptyObject;
	Json supported = Json.emptyArray;
	foreach (v; supportedVersions)
		supported ~= Json(v.toWire);
	data["supported"] = supported;
	data["requested"] = Json(protoHeader);
	return new McpException(ErrorCode.unsupportedProtocolVersion,
			"Unsupported MCP-Protocol-Version header: " ~ protoHeader, data);
}

/// The transport-level MCP-Protocol-Version check that gates EVERY POST to the
/// MCP endpoint, irrespective of whether the body is a request, notification, or
/// response. basic/transports §Protocol Version Header (2025-06-18 /
/// 2025-11-25): "If the server receives a request with an invalid or unsupported
/// MCP-Protocol-Version, it MUST respond with 400 Bad Request." Returns the
/// rejecting McpException (mapped to HTTP 400) or null when the header is absent
/// or names a supported version. This is just `validateProtocolVersionHeader`,
/// named to make explicit that it runs before the per-kind routing switch.
McpException postProtocolVersionGate(string protoHeader) @safe
{
	return validateProtocolVersionHeader(protoHeader);
}

/// Whether a `Host` header value (e.g. "127.0.0.1:3000") is localhost or listed.
package bool hostAllowed(string host, const string[] extra) @safe
{
	import std.algorithm : canFind;

	if (extra.canFind(host))
		return true;
	return isLoopbackHostname(stripPort(host));
}

/// Whether an `Origin` header value (e.g. "http://localhost:3000") is localhost
/// or listed.
package bool originAllowed(string origin, const string[] extra) @safe
{
	import std.algorithm : canFind;
	import std.string : indexOf;

	if (extra.canFind(origin))
		return true;

	// Strip the scheme, then the path, then the port to isolate the hostname.
	auto rest = origin;
	const sep = rest.indexOf("://");
	if (sep >= 0)
		rest = rest[sep + 3 .. $];
	const slash = rest.indexOf('/');
	if (slash >= 0)
		rest = rest[0 .. slash];
	return isLoopbackHostname(stripPort(rest));
}

private string stripPort(string hostport) @safe
{
	import std.string : lastIndexOf;

	// IPv6 literal in brackets: [::1]:port
	if (hostport.length && hostport[0] == '[')
	{
		import std.string : indexOf;

		const close = hostport.indexOf(']');
		if (close >= 0)
			return hostport[1 .. close];
	}
	const colon = hostport.lastIndexOf(':');
	if (colon >= 0)
		return hostport[0 .. colon];
	return hostport;
}

private bool isLoopbackHostname(string h) @safe
{
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

/// Start a standalone Streamable HTTP server for `server` on `port` and run the
/// vibe.d event loop. Blocks until the application exits.
void runStreamableHttp(McpServer server, ushort port,
		StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
	import vibe.core.core : runEventLoop, lowerPrivileges;

	auto router = new URLRouter;
	mountMcp(router, server, opts);

	auto settings = new HTTPServerSettings;
	settings.port = port;
	settings.bindAddresses = opts.bindAddresses;
	auto listener = listenHTTP(settings, router);
	scope (exit)
		listener.stopListening();

	lowerPrivileges();
	runEventLoop();
}

unittest  // localhost hosts are accepted, foreign hosts rejected
{
	assert(hostAllowed("127.0.0.1:3000", []));
	assert(hostAllowed("localhost", []));
	assert(hostAllowed("[::1]:8080", []));
	assert(!hostAllowed("evil.example.com", []));
	assert(hostAllowed("myhost", ["myhost"]));
}

unittest  // localhost origins are accepted, foreign origins rejected
{
	assert(originAllowed("http://localhost:3000", []));
	assert(originAllowed("https://127.0.0.1", []));
	assert(!originAllowed("http://evil.example.com", []));
	assert(originAllowed("http://app.example.com", ["http://app.example.com"]));
}

version (unittest)
{
	private Message draftMsg(string method, Json params) @safe
	{
		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = "2026-07-28";
		params["_meta"] = meta;
		return Message(makeRequest(Json(1), method, params));
	}

	private Message draftNote(string method, Json params) @safe
	{
		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = "2026-07-28";
		params["_meta"] = meta;
		return Message(makeNotification(method, params));
	}
}

unittest  // pre-draft requests skip draft header enforcement
{
	auto m = Message(makeRequest(Json(1), "tools/list", Json.emptyObject));
	// protocol header empty / older -> no enforcement
	assert(validateDraftHeaders("", "", "", m) is null);
	assert(validateDraftHeaders("2025-11-25", "", "", m) is null);
}

unittest  // draft request missing Mcp-Method is a header mismatch
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "", "", m);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft request with mismatched Mcp-Method fails
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "tools/call", "", m);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft tools/list with correct headers passes
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	assert(validateDraftHeaders("2026-07-28", "tools/list", "", m) is null);
}

unittest  // draft tools/call requires matching Mcp-Name
{
	Json p = Json.emptyObject;
	p["name"] = "add";
	auto m = draftMsg("tools/call", p);
	assert(validateDraftHeaders("2026-07-28", "tools/call", "add", m) is null);
	auto e = validateDraftHeaders("2026-07-28", "tools/call", "wrong", m);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
	auto e2 = validateDraftHeaders("2026-07-28", "tools/call", "", m);
	assert(e2 !is null); // missing name
}

unittest  // draft resources/read mirrors uri into Mcp-Name
{
	Json p = Json.emptyObject;
	p["uri"] = "test://x";
	auto m = draftMsg("resources/read", p);
	assert(validateDraftHeaders("2026-07-28", "resources/read", "test://x", m) is null);
	assert(validateDraftHeaders("2026-07-28", "resources/read", "test://y", m) !is null);
}

unittest  // draft notification with correct Mcp-Method passes (no Mcp-Name required)
{
	// draft basic/transports Standard Request Headers: Mcp-Method is REQUIRED
	// for "All requests and notifications"; Mcp-Name applies only to
	// tools/call, resources/read, prompts/get requests.
	auto m = draftNote("notifications/initialized", Json.emptyObject);
	assert(validateDraftHeaders("2026-07-28", "notifications/initialized", "", m) is null);
}

unittest  // draft notification missing Mcp-Method is a header mismatch
{
	auto m = draftNote("notifications/initialized", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "", "", m);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft notification with mismatched Mcp-Method fails
{
	auto m = draftNote("notifications/cancelled", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "notifications/initialized", "", m);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // pre-draft notification skips draft header enforcement
{
	auto m = Message(makeNotification("notifications/initialized", Json.emptyObject));
	assert(validateDraftHeaders("2025-11-25", "", "", m) is null);
}

unittest  // absent MCP-Protocol-Version header is permitted (falls back to negotiated)
{
	assert(validateProtocolVersionHeader("") is null);
}

unittest  // a supported stable MCP-Protocol-Version header passes
{
	assert(validateProtocolVersionHeader("2025-06-18") is null);
	assert(validateProtocolVersionHeader("2025-11-25") is null);
	assert(validateProtocolVersionHeader("2024-11-05") is null);
}

unittest  // the draft MCP-Protocol-Version header passes
{
	assert(validateProtocolVersionHeader("2026-07-28") is null);
	assert(validateProtocolVersionHeader("draft") is null);
}

unittest  // an unsupported/invalid MCP-Protocol-Version header is rejected with -32004 (HTTP 400)
{
	auto e = validateProtocolVersionHeader("1.0.0");
	assert(e !is null);
	assert(e.code == ErrorCode.unsupportedProtocolVersion);
	// maps to HTTP 400 in the transport
	auto j = makeErrorResponse(Json(1), e);
	assert(httpStatusForResponse(j, false) == 400);
	assert(httpStatusForResponse(j, true) == 400);
	// data carries the supported list and the rejected value
	assert(e.data["requested"].get!string == "1.0.0");
	assert(e.data["supported"].length == supportedVersions.length);
}

unittest  // a garbage MCP-Protocol-Version header is rejected
{
	assert(validateProtocolVersionHeader("not-a-version") !is null);
}

unittest  // the version gate applies to EVERY POST kind, not just requests
{
	// basic/transports §Protocol Version Header (2025-06-18 / 2025-11-25): a
	// POST carrying an invalid/unsupported MCP-Protocol-Version MUST be rejected
	// with 400 regardless of whether the body is a request, notification, or
	// response. Previously the gate ran only on the request branch, so a
	// notification/response POST with a bad header was wrongly accepted (202).
	auto bad = postProtocolVersionGate("1.0.0");
	assert(bad !is null, "bad header must be rejected for all POST kinds");
	assert(bad.code == ErrorCode.unsupportedProtocolVersion);
	auto j = makeErrorResponse(Json(null), bad);
	assert(httpStatusForResponse(j, false) == 400);
	// a supported / absent header is fine for every kind
	assert(postProtocolVersionGate("2025-11-25") is null);
	assert(postProtocolVersionGate("") is null);
}

/// True if the protocol-version header denotes a draft+ request.
private bool tryDraft(string protoHeader) @safe
{
	ProtocolVersion pv;
	return tryParseVersion(protoHeader, pv) && pv.isDraft;
}

/// The effective protocol version for a POST that decides whether a JSON-RPC
/// array body (a batch) may be accepted. The header wins when present and
/// parseable; otherwise we fall back to the version negotiated at `initialize`
/// (basic/transports §Protocol Version Header: "if the server does not receive
/// an MCP-Protocol-Version header ... it SHOULD assume protocol version
/// 2025-03-26", but a negotiated session gives us a sharper answer).
private ProtocolVersion effectivePostVersion(string protoHeader, ProtocolVersion negotiated) @safe
{
	ProtocolVersion pv;
	return tryParseVersion(protoHeader, pv) ? pv : negotiated;
}

/// Whether a JSON-RPC batch (array body) is permitted on the Streamable HTTP
/// POST endpoint for the given effective protocol version.
///
/// JSON-RPC batching was introduced in 2025-03-26 and REMOVED thereafter:
/// 2025-06-18 / 2025-11-25 / draft all state "The body of the POST request MUST
/// be a single JSON-RPC request, notification, or response" (basic/transports
/// §Sending Messages), and their `JSONRPCMessage` schema no longer includes the
/// batch union members. So batches are accepted ONLY for 2025-03-26 back-compat;
/// every newer version MUST reject an array body with 400 Bad Request.
bool streamableBatchAllowed(ProtocolVersion v) @safe pure nothrow
{
	return v == ProtocolVersion.v2025_03_26;
}

unittest  // batches are accepted only on 2025-03-26, rejected on every newer version
{
	// basic/transports §Sending Messages: the POST body MUST be a single
	// message on 2025-06-18 and later (JSON-RPC batching was removed after
	// 2025-03-26).
	assert(streamableBatchAllowed(ProtocolVersion.v2025_03_26));
	assert(!streamableBatchAllowed(ProtocolVersion.v2025_06_18));
	assert(!streamableBatchAllowed(ProtocolVersion.v2025_11_25));
	assert(!streamableBatchAllowed(ProtocolVersion.draft));
}

unittest  // a 2024-11-05 fallback (no batching in HTTP+SSE era) also rejects arrays
{
	assert(!streamableBatchAllowed(ProtocolVersion.v2024_11_05));
}

unittest  // effective version: header present and parseable wins over negotiated
{
	assert(effectivePostVersion("2025-06-18",
			ProtocolVersion.v2025_03_26) == ProtocolVersion.v2025_06_18);
}

unittest  // effective version: absent/unparseable header falls back to negotiated
{
	assert(effectivePostVersion("", ProtocolVersion.v2025_11_25) == ProtocolVersion.v2025_11_25);
	assert(effectivePostVersion("garbage",
			ProtocolVersion.v2025_11_25) == ProtocolVersion.v2025_11_25);
}

unittest  // a batch on a modern version is rejected with an invalidRequest 400
{
	// The transport must surface a -32600 invalidRequest on HTTP 400 (not the
	// old "errors-ride-on-200" handleRaw path) when an array body arrives on a
	// version that forbids batching.
	auto v = effectivePostVersion("2025-11-25", ProtocolVersion.v2025_11_25);
	assert(!streamableBatchAllowed(v));
	auto e = invalidRequest(
			"JSON-RPC batching is not supported on protocol version 2025-06-18 and later");
	assert(e.code == ErrorCode.invalidRequest);
	auto j = makeErrorResponse(Json(null), e);
	assert(j["error"]["code"].get!int == ErrorCode.invalidRequest);
}

/// Decide whether a request must be answered with a long-lived `text/event-stream`
/// notification stream rather than the ordinary one-shot JSON response
/// (draft basic/transports / basic/utilities/subscriptions). Only the draft
/// `subscriptions/listen` request takes this path: "The server's response is
/// itself an SSE stream that stays open and delivers the change notifications."
/// Pre-draft versions never defined `subscriptions/listen`, so they answer
/// normally.
bool opensListenStream(string method, bool isDraft) @safe
{
	return isDraft && method == "subscriptions/listen";
}

unittest  // only a draft subscriptions/listen opens the long-lived stream
{
	assert(opensListenStream("subscriptions/listen", true));
	assert(!opensListenStream("subscriptions/listen", false));
	assert(!opensListenStream("tools/list", true));
	assert(!opensListenStream("initialize", true));
}

/// Build the leading event the transport sends when it opens a
/// `subscriptions/listen` stream: a `notifications/subscriptions/acknowledged`
/// notification carrying the agreed-upon subset of change-notification types the
/// server will deliver on the stream (draft basic/utilities/subscriptions). The
/// `subset` is what `McpServer.acknowledgedListenSubset` reported.
///
/// Per the draft spec the agreed subset is nested under `params.notifications`
/// (mirroring the `notifications` filter the client sent in the listen request);
/// the matching `io.modelcontextprotocol/subscriptionId` is stamped into
/// `params._meta` by the push channel when the event is delivered to the stream.
Json subscriptionsAcknowledgedNotification(Json subset) @safe
{
	Json params = Json.emptyObject;
	params["notifications"] = subset;
	return makeNotification("notifications/subscriptions/acknowledged", params);
}

unittest  // the acknowledgement nests the agreed subset under params.notifications
{
	Json subset = Json.emptyObject;
	subset["toolsListChanged"] = true;
	auto n = subscriptionsAcknowledgedNotification(subset);
	assert(n["method"].get!string == "notifications/subscriptions/acknowledged");
	// draft basic/utilities/subscriptions: the agreed subset is wrapped under
	// `params.notifications`, not placed at the top level of params.
	assert(n["params"]["notifications"]["toolsListChanged"].get!bool);
	assert("toolsListChanged" !in n["params"]);
	// It is a notification: no id.
	assert("id" !in n);
}

unittest  // an empty agreed subset still produces an empty params.notifications object
{
	auto n = subscriptionsAcknowledgedNotification(Json.emptyObject);
	assert(n["params"]["notifications"].type == Json.Type.object);
	assert(n["params"]["notifications"].length == 0);
}

/// Render a primitive JSON value as its `Mcp-Param-*` header string. Per the
/// draft `x-mcp-header` constraints, only `integer`, `string`, and `boolean` are
/// permitted; `number` (float) and any other type are NOT mirror-able and are
/// reported via `ok = false` so the caller can reject the request rather than
/// silently stringify them.
private string jsonScalarToString(Json v, out bool ok) @safe
{
	import std.conv : to;

	ok = true;
	switch (v.type)
	{
	case Json.Type.string:
		return v.get!string;
	case Json.Type.int_:
		return v.get!long
			.to!string;
	case Json.Type.bool_:
		return v.get!bool ? "true" : "false";
	default:
		// number/float, object, array, null — not a permitted x-mcp-header type.
		ok = false;
		return "";
	}
}

/// Resolve the value at `path` (a sequence of property keys) within `args`,
/// returning the leaf `Json` and whether every step was present.
private Json resolveArgPath(Json args, const(string)[] path, out bool present) @safe
{
	Json cur = args;
	foreach (key; path)
	{
		if (cur.type != Json.Type.object || key !in cur)
		{
			present = false;
			return Json(null);
		}
		cur = cur[key];
	}
	present = cur.type != Json.Type.null_ && cur.type != Json.Type.undefined;
	return cur;
}

/// Validate draft `x-mcp-header` mirroring: every parameter annotated with
/// `x-mcp-header` (at any nesting depth) whose value is present in `args` MUST
/// have a matching (decoded) `Mcp-Param-*` header; absent parameters MUST NOT
/// carry the header. The annotation set itself is also validated against the
/// draft value constraints (non-empty, HTTP token syntax, no CR/LF, primitive
/// types only with `number` forbidden, case-insensitive uniqueness). Returns a
/// `HeaderMismatch` exception on violation, else null.
McpException validateParamHeaders(Json inputSchema, Json args,
		scope string delegate(string) @safe headerGet) @safe
{
	import std.array : join;

	// Reject malformed x-mcp-header annotations up front per the draft.
	auto schemaErr = validateInputSchemaHeaders(inputSchema);
	if (schemaErr !is null)
		return new McpException(ErrorCode.headerMismatch, schemaErr);

	foreach (ph; paramHeaders(inputSchema))
	{
		const headerName = ph.header;
		const hv = headerGet(headerName);
		bool present;
		const leaf = resolveArgPath(args, ph.path, present);
		const pathStr = ph.path.join(".");
		if (!present)
		{
			if (hv.length)
				return new McpException(ErrorCode.headerMismatch,
						"Header " ~ headerName ~ " present but parameter '" ~ pathStr ~ "' absent");
			continue;
		}
		bool ok;
		const expected = jsonScalarToString(leaf, ok);
		if (!ok)
			return new McpException(ErrorCode.headerMismatch,
					"Parameter '" ~ pathStr ~ "' for header " ~ headerName
					~ " is not a permitted x-mcp-header type (integer/string/boolean)");
		if (hv.length == 0)
			return new McpException(ErrorCode.headerMismatch,
					"Missing required header " ~ headerName ~ " for parameter '" ~ pathStr ~ "'");
		if (decodeHeaderValue(hv) != expected)
			return new McpException(ErrorCode.headerMismatch,
					"Header " ~ headerName ~ " does not match parameter '" ~ pathStr ~ "'");
	}
	return null;
}

version (unittest)
{
	private Json schemaWithHeaderParam() @safe
	{
		Json schema = Json.emptyObject;
		schema["type"] = "object";
		Json props = Json.emptyObject;
		props["region"] = Json([
			"type": Json("string"),
			"x-mcp-header": Json("Region")
		]);
		props["query"] = Json(["type": Json("string")]);
		schema["properties"] = props;
		return schema;
	}
}

unittest  // x-mcp-header: matching header passes
{
	auto schema = schemaWithHeaderParam();
	Json args = Json(["region": Json("us-west1"), "query": Json("SELECT 1")]);
	auto e = validateParamHeaders(schema, args,
			(string h) => h == "Mcp-Param-Region" ? "us-west1" : "");
	assert(e is null);
}

unittest  // x-mcp-header: mismatched header is a HeaderMismatch
{
	auto schema = schemaWithHeaderParam();
	Json args = Json(["region": Json("us-west1")]);
	auto e = validateParamHeaders(schema, args, (string h) => "us-east1");
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: present param but missing header fails
{
	auto schema = schemaWithHeaderParam();
	Json args = Json(["region": Json("us-west1")]);
	auto e = validateParamHeaders(schema, args, (string h) => "");
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: non-ASCII value matched via base64-encoded header
{
	import mcp.protocol.draft : encodeHeaderValue;

	auto schema = schemaWithHeaderParam();
	Json args = Json(["region": Json("Zürich")]);
	const enc = encodeHeaderValue("Zürich");
	auto e = validateParamHeaders(schema, args, (string h) => h == "Mcp-Param-Region" ? enc : "");
	assert(e is null);
}

unittest  // x-mcp-header: nested object property is validated against header (any depth)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nestedProps = Json.emptyObject;
	nestedProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = nestedProps;
	Json props = Json.emptyObject;
	props["filters"] = nested;
	schema["properties"] = props;

	Json args = Json(["filters": Json(["region": Json("us-west1")])]);
	// matching nested header passes
	auto ok = validateParamHeaders(schema, args,
			(string h) => h == "Mcp-Param-Region" ? "us-west1" : "");
	assert(ok is null);
	// mismatched nested header fails
	auto bad = validateParamHeaders(schema, args, (string h) => "eu-west1");
	assert(bad !is null && bad.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: number-typed annotation is rejected as a malformed schema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	schema["properties"] = props;
	Json args = Json(["amount": Json(5)]);
	auto e = validateParamHeaders(schema, args, (string h) => "5");
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: duplicate (case-insensitive) values rejected as malformed schema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["a"] = Json(["type": Json("string"), "x-mcp-header": Json("Region")]);
	props["b"] = Json(["type": Json("string"), "x-mcp-header": Json("region")]);
	schema["properties"] = props;
	Json args = Json(["a": Json("x"), "b": Json("y")]);
	auto e = validateParamHeaders(schema, args, (string h) => "");
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: CR/LF injection in annotation value rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Reg\r\nion")
	]);
	schema["properties"] = props;
	Json args = Json(["region": Json("us-west1")]);
	auto e = validateParamHeaders(schema, args, (string h) => "");
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

version (unittest)
{
	private Json errResponse(int code) @safe
	{
		Json r = Json.emptyObject;
		r["jsonrpc"] = "2.0";
		r["id"] = 1;
		Json err = Json.emptyObject;
		err["code"] = code;
		err["message"] = "x";
		r["error"] = err;
		return r;
	}
}

unittest  // a successful (non-error) response always rides on HTTP 200
{
	Json ok = Json.emptyObject;
	ok["jsonrpc"] = "2.0";
	ok["id"] = 1;
	ok["result"] = Json.emptyObject;
	assert(httpStatusForResponse(ok, true) == 200);
	assert(httpStatusForResponse(ok, false) == 200);
}

unittest  // UnsupportedProtocolVersionError maps to HTTP 400 on any modern version
{
	auto r = errResponse(ErrorCode.unsupportedProtocolVersion);
	assert(httpStatusForResponse(r, true) == 400);
	assert(httpStatusForResponse(r, false) == 400);
}

unittest  // HeaderMismatch maps to HTTP 400
{
	auto r = errResponse(ErrorCode.headerMismatch);
	assert(httpStatusForResponse(r, true) == 400);
}

unittest  // draft Method-not-found maps to HTTP 404 (distinguishes modern endpoint from legacy)
{
	auto r = errResponse(ErrorCode.methodNotFound);
	assert(httpStatusForResponse(r, true) == 404);
}

unittest  // pre-draft Method-not-found stays on HTTP 200 (legacy JSON-RPC-over-200 shape)
{
	auto r = errResponse(ErrorCode.methodNotFound);
	assert(httpStatusForResponse(r, false) == 200);
}

unittest  // ordinary application errors (e.g. invalidParams) ride on HTTP 200
{
	auto r = errResponse(ErrorCode.invalidParams);
	assert(httpStatusForResponse(r, true) == 200);
	assert(httpStatusForResponse(r, false) == 200);
}

unittest  // draft subscriptions/listen: ack first, then opted-in change notifications flow
{
	import mcp.transport.sse_context : StreamCoordinator, ServerPushChannel;
	import mcp.protocol.draft : MetaKey;
	import std.algorithm : canFind;

	auto server = new McpServer("t", "1");

	// Drive the server onto the draft via a draft subscriptions/listen request,
	// mirroring what handleListenStream does: record the opted-in filters.
	Json listenParams = Json.emptyObject;
	listenParams["toolsListChanged"] = true;
	auto m = draftMsg("subscriptions/listen", listenParams);
	server.handle(m);
	assert(server.listensFor("toolsListChanged"));
	assert(!server.listensFor("resourcesListChanged"));

	// The listen stream registers as a push-channel listener (carrying the listen
	// request's id as the stream's subscriptionId) and receives the ack.
	auto coord = new StreamCoordinator;
	auto push = server.serverPushChannel(coord);
	string[] frames;
	const lid = push.addListener((string f) @safe { frames ~= f; }, rpcIdString(m.id));
	push.emitTo(lid, subscriptionsAcknowledgedNotification(server.acknowledgedListenSubset()));
	assert(frames.length == 1);
	assert(frames[0].canFind("notifications/subscriptions/acknowledged"));
	// The agreed subset is nested under params.notifications (draft spec shape).
	assert(frames[0].canFind("\"notifications\""));
	assert(frames[0].canFind("toolsListChanged"));
	// The ack is the FIRST message and carries the subscriptionId (the listen id).
	assert(frames[0].canFind(cast(string) MetaKey.subscriptionId));
	assert(frames[0].canFind(rpcIdString(m.id)));

	// An opted-in change notification is delivered onto the open stream, also
	// stamped with the subscriptionId.
	assert(server.notifyToolsListChanged() == 1);
	assert(frames.length == 2);
	assert(frames[1].canFind("notifications/tools/list_changed"));
	assert(frames[1].canFind(cast(string) MetaKey.subscriptionId));
	assert(frames[1].canFind(rpcIdString(m.id)));

	// A change type the client did NOT opt into is suppressed (no new frame).
	server.enableResourcesListChanged();
	assert(server.notifyResourcesListChanged() == 0);
	assert(frames.length == 2);
}
