module mcp.transport.streamable_http;

import vibe.http.server;
import vibe.http.router : URLRouter;
import vibe.stream.operations : readAllUTF8;
import vibe.data.json : Json;
import std.typecons : Nullable;

import mcp.server.server;
import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.modern;
import mcp.protocol.mrtr;
import mcp.protocol.events;
import mcp.transport.sse_context;
import mcp.transport.session;
import mcp.auth.resource_server;
import mcp.server.context : RequestContext, BaseRequestContext, ConnectionScoped;
import mcp.server.connection : ConnectionState;
import mcp.server.push : ListenFilter;
import mcp.protocol.capabilities : ClientCapabilities;

/// The HTTP header carrying the session id (basic/transports §Session Management).
enum SessionHeader = "Mcp-Session-Id";

/// Configuration for the Streamable HTTP server transport.
struct StreamableHttpOptions
{
	ushort port = 8080; /// the TCP port to listen on
	string path = "/mcp"; /// the single MCP endpoint path
	string[] bindAddresses = ["127.0.0.1"]; /// addresses to bind

	/// DNS-rebinding protection: reject requests whose Host/Origin is not a
	/// recognized localhost value (or in the explicit allow-lists below). On by
	/// default per the MCP transport security guidance; disable when fronting
	/// the server with a trusted reverse proxy.
	bool validateOrigin = true;
	string[] allowedHosts = []; /// extra Host header values to accept
	string[] allowedOrigins = []; /// extra Origin header values to accept

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

	/// Reconnect-delay hint (milliseconds) for the standalone server->client SSE
	/// stream on the 2025-11-25 revision. When non-zero, the GET stream emits a
	/// standard SSE `retry:` event right after opening, so that if the server
	/// later closes the connection without terminating the stream (e.g. to avoid
	/// holding a long-lived socket), the client already knows how long to wait
	/// before reconnecting (basic/transports §Sending Messages item 6 /
	/// §Listening for Messages item 4: "it SHOULD send an SSE event with a
	/// standard `retry` field before closing the connection. The client MUST
	/// respect the `retry` field"). This is a 2025-11-25-only SHOULD: it is built
	/// on the connection/stream split and Last-Event-ID reconnect that only that
	/// revision defines, so it never alters 2025-06-18 / 2025-03-26 / 2024-11-05
	/// or draft wire output. When zero (the default) no `retry:` hint is sent.
	uint reconnectDelayMs = 0;

	/// Opt-in backwards compatibility with the deprecated 2024-11-05 HTTP+SSE
	/// two-endpoint transport (basic/transports §HTTP with SSE; and the
	/// 2025-06-18 / 2025-11-25 / draft §Backwards Compatibility guidance:
	/// "Servers wanting to support older clients should: Continue to host both the
	/// SSE and POST endpoints of the old transport, alongside the new MCP
	/// endpoint"). This is a SHOULD, so it is off by default. When enabled,
	/// `mountMcp` ALSO mounts the two legacy endpoints alongside the modern MCP
	/// endpoint:
	///   - GET `legacySsePath`: opens a `text/event-stream`, immediately emits an
	///     `endpoint` event whose data is `legacyMessagePath` (the URI the client
	///     must POST to), then holds the stream open delivering server messages as
	///     SSE `message` events;
	///   - POST `legacyMessagePath`: accepts a single JSON-RPC message, processes
	///     it, replies `202 Accepted` with no body, and pushes any JSON-RPC
	///     response back onto the open GET stream as a `message` event.
	/// A 2024-11-05-only client can then negotiate the legacy transport against a D
	/// MCP server. The modern Streamable HTTP endpoint is unchanged.
	bool legacyHttpSse = false;
	string legacySsePath = "/sse"; /// legacy GET SSE endpoint path
	string legacyMessagePath = "/message"; /// legacy POST message endpoint path

	/// Emit one Apache-combined-format access-log line per request
	/// (`%h - %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"`: client IP,
	/// authenticated user, timestamp, request line, status, response bytes,
	/// Referer and User-Agent). Off by default: the transport stays silent so it
	/// imposes no logging — or PII capture (client IPs, user agents) — on the host
	/// process. Lines are written through vibe.core.log to the console, unless
	/// `accessLogFile` directs them to a file instead.
	bool accessLog = false;
	/// When `accessLog` is enabled, write the access-log lines to this file path
	/// instead of the console. Ignored unless `accessLog` is set.
	string accessLogFile = "";
}

/// The well-known path (RFC 9728 §3) at which a protected resource server
/// publishes its OAuth 2.0 Protected Resource Metadata document.
enum ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource";

/// Validate that an auth-enabled `ResourceServerConfig` can publish a
/// spec-compliant Protected Resource Metadata document before the transport
/// starts serving it. basic/authorization §Authorization Server Location (all
/// of 2025-06-18 / 2025-11-25 / draft) makes RFC 9728 a MUST: "The Protected
/// Resource Metadata document returned by the MCP server MUST include the
/// `authorization_servers` field containing at least one authorization server."
/// An operator who sets `auth.validator` but forgets `auth.authorizationServers`
/// would otherwise publish `"authorization_servers": []`, a silent MUST
/// violation. We fail loudly here (at mount time) rather than serve it.
///
/// Throws: `Exception` when `cfg.enabled` and `cfg.authorizationServers` is empty.
void validateAuthConfig(ResourceServerConfig cfg) @safe
{
	if (cfg.enabled && cfg.authorizationServers.length == 0)
		throw new Exception("ResourceServerConfig enables auth but has no authorizationServers; "
				~ "RFC 9728 / basic/authorization §Authorization Server Location requires the "
				~ "published Protected Resource Metadata document to list at least one "
				~ "authorization server. Set auth.authorizationServers (or use an IdP preset "
				~ "that pins an issuer).");
}

unittest  // an auth-enabled config with no authorizationServers is rejected at mount
{
	import std.exception : assertThrown;

	ResourceServerConfig cfg;
	cfg.validator = (string t) => TokenInfo.invalid();
	cfg.resource = "https://mcp.example.com/mcp";
	// authorizationServers left empty -> spec-violating PRM document.
	assertThrown!Exception(validateAuthConfig(cfg));
}

unittest  // an auth-enabled config with at least one authorizationServer passes
{
	import std.exception : assertNotThrown;

	ResourceServerConfig cfg;
	cfg.validator = (string t) => TokenInfo.invalid();
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.authorizationServers = ["https://auth.example.com"];
	assertNotThrown!Exception(validateAuthConfig(cfg));
}

unittest  // a disabled (no-validator) config is never rejected, even with no AS
{
	import std.exception : assertNotThrown;

	ResourceServerConfig cfg;
	// validator null -> auth off -> no PRM document is published, nothing to validate.
	assertNotThrown!Exception(validateAuthConfig(cfg));
}

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
	// Session minting is derived from the server's mode: a `stateful`
	// server mints/tracks an `Mcp-Session-Id`; a `stateless` server never does.
	auto sessions = server.mode == ServerMode.stateful ? new SessionManager : null;

	// This mount owns a single fallback `ConnectionState`, which the server core
	// threads through dispatch and reads back for the notify/push path. It is the
	// state used when a request carries none; stateful HTTP requests instead
	// resolve their own per-`Mcp-Session-Id` state.
	server.bindConnection(new ConnectionState);

	// basic/authorization §Authorization Server Location (RFC 9728): refuse to start
	// serving a Protected Resource Metadata document that would violate the MUST to
	// list at least one authorization server. Fail loudly rather than publish an empty
	// authorization_servers array.
	validateAuthConfig(opts.auth);

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
	auto push = ensurePushChannel(server, coord);
	router.get(opts.path, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		handleGet(server, push, sessions, opts.reconnectDelayMs, req, res);
	});
	router.match(HTTPMethod.DELETE, opts.path, (HTTPServerRequest req,
			HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		// The DELETE is a subsequent HTTP request and is subject to the same
		// rule as the POST and GET paths: an invalid or unsupported
		// MCP-Protocol-Version MUST be answered with 400 Bad Request (a null-id
		// JSON-RPC error) rather than proceeding to a 204 terminate or a 405.
		if (auto verErr = postProtocolVersionGate(req.headers.get(HttpHeader.protocolVersion, "")))
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(Json(null), verErr).toString(), "application/json");
			return;
		}
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
		res.headers["Allow"] = allowedMethodsHeader(server.negotiatedVersion,
			server.mode == ServerMode.stateful);
		res.writeBody("", "text/plain");
	});

	// Opt-in backwards compatibility: also host the deprecated 2024-11-05
	// HTTP+SSE two-endpoint transport alongside the modern MCP endpoint
	// (basic/transports §Backwards Compatibility — a SHOULD, hence opt-in).
	if (opts.legacyHttpSse)
		mountLegacyHttpSse(router, server, opts);
}

/// Mount the deprecated 2024-11-05 HTTP+SSE two-endpoint transport
/// (basic/transports §HTTP with SSE) onto `router`, so a legacy-only client can
/// still negotiate it against a D MCP server. Called by `mountMcp` when
/// `opts.legacyHttpSse` is set, but also usable directly to host ONLY the legacy
/// transport. It mounts:
///   - GET `opts.legacySsePath`: opens a `text/event-stream`; the FIRST event is
///     the `endpoint` event whose data is `opts.legacyMessagePath` ("When a
///     client connects, the server MUST send an `endpoint` event containing a URI
///     for the client to use for sending messages"); the stream is then held open
///     and every server message is delivered as an SSE `message` event;
///   - POST `opts.legacyMessagePath`: accepts a single JSON-RPC message, replies
///     `202 Accepted` with no body, and pushes any JSON-RPC response back onto the
///     open GET stream as a `message` event ("Server messages are sent as SSE
///     `message` events, with the message content encoded as JSON in the event
///     data"). Origin/auth guards mirror the modern endpoint.
void mountLegacyHttpSse(URLRouter router, McpServer server,
		StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
	auto channel = new LegacySseChannel(opts.legacyMessagePath);

	router.get(opts.legacySsePath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		handleLegacyGet(channel, res);
	});

	router.post(opts.legacyMessagePath, (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (!guardOrigin(req, res, opts))
			return;
		TokenInfo token;
		if (!guardAuth(req, res, opts, token))
			return;
		const payload = req.bodyReader.readAllUTF8();
		// The per-stream session token the client echoes from its `endpoint` event
		// correlates this POST with the GET stream that should receive the reply, so
		// a response never leaks onto another client's stream.
		const sessionId = req.query.get("sessionId", "");
		// Resolve the per-stream ConnectionState so each client's dispatch runs
		// against its own isolated state rather than the shared fallback.
		auto connState = channel.connStateFor(sessionId);
		cast(void) handleLegacyPostBody(server, channel, sessionId, payload, connState);
		// All subsequent client messages are POSTed here; the response (if any)
		// is delivered on the GET SSE stream, so the POST itself just acknowledges
		// receipt with 202 Accepted and no body.
		res.statusCode = HTTPStatus.accepted;
		res.writeBody("", "text/plain");
	});
}

/// The legacy 2024-11-05 HTTP+SSE server->client channel. It manages the open GET
/// SSE listeners and routes JSON-RPC server messages onto them as SSE `message`
/// events. On registration a listener is minted a per-stream session token and
/// immediately receives the `endpoint` event whose data carries that token as a
/// `?sessionId=` query parameter on the message-POST path, as the transport
/// requires before any other traffic. The client echoes the token on every POST,
/// so a response is routed back ONLY to the originating stream — never broadcast
/// to other concurrently-connected clients (which would leak one client's results
/// onto another client's stream).
///
/// Each registered listener owns a fresh `ConnectionState` so concurrent clients
/// do not interfere with each other's negotiated version, client capabilities,
/// subscriptions, or in-flight cancellation registry.
final class LegacySseChannel
{
	private struct Listener
	{
		long id;
		string sessionId;
		void delegate(string frame) @safe write;
		ConnectionState connState;
	}

	private string endpointPath;
	private Listener[] listeners;
	private long nextId = 1;
	/// Correlates server->client requests with the client's reply POSTs, keyed by
	/// (sessionId, requestId). A handler that blocks in ctx.sample/ctx.elicit/
	/// ctx.listRoots registers here; the client's reply POST resolves the waiter.
	StreamCoordinator coord;

	this(string endpointPath) @safe
	{
		this.endpointPath = endpointPath;
		this.coord = new StreamCoordinator;
	}

	/// Register an open GET SSE stream. A fresh per-stream session token and a
	/// fresh per-stream `ConnectionState` are minted; the listener immediately
	/// receives the leading `endpoint` event (basic/transports §HTTP with SSE:
	/// the server MUST send it "When a client connects") whose URI carries that
	/// token, so a later POST can be correlated back to exactly this stream.
	/// Returns the listener id.
	long addListener(void delegate(string frame) @safe write) @safe
	{
		const id = nextId++;
		const sessionId = generateSessionId();
		write(formatLegacyEndpointEvent(endpointWithSession(endpointPath, sessionId)));
		listeners ~= Listener(id, sessionId, write, new ConnectionState);
		return id;
	}

	/// The per-stream session token minted for the listener `id`, or null when no
	/// such listener exists. Exposed so the two-endpoint flow (and tests) can
	/// correlate a POST back to the stream that should receive its reply.
	string sessionIdFor(long id) @safe
	{
		foreach (l; listeners)
			if (l.id == id)
				return l.sessionId;
		return null;
	}

	/// The per-stream `ConnectionState` for the stream whose session token is
	/// `sessionId`, or null when no matching open stream exists. The POST handler
	/// passes this to `handleRaw` so each client's JSON-RPC dispatch runs against
	/// its own isolated state (negotiated version, client capabilities, etc.).
	ConnectionState connStateFor(string sessionId) @safe
	{
		foreach (l; listeners)
			if (l.sessionId == sessionId)
				return l.connState;
		return null;
	}

	/// Drop a listener (its GET stream closed).
	void removeListener(long id) @safe
	{
		import std.algorithm : remove;

		listeners = listeners.remove!(l => l.id == id);
	}

	/// Number of currently-open legacy streams.
	size_t listenerCount() const @safe
	{
		return listeners.length;
	}

	/// Deliver a raw JSON-RPC payload as an SSE `message` event to the single
	/// stream whose minted session token is `sessionId`, so a response is routed
	/// only to the client that issued the corresponding POST and never leaks across
	/// sessions. A listener whose write throws (a disconnected client) is dropped so
	/// the channel self-heals. An empty payload, or an unknown/empty token (no
	/// matching open stream), is a no-op.
	void deliverTo(string sessionId, string jsonText) @safe
	{
		if (jsonText.length == 0 || sessionId.length == 0)
			return;
		const frame = formatLegacyMessageEventRaw(jsonText);
		long[] dead;
		// Iterate a snapshot so a self-healing removal (or any concurrent listener
		// mutation across the async `l.write`) cannot dangle the loop reference.
		// The dup is a shallow copy of the small Listener[].
		foreach (l; listeners.dup)
		{
			if (l.sessionId != sessionId)
				continue;
			try
				l.write(frame);
			catch (Exception)
				dead ~= l.id;
		}
		foreach (id; dead)
			removeListener(id);
	}
}

/// Append a per-stream session token to the legacy message-POST URI so the leading
/// `endpoint` event tells a client where to POST AND which stream its replies
/// belong to. The token is added as a `sessionId` query parameter, preserving any
/// existing query string already present on the path.
string endpointWithSession(string endpointPath, string sessionId) @safe
{
	import std.string : indexOf;

	const sep = endpointPath.indexOf('?') >= 0 ? "&" : "?";
	return endpointPath ~ sep ~ "sessionId=" ~ sessionId;
}

/// Serialize every write to one response's bodyWriter through a fresh per-stream
/// TaskMutex and return the resulting write+flush closure. Each SSE handler shares
/// its connection between a registered-listener writer and a heartbeat loop running
/// on different fibers, and the underlying channel mutex guards only channel state,
/// not these foreign writers — so without per-stream serialization two concurrent
/// writes could interleave the bytes of different SSE frames.
private void delegate(string) @safe sseFrameWriter(HTTPServerResponse res) @safe
{
	import vibe.core.sync : TaskMutex;

	auto writeMtx = new TaskMutex;
	return (string frame) @safe {
		() @trusted {
			synchronized (writeMtx)
			{
				res.bodyWriter.write(cast(const(ubyte)[]) frame);
				res.bodyWriter.flush();
			}
		}();
	};
}

/// Hold an SSE connection open, emitting a comment heartbeat every 15s so a write
/// failure (client disconnect) is observed and the loop terminates.
private void runSseHeartbeat(void delegate(string) @safe writeFrame) @safe
{
	import vibe.core.core : sleep;
	import core.time : seconds;

	while (true)
	{
		sleep(15.seconds);
		try
			writeFrame(": ping\n\n");
		catch (Exception)
			break;
	}
}

/// Open a legacy GET SSE stream: register it on `channel` (which emits the
/// leading `endpoint` event), then hold the connection open with SSE comment
/// heartbeats so a client disconnect terminates the loop and drops the listener.
private void handleLegacyGet(LegacySseChannel channel, HTTPServerResponse res) @safe
{
	res.contentType = "text/event-stream";
	applySseStreamHeaders(res, false);

	// LegacySseChannel.deliverTo itself has no write serialization, so without the
	// per-stream lock two concurrent deliveries -- or a delivery racing the
	// heartbeat -- could interleave SSE frames.
	auto writeFrame = sseFrameWriter(res);

	const listenerId = channel.addListener((string frame) @safe {
		writeFrame(frame);
	});
	scope (exit)
		channel.removeListener(listenerId);

	runSseHeartbeat(writeFrame);
}

/// Process a single JSON-RPC message POSTed to the legacy message endpoint and
/// route any response back onto the originating client's legacy GET SSE stream as a
/// `message` event. `sessionId` is the per-stream token the client echoed from its
/// `endpoint` event, so the response is delivered ONLY to the stream that issued
/// this POST — never broadcast across concurrently-connected clients. `conn` is the
/// per-stream `ConnectionState` owned by the originating GET listener. Returns true
/// (the server accepts every well-formed POST on this transport; a parse failure
/// still yields a JSON-RPC error response delivered on the stream). A notification
/// produces no response, so nothing is delivered. A client response/errorResponse
/// (the client's reply to a server->client request) is routed to the channel's
/// coordinator so a handler blocked in ctx.sample/ctx.elicit/ctx.listRoots is
/// unblocked. Exposed (package-level) so the two-endpoint flow can be exercised
/// without a live socket.
bool handleLegacyPostBody(McpServer server, LegacySseChannel channel,
		string sessionId, string payload, ConnectionState conn = null) @safe
{
	// Parse the message to distinguish client responses (replies to a server->client
	// request) from client requests and notifications. A parse failure falls through
	// to handleRaw which produces a JSON-RPC error response on the SSE stream.
	try
	{
		const msg = parseMessage(payload);
		if (msg.kind == MessageKind.response || msg.kind == MessageKind.errorResponse)
		{
			// Route the client's reply to whatever handler task is awaiting it.
			// The coordinator key is (sessionId, requestId) so a reply for one session
			// cannot wake a waiter registered under a different session token.
			channel.coord.resolve(msg.id, msg.result, msg.error, sessionId);
			return true;
		}
	}
	catch (Exception)
	{
		// Parse failure: fall through so handleRaw returns the protocol error.
	}

	// Wire a sink that pushes any out-of-band server frame (progress, log,
	// server->client request) onto the originating SSE stream, and a serverRequest
	// delegate that issues a server->client request through the channel coordinator
	// and blocks until the client's reply POST arrives.
	void sink(string frame) @safe
	{
		channel.deliverTo(sessionId, frame);
	}

	Json serverRequest(string method, Json params) @safe
	{
		import core.time : seconds;

		const id = channel.coord.alloc();
		channel.coord.register(id, sessionId);
		try
			channel.deliverTo(sessionId, makeRequest(Json(id), method, params).toString());
		catch (Exception e)
		{
			channel.coord.cancel(id, sessionId);
			throw e;
		}
		return channel.coord.await(id, 60.seconds, sessionId);
	}

	const responseText = server.handleRaw(payload, &sink, &serverRequest);
	channel.deliverTo(sessionId, responseText);
	return true;
}

/// Frame the legacy `endpoint` SSE event (2024-11-05 basic/transports §HTTP with
/// SSE): a typed `endpoint` event whose data is the URI the client must POST
/// subsequent messages to.
string formatLegacyEndpointEvent(string uri) @safe
{
	return "event: endpoint\ndata: " ~ uri ~ "\n\n";
}

/// Frame a legacy server `message` SSE event from already-serialised JSON text
/// (2024-11-05 basic/transports §HTTP with SSE: "Server messages are sent as SSE
/// `message` events, with the message content encoded as JSON in the event data").
string formatLegacyMessageEventRaw(string jsonText) @safe
{
	return "event: message\ndata: " ~ jsonText ~ "\n\n";
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

	// HTTP/1.1 mandates a Host header; an absent (or disallowed) Host is rejected
	// so a request carrying neither Host nor Origin cannot fall through the guard.
	if (!hostAllowed(host, opts.allowedHosts))
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
	res.headers["WWW-Authenticate"] = wwwAuthenticate(failure, metaUrl, opts.auth.scopeHint());
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
///
/// The raw Host header is client-controlled and is reflected verbatim into the
/// `WWW-Authenticate: ... resource_metadata="..."` challenge, so it is NOT trusted
/// unconditionally:
///   - When origin validation is disabled (`validateOrigin == false`, the trusted-
///     reverse-proxy mode), the configured `resource` origin is preferred as the
///     primary source so an attacker-supplied Host cannot steer RFC 9728 discovery.
///   - A Host that does not satisfy the host/port grammar (or, under enabled origin
///     validation, the allow-list) is rejected before interpolation, so it can never
///     break out of the quoted-string or redirect discovery.
/// `wwwAuthenticate` additionally percent-encodes any residual quoted-string-illegal
/// characters as defence in depth.
private string resourceMetadataUrl(scope HTTPServerRequest req, StreamableHttpOptions opts) @safe
{
	import std.string : startsWith;

	// In unvalidated (reverse-proxy) mode the client-controlled Host is untrusted,
	// so the operator-configured `resource` origin is the PRIMARY source: prefer it
	// whenever it is set, falling back to the Host only when no resource is
	// configured. In validated mode the Host already cleared the allow-list guard,
	// so the request's own origin is used. Either way a Host that does not satisfy
	// the host/port grammar (validated mode: the allow-list) is never interpolated.
	if (!opts.validateOrigin)
	{
		if (auto fromResource = resourceOrigin(opts.auth.resource))
			return fromResource ~ ProtectedResourceMetadataPath;
	}

	const host = req.headers.get("Host", "");
	const hostUsable = host.length && (opts.validateOrigin ? hostAllowed(host,
			opts.allowedHosts) : isAllowedHostGrammar(host));
	if (hostUsable)
	{
		const scheme = req.headers.get("X-Forwarded-Proto",
				isLoopbackHostname(stripPort(host)) ? "http" : "https");
		return scheme ~ "://" ~ host ~ ProtectedResourceMetadataPath;
	}
	// No usable Host header: derive the origin from the configured resource identifier.
	if (auto fromResource = resourceOrigin(opts.auth.resource))
		return fromResource ~ ProtectedResourceMetadataPath;
	return ProtectedResourceMetadataPath;
}

/// The scheme://host[:port] origin of a configured RFC 8707 `resource` identifier
/// (its path stripped), or null when `resource` is empty or carries no scheme.
/// Used as the trustworthy source for the Protected Resource Metadata URL when the
/// client-controlled Host cannot be trusted.
private string resourceOrigin(string resource) @safe
{
	import std.string : indexOf;

	if (resource.length == 0)
		return null;
	const sep = resource.indexOf("://");
	if (sep < 0)
		return null;
	auto rest = resource[sep + 3 .. $];
	const slash = rest.indexOf('/');
	return slash >= 0 ? resource[0 .. sep + 3 + slash] : resource;
}

/// Whether a `Host` header value satisfies the RFC 3986 host[:port] grammar
/// tightly enough to be safely interpolated into a `WWW-Authenticate`
/// quoted-string. Permits unreserved host characters, IPv6 bracket literals, and a
/// trailing `:port`; rejects anything containing a quote, whitespace, control
/// character, or other byte that would break out of the quoted-string or steer
/// discovery. This is the grammar gate used in unvalidated (reverse-proxy) mode,
/// where the allow-list guard is intentionally off but the reflected value must
/// still be well-formed.
private bool isAllowedHostGrammar(string host) @safe
{
	if (host.length == 0)
		return false;
	foreach (char c; host)
	{
		const ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0'
				&& c <= '9') || c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '%';
		if (!ok)
			return false;
	}
	return true;
}

unittest  // isAllowedHostGrammar accepts well-formed hosts and rejects injection attempts
{
	assert(isAllowedHostGrammar("example.com"));
	assert(isAllowedHostGrammar("example.com:8443"));
	assert(isAllowedHostGrammar("127.0.0.1:3000"));
	assert(isAllowedHostGrammar("[::1]:8080"));
	assert(!isAllowedHostGrammar(""));
	// A quote would break out of the resource_metadata quoted-string.
	assert(!isAllowedHostGrammar(`x" foo="bar`));
	assert(!isAllowedHostGrammar("evil.example.com/path"));
	assert(!isAllowedHostGrammar("has space"));
}

unittest  // resourceOrigin strips the path from a configured resource identifier
{
	assert(resourceOrigin("https://mcp.example.com/mcp") == "https://mcp.example.com");
	assert(resourceOrigin("https://mcp.example.com") == "https://mcp.example.com");
	assert(resourceOrigin("") is null);
	assert(resourceOrigin("no-scheme") is null);
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
	return !negotiated.isModern;
}

unittest  // stable revisions open the GET SSE stream; the draft does not
{
	assert(getOpensSseStream(ProtocolVersion.v2025_11_25));
	assert(getOpensSseStream(ProtocolVersion.v2025_06_18));
	assert(getOpensSseStream(ProtocolVersion.v2025_03_26));
	assert(!getOpensSseStream(ProtocolVersion.modern));
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
	return !negotiated.isModern;
}

unittest  // stable revisions terminate sessions on DELETE; the draft answers 405
{
	assert(deleteTerminatesSession(ProtocolVersion.v2025_11_25));
	assert(deleteTerminatesSession(ProtocolVersion.v2025_06_18));
	assert(deleteTerminatesSession(ProtocolVersion.v2025_03_26));
	assert(!deleteTerminatesSession(ProtocolVersion.modern));
}

/// Decide whether protocol-level sessions apply to a POST request
/// (basic/transports §Backward Compatibility / §Earlier Streamable HTTP
/// Revisions). The stable revisions (2025-03-26 / 2025-06-18 / 2025-11-25) carry
/// protocol-level sessions: the server mints an `Mcp-Session-Id` on the
/// `InitializeResult` and requires the client to echo it on every later request.
/// The draft removed protocol-level sessions (revision 2026-07-28: "Removal of
/// protocol-level sessions"), so a draft-only server "SHOULD respond as follows:
/// ... An `Mcp-Session-Id` header on a request: ignore it, and do not mint or echo
/// session IDs."
///
/// Returns true when POST session minting/requiring applies (stable revisions),
/// false when the server must neither mint nor require a session id (the draft) —
/// mirroring the version gates `getOpensSseStream` (GET) and
/// `deleteTerminatesSession` (DELETE) already apply.
bool sessionsApply(ProtocolVersion negotiated) @safe
{
	return !negotiated.isModern;
}

unittest  // stable revisions mint/require Mcp-Session-Id on POST; the draft does not
{
	assert(sessionsApply(ProtocolVersion.v2025_11_25));
	assert(sessionsApply(ProtocolVersion.v2025_06_18));
	assert(sessionsApply(ProtocolVersion.v2025_03_26));
	assert(!sessionsApply(ProtocolVersion.modern));
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
///
/// The GET stream is, however, only actually mounted on a stateful server: a
/// stateless server answers GET with 405 `Allow: POST` (handleGet) regardless of
/// version. `getSupported` carries that mode gate so the DELETE 405 cannot
/// advertise a GET the same endpoint provably rejects with its own 405.
string allowedMethodsHeader(ProtocolVersion negotiated, bool getSupported = true) @safe
{
	return (getSupported && getOpensSseStream(negotiated)) ? "GET, POST" : "POST";
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
	assert(allowedMethodsHeader(ProtocolVersion.modern) == "POST");
}

unittest  // a stateless server (no GET stream) advertises only POST, matching its own GET 405
{
	// handleGet answers a stateless GET with 405 Allow: POST, so the DELETE 405 on
	// the same endpoint MUST NOT advertise GET — even on a stable revision.
	assert(allowedMethodsHeader(ProtocolVersion.v2025_11_25, false) == "POST");
	assert(allowedMethodsHeader(ProtocolVersion.v2025_06_18, false) == "POST");
	assert(allowedMethodsHeader(ProtocolVersion.v2025_03_26, false) == "POST");
	assert(allowedMethodsHeader(ProtocolVersion.modern, false) == "POST");
}

/// Whether the given `Accept` request-header value admits a `text/event-stream`
/// response. The standalone GET stream the MCP endpoint opens is always an SSE
/// stream, so a client whose `Accept` provably excludes that media type cannot
/// consume what the server would send. A media type is admitted by an exact
/// `text/event-stream` token, by the `text/*` subtype wildcard, or by the `*/*`
/// full wildcard; quality and other parameters after a `;` are ignored. An empty
/// value (no `Accept` header) is treated permissively as acceptable, since the
/// transport never required clients to send one. Only a header that names media
/// types and omits any matching one returns false.
bool acceptsEventStream(string accept) @safe
{
	import std.string : strip, toLower;
	import std.algorithm : splitter;

	auto trimmed = accept.strip;
	if (trimmed.length == 0)
		return true;

	foreach (part; trimmed.splitter(','))
	{
		auto mediaType = part;
		foreach (i, c; part)
		{
			if (c == ';')
			{
				mediaType = part[0 .. i];
				break;
			}
		}
		const token = mediaType.strip.toLower;
		if (token == "text/event-stream" || token == "text/*" || token == "*/*")
			return true;
	}
	return false;
}

unittest  // an Accept that names text/event-stream (or a wildcard covering it) is admitted
{
	assert(acceptsEventStream("text/event-stream"));
	assert(acceptsEventStream("application/json, text/event-stream"));
	assert(acceptsEventStream("text/event-stream;q=0.9"));
	assert(acceptsEventStream("text/*"));
	assert(acceptsEventStream("*/*"));
	assert(acceptsEventStream("application/json, */*"));
}

unittest  // a missing/blank Accept is treated permissively as acceptable
{
	assert(acceptsEventStream(""));
	assert(acceptsEventStream("   "));
}

unittest  // an Accept that names media types but omits text/event-stream is rejected
{
	assert(!acceptsEventStream("application/json"));
	assert(!acceptsEventStream("application/json, text/plain"));
	assert(!acceptsEventStream("application/*"));
}

unittest  // matching is case-insensitive and tolerant of surrounding whitespace
{
	assert(acceptsEventStream(" TEXT/Event-Stream "));
	assert(acceptsEventStream("application/json ,  text/event-stream"));
}

/// Whether the given `Accept` request-header value admits an `application/json`
/// response — the single-JSON reply a plain POST request receives. Matching
/// mirrors `acceptsEventStream`: an exact `application/json` token, the
/// `application/*` subtype wildcard, or the `*/*` full wildcard; quality and
/// other `;`-parameters are ignored. An empty value (no `Accept`) is permissive.
bool acceptsJson(string accept) @safe
{
	import std.string : strip, toLower;
	import std.algorithm : splitter;

	auto trimmed = accept.strip;
	if (trimmed.length == 0)
		return true;

	foreach (part; trimmed.splitter(','))
	{
		auto mediaType = part;
		foreach (i, c; part)
		{
			if (c == ';')
			{
				mediaType = part[0 .. i];
				break;
			}
		}
		const token = mediaType.strip.toLower;
		if (token == "application/json" || token == "application/*" || token == "*/*")
			return true;
	}
	return false;
}

unittest  // an Accept that names application/json (or a wildcard covering it) is admitted
{
	assert(acceptsJson("application/json"));
	assert(acceptsJson("application/json, text/event-stream"));
	assert(acceptsJson("application/json;q=0.9"));
	assert(acceptsJson("application/*"));
	assert(acceptsJson("*/*"));
	assert(acceptsJson(""));
}

unittest  // an Accept that names media types but omits application/json is rejected
{
	assert(!acceptsJson("text/event-stream"));
	assert(!acceptsJson("text/plain"));
	assert(!acceptsJson("text/*"));
}

/// Whether a POSTed request's `Accept` header admits at least one of the two
/// media types the Streamable HTTP transport can answer a request with —
/// `application/json` (a single JSON reply) or `text/event-stream` (an SSE
/// stream). The spec REQUIRES POST clients to send
/// `Accept: application/json, text/event-stream`; a request whose Accept
/// provably excludes BOTH could not consume any response the server may produce,
/// so it is rejected up front with 406 Not Acceptable. A missing/blank Accept is
/// permissive (both helpers admit it), matching the GET path's tolerance.
bool postAccepted(string accept) @safe
{
	return acceptsJson(accept) || acceptsEventStream(accept);
}

unittest  // a POST Accept admitting either media type is accepted; one excluding both is not
{
	assert(postAccepted("application/json, text/event-stream"));
	assert(postAccepted("application/json"));
	assert(postAccepted("text/event-stream"));
	assert(postAccepted("*/*"));
	assert(postAccepted("")); // permissive: no Accept header
	// Provably excludes BOTH acceptable media types -> not accepted.
	assert(!postAccepted("text/plain"));
	assert(!postAccepted("application/xml"));
}

private void handleGet(McpServer server, ServerPushChannel push, SessionManager sessions,
		uint reconnectDelayMs, HTTPServerRequest req, HTTPServerResponse res) @safe
{
	// The GET that opens the standalone stream is a subsequent HTTP request and
	// is subject to the same rule as the POST path: an invalid or unsupported
	// MCP-Protocol-Version MUST be answered with 400 Bad Request rather than a
	// 200 text/event-stream or a 405. This precedes the mode/getOpensSseStream
	// gate so a stateless or draft-negotiated server still rejects a bad version
	// with 400 rather than masking it behind a 405.
	if (auto verErr = postProtocolVersionGate(req.headers.get(HttpHeader.protocolVersion, "")))
	{
		res.statusCode = HTTPStatus.badRequest;
		res.writeBody(makeErrorResponse(Json(null), verErr).toString(), "application/json");
		return;
	}

	// The standalone GET SSE stream is an unsolicited server->client
	// push channel — shared state correlating more than one HTTP call. A stateless
	// server keeps no such state, so it MUST answer 405 (no unsolicited push
	// without a session) regardless of the negotiated version. Only a stateful
	// server (sessions keyed on Mcp-Session-Id) opens the stream.
	//
	// Per the transport: the server MUST either open a text/event-stream or
	// answer 405. The draft drops the standalone GET stream (server->client
	// traffic rides the POST-response SSE), so it keeps the 405 alternative.
	if (server.mode != ServerMode.stateful || !getOpensSseStream(server.negotiatedVersion))
	{
		res.statusCode = HTTPStatus.methodNotAllowed;
		res.headers["Allow"] = "POST";
		// A stateless server has no session to anchor the unsolicited push stream;
		// name the remedy. The draft (stateful or not) simply has no standalone GET
		// stream, so its 405 stays bodiless.
		res.writeBody(server.mode != ServerMode.stateful
				? "The standalone GET SSE stream requires a stateful server;"
				~ " construct it with McpServer.stateful()." : "", "text/plain");
		return;
	}

	// The standalone stream this GET would open is always text/event-stream. A
	// well-behaved client signals it can consume that via Accept; a client whose
	// Accept provably excludes text/event-stream could not read the stream, so
	// answer with the spec-sanctioned GET alternative (405 Allow: POST) rather
	// than opening a stream it cannot use. A missing Accept is treated
	// permissively and still opens the stream.
	if (!acceptsEventStream(req.headers.get("Accept", "")))
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
	// The per-session ConnectionState this GET stream belongs to, resolved from
	// Mcp-Session-Id. Bound into the push listener's eligibility predicate so
	// `notifications/resources/updated` delivery on this stream gates on THIS
	// session's `resources/subscribe` set rather than the shared fallback state.
	ConnectionState getConn;
	// The owning session's `Mcp-Session-Id`, used to scope Last-Event-ID resume to
	// this session so one client cannot replay another session's buffered stream
	// history by presenting its event id (cross-session disclosure).
	string ownerToken;
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
		getConn = sessions.stateFor(sid);
		ownerToken = sid;
	}

	// Open a long-lived SSE stream wired to the server-push channel, so the
	// server can deliver unsolicited notifications/requests outside any POST.
	res.contentType = "text/event-stream";
	// The standalone GET stream is offered only on the stable revisions
	// (getOpensSseStream gated above); the X-Accel-Buffering: no SHOULD is a
	// draft-only rule, so it is not emitted here.
	applySseStreamHeaders(res, false);

	auto writeFrame = sseFrameWriter(res);

	// Resumability and Redelivery (basic/transports §Resumability and Redelivery):
	// if the reconnecting client supplied the `Last-Event-ID` header, hand it to
	// the channel so it resumes the disconnected stream — replaying the events
	// emitted after that id on the same stream ordinal — instead of opening a fresh
	// one. The header is honoured only on the stable revisions that mount the GET
	// stream (gated by getOpensSseStream above); the draft never reaches here.
	const lastEventId = req.headers.get("Last-Event-ID", "");
	const listenerId = push.addListener((string frame) @safe {
		writeFrame(frame);
	}, "", ListenFilter.init, lastEventId, getConn !is null
			? server.sessionPushEligibility(getConn) : null, ownerToken);
	// Drop the listener when the stream ends so the channel self-heals.
	scope (exit)
		push.removeListener(listenerId);

	// 2025-11-25 basic/transports §Listening for Messages item 4 / §Sending
	// Messages item 6: if the server closes the connection without terminating
	// the stream, it SHOULD send a standard SSE `retry:` field first so the
	// client knows how long to wait before reconnecting. Emit it up-front (right
	// after opening) when configured, so the client has cached the reconnect
	// delay before any server-initiated close. Version-gated to 2025-11-25 only,
	// so other revisions' wire output is unchanged.
	if (reconnectDelayMs > 0 && sendsRetryOnClose(server.negotiatedVersion))
	{
		try
			writeFrame(formatRetryEvent(reconnectDelayMs));
		catch (Exception)
		{
		}
	}

	runSseHeartbeat(writeFrame);
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
		Message msg, HTTPServerResponse res, string protoHeader, string connToken) @safe
{
	// Record the opted-in filters (route -> doSubscribeListen). The one-shot JSON
	// result is discarded on success: the acknowledgement is delivered as the
	// first SSE event instead. A routing error (e.g. the version gate rejected
	// the request) is surfaced as a JSON-RPC error response — listen is draft-only,
	// so a method-not-found rides the draft 404 — rather than opening the stream
	// with a stale filter. The state is built the same way the regular POST path
	// builds it (`freshStatelessState`: header, then body `_meta`, then the
	// server default).
	auto reqState = freshStatelessState(protoHeader, msg.params, server.negotiatedVersion);
	auto routed = routeListenRequest(server, msg, reqState, connToken);
	if (!routed.isNull)
	{
		res.statusCode = httpStatusForResponse(routed.get, true);
		res.writeBody(routed.get.toString(), "application/json");
		return;
	}
	// THIS request's parsed filter, read back from its own per-request state, so
	// both the per-stream listener and its acknowledgement reflect exactly this
	// listen request's opt-in (draft basic/utilities/subscriptions §Multiple
	// Concurrent Subscriptions: each subscription is independent) — a concurrent
	// listen on the shared McpServer dispatches on a different state and cannot
	// overwrite it.
	auto streamFilter = reqState.listenFilter;

	res.contentType = "text/event-stream";
	// subscriptions/listen is a draft-only stream; emit the draft SHOULD header
	// X-Accel-Buffering: no alongside Cache-Control (basic/transports
	// §Receiving Messages).
	applySseStreamHeaders(res, true);

	auto writeFrame = sseFrameWriter(res);

	auto push = ensurePushChannel(server, coord);
	// The listen request's id becomes the stream's subscriptionId: every
	// notification delivered to this listener (including the leading
	// acknowledgement) is stamped with it in
	// `params._meta["io.modelcontextprotocol/subscriptionId"]` (draft
	// basic/utilities/subscriptions).
	const listenerId = push.addListener((string frame) @safe {
		writeFrame(frame);
	}, rpcIdString(msg.id), streamFilter);
	// Drop the listener when the stream ends so the channel self-heals.
	scope (exit)
		push.removeListener(listenerId);

	// First event: acknowledge with the agreed-upon subset for THIS request only,
	// delivered only to this stream (not broadcast to any other open listen stream).
	// Built from this stream's filter — not the server-wide accumulator — so a
	// concurrent (or already-closed) stream's opt-in cannot leak into this ack
	// (draft basic/utilities/subscriptions Acknowledgment). It is stamped with the
	// subscriptionId by the push channel, so it carries the listen id in `_meta`
	// like every subsequent notification on the stream.
	push.emitTo(listenerId,
			subscriptionsAcknowledgedNotification(server.acknowledgedSubsetFor(streamFilter)));

	runSseHeartbeat(writeFrame);
}

/// Whether `method` opens a draft `events/stream` push response.
bool opensEventsStream(string method, bool isDraft) @safe
{
	return isDraft && method == "events/stream";
}

/// The JSON-RPC error surfaced (under a 406 Not Acceptable) when a POST that would
/// open a `text/event-stream` response (`subscriptions/listen` or `events/stream`)
/// carries an `Accept` that provably excludes that media type.
McpException eventStreamNotAcceptable() @safe
{
	return invalidRequest(
			"this request opens a text/event-stream response; Accept must admit text/event-stream");
}

/// The heartbeat cadence: a `notifications/events/heartbeat` carries the cursor at
/// least this often so a quiet stream still advances the client cursor and the
/// periodic write doubles as the client-disconnect detector.
enum long eventStreamHeartbeatIntervalMs = 15_000;

/// One iteration's decision for the SSE hold-open loop, computed purely from the
/// timing inputs so it is unit-testable without a network or a real clock.
struct EventStreamTick
{
	bool poll; /// pull check-function events this iteration (false for emit-only streams)
	bool heartbeat; /// write a cursor-carrying heartbeat this iteration
}

/// The fixed sleep between hold-open loop iterations. An emit-only stream wakes
/// only on the heartbeat cadence (its events arrive via the sink); a poll-driven
/// stream wakes on its poll cadence, clamped to `[1s, heartbeat interval]` so a
/// fast poll never starves the disconnect-detecting heartbeat and a slow one never
/// outlives it.
long eventStreamSleepMs(bool emitOnly, long pollMs) @safe pure nothrow @nogc
{
	import std.algorithm : min, max;

	return emitOnly ? eventStreamHeartbeatIntervalMs : max(1_000L, min(pollMs,
			eventStreamHeartbeatIntervalMs));
}

/// Decide what one hold-open iteration does, given whether the stream is emit-only
/// and how long it has been since the last heartbeat. A poll-driven stream always
/// polls; either kind heartbeats only once the cadence has elapsed (so a sub-15s
/// poll loop does not heartbeat on every wake-up).
EventStreamTick eventStreamTick(bool emitOnly, long sinceHeartbeatMs) @safe pure nothrow @nogc
{
	EventStreamTick t;
	t.poll = !emitOnly;
	t.heartbeat = sinceHeartbeatMs >= eventStreamHeartbeatIntervalMs;
	return t;
}

/// Serve a draft `events/stream` (push) request as a long-lived SSE response that
/// carries `notifications/events/*` for one subscription. The subscription is
/// validated via the events runtime (an invalid one yields a JSON-RPC error and
/// no stream); then the response is upgraded to `text/event-stream`, the leading
/// `notifications/events/active` carries the starting cursor, backlog (if any) is
/// drained, and the connection is held open — emit-driven types receive live
/// events via the registered sink while check-function types are polled — with a
/// cursor-carrying `notifications/events/heartbeat` so the client's cursor
/// advances during quiet periods. Every frame is stamped with the request id in
/// `_meta` so a client multiplexing several streams can route it.
private void handleEventsStream(McpServer server, Message msg,
		HTTPServerResponse res, string principal) @safe
{
	import vibe.core.core : sleep;
	import core.time : msecs;

	auto rt = server.events();
	if (rt is null)
	{
		auto e = methodNotFound("events");
		res.statusCode = httpStatusForResponse(makeErrorResponse(msg.id, e), true);
		res.writeBody(makeErrorResponse(msg.id, e).toString(), "application/json");
		return;
	}

	auto p = StreamParams.fromJson(msg.params);
	if (p.name.length == 0)
	{
		auto e = invalidParams("events/stream requires a string 'name'");
		res.statusCode = httpStatusForResponse(makeErrorResponse(msg.id, e), true);
		res.writeBody(makeErrorResponse(msg.id, e).toString(), "application/json");
		return;
	}

	auto writeFrame = sseFrameWriter(res);
	const subId = msg.id;
	void deliver(string method, Json params) @safe
	{
		writeFrame("data: " ~ makeNotification(method, params).toString() ~ "\n\n");
	}

	// Validate (and register the emit sink + fire on_subscribe) BEFORE upgrading
	// the response, so an invalid subscription returns a JSON-RPC error.
	import mcp.server.events_runtime : PushHandle;

	PushHandle handle;
	try
		handle = rt.openPushStream(p.name, p.arguments, principal, subId, &deliver);
	catch (McpException e)
	{
		res.statusCode = httpStatusForResponse(makeErrorResponse(msg.id, e), true);
		res.writeBody(makeErrorResponse(msg.id, e).toString(), "application/json");
		return;
	}
	scope (exit)
		handle.close();

	res.contentType = "text/event-stream";
	applySseStreamHeaders(res, true);

	const emitOnly = rt.isEmitOnly(p.name);
	Nullable!string cursor = p.cursor;
	long pollMs = 15_000;

	// Leading active frame + any backlog, from an initial poll.
	try
	{
		auto first = rt.poll(p.name, p.arguments, principal, p.cursor,
				p.maxAgeMs, Nullable!long.init);
		deliver(eventsActiveNotification,
				withSubscriptionId(activeParams(first.cursor, first.truncated), subId));
		foreach (ev; first.events)
			deliver(eventsEventNotification, withSubscriptionId(ev.toJson(), subId));
		cursor = first.cursor;
		handle.stream.cursor = first.cursor;
		if (!first.nextPollMs.isNull)
			pollMs = first.nextPollMs.get;
	}
	catch (Exception)
		deliver(eventsActiveNotification, withSubscriptionId(activeParams(p.cursor, false), subId));

	// Hold open: poll-driven check types pull events on a cadence; emit-driven
	// types receive them via the sink. Either way a heartbeat carries the cursor.
	// The per-iteration (poll? heartbeat?) decision and the loop cadence are pure
	// (`eventStreamTick`/`eventStreamSleepMs`); this loop only supplies the clock,
	// the I/O, and the disconnect-on-write-failure break.
	import core.time : MonoTime;

	const sleepMs = eventStreamSleepMs(emitOnly, pollMs);
	auto lastHeartbeat = MonoTime.currTime;
	while (true)
	{
		try
			sleep(sleepMs.msecs);
		catch (Exception)
			break;
		const sinceHeartbeatMs = (MonoTime.currTime - lastHeartbeat).total!"msecs";
		const tick = eventStreamTick(emitOnly, sinceHeartbeatMs);
		if (tick.poll)
		{
			try
			{
				auto r = rt.poll(p.name, p.arguments, principal, cursor,
						p.maxAgeMs, Nullable!long.init);
				foreach (ev; r.events)
					deliver(eventsEventNotification, withSubscriptionId(ev.toJson(), subId));
				if (!r.cursor.isNull)
				{
					cursor = r.cursor;
					handle.stream.cursor = r.cursor;
				}
			}
			catch (Exception)
			{
			}
		}
		else
			cursor = handle.stream.cursor; // advanced by sink deliveries
		if (!tick.heartbeat)
			continue; // not yet due — avoid heartbeating every sub-15s poll iteration
		try
			deliver(eventsHeartbeatNotification, withSubscriptionId(heartbeatParams(cursor), subId));
		catch (Exception)
			break; // client disconnected
		lastHeartbeat = MonoTime.currTime;
	}
}

/// A minimal connection-scoped `RequestContext` for one-shot dispatches on the
/// Streamable HTTP transport that carry a per-connection token and
/// `ConnectionState` but never stream server->client traffic. Two paths use it:
/// an inbound `notifications/cancelled` (which reads the token to scope the
/// in-flight cancellation key), and the draft `subscriptions/listen` route (which
/// reads the `ConnectionState` so dispatch resolves the draft effective version
/// before the long-lived stream is wired up on the push channel separately). It
/// has no server->client channel — it never emits progress/logging or
/// server-initiated requests — inheriting the no-op member bodies from
/// `BaseRequestContext` and overriding only the connection scope and the
/// no-channel exception message.
private final class HttpScopedContext : BaseRequestContext, ConnectionScoped
{
	private string token_;
	// The request's ConnectionState. For an inbound `notifications/cancelled` this
	// is the session's state, so the cancellation flips the token in the SAME
	// per-session in-flight registry the request side used (null in stateless mode,
	// which has no cross-POST cancellation correlation). For the draft listen route
	// it is the per-request draft state, so dispatch resolves the draft effective
	// version and serves the draft-only listen RPC.
	private ConnectionState connState_;

	this(string token, ConnectionState connState = null) @safe
	{
		this.token_ = token;
		this.connState_ = connState;
	}

	string connectionToken() @safe
	{
		return token_;
	}

	ConnectionState connectionState() @safe
	{
		return connState_;
	}

	protected override Json noChannel() @safe
	{
		throw internalError("connection-scoped context has no server-to-client channel");
	}
}

/// Route a draft `subscriptions/listen` through `server.handle` with the
/// caller's draft-aware per-request `ConnectionState`, so dispatch resolves the
/// draft effective version — and thus the draft-only listen RPC — even when the
/// draft was signalled by the `MCP-Protocol-Version` header alone (no body
/// `_meta.protocolVersion`). On success the server has recorded this request's
/// per-stream filter on `reqState.listenFilter` and `null` is returned; when
/// routing rejects the request the JSON-RPC error response is returned for the
/// caller to surface instead of opening a stream with a stale filter.
private Nullable!Json routeListenRequest(McpServer server, Message msg,
		ConnectionState reqState, string connToken) @safe
{
	auto resp = server.handle(msg, new HttpScopedContext(connToken, reqState));
	if (!resp.isNull && "error" in resp.get && resp.get["error"].type == Json.Type.object)
		return resp;
	return Nullable!Json.init;
}

unittest  // a draft listen signalled by the header alone routes against the draft version
{
	import mcp.protocol.jsonrpc : makeRequest, Message;

	// A draft client may signal the draft via the MCP-Protocol-Version header
	// alone, with no `_meta.protocolVersion` in the body. The listen routing must
	// still dispatch against the draft effective version so the draft-only
	// subscriptions/listen RPC is served (not -32601 methodNotFound) and THIS
	// request's opt-in filter is recorded — not dropped on an error path that
	// would open the stream with a stale filter.
	auto server = McpServer.stateful("t", "1");
	server.enableToolsListChanged();

	Json notifications = Json.emptyObject;
	notifications["toolsListChanged"] = true;
	Json params = Json.emptyObject;
	params["notifications"] = notifications;
	auto msg = Message(makeRequest(Json(7), "subscriptions/listen", params));

	auto reqState = freshStatelessState("2026-07-28", params, server.negotiatedVersion);
	auto routed = routeListenRequest(server, msg, reqState, "");
	assert(routed.isNull, "a header-signalled draft listen must route, not error");
	assert(reqState.listenFilter.active);
	assert(reqState.listenFilter.toolsListChanged);
}

unittest  // concurrent listens each keep their own per-stream filter
{
	import mcp.protocol.jsonrpc : makeRequest, Message;

	// Two subscriptions/listen requests interleaved on one shared server (as two
	// concurrent HTTP listen streams race). Each stream's opt-in must be recorded
	// on its own request state: a server-global "last filter" field would hand
	// the first stream the second stream's filter.
	auto server = McpServer.stateful("t", "1");
	server.enableToolsListChanged();
	server.enablePromptsListChanged();

	static Json listenParams(string changeType)
	{
		Json notifications = Json.emptyObject;
		notifications[changeType] = true;
		Json params = Json.emptyObject;
		params["notifications"] = notifications;
		return params;
	}

	auto paramsA = listenParams("toolsListChanged");
	auto paramsB = listenParams("promptsListChanged");
	auto msgA = Message(makeRequest(Json(1), "subscriptions/listen", paramsA));
	auto msgB = Message(makeRequest(Json(2), "subscriptions/listen", paramsB));

	auto a = freshStatelessState("2026-07-28", paramsA, server.negotiatedVersion);
	auto b = freshStatelessState("2026-07-28", paramsB, server.negotiatedVersion);
	assert(routeListenRequest(server, msgA, a, "").isNull);
	assert(routeListenRequest(server, msgB, b, "").isNull);

	assert(a.listenFilter.active && a.listenFilter.toolsListChanged
			&& !a.listenFilter.promptsListChanged,
			"stream A must keep its own toolsListChanged opt-in");
	assert(b.listenFilter.active && b.listenFilter.promptsListChanged
			&& !b.listenFilter.toolsListChanged,
			"stream B must keep its own promptsListChanged opt-in");
}

/// Validate the draft-only request headers on a POSTed JSON-RPC request, returning
/// the first error (caller emits it as a 400) or null when they pass. The
/// MCP-Protocol-Version header is already validated by `postProtocolVersionGate`.
private McpException validatePostRequestHeaders(HTTPServerRequest req,
		ref Message msg, bool isDraftReq, McpServer server) @safe
{
	// Draft: validate the standard request headers against the body.
	if (auto hdrErr = validateDraftHeaders(req.headers.get(HttpHeader.protocolVersion,
			""), req.headers.get(HttpHeader.method, ""),
			req.headers.get(HttpHeader.name, ""), msg, isDraftReq))
		return hdrErr;

	// Draft x-mcp-header: validate Mcp-Param-* headers against the tool's
	// declared header parameters and the body arguments.
	if (msg.method == "tools/call" && isDraftReq)
	{
		const tname = ("name" in msg.params && msg.params["name"].type == Json.Type.string) ? msg
			.params["name"].get!string : "";
		auto schema = server.toolInputSchema(tname);
		auto args = ("arguments" in msg.params) ? msg.params["arguments"] : Json.emptyObject;
		return validateParamHeaders(schema, args, (string h) => req.headers.get(h, ""));
	}

	return null;
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
		res.statusCode = HTTPStatus.badRequest;
		res.writeBody(makeErrorResponse(Json(null), e).toString(), "application/json");
		return;
	}
	catch (Exception e)
	{
		res.statusCode = HTTPStatus.badRequest;
		res.writeBody(makeErrorResponse(Json(null), parseError(e.msg))
				.toString(), "application/json");
		return;
	}

	// Session Management: when enabled, the very first request MUST be an
	// `initialize` (which receives a freshly-minted Mcp-Session-Id); every
	// later request MUST carry that id (400 when absent, 404 when unknown or
	// terminated). The id is also issued for the InitializeResult below.
	if (sessions !is null && sessionsApply(server.negotiatedVersion))
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

	// Per-connection cancellation scope. A request and its later
	// `notifications/cancelled` arrive on SEPARATE POSTs that share only the
	// `Mcp-Session-Id` header, so the cancellation registry must be keyed by that
	// session id for the two to match. The token is therefore the session id when
	// stateful sessions are enabled and applicable; otherwise the empty (shared)
	// token, in which case bare-id cancellation is unscoped across connections
	// (documented in `mcp.transport.session` -- stateful sessions are required for
	// cross-client cancellation isolation).
	const connToken = (sessions !is null && sessionsApply(server.negotiatedVersion)) ? req
		.headers.get(SessionHeader, "") : "";

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
		// Resolve THIS request's connection state (the SessionManager-owned state
		// for a stateful session, else a fresh/implicit-peer state) and gate the
		// batch on its negotiated version — the SAME source the server core gates
		// on — rather than trusting the client's MCP-Protocol-Version header. This
		// keeps the transport gate and the core gate from disagreeing: a batch the
		// transport forwards is one the core will accept.
		// A batch is never an `initialize` (that is a single message), so no session
		// is minted on this path: the only session id is the `Mcp-Session-Id` header
		// (`connToken`).
		ConnectionState reqState = postState(server, sessions, "", connToken,
				req.headers.get(HttpHeader.protocolVersion, ""), Json.undefined);
		const ver = (reqState !is null) ? reqState.negotiated : server.negotiatedVersion;
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
		// server->client traffic), dispatched against the resolved state so the
		// legacy path is actually reachable for a session that negotiated 2025-03-26.
		const txt = server.handleRaw(payload, reqState);
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
		// A client's reply to a server->client request: route it to the waiter,
		// but only when this POST's session owns that pending request. Passing the
		// connection token lets the coordinator reject a reply whose session
		// differs from the one the request was issued to, so a session cannot
		// resolve or hijack another session's pending server->client request. For
		// the stateless / shared path (empty token) this matches as before.
		coord.resolve(msg.id,
				msg.result, msg.error, connToken);
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
		const isDraftNote = tryDraft(
				req.headers.get(HttpHeader.protocolVersion, ""))
			|| tryDraft(RequestMeta.fromParams(msg.params).protocolVersion);
		if (auto noteErr = validateDraftHeaders(req.headers.get(HttpHeader.protocolVersion,
				""), req.headers.get(HttpHeader.method, ""),
				req.headers.get(HttpHeader.name, ""), msg, isDraftNote))
		{
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(Json(null), noteErr).toString(), "application/json");
			return;
		}
		// Route the notification through a connection-scoped context so a
		// `notifications/cancelled` resolves to the SAME per-session in-flight key the
		// request side (HttpStreamContext) uses. Without this it would go through
		// NullContext (token ""), never matching the scoped in-flight request.
		// Carry the session's ConnectionState so a
		// `notifications/cancelled` flips the cancellation token in the SAME
		// per-session in-flight registry the request side used. Stateful only —
		// stateless has no cross-POST correlation, so the state is null there.
		ConnectionState noteState = (sessions !is null && sessionsApply(server.negotiatedVersion)) ? sessions
			.stateFor(connToken) : null;
		server.handle(msg, new HttpScopedContext(connToken, noteState));
		res.statusCode = HTTPStatus.accepted;
		res.writeBody("", "text/plain");
		return;
	case MessageKind.request:
		// Content Negotiation (basic/transports §Sending Messages): a POST carrying
		// a request "MUST include an Accept header, listing both application/json and
		// text/event-stream as supported content types." A client whose Accept
		// provably excludes BOTH could not consume any response the server may
		// produce (a single JSON reply or an SSE stream), so reject it up front with
		// 406 Not Acceptable rather than answering with a body it declared it cannot
		// read. A missing/blank Accept stays permissive. This precedes session
		// minting so a 406 never leaves a session behind.
		if (!postAccepted(req.headers.get("Accept", "")))
		{
			res.statusCode = HTTPStatus.notAcceptable;
			res.writeBody(
					"Not Acceptable: POST requests must accept application/json or text/event-stream",
					"text/plain");
			return;
		}
		// Session Management: mint a session id for an `initialize` so dispatch can
		// negotiate against the SessionManager-owned `ConnectionState`. The id is
		// COMMITTED to the response (its `Mcp-Session-Id` header) only once
		// `server.handle` returns a successful `InitializeResult`; on any error path
		// below the minted session is rolled back via `sessions.terminate` so a
		// failed/invalid initialize neither leaks a session nor stamps the header on
		// a non-`InitializeResult` response (the spec ties that header to "the HTTP
		// response containing the InitializeResult").
		// `sessions.create()` is fail-closed: it throws McpException when the OS
		// CSPRNG is unavailable. Map that to a JSON-RPC error response on HTTP 500 --
		// the same shape as every other error path in handlePost -- instead of
		// letting it escape to vibe's generic error page.
		string mintedSessionId;
		if (sessions !is null && sessionsApply(server.negotiatedVersion)
				&& msg.method == "initialize")
		{
			try
				mintedSessionId = sessions.create();
			catch (McpException e)
			{
				res.statusCode = HTTPStatus.internalServerError;
				res.writeBody(makeErrorResponse(msg.id, e).toString(), "application/json");
				return;
			}
		}
		// The effective draft signal for this request: the draft protocol is
		// stateless-only and may negotiate via the body `_meta.protocolVersion`
		// alone (absent/non-draft MCP-Protocol-Version header), so classify the
		// request as draft on header OR body — the same precedence the rest of this
		// handler (opensListenStream, httpStatusForResponse, freshStatelessState)
		// uses. All draft-gated header validation below keys off this single value.
		const isDraftReq = tryDraft(req.headers.get(HttpHeader.protocolVersion, ""))
			|| tryDraft(RequestMeta.fromParams(msg.params).protocolVersion);
		if (auto hdrErr = validatePostRequestHeaders(req, msg, isDraftReq, server))
		{
			// Roll back a session minted above for an initialize that fails header
			// validation: it never reached a successful InitializeResult, so it must
			// not survive as a leaked session (no-op when nothing was minted).
			sessions !is null && sessions.terminate(mintedSessionId);
			res.statusCode = HTTPStatus.badRequest;
			res.writeBody(makeErrorResponse(msg.id, hdrErr).toString(), "application/json");
			return;
		}
		// Draft subscriptions/listen: the response is itself a long-lived SSE
		// stream that stays open and delivers change notifications until the
		// client closes it (draft basic/transports / basic/utilities/
		// subscriptions). Record the opted-in filters, open the stream, send the
		// acknowledgement as the first event, then hold it open — wired to the
		// server-push channel so notify*/notifyResourceUpdated reach it.
		if (opensListenStream(msg.method, isDraftReq))
		{
			// subscriptions/listen is a DRAFT RPC and the draft protocol is
			// stateless-only, so it MUST work on a stateless server too. It is a single
			// self-contained long-lived HTTP request: this POST opens the SSE response
			// stream, and notify*/notifyResourceUpdated stream
			// `notifications/resources/updated` and `.../list_changed` down THAT SAME
			// stream — exactly like a tool call emitting progress on its own SSE stream.
			// It needs NO session, NO Mcp-Session-Id, NO inbound correlation; delivery
			// is driven by this stream's own per-URI `ListenFilter` at the push
			// channel. (The 2025-era resources/subscribe RPC and the standalone GET
			// stream stay gated in stateless; only this draft listen path is opened.)
			//
			// The response is always text/event-stream. A client whose Accept provably
			// excludes it could not read the stream, so refuse with 406 rather than
			// upgrading regardless (mirroring the GET path). A missing Accept is permissive.
			if (!acceptsEventStream(req.headers.get("Accept", "")))
			{
				sessions !is null && sessions.terminate(mintedSessionId);
				res.statusCode = HTTPStatus.notAcceptable;
				res.writeBody(makeErrorResponse(msg.id,
						eventStreamNotAcceptable()).toString(), "application/json");
				return;
			}
			handleListenStream(server, coord, msg, res,
					req.headers.get(HttpHeader.protocolVersion, ""), connToken);
			return;
		}
		// Draft events/stream (push): like subscriptions/listen, this POST opens a
		// long-lived SSE response that streams `notifications/events/*` for one
		// subscription until the client disconnects. It is self-contained (no
		// session, no inbound correlation), so it works on a stateless server too.
		if (opensEventsStream(msg.method, isDraftReq))
		{
			// As above: the response is text/event-stream, so a POST whose Accept
			// provably excludes it is refused with 406 rather than upgraded anyway.
			if (!acceptsEventStream(req.headers.get("Accept", "")))
			{
				sessions !is null && sessions.terminate(mintedSessionId);
				res.statusCode = HTTPStatus.notAcceptable;
				res.writeBody(makeErrorResponse(msg.id,
						eventStreamNotAcceptable()).toString(), "application/json");
				return;
			}
			handleEventsStream(server, msg, res, token.valid ? token.subject : "");
			return;
		}
		// The effective version for this POST decides whether a server-initiated
		// SSE stream must lead with the 2025-11-25 priming event (event id + empty
		// data field; basic/transports §Sending Messages item 6).
		const effVersion = effectivePostVersion(req.headers.get(HttpHeader.protocolVersion,
				""), server.negotiatedVersion);
		// Resolve THIS request's per-connection state and hand it to
		// the context so the server core dispatches against it (never the single
		// bound `activeConnection`). Stateful HTTP -> the SessionManager-owned state
		// for this session id (the just-minted id on `initialize`, else the
		// `Mcp-Session-Id` header). Stateless HTTP -> a FRESH per-request state
		// seeded from the effective version + `_meta`, retained nowhere.
		ConnectionState reqState = postState(server, sessions, mintedSessionId,
				connToken, req.headers.get(HttpHeader.protocolVersion, ""), msg.params);
		// Whether this POST's Accept admits text/event-stream. When it provably does
		// not, an attempt by the handler to stream (progress/log/server-initiated
		// request) is refused inside the context and surfaced as 406 below, rather
		// than emitting an SSE body the client declared it cannot read.
		const reqAcceptsSse = acceptsEventStream(req.headers.get("Accept", ""));
		auto ctx = new HttpStreamContext(res, coord, clientCapsFor(server, reqState),
				extractProgressToken(msg.params),
				token, isDraftReq, effVersion, connToken, reqState,
				server.mode == ServerMode.stateless, reqAcceptsSse);
		auto resp = server.handle(msg, ctx);
		// Draft basic/utilities/cancellation §Transport-Specific Cancellation: on
		// Streamable HTTP "Closing the SSE response stream is the cancellation
		// signal. The server MUST treat a client disconnect as cancellation of that
		// request. No notifications/cancelled message is required or expected." If the
		// client dropped the connection while the handler ran, honour it as a
		// cancellation: emit no response, exactly as `notifications/cancelled` would
		// suppress it. Released versions (2025-*) keep their behaviour: a dropped
		// connection still completes the write, which is a harmless no-op there.
		if (suppressOnDisconnect(isDraftReq, res.connected))
		{
			// The draft is stateless-only, so it never mints a session; the rollback
			// is a no-op there. Kept for symmetry: a suppressed initialize must not
			// leave a session behind.
			sessions !is null && sessions.terminate(mintedSessionId);
			return;
		}
		// A request whose handling was cancelled mid-flight (e.g. a
		// `notifications/cancelled` arrived on a sibling POST, or the draft
		// client-disconnect cancellation) returns a NULL response: the spec says no
		// response is sent for a cancelled request. Guard the dereference exactly as
		// the stdio path does (`resp.isNull ? <no response> : resp.get`) so a
		// cancelled request suppresses its reply rather than asserting on `resp.get`.
		if (resp.isNull)
		{
			// No response to commit. Roll back any session minted for an initialize
			// that produced no result so a cancelled initialize leaves nothing behind,
			// then send the spec's no-body acknowledgement on the non-streaming path
			// (a streamed response has already written its events and simply ends).
			sessions !is null && sessions.terminate(mintedSessionId);
			if (!ctx.streaming)
			{
				res.statusCode = HTTPStatus.accepted;
				res.writeBody("", "text/plain");
			}
			return;
		}
		auto j = resp.get;
		// Commit the minted session only now that initialize produced a successful
		// InitializeResult: set its Mcp-Session-Id header. Any other outcome (a
		// JSON-RPC error result) rolls the minted session back so neither the leaked
		// session nor the spec-deviating header on an error response survives.
		if (mintedSessionId.length)
		{
			if (initializeSucceeded(j))
				res.headers[SessionHeader] = mintedSessionId;
			else
				sessions.terminate(mintedSessionId);
		}
		// The handler tried to stream but this POST's Accept excludes
		// text/event-stream, so the context refused the SSE upgrade (no body was
		// written). Surface 406 Not Acceptable with the refusal as a JSON-RPC error,
		// rather than the would-be SSE body the client declared it cannot read.
		if (ctx.streamRefused)
		{
			res.statusCode = HTTPStatus.notAcceptable;
			res.writeBody(j.toString(), "application/json");
			return;
		}
		if (ctx.streaming)
			ctx.finishWith(j);
		else
		{
			// Map reserved JSON-RPC errors onto their required HTTP statuses
			// (400 for unsupported-version/header-mismatch, draft 404 for
			// method-not-found); everything else rides on 200.
			res.statusCode = httpStatusForResponse(j, isDraftReq);
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
	// DELETE branches).
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
///   - `MissingRequiredClientCapability` (-32003) -> `400` (all modern versions),
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
	if (code == ErrorCode.unsupportedProtocolVersion || code == ErrorCode.headerMismatch
			|| code == ErrorCode.missingRequiredClientCapability)
		return 400;
	if (isDraft && code == ErrorCode.methodNotFound)
		return 404;
	return 200;
}

/// Whether a JSON-RPC response to an `initialize` request carries a successful
/// result rather than an error. Session Management (basic/transports §Session
/// Management) ties the `Mcp-Session-Id` header to "the HTTP response containing
/// the InitializeResult", so a freshly-minted session is committed (its header
/// set, the session kept) only when this is true; an error response (e.g. a
/// second initialize rejected with `invalidRequest`) rolls the minted session
/// back instead.
bool initializeSucceeded(Json resp) @safe
{
	return ("result" in resp) !is null && ("error" in resp) is null;
}

unittest  // a successful InitializeResult commits; an error response does not
{
	Json ok = Json.emptyObject;
	ok["result"] = Json.emptyObject;
	assert(initializeSucceeded(ok));

	Json err = Json.emptyObject;
	err["error"] = Json.emptyObject;
	assert(!initializeSucceeded(err));

	// A malformed response carrying neither is treated as not-successful so the
	// session is rolled back rather than leaked.
	assert(!initializeSucceeded(Json.emptyObject));
}

/// Decide whether a finished POST response must be suppressed because the client
/// disconnected mid-request. On the draft Streamable HTTP transport a client
/// disconnect IS the cancellation signal (draft basic/utilities/cancellation
/// §Transport-Specific Cancellation: "Closing the SSE response stream is the
/// cancellation signal. The server MUST treat a client disconnect as cancellation
/// of that request. No notifications/cancelled message is required or expected.").
/// So when the connection has dropped on a draft request, the response is
/// suppressed. Released versions (2025-*) never suppress on this basis: that MUST
/// is draft-only, so their wire behaviour is unchanged.
bool suppressOnDisconnect(bool isDraft, bool connected) @safe pure nothrow @nogc
{
	return isDraft && !connected;
}

unittest  // draft: a disconnected client cancels the request -> response suppressed
{
	assert(suppressOnDisconnect(true, false));
}

unittest  // draft: a still-connected client gets its response (no suppression)
{
	assert(!suppressOnDisconnect(true, true));
}

unittest  // released versions never suppress on disconnect (draft-only MUST)
{
	assert(!suppressOnDisconnect(false, false));
	assert(!suppressOnDisconnect(false, true));
}

/// Validate the draft Streamable HTTP request headers against the JSON-RPC body.
/// Returns a `HeaderMismatch` (-32001) exception on failure, or null when the
/// request is valid — or when the request is not a draft request (older versions
/// did not define these headers, so they are not enforced).
///
/// `isDraft` is the effective draft signal for the request (header OR body
/// `_meta.protocolVersion`), matching how the rest of the POST handler classifies
/// the request: the draft protocol is stateless-only and may negotiate via the
/// body alone, so a body-only-draft request still has its draft headers enforced.
McpException validateDraftHeaders(string protoHeader, string methodHeader,
		string nameHeader, Message msg, bool isDraft) @safe
{
	if (!isDraft)
		return null; // not a draft request: do not enforce draft headers

	if (methodHeader.length == 0)
		return new McpException(ErrorCode.headerMismatch, "Missing Mcp-Method header");
	if (methodHeader != msg.method)
		return new McpException(ErrorCode.headerMismatch,
				"Mcp-Method header '" ~ methodHeader
				~ "' does not match body method '" ~ msg.method ~ "'");

	// When the MCP-Protocol-Version header IS present it must match the body's
	// _meta protocol version. A body-only-draft request (absent header) is a valid
	// draft negotiation, so an empty header is not a mismatch.
	auto bodyMeta = RequestMeta.fromParams(msg.params);
	if (protoHeader.length && bodyMeta.protocolVersion.length
			&& bodyMeta.protocolVersion != protoHeader)
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
	return h == "localhost" || h == "127.0.0.1" || h == "::1";
}

/// Whether the server is bound to a public (non-loopback) address while accepting
/// no extra Host values — the configuration in which the DNS-rebinding guard
/// rejects every external request with 403. Used to warn at startup.
private bool publicBindWithoutAllowlist(const string[] bindAddresses, const string[] allowedHosts) @safe
{
	if (allowedHosts.length)
		return false;
	foreach (a; bindAddresses)
		if (!isLoopbackHostname(a))
			return true;
	return false;
}

/// Translate the transport-level `opts` into a vibe.d `HTTPServerSettings`:
/// listen address, plus access logging when `opts.accessLog` is set (to
/// `opts.accessLogFile` if given, otherwise the console). Access logging stays
/// off unless explicitly opted in.
private HTTPServerSettings buildStreamableHttpSettings(ushort port, StreamableHttpOptions opts) @safe
{
	auto settings = new HTTPServerSettings;
	settings.port = port;
	settings.bindAddresses = opts.bindAddresses;
	if (opts.accessLog)
	{
		if (opts.accessLogFile.length)
			settings.accessLogFile = opts.accessLogFile;
		else
			settings.accessLogToConsole = true;
	}
	return settings;
}

/// Start a standalone Streamable HTTP server for `server` on `port` and run the
/// vibe.d event loop. Blocks until the application exits.
void runStreamableHttp(McpServer server, ushort port,
		StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
	import vibe.core.core : runEventLoop, lowerPrivileges;
	import vibe.core.log : logWarn;
	import std.array : join;

	if (publicBindWithoutAllowlist(opts.bindAddresses, opts.allowedHosts))
		logWarn("Streamable HTTP bound to a public address (%s) with an empty "
				~ "allowedHosts: the DNS-rebinding guard will reject external requests "
				~ "with 403. Set StreamableHttpOptions.allowedHosts to your public host(s).",
				opts.bindAddresses.join(", "));

	auto router = new URLRouter;
	mountMcp(router, server, opts);

	auto settings = buildStreamableHttpSettings(port, opts);
	auto listener = listenHTTP(settings, router);
	scope (exit)
		listener.stopListening();

	lowerPrivileges();
	runEventLoop();
}

/// Convenience: start a Streamable HTTP server for `server` on `port`, bound to
/// a single `host`. Sets `StreamableHttpOptions.bindAddresses = [host]` and
/// forwards to `runStreamableHttp(server, port, opts)`. Blocks until exit.
void runStreamableHttp(McpServer server, ushort port, string host) @safe
{
	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	runStreamableHttp(server, port, opts);
}

/// Start a Streamable HTTP server fully described by `opts` (listening on
/// `opts.port`). The single-struct form of `runStreamableHttp`, used by the
/// `ServerSettings`-based entry point. Blocks until exit.
void runStreamableHttp(McpServer server, StreamableHttpOptions opts) @safe
{
	runStreamableHttp(server, opts.port, opts);
}

unittest  // a public bind with no allowedHosts is flagged (would 403 external hosts)
{
	// 0.0.0.0 / :: are wildcard (public) binds; with an empty allowlist the
	// DNS-rebinding guard rejects every non-loopback Host.
	assert(publicBindWithoutAllowlist(["0.0.0.0"], []));
	assert(publicBindWithoutAllowlist(["::"], []));
	assert(publicBindWithoutAllowlist(["10.0.0.5", "127.0.0.1"], []));
	// Loopback-only binds are fine without an allowlist.
	assert(!publicBindWithoutAllowlist(["127.0.0.1"], []));
	assert(!publicBindWithoutAllowlist(["localhost"], []));
	// An allowlist resolves the public-bind case.
	assert(!publicBindWithoutAllowlist(["0.0.0.0"], ["myapp.fly.dev"]));
}

unittest  // access logging is off by default
{
	StreamableHttpOptions opts;
	assert(!opts.accessLog);
	assert(opts.accessLogFile == "");
}

unittest  // accessLog routes per-request lines to the console
{
	StreamableHttpOptions opts;
	opts.accessLog = true;
	auto settings = buildStreamableHttpSettings(cast(ushort) 8080, opts);
	assert(settings.accessLogToConsole);
	assert(settings.accessLogFile == "");
}

unittest  // accessLogFile sends lines to the file instead of the console
{
	StreamableHttpOptions opts;
	opts.accessLog = true;
	opts.accessLogFile = "/var/log/mcp.log";
	auto settings = buildStreamableHttpSettings(cast(ushort) 8080, opts);
	assert(!settings.accessLogToConsole);
	assert(settings.accessLogFile == "/var/log/mcp.log");
}

unittest  // accessLogFile alone (without accessLog) emits nothing
{
	StreamableHttpOptions opts;
	opts.accessLogFile = "/var/log/mcp.log";
	auto settings = buildStreamableHttpSettings(cast(ushort) 8080, opts);
	assert(!settings.accessLogToConsole);
	assert(settings.accessLogFile == "");
}

unittest  // port and bind addresses still flow through unchanged
{
	StreamableHttpOptions opts;
	opts.bindAddresses = ["0.0.0.0"];
	auto settings = buildStreamableHttpSettings(cast(ushort) 9090, opts);
	assert(settings.port == 9090);
	assert(settings.bindAddresses == ["0.0.0.0"]);
}

unittest  // runStreamableHttp(server, port, host) overload exists and forwards
{
	// Compile-only: a full run blocks on the event loop and isn't unit-testable.
	// Assert the single-host overload is callable (and that the existing
	// options overload still is, so we didn't shadow it).
	static assert(__traits(compiles, (McpServer s) {
			runStreamableHttp(s, cast(ushort) 8080, "0.0.0.0");
		}));
	static assert(__traits(compiles, (McpServer s) {
			runStreamableHttp(s, cast(ushort) 8080, StreamableHttpOptions.init);
		}));
}

unittest  // legacy endpoint event: `event: endpoint` carrying the message-POST URI
{
	// 2024-11-05 basic/transports §HTTP with SSE: "When a client connects, the
	// server MUST send an `endpoint` event containing a URI for the client to use
	// for sending messages." The frame is a typed SSE `endpoint` event whose data
	// is that URI.
	const frame = formatLegacyEndpointEvent("/message");
	assert(frame == "event: endpoint\ndata: /message\n\n");
}

unittest  // legacy server messages are SSE `message` events with JSON data
{
	// 2024-11-05 basic/transports §HTTP with SSE: "Server messages are sent as SSE
	// `message` events, with the message content encoded as JSON in the event
	// data." The frame is a typed SSE `message` event carrying the JSON-RPC payload.
	import std.string : startsWith, endsWith;
	import std.algorithm : canFind;

	auto j = makeNotification("notifications/message", Json.emptyObject);
	const frame = formatLegacyMessageEventRaw(j.toString());
	assert(frame.startsWith("event: message\ndata: "));
	assert(frame.canFind("\"method\":\"notifications/message\""));
	assert(frame.endsWith("\n\n"));
}

unittest  // legacy channel: GET stream first receives the endpoint event, then messages
{
	// The legacy SSE GET stream MUST emit the `endpoint` event first (so the
	// client learns where to POST), then deliver each subsequent server message as
	// a `message` event on the open stream.
	import std.string : startsWith;
	import std.algorithm : canFind;

	auto ch = new LegacySseChannel("/message");
	string[] frames;
	const id = ch.addListener((string f) @safe { frames ~= f; });
	// On connect the channel emits the endpoint event naming the POST path, now
	// carrying the per-stream session token so replies can be correlated back.
	assert(frames.length == 1);
	const sid = ch.sessionIdFor(id);
	assert(sid.length > 0);
	assert(frames[0] == "event: endpoint\ndata: /message?sessionId=" ~ sid ~ "\n\n");

	// A server response routed to this stream's token arrives as a `message` event.
	ch.deliverTo(sid, `{"jsonrpc":"2.0","id":1,"result":{}}`);
	assert(frames.length == 2);
	assert(frames[1].startsWith("event: message\ndata: "));
	assert(frames[1].canFind("\"id\":1"));
	ch.removeListener(id);
	assert(ch.listenerCount == 0);
}

unittest  // legacy POST: a request is processed and its response pushed onto the SSE stream
{
	// The legacy two-endpoint transport: the client POSTs a JSON-RPC request to
	// the message endpoint; the server processes it and delivers the response back
	// over the open GET SSE stream (not in the POST response body). A notification
	// produces no response frame.
	import std.algorithm : canFind;

	auto server = new McpServer("t", "1");
	auto ch = new LegacySseChannel("/message");
	string[] frames;
	const id = ch.addListener((string f) @safe { frames ~= f; });
	assert(frames.length == 1); // the endpoint event
	const sid = ch.sessionIdFor(id);

	// A request: the response is pushed onto the originating stream as a `message`
	// event, routed by the per-stream session token.
	const accepted = handleLegacyPostBody(server, ch, sid,
			`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	assert(accepted); // the server accepted the message
	assert(frames.length == 2);
	assert(frames[1].canFind("\"id\":1"));

	// A notification: accepted, but nothing is pushed back.
	const accepted2 = handleLegacyPostBody(server, ch, sid,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
	assert(accepted2);
	assert(frames.length == 2); // no new frame
}

unittest  // legacy POST: a handler that calls ctx.listRoots() sends the request on the SSE stream
{
	// A handler may issue a server->client request (roots/list, sampling, elicitation).
	// On the legacy HTTP+SSE transport, handleLegacyPostBody must wire a serverRequest
	// delegate so the outbound request is pushed onto the originating GET SSE stream
	// and the client's reply POST is correlated back to the blocked handler.
	import std.algorithm : canFind;
	import vibe.core.core : runTask, yield;
	import vibe.data.json : parseJsonString;
	import mcp.protocol.types : Tool, CallToolResult;

	auto server = McpServer.stateful("t", "1");
	// Register a tool whose handler issues a roots/list server->client request.
	Tool descriptor;
	descriptor.name = "roottool";
	server.registerTool(descriptor, (Json args, RequestContext ctx) @safe {
		ctx.listRootsRaw(); // blocks until client replies; bypasses capability check
		CallToolResult r;
		return ToolResponse.complete(r);
	});

	auto ch = new LegacySseChannel("/message");
	string[] frames;
	const id = ch.addListener((string f) @safe { frames ~= f; });
	const sid = ch.sessionIdFor(id);
	assert(frames.length == 1); // endpoint event only

	// The tool call is dispatched in a task so it can block on the roots/list reply.
	bool done;
	runTask(() nothrow{
		try
		{
			cast(void) handleLegacyPostBody(server, ch, sid, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"roottool","arguments":{}}}`);
		}
		catch (Exception)
		{
		}
		finally
			done = true;
	});
	// Yield so the task runs and the handler blocks awaiting the roots/list reply.
	yield();
	// The handler must have sent the roots/list request as an SSE message event.
	assert(frames.length == 2, "expected roots/list request on SSE stream");
	assert(frames[1].canFind("roots/list"), "SSE frame must contain roots/list");

	// Parse the server->client request id from the SSE frame so we can correlate
	// the client's reply POST back to the blocked handler.
	const reqFrame = frames[1]["event: message\ndata: ".length .. $ - 2]; // strip SSE wrapper
	auto reqJson = parseJsonString(reqFrame);
	const serverReqId = reqJson["id"];

	// Client POSTs back a roots/list response; handleLegacyPostBody routes it to
	// the coordinator, waking the blocked handler.
	Json resp = Json.emptyObject;
	resp["jsonrpc"] = "2.0";
	resp["id"] = serverReqId;
	resp["result"] = Json(["roots": Json.emptyArray]);
	cast(void) handleLegacyPostBody(server, ch, sid, resp.toString());

	// Drain until the handler task completes and delivers the tool result.
	foreach (_; 0 .. 4096)
	{
		if (done)
			break;
		yield();
	}
	assert(done, "handler task must complete after receiving the roots/list reply");
	// The tool-call response must now appear on the SSE stream.
	assert(frames.length == 3, "expected tool-call response on SSE stream");
	assert(frames[2].canFind("\"id\":10"), "tool response must echo the original request id");
}

unittest  // legacy channel: a response routes only to the originating stream, not all clients
{
	// Two concurrent legacy clients each get a distinct per-stream session token in
	// their `endpoint` event. A response delivered for one client's token MUST reach
	// only that client's stream — never the other's (a cross-session response leak).
	import std.algorithm : canFind;

	auto ch = new LegacySseChannel("/message");
	string[] framesA;
	string[] framesB;
	const idA = ch.addListener((string f) @safe { framesA ~= f; });
	const idB = ch.addListener((string f) @safe { framesB ~= f; });
	const sidA = ch.sessionIdFor(idA);
	const sidB = ch.sessionIdFor(idB);

	// Distinct tokens, each advertised on its own endpoint event.
	assert(sidA.length > 0 && sidB.length > 0 && sidA != sidB);
	assert(framesA[0].canFind("sessionId=" ~ sidA));
	assert(framesB[0].canFind("sessionId=" ~ sidB));

	// A response for client A reaches A's stream and ONLY A's stream.
	ch.deliverTo(sidA, `{"jsonrpc":"2.0","id":1,"result":{"who":"A"}}`);
	assert(framesA.length == 2);
	assert(framesA[1].canFind("\"who\":\"A\""));
	assert(framesB.length == 1); // B saw only its endpoint event, never A's reply
}

unittest  // legacy channel: an unknown or empty session token delivers nowhere
{
	// A POST that carries no (or a stale) session token must not fall back to a
	// broadcast that would leak the reply onto every open stream.
	auto ch = new LegacySseChannel("/message");
	string[] frames;
	ch.addListener((string f) @safe { frames ~= f; });
	assert(frames.length == 1); // endpoint event only

	ch.deliverTo("", `{"jsonrpc":"2.0","id":1,"result":{}}`);
	ch.deliverTo("not-a-real-token", `{"jsonrpc":"2.0","id":2,"result":{}}`);
	assert(frames.length == 1); // nothing delivered to the open stream
}

unittest  // addListener does not leave a zombie entry when the initial write throws
{
	// If the delegate write throws on the first call (e.g., the client disconnected
	// between sending the GET and the server flushing the endpoint event), the
	// listener must not remain in the channel's listener array.
	auto ch = new LegacySseChannel("/message");
	bool threw = false;
	try
		ch.addListener((string) @safe { throw new Exception("write failed"); });
	catch (Exception)
		threw = true;
	assert(threw, "write exception must propagate to the caller");
	assert(ch.listenerCount == 0, "failed-write listener must not remain in the channel");
}

unittest  // legacy channel: each connected client gets its own isolated ConnectionState
{
	// Two concurrent legacy clients must not share a ConnectionState. Sharing one
	// causes one client's initialize (which writes conn.negotiated / conn.clientCaps)
	// to overwrite the other client's in-flight state. Each listener registered with
	// LegacySseChannel must own a distinct ConnectionState instance.
	import std.algorithm : canFind;

	auto ch = new LegacySseChannel("/message");
	string[] framesA;
	string[] framesB;
	const idA = ch.addListener((string f) @safe { framesA ~= f; });
	const idB = ch.addListener((string f) @safe { framesB ~= f; });
	const sidA = ch.sessionIdFor(idA);
	const sidB = ch.sessionIdFor(idB);

	auto stateA = ch.connStateFor(sidA);
	auto stateB = ch.connStateFor(sidB);

	// Each listener must have its own ConnectionState (not the same object).
	assert(stateA !is null, "client A must have a ConnectionState");
	assert(stateB !is null, "client B must have a ConnectionState");
	assert(stateA !is stateB, "two concurrent legacy clients must not share one ConnectionState");

	// Mutating one client's state must not affect the other.
	import mcp.protocol.versions : ProtocolVersion;

	stateA.negotiated = ProtocolVersion.v2025_03_26;
	assert(stateB.negotiated != ProtocolVersion.v2025_03_26,
			"client B's negotiated version must be independent of client A's");
}

unittest  // endpointWithSession appends the session token, preserving any existing query
{
	assert(endpointWithSession("/message", "abc") == "/message?sessionId=abc");
	assert(endpointWithSession("/message?x=1", "abc") == "/message?x=1&sessionId=abc");
}

unittest  // legacy support is opt-in: off by default
{
	StreamableHttpOptions opts;
	assert(!opts.legacyHttpSse);
	assert(opts.legacySsePath == "/sse");
	assert(opts.legacyMessagePath == "/message");
}

unittest  // legacy GET write serialization keeps concurrent SSE frames non-interleaved
{
	// LegacySseChannel.deliver has no write serialization, so two
	// concurrent deliveries to one legacy listener could interleave SSE frame bytes
	// when the underlying socket write yields. handleLegacyGet routes every write --
	// the listener writer AND the heartbeat -- through one per-stream TaskMutex
	// (writeFrame), so a write that yields mid-frame cannot be cut into by another
	// writer. This test models that writeFrame and proves the mutex prevents
	// interleaving even when the write yields between its two halves.
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
	import vibe.core.sync : TaskMutex;
	import core.time : msecs;

	auto writeMtx = new TaskMutex;
	string log;
	// A write that yields between writing the frame's head and tail: without the
	// lock a second writer would slot its bytes into the gap.
	void writeFrame(string head, string tail) @safe
	{
		() @trusted {
			synchronized (writeMtx)
			{
				log ~= head;
				sleep(5.msecs); // yield mid-frame
				log ~= tail;
			}
		}();
	}

	runTask(() nothrow{
		try
		{
			auto t1 = runTask(() nothrow{
				try
					writeFrame("[A", "A]");
				catch (Exception)
				{
				}
			});
			auto t2 = runTask(() nothrow{
				try
					writeFrame("[B", "B]");
				catch (Exception)
				{
				}
			});
			t1.join();
			t2.join();
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();

	// Each frame's head and tail are adjacent (no foreign bytes between them):
	// the only valid serializations are "[AA][BB]" or "[BB][AA]".
	assert(log == "[AA][BB]" || log == "[BB][AA]", "legacy SSE frames interleaved: " ~ log);
}

unittest  // localhost hosts are accepted, foreign hosts rejected
{
	assert(hostAllowed("127.0.0.1:3000", []));
	assert(hostAllowed("localhost", []));
	assert(hostAllowed("[::1]:8080", []));
	assert(!hostAllowed("evil.example.com", []));
	assert(hostAllowed("myhost", ["myhost"]));
}

unittest  // an empty Host is rejected (closes the no-Host/no-Origin guard bypass)
{
	// guardOrigin no longer short-circuits on an empty Host, so it relies on
	// hostAllowed("") being false: a request carrying neither Host nor Origin must
	// not slip past the DNS-rebinding guard.
	assert(!hostAllowed("", []));
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
	assert(validateDraftHeaders("", "", "", m, false) is null);
	assert(validateDraftHeaders("2025-11-25", "", "", m, false) is null);
}

unittest  // draft request missing Mcp-Method is a header mismatch
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "", "", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft request with mismatched Mcp-Method fails
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "tools/call", "", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft tools/list with correct headers passes
{
	auto m = draftMsg("tools/list", Json.emptyObject);
	assert(validateDraftHeaders("2026-07-28", "tools/list", "", m, true) is null);
}

unittest  // draft tools/call requires matching Mcp-Name
{
	Json p = Json.emptyObject;
	p["name"] = "add";
	auto m = draftMsg("tools/call", p);
	assert(validateDraftHeaders("2026-07-28", "tools/call", "add", m, true) is null);
	auto e = validateDraftHeaders("2026-07-28", "tools/call", "wrong", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
	auto e2 = validateDraftHeaders("2026-07-28", "tools/call", "", m, true);
	assert(e2 !is null); // missing name
}

unittest  // draft resources/read mirrors uri into Mcp-Name
{
	Json p = Json.emptyObject;
	p["uri"] = "test://x";
	auto m = draftMsg("resources/read", p);
	assert(validateDraftHeaders("2026-07-28", "resources/read", "test://x", m, true) is null);
	assert(validateDraftHeaders("2026-07-28", "resources/read", "test://y", m, true) !is null);
}

unittest  // draft notification with correct Mcp-Method passes (no Mcp-Name required)
{
	// draft basic/transports Standard Request Headers: Mcp-Method is REQUIRED
	// for "All requests and notifications"; Mcp-Name applies only to
	// tools/call, resources/read, prompts/get requests.
	auto m = draftNote("notifications/initialized", Json.emptyObject);
	assert(validateDraftHeaders("2026-07-28", "notifications/initialized", "", m, true) is null);
}

unittest  // draft notification missing Mcp-Method is a header mismatch
{
	auto m = draftNote("notifications/initialized", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "", "", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft notification with mismatched Mcp-Method fails
{
	auto m = draftNote("notifications/cancelled", Json.emptyObject);
	auto e = validateDraftHeaders("2026-07-28", "notifications/initialized", "", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // body-only draft (absent MCP-Protocol-Version header) still enforces Mcp-Method
{
	// The draft is stateless-only and may negotiate via params._meta.protocolVersion
	// alone. A mismatched Mcp-Method/Mcp-Name on such a request MUST still be
	// rejected, even though the MCP-Protocol-Version header is absent.
	Json p = Json.emptyObject;
	p["name"] = "add";
	auto m = draftMsg("tools/call", p); // body _meta carries the draft version
	// absent proto header, but effective-draft flag true: a wrong Mcp-Method fails.
	auto e = validateDraftHeaders("", "tools/call", "wrong", m, true);
	assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // body-only draft with absent header but correct headers passes (no false version mismatch)
{
	// An absent MCP-Protocol-Version header against a body-only-draft request is a
	// valid negotiation: it must not be flagged as a header/_meta version mismatch.
	Json p = Json.emptyObject;
	p["name"] = "add";
	auto m = draftMsg("tools/call", p);
	assert(validateDraftHeaders("", "tools/call", "add", m, true) is null);
}

unittest  // pre-draft notification skips draft header enforcement
{
	auto m = Message(makeNotification("notifications/initialized", Json.emptyObject));
	assert(validateDraftHeaders("2025-11-25", "", "", m, false) is null);
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
	// response.
	auto bad = postProtocolVersionGate("1.0.0");
	assert(bad !is null, "bad header must be rejected for all POST kinds");
	assert(bad.code == ErrorCode.unsupportedProtocolVersion);
	auto j = makeErrorResponse(Json(null), bad);
	assert(httpStatusForResponse(j, false) == 400);
	// a supported / absent header is fine for every kind
	assert(postProtocolVersionGate("2025-11-25") is null);
	assert(postProtocolVersionGate("") is null);
}

unittest  // the standalone GET stream is version-gated like a POST: bad version -> 400, not a 200 stream
{
	// basic/transports §Protocol Version Header: the GET that opens the
	// standalone server->client stream is a subsequent HTTP request, so an
	// invalid/unsupported MCP-Protocol-Version MUST yield 400 Bad Request rather
	// than opening a 200 text/event-stream or a 405. handleGet runs
	// postProtocolVersionGate (the same gate every POST kind runs) ahead of the
	// mode/getOpensSseStream 405 gate and before setting Content-Type, so the
	// rejecting McpException maps to HTTP 400 even for a stateless/draft server.
	auto bad = postProtocolVersionGate("1.0.0");
	assert(bad !is null, "an invalid version on the standalone GET must be rejected");
	assert(bad.code == ErrorCode.unsupportedProtocolVersion);
	auto j = makeErrorResponse(Json(null), bad);
	assert(httpStatusForResponse(j, false) == 400);
	// a supported / absent header opens the stream (gate returns null)
	assert(postProtocolVersionGate("2025-11-25") is null);
	assert(postProtocolVersionGate("") is null);
}

unittest  // DELETE is version-gated like POST/GET: bad version -> 400, not 204/405
{
	// basic/transports §Protocol Version Header: the DELETE that signals session
	// teardown is a subsequent HTTP request, so an invalid/unsupported
	// MCP-Protocol-Version MUST yield 400 Bad Request (a null-id JSON-RPC error)
	// rather than proceeding to a 204 terminate or a 405. The DELETE route runs
	// postProtocolVersionGate after the origin/auth guards and before the
	// deleteTerminatesSession branch, so the rejecting McpException maps to 400.
	auto bad = postProtocolVersionGate("1.0.0");
	assert(bad !is null, "an invalid version on a DELETE must be rejected");
	assert(bad.code == ErrorCode.unsupportedProtocolVersion);
	auto j = makeErrorResponse(Json(null), bad);
	assert(httpStatusForResponse(j, false) == 400);
	// a supported / absent header lets the DELETE proceed (gate returns null)
	assert(postProtocolVersionGate("2025-11-25") is null);
	assert(postProtocolVersionGate("") is null);
}

/// True if the protocol-version header denotes a draft+ request.
private bool tryDraft(string protoHeader) @safe
{
	ProtocolVersion pv;
	return tryParseVersion(protoHeader, pv) && pv.isModern;
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

/// Resolve the per-connection `ConnectionState` for a Streamable HTTP POST
/// request. Stateful HTTP returns the `SessionManager`-owned state
/// for the request's session id — the just-minted id on `initialize`
/// (`mintedSessionId`), otherwise the `Mcp-Session-Id` header (`connToken`).
///
/// Stateless HTTP:
///   - A MODERN-stateless (draft / MRTR) request is fully self-describing: its
///     protocol version, client capabilities, and log level all travel in the
///     request's own `_meta` on EVERY call (there is no `initialize` handshake to
///     remember). So a FRESH per-request `ConnectionState` (`freshStatelessState`)
///     is built from that `_meta` and discarded — nothing is stored across calls,
///     and two such requests can never observe each other's state. This is the
///     structural "no shared state across HTTP calls" guarantee for the stateless
///     protocol that was designed for it.
///   - A pre-draft (stable-version) stateless request belongs to the SDK's single
///     implicit-peer model: a stable client still performs an `initialize`
///     handshake whose negotiated capabilities the server MUST honour on the later
///     `tools/call` over the same connection. There is no per-request `_meta`
///     handshake to rebuild that from, so this path returns `null` and the server
///     falls back to its single bound `activeConnection` — exactly the supported
///     single-client-per-mount deployment (documented in `mcp.transport.session`).
///     Isolating *distinct* stable clients still requires `stateful` mode.
private ConnectionState postState(McpServer server, SessionManager sessions,
		string mintedSessionId, string connToken, string protoHeader, Json params) @safe
{
	if (sessions !is null && sessionsApply(server.negotiatedVersion))
	{
		const id = mintedSessionId.length ? mintedSessionId : connToken;
		return sessions.stateFor(id);
	}
	return freshStatelessState(protoHeader, params, server.negotiatedVersion);
}

/// The client capabilities a `HttpStreamContext` should advertise for a request,
/// taken from the request's resolved `ConnectionState`: the
/// session's negotiated caps (stateful) or the per-request `_meta` caps
/// (modern-stateless draft), so `ctx.clientSupports` reflects THIS connection
/// rather than a sibling's. Falls back to the server's bound view when no state
/// was resolved (pre-draft stateless single-peer / stateful fallback).
private ClientCapabilities clientCapsFor(McpServer server, ConnectionState reqState) @safe
{
	if (reqState !is null)
		return reqState.clientCaps;
	return server.clientCapabilities;
}

/// Build the FRESH per-request `ConnectionState` for a MODERN-stateless (draft /
/// MRTR) HTTP POST, or return `null` for a pre-draft stateless request.
///
/// Only the draft (stateless) protocol is fully self-describing — every request
/// carries its own protocol version, capabilities, and log level in `_meta`, with
/// no `initialize` handshake to remember — so only there can a request be served
/// from a transient state the server retains nowhere. The fresh state is seeded
/// from the request's `_meta` (the per-request
/// `io.modelcontextprotocol/clientCapabilities` / `logLevel`), mirroring how the
/// draft dispatch path already reads them.
///
/// For a pre-draft (stable-version) request this returns `null`: a stable client
/// negotiates capabilities once at `initialize` that the server must honour on
/// later requests over the same connection, which is the single implicit-peer
/// model held in `activeConnection` (the server falls back to it on null). The
/// effective version is the body `_meta.protocolVersion`, then the
/// `MCP-Protocol-Version` header, then the server default. When both the header
/// and `_meta.protocolVersion` are present, `validateDraftHeaders` already
/// ensures they agree, so the final overwrite is always a no-op in practice.
private ConnectionState freshStatelessState(string protoHeader, Json params,
		ProtocolVersion serverDefault) @safe
{
	// Effective version: _meta.protocolVersion wins over the header when present;
	// the header (via effectivePostVersion) is the fallback before the server
	// default. validateDraftHeaders rejects any request where both are present but
	// disagree, so when both exist they are equal and the overwrite is benign.
	auto meta = RequestMeta.fromParams(params);
	ProtocolVersion eff = effectivePostVersion(protoHeader, serverDefault);
	ProtocolVersion mv;
	if (meta.protocolVersion.length && tryParseVersion(meta.protocolVersion, mv))
		eff = mv;
	// Pre-draft stateless: defer to the single implicit-peer `activeConnection`
	// (return null) so an initialize-negotiated capability survives to tools/call.
	if (!eff.isModern)
		return null;
	auto conn = new ConnectionState;
	conn.negotiated = eff;
	conn.clientCaps = meta.clientCapabilities;
	if (!meta.logLevel.isNull)
		conn.logLevel = meta.logLevel.get;
	return conn;
}

unittest  // a pre-draft stateless request defers to activeConnection (null)
{
	import vibe.data.json : Json;

	// A stable-version request has no per-request _meta handshake to rebuild a
	// transient state from, so freshStatelessState returns null and dispatch falls
	// back to the single bound activeConnection (the supported single-peer model).
	assert(freshStatelessState("2025-11-25", Json.emptyObject, ProtocolVersion.v2025_11_25) is null);
	// Absent header + no _meta version -> server default (stable) -> still null.
	assert(freshStatelessState("", Json.emptyObject, ProtocolVersion.v2025_11_25) is null);
}

unittest  // a modern (draft/MRTR) stateless request gets a FRESH state from _meta
{
	import vibe.data.json : parseJsonString;
	import mcp.protocol.mrtr : MetaKey;

	// The draft request carries its capabilities + log level in _meta; the fresh
	// per-request state is built from them and retained nowhere.
	auto params = parseJsonString(
			`{"_meta":{` ~ `"io.modelcontextprotocol/clientCapabilities":{"sampling":{}},`
			~ `"io.modelcontextprotocol/logLevel":"warning"}}`);
	auto conn = freshStatelessState("2026-07-28", params, ProtocolVersion.v2025_11_25);
	assert(conn !is null);
	assert(conn.negotiated.isModern);
	assert(conn.clientCaps.sampling, "modern-stateless caps must come from the request _meta");
	assert(conn.logLevel == "warning");
}

unittest  // two modern-stateless requests resolve to INDEPENDENT states
{
	import vibe.data.json : parseJsonString;

	// Two draft requests with different _meta capabilities must yield distinct
	// ConnectionState objects: there is no shared state across the two HTTP calls.
	auto pA = parseJsonString(
			`{"_meta":{"io.modelcontextprotocol/clientCapabilities":{"sampling":{}}}}`);
	auto pB = parseJsonString(
			`{"_meta":{"io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}}`);
	auto a = freshStatelessState("2026-07-28", pA, ProtocolVersion.v2025_11_25);
	auto b = freshStatelessState("2026-07-28", pB, ProtocolVersion.v2025_11_25);
	assert(a !is b, "each stateless request must get its own ConnectionState");
	assert(a.clientCaps.sampling && !a.clientCaps.elicitation);
	assert(b.clientCaps.elicitation && !b.clientCaps.sampling,
			"request B must not observe request A's capabilities");
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
	assert(!streamableBatchAllowed(ProtocolVersion.modern));
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
	// The transport must surface a -32600 invalidRequest on HTTP 400 (not an
	// error riding on HTTP 200) when an array body arrives on a version that
	// forbids batching.
	auto v = effectivePostVersion("2025-11-25", ProtocolVersion.v2025_11_25);
	assert(!streamableBatchAllowed(v));
	auto e = invalidRequest(
			"JSON-RPC batching is not supported on protocol version 2025-06-18 and later");
	assert(e.code == ErrorCode.invalidRequest);
	auto j = makeErrorResponse(Json(null), e);
	assert(j["error"]["code"].get!int == ErrorCode.invalidRequest);
}

unittest  // an unparseable / non-envelope POST body throws so handlePost answers 400
{
	// basic/transports: a POST whose body is not parseable JSON, or is JSON but
	// not a valid JSON-RPC envelope, is answered with HTTP 400. handlePost wraps
	// parseAny in try/catch and, on failure, sets statusCode = badRequest before
	// writing the JSON-RPC error body. This asserts the trigger the fix relies on:
	// parseAny throws a parseError (-32700) for invalid JSON and an invalidRequest
	// (-32600) for a body that is not a valid JSON-RPC envelope, and that those
	// codes carry into the error response body the handler writes alongside the 400.
	import std.exception : assertThrown, collectException;

	auto badJson = collectException!McpException(parseAny("not json at all"));
	assert(badJson !is null, "unparseable JSON must throw");

	auto badEnvelope = collectException!McpException(parseAny(`{"id":1,"method":"ping"}`));
	assert(badEnvelope !is null, "a body missing the jsonrpc field must throw");
	assert(badEnvelope.code == ErrorCode.invalidRequest);
	auto body_ = makeErrorResponse(Json(null), badEnvelope);
	assert(body_["error"]["code"].get!int == ErrorCode.invalidRequest);
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

unittest  // only a draft events/stream opens the push response
{
	assert(opensEventsStream("events/stream", true));
	assert(!opensEventsStream("events/stream", false));
	assert(!opensEventsStream("events/poll", true));
	assert(!opensEventsStream("subscriptions/listen", true));
}

unittest  // eventStreamSleepMs: emit-only sleeps the heartbeat interval, poll clamps to [1s, 15s]
{
	// An emit-only stream wakes only on the heartbeat cadence.
	assert(eventStreamSleepMs(true, 1_000) == eventStreamHeartbeatIntervalMs);
	assert(eventStreamSleepMs(true, 60_000) == eventStreamHeartbeatIntervalMs);
	// A fast poll cadence floors at 1s.
	assert(eventStreamSleepMs(false, 100) == 1_000);
	// A mid-range cadence is used as-is.
	assert(eventStreamSleepMs(false, 5_000) == 5_000);
	// A slow poll cadence is capped at the heartbeat interval.
	assert(eventStreamSleepMs(false, 60_000) == eventStreamHeartbeatIntervalMs);
}

unittest  // eventStreamTick: poll only for non-emit-only; heartbeat only once the cadence elapses
{
	// Emit-only never polls; heartbeats once due.
	assert(!eventStreamTick(true, 0).poll);
	assert(!eventStreamTick(true, eventStreamHeartbeatIntervalMs - 1).heartbeat);
	assert(eventStreamTick(true, eventStreamHeartbeatIntervalMs).heartbeat);
	// Poll-driven always polls; heartbeats only at/after the cadence boundary.
	assert(eventStreamTick(false, 0).poll);
	assert(!eventStreamTick(false, eventStreamHeartbeatIntervalMs - 1).heartbeat);
	assert(eventStreamTick(false, eventStreamHeartbeatIntervalMs).heartbeat);
	assert(eventStreamTick(false, eventStreamHeartbeatIntervalMs * 2).heartbeat);
}

version (unittest) private HTTPServerRequest makeInitPostReq(string body_,
		string[string] headers = null) @safe
{
	import vibe.http.server : createTestHTTPServerRequest;
	import vibe.http.common : HTTPMethod;
	import vibe.inet.url : URL;
	import vibe.stream.memory : createMemoryStream;

	auto buf = () @trusted { return cast(ubyte[]) body_.dup; }();
	auto req = createTestHTTPServerRequest(URL("http://127.0.0.1/mcp"),
			HTTPMethod.POST, createMemoryStream(buf, false));
	req.headers["Host"] = "127.0.0.1";
	req.headers["Content-Type"] = "application/json";
	if (headers !is null)
		foreach (k, v; headers)
			req.headers[k] = v;
	return req;
}

version (unittest) private string initializeBody(string ver = "2025-11-25") @safe
{
	return `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` ~ `"protocolVersion":"`
		~ ver ~ `","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`;
}

unittest  // a successful stateful initialize commits the Mcp-Session-Id header
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.router : URLRouter;
	import vibe.stream.memory : createMemoryOutputStream;

	auto server = McpServer.stateful("t", "1");
	auto router = new URLRouter;
	mountMcp(router, server);

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto req = makeInitPostReq(initializeBody(), [
		"Accept": "application/json, text/event-stream"
	]);
	router.handleRequest(req, res);

	// The session id is committed only on a successful InitializeResult.
	assert(SessionHeader in res.headers, "a successful initialize MUST carry Mcp-Session-Id");
	assert(res.headers[SessionHeader].length > 0);
}

unittest  // an initialize that fails header validation mints no surviving session and no header
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.router : URLRouter;
	import vibe.stream.memory : createMemoryOutputStream;

	auto server = McpServer.stateful("t", "1");
	auto router = new URLRouter;
	mountMcp(router, server);

	// A draft-tagged initialize whose Mcp-Method header mismatches the body method
	// fails validatePostRequestHeaders -> 400, exercising the rollback path: the
	// minted session must be terminated and NO Mcp-Session-Id stamped on the error.
	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto req = makeInitPostReq(initializeBody("2026-07-28"),
			[
				"Accept": "application/json, text/event-stream",
				HttpHeader.protocolVersion: "2026-07-28",
				HttpHeader.method: "tools/list",
	]);
	router.handleRequest(req, res);

	assert(res.statusCode == HTTPStatus.badRequest);
	assert(SessionHeader !in res.headers,
			"a failed initialize MUST NOT stamp Mcp-Session-Id on the error response");
}

unittest  // a POST request whose Accept excludes both media types is rejected with 406
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.router : URLRouter;
	import vibe.stream.memory : createMemoryOutputStream;

	auto server = McpServer.stateful("t", "1");
	auto router = new URLRouter;
	mountMcp(router, server);

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	// Accept names a media type but provably excludes both application/json and
	// text/event-stream -> 406, before any session is minted.
	auto req = makeInitPostReq(initializeBody(), ["Accept": "text/plain"]);
	router.handleRequest(req, res);

	assert(res.statusCode == HTTPStatus.notAcceptable);
	assert(SessionHeader !in res.headers);
}

unittest  // an events/stream POST whose Accept excludes text/event-stream is 406
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.http.router : URLRouter;
	import vibe.stream.memory : createMemoryOutputStream;

	auto server = McpServer.stateless("t", "1");
	server.enableEvents();
	auto router = new URLRouter;
	mountMcp(router, server);

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	// events/stream always opens a text/event-stream response. An Accept that admits
	// application/json (so it passes the both-excluded gate) but provably excludes
	// text/event-stream cannot read the stream, so the upgrade is refused with 406.
	const body_ = `{"jsonrpc":"2.0","id":1,"method":"events/stream","params":{`
		~ `"name":"x","_meta":{"protocolVersion":"2026-07-28"}}}`;
	auto req = makeInitPostReq(body_, [
		"Accept": "application/json",
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method": "events/stream"
	]);
	router.handleRequest(req, res);
	assert(res.statusCode == HTTPStatus.notAcceptable);
}

/// Build the leading event the transport sends when it opens a
/// `subscriptions/listen` stream: a `notifications/subscriptions/acknowledged`
/// notification carrying the agreed-upon subset of change-notification types the
/// server will deliver on the stream (draft basic/utilities/subscriptions). The
/// `subset` is what `McpServer.acknowledgedSubsetFor` reported for that one
/// stream's filter (each subscription is independent — §Multiple Concurrent
/// Subscriptions).
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
	import mcp.protocol.mrtr : encodeHeaderValue;

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

unittest  // MissingRequiredClientCapability maps to HTTP 400 on any modern version
{
	auto r = errResponse(ErrorCode.missingRequiredClientCapability);
	assert(httpStatusForResponse(r, true) == 400);
	assert(httpStatusForResponse(r, false) == 400);
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
	import mcp.protocol.mrtr : MetaKey;
	import std.algorithm : canFind;

	auto server = new McpServer("t", "1");
	// The server must advertise the tools list-changed capability for the
	// toolsListChanged opt-in to be honored (draft basic/utilities/subscriptions).
	server.enableToolsListChanged();

	// Drive the server onto the draft via a draft subscriptions/listen request,
	// mirroring what handleListenStream does: record the opted-in filters.
	Json listenParams = Json.emptyObject;
	listenParams["toolsListChanged"] = true;
	auto m = draftMsg("subscriptions/listen", listenParams);
	auto reqState = freshStatelessState("2026-07-28", m.params, server.negotiatedVersion);
	assert(routeListenRequest(server, m, reqState, "").isNull);
	assert(reqState.listenFilter.toolsListChanged);
	assert(!reqState.listenFilter.resourcesListChanged);

	// The listen stream registers as a push-channel listener (carrying the listen
	// request's id as the stream's subscriptionId, and its OWN active per-stream
	// filter — exactly as handleListenStream does) and receives the ack. Delivery
	// onto the stream is decided by that filter.
	auto coord = new StreamCoordinator;
	auto push = ensurePushChannel(server, coord);
	string[] frames;
	ListenFilter streamFilter;
	streamFilter.active = true;
	streamFilter.toolsListChanged = true;
	const lid = push.addListener((string f) @safe { frames ~= f; }, rpcIdString(m.id), streamFilter);
	push.emitTo(lid, subscriptionsAcknowledgedNotification(
			server.acknowledgedSubsetFor(reqState.listenFilter)));
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
