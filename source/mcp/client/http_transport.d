module mcp.client.http_transport;

import core.time : Duration, seconds;
import std.algorithm : canFind;
import std.string : startsWith;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8, readLine;
import vibe.core.net : TCPConnection, connectTCP;
import vibe.stream.tls : createTLSContext, createTLSStream, TLSContextKind, TLSPeerValidationMode;
import vibe.stream.wrapper : ProxyStream, createProxyStream;
import vibe.core.sync : LocalManualEvent, createManualEvent, LocalTaskSemaphore;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.mrtr : isHeaderValueUnsafe;
import mcp.client.transport : ClientTransport, ClientProtocol;
import mcp.client.subscription : SubscriptionStream;

/// A request rejected at the HTTP layer: the server answered with a non-success
/// status and no JSON-RPC response for the request. `status` is the HTTP status
/// code. A 400/404/405 raised while `McpClient.connect` probes the server is the
/// backward-compatibility trigger; a 404 on a request that carried an
/// `Mcp-Session-Id` means the session expired (the transport drops the id so the
/// next `initialize` starts a new session).
///
/// When the body carried a JSON-RPC error, `code`/`msg`/`data` are that error's;
/// otherwise `code` is `internalError`. `wwwAuthenticate` is the response's
/// `WWW-Authenticate` challenge (empty when absent), which a 401/403 carries so
/// the caller can refresh or step up its token.
class HttpStatusException : McpException
{
	int status;
	string wwwAuthenticate;

	this(int status, string message, string wwwAuthenticate = null) @safe
	{
		this(status, ErrorCode.internalError, message, Json.undefined, wwwAuthenticate);
	}

	this(int status, int code, string message, Json data, string wwwAuthenticate) @safe
	{
		super(code, message, data);
		this.status = status;
		this.wwwAuthenticate = wwwAuthenticate;
	}
}

/// Build the `HttpStatusException` for a non-success HTTP `status` whose response
/// `body` is not a usable JSON-RPC response: a JSON-RPC error in the body keeps its
/// code, message and data; any other body yields a generic HTTP error.
HttpStatusException httpStatusError(int status, string body, string wwwAuthenticate) @safe
{
	import std.conv : to;

	try
	{
		auto m = parseMessage(body);
		if (m.kind == MessageKind.errorResponse && m.error.type == Json.Type.object)
		{
			auto e = m.error;
			const code = ("code" in e && e["code"].type == Json.Type.int_) ? e["code"]
				.get!int : ErrorCode.internalError;
			const msg = ("message" in e && e["message"].type == Json.Type.string) ? e["message"]
				.get!string : "HTTP " ~ status.to!string;
			return new HttpStatusException(status, code, msg, ("data" in e)
					? e["data"] : Json.undefined, wwwAuthenticate);
		}
	}
	catch (Exception)
	{
	}
	return new HttpStatusException(status,
			"HTTP " ~ status.to!string ~ " from the MCP endpoint with no JSON-RPC response",
			wwwAuthenticate);
}

/// A handle to the live socket of a `subscriptions/listen` background stream,
/// shared between the stream's task (which `attach`es its socket once connected)
/// and the `SubscriptionStream.onCancel` delegate (which `closeSocket`s it). A
/// blocked `readLine`/`conn.read` on the parked stream returns immediately once
/// the socket is closed, so cancellation tears the connection down promptly
/// rather than waiting for the next server event.
private final class ListenSocketSlot
{
	import vibe.core.net : TCPConnection;

	private TCPConnection sock;
	private bool open;

	/// Record the connected socket. If a cancel already arrived (`closeSocket`
	/// ran before the task connected), close immediately.
	void attach(TCPConnection s) @trusted nothrow
	{
		if (closed)
		{
			try
				s.close();
			catch (Exception)
			{
			}
			return;
		}
		sock = s;
		open = true;
	}

	private bool closed;

	/// Force-close the socket (idempotent). Safe to call before `attach`: it sets
	/// a flag so the subsequent `attach` closes the socket on arrival.
	void closeSocket() @trusted nothrow
	{
		closed = true;
		if (open)
		{
			open = false;
			try
				sock.close();
			catch (Exception)
			{
			}
		}
	}
}

/// The abortable state of one in-flight Streamable HTTP request: the socket
/// currently carrying its response (the POST, then any resume GET) and the reason
/// it was aborted, if it was. Aborting closes that socket so a read parked on a
/// silent stream returns at once.
private final class PostRequest
{
	ListenSocketSlot slot;
	McpException aborted;

	void abort(McpException reason) @safe nothrow
	{
		aborted = reason;
		if (slot !is null)
			slot.closeSocket();
	}

	/// Make `s` the socket carrying the response, closing it at once when the
	/// request was already aborted.
	void use(ListenSocketSlot s) @safe nothrow
	{
		slot = s;
		if (aborted !is null)
			s.closeSocket();
	}
}

/// A single in-flight legacy (2024-11-05) request's response slot, owned by the
/// `legacyRpc` call that registered it under its request id. The legacy GET-SSE
/// reader fills `result`/`err` and sets `got` on the matching id; any unmatched
/// message falls through to the inbound dispatcher.
private struct LegacyWaiter
{
	Json result;
	McpException err;
	bool got;
}

/// Per-reader SSE resumption cursor: the most recent `id:`/`retry:` seen while
/// decoding one response stream. Owned by the caller of `readSseBody` (a local in
/// each POST / GET reader path) rather than shared across the transport, so a
/// concurrent reader's `id:`/`retry:` line cannot clobber another stream's
/// resume decision under vibe's cooperative scheduler.
private struct SseCursor
{
	string lastEventId;
	long retryMs;
}

/// A `ClientTransport` over the MCP Streamable HTTP transport.
///
/// Owns the HTTP/SSE machinery: the POST-and-await loop (with SSE resumability),
/// the standalone server->client GET SSE stream, the `subscriptions/listen`
/// stream, session-id capture, the OAuth bearer token, and the legacy
/// 2024-11-05 HTTP+SSE two-endpoint fallback (`legacyMode`). The owning
/// `McpClient` supplies the protocol-derived request headers (version / modern
/// method+name / `Mcp-Param-*`) and the cancelled-response predicate through the
/// `ClientProtocol` it installs via `setProtocol`, so this transport never needs
/// the tool inputSchema cache or modern state.
final class HttpClientTransport : ClientTransport
{
	private string url;
	private string sessionId;
	private string bearerToken;
	private string delegate() @safe bearerProvider;
	// Set after the first plaintext-bearer warning so the cleartext-credential
	// notice is logged at most once per transport instead of on every request.
	private bool warnedInsecureBearer;
	// Legacy HTTP+SSE (2024-11-05) transport state. When `legacyMode` is set,
	// JSON-RPC messages are POSTed to `legacyEndpoint` (discovered from the GET
	// stream's `endpoint` event) and responses arrive on the standalone GET SSE
	// stream rather than on the POST response.
	private bool legacyMode;
	private string legacyEndpoint;
	// Set when the background reader receives an `endpoint` event whose URI is
	// rejected by the SSRF guard (cross-origin). Distinguishes "endpoint received
	// but rejected" from "endpoint not yet received", so `startLegacyFallback` can
	// break its wait loop immediately instead of stalling until the 10s deadline.
	private bool legacyEndpointRejected;
	// Per-request waiters for responses arriving on the legacy GET SSE stream,
	// keyed by request id. Each in-flight `legacyRpc` registers a waiter and polls
	// its own slot, so overlapping or reentrant legacy requests never clobber one
	// another's response (the modern path is already per-call by ref locals).
	private LegacyWaiter*[long] legacyWaiters;
	// Set when a oneway send (notification / server->client reply) is rejected
	// with a session-gone status (404/410): the session no longer exists, so the
	// next request `deliver()` throws a clear "session expired" error rather than
	// silently issuing requests under a dead session. An `initialize` clears it,
	// since it starts a new session.
	private bool sessionExpired;
	// True when the negotiated protocol version is modern (2026-07-28 / modern).
	// The modern removed Last-Event-ID resumption and standalone GET SSE streams;
	// postAndAwait skips resumeViaGet when this is set so the pointless 405
	// round-trip to a modern server is avoided.
	private bool modernProtocol;
	// Set by `close()` to ask the background stream readers to stop between reads;
	// the held sockets are closed so a blocked read returns immediately.
	private shared(bool) closeRequested;
	// Live sockets for the spawned server / legacy background streams, closed by
	// `close()` so a parked `conn.read` unblocks. Guarded for @safe access only on
	// the owning event loop.
	// Slots for the sockets of the standalone server->client SSE stream. Each
	// connect attempt in `runServerStream` registers a slot before connecting and
	// removes it on scope exit; `close()` force-closes every registered slot so a
	// reader parked on `conn.read` unblocks immediately. Tracking the live sockets
	// in a slot array (rather than a single shared field) ensures `close()` tears
	// down every server-stream socket, not only the last one connected.
	private ListenSocketSlot[] serverStreamSlots;
	private TCPConnection legacyStreamSock;
	private bool legacyStreamSockOpen;
	// Slots for the sockets of in-flight `postAndAwaitRaw` POSTs whose response is
	// a long-lived SSE stream. Each POST registers a slot before connecting and
	// removes it on scope exit; `close()` force-closes every registered slot so a
	// POST parked reading the stream unblocks immediately. `ListenSocketSlot`'s
	// `attach`/`closeSocket` are order-independent, closing the window where a
	// `close()` races the `connectTCP` yield.
	private ListenSocketSlot[] postSockets;
	// The abortable state of each in-flight Streamable HTTP request, keyed by its
	// JSON-RPC id, so `abort` can close the socket carrying its response.
	private PostRequest[long] inflightPosts;
	// True while the legacy GET-SSE reader task is running. A `legacyRpc` issued
	// after the reader has exited fails its waiter at once instead of polling for
	// the full timeout, since no response can ever arrive on a dead stream.
	private bool legacyStreamAlive;
	// True while the standalone server->client SSE reader task is running. Makes
	// `startServerStream()` idempotent: a second call while a reader is live is a
	// no-op, so a second standalone stream is never spawned and the live socket
	// slots are never orphaned.
	private bool serverStreamAlive;
	// Event-driven completion for the two legacy-path waits (`startLegacyFallback`
	// endpoint discovery and `legacyRpc` response arrival), replacing fixed 50ms
	// busy-poll loops. The background `runLegacyStream` reader emits it after
	// setting `legacyEndpoint` and after filling a waiter; `close()` emits it so a
	// blocked waiter wakes at once. Each waiter re-checks its own condition after
	// every wake and honors a bounded deadline.
	private LocalManualEvent legacyEvent;
	private bool legacyEventInit;
	// Upper bound on each raw `connectTCP`. A connect that cannot complete within
	// this window (e.g. the local ephemeral-port range is exhausted, so the kernel
	// cannot allocate a source port) fails with a typed error instead of parking
	// the calling fiber forever. Configurable via `setConnectTimeout`.
	private Duration connectTimeout = 30.seconds;

	/// Inbound dispatcher installed by `McpClient` (its `dispatchInbound`),
	/// invoked for notifications and server->client requests on any stream.
	private void delegate(Message) @safe inbound;
	/// The owning client's `ClientProtocol`, installed via `setProtocol`. Supplies
	/// the protocol-derived request headers (`headersFor`) and the
	/// cancelled-response predicate (`isCancelled`), so this transport never needs
	/// the tool inputSchema cache or modern state.
	private ClientProtocol protocol;

	// Optional cap on the number of POSTs in flight at once. Zero (the default)
	// means unlimited: no semaphore is created and every request issues its POST
	// immediately, so existing callers see no behavior change. When positive, a
	// `LocalTaskSemaphore` admits at most this many concurrent POSTs and an excess
	// caller awaits a permit instead of minting another socket, bounding the
	// ephemeral-port / TIME_WAIT pressure a burst of concurrent requests creates.
	private uint maxInFlight;
	private LocalTaskSemaphore inFlightSem;

	this(string url, uint maxInFlight = 0) @safe
	{
		this.url = url;
		this.maxInFlight = maxInFlight;
	}

	void setInboundHandler(void delegate(Message) @safe handler) @safe
	{
		inbound = handler;
	}

	/// Install the owning client's `ClientProtocol`, through which this transport
	/// obtains the protocol-derived request headers and the cancelled-response
	/// predicate, so the modern header/schema logic and the cancellation set stay in
	/// the client.
	void setProtocol(ClientProtocol p) @safe
	{
		protocol = p;
	}

	void setBearerToken(string token) @safe
	{
		bearerToken = token;
		bearerProvider = null;
	}

	void setBearerProvider(string delegate() @safe provider) @safe
	{
		bearerProvider = provider;
		bearerToken = null;
	}

	/// The bearer to attach to the request being built: the provider's current
	/// token when one is installed, else the static token.
	private string currentBearer() @safe
	{
		if (bearerProvider !is null)
			bearerToken = bearerProvider();
		return bearerToken;
	}

	/// Mark whether the negotiated protocol version is modern (2026-07-28 / modern).
	/// When true, `postAndAwait` skips Last-Event-ID resumption via GET because the
	/// modern removed SSE resumability; a modern server responds to such a GET with 405.
	void setModernProtocol(bool modern) @safe
	{
		modernProtocol = modern;
	}

	/// A modern Streamable HTTP client cancels by closing the request's SSE response
	/// stream; the modern sends no `notifications/cancelled` over HTTP. Legacy HTTP
	/// (legacy) still uses the notification.
	bool cancelsByStreamClose() @safe
	{
		return modernProtocol;
	}

	/// Bound each raw `connectTCP` by `timeout`. A connect that cannot complete in
	/// time fails with a typed `McpException` rather than parking indefinitely,
	/// so ephemeral-port exhaustion surfaces as an error the caller can handle.
	void setConnectTimeout(Duration timeout) @safe
	{
		connectTimeout = timeout;
	}

	/// Stop the transport: signal the background stream readers
	/// (server->client, legacy GET) to stop between reads and force-close their
	/// held sockets so any blocked `conn.read` unblocks immediately, terminating
	/// the spawned tasks. A `subscriptions/listen` stream is owned by its
	/// `SubscriptionStream` handle and torn down through `cancel()`.
	void close() @safe
	{
		endSession();
		() @trusted {
			import core.atomic : atomicStore;

			atomicStore(closeRequested, true);
		}();
		// Force-close every standalone server->client SSE socket so a reader parked
		// on `conn.read` unblocks at once, rather than only the most recent socket.
		foreach (slot; serverStreamSlots)
			slot.closeSocket();
		if (legacyStreamSockOpen)
		{
			legacyStreamSockOpen = false;
			() @trusted { legacyStreamSock.close(); }();
		}
		// Force-close every in-flight POST socket so a POST parked reading a
		// long-lived SSE response stream unblocks at once.
		foreach (slot; postSockets)
			slot.closeSocket();
		// Fail any in-flight legacy waiter at once so its `legacyRpc` wait returns
		// immediately instead of waiting out the timeout on a closing transport.
		foreach (id, w; legacyWaiters)
			if (!w.got && w.err is null)
				w.err = internalError("legacy HTTP+SSE transport closing");
		// Wake both the per-request waiters and any pending endpoint-discovery wait.
		notifyLegacy();
	}

	/// Tell a stateful Streamable HTTP server the session is over: `DELETE` the
	/// endpoint with its `Mcp-Session-Id` (basic/transports §Session Management:
	/// clients that no longer need a session SHOULD). Best-effort — a server may
	/// answer 405 (it does not let clients end sessions) and any failure is ignored.
	private void endSession() @safe nothrow
	{
		import mcp.protocol.ssrf : secureRequestHTTP, SsrfPolicy;

		if (sessionId.length == 0 || legacyMode || modernProtocol)
			return;
		const sid = sessionId;
		sessionId = null;
		try
		{
			auto versionHeaders = requestHeaders(Json.undefined);
			secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.DELETE;
				req.headers["Mcp-Session-Id"] = sid;
				if (bearerToken.length)
					req.headers["Authorization"] = "Bearer " ~ bearerToken;
				foreach (k, v; versionHeaders)
					if (!isHeaderValueUnsafe(v))
						req.headers[k] = v;
			}, (scope HTTPClientResponse res) { res.dropBody(); }, connectTimeout);
		}
		catch (Exception)
		{
		}
	}

	private bool closing() @safe
	{
		return () @trusted {
			import core.atomic : atomicLoad;

			return atomicLoad(closeRequested);
		}();
	}

	/// Lazily create the legacy-path completion event (a `LocalManualEvent` must be
	/// constructed on the event loop, not at field-init time) and return it.
	private ref LocalManualEvent legacyCompletionEvent() @safe
	{
		if (!legacyEventInit)
		{
			legacyEvent = createManualEvent();
			legacyEventInit = true;
		}
		return legacyEvent;
	}

	/// Wake any legacy-path waiter blocked in `legacyCompletionEvent`. Called by the
	/// background reader after it makes progress (endpoint discovered / waiter
	/// filled) and by `close()`.
	private void notifyLegacy() @safe
	{
		if (legacyEventInit)
			legacyEvent.emit();
	}

	private string[string] requestHeaders(Json message) @safe
	{
		return protocol is null ? null : protocol.headersFor(message);
	}

	/// Acquire one in-flight POST permit, blocking the calling task until one is
	/// free when the cap is reached, and return the semaphore so the caller can
	/// release it. Returns null when no cap is configured (`maxInFlight == 0`), in
	/// which case the POST proceeds unthrottled. The `LocalTaskSemaphore` is created
	/// lazily on first use because it must be constructed on the event loop.
	private LocalTaskSemaphore acquireInFlight() @safe
	{
		if (maxInFlight == 0)
			return null;
		if (inFlightSem is null)
			inFlightSem = new LocalTaskSemaphore(maxInFlight);
		inFlightSem.lock();
		return inFlightSem;
	}

	Json deliver(Json message, long expectId) @safe
	{
		if (isInitialize(message))
			sessionExpired = false;
		else if (sessionExpired)
			throw new HttpStatusException(404,
					"MCP session expired (server rejected a prior request with HTTP 404/410)");
		if (legacyMode)
			return legacyRpc(message, expectId);
		return postAndAwait(message, expectId);
	}

	void sendOneway(Json message) @safe
	{
		post(message);
	}

	void abort(long expectId, McpException reason) @safe
	{
		if (auto w = expectId in legacyWaiters)
		{
			if (!(*w).got && (*w).err is null)
				(*w).err = reason;
			notifyLegacy();
		}
		if (auto r = expectId in inflightPosts)
			(*r).abort(reason);
	}

	/// False: a reply to a server->client request travels on a *different* HTTP
	/// request than the one whose inbound stream delivered it, and a nested
	/// synchronous POST from inside an awaiting read loop could deadlock the
	/// connection. `McpClient` therefore defers the reply to a background task
	/// (which the HTTP transport already runs under an event loop).
	bool repliesSynchronously() @safe
	{
		return false;
	}

	// --- POST helpers --------------------------------------------------------

	/// POST a message whose reply (if any) does not come back on this response: a
	/// notification or response, or a legacy HTTP+SSE request. In legacy mode,
	/// messages go to the server-supplied endpoint URI. Returns the HTTP status.
	private int post(Json message) @safe
	{
		import std.conv : to;

		import mcp.protocol.ssrf : secureRequestHTTP, SsrfPolicy;

		const target = legacyMode ? legacyEndpoint : url;
		int status;
		// Hold an in-flight permit (no-op when uncapped) for the duration of the
		// POST so a oneway send counts against the concurrency cap and releases on
		// every exit path, including exceptions.
		auto permit = acquireInFlight();
		scope (exit)
			if (permit !is null)
				permit.unlock();
		// Funnel the pooled-client oneway POST through the resolve-validate-pin
		// connector with the user-configured policy: the user-chosen endpoint host
		// is resolved and the connection pinned to that vetted address (preserving
		// the Host header + TLS SNI), but internal/loopback targets stay permitted.
		secureRequestHTTP(target, SsrfPolicy.allowUserConfigured, (scope HTTPClientRequest req) {
			setupRequest(req, message);
		}, (scope HTTPClientResponse res) {
			captureSession(res);
			status = res.statusCode;
			res.dropBody();
		});
		// A oneway send carries no awaited reply, so a rejection would otherwise be
		// invisible: 404/410 under a session means the session is gone (drop its id
		// and mark it so the next non-initialize request surfaces a clear error);
		// any other non-2xx is logged so the rejection is at least observable.
		if ((status == 404 || status == 410) && sessionId.length)
		{
			sessionExpired = true;
			sessionId = null;
		}
		else if (status != 0 && (status < 200 || status >= 300))
			() @trusted {
			import vibe.core.log : logWarn;

			logWarn("MCP oneway HTTP send rejected with status %d", status);
		}();
		return status;
	}

	/// POST a request and await the response with id `expectId`, processing any
	/// SSE notifications and server->client requests in between. If the response
	/// SSE stream closes before the final response and carried an SSE `retry:`
	/// hint, wait that long and reconnect (resuming with `Last-Event-ID`), per
	/// the Streamable HTTP resumability rules.
	private Json postAndAwait(Json message, long expectId) @safe
	{
		import core.time : msecs;
		import vibe.core.core : sleep;

		Json result = Json.undefined;
		bool got;
		McpException err;
		// This POST owns its own resume cursor, so a concurrently scheduled stream
		// reader cannot overwrite the Last-Event-ID / retry delay this POST uses to
		// decide resumption.
		SseCursor cursor;

		// The modern single-endpoint POST is sent over a DEDICATED, raw TCP
		// connection (`postAndAwaitRaw`) rather than vibe's pooled `requestHTTP`.
		// When a tool handler on the server opens a server->client request
		// (sampling / elicitation / roots) it writes that request as an SSE event
		// on THIS POST's response stream and then blocks awaiting our reply. The
		// reply must be sent on a SEPARATE POST while we are still reading this
		// stream. vibe's pooled chunked HTTP-client reader does not surface a
		// freshly-flushed SSE event's terminating blank line until the next chunk
		// arrives, which would deadlock both peers. A raw connection (the same
		// approach `runServerStream`/`resumeViaGet` use for long-lived SSE)
		// delivers each event immediately, so the client can reply and the
		// round-trip completes.
		auto req = new PostRequest;
		inflightPosts[expectId] = req;
		scope (exit)
			inflightPosts.remove(expectId);

		const sentSession = sessionId.length > 0;
		int status;
		postAndAwaitRaw(message, expectId, cursor, result, got, err, status, req);
		if (req.aborted !is null)
			throw req.aborted;

		// A 404 under a session means the session is gone: drop the id so the
		// next `initialize` starts a new session without it.
		if (status == 404 && sentSession && !got && err is null)
		{
			sessionId = null;
			throw new HttpStatusException(status,
					"MCP session expired (server answered HTTP 404 for the session)");
		}
		// Any other 400/404/405 without a recognised modern error is the signal
		// `McpClient.connect` uses to fall back to an older transport.
		if (isLegacyFallbackStatus(status) && !got && err is null)
			throw new HttpStatusException(status,
					"HTTP " ~ idStr(status) ~ " from the MCP endpoint with no JSON-RPC response");

		if (err !is null)
			throw err;
		if (got)
			return result;

		// The stream closed before the response. When it carried an event id, wait
		// the server's `retry:` delay (or a growing backoff) and RESUME it with a GET
		// carrying `Last-Event-ID` (basic/transports §Resumability and Redelivery —
		// not a re-POST), repeating from the latest id each time the resumed stream
		// closes too. Resumption stops when the server refuses the GET or after
		// `maxIdleResumes` resumes that deliver no new event; the client's request
		// timeout bounds it overall. The 2026-07-28 removed resumability (a modern
		// server answers the GET with 405), so a modern session never resumes.
		enum maxIdleResumes = 3;
		string failure;
		if (!modernProtocol)
		{
			auto backoff = 250.msecs;
			size_t idle;
			while (cursor.lastEventId.length && idle < maxIdleResumes)
			{
				sleep(cursor.retryMs > 0 ? cursor.retryMs.msecs : backoff);
				backoff = nextBackoff(backoff, 5.seconds);
				if (req.aborted !is null)
					throw req.aborted;
				const before = cursor.lastEventId;
				const opened = resumeViaGet(expectId, cursor, result, got, err, failure, req);
				if (req.aborted !is null)
					throw req.aborted;
				if (err !is null)
					throw err;
				if (got)
					return result;
				if (!opened)
					break;
				idle = cursor.lastEventId == before ? idle + 1 : 0;
			}
		}
		throw internalError("No response received for request " ~ idStr(expectId) ~ (failure.length
				? ": " ~ failure : ""));
	}

	/// Double `current`, capped at `cap`: the reconnect delay after another
	/// attempt that made no progress.
	private static Duration nextBackoff(Duration current, Duration cap) @safe pure nothrow
	{
		const doubled = current * 2;
		return doubled > cap ? cap : doubled;
	}

	/// Open a raw TCP connection to `host:port`, bounding the attempt by
	/// `connectTimeout`. vibe's `connectTCP` reports an expired timeout by throwing
	/// with a `": timeout"` message; translate that into a typed, descriptive
	/// `McpException` so an exhausted local ephemeral-port range surfaces as a clear
	/// error instead of parking the calling fiber forever. Any other connect failure
	/// (e.g. connection refused) is rethrown unchanged for the caller's own handling.
	private TCPConnection connectTimed(string host, ushort port) @trusted
	{
		import std.algorithm : canFind;
		import std.conv : to;

		try
			return connectTCP(host, port, null, 0, connectTimeout);
		catch (Exception e)
		{
			if (e.msg.canFind("timeout"))
				throw internalError("connect to " ~ host ~ ":" ~ port.to!string ~ " timed out after "
						~ connectTimeout.toString ~ " — local ephemeral ports may be exhausted");
			throw e;
		}
	}

	/// POST `message` over a fresh TCP connection and read the response, awaiting
	/// the JSON-RPC response with id `expectId`. The response is either a single
	/// JSON body or a `text/event-stream`; for an SSE response, notifications and
	/// server->client requests that arrive BEFORE the final response are
	/// dispatched (via `dispatchSse`) as soon as each complete event is received —
	/// the key property the pooled `requestHTTP` reader does not provide (see
	/// `postAndAwait`). Mirrors the chunked-decode SSE parser of
	/// `runServerStream`/`resumeViaGet`.
	private void postAndAwaitRaw(Json message, long expectId, ref SseCursor cursor,
			ref Json result, ref bool got, ref McpException err, out int status,
			PostRequest req = null) @safe
	{
		import vibe.stream.operations : readLine;
		import std.string : indexOf, startsWith, strip, toLower;
		import std.conv : to;

		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address; the
		// connect targets the pinned IP while `ep.host` is still used for SNI/Host.
		const pinnedHost = pinnedEndpointHost(ep);

		const payload = message.toString();
		auto hdrs = requestHeaders(message);

		// Hold an in-flight permit (no-op when uncapped) across the whole POST,
		// including the long-lived SSE response read, so no more than `maxInFlight`
		// POSTs occupy a socket at once. Released on every exit path via scope(exit).
		auto permit = acquireInFlight();
		scope (exit)
			if (permit !is null)
				permit.unlock();

		// Register a slot so `close()` can force-close this POST's socket even while
		// it is parked reading a long-lived SSE response stream.
		auto slot = new ListenSocketSlot;
		postSockets ~= slot;
		if (req !is null)
			req.use(slot);
		scope (exit)
		{
			import std.algorithm : remove;

			slot.closeSocket();
			postSockets = postSockets.remove!(s => s is slot);
		}

		() @trusted {
			try
			{
				auto sock = connectTimed(pinnedHost, ep.port);
				// `attach` closes `sock` immediately if a `close()` already ran during
				// the `connectTCP` yield, so the socket is never leaked or left parked.
				slot.attach(sock);
				if (closing)
					return;
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, ep.host);

				const req = buildHttpRequest("POST", ep.path, ep.host,
						"application/json, text/event-stream", "close", true, hdrs, null, payload);
				conn.write(cast(const(ubyte)[]) req);

				// Status line + response headers.
				auto statusLine = cast(string) readLine(conn).idup;
				status = parseHttpStatus(statusLine);
				bool chunked;
				bool sse;
				string wwwAuthenticate;
				foreach (h; readHeaderLines(conn))
				{
					const lower = h.toLower;
					if (lower.startsWith("transfer-encoding:") && lower.indexOf("chunked") >= 0)
						chunked = true;
					if (lower.startsWith("content-type:") && lower.indexOf("text/event-stream") >= 0)
						sse = true;
					const c = h.indexOf(':');
					if (c > 0 && h[0 .. c].toLower == "mcp-session-id")
						sessionId = h[c + 1 .. $].strip;
					if (c > 0 && h[0 .. c].toLower == "www-authenticate")
						wwwAuthenticate = h[c + 1 .. $].strip;
				}

				// A 400/404/405 is the legacy-fallback signal: read the (small) body
				// and surface a recognised modern JSON-RPC error if present.
				if (isLegacyFallbackStatus(status))
				{
					const b = readRemaining(conn, chunked);
					McpException modernErr;
					if (modernErrorFromBody(b, modernErr))
						err = modernErr;
					return;
				}

				// Any other non-success status (401/403/5xx, ...) carries no result;
				// keep the HTTP status and challenge so the caller can act on them.
				if (status < 200 || status >= 300)
				{
					err = httpStatusError(status, readRemaining(conn, chunked), wwwAuthenticate);
					return;
				}

				if (!sse)
				{
					// A single JSON body (the common non-streaming response): it must be
					// the response to this request.
					const b = readRemaining(conn, chunked);
					Message m;
					try
						m = parseMessage(b);
					catch (Exception)
					{
						err = httpStatusError(status, b, wwwAuthenticate);
						return;
					}
					const forUs = m.id.type == Json.Type.int_ && m.id.get!long == expectId;
					if (m.kind == MessageKind.errorResponse && (forUs || m.id.type
							== Json.Type.null_))
						err = errorFrom(m.error);
					else if (m.kind == MessageKind.response && forUs)
					{
						result = m.result;
						got = true;
					}
					else
						err = internalError(
								"HTTP response body is not the response to request " ~ idStr(
								expectId));
					return;
				}

				// SSE body: decode the stream, dispatching each COMPLETE event
				// immediately. This is what lets a mid-stream server->client request
				// be answered while we keep reading for the final response. Stop once
				// the awaited response/error arrives or the transport is closing.
				readSseBody(conn, chunked, cursor, () @safe => got
						|| err !is null || closing, (string eventType, string data) @safe {
					dispatchSse(data, expectId, result, got, err);
				});
			}
			catch (Exception e)
			{
				recordTransportFailure(e.msg, got, err);
			}
		}();
	}

	/// Parse the numeric status code out of an HTTP status line
	/// (`HTTP/1.1 200 OK` -> 200). Returns 0 when it cannot be parsed.
	private static int parseHttpStatus(string statusLine) @trusted
	{
		import std.string : split, strip;
		import std.conv : to;

		if (statusLine.length && statusLine[$ - 1] == '\r')
			statusLine = statusLine[0 .. $ - 1];
		auto parts = statusLine.strip.split(" ");
		if (parts.length < 2)
			return 0;
		try
			return parts[1].to!int;
		catch (Exception)
			return 0;
	}

	/// Read the response header block from `conn` (up to the blank line),
	/// returning each header line with its trailing CR stripped.
	private static string[] readHeaderLines(Conn)(Conn conn) @trusted
	{
		import vibe.stream.operations : readLine;

		string[] headers;
		for (;;)
		{
			auto h = cast(string) readLine(conn).idup;
			if (h.length && h[$ - 1] == '\r')
				h = h[0 .. $ - 1];
			if (h.length == 0)
				break;
			headers ~= h;
		}
		return headers;
	}

	/// Read one chunked-transfer-encoding frame from `conn`: the hex size line,
	/// then `size` payload bytes, then the trailing per-chunk CRLF. Sets `data` to
	/// the payload and returns true to continue; returns false on the terminating
	/// zero-size chunk, a malformed/unparseable size line, or end-of-stream. The
	/// single chunk-framing primitive shared by `readRemaining` and `readSseBody`,
	/// so size parsing and trailing-CRLF consumption live in exactly one place.
	private static bool readChunk(Conn)(Conn conn, out string data) @trusted
	{
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : strip;
		import std.conv : parse;

		for (;;)
		{
			string sizeLine;
			try
				sizeLine = (cast(string) readLine(conn).idup).strip;
			catch (Exception)
				return false;
			if (sizeLine.length == 0)
				continue; // tolerate a stray blank line before the size
			uint sz;
			try
			{
				auto sl = sizeLine;
				sz = parse!uint(sl, 16);
			}
			catch (Exception)
				return false;
			if (sz == 0)
				return false; // last chunk
			auto chunk = new ubyte[sz];
			conn.read(chunk, IOMode.all);
			data = cast(string) chunk.idup;
			try
				readLine(conn); // trailing CRLF after the chunk data
			catch (Exception)
			{
			}
			return true;
		}
	}

	/// Read the remaining response body from `conn` to end-of-stream, decoding
	/// chunked transfer-encoding when `chunked` is true. Used for the small
	/// non-streaming JSON body and the 4xx legacy-fallback body.
	private static string readRemaining(Conn)(Conn conn, bool chunked) @trusted
	{
		import vibe.core.stream : IOMode;

		string acc;
		if (chunked)
		{
			string chunk;
			while (readChunk(conn, chunk))
				acc ~= chunk;
		}
		else
		{
			for (;;)
			{
				ubyte[4096] buf;
				size_t n;
				try
					n = conn.read(buf, IOMode.once);
				catch (Exception)
					break;
				if (n == 0)
					break;
				acc ~= cast(string) buf[0 .. n].idup;
			}
		}
		return acc;
	}

	/// Resume a closed response stream via `GET` with `Last-Event-ID`, reading
	/// the resumed SSE stream until the awaited response (`expectId`) arrives.
	///
	/// The GET carries `cursor.lastEventId` and the resumed stream's `id:`/`retry:`
	/// fields update `cursor`, so a further resume continues from the latest event.
	/// Returns false when the stream could not be (re)opened — the server refused
	/// the GET or the connection failed (its message is left in `failure`).
	private bool resumeViaGet(long expectId, ref SseCursor cursor, ref Json result,
			ref bool got, ref McpException err, ref string failure, PostRequest req = null) @safe
	{
		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		// Protocol-version header for the GET stream (set after initialize).
		auto verHeaders = requestHeaders(Json.undefined);

		// Register a slot so `close()` force-closes this retry-resume GET socket even
		// while the reader is parked on a long-lived SSE read, exactly as
		// `runServerStream`/`postAndAwaitRaw` do. Without it a `close()` could not
		// interrupt a parked resume read and the socket would leak.
		auto slot = new ListenSocketSlot;
		serverStreamSlots ~= slot;
		if (req !is null)
			req.use(slot);
		scope (exit)
		{
			import std.algorithm : remove;

			slot.closeSocket();
			serverStreamSlots = serverStreamSlots.remove!(s => s is slot);
		}

		bool opened;
		() @trusted {
			try
			{
				auto sock = connectTimed(pinnedHost, ep.port);
				// `attach` closes `sock` immediately if a `close()` already ran during
				// the `connectTCP` yield, so the socket is never leaked or left parked.
				slot.attach(sock);
				if (closing)
					return;
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, ep.host);
				const getReq = buildHttpRequest("GET", ep.path, ep.host, "text/event-stream",
						"keep-alive", true, verHeaders, cursor.lastEventId, null);
				conn.write(cast(const(ubyte)[]) getReq);

				bool chunked;
				if (!readSseResponseHead(conn, chunked))
					return;
				opened = true;

				bool done;
				readSseBody(conn, chunked, cursor, () @safe => done,
						(string eventType, string data) @safe {
					// Reuse the POST-path dispatcher: it isolates parseJsonString
					// (keep-alive tolerance), applies the cancelled-id guard, and
					// captures got/result/err for the awaited id or dispatches an
					// inbound message. A cancelled-but-matching response leaves
					// got/err unset, so the read continues to stream end — the same
					// observable outcome as the POST path.
					dispatchSse(data, expectId, result, got, err);
					done = awaitSatisfied(got, err);
				});
			}
			catch (Exception e)
				failure = e.msg;
		}();
		return opened;
	}

	private static bool isInitialize(Json message) @safe
	{
		return message.type == Json.Type.object && "method" in message
			&& message["method"].type == Json.Type.string
			&& message["method"].get!string == "initialize";
	}

	private static string idStr(long id) @safe
	{
		import std.conv : to;

		return id.to!string;
	}

	/// Warn (once) when a bearer token is about to be sent over a plaintext,
	/// non-loopback endpoint. RFC 6750 5.3 and the MCP authorization spec require
	/// TLS for bearer credentials; a plaintext `http://` target transmits the
	/// token in cleartext. Loopback (localhost/127.0.0.1/::1) is exempt as a
	/// development/testing convenience. This does not refuse the request — it
	/// surfaces the misconfiguration rather than silently leaking the credential.
	private void warnIfInsecureBearer() @safe
	{
		import std.string : toLower;
		import vibe.core.log : logWarn;

		if (warnedInsecureBearer || bearerToken.length == 0)
			return;
		const ep = parseHttpEndpoint(url);
		if (ep.tls)
			return;
		const host = ep.host.toLower;
		if (host == "localhost" || host == "127.0.0.1" || host == "::1")
			return;
		warnedInsecureBearer = true;
		logWarn("MCP bearer token sent over plaintext http:// to non-loopback host %s; "
				~ "use https:// to avoid transmitting the credential in cleartext", ep.host);
	}

	private void setupRequest(scope HTTPClientRequest req, Json message) @safe
	{
		req.method = HTTPMethod.POST;
		req.headers["Accept"] = "application/json, text/event-stream";
		req.contentType = "application/json";
		// Defense-in-depth: only attach the bearer when this POST targets the
		// configured origin. In legacy mode the target is the server-supplied
		// `legacyEndpoint`; if a future change ever let a cross-origin value reach
		// here, the credential still must not leave the configured origin.
		const target = legacyMode ? legacyEndpoint : url;
		if (sameOrigin(url, target))
		{
			const bearer = currentBearer();
			if (bearer.length)
			{
				warnIfInsecureBearer();
				req.headers["Authorization"] = "Bearer " ~ bearer;
			}
		}
		if (sessionId.length)
			req.headers["Mcp-Session-Id"] = sessionId;
		foreach (k, v; requestHeaders(message))
			if (!isHeaderValueUnsafe(v))
				req.headers[k] = v;
		req.writeBody(cast(const(ubyte)[]) message.toString());
	}

	private void captureSession(scope HTTPClientResponse res) @safe
	{
		if ("Mcp-Session-Id" in res.headers)
			sessionId = res.headers["Mcp-Session-Id"];
	}

	private void dispatchSse(string data, long expectId, ref Json result,
			ref bool got, ref McpException err) @safe
	{
		Message msg;
		try
			msg = Message(parseJsonString(data));
		catch (Exception)
			return; // ignore non-JSON SSE comments/heartbeats

		// A response for a request we have cancelled is ignored per spec, even if
		// it matches the id we are awaiting.
		if ((msg.kind == MessageKind.response || msg.kind == MessageKind.errorResponse)
				&& msg.id.type == Json.Type.int_ && protocol !is null
				&& protocol.isCancelled(msg.id.get!long))
			return;

		final switch (msg.kind)
		{
		case MessageKind.response:
			if (msg.id.type == Json.Type.int_ && msg.id.get!long == expectId)
			{
				result = msg.result;
				got = true;
			}
			break;
		case MessageKind.errorResponse:
			if (msg.id.type == Json.Type.int_
					&& msg.id.get!long == expectId)
				err = errorFrom(msg.error);
			break;
		case MessageKind.request:
			dispatch(msg);
			break;
		case MessageKind.notification:
			dispatch(msg);
			break;
		}
	}

	/// Hand an inbound message to the client's dispatcher.
	private void dispatch(Message msg) @safe
	{
		if (inbound !is null)
			inbound(msg);
	}

	// --- shared raw-HTTP/SSE plumbing -----------------------------------------

	/// Build a raw HTTP/1.1 request for one of the SSE stream methods, collapsing
	/// the five hand-written header builders into a single, consistent policy.
	/// `accept` is the `Accept` header value, `connection` the `Connection` value.
	/// When `includeAuth` is set and a bearer token is present, an
	/// `Authorization: Bearer` header is emitted; the `Mcp-Session-Id` header
	/// follows whenever a session id is known. `extraHeaders` (the protocol-derived
	/// version/modern headers) are appended, skipping any unsafe value. A non-empty
	/// `lastEventId` adds `Last-Event-ID` for SSE resumption, and a non-empty `body`
	/// adds `Content-Length` and the payload. The terminating blank line is always
	/// written.
	private string buildHttpRequest(string verb, string path, string host,
			string accept, string connection,
			bool includeAuth, string[string] extraHeaders, string lastEventId, string body) @safe
	{
		import std.conv : to;

		string req = verb ~ " " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
			~ "\r\nAccept: " ~ accept ~ "\r\n";
		if (body.length)
			req ~= "Content-Type: application/json\r\n";
		req ~= "Connection: " ~ connection ~ "\r\n";
		const bearer = includeAuth ? currentBearer() : null;
		if (bearer.length)
		{
			warnIfInsecureBearer();
			req ~= "Authorization: Bearer " ~ bearer ~ "\r\n";
		}
		if (sessionId.length)
			req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
		foreach (k, v; extraHeaders)
			if (!isHeaderValueUnsafe(v))
				req ~= k ~ ": " ~ v ~ "\r\n";
		if (lastEventId.length)
			req ~= "Last-Event-ID: " ~ lastEventId ~ "\r\n";
		if (body.length)
			req ~= "Content-Length: " ~ body.length.to!string ~ "\r\n";
		req ~= "\r\n";
		if (body.length)
			req ~= body;
		return req;
	}

	/// Read the status line and header block of an SSE GET/POST response from
	/// `conn`, the single status gate replacing the four hand-written
	/// `statusLine.indexOf(" 200") < 0` + chunked-detection loops. Returns true iff
	/// the status is 200, and sets `chunked` when the response uses chunked
	/// transfer-encoding. Must run inside a `@trusted` block (raw socket I/O).
	private static bool readSseResponseHead(Conn)(Conn conn, out bool chunked) @trusted
	{
		import vibe.stream.operations : readLine;
		import std.string : indexOf, toLower;

		auto statusLine = cast(string) readLine(conn).idup;
		const ok = statusLine.indexOf(" 200") >= 0;
		foreach (h; readHeaderLines(conn))
		{
			const lower = h.toLower;
			if (lower.indexOf("transfer-encoding:") == 0 && lower.indexOf("chunked") >= 0)
				chunked = true;
		}
		return ok;
	}

	/// Read and decode an SSE response body from `conn`, the single tested state
	/// machine that replaces the five hand-duplicated `parseSse()` closures and
	/// chunked/raw read loops.
	///
	/// Frames the body (chunked transfer-encoding when `chunked`, else raw reads to
	/// EOF via `leastSize`) and runs the SSE line tokenizer over it, accumulating
	/// `data:` (joined with `\n`, one leading space stripped) and `event:` and
	/// flushing a complete event to `onEvent(eventType, data)` on each blank line.
	/// `id:`/`retry:` fields are handled uniformly here — updating the caller-owned
	/// `cursor` resumption state — so every caller gets `event:`/`id:`/`retry:`
	/// support whether or not it consumes them, while keeping that state per-reader
	/// (no shared mutable resumption fields across concurrent streams). The loop
	/// stops between reads (and after each flushed event) once `shouldStop()`
	/// returns true. Must run inside a `@trusted` block (raw socket I/O).
	private void readSseBody(Conn)(Conn conn, bool chunked, ref SseCursor cursor,
			scope bool delegate() @safe shouldStop,
			scope void delegate(string eventType, string data) @safe onEvent) @trusted
	{
		import vibe.core.stream : IOMode;
		import std.string : indexOf, startsWith, strip;
		import std.conv : to;

		string acc, data, eventType;
		void tokenize()
		{
			for (;;)
			{
				const nl = acc.indexOf('\n');
				if (nl < 0)
					break;
				auto line = acc[0 .. nl];
				acc = acc[nl + 1 .. $];
				if (line.length && line[$ - 1] == '\r')
					line = line[0 .. $ - 1];
				if (line.length == 0)
				{
					if (data.length)
						onEvent(eventType, data);
					data = null;
					eventType = null;
				}
				else if (line.startsWith("event:"))
				{
					auto v = line["event:".length .. $];
					if (v.startsWith(" "))
						v = v[1 .. $];
					eventType = v;
				}
				else if (line.startsWith("data:"))
				{
					auto d = line["data:".length .. $];
					if (d.startsWith(" "))
						d = d[1 .. $];
					data ~= (data.length ? "\n" : "") ~ d;
				}
				else if (line.startsWith("id:"))
					cursor.lastEventId = line["id:".length .. $].strip;
				else if (line.startsWith("retry:"))
				{
					try
						cursor.retryMs = line["retry:".length .. $].strip.to!long;
					catch (Exception)
					{
					}
				}
				if (shouldStop())
					break;
			}
		}

		for (;;)
		{
			if (shouldStop())
				break;
			if (chunked)
			{
				string chunk;
				if (!readChunk(conn, chunk))
					break;
				acc ~= chunk;
				tokenize();
			}
			else
			{
				const avail = conn.leastSize;
				if (avail == 0)
					break;
				const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
				auto buf = new ubyte[toRead];
				const n = conn.read(buf, IOMode.once);
				acc ~= cast(string) buf[0 .. n].idup;
				tokenize();
			}
		}
	}

	// --- standalone server->client stream ------------------------------------

	/// Open the standalone server->client SSE stream (`GET /mcp`) in a background
	/// task, so the server can deliver sampling / elicitation / roots requests
	/// and notifications outside of any POST response. A server that does not
	/// offer this stream (e.g. responds 405) is tolerated as a no-op.
	void startServerStream() @safe
	{
		import vibe.core.core : runTask;

		// Idempotent: a reader task is already live, so a second start would spawn a
		// duplicate standalone stream and orphan the first reader. Set the flag here,
		// before `runTask` yields, so a re-entrant call observes it.
		if (serverStreamAlive)
			return;
		serverStreamAlive = true;
		runTask(() nothrow{
			try
				runServerStream();
			catch (Exception)
			{
			}
		});
	}

	/// Open the standalone server->client SSE stream over a raw TCP connection
	/// (vibe's pooled `requestHTTP` does not reliably surface a long-lived,
	/// idle-then-active SSE body). Whenever the stream closes or the connection
	/// fails it reconnects — after the server's SSE `retry:` delay, else a
	/// backoff that grows while attempts make no progress — resuming with the
	/// latest `Last-Event-ID`, until `close()`. A server that refuses the GET
	/// (e.g. 405: it offers no standalone stream) ends the reader.
	private void runServerStream() @safe
	{
		import core.time : msecs;
		import vibe.core.core : sleep;

		// Clear the liveness flag when the reader task exits, so a later
		// `startServerStream()` can re-open the stream instead of being suppressed.
		scope (exit)
			serverStreamAlive = false;

		// Parse scheme://host[:port]/path.
		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		// Protocol-version header for the GET stream (set after initialize).
		auto verHeaders = requestHeaders(Json.undefined);

		// `id:`/`retry:` resumption state is tracked in this reconnect loop's own
		// cursor by the decoder; the loop reads it between attempts. Keeping it local
		// (not a shared transport field) prevents a concurrent POST/listen reader from
		// clobbering this stream's Last-Event-ID resume on reconnect.
		SseCursor cursor;
		auto backoff = 250.msecs;
		while (!closing)
		{
			bool refused;
			bool sawData;
			// Register a slot so `close()` can force-close this connection's socket
			// even while the reader is parked on a long-lived SSE read.
			auto slot = new ListenSocketSlot;
			serverStreamSlots ~= slot;
			scope (exit)
			{
				import std.algorithm : remove;

				slot.closeSocket();
				serverStreamSlots = serverStreamSlots.remove!(s => s is slot);
			}
			() @trusted {
				try
				{
					auto sock = connectTimed(pinnedHost, ep.port);
					// `attach` closes `sock` immediately if a `close()` already ran during
					// the `connectTCP` yield, so the socket is never leaked or left parked.
					slot.attach(sock);
					if (closing)
						return;
					// Wrap in TLS for https/wss; plaintext is returned unwrapped.
					auto conn = openClientStream(sock, ep.tls, ep.host);

					const req = buildHttpRequest("GET", ep.path, ep.host, "text/event-stream",
							"keep-alive", true, verHeaders, cursor.lastEventId, null);
					conn.write(cast(const(ubyte)[]) req);

					bool chunked;
					if (!readSseResponseHead(conn, chunked))
					{
						refused = true;
						return;
					}

					readSseBody(conn, chunked, cursor, () @safe => closing,
							(string eventType, string data) @safe {
						sawData = true;
						try
							dispatch(Message(parseJsonString(data)));
						catch (Exception)
						{
						}
					});
				}
				catch (Exception)
				{
				}
			}();

			if (closing || refused)
				break;
			// A stream that delivered events was healthy: restart the backoff.
			if (sawData)
				backoff = 250.msecs;
			sleep(cursor.retryMs > 0 ? cursor.retryMs.msecs : backoff);
			backoff = nextBackoff(backoff, 30.seconds);
		}
	}

	// --- subscriptions/listen stream -----------------------------------------

	SubscriptionStream openListen(Json message) @safe
	{
		import vibe.core.core : runTask;
		import core.time : seconds;

		auto cancelled = () @trusted { return new shared bool(false); }();
		// The background task fills this slot with its live socket once connected;
		// the stream's onCancel delegate force-closes it so a blocked readLine /
		// conn.read returns immediately rather than parking until the next event.
		auto slot = new ListenSocketSlot;
		auto onCancel = () @safe nothrow{
			try
				slot.closeSocket();
			catch (Exception)
			{
			}
		};
		auto stream = new SubscriptionStream(cancelled, onCancel);

		// Gate the return on the server confirming the stream is open. The reader
		// fires `established` once it has dispatched the leading SSE frame — the
		// server emits that frame (`active` for events/stream, `acknowledged` for
		// subscriptions/listen) only after registering the subscription, so an
		// occurrence published immediately after this call cannot race ahead of the
		// registration and be missed. Capture the emit count before spawning the
		// reader so an establishment that lands before we wait is not lost. The wait
		// is bounded: a server that never sends a leading frame (or a connect
		// failure, signalled on the reader's exit) degrades to returning rather than
		// hanging.
		auto established = createManualEvent();
		const ec = established.emitCount;
		auto signal = () @safe nothrow{
			try
				established.emit();
			catch (Exception)
			{
			}
		};
		runTask(() nothrow{
			try
				runListenStream(message, cancelled, slot, signal);
			catch (Exception)
			{
			}
		});
		() @trusted {
			if (*cancelled)
				return;
			try
				established.waitUninterruptible(10.seconds, ec);
			catch (Exception)
			{
			}
		}();
		return stream;
	}

	/// Drive a `subscriptions/listen` stream over a raw TCP connection: POST the
	/// listen request, read the server's long-lived `text/event-stream` response,
	/// and dispatch every inbound message (the leading
	/// `notifications/subscriptions/acknowledged` and subsequent change
	/// notifications) via the inbound handler. The loop checks `*cancelled`
	/// between reads and on each SSE event, closing the connection promptly once
	/// the caller cancels. A raw TCP POST is used (rather than vibe's pooled
	/// `requestHTTP`) for the same reason as `runServerStream`: a long-lived,
	/// idle-then-active SSE body is not reliably surfaced by the pooled client.
	private void runListenStream(Json message, shared(bool)* cancelled,
			ListenSocketSlot slot, void delegate() @safe nothrow onEstablished = null) @safe
	{
		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		// Protocol-derived headers (version + modern method) for this POST.
		auto reqHeaders = requestHeaders(message);
		const 
		body = message.toString();

		auto isCancelled = () @safe => () @trusted { return *cancelled; }();

		// Fire the establishment signal at most once: on the first dispatched frame
		// (the stream is now confirmed open server-side) and, as a fallback, on any
		// exit before that frame (connect/head failure) so a waiter in `openListen`
		// returns promptly instead of blocking the full bound.
		bool established;
		void markEstablished() @safe nothrow
		{
			if (established)
				return;
			established = true;
			if (onEstablished !is null)
				onEstablished();
		}

		() @trusted {
			scope (exit)
				markEstablished();
			if (*cancelled)
				return;
			auto sock = connectTimed(pinnedHost, ep.port);
			slot.attach(sock);
			scope (exit)
				slot.closeSocket();
			// A cancel() that raced ahead of attach must still tear the socket down.
			if (*cancelled)
				return;
			// Wrap in TLS for https/wss; plaintext is returned unwrapped.
			auto conn = openClientStream(sock, ep.tls, ep.host);

			const req = buildHttpRequest("POST", ep.path, ep.host,
					"text/event-stream", "keep-alive", true, reqHeaders, null, body);
			conn.write(cast(const(ubyte)[]) req);

			bool chunked;
			if (!readSseResponseHead(conn, chunked))
				return;

			// This stream consumes no resumption state; give the decoder its own
			// throwaway cursor rather than a shared field.
			SseCursor cursor;
			readSseBody(conn, chunked, cursor, isCancelled, (string eventType, string data) @safe {
				markEstablished();
				try
					dispatch(Message(parseJsonString(data)));
				catch (Exception)
				{
				}
			});
		}();
	}

	// --- legacy HTTP+SSE (2024-11-05) two-endpoint transport -----------------

	/// Establish the legacy HTTP+SSE (2024-11-05) two-endpoint transport:
	/// open the GET SSE stream at the server URL, read the first `endpoint`
	/// event to learn the message-POST URI, then keep the stream open in a
	/// background task to receive JSON-RPC responses and server notifications.
	/// Throws if the `endpoint` event is not received. Called by
	/// `McpClient.connect` once a modern POST has been rejected with 400/404/405.
	void startLegacyFallback() @safe
	{
		import vibe.core.core : runTask;
		import core.time : msecs, MonoTime;

		legacyMode = true;
		legacyEndpoint = null;
		legacyEndpointRejected = false;

		// Create the completion event before spawning the reader so an `endpoint`
		// event the reader discovers immediately cannot be missed.
		auto ec = legacyCompletionEvent().emitCount;

		// The GET SSE stream is long-lived: run its reader on a background task
		// so this method can return once the `endpoint` event has arrived.
		runTask(() nothrow{
			try
				runLegacyStream();
			catch (Exception)
			{
			}
		});

		// Wait (bounded, ~10s ceiling) for the background task to discover the
		// endpoint URI, woken by the reader's `notifyLegacy` rather than polling.
		// Exit immediately when the reader sets `legacyEndpointRejected`: a
		// cross-origin endpoint was received and rejected by the SSRF guard, so
		// no valid endpoint will ever arrive on this stream.
		const deadline = MonoTime.currTime + 10_000.msecs;
		while (legacyEndpoint.length == 0 && !legacyEndpointRejected)
		{
			const now = MonoTime.currTime;
			if (now >= deadline)
				break;
			ec = legacyCompletionEvent().waitUninterruptible(deadline - now, ec);
		}
		if (legacyEndpointRejected)
		{
			legacyMode = false;
			throw internalError("legacy HTTP+SSE server sent a cross-origin `endpoint` event (SSRF guard rejected it)");
		}
		if (legacyEndpoint.length == 0)
		{
			legacyMode = false;
			throw internalError(
					"legacy HTTP+SSE server did not send an `endpoint` event on the GET stream");
		}
	}

	/// Send a JSON-RPC request over the legacy transport: POST it to the
	/// server-supplied endpoint URI, then await the correlated response, which
	/// arrives asynchronously on the standalone GET SSE stream.
	private Json legacyRpc(Json message, long expectId) @safe
	{
		auto waiter = new LegacyWaiter;
		waiter.result = Json.undefined;
		legacyWaiters[expectId] = waiter;
		scope (exit)
			legacyWaiters.remove(expectId);

		// Snapshot the completion event before the POST so a response the reader
		// delivers immediately after cannot be missed.
		auto ec = legacyCompletionEvent().emitCount;

		// POST to legacyEndpoint; the server replies on the GET stream, unless it
		// rejects the POST outright, in which case no reply will ever come.
		const status = post(message);
		if (status < 200 || status >= 300)
			throw new HttpStatusException(status,
					"legacy HTTP+SSE server rejected the request with HTTP " ~ idStr(status));

		// If the reader has already exited, no response can arrive on the stream:
		// fail fast rather than waiting out the timeout.
		if (!legacyStreamAlive && !waiter.got && waiter.err is null)
			throw internalError("legacy HTTP+SSE stream is not active");

		// Wait for the correlated response, woken by the reader's `notifyLegacy`,
		// `close()`, or `abort` (through which `McpClient` enforces its deadline).
		while (!waiter.got && waiter.err is null && !closing)
			ec = legacyCompletionEvent().waitUninterruptible(Duration.max, ec);
		if (waiter.err !is null)
			throw waiter.err;
		if (waiter.got)
			return waiter.result;
		throw internalError("legacy HTTP+SSE transport closing");
	}

	/// Read the legacy GET SSE stream over a raw TCP connection, dispatching
	/// each event by type: an `endpoint` event sets the message-POST URI; a
	/// `message` (or default) event is a JSON-RPC message routed to the awaited
	/// response slot or to the inbound dispatcher.
	private void runLegacyStream() @safe
	{
		import std.string : strip;

		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		legacyStreamAlive = true;
		scope (exit)
			legacyStreamAlive = false;

		() @trusted {
			try
			{
				if (closing)
					return;
				auto sock = connectTimed(pinnedHost, ep.port);
				// `connectTCP` yielded; a `close()` during that yield saw the socket as
				// not-yet-open and did nothing. Re-check here, in the same fiber with no
				// intervening yield, so the freshly connected socket is not leaked.
				if (closing)
				{
					sock.close();
					return;
				}
				legacyStreamSock = sock;
				legacyStreamSockOpen = true;
				scope (exit)
				{
					legacyStreamSockOpen = false;
					sock.close();
				}
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, ep.host);

				const req = buildHttpRequest("GET", ep.path, ep.host,
						"text/event-stream", "keep-alive", true, null, null, null);
				conn.write(cast(const(ubyte)[]) req);

				bool chunked;
				if (!readSseResponseHead(conn, chunked))
					return;

				SseCursor cursor;
				readSseBody(conn, chunked, cursor, () @safe => closing,
						(string eventType, string data) @safe {
					if (eventType == "endpoint")
					{
						const resolved = resolveEndpointUri(url, data.strip);
						if (resolved is null)
							legacyEndpointRejected = true; // cross-origin: SSRF guard rejected it
						else
							legacyEndpoint = resolved;
						notifyLegacy(); // wake `startLegacyFallback`
						return;
					}
					// `message` event (or untyped): a JSON-RPC message. Resolution and
					// inbound dispatch run OUTSIDE any catch here, so a failure during
					// dispatch propagates to the outer catch and tears the stream down
					// (fast-failing every waiter) rather than being swallowed.
					resolveLegacyMessage(data);
				});
			}
			catch (Exception e)
			{
				failOutstandingLegacyWaiters("legacy HTTP+SSE stream failed: " ~ e.msg);
			}
		}();

		// The stream closed: fail every still-outstanding waiter so its `legacyRpc`
		// wait returns promptly with a clear error instead of waiting out the timeout.
		failOutstandingLegacyWaiters("legacy HTTP+SSE stream closed before response");
	}

	/// Resolve one `message`-event frame from the legacy HTTP+SSE stream. A response
	/// or error addressed to a registered waiter id resolves that waiter; any other
	/// message falls through to the inbound dispatcher. Only the `parseJsonString`
	/// step tolerates failure (non-JSON keep-alive frames), logged for visibility;
	/// a failure anywhere else propagates so the caller can tear the stream down.
	private void resolveLegacyMessage(string data) @safe
	{
		Message m;
		try
			m = Message(parseJsonString(data));
		catch (Exception e)
		{
			import vibe.core.log : logDiagnostic;

			// Tolerate non-JSON keep-alive frames (mirrors dispatchSse), but make a
			// malformed legacy frame visible rather than an invisible swallow that
			// strands a waiter until its deadline.
			logDiagnostic("legacy HTTP+SSE: ignoring unparseable event data: %s", e.msg);
			return;
		}

		LegacyWaiter** w;
		if ((m.kind == MessageKind.response
				|| m.kind == MessageKind.errorResponse) && m.id.type == Json.Type.int_
				&& (w = (m.id.get!long  in legacyWaiters)) !is null)
		{
			// A response for a request we have cancelled is dropped per spec, even
			// when a waiter is still registered for its id (mirrors `dispatchSse`).
			if (protocol !is null && protocol.isCancelled(m.id.get!long))
				return;
			if (m.kind == MessageKind.errorResponse)
				(*w).err = errorFrom(m.error);
			else
			{
				(*w).result = m.result;
				(*w).got = true;
			}
			notifyLegacy(); // wake the matching `legacyRpc`
		}
		else
			dispatch(m);
	}

	/// Fail every still-outstanding legacy waiter with a typed error so each blocked
	/// `legacyRpc` returns promptly with the real cause instead of waiting out the
	/// timeout. Already-resolved waiters are left untouched.
	private void failOutstandingLegacyWaiters(string msg) @safe
	{
		foreach (id, w; legacyWaiters)
			if (!w.got && w.err is null)
				w.err = internalError(msg);
		notifyLegacy();
	}

	/// Record a connect/TLS/write/read failure as a typed `McpException` through the
	/// by-ref `err` out-param shared by the raw-TCP request paths, so the caller
	/// throws the actual cause instead of a generic "No response". The guard keeps a
	/// response (`got`) or error already captured by an in-stream dispatch from being
	/// overwritten by a failure that arrives later on the same stream.
	private static void recordTransportFailure(string msg, ref bool got, ref McpException err) @safe
	{
		if (err is null && !got)
			err = internalError(msg);
	}

	/// The awaited response/error has arrived, so an SSE read loop can stop. Used as
	/// the resume-via-GET stop predicate, mirroring the POST path's predicate.
	private static bool awaitSatisfied(bool got, McpException err) @safe
	{
		return got || err !is null;
	}

	private static McpException errorFrom(Json error) @safe
	{
		const code = ("code" in error && error["code"].type == Json.Type.int_) ? error["code"]
			.get!int : ErrorCode.internalError;
		const m = ("message" in error && error["message"].type == Json.Type.string) ? error["message"]
			.get!string : "server error";
		return new McpException(code, m, error);
	}
}

/// The parsed components of an MCP endpoint URL, shared by every raw-TCP request
/// path so host/port/scheme parsing lives in exactly one place. `tls` is true for
/// an `https://`/`wss://` scheme; `port` defaults to the scheme's well-known port
/// (443 when `tls`, else 80) when the URL omits it, so a TLS URL can never be
/// silently treated as plaintext on port 80.
struct HttpEndpoint
{
	string host;
	ushort port;
	string path;
	bool tls;
}

/// Parse `scheme://host[:port][/path]` into its components, defaulting the port
/// to 443 for a TLS scheme (https/wss) and 80 otherwise. An absent path becomes
/// "/". Tolerates a missing scheme (treated as non-TLS). See `HttpEndpoint`.
HttpEndpoint parseHttpEndpoint(string url) @safe
{
	import std.string : indexOf, toLower;
	import std.conv : to;

	HttpEndpoint ep;
	auto rest = url;
	string scheme;
	const sep = rest.indexOf("://");
	if (sep >= 0)
	{
		scheme = rest[0 .. sep].toLower;
		rest = rest[sep + 3 .. $];
	}
	ep.tls = scheme == "https" || scheme == "wss";

	const slash = rest.indexOf('/');
	const hostPort = (slash < 0) ? rest : rest[0 .. slash];
	ep.path = (slash < 0) ? "/" : rest[slash .. $];

	const defaultPort = ep.tls ? cast(ushort) 443 : cast(ushort) 80;

	// An IPv6 literal is bracketed (RFC 3986 §3.2.2): the host runs to the
	// matching ']' and only a ':' *after* the bracket introduces the port. The
	// brackets are kept on `ep.host` (the form the `Host` header needs); the SNI
	// and connect paths strip them where the bare address is required.
	string portText;
	if (hostPort.length && hostPort[0] == '[')
	{
		const close = hostPort.indexOf(']');
		if (close < 0)
		{
			// Unterminated bracket: take the whole authority as the host.
			ep.host = hostPort;
		}
		else
		{
			ep.host = hostPort[0 .. close + 1];
			const after = hostPort[close + 1 .. $];
			if (after.length && after[0] == ':')
				portText = after[1 .. $];
		}
	}
	else
	{
		const colon = hostPort.indexOf(':');
		ep.host = (colon < 0) ? hostPort : hostPort[0 .. colon];
		if (colon >= 0)
			portText = hostPort[colon + 1 .. $];
	}

	if (portText.length == 0)
		ep.port = defaultPort;
	else
	{
		try
			ep.port = portText.to!ushort;
		catch (Exception)
			ep.port = defaultPort;
	}
	return ep;
}

/// Resolve, classify and PIN the host of an MCP client transport endpoint to a
/// numeric address, returning the address to `connectTCP` to. The endpoint is
/// user-configured (the URL the host passed to `McpClient`), so the
/// `allowUserConfigured` SSRF policy is used: the address is resolved and pinned
/// for TOCTOU stability, but loopback/private/link-local targets are permitted
/// (a developer may legitimately point the client at `localhost` or an internal
/// service). Only a fail-closed classification (unresolvable / malformed host)
/// throws. The original `ep.host` is still used for the TLS SNI / `Host` header
/// by `openClientStream`/`buildHttpRequest`; only the connect target changes.
/// `@safe`.
string pinnedEndpointHost(HttpEndpoint ep) @safe
{
	import mcp.protocol.ssrf : pinnedConnectAddress, SsrfPolicy;
	import mcp.protocol.errors : internalError;

	const pin = pinnedConnectAddress(ep.host, ep.tls, SsrfPolicy.allowUserConfigured);
	if (!pin.ok)
		throw internalError(
				"Refusing to connect to MCP endpoint whose host could not be resolved: " ~ ep.host);
	return pin.pinnedIp;
}

/// Open a client byte stream to `ep`, wrapping the raw TCP connection in a vibe
/// TLS tunnel when `ep.tls` is set (https/wss). Returns a `ProxyStream` so the
/// five raw-TCP request paths share ONE TLS-handling site and treat the plaintext
/// and TLS cases uniformly. The TLS context uses
/// `TLSContextKind.client` with peer-certificate verification (`checkPeer`) and
/// sets the SNI/peer name to `ep.host`, so the server certificate and hostname are
/// validated; the underlying `conn` must outlive the returned stream (callers keep
/// it in scope and `close()` it). On a plaintext endpoint the raw connection is
/// returned unwrapped (still as a `ProxyStream` for a single static type).
/// Remove the surrounding brackets from a bracketed IPv6 literal host
/// (`[::1]` -> `::1`), leaving any other host untouched. The TLS SNI/peer name
/// and the SSRF/connect resolver both want the bare address, while the `Host`
/// header keeps the brackets.
string unbracketHost(string host) pure nothrow @safe @nogc
{
	if (host.length >= 2 && host[0] == '[' && host[$ - 1] == ']')
		return host[1 .. $ - 1];
	return host;
}

private ProxyStream openClientStream(TCPConnection conn, bool tls, string host) @trusted
{
	if (tls)
	{
		auto ctx = createTLSContext(TLSContextKind.client);
		ctx.peerValidationMode = TLSPeerValidationMode.checkPeer;
		// vibe's TLS layer wants the bare peer name; an IPv6 literal reaches here
		// bracketed (the form the `Host` header needs), so strip the brackets.
		auto t = createTLSStream(conn, ctx, unbracketHost(host));
		return createProxyStream(t);
	}
	return createProxyStream(conn);
}

/// Whether an HTTP status from the initial modern POST should trigger the
/// legacy HTTP+SSE (2024-11-05) backward-compatibility fallback. Per
/// basic/transports §Backwards Compatibility, a client probing a single modern
/// endpoint should fall back when the POST fails with 400 Bad Request, 404 Not
/// Found, or 405 Method Not Allowed.
bool isLegacyFallbackStatus(int status) pure nothrow @safe @nogc
{
	return status == 400 || status == 404 || status == 405;
}

/// Whether a JSON-RPC error `code` carried in a 400/404/405 response body
/// proves the peer speaks a *modern* MCP version (so the client should retry /
/// correct rather than fall back to the legacy HTTP+SSE transport). Per modern
/// basic/transports §Backward Compatibility the disambiguating modern errors a
/// 4xx body may carry are `UnsupportedProtocolVersionError` (-32022),
/// `HeaderMismatch` (-32020, header-validation failure),
/// `MissingRequiredClientCapabilityError` (-32021), and — for a 404 to an
/// unimplemented modern method — `Method not found` (-32601). These mirror the
/// codes the SDK's own server emits via `httpStatusForResponse`.
bool isModernRpcErrorCode(int code) pure nothrow @safe @nogc
{
	return code == ErrorCode.unsupportedProtocolVersion || code == ErrorCode.headerMismatch
		|| code == ErrorCode.missingRequiredClientCapability || code == ErrorCode.methodNotFound;
}

/// Inspect a 400/404/405 response `body` for a recognized modern JSON-RPC
/// error before deciding whether to fall back to legacy HTTP+SSE. Per modern
/// basic/transports §Backward Compatibility: "If the body contains a recognized
/// modern JSON-RPC error, the server speaks a modern version of MCP — retry ...
/// rather than falling back. If the body is empty or is not a recognized modern
/// JSON-RPC error, fall back to initialize." Returns true and sets `err` to a
/// typed `McpException` only when the body parses as a JSON-RPC error response
/// whose code passes `isModernRpcErrorCode`; otherwise returns false (legacy
/// fallback) and leaves `err` null. Never throws — a malformed/empty body is a
/// legacy signal, not an error.
bool modernErrorFromBody(string body, out McpException err) @safe nothrow
{
	import std.string : strip;

	err = null;
	try
	{
		if (body.strip.length == 0)
			return false;
		auto msg = parseMessage(body);
		if (msg.kind != MessageKind.errorResponse)
			return false;
		auto e = msg.error;
		if (e.type != Json.Type.object || "code" !in e || e["code"].type != Json.Type.int_)
			return false;
		const code = e["code"].get!int;
		if (!isModernRpcErrorCode(code))
			return false;
		const m = ("message" in e && e["message"].type == Json.Type.string) ? e["message"]
			.get!string : "server error";
		err = new McpException(code, m, e);
		return true;
	}
	catch (Exception)
	{
		// Malformed body: not a recognized modern error → legacy fallback.
		err = null;
		return false;
	}
}

/// Parse a legacy HTTP+SSE event stream looking for the first `endpoint` event,
/// returning its `data:` payload (the message-POST URI) in `uri`. Returns false
/// if no `endpoint` event is found in the supplied buffer. Handles CRLF and LF
/// line endings and the optional single leading space after `data:`.
bool parseEndpointEvent(string sse, out string uri) @safe
{
	import std.string : startsWith, splitLines;

	string eventType;
	string data;
	bool haveData;

	bool flush()
	{
		if (eventType == "endpoint" && haveData)
		{
			uri = data;
			return true;
		}
		eventType = null;
		data = null;
		haveData = false;
		return false;
	}

	foreach (raw; sse.splitLines())
	{
		auto line = raw;
		if (line.length && line[$ - 1] == '\r')
			line = line[0 .. $ - 1];
		if (line.length == 0)
		{
			if (flush())
				return true;
			continue;
		}
		if (line.startsWith("event:"))
		{
			auto v = line["event:".length .. $];
			if (v.startsWith(" "))
				v = v[1 .. $];
			eventType = v;
		}
		else if (line.startsWith("data:"))
		{
			auto d = line["data:".length .. $];
			if (d.startsWith(" "))
				d = d[1 .. $];
			data ~= (haveData ? "\n" : "") ~ d;
			haveData = true;
		}
	}
	// A trailing event without a terminating blank line.
	return flush();
}

/// Whether `candidate` shares `base`'s security origin: same scheme, host, and
/// effective port (per-scheme default applied). The legacy POST endpoint a server
/// supplies on the SSE stream is only trusted when it is same-origin, so the
/// client never POSTs its bearer token to a server-named cross-origin URI. A
/// scheme mismatch (e.g. an https base vs. an http candidate) is rejected too, so
/// a downgrade cannot leak the credential in plaintext.
bool sameOrigin(string base, string candidate) @safe
{
	import std.string : toLower;

	auto b = parseHttpEndpoint(base);
	auto c = parseHttpEndpoint(candidate);
	return b.tls == c.tls && b.host.toLower == c.host.toLower && b.port == c.port;
}

/// Resolve a legacy `endpoint` event URI (which may be absolute, root-relative,
/// or document-relative) against the GET-SSE base URL, yielding the absolute URL
/// to POST subsequent JSON-RPC messages to. An absolute URI is only accepted when
/// it is same-origin with the base; a cross-origin absolute URI yields null so the
/// legacy fallback fails closed rather than POSTing the bearer token off-origin.
string resolveEndpointUri(string baseUrl, string endpoint) @safe
{
	import std.string : indexOf, startsWith, lastIndexOf;

	if (endpoint.startsWith("http://") || endpoint.startsWith("https://"))
		return sameOrigin(baseUrl, endpoint) ? endpoint : null;

	// Split base into scheme://authority and path.
	const sep = baseUrl.indexOf("://");
	if (sep < 0)
		return endpoint;
	const afterScheme = sep + 3;
	const slash = baseUrl[afterScheme .. $].indexOf('/');
	string origin = (slash < 0) ? baseUrl : baseUrl[0 .. afterScheme + slash];
	string basePath = (slash < 0) ? "/" : baseUrl[afterScheme + slash .. $];

	if (endpoint.startsWith("/"))
		return origin ~ endpoint;

	// Document-relative: replace the last path segment of the base.
	const lastSlash = basePath.lastIndexOf('/');
	string dir = (lastSlash < 0) ? "/" : basePath[0 .. lastSlash + 1];
	return origin ~ dir ~ endpoint;
}

unittest  // parseHttpEndpoint defaults the port per scheme (443 for TLS)
{
	// https/wss default to 443; http and a bare host to 80. An explicit port wins.
	auto h = parseHttpEndpoint("http://host/mcp");
	assert(!h.tls && h.port == 80 && h.host == "host" && h.path == "/mcp");

	auto s = parseHttpEndpoint("https://host/mcp");
	assert(s.tls && s.port == 443 && s.host == "host" && s.path == "/mcp");

	auto sp = parseHttpEndpoint("https://host:8443/x");
	assert(sp.tls && sp.port == 8443);

	auto ws = parseHttpEndpoint("wss://host");
	assert(ws.tls && ws.port == 443 && ws.path == "/");

	auto bare = parseHttpEndpoint("host:9000/p");
	assert(!bare.tls && bare.port == 9000 && bare.host == "host" && bare.path == "/p");
}

unittest  // parseHttpEndpoint keeps the explicit port and bracketed host for IPv6 literals
{
	// A bracketed IPv6 literal with an explicit port must not let the colons
	// inside the address be mistaken for the port delimiter: the host keeps its
	// brackets and the trailing :port is preserved.
	auto ep = parseHttpEndpoint("https://[::1]:8443/mcp");
	assert(ep.tls);
	assert(ep.host == "[::1]");
	assert(ep.port == 8443);
	assert(ep.path == "/mcp");

	// Without an explicit port the scheme default applies (not a colon inside ::).
	auto noport = parseHttpEndpoint("https://[2606:4700::1]/x");
	assert(noport.host == "[2606:4700::1]");
	assert(noport.port == 443);
	assert(noport.path == "/x");

	// Plaintext IPv6 with an explicit port and no path.
	auto plain = parseHttpEndpoint("http://[fe80::1]:9000");
	assert(!plain.tls);
	assert(plain.host == "[fe80::1]");
	assert(plain.port == 9000);
	assert(plain.path == "/");

	// The bare address (for SNI / connect resolution) drops the brackets.
	assert(unbracketHost(ep.host) == "::1");
	assert(unbracketHost("host") == "host");
}

unittest  // an https URL constructs (TLS supported)
{
	// The streaming HTTP client transport wires real TLS through every raw-TCP
	// path (openClientStream wraps the connection in a vibe TLS tunnel with
	// SNI = host and peer-certificate verification, port 443 by default). An
	// https/wss URL constructs successfully and the TLS handshake happens on
	// first connect.
	auto https = new HttpClientTransport("https://example.com/mcp");
	assert(https !is null);
	auto wss = new HttpClientTransport("wss://example.com/mcp");
	assert(wss !is null);

	// A plaintext http URL still constructs fine (the common case is unaffected).
	auto ok = new HttpClientTransport("http://127.0.0.1:8080/mcp");
	assert(ok !is null);
}

unittest  // openClientStream returns a usable stream for plaintext (TLS path needs a live peer)
{
	// The plaintext branch returns the raw connection boxed in a ProxyStream so the
	// five request paths share one static stream type. We cannot complete a TLS
	// handshake without a live peer here, but we can assert the helper is wired (the
	// TLS branch is exercised end-to-end by the integration paths / conformance).
	auto ep = parseHttpEndpoint("https://example.com/mcp");
	assert(ep.tls && ep.port == 443 && ep.host == "example.com");
	auto plain = parseHttpEndpoint("http://example.com/mcp");
	assert(!plain.tls && plain.port == 80);
}

unittest  // parseHttpStatus reads the code out of an HTTP status line
{
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 200 OK") == 200);
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 202 Accepted\r") == 202);
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 404 Not Found") == 404);
	// Unparseable lines yield 0 (treated as no status).
	assert(HttpClientTransport.parseHttpStatus("garbage") == 0);
	assert(HttpClientTransport.parseHttpStatus("") == 0);
}

unittest  // isLegacyFallbackStatus recognises the spec's 400/404/405 triggers
{
	assert(isLegacyFallbackStatus(400));
	assert(isLegacyFallbackStatus(404));
	assert(isLegacyFallbackStatus(405));
}

unittest  // isLegacyFallbackStatus ignores success and other errors
{
	assert(!isLegacyFallbackStatus(200));
	assert(!isLegacyFallbackStatus(202));
	assert(!isLegacyFallbackStatus(401));
	assert(!isLegacyFallbackStatus(500));
}

unittest  // isModernRpcErrorCode recognises the modern-vs-legacy disambiguators
{
	// Per 2026-07-28 basic/transports §Backward Compatibility, these are the
	// JSON-RPC error codes a 400/404/405 body may carry to prove the server
	// speaks a modern MCP version rather than being a legacy HTTP+SSE server.
	assert(isModernRpcErrorCode(ErrorCode.unsupportedProtocolVersion)); // -32022
	assert(isModernRpcErrorCode(ErrorCode.headerMismatch)); // -32020
	assert(isModernRpcErrorCode(ErrorCode.methodNotFound)); // -32601
	assert(isModernRpcErrorCode(ErrorCode.missingRequiredClientCapability)); // -32021
}

unittest  // isModernRpcErrorCode rejects unrelated codes
{
	assert(!isModernRpcErrorCode(ErrorCode.internalError));
	assert(!isModernRpcErrorCode(ErrorCode.invalidParams));
	assert(!isModernRpcErrorCode(0));
}

unittest  // modernErrorFromBody surfaces a recognized modern JSON-RPC error
{
	// 400 + UnsupportedProtocolVersionError body → typed McpException, NOT legacy.
	McpException err;
	assert(modernErrorFromBody(`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"bad version","data":{"supported":["2025-11-25"]}}}`,
			err));
	assert(err !is null);
	assert(err.code == ErrorCode.unsupportedProtocolVersion);
}

unittest  // modernErrorFromBody surfaces a 404 method-not-found body
{
	McpException err;
	assert(modernErrorFromBody(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, err));
	assert(err !is null);
	assert(err.code == ErrorCode.methodNotFound);
}

unittest  // modernErrorFromBody ignores an empty body (legacy fallback path)
{
	McpException err;
	assert(!modernErrorFromBody("", err));
	assert(err is null);
	assert(!modernErrorFromBody("   ", err));
	assert(err is null);
}

unittest  // modernErrorFromBody ignores non-JSON / non-error bodies
{
	McpException err;
	assert(!modernErrorFromBody("not json at all", err));
	assert(err is null);
	// A well-formed JSON-RPC result is not an error body.
	assert(!modernErrorFromBody(`{"jsonrpc":"2.0","id":1,"result":{}}`, err));
	assert(err is null);
}

unittest  // modernErrorFromBody ignores an error whose code is not a modern disambiguator
{
	// e.g. a generic internalError in a 400 body is NOT a modern-MCP signal.
	McpException err;
	assert(!modernErrorFromBody(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}`, err));
	assert(err is null);
}

unittest  // parseEndpointEvent extracts the message URI from a legacy SSE endpoint event
{
	// A real 2024-11-05 HTTP+SSE server's first event on the GET stream.
	string sse = "event: endpoint\ndata: /messages?sessionId=abc123\n\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/messages?sessionId=abc123");
}

unittest  // parseEndpointEvent handles CRLF line endings and leading data space
{
	string sse = "event: endpoint\r\ndata:/messages\r\n\r\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/messages");
}

unittest  // parseEndpointEvent ignores a message event and finds a later endpoint event
{
	string sse = "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n"
		~ "event: endpoint\ndata: /post\n\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/post");
}

unittest  // parseEndpointEvent returns false when no endpoint event is present
{
	string sse = "event: message\ndata: {}\n\n";
	string uri;
	assert(!parseEndpointEvent(sse, uri));
}

unittest  // resolveEndpointUri keeps a same-origin absolute URI unchanged
{
	assert(resolveEndpointUri("http://host:8080/mcp",
			"http://host:8080/messages") == "http://host:8080/messages");
}

unittest  // resolveEndpointUri rejects a cross-origin absolute URI (returns null)
{
	// A server (or SSE-injecting attacker) naming a foreign host must not become
	// the legacy POST target; null keeps `legacyEndpoint` empty so the fallback
	// fails closed and the bearer is never POSTed off-origin.
	assert(resolveEndpointUri("http://host:8080/mcp", "http://attacker.example/messages") is null);
}

unittest  // resolveEndpointUri rejects a same-host cross-port absolute URI
{
	assert(resolveEndpointUri("http://host:8080/mcp", "http://host:9000/messages") is null);
}

unittest  // resolveEndpointUri rejects a TLS downgrade for the absolute endpoint
{
	// An https base must not accept an http endpoint: that would leak the bearer
	// in plaintext.
	assert(resolveEndpointUri("https://host/mcp", "http://host/messages") is null);
}

unittest  // sameOrigin matches scheme, host, and effective default port
{
	assert(sameOrigin("https://host/mcp", "https://host:443/messages"));
	assert(sameOrigin("http://host/mcp", "http://host:80/messages"));
	assert(!sameOrigin("https://host/mcp", "https://other/messages"));
	assert(!sameOrigin("https://host/mcp", "http://host/messages"));
}

unittest  // setupRequest withholds the bearer when the legacy target is cross-origin
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.setBearerToken("secret-token");
	t.legacyMode = true;
	t.legacyEndpoint = "http://attacker.example/messages";

	// A minimal real HTTPClientRequest cannot be constructed @safe in a unittest,
	// so assert the gating predicate directly: the bearer is only attached when
	// the POST target is same-origin with the configured url.
	const target = t.legacyMode ? t.legacyEndpoint : t.url;
	assert(!sameOrigin(t.url, target));
}

unittest  // setupRequest attaches the bearer when the legacy target is same-origin
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.setBearerToken("secret-token");
	t.legacyMode = true;
	t.legacyEndpoint = "http://host:8080/messages";

	const target = t.legacyMode ? t.legacyEndpoint : t.url;
	assert(sameOrigin(t.url, target));
}

unittest  // resolveEndpointUri resolves a root-relative path against the server origin
{
	assert(resolveEndpointUri("http://host:8080/sse",
			"/messages?sessionId=abc") == "http://host:8080/messages?sessionId=abc");
}

unittest  // resolveEndpointUri resolves a relative path against the base directory
{
	assert(resolveEndpointUri("http://host:8080/api/sse",
			"messages") == "http://host:8080/api/messages");
}

unittest  // close() fails every outstanding legacy waiter so an in-flight legacyRpc returns at once
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto waiter = new LegacyWaiter;
	waiter.result = Json.undefined;
	t.legacyWaiters[7] = waiter;
	t.close();
	assert(waiter.err !is null);
	assert(!waiter.got);
}

unittest  // close() leaves an already-resolved legacy waiter untouched
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto waiter = new LegacyWaiter;
	waiter.got = true;
	waiter.result = Json(true);
	t.legacyWaiters[3] = waiter;
	t.close();
	assert(waiter.err is null);
	assert(waiter.got);
}

unittest  // the legacy reader liveness flag starts false before runLegacyStream runs
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	assert(!t.legacyStreamAlive);
}

unittest  // errorFrom maps a well-formed JSON-RPC error object
{
	auto err = HttpClientTransport.errorFrom(
			parseJsonString(`{"code":-32601,"message":"Method not found"}`));
	assert(err.code == ErrorCode.methodNotFound);
	assert(err.msg == "Method not found");
}

unittest  // errorFrom tolerates a non-integer code without throwing
{
	// A hostile body with a string `code` must not throw a vibe type-mismatch.
	auto err = HttpClientTransport.errorFrom(parseJsonString(`{"code":"x","message":"boom"}`));
	assert(err.code == ErrorCode.internalError);
	assert(err.msg == "boom");
}

unittest  // errorFrom tolerates a non-string message without throwing
{
	auto err = HttpClientTransport.errorFrom(parseJsonString(`{"code":-32000,"message":42}`));
	assert(err.code == -32000);
	assert(err.msg == "server error");
}

unittest  // errorFrom falls back to defaults when fields are absent
{
	auto err = HttpClientTransport.errorFrom(parseJsonString(`{}`));
	assert(err.code == ErrorCode.internalError);
	assert(err.msg == "server error");
}

unittest  // close() force-closes every registered in-flight POST socket slot
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto slot = new ListenSocketSlot;
	t.postSockets ~= slot;
	t.close();
	// closeSocket() set the slot's `closed` flag, so a socket attached afterward
	// (the connectTCP-race window) is torn down on arrival rather than leaked.
	assert(slot.closed);
}

unittest  // the server-stream reader liveness flag starts false before runServerStream runs
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	assert(!t.serverStreamAlive);
}

unittest  // startServerStream() is idempotent: a second call while a reader is live is a no-op
{
	// Regression: a second start must not spawn a duplicate standalone stream. The
	// liveness flag is set synchronously before the task is spawned, so simulating
	// a live reader makes a subsequent start observe it and return early.
	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.serverStreamAlive = true;
	const before = t.serverStreamSlots.length;
	t.startServerStream();
	assert(t.serverStreamSlots.length == before);
}

unittest  // close() force-closes every registered server-stream socket slot
{
	// Regression: a parked server-stream reader must be torn down by close(). Each
	// connection registers a slot; close() must force-close every one, not only the
	// most recent socket.
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto slotA = new ListenSocketSlot;
	auto slotB = new ListenSocketSlot;
	t.serverStreamSlots ~= slotA;
	t.serverStreamSlots ~= slotB;
	t.close();
	assert(slotA.closed && slotB.closed);
}

unittest  // close() sets closing(), which the post-connect re-check in the stream readers observes
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	assert(!t.closing);
	t.close();
	assert(t.closing);
}

unittest  // a slot registered after close() is born-closed, so resumeViaGet's race-window socket is torn down
{
	// resumeViaGet now registers its retry-resume socket in `serverStreamSlots`
	// (the same teardown contract runServerStream/postAndAwaitRaw use), so a
	// `close()` racing the connect closes the socket on arrival rather than leaking
	// a parked SSE read. Model the connectTCP-yield race: close() first, then a slot
	// registered + attached afterwards must be torn down immediately.
	import vibe.core.net : TCPConnection;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.close();
	auto slot = new ListenSocketSlot;
	t.serverStreamSlots ~= slot;
	// close() already ran, but a slot registered in the race window must be closed
	// the moment a socket is attached: closeSocket() set `closed`, so attach() closes.
	slot.closeSocket();
	assert(slot.closed,
			"a resume-path slot registered around close() must be force-closed, not leaked");
}

unittest  // notifyLegacy is a no-op before the completion event is created
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	assert(!t.legacyEventInit);
	t.notifyLegacy(); // must not touch an uninitialized LocalManualEvent
	assert(!t.legacyEventInit);
}

unittest  // a cross-origin endpoint event sets the rejection flag, not the endpoint
{
	// When resolveEndpointUri returns null (cross-origin URL), the endpoint handler
	// must set legacyEndpointRejected so the startLegacyFallback wait loop can
	// break immediately rather than stalling until the 10-second deadline expires.
	auto t = new HttpClientTransport("http://host:8080/mcp");
	assert(!t.legacyEndpointRejected);

	// Simulate the endpoint event handler receiving a cross-origin URL.
	const resolved = resolveEndpointUri(t.url, "http://attacker.example/messages");
	assert(resolved is null); // cross-origin: resolveEndpointUri returns null
	if (resolved is null)
		t.legacyEndpointRejected = true;
	else
		t.legacyEndpoint = resolved;

	assert(t.legacyEndpointRejected);
	assert(t.legacyEndpoint is null); // endpoint is not populated on rejection
}

unittest  // readSseBody records id:/retry: into the caller-owned cursor
{
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) "id: evt-7\nretry: 1500\ndata: {}\n\n".dup, false);
	}();
	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(cursor.lastEventId == "evt-7");
	assert(cursor.retryMs == 1500);
	assert(events == ["{}"]);
}

unittest  // each readSseBody caller's cursor is independent (no shared resumption state)
{
	import vibe.stream.memory : createMemoryStream;

	// Regression: the resumption cursor must be per-reader. One stream's `id:`/
	// `retry:` line must not clobber another concurrent reader's resume decision,
	// so two decode passes with distinct cursors keep distinct state.
	auto t = new HttpClientTransport("http://host:8080/mcp");

	auto streamA = () @trusted {
		return createMemoryStream(cast(ubyte[]) "id: A\nretry: 100\ndata: a\n\n".dup, false);
	}();
	SseCursor cursorA;
	() @trusted {
		t.readSseBody(streamA, false, cursorA, () @safe => false, (string e, string d) @safe {
		});
	}();

	auto streamB = () @trusted {
		return createMemoryStream(cast(ubyte[]) "id: B\nretry: 200\ndata: b\n\n".dup, false);
	}();
	SseCursor cursorB;
	() @trusted {
		t.readSseBody(streamB, false, cursorB, () @safe => false, (string e, string d) @safe {
		});
	}();

	assert(cursorA.lastEventId == "A" && cursorA.retryMs == 100);
	assert(cursorB.lastEventId == "B" && cursorB.retryMs == 200);
}

unittest  // readChunk decodes a multi-frame chunked body via readRemaining
{
	import vibe.stream.memory : createMemoryStream;

	// Two data chunks (each with its trailing CRLF) then the terminating
	// zero-size chunk; the shared `readChunk` framing must reassemble the bytes
	// exactly and stop at the 0 chunk.
	auto body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	auto got = () @trusted {
		return HttpClientTransport.readRemaining(stream, true);
	}();
	assert(got == "hello world");
}

unittest  // readChunk consumes the per-chunk trailing CRLF so framing stays aligned
{
	import vibe.stream.memory : createMemoryStream;

	// Regression for the previously divergent trailing-CRLF handling: with the
	// per-chunk CRLF consumed, the size line of the next chunk parses cleanly and
	// the full payload is recovered rather than the decoder desyncing.
	auto body = "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	auto got = () @trusted {
		return HttpClientTransport.readRemaining(stream, true);
	}();
	assert(got == "abcdef");
}

unittest  // readSseBody decodes events delivered across chunked frames
{
	import vibe.stream.memory : createMemoryStream;

	// A single SSE event split across two chunked frames: the shared `readChunk`
	// reader must rejoin the frames so the tokenizer sees one complete event.
	auto body = "6\r\ndata: \r\n4\r\nhi\n\n\r\n0\r\n\r\n";
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, true, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(events == ["hi"]);
}

unittest  // warnIfInsecureBearer warns once for a plaintext non-loopback bearer
{
	auto t = new HttpClientTransport("http://example.com/mcp");
	t.setBearerToken("secret-token");
	assert(!t.warnedInsecureBearer);
	t.warnIfInsecureBearer();
	assert(t.warnedInsecureBearer); // plaintext + non-loopback host -> warned
	t.warnIfInsecureBearer();
	assert(t.warnedInsecureBearer); // idempotent: still set, no second warning path
}

unittest  // warnIfInsecureBearer stays silent for an https endpoint
{
	auto t = new HttpClientTransport("https://example.com/mcp");
	t.setBearerToken("secret-token");
	t.warnIfInsecureBearer();
	assert(!t.warnedInsecureBearer);
}

unittest  // warnIfInsecureBearer exempts loopback plaintext endpoints
{
	auto t = new HttpClientTransport("http://127.0.0.1:8080/mcp");
	t.setBearerToken("secret-token");
	t.warnIfInsecureBearer();
	assert(!t.warnedInsecureBearer);
}

unittest  // warnIfInsecureBearer is a no-op when no bearer token is set
{
	auto t = new HttpClientTransport("http://example.com/mcp");
	t.warnIfInsecureBearer();
	assert(!t.warnedInsecureBearer);
}

unittest  // resumeViaGet GET includes Authorization: Bearer when a bearer token is set
{
	// Regression: the GET paths (resumeViaGet, runServerStream) must pass
	// includeAuth=true so the bearer token is forwarded on resume and standalone
	// server-stream GETs against OAuth-protected 2025-era servers.
	import std.algorithm : canFind;

	auto t = new HttpClientTransport("https://host:8080/mcp");
	t.setBearerToken("my-token");
	const req = t.buildHttpRequest("GET", "/mcp", "host:8080", "text/event-stream",
			"keep-alive", true, (string[string]).init, "last-id", null);
	assert(req.canFind("Authorization: Bearer my-token"),
			"GET resume path must include Authorization header when bearer token is set");
}

unittest  // a bearer provider is consulted on every request, so a refreshed token is sent
{
	import std.algorithm : canFind;

	auto t = new HttpClientTransport("https://host:8080/mcp");
	int calls;
	t.setBearerProvider(() @safe {
		return ++calls == 1 ? "first-token" : "refreshed-token";
	});
	auto first = t.buildHttpRequest("GET", "/mcp", "host:8080",
			"text/event-stream", "keep-alive", true, (string[string]).init, null, null);
	auto second = t.buildHttpRequest("GET", "/mcp", "host:8080",
			"text/event-stream", "keep-alive", true, (string[string]).init, null, null);
	assert(first.canFind("Authorization: Bearer first-token"));
	assert(second.canFind("Authorization: Bearer refreshed-token"));
}

unittest  // setBearerToken replaces an installed bearer provider
{
	import std.algorithm : canFind;

	auto t = new HttpClientTransport("https://host:8080/mcp");
	t.setBearerProvider(() @safe => "provided");
	t.setBearerToken("static");
	const req = t.buildHttpRequest("GET", "/mcp", "host:8080",
			"text/event-stream", "keep-alive", true, (string[string]).init, null, null);
	assert(req.canFind("Authorization: Bearer static"));
}

unittest  // runServerStream GET includes Authorization: Bearer when a bearer token is set
{
	// Regression: the standalone server->client stream GET passed includeAuth=false,
	// so the bearer token was dropped on OAuth-protected 2025-era servers.
	import std.algorithm : canFind;

	auto t = new HttpClientTransport("https://host:8080/mcp");
	t.setBearerToken("stream-token");
	const req = t.buildHttpRequest("GET", "/mcp", "host:8080",
			"text/event-stream", "keep-alive", true, (string[string]).init, null, null);
	assert(req.canFind("Authorization: Bearer stream-token"),
			"standalone server-stream GET must include Authorization header when bearer token is set");
}

unittest  // postAndAwait skips resumeViaGet when the session is in modern mode
{
	// The 2026-07-28 removed Last-Event-ID resumption; a modern server responds
	// to the GET with 405. the resume is gated on !modernProtocol so
	// the pointless GET round-trip is avoided when the negotiated version is modern.
	auto t = new HttpClientTransport("https://host:8080/mcp");
	assert(!t.modernProtocol,
			"transport starts in legacy mode; resumeViaGet is allowed by default");
	t.modernProtocol = true;
	assert(t.modernProtocol, "after setModernProtocol(true) the transport skips resumeViaGet");
}

unittest  // readSseBody handles a partial IOMode.once read without appending zero bytes
{
	import vibe.core.stream : IOMode, InputStream;
	import std.conv : to;

	// A mock InputStream that reports more bytes available via leastSize than it
	// actually delivers per read(IOMode.once) call. This exercises the partial-read
	// path: the previous code discarded the return value of read(), so it appended
	// the full (zero-padded) buffer instead of only the bytes that were read,
	// corrupting the SSE accumulator with null bytes.
	class PartialInputStream : InputStream
	{
	@safe:
		private ubyte[] data;
		private size_t pos;

		this(ubyte[] d)
		{
			data = d;
		}

		@property bool empty()
		{
			return pos >= data.length;
		}

		// leastSize reports all remaining bytes.
		@property ulong leastSize()
		{
			return data.length - pos;
		}

		@property bool dataAvailableForRead()
		{
			return pos < data.length;
		}

		const(ubyte)[] peek()
		{
			return data[pos .. $];
		}

		// read with IOMode.once delivers at most half the bytes to simulate a partial
		// TCP read; IOMode.all delivers everything requested (required for readLine).
		size_t read(scope ubyte[] dst, IOMode mode) @trusted
		{
			if (pos >= data.length)
				return 0;
			size_t off;
			while (off < dst.length)
			{
				const avail = data.length - pos;
				if (avail == 0)
					break;
				// IOMode.once: at most half the available bytes (simulates a short read).
				const limit = (mode == IOMode.once && avail / 2 > 0) ? avail / 2 : avail;
				const take = (dst.length - off < limit) ? dst.length - off : limit;
				dst[off .. off + take] = data[pos .. pos + take];
				pos += take;
				off += take;
				if (mode == IOMode.once)
					break;
			}
			return off;
		}

		// Expose the one-arg read from InputStream (hidden by the two-arg override above).
		alias read = InputStream.read;
	}

	auto t = new HttpClientTransport("http://host:8080/mcp");

	// A well-formed SSE event: the partial-read stream will deliver it in two
	// read() calls (each half the leastSize). Both halves together must produce
	// exactly one event with data "hello" — no corruption from extra null bytes.
	auto stream = new PartialInputStream(cast(ubyte[]) "data: hello\n\n".dup);

	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(events == ["hello"],
			"partial IOMode.once read must not corrupt the SSE accumulator with zero bytes; got: "
			~ events.to!string);
}

unittest  // a bounded connect timeout surfaces ephemeral-port exhaustion as a typed McpException instead of hanging
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import core.time : msecs, seconds, MonoTime, Duration;

	// RFC 5737 TEST-NET-1 is a black hole: a connect to it never completes. It is a
	// literal IP, so the SSRF guard's user-configured policy permits it. With a short
	// connect timeout the deliver must fail loud (typed McpException) within roughly
	// the timeout window rather than parking the calling fiber forever.
	auto t = new HttpClientTransport("http://192.0.2.1:80/mcp");
	t.setConnectTimeout(200.msecs);

	Json req = Json.emptyObject;
	req["jsonrpc"] = "2.0";
	req["id"] = 1;
	req["method"] = "ping";

	bool threw;
	bool typed;
	Duration elapsed;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		const start = MonoTime.currTime;
		try
			t.deliver(req, 1);
		catch (McpException)
		{
			threw = true;
			typed = true;
		}
		catch (Exception)
			threw = true;
		elapsed = MonoTime.currTime - start;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(threw, "connect to a black-hole address did not throw");
	assert(typed, "connect timeout was not surfaced as a typed McpException");
	assert(elapsed < 10.seconds,
			"connect did not honor the bounded timeout; elapsed: " ~ elapsed.toString);
}

unittest  // recordTransportFailure surfaces a transport failure as a typed McpException
{
	bool got;
	McpException err;
	HttpClientTransport.recordTransportFailure("Connection refused", got, err);
	assert(err !is null);
	assert(err.code == ErrorCode.internalError);
	assert(err.msg == "Connection refused");
}

unittest  // recordTransportFailure does not clobber a response already captured by an in-stream dispatch
{
	bool got = true;
	McpException err;
	HttpClientTransport.recordTransportFailure("late read error", got, err);
	assert(err is null);
}

unittest  // recordTransportFailure does not overwrite an error already captured for the awaited id
{
	bool got;
	McpException err = new McpException(-32000, "server error");
	HttpClientTransport.recordTransportFailure("late read error", got, err);
	assert(err.code == -32000);
}

unittest  // the resume-via-GET read reuses dispatchSse: a matching error response is captured and stops the read
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	Json result;
	bool got;
	McpException err;
	t.dispatchSse(`{"jsonrpc":"2.0","id":9,"error":{"code":-32000,"message":"boom"}}`,
			9, result, got, err);
	assert(err !is null && err.code == -32000);
	assert(!got);
	assert(HttpClientTransport.awaitSatisfied(got, err));
}

unittest  // a matching success response on the resume path is captured and stops the read
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	Json result;
	bool got;
	McpException err;
	t.dispatchSse(`{"jsonrpc":"2.0","id":9,"result":{"ok":true}}`, 9, result, got, err);
	assert(got && result["ok"].get!bool);
	assert(HttpClientTransport.awaitSatisfied(got, err));
}

unittest  // a non-JSON keep-alive frame on the resume path neither fails nor stops the read
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	Json result;
	bool got;
	McpException err;
	t.dispatchSse(": keep-alive", 9, result, got, err);
	assert(!got && err is null);
	assert(!HttpClientTransport.awaitSatisfied(got, err));
}

unittest  // resolveLegacyMessage resolves the matching waiter from a well-formed response
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto w = new LegacyWaiter;
	t.legacyWaiters[5] = w;
	t.resolveLegacyMessage(`{"jsonrpc":"2.0","id":5,"result":{"ok":true}}`);
	assert(w.got);
	assert(w.result["ok"].get!bool);
}

unittest  // resolveLegacyMessage routes a JSON-RPC error response to the waiter's err
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto w = new LegacyWaiter;
	t.legacyWaiters[5] = w;
	t.resolveLegacyMessage(`{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"nope"}}`);
	assert(!w.got);
	assert(w.err !is null && w.err.code == -32601);
}

unittest  // resolveLegacyMessage tolerates a non-JSON keep-alive frame without resolving a waiter
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto w = new LegacyWaiter;
	t.legacyWaiters[5] = w;
	t.resolveLegacyMessage(": keep-alive");
	assert(!w.got && w.err is null);
}

unittest  // failOutstandingLegacyWaiters fails every still-pending waiter with a typed error
{
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto pending = new LegacyWaiter;
	auto done = new LegacyWaiter;
	done.got = true;
	t.legacyWaiters[1] = pending;
	t.legacyWaiters[2] = done;
	t.failOutstandingLegacyWaiters("stream failed");
	assert(pending.err !is null && pending.err.msg == "stream failed");
	assert(done.err is null); // an already-resolved waiter is left untouched
}

version (unittest)
{
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse;

	/// Serve `router` on an ephemeral loopback port and run `scenario` against its
	/// `/mcp` URL inside the event loop, returning the scenario's failure message
	/// (empty on success).
	private string runAgainstFakeServer(URLRouter router, void delegate(string url) @safe scenario)
	{
		import std.conv : to;
		import vibe.core.core : runTask, runEventLoop, exitEventLoop;
		import vibe.http.server : HTTPServerSettings, listenHTTP;

		auto settings = new HTTPServerSettings;
		settings.port = 0;
		settings.bindAddresses = ["127.0.0.1"];
		string failure;
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
			{
				auto listener = listenHTTP(settings, router);
				scope (exit)
					() @trusted { listener.stopListening(); }();
				scenario("http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/mcp");
			}
			catch (Exception e)
				failure = e.msg.length ? e.msg : "exception";
		});
		runEventLoop();
		return failure;
	}

	/// Read a POST body as JSON inside a fake-server handler.
	private Json requestJson(HTTPServerRequest req) @safe
	{
		return parseJsonString(() @trusted { return req.bodyReader.readAllUTF8(); }());
	}

	/// A minimal initialize result for protocol `version_`, echoing the request id.
	private Json initializeReply(Json request, string version_) @safe
	{
		auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"capabilities":{},`
				~ `"serverInfo":{"name":"fake","version":"1.0"}}}`);
		resp["id"] = request["id"];
		resp["result"]["protocolVersion"] = version_;
		return resp;
	}
}

unittest  // connect() tries a Streamable HTTP initialize before legacy HTTP+SSE when a 2025-11-25 server rejects the modern probe
{
	import mcp.client.client : McpClient;
	import mcp.protocol.versions : ProtocolVersion;

	// A conformant 2025-11-25 server answers the 2026-07-28 probe with a plain 400
	// whose body is not a recognised modern error, serves initialize normally, and
	// offers no legacy GET SSE stream.
	bool sawLegacyGet;
	auto router = new URLRouter;
	router.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		auto j = requestJson(req);
		if (req.headers.get("MCP-Protocol-Version", "") == "2026-07-28")
		{
			res.statusCode = 400;
			res.writeBody(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,`
				~ `"message":"Bad Request: Unsupported protocol version"}}`, "application/json");
			return;
		}
		const method = ("method" in j) ? j["method"].get!string : "";
		if (method == "initialize")
		{
			res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
			return;
		}
		res.statusCode = 202;
		res.writeBody("", "text/plain");
	});
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		sawLegacyGet = true;
		res.statusCode = 405;
		res.writeBody("", "text/plain");
	});

	ProtocolVersion negotiated;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		negotiated = client.connect();
	});
	assert(failure.length == 0, "connect failed: " ~ failure);
	assert(negotiated == ProtocolVersion.v2025_11_25);
	assert(!sawLegacyGet, "a Streamable HTTP server must not be treated as legacy HTTP+SSE");
}

version (unittest)
{
	/// A stateful 2025-11-25 fake server: `initialize` mints a fresh
	/// `Mcp-Session-Id`, any other POST under an unknown/expired id gets 404, and
	/// `tools/list` answers an empty list. `expire()` drops the live session.
	private final class SessionFakeServer
	{
		import std.conv : to;

		string live;
		int minted;
		string[] initializeSessionHeaders; // the Mcp-Session-Id each initialize carried

		void expire() @safe
		{
			live = null;
		}

		URLRouter router() @safe
		{
			auto r = new URLRouter;
			r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
				auto j = requestJson(req);
				const method = ("method" in j) ? j["method"].get!string : "";
				const sid = req.headers.get("Mcp-Session-Id", "");
				if (method == "initialize")
				{
					initializeSessionHeaders ~= sid;
					live = "s" ~ (++minted).to!string;
					res.headers["Mcp-Session-Id"] = live;
					res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
					return;
				}
				if (sid != live || live.length == 0)
				{
					res.statusCode = 404;
					res.writeBody("", "text/plain");
					return;
				}
				if (method == "tools/list")
				{
					auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"tools":[]}}`);
					resp["id"] = j["id"];
					res.writeBody(resp.toString(), "application/json");
					return;
				}
				res.statusCode = 202;
				res.writeBody("", "text/plain");
			});
			return r;
		}
	}
}

unittest  // a mid-session 404 surfaces as a typed McpException and a fresh initialize starts a new session
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	bool typed;
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(srv.router(), (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		srv.expire();
		try
			client.listTools();
		catch (McpException)
			typed = true;
		client.initialize("2025-11-25");
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(typed, "a mid-session 404 must raise an McpException");
	assert(srv.initializeSessionHeaders == ["", ""],
			"the re-initialize must not carry the expired session id");
	assert(tools == 0);
}

unittest  // a oneway 404 does not poison the transport: a fresh initialize still succeeds
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(srv.router(), (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		srv.expire();
		client.sendNotification("notifications/roots/list_changed");
		client.initialize("2025-11-25");
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(srv.initializeSessionHeaders == ["", ""]);
	assert(tools == 0);
}

version (unittest)
{
	/// A stateless 2025-11-25 fake server that answers `initialize` normally and
	/// every other request through `answer`.
	private URLRouter answeringRouter(void delegate(Json request, HTTPServerResponse res) @safe answer,
			void delegate(Json notification) @safe onNotification = null) @safe
	{
		auto r = new URLRouter;
		r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
			auto j = requestJson(req);
			const method = ("method" in j) ? j["method"].get!string : "";
			if (method == "initialize")
			{
				res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
				return;
			}
			if ("id" !in j)
			{
				if (onNotification !is null)
					onNotification(j);
				res.statusCode = 202;
				res.writeBody("", "text/plain");
				return;
			}
			answer(j, res);
		});
		return r;
	}

	/// Run `listTools` against a server answering it through `answer` and return
	/// what it threw (null when it returned).
	private Exception listToolsFailure(void delegate(Json request, HTTPServerResponse res) @safe answer)
	{
		import mcp.client.client : McpClient;

		Exception thrown;
		const failure = runAgainstFakeServer(answeringRouter(answer), (string url) @safe {
			auto client = McpClient.http(url);
			scope (exit)
				client.close();
			client.initialize("2025-11-25");
			try
				client.listTools();
			catch (Exception e)
				thrown = e;
		});
		assert(failure.length == 0, "scenario failed: " ~ failure);
		return thrown;
	}
}

unittest  // a 401 surfaces as an HttpStatusException carrying the status and WWW-Authenticate challenge
{
	enum challenge = `Bearer resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource"`;
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		res.statusCode = 401;
		res.headers["WWW-Authenticate"] = challenge;
		res.writeBody(`{"error":"invalid_token"}`, "application/json");
	});
	auto h = cast(HttpStatusException) e;
	assert(h !is null, "a 401 must raise HttpStatusException");
	assert(h.status == 401);
	assert(h.wwwAuthenticate == challenge);
}

unittest  // a 500 with an HTML body surfaces its HTTP status rather than a JSON parse error
{
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		res.statusCode = 500;
		res.writeBody("<html>oops</html>", "text/html");
	});
	auto h = cast(HttpStatusException) e;
	assert(h !is null, "a 500 must raise HttpStatusException");
	assert(h.status == 500);
}

unittest  // a 202 with no body for a request is an error, not a JSON parse failure
{
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		res.statusCode = 202;
		res.writeBody("", "text/plain");
	});
	auto h = cast(HttpStatusException) e;
	assert(h !is null, "a bodiless 202 for a request must raise HttpStatusException");
	assert(h.status == 202);
}

unittest  // a JSON-RPC error body on a 5xx keeps its code alongside the HTTP status
{
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"busy"}}`);
		resp["id"] = req["id"];
		res.statusCode = 503;
		res.writeBody(resp.toString(), "application/json");
	});
	auto h = cast(HttpStatusException) e;
	assert(h !is null);
	assert(h.status == 503 && h.code == -32001 && h.msg == "busy");
}

unittest  // a 200 JSON body whose id does not match the request is rejected
{
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"tools":[]}}`);
		resp["id"] = req["id"].get!long + 1000;
		res.writeBody(resp.toString(), "application/json");
	});
	assert(cast(McpException) e !is null, "a mismatched response id must be rejected");
}

unittest  // an HTTP request whose SSE stream goes silent fails after requestTimeout and sends notifications/cancelled
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;
	import mcp.client.client : McpClient, ClientSettings, RequestTimeoutException;

	bool release;
	long cancelledId = -1;
	long silentId = -2;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		silentId = req["id"].get!long;
		res.contentType = "text/event-stream";
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) ": open\n\n");
			res.bodyWriter.flush();
		}();
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
	}, (Json n) @safe {
		if (n["method"].get!string == "notifications/cancelled")
			cancelledId = n["params"]["requestId"].get!long;
	});

	bool timedOut;
	Duration took;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		ClientSettings s;
		s.requestTimeout = 300.msecs;
		auto client = McpClient.http(url, s);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		const start = MonoTime.currTime;
		try
			client.listTools();
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		const until = MonoTime.currTime + 2.seconds;
		while (cancelledId < 0 && MonoTime.currTime < until)
			sleep(20.msecs);
		release = true;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(timedOut, "a silent SSE stream must fail with RequestTimeoutException");
	assert(took < 3.seconds);
	assert(cancelledId == silentId, "the timeout must send notifications/cancelled for the request");
}

unittest  // cancelling a modern HTTP request closes its response stream and fails the call at once
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : runTask, sleep;
	import mcp.client.client : McpClient, ClientSettings, RequestOptions, CancellationToken;

	bool streamClosed;
	bool sawCancelledNotification;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		res.contentType = "text/event-stream";
		const until = MonoTime.currTime + 5.seconds;
		try
		{
			while (MonoTime.currTime < until)
			{
				() @trusted {
					res.bodyWriter.write(cast(const(ubyte)[]) ": keep-alive\n\n");
					res.bodyWriter.flush();
				}();
				sleep(30.msecs);
			}
		}
		catch (Exception)
			streamClosed = true;
	}, (Json n) @safe {
		if (n["method"].get!string == "notifications/cancelled")
			sawCancelledNotification = true;
	});

	int code;
	Duration took;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		ClientSettings s;
		s.requestTimeout = Duration.zero;
		auto client = McpClient.http(url, s);
		scope (exit)
			client.close();
		client.enableModern();
		auto token = new CancellationToken;
		RequestOptions opts;
		opts.cancellation = token;
		runTask(() nothrow{
			try
			{
				sleep(150.msecs);
				token.cancel();
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.listTools(opts);
		catch (McpException e)
			code = e.code;
		took = MonoTime.currTime - start;
		const until = MonoTime.currTime + 2.seconds;
		while (!streamClosed && MonoTime.currTime < until)
			sleep(20.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(code == ErrorCode.requestCancelled);
	assert(took < 3.seconds);
	assert(streamClosed, "cancellation must close the request's response stream");
	assert(!sawCancelledNotification,
			"modern HTTP cancels by closing the stream, not by notification");
}

version (unittest)
{
	/// A 2025-11-25 fake whose `tools/list` POST stream carries only the SSE
	/// prelude `postPrelude` before closing; each resume GET is answered by
	/// `onGet(lastEventId, requestId, res)`. Other POSTs behave as in
	/// `answeringRouter`.
	private URLRouter droppingRouter(string postPrelude, void delegate(string lastEventId,
			long requestId, HTTPServerResponse res) @safe onGet) @safe
	{
		long droppedId = -1;
		auto r = answeringRouter((Json req, HTTPServerResponse res) @safe {
			droppedId = req["id"].get!long;
			res.contentType = "text/event-stream";
			() @trusted {
				res.bodyWriter.write(cast(const(ubyte)[]) postPrelude);
				res.bodyWriter.flush();
			}();
		});
		r.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
			onGet(req.headers.get("Last-Event-ID", ""), droppedId, res);
		});
		return r;
	}

	private void writeSse(HTTPServerResponse res, string frames) @safe
	{
		res.contentType = "text/event-stream";
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frames);
			res.bodyWriter.flush();
		}();
	}

	private string toolsListFrame(long id) @safe
	{
		auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"tools":[]}}`);
		resp["id"] = Json(id);
		return "data: " ~ resp.toString() ~ "\n\n";
	}
}

unittest  // a POST stream that closes after an event id resumes via GET even without a retry hint
{
	import mcp.client.client : McpClient;

	string[] getIds;
	auto router = droppingRouter("id: evt-1\n\n", (string lastId, long reqId,
			HTTPServerResponse res) @safe {
		getIds ~= lastId;
		writeSse(res, "id: evt-2\n" ~ toolsListFrame(reqId));
	});
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(getIds == ["evt-1"]);
	assert(tools == 0);
}

unittest  // a resumed stream that closes again is resumed from the latest event id
{
	import mcp.client.client : McpClient;

	string[] getIds;
	auto router = droppingRouter("retry: 20\nid: evt-1\n\n", (string lastId,
			long reqId, HTTPServerResponse res) @safe {
		getIds ~= lastId;
		if (lastId == "evt-1")
			writeSse(res, "id: evt-2\n: still working\n\n");
		else
			writeSse(res, toolsListFrame(reqId));
	});
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(getIds == ["evt-1", "evt-2"], "each resume must carry the latest event id");
	assert(tools == 0);
}

unittest  // a POST stream with a retry hint but no event id is not resumed with a cursor-less GET
{
	import mcp.client.client : McpClient;

	bool sawGet;
	auto router = droppingRouter("retry: 20\n\n", (string lastId, long reqId,
			HTTPServerResponse res) @safe {
		sawGet = true;
		writeSse(res, toolsListFrame(reqId));
	});
	bool failed;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		try
			client.listTools();
		catch (McpException)
			failed = true;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(!sawGet, "without an event id there is nothing to resume");
	assert(failed);
}

unittest  // the standalone server stream keeps reconnecting after repeated closes, carrying the latest event id
{
	import core.time : msecs, MonoTime;
	import std.conv : to;
	import vibe.core.core : sleep;
	import mcp.client.client : McpClient;

	string[] getIds;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		res.statusCode = 500;
		res.writeBody("", "text/plain");
	});
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		getIds ~= req.headers.get("Last-Event-ID", "");
		writeSse(res, "retry: 20\nid: s" ~ getIds.length.to!string ~ "\n: tick\n\n");
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		client.startServerStream();
		const until = MonoTime.currTime + 3.seconds;
		while (getIds.length < 4 && MonoTime.currTime < until)
			sleep(20.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(getIds.length >= 4, "the standalone stream must keep reconnecting");
	assert(getIds[0 .. 4] == ["", "s1", "s2", "s3"]);
}

unittest  // a legacy HTTP+SSE request whose POST is rejected fails at once with the HTTP status
{
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	auto router = new URLRouter;
	router.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		res.statusCode = 500;
		res.writeBody("", "text/plain");
	});
	Exception thrown;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		t.legacyMode = true;
		t.legacyEndpoint = url;
		t.legacyStreamAlive = true;
		// Backstop so a waiter left pending still ends the test.
		runTask(() nothrow{
			try
			{
				sleep(2.seconds);
				t.abort(1, internalError("left waiting"));
			}
			catch (Exception)
			{
			}
		});
		try
			t.deliver(makeRequest(Json(1L), "tools/list", Json.emptyObject), 1);
		catch (Exception e)
			thrown = e;
		t.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	auto h = cast(HttpStatusException) thrown;
	assert(h !is null && h.status == 500,
			"a rejected legacy POST must fail its waiter with the status");
}

unittest  // close() ends a stateful session with DELETE carrying its Mcp-Session-Id
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	auto router = srv.router();
	string[] deleted;
	router.delete_("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		deleted ~= req.headers.get("Mcp-Session-Id", "");
		res.statusCode = 204;
		res.writeVoidBody();
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		client.initialize("2025-11-25");
		client.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(deleted == ["s1"], "close() must DELETE the live session");
}

unittest  // close() tolerates a server that answers the session DELETE with 405
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	auto router = srv.router();
	bool sawDelete;
	router.delete_("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		sawDelete = true;
		res.statusCode = 405;
		res.writeBody("", "text/plain");
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		client.initialize("2025-11-25");
		client.close();
	});
	assert(failure.length == 0, "close() must not throw on 405: " ~ failure);
	assert(sawDelete);
}
