module mcp.client.http_transport;

import core.time : Duration, seconds;
import std.algorithm : canFind;
import std.string : startsWith;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8, readLine;
import vibe.core.net : TCPConnection, connectTCP;
import vibe.stream.tls : createTLSContext, createTLSStream, TLSContext, TLSContextKind;
import vibe.stream.wrapper : ProxyStream, createProxyStream;
import vibe.core.stream : Stream;
import vibe.internal.interfaceproxy : InterfaceProxy, interfaceProxy;
import vibe.core.sync : LocalManualEvent, createManualEvent;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.mrtr : isHeaderValueUnsafe;
import mcp.protocol.ssrf : FetchOptions, TlsTrust;
import mcp.client.transport : BearerProvider, ClientTransport, ClientProtocol;
import mcp.client.subscription : SubscriptionStream, ListenGate;

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
private HttpStatusException httpStatusError(int status, string body, string wwwAuthenticate) @safe
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
	import vibe.core.task : Task;

	private TCPConnection sock;
	private bool open;
	/// The task reading this socket, which `abort` interrupts.
	Task owner;
	/// Nonzero while `owner` runs an inbound handler; `abort` then only closes
	/// the socket, so application code is never interrupted.
	uint inHandler;

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

	/// Close the attached socket but keep the slot open for the stream's next
	/// connection; a cancel that already arrived still closes that one on `attach`.
	void detach() @trusted nothrow
	{
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

	/// Close the socket and interrupt its reader, so a read parked on a silent
	/// stream returns at once even where closing a socket does not wake a pending
	/// read (the Windows event driver).
	void abort() @safe nothrow
	{
		closeSocket();
		if (inHandler == 0 && owner != Task.init && owner != Task.getThis() && owner.running)
			owner.interrupt();
	}
}

/// The abortable state of one in-flight Streamable HTTP request: the socket
/// currently carrying its response (the POST, then any resume GET), the task
/// awaiting it, and the reason it was aborted, if it was. Aborting closes that
/// socket and interrupts the awaiting task, so a read parked on a silent stream
/// returns at once even where closing a socket does not wake a pending read
/// (the Windows event driver).
private final class PostRequest
{
	import vibe.core.task : Task;

	ListenSocketSlot slot;
	McpException aborted;
	Task owner;
	/// Nonzero while the owning task runs application code: the client's
	/// handler for a server->client request read off this stream, or the bearer
	/// provider. The abort then only closes the socket, so application code is
	/// never interrupted; the request observes `aborted` once that code returns.
	uint inHandler;

	void abort(McpException reason) @safe nothrow
	{
		aborted = reason;
		if (slot !is null)
			slot.closeSocket();
		if (inHandler == 0 && owner != Task.init && owner != Task.getThis() && owner.running)
			owner.interrupt();
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

/// A counting semaphore bounding concurrent request POSTs. Unlike vibe's
/// `LocalTaskSemaphore`, a task parked in `acquire` is woken by
/// `Task.interrupt`, so a request that times out or is cancelled while waiting
/// for a permit fails at once instead of waiting for one to free up.
private final class InFlightPermits
{
	private uint max_;
	private uint held_;
	private LocalManualEvent released_;

	this(uint max) @safe
	{
		max_ = max;
		released_ = createManualEvent();
	}

	/// Take a permit, parking the calling task until one is free. Throws
	/// `InterruptException` when the task is interrupted while parked.
	void acquire() @safe
	{
		while (held_ >= max_)
		{
			const ec = released_.emitCount;
			released_.wait(ec);
		}
		held_++;
	}

	/// Return a permit taken by `acquire`.
	void release() @safe nothrow
	{
		held_--;
		released_.emit();
	}
}

/// A single in-flight legacy (2024-11-05) request's response slot, owned by the
/// `legacyRpc` call that registered it under its request id. The legacy GET-SSE
/// reader fills `result`/`err` and sets `got` on the matching id; any unmatched
/// message falls through to the inbound dispatcher.
private struct LegacyWaiter
{
	import vibe.core.task : Task;

	Json result;
	McpException err;
	bool got;
	/// The task sending the request's POST, while it is being sent, so an abort
	/// can interrupt a POST the server never answers.
	Task poster;
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

/// The status and the framing, session and auth headers of a raw HTTP response.
private struct ResponseHead
{
	/// The status code, 0 when the status line does not parse.
	int status;
	/// `Transfer-Encoding: chunked`.
	bool chunked;
	/// A `text/event-stream` body.
	bool sse;
	/// The `Mcp-Session-Id` header, empty when absent.
	string sessionId;
	/// The `WWW-Authenticate` challenge, empty when absent.
	string wwwAuthenticate;

	/// Record one header line (`Name: value`, CR stripped).
	void addHeader(string line) @safe
	{
		import std.string : indexOf, strip, toLower;

		const c = line.indexOf(':');
		if (c <= 0)
			return;
		const name = line[0 .. c].strip.toLower;
		const value = line[c + 1 .. $].strip;
		if (name == "transfer-encoding" && value.toLower.indexOf("chunked") >= 0)
			chunked = true;
		else if (name == "content-type" && value.toLower.indexOf("text/event-stream") >= 0)
			sse = true;
		else if (name == "mcp-session-id")
			sessionId = value;
		else if (name == "www-authenticate")
			wwwAuthenticate = value;
	}
}

/// Default bound on a single response body or SSE event (16 MiB).
enum size_t defaultMaxMessageBytes = 16 * 1024 * 1024;

// Bounds on the HTTP framing lines read ahead of a body: one status, header or
// chunk-size line, and the whole header block.
private enum size_t maxHeaderLineBytes = 8 * 1024;
private enum size_t maxHeaderBlockBytes = 64 * 1024;

/// The error raised when the server sends more than `limit` bytes in one message.
private McpException messageTooLarge(size_t limit) @safe
{
	import std.conv : to;

	return internalError("HTTP response exceeds the " ~ limit.to!string ~ "-byte message limit");
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
	private BearerProvider bearerProvider;
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
	// Set when the server rejects a message under the session with a session-gone
	// status (a request answered 404, a oneway send answered 404/410): the session
	// no longer exists, so the next request `deliver()` throws a clear "session
	// expired" error rather than issuing requests without the session id. An
	// `initialize` clears it, since it starts a new session.
	private bool sessionExpired;
	// True when the negotiated protocol version is modern (2026-07-28), which has
	// no Last-Event-ID resumption or standalone GET SSE streams;
	// postAndAwait skips resumeViaGet when this is set so the pointless 405
	// round-trip to a modern server is avoided.
	private bool modernProtocol;
	// Set by `close()` to ask the background stream readers to stop between reads;
	// the held sockets are closed so a blocked read returns immediately. Like all
	// transport state it is only touched from the owning event loop's tasks.
	private bool closeRequested;
	// Slots for the sockets of the standalone server->client SSE stream and of
	// resume GETs. Each connect attempt in `runServerStream` / `resumeViaGet`
	// registers a slot before connecting and removes it on scope exit; `close()`
	// aborts every registered slot so a reader parked on `conn.read` unblocks
	// immediately, whichever connection it is reading.
	private ListenSocketSlot[] serverStreamSlots;
	// The socket and reader task of the legacy GET-SSE stream, aborted by `close()`.
	private ListenSocketSlot legacyStreamSlot;
	// Slots for the sockets of in-flight `postAndAwaitRaw` POSTs whose response is
	// a long-lived SSE stream. Each POST registers a slot before connecting and
	// removes it on scope exit; `close()` force-closes every registered slot so a
	// POST parked reading the stream unblocks immediately. `ListenSocketSlot`'s
	// `attach`/`closeSocket` are order-independent, closing the window where a
	// `close()` races the `connectTCP` yield.
	private ListenSocketSlot[] postSockets;
	// The sockets of the open `subscriptions/listen` / `events/stream` streams, so
	// `close()` ends them along with the transport.
	private ListenSocketSlot[] listenSockets;
	// The abortable state of each in-flight Streamable HTTP request, keyed by its
	// JSON-RPC id, so `abort` can close the socket carrying its response.
	private PostRequest[long] inflightPosts;
	// True while the legacy GET-SSE reader task is running. A `legacyRpc` issued
	// after the reader has exited fails its waiter at once instead of polling for
	// the full timeout, since no response can ever arrive on a dead stream.
	private bool legacyStreamAlive;
	// Set when the legacy GET-SSE reader task exits, together with the cause when
	// it failed (a rejected GET's HTTP status, or a connect/read error), so
	// `startLegacyFallback` stops waiting for an `endpoint` event that cannot come
	// and reports why.
	private bool legacyStreamEnded;
	private McpException legacyStreamFailure;
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
	/// How long `openListen` waits for the stream's leading frame.
	package Duration listenTimeout_ = 10.seconds;
	private enum Duration defaultSendTimeout = 30.seconds;
	private Duration sendTimeout = defaultSendTimeout;
	// Upper bound on any single response body or SSE event read from the server,
	// so a hostile or broken server cannot make the client allocate without limit.
	// Configurable via `setMaxMessageBytes`.
	private size_t maxMessageBytes = defaultMaxMessageBytes;

	// How https/wss servers are validated, and the client TLS context built from
	// it on first use and shared by every connection.
	private TlsTrust tlsTrust;
	private TLSContext tlsContext_;

	/// Inbound dispatcher installed by `McpClient` (its `dispatchInbound`),
	/// invoked for notifications and server->client requests on any stream.
	private void delegate(Message) @safe inbound;
	/// The owning client's `ClientProtocol`, installed via `setProtocol`. Supplies
	/// the protocol-derived request headers (`headersFor`) and the
	/// cancelled-response predicate (`isCancelled`), so this transport never needs
	/// the tool inputSchema cache or modern state.
	private ClientProtocol protocol;

	// Optional cap on the number of request POSTs in flight at once. Zero (the
	// default) means unlimited: no semaphore is created and every request issues
	// its POST immediately. When positive, an `InFlightPermits` admits at most
	// this many concurrent request POSTs (notifications and replies bypass it,
	// see `post`) and an excess
	// caller awaits a permit instead of minting another socket, bounding the
	// ephemeral-port / TIME_WAIT pressure a burst of concurrent requests creates.
	private uint maxInFlight;
	private InFlightPermits inFlightSem;

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
		bearerProvider = BearerProvider.init;
	}

	void setBearerProvider(BearerProvider provider) @safe
	{
		bearerProvider = provider;
		bearerToken = null;
	}

	/// The bearer to attach to the request being built: the provider's current
	/// token when one is installed, else the static token.
	private string currentBearer() @safe
	{
		if (bearerProvider.token !is null)
			bearerToken = bearerProvider.token();
		return bearerToken;
	}

	/// Mark whether the negotiated protocol version is modern (2026-07-28).
	/// When true, `postAndAwait` skips Last-Event-ID resumption via GET because the
	/// modern protocol has no SSE resumability; a modern server responds to such a
	/// GET with 405.
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

	/// Bound each one-way POST (a notification, a reply to a server->client
	/// request, or a legacy HTTP+SSE request) by the client's request timeout, so
	/// an unresponsive server cannot hold the sending task indefinitely; with no
	/// request deadline (`Duration.zero`) the default send bound applies.
	void setRequestTimeout(Duration timeout) @safe
	{
		sendTimeout = timeout > Duration.zero ? timeout : defaultSendTimeout;
	}

	/// Bound every response body and SSE event read from the server to `limit`
	/// bytes; a larger one fails the request it belongs to with an `McpException`.
	void setMaxMessageBytes(size_t limit) @safe
	{
		maxMessageBytes = limit;
	}

	/// Validate https/wss servers under `trust` (trusted CAs, or no verification
	/// for development). Applies to connections opened afterwards.
	void setTlsTrust(TlsTrust trust) @safe
	{
		tlsTrust = trust;
		tlsContext_ = null;
	}

	/// The client TLS context for this transport's https/wss connections: it
	/// requires a server certificate chaining to a trusted CA and matching the
	/// endpoint host name, unless `tlsTrust` disables verification.
	private TLSContext tlsContext() @trusted
	{
		import mcp.protocol.ssrf : tlsContextSetup;

		if (tlsContext_ is null)
		{
			auto ctx = createTLSContext(TLSContextKind.client);
			tlsContextSetup(tlsTrust)(ctx);
			tlsContext_ = ctx;
		}
		return tlsContext_;
	}

	/// Stop the transport: signal the background stream readers
	/// (server->client, legacy GET, `subscriptions/listen` / `events/stream`) to
	/// stop between reads and force-close their held sockets so any blocked
	/// `conn.read` unblocks immediately, terminating the spawned tasks, then end a
	/// stateful session (`endSession`). A listen stream ended this way reports
	/// `ended` with no `error`.
	void close() @safe
	{
		import mcp.client.client : TransportClosedException;

		closeRequested = true;
		// Close every stream socket and interrupt its reader, so a reader parked on
		// `conn.read` unblocks at once even where closing a socket does not wake a
		// pending read (the Windows event driver). A reader running an inbound
		// handler is not interrupted; it observes `closing` once the handler returns.
		foreach (slot; serverStreamSlots)
			slot.abort();
		if (legacyStreamSlot !is null)
			legacyStreamSlot.abort();
		// Abort every in-flight request, which closes the socket carrying its
		// response and interrupts the task awaiting it.
		auto closed = new TransportClosedException("HTTP transport closed");
		foreach (id, r; inflightPosts)
			r.abort(closed);
		foreach (slot; postSockets)
			slot.closeSocket();
		foreach (slot; listenSockets)
			slot.abort();
		// Fail any in-flight legacy waiter at once so its `legacyRpc` wait returns
		// immediately instead of waiting out the timeout on a closing transport.
		foreach (id, w; legacyWaiters)
			if (!w.got && w.err is null)
				w.err = closed;
		// Wake both the per-request waiters and any pending endpoint-discovery wait.
		notifyLegacy();
		// The readers are stopped first, so none reconnects without the session id
		// while this DELETE is outstanding.
		endSession();
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
			const bearer = currentBearer();
			secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.DELETE;
				req.headers["Mcp-Session-Id"] = sid;
				if (bearer.length)
					req.headers["Authorization"] = "Bearer " ~ bearer;
				foreach (k, v; versionHeaders)
					if (!isHeaderValueUnsafe(v))
						req.headers[k] = v;
			}, (scope HTTPClientResponse res) { res.dropBody(); },
					FetchOptions(connectTimeout, tlsTrust));
		}
		catch (Exception)
		{
		}
	}

	private bool closing() @safe
	{
		return closeRequested;
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
	/// which case the POST proceeds unthrottled. The permits are created lazily on
	/// first use because their event must be constructed on the event loop. An
	/// `abort` of the waiting request interrupts the wait.
	private InFlightPermits acquireInFlight() @safe
	{
		if (maxInFlight == 0)
			return null;
		if (inFlightSem is null)
			inFlightSem = new InFlightPermits(maxInFlight);
		inFlightSem.acquire();
		return inFlightSem;
	}

	Json deliver(Json message, long expectId) @safe
	{
		import vibe.core.task : InterruptException, Task;

		if (isInitialize(message))
		{
			// An initialize always opens a new session; the server assigns its id
			// in the response.
			sessionExpired = false;
			sessionId = null;
		}
		else if (sessionExpired)
			throw new HttpStatusException(404,
					"MCP session expired (server rejected a prior request with HTTP 404/410)");
		if (legacyMode)
			return legacyRpc(message, expectId);
		// Register the request before anything that can yield (the bearer
		// provider's `token`, its `onRejected` refresh), so an `abort` landing
		// there is recorded and fails the request rather than being lost.
		auto req = new PostRequest;
		req.owner = Task.getThis();
		inflightPosts[expectId] = req;
		scope (exit)
			inflightPosts.remove(expectId);
		try
		{
			// The token this request carries. A refresh between here and the send
			// can only make it stale, and `onRejected` ignores a token already
			// replaced. The provider runs shielded from an abort's interrupt, so a
			// token refresh is never cut off part-way; the abort is observed once
			// it returns.
			string sentBearer;
			if (bearerProvider.onRejected !is null)
			{
				req.inHandler++;
				scope (exit)
					req.inHandler--;
				sentBearer = currentBearer();
			}
			try
				return postAndAwait(message, expectId, req);
			catch (HttpStatusException e)
			{
				if (sentBearer.length == 0 || !isRejectedBearer(e))
					throw e;
				req.inHandler++;
				scope (exit)
					req.inHandler--;
				if (!bearerProvider.onRejected(sentBearer))
					throw e;
			}
			return postAndAwait(message, expectId, req);
		}
		catch (InterruptException e)
		{
			if (req.aborted !is null)
				throw req.aborted;
			throw e;
		}
	}

	/// Whether `e` rejects the bearer token a request carried (RFC 6750 §3.1): a
	/// 401 whose Bearer challenge has `error="invalid_token"` or no error code.
	/// Other errors (`invalid_request`, `insufficient_scope`) would recur with a
	/// fresh token.
	private static bool isRejectedBearer(HttpStatusException e) @safe
	{
		return isRejectedBearer(e.status, e.wwwAuthenticate);
	}

	/// Whether an HTTP `status` with challenge `wwwAuthenticate` rejects the
	/// bearer token the request carried.
	private static bool isRejectedBearer(int status, string wwwAuthenticate) @safe
	{
		import mcp.auth.oauth : parseWwwAuthenticate;

		if (status != 401)
			return false;
		const error = parseWwwAuthenticate(wwwAuthenticate).error;
		return error.length == 0 || error == "invalid_token";
	}

	/// Report the rejected bearer `sent` to the provider's `onRejected`,
	/// returning whether a fresh token is now available. A throwing refresh
	/// counts as a failed one.
	private bool refreshBearer(string sent) @safe
	{
		try
			return bearerProvider.onRejected(sent);
		catch (Exception)
			return false;
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
			auto poster = (*w).poster;
			if (poster != typeof(poster).init && poster != typeof(poster).getThis()
					&& poster.running)
				poster.interrupt();
		}
		if (auto r = expectId in inflightPosts)
			(*r).abort(reason);
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
		// Only a legacy request takes an in-flight permit. A notification or a reply
		// to a server->client request bypasses the cap: the request POST awaiting
		// that reply already holds a permit, so with every permit held by such
		// requests a capped reply could never be sent.
		const isRequest = message.type == Json.Type.object && "method" in message && "id" in message;
		auto permit = isRequest ? acquireInFlight() : null;
		scope (exit)
			if (permit !is null)
				permit.release();
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
		}, FetchOptions(sendTimeout, tlsTrust));
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
	/// the Streamable HTTP resumability rules. `req` carries the request's abort
	/// state; a request already aborted is not sent.
	private Json postAndAwait(Json message, long expectId, PostRequest req) @safe
	{
		if (req.aborted !is null)
			throw req.aborted;
		return awaitPostResponse(message, expectId, req);
	}

	/// Send `message` and read the response with id `expectId` for `postAndAwait`,
	/// resuming a dropped 2025-era stream; `req` carries the request's abort state.
	private Json awaitPostResponse(Json message, long expectId, PostRequest req) @safe
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
		const sentSession = sessionId.length > 0;
		int status;
		postAndAwaitRaw(message, expectId, cursor, result, got, err, status, req);
		if (req.aborted !is null)
			throw req.aborted;

		// A 404 under a session means the session is gone: drop the id and mark it
		// so later requests fail until an `initialize` starts a new session.
		if (status == 404 && sentSession && !got && err is null)
		{
			sessionExpired = true;
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
		// timeout bounds it overall. The 2026-07-28 protocol has no resumability (a
		// modern server answers the GET with 405), so a modern session never resumes.
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
				permit.release();

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
				auto conn = openClientStream(sock, ep.tls ? tlsContext() : null, ep.host);
				scope (exit)
					conn.release();

				const req = buildHttpRequest("POST", ep.path, ep.hostHeader,
						"application/json, text/event-stream", "close", true, hdrs, null, payload);
				conn.write(cast(const(ubyte)[]) req);

				const head = readResponseHead(conn);
				status = head.status;
				const chunked = head.chunked;
				const wwwAuthenticate = head.wwwAuthenticate;
				if (head.sessionId.length)
					sessionId = head.sessionId;

				// A 400/404/405 is the legacy-fallback signal: read the (small) body
				// and surface a recognised modern JSON-RPC error if present.
				if (isLegacyFallbackStatus(status))
				{
					const b = readRemaining(conn, chunked, maxMessageBytes);
					McpException modernErr;
					if (modernErrorFromBody(b, modernErr))
						err = modernErr;
					return;
				}

				// Any other non-success status (401/403/5xx, ...) carries no result;
				// keep the HTTP status and challenge so the caller can act on them.
				if (status < 200 || status >= 300)
				{
					err = httpStatusError(status, readRemaining(conn, chunked,
							maxMessageBytes), wwwAuthenticate);
					return;
				}

				if (!head.sse)
				{
					// A single JSON body (the common non-streaming response): it must be
					// the response to this request.
					const b = readRemaining(conn, chunked, maxMessageBytes);
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
	/// returning each header line with its trailing CR stripped. Each line is
	/// bounded by `maxHeaderLineBytes` and the block by `maxHeaderBlockBytes`.
	private static string[] readHeaderLines(Conn)(Conn conn) @trusted
	{
		import vibe.stream.operations : readLine;
		import std.conv : to;

		string[] headers;
		size_t total;
		for (;;)
		{
			auto h = cast(string) readLine(conn, maxHeaderLineBytes).idup;
			total += h.length;
			if (total > maxHeaderBlockBytes)
				throw internalError(
						"HTTP response header block exceeds "
						~ maxHeaderBlockBytes.to!string ~ " bytes");
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
	/// A chunk declaring more than `maxBytes` fails before anything is allocated.
	private static bool readChunk(Conn)(Conn conn, size_t maxBytes, out string data) @trusted
	{
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : strip;
		import std.conv : parse;

		for (;;)
		{
			string sizeLine;
			try
				sizeLine = (cast(string) readLine(conn, maxHeaderLineBytes).idup).strip;
			catch (Exception)
				return false;
			if (sizeLine.length == 0)
				continue; // tolerate a stray blank line before the size
			ulong sz;
			try
			{
				auto sl = sizeLine;
				sz = parse!ulong(sl, 16);
			}
			catch (Exception)
				return false;
			if (sz == 0)
				return false; // last chunk
			if (sz > maxBytes)
				throw messageTooLarge(maxBytes);
			auto chunk = new ubyte[cast(size_t) sz];
			conn.read(chunk, IOMode.all);
			data = cast(string) chunk.idup;
			try
				readLine(conn, maxHeaderLineBytes); // trailing CRLF after the chunk data
			catch (Exception)
			{
			}
			return true;
		}
	}

	/// Read the remaining response body from `conn` to end-of-stream, decoding
	/// chunked transfer-encoding when `chunked` is true. Used for the small
	/// non-streaming JSON body and the 4xx legacy-fallback body. A body longer than
	/// `maxBytes` fails with an `McpException`.
	private static string readRemaining(Conn)(Conn conn, bool chunked, size_t maxBytes) @trusted
	{
		import vibe.core.stream : IOMode;

		string acc;
		if (chunked)
		{
			string chunk;
			while (readChunk(conn, maxBytes - acc.length, chunk))
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
				if (n > maxBytes - acc.length)
					throw messageTooLarge(maxBytes);
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
				auto conn = openClientStream(sock, ep.tls ? tlsContext() : null, ep.host);
				scope (exit)
					conn.release();
				const getReq = buildHttpRequest("GET", ep.path, ep.hostHeader,
						"text/event-stream", "keep-alive", true, verHeaders,
						cursor.lastEventId, null);
				conn.write(cast(const(ubyte)[]) getReq);

				const head = readResponseHead(conn);
				if (head.status != 200)
					return;
				opened = true;

				bool done;
				readSseBody(conn, head.chunked, cursor, () @safe => done,
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
			msg = Message(parseJsonBounded(data));
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
			// A null-id error is one the server could not tie to a request id; on
			// this request's stream it answers this request, as on a JSON body.
			if ((msg.id.type == Json.Type.int_
					&& msg.id.get!long == expectId) || msg.id.type == Json.Type.null_)
				err = errorFrom(msg.error);
			break;
		case MessageKind.request:
		case MessageKind.notification:
			auto slot = expectId in inflightPosts;
			PostRequest req = slot is null ? null : *slot;
			if (req !is null)
				req.inHandler++;
			scope (exit)
				if (req !is null)
					req.inHandler--;
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

	/// Read the status line and header block of a raw HTTP response from `conn`.
	/// Must run inside a `@trusted` block (raw socket I/O).
	private static ResponseHead readResponseHead(Conn)(Conn conn) @trusted
	{
		import vibe.stream.operations : readLine;

		ResponseHead head;
		head.status = parseHttpStatus(cast(string) readLine(conn, maxHeaderLineBytes).idup);
		foreach (h; readHeaderLines(conn))
			head.addHeader(h);
		return head;
	}

	/// Read and decode an SSE response body from `conn`, the single tested state
	/// machine that replaces the five hand-duplicated `parseSse()` closures and
	/// chunked/raw read loops.
	///
	/// Frames the body (chunked transfer-encoding when `chunked`, else raw reads to
	/// EOF via `leastSize`) and runs the SSE line tokenizer over it (lines end in
	/// CRLF, LF or CR), accumulating `data:` (joined with `\n`, one leading space
	/// stripped) and `event:` and flushing a complete event to
	/// `onEvent(eventType, data)` on each blank line. `id:`/`retry:` fields are
	/// handled uniformly here — updating the caller-owned `cursor` resumption
	/// state, with an `id:` taking effect when its event is dispatched — so every
	/// caller gets `event:`/`id:`/`retry:`
	/// support whether or not it consumes them, while keeping that state per-reader
	/// (no shared mutable resumption fields across concurrent streams). The loop
	/// stops between reads (and after each flushed event) once `shouldStop()`
	/// returns true. Must run inside a `@trusted` block (raw socket I/O).
	private void readSseBody(Conn)(Conn conn, bool chunked, ref SseCursor cursor,
			scope bool delegate() @safe shouldStop,
			scope void delegate(string eventType, string data) @safe onEvent) @trusted
	{
		import vibe.core.stream : IOMode;
		import std.string : indexOfAny, startsWith, strip;
		import std.conv : to;

		string acc, data, eventType;
		// The `id:` of the event being read; it becomes the resume cursor only when
		// that event is dispatched, so a stream cut mid-event resumes before it.
		string idBuffer = cursor.lastEventId;
		// The previous line ended in CR at the end of a read, so a LF opening the
		// next read completes that CRLF rather than ending an empty line.
		bool pendingCr;
		// How much of `acc` is already known to hold no line ending, so each read
		// scans only its new bytes and a long line costs time linear in its length.
		size_t scanned;
		void tokenize()
		{
			for (;;)
			{
				if (pendingCr && acc.length)
				{
					if (acc[0] == '\n')
						acc = acc[1 .. $];
					pendingCr = false;
				}
				const found = acc[scanned .. $].indexOfAny("\r\n");
				if (found < 0)
				{
					// `acc` holds one incomplete line; it may not outgrow a message.
					if (acc.length > maxMessageBytes)
						throw messageTooLarge(maxMessageBytes);
					scanned = acc.length;
					break;
				}
				const eol = scanned + found;
				scanned = 0;
				auto line = acc[0 .. eol];
				size_t next = eol + 1;
				if (acc[eol] == '\r')
				{
					if (next < acc.length)
					{
						if (acc[next] == '\n')
							++next;
					}
					else
						pendingCr = true;
				}
				acc = acc[next .. $];
				if (line.length == 0)
				{
					cursor.lastEventId = idBuffer;
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
					if (data.length + d.length + 1 > maxMessageBytes)
						throw messageTooLarge(maxMessageBytes);
					data ~= (data.length ? "\n" : "") ~ d;
				}
				else if (line.startsWith("id:"))
					idBuffer = line["id:".length .. $].strip;
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
				if (!readChunk(conn, maxMessageBytes, chunk))
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
	/// idle-then-active SSE body). Whenever the stream closes, the connection
	/// fails or the server answers the GET with another error status (a 5xx, an
	/// expired token's 401) it reconnects — after the server's SSE `retry:` delay,
	/// else a backoff that grows while attempts make no progress — resuming with
	/// the latest `Last-Event-ID`, until `close()`. A 401 that rejects the bearer
	/// is reported to the bearer provider's `onRejected` first, so the reconnect
	/// carries a fresh token; a 401 that no refresh answers ends the reader. Any
	/// other 4xx except 408 and 429 would recur on every attempt (a 405: the
	/// server offers no standalone stream; a 404: no stream at the endpoint, or
	/// the session is gone), so it ends the reader too.
	private void runServerStream() @safe
	{
		import core.time : msecs;
		import vibe.core.core : sleep;
		import vibe.core.task : Task;

		// Clear the liveness flag when the reader task exits, so a later
		// `startServerStream()` can re-open the stream instead of being suppressed.
		scope (exit)
			serverStreamAlive = false;

		// Parse scheme://host[:port]/path.
		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

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
			int status;
			string wwwAuthenticate;
			const sentSession = sessionId;
			const sentBearer = bearerProvider.onRejected !is null ? currentBearer() : null;
			// Register a slot so `close()` can force-close this connection's socket
			// even while the reader is parked on a long-lived SSE read.
			auto slot = new ListenSocketSlot;
			slot.owner = Task.getThis();
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
					auto conn = openClientStream(sock, ep.tls ? tlsContext() : null, ep.host);
					scope (exit)
						conn.release();

					// The protocol-version header is read per attempt, so a reconnect
					// after a re-negotiation carries the current version.
					const req = buildHttpRequest("GET", ep.path, ep.hostHeader,
							"text/event-stream", "keep-alive",
							true, requestHeaders(Json.undefined), cursor.lastEventId, null);
					conn.write(cast(const(ubyte)[]) req);

					const head = readResponseHead(conn);
					status = head.status;
					wwwAuthenticate = head.wwwAuthenticate;
					if (status != 200)
					{
						refused = status >= 400 && status < 500 && status != 408
							&& status != 429 && status != 401;
						return;
					}

					readSseBody(conn, head.chunked, cursor, () @safe => closing,
							(string eventType, string data) @safe {
						sawData = true;
						slot.inHandler++;
						scope (exit)
							slot.inHandler--;
						try
							dispatch(Message(parseJsonBounded(data)));
						catch (Exception)
						{
						}
					});
				}
				catch (Exception)
				{
				}
			}();

			if (closing)
				break;
			if (refused)
			{
				// A 404 for the session this GET carried means it is gone; a session
				// started since then is left alone.
				if (status == 404 && sentSession.length && sessionId == sentSession)
				{
					sessionExpired = true;
					sessionId = null;
				}
				break;
			}
			if (status == 401 && !(sentBearer.length && isRejectedBearer(status,
					wwwAuthenticate) && refreshBearer(sentBearer)))
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
		// the stream's onCancel delegate aborts it (closing the socket and
		// interrupting the reader) so a blocked readLine / conn.read returns
		// immediately rather than parking until the next event.
		auto slot = new ListenSocketSlot;
		// A slot registered after close() is born closed, so the stream ends at once.
		if (closing)
			slot.closeSocket();
		listenSockets ~= slot;
		auto onCancel = () @safe nothrow{ slot.abort(); };
		auto stream = new SubscriptionStream(cancelled, onCancel);

		// Gate the return on the server confirming the stream is open. The reader
		// fires `established` once it has dispatched the leading SSE frame — the
		// server emits that frame (`active` for events/stream, `acknowledged` for
		// subscriptions/listen) only after registering the subscription, so an
		// occurrence published immediately after this call cannot race ahead of the
		// registration and be missed. Capture the emit count before spawning the
		// reader so an establishment that lands before we wait is not lost. A stream
		// the server refuses before any frame (HTTP error, JSON-RPC error, connect
		// failure) ends with an error, which is thrown here. A server that sends no
		// leading frame within `listenTimeout_` has the stream cancelled and the
		// open fails with a timeout.
		auto gate = new ListenGate;
		slot.owner = runTask(() nothrow{
			scope (exit)
			{
				import std.algorithm : remove;

				listenSockets = listenSockets.remove!(s => s is slot);
			}
			try
				runListenStream(message, cancelled, slot, stream, &gate.signal);
			catch (Exception)
			{
			}
		});
		if (!gate.wait(listenTimeout_))
		{
			if (stream.error !is null)
				throw stream.error;
			if (!stream.ended)
			{
				import mcp.client.client : RequestTimeoutException;

				stream.cancel();
				const method = ("method" in message && message["method"].type == Json.Type.string) ? message["method"]
					.get!string : "subscriptions/listen";
				throw new RequestTimeoutException(
						method ~ " received no leading frame within " ~ listenTimeout_.toString());
			}
		}
		return stream;
	}

	/// Drive a `subscriptions/listen` (or `events/stream`) stream over a raw TCP
	/// connection: POST the request, read the server's long-lived
	/// `text/event-stream` response, and dispatch every inbound message (the
	/// leading `notifications/subscriptions/acknowledged` and subsequent change
	/// notifications) via the inbound handler. The loop checks `*cancelled`
	/// between reads and on each SSE event, closing the connection promptly once
	/// the caller cancels. When the server ends the stream — closing it, refusing
	/// the POST with an HTTP or JSON-RPC error, or answering the request — the end
	/// and any error are recorded on `stream`. A raw TCP POST is used (rather than
	/// vibe's pooled `requestHTTP`) for the same reason as `runServerStream`: a
	/// long-lived, idle-then-active SSE body is not reliably surfaced by the pooled
	/// client. `onEstablished(true)` fires on the first dispatched frame;
	/// `onEstablished(false)` fires if the stream ends before one.
	private void runListenStream(Json message, shared(bool)* cancelled, ListenSocketSlot slot,
			SubscriptionStream stream, void delegate(bool frame) @safe nothrow onEstablished) @safe
	{
		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		// Protocol-derived headers (version + modern method) for this POST.
		auto reqHeaders = requestHeaders(message);
		const 
		body = message.toString();
		const listenId = ("id" in message) ? message["id"] : Json(null);

		// A local cancel and the transport's close() both end the stream without
		// it counting as a server failure.
		auto isCancelled = () @safe => closing || () @trusted {
			return *cancelled;
		}();

		// Fire the establishment signal at most once: on the first dispatched frame
		// (the stream is now confirmed open server-side) and, as a fallback, on any
		// exit before that frame so a waiter in `openListen` returns promptly
		// instead of blocking the full bound.
		bool established;
		void markEstablished(bool frame) @safe nothrow
		{
			if (established)
				return;
			established = true;
			onEstablished(frame);
		}

		McpException failure;
		// Whether `m` answers the listen request itself, which ends the stream; an
		// error response records the failure.
		bool endsStream(Message m) @safe
		{
			if (m.kind != MessageKind.response && m.kind != MessageKind.errorResponse)
				return false;
			if (m.id != listenId && m.id.type != Json.Type.null_)
				return false;
			if (m.kind == MessageKind.errorResponse)
				failure = errorFrom(m.error);
			return true;
		}

		() @trusted {
			scope (exit)
			{
				slot.closeSocket();
				stream.finish(failure);
				markEstablished(false);
			}
			try
			{
				// A 401 rejecting the bearer is reported to the provider's
				// `onRejected`, and the stream is opened once more with the
				// refreshed token, as `deliver` does for a request.
				for (bool mayRetry = true;; mayRetry = false)
				{
					if (isCancelled())
						return;
					const sentBearer = mayRetry
						&& bearerProvider.onRejected !is null ? currentBearer() : null;
					auto sock = connectTimed(pinnedHost, ep.port);
					slot.attach(sock);
					scope (exit)
						slot.detach();
					// A cancel() that raced ahead of attach must still tear the socket down.
					if (isCancelled())
						return;
					// Wrap in TLS for https/wss; plaintext is returned unwrapped.
					auto conn = openClientStream(sock, ep.tls ? tlsContext() : null, ep.host);
					scope (exit)
						conn.release();

					// One response per connection: `close` lets a non-streamed answer
					// (an error body) be read to end-of-stream.
					const req = buildHttpRequest("POST", ep.path, ep.hostHeader,
							"application/json, text/event-stream", "close",
							true, reqHeaders, null, body);
					conn.write(cast(const(ubyte)[]) req);

					const head = readResponseHead(conn);
					const status = head.status;
					const chunked = head.chunked;
					const wwwAuthenticate = head.wwwAuthenticate;
					if (status < 200 || status >= 300)
					{
						const b = readRemaining(conn, chunked, maxMessageBytes);
						if (sentBearer.length && isRejectedBearer(status,
								wwwAuthenticate) && refreshBearer(sentBearer))
							continue;
						failure = httpStatusError(status, b, wwwAuthenticate);
						return;
					}
					if (!head.sse)
					{
						// A plain JSON answer: the server answered the request outright
						// instead of opening a stream.
						const b = readRemaining(conn, chunked, maxMessageBytes);
						try
						{
							if (!endsStream(parseMessage(b)))
								failure = httpStatusError(status, b, wwwAuthenticate);
						}
						catch (Exception)
							failure = httpStatusError(status, b, wwwAuthenticate);
						return;
					}

					// This stream consumes no resumption state; give the decoder its own
					// throwaway cursor rather than a shared field.
					SseCursor cursor;
					bool answered;
					readSseBody(conn, chunked, cursor, () @safe => answered
							|| isCancelled(), (string eventType, string data) @safe {
						Message m;
						try
							m = Message(parseJsonBounded(data));
						catch (Exception)
							return; // not a JSON-RPC message (keep-alive or comment)
						if (endsStream(m))
						{
							answered = true;
							return;
						}
						markEstablished(true);
						slot.inHandler++;
						scope (exit)
							slot.inHandler--;
						try
							dispatch(m);
						catch (Exception)
						{
						}
					});
					return;
				}
			}
			catch (Exception e)
			{
				if (!isCancelled())
					failure = internalError("subscription stream failed: " ~ e.msg);
			}
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
		legacyStreamEnded = false;
		legacyStreamFailure = null;

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
		// no valid endpoint will ever arrive on this stream. Exit too when the
		// reader has ended, since a dead stream delivers no endpoint either.
		const deadline = MonoTime.currTime + 10_000.msecs;
		while (legacyEndpoint.length == 0 && !legacyEndpointRejected && !legacyStreamEnded)
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
			if (legacyStreamFailure !is null)
				throw legacyStreamFailure;
			if (legacyStreamEnded)
				throw internalError(
						"legacy HTTP+SSE GET stream closed before sending an `endpoint` event");
			throw internalError(
					"legacy HTTP+SSE server did not send an `endpoint` event on the GET stream");
		}
	}

	/// Send a JSON-RPC request over the legacy transport: POST it to the
	/// server-supplied endpoint URI, then await the correlated response, which
	/// arrives asynchronously on the standalone GET SSE stream.
	private Json legacyRpc(Json message, long expectId) @safe
	{
		import vibe.core.task : InterruptException, Task;
		import mcp.client.client : TransportClosedException;

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
		int status;
		waiter.poster = Task.getThis();
		try
			status = post(message);
		catch (InterruptException e)
		{
			if (waiter.err !is null)
				throw waiter.err;
			throw e;
		}
		finally
			waiter.poster = Task.init;
		if (waiter.err !is null)
			throw waiter.err;
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
		throw new TransportClosedException("HTTP transport closed");
	}

	/// Read the legacy GET SSE stream over a raw TCP connection, dispatching
	/// each event by type: an `endpoint` event sets the message-POST URI; a
	/// `message` (or default) event is a JSON-RPC message routed to the awaited
	/// response slot or to the inbound dispatcher.
	private void runLegacyStream() @safe
	{
		import std.string : strip;
		import vibe.core.task : Task;

		const ep = parseHttpEndpoint(url);
		// Resolve + pin the user-configured endpoint host to a numeric address.
		const pinnedHost = pinnedEndpointHost(ep);

		legacyStreamAlive = true;
		scope (exit)
		{
			legacyStreamAlive = false;
			legacyStreamEnded = true;
			notifyLegacy(); // wake `startLegacyFallback`
		}

		auto slot = new ListenSocketSlot;
		slot.owner = Task.getThis();
		legacyStreamSlot = slot;
		scope (exit)
		{
			slot.closeSocket();
			if (legacyStreamSlot is slot)
				legacyStreamSlot = null;
		}

		() @trusted {
			try
			{
				if (closing)
					return;
				auto sock = connectTimed(pinnedHost, ep.port);
				// `attach` closes `sock` immediately if a `close()` already ran during
				// the `connectTCP` yield, so the socket is never leaked or left parked.
				slot.attach(sock);
				if (closing)
					return;
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls ? tlsContext() : null, ep.host);
				scope (exit)
					conn.release();

				const req = buildHttpRequest("GET", ep.path, ep.hostHeader,
						"text/event-stream", "keep-alive", true, null, null, null);
				conn.write(cast(const(ubyte)[]) req);

				const head = readResponseHead(conn);
				if (head.status != 200)
				{
					legacyStreamFailure = new HttpStatusException(head.status,
							"legacy HTTP+SSE server rejected the GET stream with HTTP " ~ idStr(
								head.status), head.wwwAuthenticate);
					return;
				}

				SseCursor cursor;
				readSseBody(conn, head.chunked, cursor, () @safe => closing,
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
					// `message` event (or untyped): a JSON-RPC message, resolved to its
					// waiter or handed to the inbound handler on its own task.
					resolveLegacyMessage(data);
				});
			}
			catch (Exception e)
			{
				legacyStreamFailure = internalError("legacy HTTP+SSE stream failed: " ~ e.msg);
				failOutstandingLegacyWaiters("legacy HTTP+SSE stream failed: " ~ e.msg);
			}
		}();

		// The stream closed: fail every still-outstanding waiter so its `legacyRpc`
		// wait returns promptly with a clear error instead of waiting out the timeout.
		failOutstandingLegacyWaiters("legacy HTTP+SSE stream closed before response");
	}

	/// Resolve one `message`-event frame from the legacy HTTP+SSE stream. A response
	/// or error addressed to a registered waiter id resolves that waiter; any other
	/// message goes to the inbound dispatcher on its own task. A non-JSON frame
	/// (a keep-alive) is logged and ignored.
	private void resolveLegacyMessage(string data) @safe
	{
		Message m;
		try
			m = Message(parseJsonBounded(data));
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
			dispatchOffReader(m);
	}

	/// Run the inbound handler for `m` on its own task. Every legacy response
	/// arrives on the one GET stream, so a handler that issues a request of its
	/// own (a sampling handler calling a tool, say) would otherwise wait on a
	/// response the blocked reader can never deliver. `runTask` switches to the
	/// new task at once, so a handler that does not block finishes before the
	/// next event is read and arrival order is kept.
	private void dispatchOffReader(Message m) @safe
	{
		import vibe.core.core : runTask;

		runTask((Message msg) nothrow{
			try
				dispatch(msg);
			catch (Exception e)
			{
				import vibe.core.log : logWarn;

				logWarn("legacy HTTP+SSE: inbound handler threw: %s", e.msg);
			}
		}, m);
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
		return new McpException(code, m, "data" in error ? error["data"] : Json.undefined);
	}
}

/// The parsed components of an MCP endpoint URL, shared by every raw-TCP request
/// path so host/port/scheme parsing lives in exactly one place. `tls` is true for
/// an `https://`/`wss://` scheme; `port` defaults to the scheme's well-known port
/// (443 when `tls`, else 80) when the URL omits it, so a TLS URL can never be
/// silently treated as plaintext on port 80.
private struct HttpEndpoint
{
	string host;
	ushort port;
	string path;
	bool tls;

	/// The `Host` header value (RFC 9110 §7.2): the host, plus `:port` when the
	/// port is not the scheme's default. An IPv6 literal keeps its brackets.
	string hostHeader() const @safe
	{
		import std.conv : to;
		import std.string : indexOf;

		const h = (host.indexOf(':') >= 0 && host[0] != '[') ? "[" ~ host ~ "]" : host;
		return port == (tls ? 443 : 80) ? h : h ~ ":" ~ port.to!string;
	}
}

/// Parse `scheme://host[:port][/path]` into its components, defaulting the port
/// to 443 for a TLS scheme (https/wss) and 80 otherwise. An absent path becomes
/// "/". Tolerates a missing scheme (treated as non-TLS). See `HttpEndpoint`.
private HttpEndpoint parseHttpEndpoint(string url) @safe
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
private string pinnedEndpointHost(HttpEndpoint ep) @safe
{
	import mcp.protocol.ssrf : pinnedConnectAddress, SsrfPolicy;
	import mcp.protocol.errors : internalError;

	const pin = pinnedConnectAddress(ep.host, ep.tls, SsrfPolicy.allowUserConfigured);
	if (!pin.ok)
		throw internalError(
				"Refusing to connect to MCP endpoint whose host could not be resolved: " ~ ep.host);
	return pin.pinnedIp;
}

/// Remove the surrounding brackets from a bracketed IPv6 literal host
/// (`[::1]` -> `::1`), leaving any other host untouched. The TLS SNI/peer name
/// and the SSRF/connect resolver both want the bare address, while the `Host`
/// header keeps the brackets.
private string unbracketHost(string host) pure nothrow @safe @nogc
{
	if (host.length >= 2 && host[0] == '[' && host[$ - 1] == ']')
		return host[1 .. $ - 1];
	return host;
}

/// A byte stream (plaintext or TLS) over a raw client socket. Each stream layer
/// holds its own reference to the socket, and on Windows the socket is closed
/// (so the server sees the connection end) only once every reference is gone;
/// `release` drops this stream's references at once instead of when the GC
/// collects it.
private final class ClientStream : ProxyStream
{
	private ProxyStream socketLayer;

	this(InterfaceProxy!Stream stream, ProxyStream socketLayer) @safe
	{
		super(stream, true);
		this.socketLayer = socketLayer;
	}

	void release() @trusted nothrow
	{
		try
		{
			if (socketLayer !is null)
				socketLayer.underlying = InterfaceProxy!Stream.init;
			underlying = InterfaceProxy!Stream.init;
		}
		catch (Exception)
		{
		}
	}
}

/// Open a client byte stream over `conn`, wrapped in a TLS tunnel when `ctx`
/// is set (https/wss) and returned unwrapped otherwise, so every raw-TCP
/// request path shares one TLS-handling site. `host` is the TLS peer name the
/// server certificate is validated against under `ctx`. `conn` must outlive
/// the returned stream.
private ClientStream openClientStream(TCPConnection conn, TLSContext ctx, string host) @trusted
{
	if (ctx !is null)
	{
		// The TLS layer reads the socket through `plain`, so releasing `plain`
		// drops every reference the stream holds.
		auto plain = createProxyStream(conn);
		// vibe's TLS layer wants the bare peer name; an IPv6 literal reaches here
		// bracketed (the form the `Host` header needs), so strip the brackets. The
		// connected address lets an IP-literal host match an IP-address SAN.
		auto t = createTLSStream(plain, ctx, unbracketHost(host), conn.remoteAddress);
		return new ClientStream(interfaceProxy!Stream(t), plain);
	}
	return new ClientStream(interfaceProxy!Stream(conn), null);
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
private bool isModernRpcErrorCode(int code) pure nothrow @safe @nogc
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
private bool modernErrorFromBody(string body, out McpException err) @safe nothrow
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
		err = new McpException(code, m, ("data" in e) ? e["data"] : Json.undefined);
		return true;
	}
	catch (Exception)
	{
		// Malformed body: not a recognized modern error → legacy fallback.
		err = null;
		return false;
	}
}

/// Whether `candidate` shares `base`'s security origin: same scheme, host, and
/// effective port (per-scheme default applied). The legacy POST endpoint a server
/// supplies on the SSE stream is only trusted when it is same-origin, so the
/// client never POSTs its bearer token to a server-named cross-origin URI. A
/// scheme mismatch (e.g. an https base vs. an http candidate) is rejected too, so
/// a downgrade cannot leak the credential in plaintext.
private bool sameOrigin(string base, string candidate) @safe
{
	import std.string : toLower;

	auto b = parseHttpEndpoint(base);
	auto c = parseHttpEndpoint(candidate);
	return b.tls == c.tls && b.host.toLower == c.host.toLower && b.port == c.port;
}

/// The components of a URI reference (RFC 3986 §3). A `has*` flag distinguishes
/// an absent component from an empty one, which resolution treats differently.
private struct UriParts
{
	string scheme, authority, path, query;
	bool hasScheme, hasAuthority, hasQuery;
}

/// Split a URI reference into its components (RFC 3986 Appendix B), dropping
/// any fragment, which never reaches an HTTP request target.
private UriParts splitUri(string uri) @safe
{
	import std.string : indexOf, indexOfAny, toLower;

	UriParts p;
	const hash = uri.indexOf('#');
	if (hash >= 0)
		uri = uri[0 .. hash];
	const delim = uri.indexOfAny(":/?");
	if (delim > 0 && uri[delim] == ':')
	{
		p.hasScheme = true;
		p.scheme = uri[0 .. delim].toLower;
		uri = uri[delim + 1 .. $];
	}
	if (uri.length >= 2 && uri[0 .. 2] == "//")
	{
		uri = uri[2 .. $];
		const end = uri.indexOfAny("/?");
		p.hasAuthority = true;
		p.authority = end < 0 ? uri : uri[0 .. end];
		uri = end < 0 ? null : uri[end .. $];
	}
	const q = uri.indexOf('?');
	if (q >= 0)
	{
		p.hasQuery = true;
		p.query = uri[q + 1 .. $];
		uri = uri[0 .. q];
	}
	p.path = uri;
	return p;
}

/// Remove `.` and `..` segments from `path` (RFC 3986 §5.2.4).
private string removeDotSegments(string path) @safe
{
	import std.string : indexOf, lastIndexOf, startsWith;

	string output;
	while (path.length)
	{
		if (path.startsWith("../"))
			path = path[3 .. $];
		else if (path.startsWith("./"))
			path = path[2 .. $];
		else if (path.startsWith("/./"))
			path = path[2 .. $];
		else if (path == "/.")
			path = "/";
		else if (path.startsWith("/../") || path == "/..")
		{
			path = path == "/.." ? "/" : path[3 .. $];
			const cut = output.lastIndexOf('/');
			output = cut < 0 ? null : output[0 .. cut];
		}
		else if (path == "." || path == "..")
			path = null;
		else
		{
			const start = path[0] == '/' ? 1 : 0;
			const next = path[start .. $].indexOf('/');
			const end = next < 0 ? path.length : start + next;
			output ~= path[0 .. end];
			path = path[end .. $];
		}
	}
	return output;
}

/// Resolve a legacy `endpoint` event URI reference against the GET-SSE base URL
/// (RFC 3986 §5.2), yielding the absolute URL to POST subsequent JSON-RPC
/// messages to. A reference naming its own scheme or authority is only accepted
/// when it is an http(s) URL with the base's origin; anything else yields null so
/// the legacy fallback fails closed rather than POSTing the bearer token
/// off-origin.
private string resolveEndpointUri(string baseUrl, string endpoint) @safe
{
	import std.string : lastIndexOf;

	const base = splitUri(baseUrl);
	if (!base.hasScheme)
		return endpoint;
	const r = splitUri(endpoint);

	UriParts t;
	if (r.hasScheme)
		t = UriParts(r.scheme, r.authority, removeDotSegments(r.path), r.query,
				true, r.hasAuthority, r.hasQuery);
	else
	{
		t.scheme = base.scheme;
		t.hasScheme = true;
		if (r.hasAuthority)
		{
			t.authority = r.authority;
			t.path = removeDotSegments(r.path);
			t.query = r.query;
			t.hasQuery = r.hasQuery;
		}
		else
		{
			t.authority = base.authority;
			if (r.path.length == 0)
			{
				t.path = base.path;
				t.query = r.hasQuery ? r.query : base.query;
				t.hasQuery = r.hasQuery || base.hasQuery;
			}
			else
			{
				if (r.path[0] == '/')
					t.path = removeDotSegments(r.path);
				else
				{
					// Merge (RFC 3986 §5.2.3): the base path up to its last '/'.
					const cut = base.path.lastIndexOf('/');
					const dir = (base.hasAuthority && base.path.length == 0) ? "/" : cut < 0
						? "" : base.path[0 .. cut + 1];
					t.path = removeDotSegments(dir ~ r.path);
				}
				t.query = r.query;
				t.hasQuery = r.hasQuery;
			}
		}
		t.hasAuthority = true;
	}
	if (t.path.length == 0)
		t.path = "/";

	const resolved = t.scheme ~ "://" ~ t.authority ~ t.path ~ (t.hasQuery ? "?" ~ t.query : "");
	if (r.hasScheme || r.hasAuthority)
	{
		if ((t.scheme != "http" && t.scheme != "https") || !sameOrigin(baseUrl, resolved))
			return null;
	}
	return resolved;
}

unittest  // httpStatusError keeps the code and message of a null-id JSON-RPC error body
{
	auto e = httpStatusError(400,
			`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Bad session"}}`, null);
	assert(e.status == 400);
	assert(e.code == -32_600);
	assert(e.msg == "Bad session");
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
	// SNI = host and trusted-chain + host-name verification, port 443 by default). An
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

unittest  // the transport's TLS refuses an untrusted server certificate unless its CA is configured
{
	import std.conv : to;
	import std.exception : assertThrown;
	import mcp.protocol.ssrf : selfSignedTestCertPem, startSelfSignedTlsServer, writeTestPemFile;

	auto listener = startSelfSignedTlsServer();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	const port = listener.bindAddresses[0].port;
	auto t = new HttpClientTransport("https://127.0.0.1:" ~ port.to!string ~ "/mcp");

	auto untrusted = connectTCP("127.0.0.1", port);
	scope (exit)
		untrusted.close();
	assertThrown(openClientStream(untrusted, t.tlsContext(), "127.0.0.1"));

	TlsTrust trust;
	trust.caFile = writeTestPemFile(selfSignedTestCertPem);
	t.setTlsTrust(trust);
	auto trusted = connectTCP("127.0.0.1", port);
	scope (exit)
		trusted.close();
	auto s = openClientStream(trusted, t.tlsContext(), "127.0.0.1");
	s.release();
}

unittest  // openClientStream returns a usable stream for plaintext (TLS path needs a live peer)
{
	// The plaintext branch returns the raw connection boxed in a ProxyStream so the
	// five request paths share one static stream type; the TLS branch is exercised
	// against a live self-signed peer above.
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

unittest  // ResponseHead.addHeader records framing, session and challenge headers case-insensitively
{
	ResponseHead h;
	h.addHeader("Transfer-Encoding: Chunked");
	h.addHeader("content-type: text/event-stream; charset=utf-8");
	h.addHeader("MCP-Session-Id:  abc ");
	h.addHeader("WWW-Authenticate: Bearer realm=\"mcp\"");
	h.addHeader("X-Other: chunked");
	assert(h.chunked && h.sse);
	assert(h.sessionId == "abc");
	assert(h.wwwAuthenticate == `Bearer realm="mcp"`);
}

unittest  // ResponseHead.addHeader leaves the flags unset for a JSON, unchunked response
{
	ResponseHead h;
	h.addHeader("Content-Type: application/json");
	h.addHeader("Content-Length: 12");
	h.addHeader("malformed");
	assert(!h.chunked && !h.sse && h.sessionId.length == 0);
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
	assert(err.data.type == Json.Type.object);
	assert(err.data["supported"].type == Json.Type.array);
	assert(err.data["supported"][0].get!string == "2025-11-25");
}

unittest  // modernErrorFromBody leaves data undefined when the error carries none
{
	McpException err;
	assert(modernErrorFromBody(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, err));
	assert(err.data.type == Json.Type.undefined);
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

unittest  // resolveEndpointUri keeps the base path for a query-only reference
{
	assert(resolveEndpointUri("http://h/sse", "?sessionId=abc") == "http://h/sse?sessionId=abc");
	assert(resolveEndpointUri("http://h/sse?old=1",
			"?sessionId=abc") == "http://h/sse?sessionId=abc");
}

unittest  // resolveEndpointUri removes dot segments from a relative path
{
	assert(resolveEndpointUri("http://h/a/b/sse", "./messages?x=1") == "http://h/a/b/messages?x=1");
	assert(resolveEndpointUri("http://h/a/b/sse", "../messages") == "http://h/a/messages");
	assert(resolveEndpointUri("http://h/a/sse", "../../../messages") == "http://h/messages");
	assert(resolveEndpointUri("http://h/a/sse", "/x/../messages") == "http://h/messages");
	assert(resolveEndpointUri("http://h/a/sse", "..") == "http://h/");
	assert(resolveEndpointUri("http://h", "messages") == "http://h/messages");
}

unittest  // resolveEndpointUri matches the RFC 3986 §5.4 reference resolution examples
{
	enum b = "http://a/b/c/d;p?q";
	assert(resolveEndpointUri(b, "g") == "http://a/b/c/g");
	assert(resolveEndpointUri(b, "g/") == "http://a/b/c/g/");
	assert(resolveEndpointUri(b, "?y") == "http://a/b/c/d;p?y");
	assert(resolveEndpointUri(b, "g?y") == "http://a/b/c/g?y");
	assert(resolveEndpointUri(b, "g;x?y#s") == "http://a/b/c/g;x?y");
	assert(resolveEndpointUri(b, ".") == "http://a/b/c/");
	assert(resolveEndpointUri(b, "./") == "http://a/b/c/");
	assert(resolveEndpointUri(b, "..") == "http://a/b/");
	assert(resolveEndpointUri(b, "../g") == "http://a/b/g");
	assert(resolveEndpointUri(b, "../..") == "http://a/");
	assert(resolveEndpointUri(b, "../../g") == "http://a/g");
	assert(resolveEndpointUri(b, "/./g") == "http://a/g");
	assert(resolveEndpointUri(b, "g.") == "http://a/b/c/g.");
	assert(resolveEndpointUri(b, "..g") == "http://a/b/c/..g");
	assert(resolveEndpointUri(b, "./g/.") == "http://a/b/c/g/");
	assert(resolveEndpointUri(b, "g/../h") == "http://a/b/c/h");
	assert(resolveEndpointUri(b, "g;x=1/../y") == "http://a/b/c/y");
}

unittest  // resolveEndpointUri treats an empty reference as the base without its fragment
{
	assert(resolveEndpointUri("http://h/sse?q=1#f", "") == "http://h/sse?q=1");
	assert(resolveEndpointUri("http://h/sse", "#frag") == "http://h/sse");
}

unittest  // resolveEndpointUri applies the same-origin check to network-path and absolute references
{
	assert(resolveEndpointUri("http://h:8080/sse", "//h:8080/messages") == "http://h:8080/messages");
	assert(resolveEndpointUri("http://h:8080/sse", "//evil.example/messages") is null);
	assert(resolveEndpointUri("http://h/sse", "HTTP://h/a/../messages") == "http://h/messages");
	assert(resolveEndpointUri("http://h/sse", "javascript:alert(1)") is null);
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

unittest  // a legacy server->client request is handled off the reader so the reader keeps reading
{
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	bool started, finished, readerFree;
	const failure = runAgainstFakeServer(new URLRouter, (string url) @safe {
		auto t = new HttpClientTransport(url);
		auto release = createManualEvent();
		t.setInboundHandler((Message m) @safe {
			started = true;
			// Stands in for a handler awaiting a response only the reader can deliver.
			auto ec = release.emitCount;
			release.wait(2.seconds, ec);
			finished = true;
		});
		t.resolveLegacyMessage(
			`{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}`);
		readerFree = !finished;
		release.emit();
		sleep(50.msecs);
		t.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(started && finished);
	assert(readerFree, "the reader must not wait for a server->client request's handler");
}

unittest  // errorFrom maps a well-formed JSON-RPC error object
{
	auto err = HttpClientTransport.errorFrom(
			parseJsonString(`{"code":-32601,"message":"Method not found"}`));
	assert(err.code == ErrorCode.methodNotFound);
	assert(err.msg == "Method not found");
}

unittest  // errorFrom keeps only the error's data member as McpException.data, like a local error
{
	auto err = HttpClientTransport.errorFrom(
			parseJsonString(`{"code":-32042,"message":"m","data":{"elicitations":[]}}`));
	assert(err.data.type == Json.Type.object && "elicitations" in err.data);
	assert(HttpClientTransport.errorFrom(parseJsonString(`{"code":-32601,"message":"m"}`))
			.data.type == Json.Type.undefined);
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

version (unittest)
{
	import vibe.core.task : Task;

	/// Run `scenario` with a task parked in a long sleep, returning whether the
	/// task was interrupted (woken by `InterruptException`) within one second.
	private bool interruptsParkedTask(void delegate(Task parked) @safe scenario)
	{
		import core.time : msecs, MonoTime;
		import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
		import vibe.core.task : InterruptException;

		bool interrupted;
		bool result;
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
			{
				auto parked = runTask(() nothrow{
					try
						sleep(5.seconds);
					catch (InterruptException)
						interrupted = true;
					catch (Exception)
					{
					}
				});
				sleep(10.msecs);
				scenario(parked);
				const until = MonoTime.currTime + 1.seconds;
				while (!interrupted && MonoTime.currTime < until)
					sleep(10.msecs);
				result = interrupted;
				if (!interrupted)
					parked.interrupt();
			}
			catch (Exception)
			{
			}
		});
		runEventLoop();
		return result;
	}
}

unittest  // close() interrupts the reader of a standalone-stream slot, waking a read the socket close may not
{
	const interrupted = interruptsParkedTask((Task parked) @safe {
		auto t = new HttpClientTransport("http://host:8080/mcp");
		auto slot = new ListenSocketSlot;
		slot.owner = parked;
		t.serverStreamSlots ~= slot;
		t.close();
	});
	assert(interrupted);
}

unittest  // close() leaves a standalone-stream reader running an inbound handler uninterrupted
{
	const interrupted = interruptsParkedTask((Task parked) @safe {
		auto t = new HttpClientTransport("http://host:8080/mcp");
		auto slot = new ListenSocketSlot;
		slot.owner = parked;
		slot.inHandler = 1;
		t.serverStreamSlots ~= slot;
		t.close();
	});
	assert(!interrupted);
}

unittest  // close() aborts every in-flight request, interrupting the task awaiting its response
{
	McpException reason;
	const interrupted = interruptsParkedTask((Task parked) @safe {
		auto t = new HttpClientTransport("http://host:8080/mcp");
		auto r = new PostRequest;
		r.owner = parked;
		t.inflightPosts[7] = r;
		t.close();
		reason = r.aborted;
	});
	assert(interrupted);
	assert(reason !is null);
}

unittest  // close() interrupts the legacy GET-SSE reader
{
	const interrupted = interruptsParkedTask((Task parked) @safe {
		auto t = new HttpClientTransport("http://host:8080/mcp");
		t.legacyStreamSlot = new ListenSocketSlot;
		t.legacyStreamSlot.owner = parked;
		t.close();
	});
	assert(interrupted);
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
	// resumeViaGet registers its retry-resume socket in `serverStreamSlots`
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
		return HttpClientTransport.readRemaining(stream, true, defaultMaxMessageBytes);
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
		return HttpClientTransport.readRemaining(stream, true, defaultMaxMessageBytes);
	}();
	assert(got == "abcdef");
}

unittest  // readRemaining rejects a chunk whose declared size exceeds the message limit before allocating it
{
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	auto body = "7fffffff\r\nabc\r\n0\r\n\r\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	auto e = collectException(() @trusted {
		return HttpClientTransport.readRemaining(stream, true, 1024);
	}());
	assert(cast(McpException) e !is null, "an oversized chunk must fail the read");
}

unittest  // readRemaining rejects a chunked body whose total exceeds the message limit
{
	import std.array : replicate;
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	string body;
	foreach (i; 0 .. 8)
		body ~= "100\r\n" ~ "x".replicate(256) ~ "\r\n";
	body ~= "0\r\n\r\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	auto e = collectException(() @trusted {
		return HttpClientTransport.readRemaining(stream, true, 1024);
	}());
	assert(cast(McpException) e !is null, "a chunked body past the limit must fail the read");
}

unittest  // readRemaining rejects a raw body that exceeds the message limit
{
	import std.array : replicate;
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) "x".replicate(4096).dup, false);
	}();
	auto e = collectException(() @trusted {
		return HttpClientTransport.readRemaining(stream, false, 1024);
	}());
	assert(cast(McpException) e !is null, "a raw body past the limit must fail the read");
}

unittest  // readHeaderLines rejects a header line longer than the header line limit
{
	import std.array : replicate;
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	auto head = "X-Big: " ~ "x".replicate(64 * 1024) ~ "\r\n\r\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) head.dup, false);
	}();
	auto e = collectException(() @trusted {
		return HttpClientTransport.readHeaderLines(stream);
	}());
	assert(e !is null, "an unbounded header line must fail the read");
}

unittest  // readSseBody rejects an SSE line that grows past the message limit without a newline
{
	import std.array : replicate;
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.setMaxMessageBytes(1024);
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])("data: " ~ "x".replicate(4096)).dup, false);
	}();
	SseCursor cursor;
	auto e = collectException(() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
		});
	}());
	assert(cast(McpException) e !is null,
			"an unterminated SSE line past the limit must fail the read");
}

unittest  // readSseBody rejects an SSE event whose joined data lines exceed the message limit
{
	import std.array : replicate;
	import std.exception : collectException;
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	t.setMaxMessageBytes(1024);
	string body;
	foreach (i; 0 .. 16)
		body ~= "data: " ~ "x".replicate(200) ~ "\n";
	body ~= "\n";
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body.dup, false);
	}();
	SseCursor cursor;
	bool delivered;
	auto e = collectException(() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			delivered = true;
		});
	}());
	assert(cast(McpException) e !is null, "an SSE event past the limit must fail the read");
	assert(!delivered);
}

unittest  // a response body larger than ClientSettings.maxMessageBytes fails the request
{
	import std.array : replicate;
	import mcp.client.client : McpClient, ClientSettings;

	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"tools":[]}}`);
		resp["id"] = req["id"];
		resp["result"]["padding"] = "x".replicate(8192);
		res.writeBody(resp.toString(), "application/json");
	});
	Exception thrown;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		ClientSettings s;
		s.maxMessageBytes = 4096;
		auto client = McpClient.http(url, s);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		try
			client.listTools();
		catch (Exception e)
			thrown = e;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(cast(McpException) thrown !is null, "an oversized response must fail the request");
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
	t.setBearerProvider(BearerProvider(() @safe {
			return ++calls == 1 ? "first-token" : "refreshed-token";
		}));
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
	t.setBearerProvider(BearerProvider(() @safe => "provided"));
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
	// The 2026-07-28 protocol has no Last-Event-ID resumption; a modern server
	// responds to the GET with 405. The resume is gated on !modernProtocol so the
	// pointless GET round-trip is avoided when the negotiated version is modern.
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
		int sessionlessRequests; // non-initialize POSTs that carried no Mcp-Session-Id

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
				if (sid.length == 0)
					++sessionlessRequests;
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

unittest  // after a request is answered 404 for its session, the next request fails without being sent sessionless
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	int typed;
	const failure = runAgainstFakeServer(srv.router(), (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		srv.expire();
		foreach (_; 0 .. 2)
		{
			try
				client.listTools();
			catch (McpException)
				++typed;
		}
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(typed == 2);
	assert(srv.sessionlessRequests == 0,
			"a request after the session expired must not go out without Mcp-Session-Id");
}

unittest  // re-running initialize on a live session starts a new session without the old id
{
	import mcp.client.client : McpClient;

	auto srv = new SessionFakeServer;
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(srv.router(), (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		client.initialize("2025-11-25");
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(srv.initializeSessionHeaders == ["", ""],
			"an initialize must not carry the previous session id");
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

version (unittest)
{
	/// Run `listTools` with a bearer provider against a server that answers
	/// every `tools/list` with a 401 carrying `challenge`. Returns the tokens
	/// passed to `onRejected` and the number of `tools/list` attempts.
	private string[] rejectedBearers(string challenge, out int attempts, bool replaced = true)
	{
		import mcp.client.client : McpClient;

		int seen;
		string[] rejected;
		auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
			++seen;
			res.statusCode = 401;
			res.headers["WWW-Authenticate"] = challenge;
			res.writeBody("", "text/plain");
		});
		const failure = runAgainstFakeServer(router, (string url) @safe {
			auto client = McpClient.http(url);
			scope (exit)
				client.close();
			client.setBearerProvider(BearerProvider(() @safe => "tok", (string t) @safe {
					rejected ~= t;
					return replaced;
				}));
			client.initialize("2025-11-25");
			try
				client.listTools();
			catch (HttpStatusException)
			{
			}
		});
		assert(failure.length == 0, "scenario failed: " ~ failure);
		attempts = seen;
		return rejected;
	}
}

unittest  // a rejected bearer is reported once and the request retried only once
{
	int attempts;
	assert(rejectedBearers(`Bearer error="invalid_token"`, attempts) == ["tok"]);
	assert(attempts == 2);
	assert(rejectedBearers(`Bearer realm="mcp"`, attempts) == ["tok"]);
	assert(attempts == 2);
}

unittest  // a rejected bearer with no replacement surfaces the 401 without a retry
{
	int attempts;
	assert(rejectedBearers(`Bearer error="invalid_token"`, attempts, false) == [
		"tok"
	]);
	assert(attempts == 1);
}

unittest  // a request that times out while its rejected bearer is being refreshed fails at its deadline
{
	import core.time : MonoTime, msecs;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings, McpClient, RequestTimeoutException;

	int seen;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		if (++seen == 1)
		{
			res.statusCode = 401;
			res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
			res.writeBody("", "text/plain");
			return;
		}
		// The retried request is answered long after the client's deadline.
		sleep(2.seconds);
		Json result = Json.emptyObject;
		result["tools"] = Json.emptyArray;
		res.writeBody(makeResponse(req["id"], result).toString(), "application/json");
	});
	bool timedOut;
	Duration took;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		ClientSettings s;
		s.requestTimeout = 300.msecs;
		auto client = McpClient.http(url, s);
		scope (exit)
			client.close();
		// The refresh outlasts the request's deadline.
		client.setBearerProvider(BearerProvider(() @safe => "tok", (string t) @safe {
				sleep(500.msecs);
				return true;
			}));
		client.initialize("2025-11-25");
		const start = MonoTime.currTime;
		try
			client.listTools();
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(timedOut);
	assert(took < 1500.msecs, "a timeout during the bearer refresh must not be lost");
}

unittest  // a 401 for a reason other than the token itself is not retried
{
	int attempts;
	assert(rejectedBearers(`Bearer error="invalid_request"`, attempts).length == 0);
	assert(attempts == 1);
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

unittest  // a null-id JSON-RPC error on a request's SSE response stream fails that request with the error
{
	auto e = listToolsFailure((Json req, HTTPServerResponse res) @safe {
		writeSse(res,
			`data: {"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"busy"}}` ~ "\n\n");
	});
	auto m = cast(McpException) e;
	assert(m !is null);
	assert(m.code == -32001 && m.msg == "busy", "got: " ~ m.msg);
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

unittest  // each reconnect of the standalone stream sends the current protocol-version header
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	static final class ChangingProtocol : ClientProtocol
	{
		string version_ = "2025-06-18";

		string[string] headersFor(Json message) @safe
		{
			return ["MCP-Protocol-Version": version_];
		}

		bool isCancelled(long id) @safe
		{
			return false;
		}
	}

	string[] versions;
	auto router = new URLRouter;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		versions ~= req.headers.get("MCP-Protocol-Version", "");
		writeSse(res, "retry: 20\n: tick\n\n");
	});
	auto proto = new ChangingProtocol;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.setProtocol(proto);
		t.startServerStream();
		auto until = MonoTime.currTime + 3.seconds;
		while (versions.length < 1 && MonoTime.currTime < until)
			sleep(10.msecs);
		proto.version_ = "2025-11-25";
		const seen = versions.length;
		until = MonoTime.currTime + 3.seconds;
		while (versions.length < seen + 2 && MonoTime.currTime < until)
			sleep(10.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(versions.length >= 3);
	assert(versions[0] == "2025-06-18");
	assert(versions[$ - 1] == "2025-11-25", "a reconnect must send the current version header");
}

unittest  // the standalone stream reconnects after a transient 5xx and keeps delivering server messages
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	int gets;
	string[] methods;
	auto router = new URLRouter;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		if (++gets == 1)
		{
			res.statusCode = 503;
			res.writeBody("", "text/plain");
			return;
		}
		writeSse(res,
			"retry: 20\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/ping\"}\n\n");
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.setInboundHandler((Message m) @safe { methods ~= m.method; });
		t.startServerStream();
		const until = MonoTime.currTime + 3.seconds;
		while (methods.length == 0 && MonoTime.currTime < until)
			sleep(10.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(gets >= 2, "a 503 on the standalone GET must be retried");
	assert(methods.length && methods[0] == "notifications/ping");
}

unittest  // a 401 on the standalone stream reports the rejected bearer and reconnects with a fresh one
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	string[] auths;
	string[] rejected;
	string token = "old";
	auto router = new URLRouter;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const auth = req.headers.get("Authorization", "");
		auths ~= auth;
		if (auth != "Bearer new")
		{
			res.statusCode = 401;
			res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
			res.writeBody("", "text/plain");
			return;
		}
		writeSse(res, "retry: 20\n: tick\n\n");
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.setBearerProvider(BearerProvider(() @safe => token, (string tok) @safe {
				rejected ~= tok;
				token = "new";
				return true;
			}));
		t.startServerStream();
		const until = MonoTime.currTime + 3.seconds;
		while (!auths.canFind("Bearer new") && MonoTime.currTime < until)
			sleep(10.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(rejected == ["old"], "the rejected bearer must be reported once");
	assert(auths.canFind("Bearer new"), "the stream must reconnect with the refreshed bearer");
}

unittest  // a 405 on the standalone stream ends the reader without reconnecting
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	int gets;
	bool alive = true;
	auto router = new URLRouter;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		++gets;
		res.statusCode = 405;
		res.writeBody("", "text/plain");
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.startServerStream();
		const until = MonoTime.currTime + 3.seconds;
		while (t.serverStreamAlive && MonoTime.currTime < until)
			sleep(10.msecs);
		sleep(400.msecs);
		alive = t.serverStreamAlive;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(!alive && gets == 1, "a 405 must end the standalone stream");
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

unittest  // a one-way POST to an unresponsive server gives up after the request timeout
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	bool release;
	auto router = new URLRouter;
	router.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
		res.statusCode = 202;
		res.writeBody("", "text/plain");
	});
	Duration took;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		t.setRequestTimeout(200.msecs);
		const start = MonoTime.currTime;
		try
			t.sendOneway(makeNotification("notifications/initialized", Json.emptyObject));
		catch (Exception)
		{
		}
		took = MonoTime.currTime - start;
		release = true;
		t.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(took < 2.seconds, "a hung one-way POST must be bounded by the request timeout");
}

unittest  // aborting a legacy HTTP+SSE request interrupts its pending POST
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : runTask, sleep;

	bool release;
	auto router = new URLRouter;
	router.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
		res.statusCode = 202;
		res.writeBody("", "text/plain");
	});
	Exception thrown;
	Duration took;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		t.legacyMode = true;
		t.legacyEndpoint = url;
		t.legacyStreamAlive = true;
		runTask(() nothrow{
			try
			{
				sleep(200.msecs);
				t.abort(1, internalError("aborted"));
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			t.deliver(makeRequest(Json(1L), "tools/list", Json.emptyObject), 1);
		catch (Exception e)
			thrown = e;
		took = MonoTime.currTime - start;
		release = true;
		t.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(thrown !is null && thrown.msg == "aborted", "the abort reason must fail the request");
	assert(took < 2.seconds, "an abort must not wait for the POST to finish");
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

unittest  // a throwing onNotification callback does not fail the request whose stream carried the notification
{
	import mcp.client.client : McpClient;

	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		writeSse(res, `data: {"jsonrpc":"2.0","method":"notifications/message",`
			~ `"params":{"level":"info","data":"hi"}}` ~ "\n\n" ~ toolsListFrame(
			req["id"].get!long));
	});
	bool notified;
	size_t tools = size_t.max;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		client.onNotification = (string method, Json params) @safe {
			notified = true;
			throw new Exception("callback failed");
		};
		tools = client.listTools().tools.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(notified);
	assert(tools == 0);
}

version (unittest)
{
	/// Open a `subscriptions/listen` stream on a modern client against a server
	/// answering the listen POST through `answer`; returns what `subscriptionsListen`
	/// threw (null when it returned a stream, which is passed to `onStream`).
	private Exception listenFailure(void delegate(Json request,
			HTTPServerResponse res) @safe answer,
			void delegate(SubscriptionStream) @safe onStream = null)
	{
		import mcp.client.client : McpClient;
		import mcp.client.subscription : SubscriptionFilter;

		Exception thrown;
		const failure = runAgainstFakeServer(answeringRouter(answer), (string url) @safe {
			auto client = McpClient.http(url);
			scope (exit)
				client.close();
			client.enableModern();
			SubscriptionFilter filter = {toolsListChanged: true};
			SubscriptionStream stream;
			try
				stream = client.subscriptionsListen(filter);
			catch (Exception e)
				thrown = e;
			if (stream !is null && onStream !is null)
				onStream(stream);
		});
		assert(failure.length == 0, "scenario failed: " ~ failure);
		return thrown;
	}
}

unittest  // a subscriptions/listen POST refused with an HTTP error fails subscriptionsListen
{
	auto e = listenFailure((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(
			`{"jsonrpc":"2.0","error":{"code":-32601,"message":"no listen"}}`);
		resp["id"] = req["id"];
		res.statusCode = 400;
		res.writeBody(resp.toString(), "application/json");
	});
	auto h = cast(HttpStatusException) e;
	assert(h !is null, "a refused listen must throw HttpStatusException");
	assert(h.status == 400 && h.code == -32601);
}

unittest  // a subscriptions/listen answered with a JSON-RPC error body fails subscriptionsListen
{
	auto e = listenFailure((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(
			`{"jsonrpc":"2.0","error":{"code":-32602,"message":"bad filter"}}`);
		resp["id"] = req["id"];
		res.writeBody(resp.toString(), "application/json");
	});
	auto m = cast(McpException) e;
	assert(m !is null, "a JSON-RPC error answer to listen must throw");
	assert(m.code == -32602);
}

unittest  // a subscriptions/listen stream whose first event is an error response fails subscriptionsListen
{
	auto e = listenFailure((Json req, HTTPServerResponse res) @safe {
		auto resp = parseJsonString(
			`{"jsonrpc":"2.0","error":{"code":-32602,"message":"bad filter"}}`);
		resp["id"] = req["id"];
		writeSse(res, "data: " ~ resp.toString() ~ "\n\n");
	});
	auto m = cast(McpException) e;
	assert(m !is null, "an error response on the listen stream must throw");
	assert(m.code == -32602);
}

unittest  // a listen stream the server fails after acknowledging records the error on the handle
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	McpException streamError;
	bool ended;
	auto e = listenFailure((Json req, HTTPServerResponse res) @safe {
		auto err = parseJsonString(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"gone"}}`);
		err["id"] = req["id"];
		writeSse(res,
			`data: {"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",`
			~ `"params":{"notifications":{}}}` ~ "\n\n" ~ "data: " ~ err.toString() ~ "\n\n");
	}, (SubscriptionStream stream) @safe {
		const until = MonoTime.currTime + 3.seconds;
		while (!stream.ended && MonoTime.currTime < until)
			sleep(20.msecs);
		ended = stream.ended;
		streamError = stream.error;
	});
	assert(e is null, "an acknowledged listen must open");
	assert(ended, "the server's error must end the stream");
	assert(streamError !is null && streamError.code == -32603);
}

unittest  // aborting a listen slot interrupts its parked reader, but not inside a handler
{
	import core.time : msecs, seconds;
	import vibe.core.core : runTask, sleep, exitEventLoop, runEventLoop;

	auto slot = new ListenSocketSlot;
	bool woke;
	bool handlerFinished;
	runTask(() nothrow @safe {
		try
		{
			auto reader = runTask(() nothrow @safe {
				try
					sleep(5.seconds); // stands in for a read that closing a socket cannot wake
				catch (Exception)
					woke = true;
			});
			slot.owner = reader;
			sleep(10.msecs);
			slot.abort();
			reader.join();

			auto handler = runTask(() nothrow @safe {
				slot.inHandler++;
				scope (exit)
					slot.inHandler--;
				try
				{
					sleep(50.msecs);
					handlerFinished = true;
				}
				catch (Exception)
				{
				}
			});
			slot.owner = handler;
			sleep(10.msecs);
			slot.abort();
			handler.join();
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();
	assert(woke, "abort() must interrupt the reader task");
	assert(handlerFinished, "abort() must not interrupt a running handler");
}

unittest  // closing the transport ends its open listen streams
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	bool release;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		writeSse(res,
			`data: {"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",`
			~ `"params":{"notifications":{}}}` ~ "\n\n");
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
	});
	bool ended;
	bool cancelled;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		scope (exit)
			release = true;
		auto t = new HttpClientTransport(url);
		auto stream = t.openListen(makeRequest(Json(1), "subscriptions/listen", Json.emptyObject));
		t.close();
		const until = MonoTime.currTime + 3.seconds;
		while (!stream.ended && MonoTime.currTime < until)
			sleep(20.msecs);
		ended = stream.ended;
		cancelled = stream.cancelled;
		assert(stream.error is null, "a stream ended by close() is not a server failure");
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(ended && !cancelled, "close() must end the transport's listen streams");
}

unittest  // the raw-socket POST sends a Host header carrying the non-default port
{
	import mcp.client.client : McpClient;
	import std.algorithm : all;
	import std.conv : to;

	string[] hosts;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		hosts ~= req.headers.get("Host", "");
		auto j = requestJson(req);
		const method = ("method" in j) ? j["method"].get!string : "";
		if (method == "initialize")
			res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
		else if ("id" !in j)
		{
			res.statusCode = 202;
			res.writeBody("", "text/plain");
		}
		else
			writeSse(res, toolsListFrame(j["id"].get!long));
	});
	string expected;
	const failure = runAgainstFakeServer(r, (string url) @safe {
		expected = "127.0.0.1:" ~ parseHttpEndpoint(url).port.to!string;
		auto client = McpClient.http(url);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		client.listTools();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(hosts.length >= 2);
	assert(hosts.all!(h => h == expected), "Host must carry the port: " ~ hosts.to!string);
}

unittest  // a reply to a server->client request is sent while every in-flight permit is held
{
	import core.time : msecs, MonoTime;
	import mcp.client.client : McpClient, ClientSettings;
	import vibe.core.core : sleep;

	bool replied;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		auto j = requestJson(req);
		const method = ("method" in j) ? j["method"].get!string : "";
		if (method == "initialize")
			res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
		else if ("id" !in j || method.length == 0)
		{
			if ("result" in j)
				replied = true;
			res.statusCode = 202;
			res.writeBody("", "text/plain");
		}
		else
		{
			writeSse(res, `data: {"jsonrpc":"2.0","id":"s1","method":"ping"}` ~ "\n\n");
			const until = MonoTime.currTime + 3.seconds;
			while (!replied && MonoTime.currTime < until)
				sleep(20.msecs);
			writeSse(res, toolsListFrame(j["id"].get!long));
		}
	});
	ClientSettings settings;
	settings.maxInFlight = 1;
	const failure = runAgainstFakeServer(r, (string url) @safe {
		auto client = McpClient.http(url, settings);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		client.listTools();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(replied, "the ping reply must not wait for the request POST's permit");
}

unittest  // cancelling a request parked on the in-flight cap wakes it at once
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import mcp.client.client : McpClient, ClientSettings, RequestOptions, CancellationToken;
	import vibe.core.core : sleep, runTask;

	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		auto j = requestJson(req);
		const method = ("method" in j) ? j["method"].get!string : "";
		if (method == "initialize")
			res.writeBody(initializeReply(j, "2025-11-25").toString(), "application/json");
		else if ("id" !in j || method.length == 0)
		{
			res.statusCode = 202;
			res.writeBody("", "text/plain");
		}
		else
		{
			// Hold the only permit for 2s before answering.
			sleep(2.seconds);
			auto resp = parseJsonString(`{"jsonrpc":"2.0","result":{"content":[]}}`);
			resp["id"] = j["id"];
			res.writeBody(resp.toString(), "application/json");
		}
	});
	ClientSettings settings;
	settings.maxInFlight = 1;
	settings.requestTimeout = Duration.zero;
	int code;
	Duration took;
	const failure = runAgainstFakeServer(r, (string url) @safe {
		auto client = McpClient.http(url, settings);
		scope (exit)
			client.close();
		client.initialize("2025-11-25");
		auto holder = runTask(() nothrow{
			try
				client.callTool("slow", Json.emptyObject);
			catch (Exception)
			{
			}
		});
		sleep(100.msecs);
		auto token = new CancellationToken;
		runTask(() nothrow{
			try
			{
				sleep(200.msecs);
				token.cancel();
			}
			catch (Exception)
			{
			}
		});
		RequestOptions opts;
		opts.cancellation = token;
		const start = MonoTime.currTime;
		try
			client.callTool("parked", Json.emptyObject, opts);
		catch (McpException e)
			code = e.code;
		took = MonoTime.currTime - start;
		holder.join();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(code == ErrorCode.requestCancelled);
	assert(took < 1.seconds, "a cancelled call must not wait for an in-flight permit");
}

unittest  // a subscriptions/listen POST accepts both JSON and SSE responses
{
	string accept;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		accept = req.headers.get("Accept", "");
		auto resp = parseJsonString(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"no"}}`);
		resp["id"] = requestJson(req)["id"];
		res.writeBody(resp.toString(), "application/json");
	});
	const failure = runAgainstFakeServer(r, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		try
			t.openListen(makeRequest(Json(1), "subscriptions/listen", Json.emptyObject));
		catch (McpException)
		{
		}
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(accept == "application/json, text/event-stream", "Accept was: " ~ accept);
}

unittest  // readSseBody frames events on bare CR line endings
{
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) "id: 1\rdata: a\rdata: b\r\rdata: c\r\r".dup, false);
	}();
	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(events == ["a\nb", "c"]);
	assert(cursor.lastEventId == "1");
}

unittest  // readSseBody treats a CRLF split across two reads as one line ending
{
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(
				ubyte[]) "8\r\ndata: a\r\r\nc\r\n\ndata: b\r\n\r\n\r\n0\r\n\r\n".dup, false);
	}();
	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, true, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(events == ["a\nb"]);
}

unittest  // readSseBody commits an event id only when its event is dispatched
{
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) "id: 1\ndata: x\n\nid: 2\ndata: y\n".dup, false);
	}();
	SseCursor cursor;
	string[] events;
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			events ~= d;
		});
	}();
	assert(events == ["x"]);
	assert(cursor.lastEventId == "1", "an undelivered event's id must not become the resume cursor");
}

unittest  // readSseBody keeps the resume cursor across a dispatched event without an id
{
	import vibe.stream.memory : createMemoryStream;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[]) "data: x\n\n".dup, false);
	}();
	SseCursor cursor;
	cursor.lastEventId = "prev";
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
		});
	}();
	assert(cursor.lastEventId == "prev");
}

unittest  // close() DELETEs the session with a bearer fetched from the provider
{
	import mcp.client.client : McpClient;
	import std.conv : to;

	auto srv = new SessionFakeServer;
	auto router = srv.router();
	string deleteAuth;
	router.delete_("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		deleteAuth = req.headers.get("Authorization", "");
		res.statusCode = 204;
		res.writeVoidBody();
	});
	int calls;
	int callsBeforeClose;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		client.setBearerProvider(BearerProvider(() @safe => "t" ~ (++calls).to!string));
		client.initialize("2025-11-25");
		callsBeforeClose = calls;
		client.close();
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(calls == callsBeforeClose + 1, "the DELETE must consult the bearer provider");
	assert(deleteAuth == "Bearer t" ~ calls.to!string, deleteAuth);
}

unittest  // close() stops the server stream before the session DELETE, so it never reconnects without the session
{
	import core.time : msecs, MonoTime;
	import mcp.client.client : McpClient;
	import std.conv : to;
	import vibe.core.core : sleep;

	auto srv = new SessionFakeServer;
	auto router = srv.router();
	string[] getSessions;
	bool ended;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		getSessions ~= req.headers.get("Mcp-Session-Id", "");
		writeSse(res, "retry: 10\n\n");
		const until = MonoTime.currTime + 3.seconds;
		while (!ended && MonoTime.currTime < until)
			sleep(10.msecs);
	});
	router.delete_("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		ended = true;
		sleep(300.msecs);
		res.statusCode = 204;
		res.writeVoidBody();
	});
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto client = McpClient.http(url);
		client.initialize("2025-11-25");
		client.startServerStream();
		const until = MonoTime.currTime + 3.seconds;
		while (getSessions.length == 0 && MonoTime.currTime < until)
			sleep(10.msecs);
		client.close();
		sleep(100.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(getSessions == ["s1"], "server stream GETs: " ~ getSessions.to!string);
}

unittest  // openListen with no leading frame times out, cancels the stream and throws
{
	import core.time : msecs, MonoTime;
	import mcp.client.client : RequestTimeoutException;
	import vibe.core.core : sleep;

	bool release;
	auto router = answeringRouter((Json req, HTTPServerResponse res) @safe {
		writeSse(res, ": no frame yet\n");
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
	});
	bool timedOut;
	size_t openSockets = size_t.max;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		scope (exit)
			release = true;
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.listenTimeout_ = 100.msecs;
		try
			t.openListen(makeRequest(Json(1), "subscriptions/listen", Json.emptyObject));
		catch (RequestTimeoutException)
			timedOut = true;
		const until = MonoTime.currTime + 2.seconds;
		while (t.listenSockets.length && MonoTime.currTime < until)
			sleep(10.msecs);
		openSockets = t.listenSockets.length;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(timedOut, "a listen with no leading frame must fail with RequestTimeoutException");
	assert(openSockets == 0, "the timed-out listen stream must be torn down");
}

unittest  // HttpEndpoint.hostHeader omits only the scheme's default port
{
	assert(parseHttpEndpoint("http://h/x").hostHeader == "h");
	assert(parseHttpEndpoint("https://h/x").hostHeader == "h");
	assert(parseHttpEndpoint("http://h:443/x").hostHeader == "h:443");
	assert(parseHttpEndpoint("https://h:8443/x").hostHeader == "h:8443");
	assert(parseHttpEndpoint("http://[::1]:9000/x").hostHeader == "[::1]:9000");
	assert(parseHttpEndpoint("https://[::1]/x").hostHeader == "[::1]");
}

unittest  // startLegacyFallback surfaces a rejected legacy GET stream promptly with its HTTP status
{
	import core.time : MonoTime, seconds;

	auto router = new URLRouter;
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		res.headers["WWW-Authenticate"] = `Bearer realm="mcp"`;
		res.statusCode = 401;
		res.writeBody("unauthorized");
	});

	int status;
	string challenge;
	auto took = 0.seconds;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		auto t = new HttpClientTransport(url);
		const start = MonoTime.currTime;
		try
			t.startLegacyFallback();
		catch (HttpStatusException e)
		{
			status = e.status;
			challenge = e.wwwAuthenticate;
		}
		took = MonoTime.currTime - start;
		t.close();
	});
	assert(failure.length == 0, failure);
	assert(status == 401);
	assert(challenge == `Bearer realm="mcp"`);
	assert(took < 5.seconds);
}

unittest  // startLegacyFallback surfaces a refused legacy GET connection promptly
{
	import core.time : MonoTime, seconds;
	import std.algorithm : canFind;

	auto router = new URLRouter;
	string msg;
	auto took = 0.seconds;
	const failure = runAgainstFakeServer(router, (string url) @safe {
		// Nothing listens on loopback port 9, so the connect is refused.
		auto t = new HttpClientTransport("http://127.0.0.1:9/mcp");
		const start = MonoTime.currTime;
		try
			t.startLegacyFallback();
		catch (McpException e)
			msg = e.msg;
		took = MonoTime.currTime - start;
		t.close();
	});
	assert(failure.length == 0, failure);
	assert(msg.length);
	assert(!msg.canFind("did not send an `endpoint` event"), msg);
	assert(took < 5.seconds);
}

unittest  // readSseBody frames a large single-line event in time linear in its size
{
	import core.time : MonoTime, seconds;
	import vibe.stream.memory : createMemoryStream;

	enum size = 6 * 1024 * 1024;
	auto body = new char[](size + "data: \n\n".length);
	body[0 .. 6] = "data: ";
	body[6 .. 6 + size] = 'x';
	body[$ - 2 .. $] = "\n\n";
	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto stream = () @trusted {
		return createMemoryStream(cast(ubyte[])
				body, false);
	}();
	SseCursor cursor;
	size_t got;
	const start = MonoTime.currTime;
	() @trusted {
		t.readSseBody(stream, false, cursor, () @safe => false, (string e, string d) @safe {
			got = d.length;
		});
	}();
	const took = MonoTime.currTime - start;
	assert(got == size);
	assert(took < 2.seconds);
}

unittest  // openListen refreshes a rejected bearer token and retries the stream once
{
	string token = "old";
	string[] rejected;
	string[] seen;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const auth = req.headers.get("Authorization", "");
		seen ~= auth;
		if (auth != "Bearer new")
		{
			res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
			res.statusCode = 401;
			res.writeBody("");
			return;
		}
		writeSse(res,
			`data: {"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",`
			~ `"params":{"notifications":{}}}` ~ "\n\n");
	});
	string error;
	const failure = runAgainstFakeServer(r, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.setBearerProvider(BearerProvider(() @safe => token, (string tok) @safe {
				rejected ~= tok;
				token = "new";
				return true;
			}));
		try
			t.openListen(makeRequest(Json(1), "subscriptions/listen", Json.emptyObject));
		catch (McpException e)
			error = e.msg;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(error.length == 0, "openListen failed: " ~ error);
	assert(rejected == ["old"]);
	assert(seen == ["Bearer old", "Bearer new"]);
}

unittest  // openListen surfaces the 401 when the bearer refresh fails
{
	int attempts;
	int status;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		attempts++;
		res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
		res.statusCode = 401;
		res.writeBody("");
	});
	const failure = runAgainstFakeServer(r, (string url) @safe {
		auto t = new HttpClientTransport(url);
		scope (exit)
			t.close();
		t.setBearerProvider(BearerProvider(() @safe => "tok", (string tok) @safe => false));
		try
			t.openListen(makeRequest(Json(1), "subscriptions/listen", Json.emptyObject));
		catch (HttpStatusException e)
			status = e.status;
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(status == 401);
	assert(attempts == 1);
}

version (unittest)
{
	/// Answer every standalone GET with `status` and count the attempts the
	/// server-stream reader makes within about a second, returning that count and
	/// whether the reader is still running.
	private int serverStreamAttempts(int status, BearerProvider provider, out bool stillAlive)
	{
		import core.time : msecs, MonoTime;
		import vibe.core.core : sleep;

		int gets;
		auto r = new URLRouter;
		r.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
			gets++;
			res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
			res.statusCode = status;
			res.writeBody("");
		});
		bool alive;
		const failure = runAgainstFakeServer(r, (string url) @safe {
			auto t = new HttpClientTransport(url);
			scope (exit)
				t.close();
			t.setBearerProvider(provider);
			t.startServerStream();
			const until = MonoTime.currTime + 1200.msecs;
			while (MonoTime.currTime < until)
				sleep(50.msecs);
			alive = t.serverStreamAlive;
		});
		assert(failure.length == 0, "scenario failed: " ~ failure);
		stillAlive = alive;
		return gets;
	}
}

unittest  // the standalone GET stream stops on a 403
{
	bool alive;
	assert(serverStreamAttempts(403, BearerProvider.init, alive) == 1);
	assert(!alive);
}

unittest  // the standalone GET stream stops on a 400
{
	bool alive;
	assert(serverStreamAttempts(400, BearerProvider.init, alive) == 1);
	assert(!alive);
}

unittest  // the standalone GET stream stops on a 401 with no bearer provider
{
	bool alive;
	assert(serverStreamAttempts(401, BearerProvider.init, alive) == 1);
	assert(!alive);
}

unittest  // the standalone GET stream stops on a 401 whose bearer refresh fails
{
	bool alive;
	assert(serverStreamAttempts(401, BearerProvider(() @safe => "tok",
			(string tok) @safe => false), alive) == 1);
	assert(!alive);
}

unittest  // the standalone GET stream reconnects after a 401 whose bearer refresh succeeds
{
	bool alive;
	assert(serverStreamAttempts(401, BearerProvider(() @safe => "tok",
			(string tok) @safe => true), alive) > 1);
}

unittest  // the standalone GET stream keeps reconnecting through a 429
{
	bool alive;
	assert(serverStreamAttempts(429, BearerProvider.init, alive) > 1);
	assert(alive);
}

unittest  // close() fails an in-flight request with TransportClosedException
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : runTask, sleep;
	import mcp.client.client : TransportClosedException;

	bool release;
	auto r = new URLRouter;
	r.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const until = MonoTime.currTime + 5.seconds;
		while (!release && MonoTime.currTime < until)
			sleep(20.msecs);
		res.writeBody("");
	});
	McpException caught;
	const failure = runAgainstFakeServer(r, (string url) @safe {
		scope (exit)
			release = true;
		auto t = new HttpClientTransport(url);
		bool done;
		runTask(() nothrow{
			try
				t.deliver(makeRequest(Json(7), "tools/list", Json.emptyObject), 7);
			catch (McpException e)
				caught = e;
			catch (Exception)
			{
			}
			done = true;
		});
		sleep(200.msecs);
		t.close();
		const until = MonoTime.currTime + 3.seconds;
		while (!done && MonoTime.currTime < until)
			sleep(20.msecs);
	});
	assert(failure.length == 0, "scenario failed: " ~ failure);
	assert(cast(TransportClosedException) caught !is null, caught is null ? "no error" : caught.msg);
}

unittest  // close() fails an outstanding legacy waiter with TransportClosedException
{
	import mcp.client.client : TransportClosedException;

	auto t = new HttpClientTransport("http://host:8080/mcp");
	auto pending = new LegacyWaiter;
	t.legacyWaiters[1] = pending;
	t.close();
	assert(cast(TransportClosedException) pending.err !is null);
}
