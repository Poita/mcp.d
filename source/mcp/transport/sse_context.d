module mcp.transport.sse_context;

import core.time : Duration, seconds;
import std.typecons : Nullable;

import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.data.json : Json;
import vibe.http.server : HTTPServerResponse;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.capabilities;
import mcp.protocol.draft : withSubscriptionId;
import mcp.protocol.versions : ProtocolVersion, latestStable;
import mcp.server.context;
import mcp.auth.resource_server : TokenInfo;

/// Correlates outbound server->client requests with the client's responses,
/// which arrive on a *separate* POST. One instance is shared across all
/// handlers of a single server mount.
final class StreamCoordinator
{
	private static final class Waiter
	{
		LocalManualEvent evt;
		Json result = Json.undefined;
		Json error = Json.undefined;
		bool done;
	}

	private long counter = 1;
	private Waiter[long] waiters;
	private long streamCounter = 0;

	/// Allocate a fresh outbound request id.
	long alloc() @safe
	{
		return counter++;
	}

	/// Allocate a fresh stream ordinal. Combined with a per-stream monotonic
	/// event sequence, this yields globally-unique SSE event ids across every
	/// stream served by this mount, as the Resumability/Redelivery requirement
	/// demands ("If present, the ID MUST be globally unique ... within ... the
	/// session").
	long allocStream() @safe
	{
		return streamCounter++;
	}

	/// Begin tracking a pending outbound request.
	void register(long id) @safe
	{
		auto w = new Waiter;
		w.evt = createManualEvent();
		waiters[id] = w;
	}

	/// Block the current task until the client responds to `id` (or `timeout`
	/// elapses). Returns the result, or throws `McpException` on error/timeout.
	Json await(long id, Duration timeout = 60.seconds) @safe
	{
		auto w = waiters[id];
		scope (exit)
			waiters.remove(id);

		auto ec = w.evt.emitCount;
		while (!w.done)
		{
			const newEc = () @trusted { return w.evt.wait(timeout, ec); }();
			if (newEc == ec && !w.done)
				throw internalError("Timed out awaiting client response");
			ec = newEc;
		}
		if (w.error.type != Json.Type.undefined)
		{
			const code = ("code" in w.error) ? w.error["code"].get!int : ErrorCode.internalError;
			const m = ("message" in w.error) ? w.error["message"].get!string : "client error";
			throw new McpException(code, m, w.error);
		}
		return w.result;
	}

	/// Drop a registered-but-unawaited request id (e.g. when delivery failed so
	/// the request will never get a response). Idempotent; unknown ids are
	/// ignored. Keeps the waiter table from leaking when `register` is not
	/// followed by `await`.
	void cancel(long id) @safe
	{
		waiters.remove(id);
	}

	/// Deliver a client response/errorResponse. Returns true if it matched a
	/// pending outbound request.
	bool resolve(Json idJson, Json result, Json error) @safe
	{
		if (idJson.type != Json.Type.int_)
			return false;
		const id = idJson.get!long;
		if (auto w = id in waiters)
		{
			w.result = result;
			w.error = error;
			w.done = true;
			w.evt.emit();
			return true;
		}
		return false;
	}
}

/// A long-lived server->client SSE channel for *unsolicited* traffic — the
/// stream a client opens with an HTTP GET to the MCP endpoint (basic/transports
/// §Listening for Messages from the Server). Unlike `HttpStreamContext`, which
/// is bound to one in-flight POST, this channel delivers a notification (or
/// server->client request) on a single one of the currently-connected GET
/// listeners.
///
/// A handler is registered per accepted GET; `emit` frames the JSON-RPC message
/// as an SSE event with a globally-unique id (via the shared `StreamCoordinator`
/// ordinal scheme) and writes it to exactly ONE live listener. This honours the
/// transport's Multiple Connections rule: "The server MUST send each of its
/// JSON-RPC messages on only one of the connected streams; that is, it MUST NOT
/// broadcast the same message across multiple streams." Listeners that fail to
/// write (a disconnected client) are skipped and dropped so the channel
/// self-heals and the message still lands on a live stream.
///
/// One instance is shared across a server mount. Thread-safety is the caller's
/// responsibility on multi-threaded vibe.d setups; the default single-fiber
/// dispatch needs none.
final class ServerPushChannel
{
	/// A connected GET listener: an opaque id plus the writer that delivers a
	/// pre-framed SSE block to it. `subscriptionId`, when non-empty, is the
	/// JSON-RPC id of the `subscriptions/listen` request that opened this stream;
	/// every notification delivered to the listener is stamped with it in
	/// `params._meta["io.modelcontextprotocol/subscriptionId"]` so the client can
	/// correlate notifications with the listen request (draft basic/utilities/
	/// subscriptions).
	private struct Listener
	{
		long id;
		void delegate(string frame) @safe write;
		string subscriptionId;
	}

	private StreamCoordinator coord;
	private Listener[] listeners;
	private long[long] streamOf; /// listener id -> its allocated stream ordinal
	private long[long] seqOf; /// listener id -> its monotonic event sequence
	private long nextListenerId = 1;

	this(StreamCoordinator coord) @safe
	{
		this.coord = coord;
	}

	/// Register a connected GET listener and return its id. Each listener gets a
	/// distinct stream ordinal so its event ids stay globally unique within the
	/// mount/session. When `subscriptionId` is non-empty (a `subscriptions/listen`
	/// stream), every notification delivered to this listener is stamped with it
	/// in `params._meta["io.modelcontextprotocol/subscriptionId"]`.
	long addListener(void delegate(string frame) @safe write, string subscriptionId = "") @safe
	{
		const id = nextListenerId++;
		listeners ~= Listener(id, write, subscriptionId);
		streamOf[id] = coord.allocStream();
		seqOf[id] = 0;
		return id;
	}

	/// Drop a listener (e.g. when its GET stream is closed).
	void removeListener(long id) @safe
	{
		import std.algorithm : remove;

		listeners = listeners.remove!(l => l.id == id);
		streamOf.remove(id);
		seqOf.remove(id);
	}

	/// Number of currently-connected listeners.
	size_t listenerCount() const @safe
	{
		return listeners.length;
	}

	/// Frame `msg` as an SSE event (with a per-stream globally-unique id) and
	/// deliver it on exactly ONE connected stream, honouring the transport's
	/// Multiple Connections rule that the server "MUST send each of its JSON-RPC
	/// messages on only one of the connected streams ... it MUST NOT broadcast the
	/// same message across multiple streams." Listeners are tried in registration
	/// order; one whose write throws (a disconnected client) is dropped and the
	/// next live listener is tried, so the message still lands on a healthy stream
	/// and the channel self-heals. Returns 1 if the message was delivered, or 0
	/// when no live listener could receive it.
	size_t emit(Json msg) @safe
	{
		import std.conv : to;

		long[] dead;
		size_t delivered;
		foreach (ref l; listeners)
		{
			const eid = streamOf[l.id].to!string ~ "-" ~ seqOf[l.id].to!string;
			const frame = formatSseEvent(eid, withSubscriptionId(msg, l.subscriptionId));
			try
			{
				l.write(frame);
				seqOf[l.id]++;
				delivered = 1;
				break; // single-stream delivery: do not fan out to other streams
			}
			catch (Exception)
			{
				dead ~= l.id;
			}
		}
		foreach (id; dead)
			removeListener(id);
		return delivered;
	}

	/// Convenience: broadcast a JSON-RPC notification to every listener.
	size_t notify(string method, Json params = Json.undefined) @safe
	{
		return emit(makeNotification(method, params));
	}

	/// Send a server->client JSON-RPC *request* on the standalone GET SSE push
	/// channel and block until a client responds. The request id is allocated
	/// and tracked by the shared `StreamCoordinator`, so the client's reply --
	/// which arrives on a *separate* POST to the MCP endpoint and is routed
	/// through `StreamCoordinator.resolve` -- wakes this call. The request frame
	/// is delivered on a single connected listener; the matching response
	/// resolves the waiter.
	/// Returns the client's result, or throws `McpException` on a client error
	/// or timeout. Throws `internalError` if no GET listener is connected (there
	/// is nobody to answer). This is the request/response counterpart to
	/// `notify`, and the foundation for server-initiated `ping`.
	Json sendRequest(string method, Json params = Json.emptyObject, Duration timeout = 60.seconds) @safe
	{
		const id = coord.alloc();
		coord.register(id);
		const delivered = emit(makeRequest(Json(id), method, params));
		if (delivered == 0)
		{
			coord.cancel(id);
			throw internalError(
					"No GET SSE listener connected to receive the server->client request");
		}
		return coord.await(id, timeout);
	}

	/// Initiate a `ping` toward the connected client(s) on the GET SSE push
	/// channel and block until one acknowledges with the spec-mandated empty
	/// result (basic/utilities/ping). This is the server-side counterpart to the
	/// client's `ping()`: it lets a server perform the SHOULD-periodic
	/// connection-health check the spec describes for either party. Throws on a
	/// client error, a timeout (treat as a stale connection), or when no GET
	/// listener is connected. The `ping` request carries no params, exactly as
	/// the spec requires.
	void ping(Duration timeout = 60.seconds) @safe
	{
		sendRequest("ping", Json.emptyObject, timeout);
	}

	/// Frame `msg` and write it to a single listener (identified by `listenerId`),
	/// rather than broadcasting to all. Used to deliver a per-stream leading event
	/// — e.g. the `notifications/subscriptions/acknowledged` the draft
	/// `subscriptions/listen` stream sends only to its own client. Returns true if
	/// the listener received it; false if the id is unknown or its write failed
	/// (in which case the listener is dropped).
	bool emitTo(long listenerId, Json msg) @safe
	{
		import std.conv : to;

		foreach (ref l; listeners)
		{
			if (l.id != listenerId)
				continue;
			const eid = streamOf[l.id].to!string ~ "-" ~ seqOf[l.id].to!string;
			const frame = formatSseEvent(eid, withSubscriptionId(msg, l.subscriptionId));
			try
			{
				l.write(frame);
				seqOf[l.id]++;
				return true;
			}
			catch (Exception)
			{
				removeListener(l.id);
				return false;
			}
		}
		return false;
	}
}

unittest  // a listener receives framed events, with monotonic per-listener ids
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string[] received;
	const id = ch.addListener((string f) @safe { received ~= f; });
	assert(ch.listenerCount == 1);

	const n = ch.notify("notifications/resources/updated", Json([
		"uri": Json("test://x")
	]));
	assert(n == 1);
	assert(received.length == 1);
	import std.string : startsWith;
	import std.algorithm : canFind;

	assert(received[0].startsWith("id: "));
	assert(received[0].canFind("notifications/resources/updated"));

	ch.notify("notifications/message");
	assert(received.length == 2);
	// event ids advance monotonically for the same listener.
	assert(received[0] != received[1]);
	ch.removeListener(id);
	assert(ch.listenerCount == 0);
}

unittest  // emit delivers to exactly ONE stream, never broadcasting to all
{
	// basic/transports §Multiple Connections: "The server MUST send each of its
	// JSON-RPC messages on only one of the connected streams; that is, it MUST
	// NOT broadcast the same message across multiple streams." With two open GET
	// streams, a single emit must reach exactly one of them.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	int aCount, bCount;
	ch.addListener((string) @safe { aCount++; });
	ch.addListener((string) @safe { bCount++; });
	assert(ch.listenerCount == 2);

	const delivered = ch.notify("notifications/message");
	assert(delivered == 1); // exactly one stream, not both
	assert(aCount + bCount == 1); // the message landed on a single stream only
	assert(ch.listenerCount == 2); // both streams remain open
}

unittest  // emit self-heals: it skips a broken stream and delivers on a live one
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	int aCount;
	// The first listener always throws (a disconnected client); the second is healthy.
	ch.addListener((string) @safe { throw new Exception("closed"); });
	ch.addListener((string) @safe { aCount++; });
	assert(ch.listenerCount == 2);

	const delivered = ch.notify("notifications/message");
	assert(delivered == 1); // the healthy stream received it
	assert(aCount == 1);
	assert(ch.listenerCount == 1); // the broken stream was dropped
}

unittest  // emitTo delivers only to the named listener, not the others
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	const a = ch.addListener((string f) @safe { aFrame = f; });
	ch.addListener((string f) @safe { bFrame = f; });

	assert(ch.emitTo(a, makeNotification("notifications/subscriptions/acknowledged",
			Json(["toolsListChanged": Json(true)]))));
	import std.algorithm : canFind;

	assert(aFrame.canFind("notifications/subscriptions/acknowledged"));
	assert(bFrame.length == 0); // the other listener got nothing

	// An unknown listener id is a no-op returning false.
	assert(!ch.emitTo(9999, makeNotification("notifications/message")));
}

unittest  // a notification delivered on a listen stream is stamped with its subscriptionId
{
	import std.algorithm : canFind;
	import mcp.protocol.draft : MetaKey;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string listenFrame;
	// A single listen stream: the chosen delivery target carries its subscriptionId.
	ch.addListener((string f) @safe { listenFrame = f; }, "listen-9");

	const delivered = ch.notify("notifications/tools/list_changed");
	assert(delivered == 1);

	assert(listenFrame.canFind(cast(string) MetaKey.subscriptionId));
	assert(listenFrame.canFind("listen-9"));
}

unittest  // a notification delivered on a plain GET stream carries no subscriptionId
{
	import std.algorithm : canFind;
	import mcp.protocol.draft : MetaKey;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string plainFrame;
	ch.addListener((string f) @safe { plainFrame = f; });

	const delivered = ch.notify("notifications/tools/list_changed");
	assert(delivered == 1);
	assert(!plainFrame.canFind(cast(string) MetaKey.subscriptionId));
}

unittest  // emitTo to a listen stream stamps subscriptionId (e.g. the leading ack)
{
	import std.algorithm : canFind;
	import mcp.protocol.draft : MetaKey;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string frame;
	const id = ch.addListener((string f) @safe { frame = f; }, "ack-id-1");

	assert(ch.emitTo(id, makeNotification("notifications/subscriptions/acknowledged",
			Json(["toolsListChanged": Json(true)]))));
	assert(frame.canFind("notifications/subscriptions/acknowledged"));
	assert(frame.canFind(cast(string) MetaKey.subscriptionId));
	assert(frame.canFind("ack-id-1"));
}

unittest  // distinct listeners get distinct stream ordinals, so ids stay unique
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	const a = ch.addListener((string f) @safe { aFrame = f; });
	const b = ch.addListener((string f) @safe { bFrame = f; });
	// Deliver one event to each stream individually (emit picks a single stream,
	// so target each explicitly here to compare their independent event ids).
	ch.emitTo(a, makeNotification("notifications/message"));
	ch.emitTo(b, makeNotification("notifications/message"));
	assert(aFrame.length && bFrame.length);
	// The first line ("id: <stream>-<seq>") differs because the stream ordinal
	// differs between the two listeners.
	import std.string : splitLines;

	assert(aFrame.splitLines()[0] != bFrame.splitLines()[0]);
}

/// The HTTP response headers a server sets when it upgrades a response to a
/// Server-Sent Events stream (`Content-Type: text/event-stream`).
///
/// `Cache-Control: no-cache` applies on every protocol version.
///
/// `isDraft` adds the draft-only `X-Accel-Buffering: no` header. The draft
/// basic/transports §Receiving Messages rule states: "When initiating an SSE
/// stream, servers SHOULD include the `X-Accel-Buffering: no` header in the HTTP
/// response" (it instructs reverse proxies such as nginx to disable response
/// buffering so events are flushed immediately). This SHOULD was introduced in
/// the draft (2026-07-28) and does NOT exist in 2025-03-26 / 2025-06-18 /
/// 2025-11-25, so it must NOT be emitted on those versions — the stable wire
/// output is unchanged.
string[string] sseStreamHeaders(bool isDraft) @safe
{
	string[string] h;
	h["Cache-Control"] = "no-cache";
	if (isDraft)
		h["X-Accel-Buffering"] = "no";
	return h;
}

unittest  // stable SSE streams: no-cache only, never X-Accel-Buffering
{
	auto h = sseStreamHeaders(false);
	assert(h["Cache-Control"] == "no-cache");
	assert("X-Accel-Buffering" !in h);
}

unittest  // draft SSE streams add X-Accel-Buffering: no (draft SHOULD)
{
	auto h = sseStreamHeaders(true);
	assert(h["Cache-Control"] == "no-cache");
	assert(h["X-Accel-Buffering"] == "no");
}

/// Set the SSE upgrade headers (see `sseStreamHeaders`) on a response, leaving
/// the caller to set `contentType`. Applies the draft-only `X-Accel-Buffering`
/// header only when `isDraft` is true.
void applySseStreamHeaders(HTTPServerResponse res, bool isDraft) @safe
{
	foreach (k, v; sseStreamHeaders(isDraft))
		res.headers[k] = v;
}

/// A `RequestContext` backed by an HTTP response that is (lazily) upgraded to a
/// Server-Sent Events stream the first time the handler emits server->client
/// traffic. Progress/logging become SSE notification events; sampling/
/// elicitation send an SSE request event then block (via the coordinator) for
/// the client's response on a later POST. The final JSON-RPC response is the
/// terminating SSE event.
final class HttpStreamContext : RequestContext
{
	private HTTPServerResponse res;
	private StreamCoordinator coord;
	private ClientCapabilities clientCaps;
	private Json progressTok;
	private bool streaming_;
	private long streamId;
	private long eventSeq;
	private TokenInfo authInfo;
	// When true, an SSE upgrade emits the draft-only `X-Accel-Buffering: no`
	// header (draft basic/transports §Receiving Messages SHOULD). Defaults to
	// false so 2025-03-26 / 2025-06-18 / 2025-11-25 wire output is unchanged.
	private bool isDraft_;
	// The effective protocol version negotiated for this request. Drives the
	// 2025-11-25-only priming event (see `beginStream`). Defaults to the latest
	// stable version.
	private ProtocolVersion version_;
	// Set once the leading priming event has been written, so it is emitted at
	// most once per stream.
	private bool primed_;

	this(HTTPServerResponse res, StreamCoordinator coord, ClientCapabilities caps, Json progressToken,
			TokenInfo auth = TokenInfo.invalid(),
			bool isDraft = false, ProtocolVersion negotiated = latestStable) @safe
	{
		this.res = res;
		this.coord = coord;
		this.clientCaps = caps;
		this.progressTok = progressToken;
		this.streamId = coord.allocStream();
		this.authInfo = auth;
		this.isDraft_ = isDraft;
		this.version_ = negotiated;
	}

	/// The globally-unique id this stream will assign to its next SSE event.
	/// Exposed for resumability tooling and tests; the format is opaque but
	/// stable and unique across all streams of the owning mount.
	string nextEventId() @safe
	{
		import std.conv : to;

		return streamId.to!string ~ "-" ~ eventSeq.to!string;
	}

	/// Whether the response has been upgraded to an SSE stream.
	bool streaming() const @safe
	{
		return streaming_;
	}

	/// Cancellation for this request is tracked by the server's `RequestScope`
	/// (which holds the shared token flipped by `notifications/cancelled`), so the
	/// transport context itself reports never-cancelled. The wrapping
	/// `RequestScope.isCancelled` consults its token before delegating here.
	bool isCancelled() @safe
	{
		return false;
	}

	private void beginStream() @safe
	{
		if (streaming_)
			return;
		res.contentType = "text/event-stream";
		// Cache-Control: no-cache on every version; X-Accel-Buffering: no only
		// on the draft (basic/transports §Receiving Messages SHOULD).
		applySseStreamHeaders(res, isDraft_);
		streaming_ = true;
		// 2025-11-25 basic/transports §Sending Messages item 6: "If the server
		// initiates an SSE stream: the server SHOULD immediately send an SSE event
		// consisting of an event ID and an empty data field in order to prime the
		// client to reconnect (using that event ID as Last-Event-ID)." This SHOULD
		// is unique to 2025-11-25 — 2025-03-26 / 2025-06-18 never defined it and the
		// draft drops Last-Event-ID resumability entirely — so the priming event is
		// emitted ONLY when the effective version is exactly 2025-11-25, leaving
		// every other version's wire output unchanged.
		writePrimingEventIfNeeded();
	}

	/// Emit the leading priming event (an event id + empty `data` field) on a
	/// freshly-opened POST-initiated SSE stream when, and only when, the negotiated
	/// version is 2025-11-25 (basic/transports §Sending Messages item 6). Consumes
	/// the next event id so subsequent frames advance from it, exactly as the SSE
	/// `Last-Event-ID` cursor requires. Emitted at most once per stream.
	private void writePrimingEventIfNeeded() @safe
	{
		if (primed_ || !sendsPrimingEvent(version_))
			return;
		primed_ = true;
		const frame = formatPrimingEvent(nextEventId());
		eventSeq++;
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frame);
			res.bodyWriter.flush();
		}();
	}

	private void writeEvent(Json msg) @safe
	{
		beginStream();
		const frame = formatSseEvent(nextEventId(), msg);
		eventSeq++;
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frame);
			res.bodyWriter.flush();
		}();
	}

	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe
	{
		if (progressTok.type == Json.Type.undefined)
			return;
		Json p = Json.emptyObject;
		p["progressToken"] = progressTok;
		p["progress"] = progress;
		if (!total.isNull)
			p["total"] = total.get;
		if (message.length)
			p["message"] = message;
		writeEvent(makeNotification("notifications/progress", p));
	}

	void log(string level, Json data, string logger = null) @safe
	{
		Json p = Json.emptyObject;
		p["level"] = level;
		if (logger.length)
			p["logger"] = logger;
		p["data"] = data;
		writeEvent(makeNotification("notifications/message", p));
	}

	Json sendRequest(string method, Json params) @safe
	{
		const id = coord.alloc();
		coord.register(id);
		writeEvent(makeRequest(Json(id), method, params));
		return coord.await(id);
	}

	bool clientSupports(string capability) @safe
	{
		switch (capability)
		{
		case "sampling":
			return clientCaps.sampling;
		case "sampling.tools":
			return clientCaps.samplingTools;
		case "sampling.context":
			return clientCaps.samplingContext;
		case "elicitation":
			return clientCaps.elicitation;
		case "elicitation.form":
			return clientCaps.elicitationForm;
		case "elicitation.url":
			return clientCaps.elicitationUrl;
		case "roots":
			return clientCaps.roots;
		default:
			return false;
		}
	}

	// Per-request protocol state (statelessness, input responses) is supplied by
	// the server's RequestScope wrapper, not the transport; default here.
	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return authInfo;
	}

	/// Write the final JSON-RPC response as the terminating SSE event.
	void finishWith(Json response) @safe
	{
		writeEvent(response);
	}
}

/// Frame a JSON-RPC message as a Server-Sent Events block. Per the transport
/// Resumability/Redelivery section, the server attaches an `id:` line so a
/// client can reconnect with `Last-Event-ID`; the id MUST be globally unique
/// within the session, which the caller guarantees via a per-stream ordinal
/// plus a monotonic event sequence. An empty `id` omits the line.
string formatSseEvent(string id, Json msg) @safe
{
	auto block = id.length ? ("id: " ~ id ~ "\n") : "";
	return block ~ "data: " ~ msg.toString() ~ "\n\n";
}

/// Whether a POST-initiated SSE stream must lead with the priming event (an
/// event id + empty `data` field) for the given negotiated version. This is a
/// 2025-11-25-only SHOULD (basic/transports §Sending Messages item 6): it did
/// not exist in 2025-03-26 / 2025-06-18, and the draft removed Last-Event-ID
/// resumability altogether, so the priming event must NOT alter those versions'
/// wire output. Gated here as a single pure predicate so the version boundary is
/// directly testable.
bool sendsPrimingEvent(ProtocolVersion v) @safe pure nothrow
{
	return v == ProtocolVersion.v2025_11_25;
}

unittest  // the priming event is sent ONLY on 2025-11-25
{
	assert(sendsPrimingEvent(ProtocolVersion.v2025_11_25));
	assert(!sendsPrimingEvent(ProtocolVersion.v2025_06_18));
	assert(!sendsPrimingEvent(ProtocolVersion.v2025_03_26));
	assert(!sendsPrimingEvent(ProtocolVersion.v2024_11_05));
	// The draft drops Last-Event-ID resumability, so no priming event there.
	assert(!sendsPrimingEvent(ProtocolVersion.draft));
}

/// Frame the 2025-11-25 leading "priming" SSE event: an `id:` line carrying the
/// stream's next event id followed by an empty `data:` field (basic/transports
/// §Sending Messages item 6 — "an SSE event consisting of an event ID and an
/// empty data field in order to prime the client to reconnect"). The empty data
/// line is required so it parses as a real SSE event (and thus updates the
/// client's last event id), while carrying no JSON-RPC payload.
string formatPrimingEvent(string id) @safe
{
	return "id: " ~ id ~ "\ndata: \n\n";
}

unittest  // the priming event is an id: line plus an empty data: field
{
	import std.string : splitLines;

	const frame = formatPrimingEvent("0-0");
	// Exactly: an event id, an empty data field, terminated by a blank line.
	assert(frame == "id: 0-0\ndata: \n\n");
	auto lines = frame.splitLines();
	assert(lines[0] == "id: 0-0");
	assert(lines[1] == "data: "); // empty data field, no JSON payload
}

unittest  // formatSseEvent emits an id: line followed by the data: line
{
	auto j = makeNotification("notifications/message", Json.emptyObject);
	const frame = formatSseEvent("0-3", j);
	import std.string : startsWith, endsWith, indexOf;

	assert(frame.startsWith("id: 0-3\n"));
	assert(frame.indexOf("\ndata: ") >= 0);
	assert(frame.endsWith("\n\n"));
}

unittest  // formatSseEvent omits the id: line when id is empty
{
	auto j = makeNotification("notifications/message", Json.emptyObject);
	const frame = formatSseEvent("", j);
	import std.string : startsWith;

	assert(frame.startsWith("data: "));
}

unittest  // each stream gets a distinct ordinal, so event ids are globally unique
{
	auto c = new StreamCoordinator;
	const a = c.allocStream();
	const b = c.allocStream();
	assert(a != b);
}

/// Extract `_meta.progressToken` from a request's params, or `Json.undefined`.
Json extractProgressToken(Json params) @safe
{
	if (params.type == Json.Type.object && "_meta" in params)
	{
		auto meta = params["_meta"];
		if (meta.type == Json.Type.object && "progressToken" in meta)
			return meta["progressToken"];
	}
	return Json.undefined;
}

unittest  // extractProgressToken finds the token or returns undefined
{
	Json p = Json.emptyObject;
	assert(extractProgressToken(p).type == Json.Type.undefined);
	Json meta = Json.emptyObject;
	meta["progressToken"] = "abc";
	p["_meta"] = meta;
	assert(extractProgressToken(p).get!string == "abc");
}

unittest  // coordinator resolves a pending request across "connections"
{
	auto c = new StreamCoordinator;
	const id = c.alloc();
	assert(id == 1);
	c.register(id);
	// Simulate the client's response arriving and being delivered.
	assert(c.resolve(Json(id), Json(["ok": Json(true)]), Json.undefined));
	// An unknown id does not match any pending request.
	assert(!c.resolve(Json(9999), Json.emptyObject, Json.undefined));
}

unittest  // cancel() drops a registered-but-unawaited request id
{
	auto c = new StreamCoordinator;
	const id = c.alloc();
	c.register(id);
	c.cancel(id);
	// After cancel the id is no longer pending, so a late response does not match.
	assert(!c.resolve(Json(id), Json.emptyObject, Json.undefined));
	// cancel is idempotent and tolerates unknown ids.
	c.cancel(id);
	c.cancel(9999);
}

unittest  // push-channel sendRequest with no listener throws (nobody to answer)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	bool threw;
	try
		ch.sendRequest("ping");
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}

unittest  // push-channel ping() with no listener throws
{
	import mcp.protocol.errors : McpException;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	bool threw;
	try
		ch.ping();
	catch (McpException)
		threw = true;
	assert(threw);
}

unittest  // push-channel ping round-trips: request frame out, empty result back
{
	import std.algorithm : canFind;
	import std.string : startsWith;
	import vibe.core.core : runTask, exitEventLoop, runEventLoop;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string frame;
	// A connected GET listener captures the server->client request frame.
	ch.addListener((string f) @safe { frame = f; });

	bool pinged;
	void delegate() @safe nothrow initiator = () @safe nothrow{
		// The server initiates a ping on the push channel; this blocks until the
		// simulated client resolves the request id via the coordinator.
		try
			ch.ping();
		catch (Exception)
			assert(false, "ping() threw");
		pinged = true;
		exitEventLoop();
	};
	// Play the client: once the request frame has been emitted, resolve the
	// in-flight id (1) with the spec-mandated empty result, exactly as a client
	// POST would via StreamCoordinator.resolve.
	void delegate() @safe nothrow responder = () @safe nothrow{
		// The emitted frame is a JSON-RPC `ping` request with an id.
		assert(frame.startsWith("id: "));
		assert(frame.canFind("\"method\":\"ping\""));
		assert(frame.canFind("\"jsonrpc\":\"2.0\""));
		assert(frame.canFind("\"id\":1"));
		bool matched;
		try
			matched = coord.resolve(Json(1), Json.emptyObject, Json.undefined);
		catch (Exception)
			assert(false, "resolve threw");
		assert(matched);
	};
	runTask(initiator);
	runTask(responder);
	runEventLoop();

	assert(pinged); // ping() returned without throwing -> client acknowledged
}
