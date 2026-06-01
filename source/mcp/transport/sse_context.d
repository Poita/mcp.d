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
/// The per-stream opt-in a client expressed when it opened a draft
/// `subscriptions/listen` stream (draft basic/utilities/subscriptions §Notification
/// Filter). It records exactly which change-notification types this one stream asked
/// for, so the server can honour the MUST NOT: "The server MUST NOT send notification
/// types the client has not explicitly requested." With Multiple Concurrent
/// Subscriptions each listen stream carries its own filter (keyed by its listen
/// request id), so a notification is delivered only to streams that opted into it —
/// never to a concurrent stream that requested a different type.
///
/// `active` distinguishes a real listen-stream filter (an opted-in draft stream) from
/// the zero value used for plain GET streams that did not go through `subscriptions/
/// listen`; an inactive filter accepts everything (the legacy GET-stream behaviour and
/// the transport's Multiple Connections rule are unchanged).
struct SubscriptionFilter
{
	bool active; /// true once this is a real `subscriptions/listen` filter
	bool toolsListChanged;
	bool promptsListChanged;
	bool resourcesListChanged;
	bool resourceSubscriptions; /// opted into `notifications/resources/updated`
	string[] resourceUris; /// the exact URIs opted into for `notifications/resources/updated`

	/// Whether a notification with this JSON-RPC `method` (and, for
	/// `notifications/resources/updated`, this resource `uri`) is one this stream
	/// explicitly requested. An inactive filter (a plain GET stream) accepts every
	/// notification; an active filter accepts only its opted-in types. Notification
	/// methods that are not subscription-gated (progress, logging, elicitation
	/// completion, server->client requests, etc.) are always accepted — the draft
	/// filter governs only the four list/subscription change types.
	bool accepts(string method, string uri = "") const @safe
	{
		if (!active)
			return true;
		switch (method)
		{
		case "notifications/tools/list_changed":
			return toolsListChanged;
		case "notifications/prompts/list_changed":
			return promptsListChanged;
		case "notifications/resources/list_changed":
			return resourcesListChanged;
		case "notifications/resources/updated":
			import std.algorithm : canFind;

			if (!resourceSubscriptions)
				return false;
			// A blanket opt-in (legacy boolean, no per-URI list) accepts any URI;
			// otherwise only the explicitly named URIs are accepted.
			return resourceUris.length == 0 || uri.length == 0 || resourceUris.canFind(uri);
		default:
			// Not a subscription-gated change notification: always deliverable.
			return true;
		}
	}
}

unittest  // an inactive filter (plain GET stream) accepts every notification type
{
	SubscriptionFilter f;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(f.accepts("notifications/resources/updated", "file:///x"));
	assert(f.accepts("notifications/message"));
}

unittest  // an active filter accepts only the change types it opted into
{
	SubscriptionFilter f;
	f.active = true;
	f.toolsListChanged = true;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(!f.accepts("notifications/prompts/list_changed"));
	assert(!f.accepts("notifications/resources/list_changed"));
	assert(!f.accepts("notifications/resources/updated", "file:///x"));
	// Non-gated notifications still flow regardless of opt-in.
	assert(f.accepts("notifications/message"));
	assert(f.accepts("notifications/progress"));
}

unittest  // resourceSubscriptions matches only the opted-in URIs
{
	SubscriptionFilter f;
	f.active = true;
	f.resourceSubscriptions = true;
	f.resourceUris = ["file:///project/config.json"];
	assert(f.accepts("notifications/resources/updated", "file:///project/config.json"));
	assert(!f.accepts("notifications/resources/updated", "file:///other"));

	// A blanket boolean opt-in (no per-URI list) accepts any resource URI.
	SubscriptionFilter blanket;
	blanket.active = true;
	blanket.resourceSubscriptions = true;
	assert(blanket.accepts("notifications/resources/updated", "file:///x"));

	// Without resourceSubscriptions opt-in, resources/updated is rejected.
	SubscriptionFilter none;
	none.active = true;
	assert(!none.accepts("notifications/resources/updated", "file:///x"));
}

final class ServerPushChannel
{
	/// A connected GET listener: an opaque id plus the writer that delivers a
	/// pre-framed SSE block to it. `subscriptionId`, when non-empty, is the
	/// JSON-RPC id of the `subscriptions/listen` request that opened this stream;
	/// every notification delivered to the listener is stamped with it in
	/// `params._meta["io.modelcontextprotocol/subscriptionId"]` so the client can
	/// correlate notifications with the listen request (draft basic/utilities/
	/// subscriptions). `filter` is the per-stream opt-in (draft §Notification
	/// Filter): an active filter receives only the change-notification types this
	/// stream explicitly requested, so a notification is never delivered to a
	/// concurrent stream that did not request it.
	private struct Listener
	{
		long id;
		void delegate(string frame) @safe write;
		string subscriptionId;
		SubscriptionFilter filter;
	}

	private StreamCoordinator coord;
	private Listener[] listeners;
	private long[long] streamOf; /// listener id -> its allocated stream ordinal
	private long[long] seqOf; /// listener id -> its monotonic event sequence
	private long nextListenerId = 1;

	/// Per-stream replay history for Last-Event-ID resumability
	/// (basic/transports §Resumability and Redelivery): for each stream ordinal,
	/// the already-framed SSE blocks emitted on it, paired with their event
	/// sequence, kept so a reconnecting GET carrying `Last-Event-ID` can have the
	/// messages emitted *after* that id replayed on the very stream that was
	/// disconnected. Bounded per stream (oldest evicted first) so the buffer cannot
	/// grow without limit. The spec rule is a MAY; this is opt-in via a non-empty
	/// `resumeFrom` on `addListener`, so a normal GET (no `Last-Event-ID`) keeps the
	/// existing fresh-ordinal behaviour and unchanged wire output.
	private struct HistoryEntry
	{
		long seq;
		string frame;
	}

	private HistoryEntry[][long] history; /// stream ordinal -> ring of recent events
	private size_t maxHistoryPerStream = 256;

	this(StreamCoordinator coord) @safe
	{
		this.coord = coord;
	}

	/// Register a connected GET listener and return its id. Each listener gets a
	/// distinct stream ordinal so its event ids stay globally unique within the
	/// mount/session. When `subscriptionId` is non-empty (a `subscriptions/listen`
	/// stream), every notification delivered to this listener is stamped with it
	/// in `params._meta["io.modelcontextprotocol/subscriptionId"]`.
	///
	/// `resumeFrom` carries the client's `Last-Event-ID` (basic/transports
	/// §Resumability and Redelivery). When it parses to `<ordinal>-<seq>` for a
	/// stream ordinal this channel still has buffered history for, the listener
	/// resumes *that* stream rather than allocating a fresh ordinal: the events with
	/// a higher sequence are replayed onto the new writer in order, and subsequent
	/// events continue the same ordinal from where it left off. This is the
	/// server-side half of resumability — the "server MAY use this header to replay
	/// messages that would have been sent after the last event ID, on the stream
	/// that was disconnected". An empty or unrecognized `resumeFrom` falls back to a
	/// fresh ordinal (the prior behaviour), so a normal GET is unaffected. The
	/// MUST NOT — "replay messages that would have been delivered on a different
	/// stream" — is honoured because replay is keyed strictly on the id's ordinal.
	long addListener(void delegate(string frame) @safe write, string subscriptionId = "",
			SubscriptionFilter filter = SubscriptionFilter.init, string resumeFrom = "") @safe
	{
		const id = nextListenerId++;
		listeners ~= Listener(id, write, subscriptionId, filter);

		long resumeOrdinal, resumeSeq;
		if (parseEventId(resumeFrom, resumeOrdinal, resumeSeq) && resumeOrdinal in history)
		{
			// Resume the disconnected stream: keep its ordinal, replay every buffered
			// event after the cursor in sequence order, and continue from the next seq.
			streamOf[id] = resumeOrdinal;
			long maxSeq = resumeSeq;
			foreach (ref e; history[resumeOrdinal])
			{
				if (e.seq <= resumeSeq)
					continue;
				write(e.frame);
				if (e.seq > maxSeq)
					maxSeq = e.seq;
			}
			seqOf[id] = maxSeq + 1;
		}
		else
		{
			streamOf[id] = coord.allocStream();
			seqOf[id] = 0;
		}
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
		return deliver(msg, (ref const Listener) @safe => true);
	}

	/// Frame `msg` and deliver it on exactly ONE connected stream whose per-stream
	/// `SubscriptionFilter` accepts a notification with this `method` (and, for
	/// `notifications/resources/updated`, this resource `uri`). This honours the draft
	/// basic/utilities/subscriptions MUST NOT — "The server MUST NOT send notification
	/// types the client has not explicitly requested" — under Multiple Concurrent
	/// Subscriptions: with two listen streams (A opting into one type, B into another),
	/// a change notification reaches only a stream that requested it, never the other.
	///
	/// A listener whose filter is *active* (a real `subscriptions/listen` stream) is
	/// eligible only if its own filter accepts the notification. A listener with an
	/// *inactive* filter (a plain GET stream that did not go through `subscriptions/
	/// listen`) falls back to `plainEligible`: the server passes its global opt-in
	/// decision there, so the legacy single-stream draft path — where a client opts in
	/// globally and a plain GET listener receives the notification — is preserved,
	/// while concurrent active listen streams are still isolated to their own opt-in.
	/// Returns 1 if the message was delivered to an eligible live stream, else 0.
	size_t emitFiltered(string method, Json params, string uri = "", bool plainEligible = true) @safe
	{
		auto msg = makeNotification(method, params);
		return deliver(msg, (ref const Listener l) @safe {
			if (l.filter.active)
				return l.filter.accepts(method, uri);
			return plainEligible;
		});
	}

	/// Shared single-stream delivery: try eligible listeners (those for which
	/// `eligible` is true) in registration order, writing `msg` to the first live one
	/// and stopping there (the Multiple Connections rule: never broadcast the same
	/// message across multiple streams). Listeners whose write throws are dropped so
	/// the channel self-heals. Returns 1 on delivery, else 0.
	private size_t deliver(Json msg, scope bool delegate(ref const Listener) @safe eligible) @safe
	{
		import std.conv : to;

		long[] dead;
		size_t delivered;
		foreach (ref l; listeners)
		{
			if (!eligible(l))
				continue;
			const seq = seqOf[l.id];
			const eid = streamOf[l.id].to!string ~ "-" ~ seq.to!string;
			const frame = formatSseEvent(eid, withSubscriptionId(msg, l.subscriptionId));
			try
			{
				l.write(frame);
				recordHistory(streamOf[l.id], seq, frame);
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

	/// Append an emitted frame to a stream's replay history (basic/transports
	/// §Resumability and Redelivery), evicting the oldest entry once the per-stream
	/// bound is reached so the buffer stays bounded. Only frames that were actually
	/// written are recorded, so the cursor a client reports via `Last-Event-ID`
	/// always lands inside (or just before) the retained window.
	private void recordHistory(long ordinal, long seq, string frame) @safe
	{
		auto entries = ordinal in history;
		if (entries is null)
		{
			history[ordinal] = [HistoryEntry(seq, frame)];
			return;
		}
		*entries ~= HistoryEntry(seq, frame);
		if (maxHistoryPerStream > 0 && entries.length > maxHistoryPerStream)
			*entries = (*entries)[$ - maxHistoryPerStream .. $];
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
			const seq = seqOf[l.id];
			const eid = streamOf[l.id].to!string ~ "-" ~ seq.to!string;
			const frame = formatSseEvent(eid, withSubscriptionId(msg, l.subscriptionId));
			try
			{
				l.write(frame);
				recordHistory(streamOf[l.id], seq, frame);
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

unittest  // a GET carrying Last-Event-ID replays events emitted after that cursor
{
	// basic/transports §Resumability and Redelivery: "The server MAY use this
	// header to replay messages that would have been sent after the last event ID,
	// on the stream that was disconnected, and to resume the stream from that
	// point." Emit two events on a stream, capture the first event's id, drop the
	// listener (simulating a broken connection), then reconnect with that id as
	// Last-Event-ID: only the SECOND event must be replayed, framed with its
	// original id, and a new event continues the SAME stream ordinal.
	import std.string : indexOf, startsWith;
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	string[] first;
	const a = ch.addListener((string f) @safe { first ~= f; });
	ch.notify("notifications/message", Json(["n": Json(1)]));
	ch.notify("notifications/message", Json(["n": Json(2)]));
	assert(first.length == 2);

	// Extract the id of the FIRST event (the last one the client "received").
	const idLine = first[0]["id: ".length .. first[0].indexOf("\n")];
	ch.removeListener(a); // connection breaks

	string[] resumed;
	ch.addListener((string f) @safe { resumed ~= f; }, "", SubscriptionFilter.init, idLine);

	// Exactly the second event is replayed, with its ORIGINAL id (same ordinal).
	assert(resumed.length == 1);
	assert(resumed[0].canFind("\"n\":2"));
	assert(!resumed[0].canFind("\"n\":1"));
	assert(resumed[0].startsWith("id: " ~ idLine[0 .. idLine.indexOf("-")] ~ "-"));

	// A further event continues the resumed stream's ordinal, not a fresh one.
	ch.notify("notifications/message", Json(["n": Json(3)]));
	assert(resumed.length == 2);
	assert(resumed[1].canFind("\"n\":3"));
	assert(resumed[1].startsWith("id: " ~ idLine[0 .. idLine.indexOf("-")] ~ "-"));
}

unittest  // an unknown / empty Last-Event-ID falls back to a fresh stream ordinal
{
	// basic/transports §Resumability and Redelivery: replay is a MAY keyed on a
	// known stream. A blank header (a normal GET) or an id whose ordinal this
	// channel never issued must NOT replay anything — it opens a brand-new stream.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	string[] plain;
	ch.addListener((string f) @safe { plain ~= f; }); // no Last-Event-ID
	assert(plain.length == 0); // nothing replayed onto a fresh stream

	string[] bogus;
	ch.addListener((string f) @safe { bogus ~= f; }, "", SubscriptionFilter.init, "999-5");
	assert(bogus.length == 0); // unknown ordinal -> no replay
}

unittest  // replay never crosses streams (MUST NOT replay a different stream)
{
	// basic/transports §Resumability and Redelivery: "The server MUST NOT replay
	// messages that would have been delivered on a different stream." Two streams
	// each get their own event; resuming stream A's cursor must replay only A's
	// later events, never B's.
	import std.string : indexOf;
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	// Stream A receives event 1 (single-stream delivery picks the first listener).
	string[] aFrames;
	const a = ch.addListener((string f) @safe { aFrames ~= f; });
	ch.notify("notifications/message", Json(["s": Json("A1")]));
	ch.notify("notifications/message", Json(["s": Json("A2")]));
	assert(aFrames.length == 2);
	const aId0 = aFrames[0]["id: ".length .. aFrames[0].indexOf("\n")];

	// A second independent stream B (registered while A is still live) gets its own
	// ordinal; force a delivery onto it by removing A first is avoided — instead use
	// emitTo to target B directly so B's history is distinct from A's.
	string[] bFrames;
	const b = ch.addListener((string f) @safe { bFrames ~= f; });
	ch.emitTo(b, makeNotification("notifications/message", Json([
		"s": Json("B1")
	])));
	assert(bFrames.length == 1);

	ch.removeListener(a);

	// Resume A: only A2 replays; B1 must never appear.
	string[] resumed;
	ch.addListener((string f) @safe { resumed ~= f; }, "", SubscriptionFilter.init, aId0);
	assert(resumed.length == 1);
	assert(resumed[0].canFind("A2"));
	assert(!resumed[0].canFind("B1"));
	assert(!resumed[0].canFind("A1"));
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

unittest  // emitFiltered delivers a change notification ONLY to a stream that opted in
{
	// draft basic/utilities/subscriptions: "The server MUST NOT send notification
	// types the client has not explicitly requested." Two concurrent listen streams:
	// A opted into toolsListChanged only, B into resourceSubscriptions only. A
	// tools/list_changed must reach A and never B, regardless of registration order.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	SubscriptionFilter fa;
	fa.active = true;
	fa.toolsListChanged = true;
	SubscriptionFilter fb;
	fb.active = true;
	fb.resourceSubscriptions = true;
	// B registers FIRST so the old first-live-listener logic would have mis-delivered
	// the tools notification to B.
	ch.addListener((string f) @safe { bFrame = f; }, "listen-B", fb);
	ch.addListener((string f) @safe { aFrame = f; }, "listen-A", fa);

	const delivered = ch.emitFiltered("notifications/tools/list_changed", Json.undefined);
	assert(delivered == 1);
	import std.algorithm : canFind;

	assert(aFrame.canFind("notifications/tools/list_changed")); // A requested it
	assert(aFrame.canFind("listen-A"));
	assert(bFrame.length == 0); // B never requested toolsListChanged
}

unittest  // emitFiltered for resources/updated targets only the stream with that URI
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	SubscriptionFilter fa;
	fa.active = true;
	fa.resourceSubscriptions = true;
	fa.resourceUris = ["file:///a"];
	SubscriptionFilter fb;
	fb.active = true;
	fb.resourceSubscriptions = true;
	fb.resourceUris = ["file:///b"];
	ch.addListener((string f) @safe { aFrame = f; }, "A", fa);
	ch.addListener((string f) @safe { bFrame = f; }, "B", fb);

	Json p = Json.emptyObject;
	p["uri"] = "file:///b";
	const delivered = ch.emitFiltered("notifications/resources/updated", p, "file:///b");
	assert(delivered == 1);
	import std.algorithm : canFind;

	assert(bFrame.canFind("file:///b")); // B opted into file:///b
	assert(aFrame.length == 0); // A opted into a different URI only
}

unittest  // emitFiltered: no eligible stream means no delivery (returns 0)
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string frame;
	SubscriptionFilter f;
	f.active = true;
	f.toolsListChanged = true; // opted into tools only
	ch.addListener((string fr) @safe { frame = fr; }, "only", f);

	// promptsListChanged was never requested by the only stream.
	const delivered = ch.emitFiltered("notifications/prompts/list_changed", Json.undefined);
	assert(delivered == 0);
	assert(frame.length == 0);
}

unittest  // emitFiltered still reaches a plain GET stream (inactive filter accepts all)
{
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string frame;
	ch.addListener((string f) @safe { frame = f; }); // plain GET stream, no opt-in

	const delivered = ch.emitFiltered("notifications/tools/list_changed", Json.undefined);
	assert(delivered == 1);
	import std.algorithm : canFind;

	assert(frame.canFind("notifications/tools/list_changed"));
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
	// Connection-liveness probe. On the draft Streamable HTTP transport a client
	// disconnect IS the cancellation signal (draft basic/utilities/cancellation
	// §Transport-Specific Cancellation: "Closing the SSE response stream is the
	// cancellation signal. The server MUST treat a client disconnect as
	// cancellation of that request"). Defaults to the live HTTP connection state;
	// overridable via `setConnectionProbe` so tests can simulate a disconnect.
	private bool delegate() @safe connAlive_;

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
		this.connAlive_ = () @safe => res.connected;
	}

	/// Override the connection-liveness probe used by `isCancelled` on the draft
	/// transport. Lets the transport or tests supply a disconnect signal in place
	/// of the live `HTTPServerResponse.connected` reading.
	void setConnectionProbe(bool delegate() @safe alive) @safe
	{
		this.connAlive_ = alive;
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

	/// Cancellation for this request. On released protocol versions
	/// (2025-03-26 / 2025-06-18 / 2025-11-25) cancellation is tracked solely by the
	/// server's `RequestScope` (the shared token flipped by `notifications/
	/// cancelled`), so the transport context itself reports never-cancelled. On the
	/// draft Streamable HTTP transport a client disconnect IS the cancellation
	/// signal (draft basic/utilities/cancellation §Transport-Specific
	/// Cancellation: "The server MUST treat a client disconnect as cancellation of
	/// that request"), so a dropped connection reports cancelled and the wrapping
	/// `RequestScope.isCancelled` surfaces it to a polling handler.
	bool isCancelled() @safe
	{
		if (isDraft_ && connAlive_ !is null)
			return !connAlive_();
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
		// `data` is REQUIRED by server/utilities/logging; emit explicit JSON
		// null for an undefined payload so vibe does not drop the key.
		p["data"] = data.type == Json.Type.undefined ? Json(null) : data;
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

/// Parse an SSE event id of the form `<ordinal>-<seq>` (the per-stream cursor
/// `ServerPushChannel` stamps on every event) back into its components. Returns
/// true with `ordinal`/`seq` populated on success, false for any malformed input
/// (empty, no dash, non-numeric, negative). Used to interpret a reconnecting
/// client's `Last-Event-ID` so the server can replay events after that cursor on
/// the stream it identifies (basic/transports §Resumability and Redelivery).
bool parseEventId(string id, out long ordinal, out long seq) @safe pure nothrow
{
	import std.string : indexOf;
	import std.conv : to;

	const dash = id.indexOf('-');
	if (dash <= 0 || dash + 1 >= id.length)
		return false;
	try
	{
		ordinal = id[0 .. dash].to!long;
		seq = id[dash + 1 .. $].to!long;
	}
	catch (Exception)
		return false;
	return ordinal >= 0 && seq >= 0;
}

unittest  // parseEventId round-trips a well-formed cursor and rejects junk
{
	long o, q;
	assert(parseEventId("3-7", o, q) && o == 3 && q == 7);
	assert(parseEventId("0-0", o, q) && o == 0 && q == 0);
	assert(!parseEventId("", o, q));
	assert(!parseEventId("3", o, q));
	assert(!parseEventId("-5", o, q));
	assert(!parseEventId("3-", o, q));
	assert(!parseEventId("x-1", o, q));
	assert(!parseEventId("3-y", o, q));
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

/// Whether the server SHOULD emit an SSE `retry:` field before closing a
/// connection that it is *not* terminating (so the client knows how long to
/// wait before reconnecting). This is a 2025-11-25-only SHOULD
/// (basic/transports §Sending Messages item 6 / §Listening for Messages item 4):
/// "If the server does close the connection prior to terminating the SSE stream,
/// it SHOULD send an SSE event with a standard `retry` field before closing the
/// connection." It builds on the 2025-11-25 connection/stream split (reconnect
/// via Last-Event-ID), which does not exist in 2025-03-26 / 2025-06-18, and the
/// draft dropped Last-Event-ID resumability — so this MUST NOT alter those
/// versions' wire output. Gated here as a single pure predicate so the version
/// boundary is directly testable.
bool sendsRetryOnClose(ProtocolVersion v) @safe pure nothrow
{
	return v == ProtocolVersion.v2025_11_25;
}

unittest  // the retry-on-close hint is sent ONLY on 2025-11-25
{
	assert(sendsRetryOnClose(ProtocolVersion.v2025_11_25));
	assert(!sendsRetryOnClose(ProtocolVersion.v2025_06_18));
	assert(!sendsRetryOnClose(ProtocolVersion.v2025_03_26));
	assert(!sendsRetryOnClose(ProtocolVersion.v2024_11_05));
	// The draft drops Last-Event-ID resumability, so no reconnect hint there.
	assert(!sendsRetryOnClose(ProtocolVersion.draft));
}

/// Frame a standalone Server-Sent Events `retry:` event carrying the
/// reconnection time in milliseconds (per the SSE standard's `retry` field:
/// https://html.spec.whatwg.org/multipage/server-sent-events.html). The server
/// SHOULD send this before closing a connection it is not terminating; the
/// client MUST then wait the given number of milliseconds before reconnecting
/// (basic/transports §Sending Messages item 6). A bare `retry:` event carries no
/// `data:` line, so it updates the client's reconnection time without dispatching
/// any JSON-RPC payload.
string formatRetryEvent(uint ms) @safe
{
	import std.conv : to;

	return "retry: " ~ ms.to!string ~ "\n\n";
}

unittest  // a retry event is a bare `retry:` line with the delay in ms
{
	assert(formatRetryEvent(3000) == "retry: 3000\n\n");
}

unittest  // the retry event carries no data: line (no JSON-RPC payload)
{
	import std.string : indexOf;

	const frame = formatRetryEvent(1500);
	assert(frame.indexOf("data:") < 0);
	assert(frame.indexOf("retry: 1500") == 0);
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

unittest  // draft HttpStreamContext: a disconnected client reports cancelled
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;
	import mcp.protocol.versions : ProtocolVersion;

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;
	auto ctx = new HttpStreamContext(res, coord, caps, Json.undefined,
			TokenInfo.invalid(), true, ProtocolVersion.draft);

	// Connection alive -> not cancelled.
	ctx.setConnectionProbe(() @safe => true);
	assert(!ctx.isCancelled);

	// Client closed the SSE stream -> the draft transport treats it as
	// cancellation of the in-flight request (draft basic/utilities/cancellation
	// §Transport-Specific Cancellation).
	ctx.setConnectionProbe(() @safe => false);
	assert(ctx.isCancelled);
}

unittest  // released versions: a disconnect never reports cancelled (draft-only MUST)
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;
	// isDraft = false (default): the 2025-* transports track cancellation solely
	// via notifications/cancelled, so the context itself stays never-cancelled
	// even when the connection has dropped.
	auto ctx = new HttpStreamContext(res, coord, caps, Json.undefined);
	ctx.setConnectionProbe(() @safe => false);
	assert(!ctx.isCancelled);
}
