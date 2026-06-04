module mcp.transport.sse_context;

import core.time : Duration, seconds, msecs;
import std.typecons : Nullable;

import vibe.core.sync : LocalManualEvent, createManualEvent, TaskMutex;
import vibe.data.json : Json;
import vibe.http.server : HTTPServerResponse;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.transport.coordinator : throwOrReturn;
import mcp.protocol.capabilities;
import mcp.protocol.draft : withSubscriptionId;
import mcp.protocol.versions : ProtocolVersion, latestStable, supportsProgressMessage;
import mcp.server.context;
import mcp.server.connection : ConnectionState;
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
		/// The connection/session token of the peer the outbound request was
		/// issued to. A client response only resolves this waiter when it arrives
		/// from the SAME token, so one session cannot satisfy another session's
		/// pending server->client request. The empty token marks an unscoped
		/// (stateless / shared) waiter, which any responder may resolve.
		string ownerToken;
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

	/// Begin tracking a pending outbound request, bound to the connection/session
	/// `ownerToken` it was issued to. Only a response arriving from the same token
	/// may resolve it; an empty token leaves the waiter unscoped (stateless /
	/// shared mode), resolvable by any responder.
	void register(long id, string ownerToken = "") @safe
	{
		auto w = new Waiter;
		w.evt = createManualEvent();
		w.ownerToken = ownerToken;
		waiters[id] = w;
	}

	/// Block the current task until the client responds to `id` (or `timeout`
	/// elapses). Returns the result, or throws `McpException` on error/timeout.
	Json await(long id, Duration timeout = 60.seconds) @safe
	{
		auto wp = id in waiters;
		if (wp is null)
			throw internalError("awaiting an unknown request id");
		auto w = *wp;
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
		return throwOrReturn(w.result, w.error, "client error");
	}

	/// Block the current task until the client responds to `id`, while polling
	/// `alive` in short slices so a dropped connection releases the awaiting fiber
	/// promptly rather than parking for the full `timeout`. When `alive` returns
	/// false before a response arrives, the pending request is failed with
	/// `disconnectError` (mirroring the GET path's `failPendingForIds` on listener
	/// disconnect) and that error is thrown. A null `alive` probe degrades to the
	/// plain `await(id, timeout)` behaviour.
	Json awaitLive(long id, bool delegate() @safe alive, McpException disconnectError,
			Duration timeout = 60.seconds, Duration slice = 250.msecs) @safe
	{
		if (alive is null)
			return await(id, timeout);

		auto wp = id in waiters;
		if (wp is null)
			throw internalError("awaiting an unknown request id");
		auto w = *wp;
		scope (exit)
			waiters.remove(id);

		auto ec = w.evt.emitCount;
		auto remaining = timeout;
		while (!w.done)
		{
			if (!alive())
			{
				Json err = Json.emptyObject;
				err["code"] = disconnectError.code;
				err["message"] = disconnectError.msg;
				w.error = err;
				w.done = true;
				break;
			}
			const thisSlice = remaining < slice ? remaining : slice;
			const newEc = () @trusted { return w.evt.wait(thisSlice, ec); }();
			if (newEc == ec && !w.done)
			{
				remaining -= thisSlice;
				if (remaining <= Duration.zero)
					throw internalError("Timed out awaiting client response");
				continue;
			}
			ec = newEc;
		}
		return throwOrReturn(w.result, w.error, "client error");
	}

	/// Drop a registered-but-unawaited request id (e.g. when delivery failed so
	/// the request will never get a response). Idempotent; unknown ids are
	/// ignored. Keeps the waiter table from leaking when `register` is not
	/// followed by `await`.
	void cancel(long id) @safe
	{
		waiters.remove(id);
	}

	/// Deliver a client response/errorResponse from the peer identified by
	/// `responderToken`. Returns true if it matched a pending outbound request
	/// that was issued to the SAME token. A response whose token differs from the
	/// waiter's owner is rejected (returns false) so one session cannot resolve or
	/// hijack another session's pending server->client request. A waiter
	/// registered with an empty owner token (stateless / shared mode) is matched
	/// regardless of `responderToken`, preserving prior behavior where no session
	/// attribution exists.
	bool resolve(Json idJson, Json result, Json error, string responderToken = "") @safe
	{
		if (idJson.type != Json.Type.int_)
			return false;
		const id = idJson.get!long;
		if (auto w = id in waiters)
		{
			if (w.ownerToken.length != 0 && w.ownerToken != responderToken)
				return false;
			w.result = result;
			w.error = error;
			w.done = true;
			w.evt.emit();
			return true;
		}
		return false;
	}

	/// Fail a single still-pending outbound request with `error` and wake its
	/// awaiting task immediately (mirrors `DuplexCoordinator.failPending`, but
	/// targeted at one id). Used when the GET SSE listener a server->client request
	/// was delivered on disconnects before the client could respond: rather than
	/// letting the awaiter block for the full timeout, it is released promptly with
	/// an `McpException`. Unknown ids are ignored.
	///
	/// The waiter is left in the table: cleanup is the awaiter's responsibility via
	/// `await`/`awaitLive`'s `scope (exit) waiters.remove(id)`. Callers MUST only fail
	/// ids that have (or will have) a live awaiter, which holds for the sole caller
	/// `removeListenerLocked`: every id it fails was registered in `sendRequest`
	/// immediately before its `awaitLive`, and an id whose delivery failed is dropped
	/// via `cancel` rather than reaching this path. A failed waiter that is awaited
	/// only afterwards still observes `done`/`error` (see the fail-then-await unittest).
	void failPending(long id, McpException error) @safe
	{
		if (auto w = id in waiters)
		{
			Json err = Json.emptyObject;
			err["code"] = error.code;
			err["message"] = error.msg;
			w.error = err;
			w.done = true;
			w.evt.emit();
		}
	}

	/// Fail several pending outbound requests at once (see `failPending`).
	void failPendingForIds(long[] ids, McpException error) @safe
	{
		foreach (id; ids)
			failPending(id, error);
	}
}

unittest  // awaitLive releases promptly with the disconnect error when liveness is false
{
	auto coord = new StreamCoordinator;
	const id = coord.alloc();
	coord.register(id);

	bool threw;
	try
		coord.awaitLive(id, () @safe => false,
				internalError("client disconnected before responding"));
	catch (McpException e)
	{
		threw = true;
		assert(e.msg == "client disconnected before responding");
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw, "disconnect must release the awaiting fiber with an McpException");
}

unittest  // a resolved response wins even when liveness is checked
{
	auto coord = new StreamCoordinator;
	const id = coord.alloc();
	coord.register(id);
	assert(coord.resolve(Json(id), Json("ok"), Json.undefined));

	const r = coord.awaitLive(id, () @safe => true,
			internalError("client disconnected before responding"));
	assert(r == Json("ok"));
}

unittest  // a null liveness probe degrades to a plain resolved await
{
	auto coord = new StreamCoordinator;
	const id = coord.alloc();
	coord.register(id);
	assert(coord.resolve(Json(id), Json("done"), Json.undefined));

	const r = coord.awaitLive(id, null, internalError("client disconnected before responding"));
	assert(r == Json("done"));
}

unittest  // await on an unregistered id surfaces a catchable McpException, not a RangeError
{
	auto coord = new StreamCoordinator;
	bool threw;
	try
		coord.await(99);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw, "awaiting an unknown id must throw a catchable McpException");
}

unittest  // awaitLive on an unregistered id surfaces a catchable McpException, not a RangeError
{
	auto coord = new StreamCoordinator;
	bool threw;
	try
		coord.awaitLive(99, () @safe => true, internalError("disconnected"));
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw, "awaiting an unknown id must throw a catchable McpException");
}

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
/// listen`; an inactive filter accepts everything, so the plain GET stream still obeys
/// only the transport's Multiple Connections rule.
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
			// A blanket boolean opt-in (no per-URI list) accepts any URI;
			// otherwise only the explicitly named URIs are accepted.
			return resourceUris.length == 0 || uri.length == 0 || resourceUris.canFind(uri);
		default:
			// Not a subscription-gated change notification: always deliverable.
			return true;
		}
	}
}

unittest  // failPending is idempotent and leaves the awaiter to clean the table up
{
	// Failing the same id twice must not throw: the second call simply re-marks an
	// already-failed waiter. The waiter stays in the table (the awaiter removes it),
	// so the fail-then-await path can still observe and report the error.
	auto coord = new StreamCoordinator;
	const id = coord.alloc();
	coord.register(id);

	coord.failPending(id, internalError("first"));
	coord.failPending(id, internalError("second")); // idempotent: no throw, no crash
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

/// A long-lived server->client SSE channel for *unsolicited* traffic — the
/// stream a client opens with an HTTP GET to the MCP endpoint (basic/transports
/// §Listening for Messages from the Server). One instance is shared across a
/// server mount. Unlike `HttpStreamContext`, which is bound to one in-flight
/// POST, `emit` frames the JSON-RPC message as an SSE event with a globally-unique
/// id (via the shared `StreamCoordinator` ordinal scheme) and writes it to exactly
/// ONE live GET listener, honouring the transport's Multiple Connections rule:
/// "The server MUST send each of its JSON-RPC messages on only one of the
/// connected streams; that is, it MUST NOT broadcast the same message across
/// multiple streams." A listener that fails to write (a disconnected client) is
/// skipped and dropped, so the channel self-heals and the message still lands on a
/// live stream.
///
/// The channel serializes delivery and listener-list mutation internally with a
/// vibe `TaskMutex`, so concurrent fibers cannot interleave the bytes of two SSE
/// frames, reuse an event id, or dangle the listener list across an async write.
/// Callers that ALSO write to the same underlying `HTTPServerResponse.bodyWriter`
/// outside the channel (e.g. a heartbeat loop or an up-front `retry:` event on the
/// GET/listen stream) MUST serialize those writes against the channel's listener
/// write callback through a shared per-stream lock, since the channel's mutex
/// guards only its own state and its own writes — not a foreign writer on the same
/// connection. Like the rest of the SDK, this assumes vibe.d's default
/// single-threaded event loop; running the router with `HTTPServerOption.distribute`
/// or worker threads is unsupported.
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
		/// Per-listener fallback eligibility for an INACTIVE-filter stream (a plain
		/// 2025-era standalone GET stream). When set, `emitFiltered` consults this
		/// instead of the mount-wide `plainEligible`, so a change notification's
		/// delivery gate (notably `notifications/resources/updated`) honours the
		/// per-session subscription set bound to THIS listener rather than a shared
		/// fallback. Null for streams that have no per-session gate (stdio fallbacks,
		/// active `subscriptions/listen` streams which decide via `filter`).
		bool delegate(string method, string uri) @safe plainEligible;
		/// The session/connection token that owns this listener's stream. Resume
		/// (Last-Event-ID) is scoped to the owning session: a listener may only
		/// resume a stream ordinal whose recorded owner equals this token, so one
		/// session cannot replay another session's buffered history by guessing its
		/// event id (cross-session disclosure). The empty token marks an unscoped
		/// (stateless / shared) stream, mirroring the unscoped
		/// `StreamCoordinator.Waiter`, for which any resume is accepted.
		string ownerToken;
		/// Per-listener serialization point. The blocking `write` to this stream —
		/// together with the seq read it is framed with and the seq/history commit
		/// that follows — runs under THIS mutex, NOT the channel-wide `mtx`. Keeping
		/// the write off `mtx` means a slow stream X does not block delivery to stream
		/// Y, `notify`, `sendRequest`, `addListener`, or `removeListener` mount-wide,
		/// while still serializing concurrent writes to the SAME stream so seq
		/// assignment cannot reorder relative to the bytes on the wire — every event id
		/// stays per-stream-monotonic and globally unique. Allocated per listener in
		/// `addListener`.
		TaskMutex writeMtx;
	}

	private StreamCoordinator coord;
	private Listener[] listeners;
	private long[long] streamOf; /// listener id -> its allocated stream ordinal
	private long[long] seqOf; /// listener id -> its monotonic event sequence
	private long nextListenerId = 1;

	/// Stream ordinal -> the session/connection token that owns it. A Last-Event-ID
	/// resume is honoured only when the resuming listener's `ownerToken` matches the
	/// owner recorded here, so a session cannot resume (and have replayed to it)
	/// another session's stream history by guessing its globally-monotonic event id.
	/// An ordinal owned by the empty token is unscoped (stateless / shared) and may
	/// be resumed by any listener, preserving prior behaviour where no session
	/// attribution exists.
	private string[long] streamOwner;

	/// Guards the channel's shared state: the listener list, `streamOf`/`seqOf`,
	/// `requestListener`, and the replay history. Held only for short,
	/// non-blocking critical sections — the candidate scan, the seq read, and the
	/// seq/history commit — and explicitly RELEASED across the blocking `l.write`
	/// socket write. The write itself is serialized per stream by the target
	/// `Listener.writeMtx` instead, so a slow stream does not block delivery to
	/// other streams / `notify` / `sendRequest` / `addListener` / `removeListener`
	/// while still keeping each stream's writes — and the seq ids they carry —
	/// strictly ordered: the listener list stays consistent and event ids stay
	/// per-stream-monotonic and globally unique.
	private TaskMutex mtx;

	/// In-flight server->client request id -> the listener id it was delivered on.
	/// When that listener disconnects (`removeListener`) the bound requests are
	/// failed immediately so their awaiters do not hang for the full timeout.
	/// Cleared as requests complete or their listener drops.
	private long[long] requestListener;

	/// LRU order of stream ordinals that currently hold replay history, oldest
	/// first. Bounds total retained memory across the mount's lifetime to
	/// `maxHistoryStreams * maxHistoryPerStream` frames regardless of how many
	/// short-lived GET streams connect and disconnect: a reconnecting client still
	/// finds a recently-disconnected stream's buffer for Last-Event-ID replay, but a
	/// stream not touched for `maxHistoryStreams` newer streams is evicted.
	private long[] historyOrder;
	private size_t maxHistoryStreams = 64;

	/// Per-stream replay history for Last-Event-ID resumability
	/// (basic/transports §Resumability and Redelivery): for each stream ordinal,
	/// the already-framed SSE blocks emitted on it, paired with their event
	/// sequence, kept so a reconnecting GET carrying `Last-Event-ID` can have the
	/// messages emitted *after* that id replayed on the very stream that was
	/// disconnected. Bounded per stream (oldest evicted first) so the buffer cannot
	/// grow without limit. The spec rule is a MAY; this is opt-in via a non-empty
	/// `resumeFrom` on `addListener`, so a normal GET (no `Last-Event-ID`) opens a
	/// fresh ordinal.
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
		this.mtx = new TaskMutex;
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
	/// fresh ordinal, so a normal GET opens a brand-new stream. The MUST NOT —
	/// "replay messages that would have been delivered on a different stream" — is
	/// honoured because replay is keyed strictly on the id's ordinal.
	long addListener(void delegate(string frame) @safe write, string subscriptionId = "",
			SubscriptionFilter filter = SubscriptionFilter.init, string resumeFrom = "",
			bool delegate(string method, string uri) @safe plainEligible = null,
			string ownerToken = "") @safe
	{
		return () @trusted {
			auto lWriteMtx = new TaskMutex;
			long id;
			string[] replay; // frames to replay, snapshotted under the lock

			// Phase 1 (under mtx): register the listener and decide its stream
			// ordinal + starting seq. For a resume, SNAPSHOT the frames to replay and
			// fix the continuation seq up-front, but DEFER the actual writes — the
			// blocking socket write must not run under the channel mutex.
			synchronized (mtx)
			{
				id = nextListenerId++;
				listeners ~= Listener(id, write, subscriptionId, filter,
						plainEligible, ownerToken, lWriteMtx);

				long resumeOrdinal, resumeSeq;
				// A resume is honoured only when the ordinal exists AND its recorded
				// owner matches this listener's token: a session must not be able to
				// replay another session's history by presenting its event id. An
				// ordinal owned by the empty token (unscoped / stateless) is resumable
				// by anyone. A token mismatch falls through to a fresh ordinal, never
				// disclosing the other session's frames.
				if (parseEventId(resumeFrom, resumeOrdinal, resumeSeq)
						&& resumeOrdinal in history && resumeOrdinal in streamOwner
						&& (streamOwner[resumeOrdinal].length == 0
							|| streamOwner[resumeOrdinal] == ownerToken))
				{
					// Resume the disconnected stream: keep its ordinal, replay every
					// buffered event after the cursor in sequence order, and continue
					// from the next seq. Touch the ordinal so its history is treated as
					// most-recently used.
					streamOf[id] = resumeOrdinal;
					touchHistory(resumeOrdinal);
					long maxSeq = resumeSeq;
					foreach (ref e; history[resumeOrdinal])
					{
						if (e.seq <= resumeSeq)
							continue;
						replay ~= e.frame;
						if (e.seq > maxSeq)
							maxSeq = e.seq;
					}
					seqOf[id] = maxSeq + 1;
				}
				else
				{
					const ord = coord.allocStream();
					streamOf[id] = ord;
					streamOwner[ord] = ownerToken;
					seqOf[id] = 0;
				}
			}

			// Phase 2 (off mtx, under the new listener's writeMtx): replay the
			// snapshotted frames in order. Holding the per-listener writeMtx means any
			// concurrent `deliver`/`emitTo` that picks this listener blocks here until
			// replay completes, so live events strictly follow the replayed ones — the
			// resumed stream's wire order (and its seq monotonicity) is preserved
			// without holding the channel mutex across these blocking writes.
			if (replay.length)
			{
				synchronized (lWriteMtx)
				{
					foreach (frame; replay)
						write(frame);
				}
			}
			return id;
		}();
	}

	/// Drop a listener (e.g. when its GET stream is closed). Any in-flight
	/// server->client request that was delivered on this listener is failed
	/// immediately so its awaiter wakes with an `McpException` instead of hanging
	/// for the full timeout. Acquires the delivery mutex so it cannot interleave
	/// with an in-progress write or another list mutation.
	void removeListener(long id) @safe
	{
		() @trusted {
			synchronized (mtx)
				removeListenerLocked(id);
		}();
	}

	/// List-mutation half of `removeListener`, assuming the delivery mutex is
	/// already held (so it can be called from inside `deliver`/`emitTo` dead-stream
	/// cleanup without re-acquiring the non-recursive mutex). Fails the in-flight
	/// requests bound to this listener.
	private void removeListenerLocked(long id) @safe
	{
		import std.algorithm : remove;

		listeners = listeners.remove!(l => l.id == id);
		streamOf.remove(id);
		seqOf.remove(id);

		// Fail exactly the in-flight server->client requests bound to this listener
		// (not every pending waiter): other requests may be bound to surviving
		// listeners.
		long[] orphaned;
		foreach (reqId, lid; requestListener)
			if (lid == id)
				orphaned ~= reqId;
		foreach (reqId; orphaned)
			requestListener.remove(reqId);
		if (orphaned.length)
			coord.failPendingForIds(orphaned,
					internalError("GET SSE listener disconnected before the client responded"));
	}

	/// Number of currently-connected listeners.
	size_t listenerCount() const @safe
	{
		return listeners.length;
	}

	/// The distinct, non-empty owner tokens of the currently-connected listeners.
	/// Each value is a session whose GET stream can receive a session-scoped
	/// server->client request (e.g. `ping`), so a caller can probe every live
	/// session in turn rather than blindly forwarding an empty token that matches no
	/// session-scoped listener. The empty (unscoped / stateless / shared) token is
	/// excluded, since that path is reached via the no-token `ping`/`sendRequest`.
	string[] connectedOwnerTokens() @safe
	{
		return () @trusted {
			synchronized (mtx)
			{
				bool[string] seen;
				string[] tokens;
				foreach (l; listeners)
					if (l.ownerToken.length != 0 && (l.ownerToken in seen) is null)
					{
						seen[l.ownerToken] = true;
						tokens ~= l.ownerToken;
					}
				return tokens;
			}
		}();
	}

	/// Whether a listener with `id` is still connected. Used as the liveness probe
	/// for `sendRequest`'s `awaitLive`, so a server->client request awaiter is
	/// released promptly if its target stream drops.
	private bool isListenerLive(long listenerId) @safe
	{
		return () @trusted {
			synchronized (mtx)
			{
				foreach (l; listeners)
					if (l.id == listenerId)
						return true;
				return false;
			}
		}();
	}

	/// Number of stream ordinals currently retaining replay history. Exposed for
	/// tests/diagnostics to verify the LRU bound; the value is at most
	/// `maxHistoryStreams`.
	size_t retainedHistoryStreams() const @safe
	{
		return history.length;
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
		return deliver(msg, (ref const Listener) @safe => true) >= 0 ? 1 : 0;
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
	/// decision there, so the single-stream draft path — where a client opts in
	/// globally and a plain GET listener receives the notification — works, while
	/// concurrent active listen streams are still isolated to their own opt-in.
	/// Returns 1 if the message was delivered to an eligible live stream, else 0.
	size_t emitFiltered(string method, Json params, string uri = "", bool plainEligible = true) @safe
	{
		auto msg = makeNotification(method, params);
		return deliver(msg, (ref const Listener l) @safe {
			if (l.filter.active)
				return l.filter.accepts(method, uri);
			// Inactive filter (plain 2025-era standalone GET stream): consult the
			// listener's own per-session gate when present so the delivery decision
			// (notably `notifications/resources/updated`) honours the subscriptions
			// bound to THIS stream's session rather than a shared fallback.
			if (l.plainEligible !is null)
				return l.plainEligible(method, uri);
			return plainEligible;
		}) >= 0 ? 1 : 0;
	}

	/// Broadcast variant of `emitFiltered` for the genuinely fan-out change
	/// notifications (`notifications/tools/list_changed`, `prompts/list_changed`,
	/// `resources/list_changed`): deliver the notification once per distinct
	/// session, so EVERY connected session's stream is reached rather than only the
	/// first eligible one. Listeners are grouped by their `ownerToken`, and the
	/// existing single-stream `deliver` runs once per distinct token — so the
	/// transport's Multiple Connections rule ("MUST NOT broadcast the same message
	/// across multiple streams") is still honoured WITHIN a session (only one of a
	/// session's streams receives it), while distinct sessions each get their own
	/// copy. Eligibility for each listener is decided exactly as in `emitFiltered`
	/// (active filter via its own opt-in; inactive filter via the per-listener or
	/// mount-wide `plainEligible`). Returns the number of distinct sessions reached.
	size_t emitFilteredPerOwner(string method, Json params, string uri = "",
			bool plainEligible = true) @safe
	{
		auto msg = makeNotification(method, params);
		scope eligible = (ref const Listener l) @safe {
			if (l.filter.active)
				return l.filter.accepts(method, uri);
			if (l.plainEligible !is null)
				return l.plainEligible(method, uri);
			return plainEligible;
		};

		// Snapshot the distinct owner tokens that currently have at least one
		// eligible live listener, under the lock, so the listener list cannot mutate
		// while we enumerate; the actual writes happen off the lock inside `deliver`.
		string[] owners;
		() @trusted {
			synchronized (mtx)
			{
				bool[string] seen;
				foreach (l; listeners)
					if (l.id in seqOf && (l.ownerToken in seen) is null && eligible(l))
					{
						seen[l.ownerToken] = true;
						owners ~= l.ownerToken;
					}
			}
		}();

		size_t delivered;
		foreach (owner; owners)
		{
			// One single-stream delivery per session: only listeners owned by this
			// token are candidates, so each distinct session receives exactly one copy.
			const landed = deliver(msg, (ref const Listener l) @safe {
				return l.ownerToken == owner && eligible(l);
			});
			if (landed >= 0)
				delivered++;
		}
		return delivered;
	}

	/// Shared single-stream delivery: try eligible listeners (those for which
	/// `eligible` is true) in registration order, writing `msg` to the first live one
	/// and stopping there (the Multiple Connections rule: never broadcast the same
	/// message across multiple streams). Listeners whose write throws are dropped so
	/// the channel self-heals. Returns the listener id the message landed on, or -1
	/// when no live eligible listener could receive it.
	///
	/// The channel mutex is held only for short, non-blocking critical sections —
	/// snapshotting the eligible candidates, reading the seq each frame is stamped
	/// with, and committing the seq/history afterwards. The blocking `l.write` runs
	/// OFF the channel mutex, serialized per stream by the target listener's own
	/// `writeMtx`, so two concurrent emits to the SAME listener are still strictly
	/// ordered (the seq read + write + commit all happen under that one `writeMtx`,
	/// so the frame that reaches the socket first carries the lower seq), while a
	/// slow stream does not block delivery to others.
	/// When `bindRequestId >= 0`, the message is an in-flight server->client request
	/// and its id is bound to the chosen listener (`requestListener[bindRequestId] =
	/// listenerId`) under `mtx` BEFORE the blocking write, atomically with confirming
	/// the candidate is still live (see `writeToListener`). This closes the disconnect
	/// race: a `removeListenerLocked` scan that runs while the frame is being written
	/// already observes the binding and fails the awaiter immediately, rather than the
	/// binding being recorded only after `deliver` returns.
	private long deliver(Json msg,
			scope bool delegate(ref const Listener) @safe eligible, long bindRequestId = -1) @safe
	{
		// Snapshot the eligible candidates (in registration order) under the lock so
		// the list cannot mutate under us; the actual writes happen off the lock.
		Listener[] candidates;
		() @trusted {
			synchronized (mtx)
			{
				foreach (l; listeners)
					if (eligible(l) && l.id in seqOf)
						candidates ~= l;
			}
		}();

		foreach (l; candidates)
		{
			if (writeToListener(l, msg, bindRequestId))
				return l.id; // single-stream delivery: stop at the first success
		}
		return -1;
	}

	/// Frame `msg` for one listener and write it, with the channel mutex held only
	/// for the brief seq read and the post-write seq/history commit — never across
	/// the blocking `l.write`. The whole read-write-commit runs under `l.writeMtx`,
	/// so concurrent writes to the same stream are serialized and their seq ids stay
	/// monotonic in write order. Returns true if the frame was written; false if the
	/// listener was concurrently removed or its write threw (in which case it is
	/// dropped from the channel).
	private bool writeToListener(Listener l, Json msg, long bindRequestId = -1) @safe
	{
		import std.conv : to;

		return () @trusted {
			synchronized (l.writeMtx)
			{
				long seq, ordinal;
				// Brief lock: confirm the listener still exists and read the seq this
				// frame will carry. Releasing before the write is what frees the
				// channel for other streams.
				bool present;
				synchronized (mtx)
				{
					if (l.id in seqOf)
					{
						present = true;
						seq = seqOf[l.id];
						ordinal = streamOf[l.id];
						// Commit the request->listener binding here, under `mtx` and
						// before the blocking write, so a concurrent disconnect's
						// `removeListenerLocked` scan observes the in-flight id and
						// fails its awaiter immediately instead of after the write.
						if (bindRequestId >= 0)
							requestListener[bindRequestId] = l.id;
					}
				}
				if (!present)
					return false; // removed by a concurrent path before we reached it

				const eid = ordinal.to!string ~ "-" ~ seq.to!string;
				const frame = formatSseEvent(eid, withSubscriptionId(msg, l.subscriptionId));
				try
				{
					l.write(frame);
				}
				catch (Exception)
				{
					synchronized (mtx)
					{
						// Drop the binding before dropping the listener so the failed
						// in-flight request is failed exactly once by the caller, not
						// orphaned onto a listener that is about to disappear.
						if (bindRequestId >= 0)
							requestListener.remove(bindRequestId);
						removeListenerLocked(l.id);
					}
					return false;
				}
				// Brief lock: commit. Because this whole body holds l.writeMtx, no
				// other write to this stream interleaved, so seqOf[l.id] is still the
				// `seq` we framed with — assign history + bump in write order.
				synchronized (mtx)
				{
					if (l.id !in seqOf)
						return true; // removed during the write; do not resurrect
					recordHistory(ordinal, seq, frame);
					seqOf[l.id]++;
				}
				return true;
			}
		}();
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
			touchHistory(ordinal);
			evictOldHistory();
			return;
		}
		touchHistory(ordinal);
		*entries ~= HistoryEntry(seq, frame);
		if (maxHistoryPerStream > 0 && entries.length > maxHistoryPerStream)
			*entries = (*entries)[$ - maxHistoryPerStream .. $];
	}

	/// Mark `ordinal` as most-recently used in the history LRU order: move it to the
	/// back of `historyOrder` so the oldest untouched ordinal is the one evicted when
	/// the cap is exceeded.
	private void touchHistory(long ordinal) @safe
	{
		import std.algorithm : remove, countUntil;

		const i = historyOrder.countUntil(ordinal);
		if (i >= 0)
			historyOrder = historyOrder.remove(i);
		historyOrder ~= ordinal;
	}

	/// Evict the oldest history ordinals once more than `maxHistoryStreams` are
	/// retained, giving an absolute upper bound of
	/// `maxHistoryStreams * maxHistoryPerStream` buffered frames over the mount's
	/// lifetime regardless of how many short-lived GET streams come and go. A
	/// still-connected listener's ordinal can be evicted too, which only forgoes
	/// resume-replay for that stream — never a correctness issue.
	private void evictOldHistory() @safe
	{
		while (maxHistoryStreams > 0 && historyOrder.length > maxHistoryStreams)
		{
			const victim = historyOrder[0];
			historyOrder = historyOrder[1 .. $];
			history.remove(victim);
			// Drop the ordinal's owner attribution alongside its evicted history so
			// the scoping map stays bounded with the history it guards.
			streamOwner.remove(victim);
		}
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
	///
	/// `ownerToken` scopes the request to the session that owns the target GET
	/// stream: the waiter is registered under it so only a response POSTed under
	/// the SAME session resolves it, and the request frame is delivered only on a
	/// listener whose `Listener.ownerToken` matches. The empty token preserves the
	/// stateless / shared path (any session, any listener), mirroring the unscoped
	/// `StreamCoordinator.Waiter` and `Listener`.
	Json sendRequest(string method, Json params = Json.emptyObject,
			Duration timeout = 60.seconds, string ownerToken = "") @safe
	{
		const id = coord.alloc();
		coord.register(id, ownerToken);
		// Bind the in-flight request to its target listener under the channel mutex
		// BEFORE the blocking write (passing `id` into `deliver`), not after it
		// returns. A listener disconnect that races the write is then seen by
		// `removeListenerLocked`'s scan, which fails this awaiter immediately rather
		// than stranding it for the full timeout.
		const listenerId = deliver(makeRequest(Json(id), method, params),
				(ref const Listener l) @safe => l.ownerToken == ownerToken, id);
		if (listenerId < 0)
		{
			coord.cancel(id);
			throw internalError(
					"No GET SSE listener connected to receive the server->client request");
		}
		scope (exit)
			() @trusted {
			synchronized (mtx)
				requestListener.remove(id);
		}();
		// Liveness defense-in-depth: even if a disconnect is somehow missed, polling
		// whether the bound listener is still connected releases the fiber within one
		// slice instead of the full timeout (mirrors the POST path's `awaitLive`).
		return coord.awaitLive(id, () @safe => isListenerLive(listenerId),
				internalError("GET SSE listener disconnected before the client responded"), timeout);
	}

	/// Initiate a `ping` toward the connected client(s) on the GET SSE push
	/// channel and block until one acknowledges with the spec-mandated empty
	/// result (basic/utilities/ping). This is the server-side counterpart to the
	/// client's `ping()`: it lets a server perform the SHOULD-periodic
	/// connection-health check the spec describes for either party. Throws on a
	/// client error, a timeout (treat as a stale connection), or when no GET
	/// listener is connected. The `ping` request carries no params, exactly as
	/// the spec requires. `ownerToken` scopes the probe to one session's GET
	/// stream (empty == the stateless / shared path); see `sendRequest`.
	void ping(Duration timeout = 60.seconds, string ownerToken = "") @safe
	{
		sendRequest("ping", Json.emptyObject, timeout, ownerToken);
	}

	/// Frame `msg` and write it to a single listener (identified by `listenerId`),
	/// rather than broadcasting to all. Used to deliver a per-stream leading event
	/// — e.g. the `notifications/subscriptions/acknowledged` the draft
	/// `subscriptions/listen` stream sends only to its own client. Returns true if
	/// the listener received it; false if the id is unknown or its write failed
	/// (in which case the listener is dropped).
	bool emitTo(long listenerId, Json msg) @safe
	{
		// Find the target under the lock (brief, non-blocking), then write off the
		// lock via the per-listener serialization point, exactly like `deliver`.
		// Serializing the write on `l.writeMtx` keeps this stream's seq ids monotonic
		// against a concurrent `deliver`/`emitTo` without holding the channel mutex
		// across the blocking write.
		Nullable!Listener target;
		() @trusted {
			synchronized (mtx)
			{
				foreach (l; listeners)
					if (l.id == listenerId && l.id in seqOf)
					{
						target = l;
						break;
					}
			}
		}();
		if (target.isNull)
			return false;
		return writeToListener(target.get, msg);
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

unittest  // resume is session-scoped: another session cannot replay a stream's history
{
	// A client must not be able to resume (and have replayed to it) another
	// session's buffered stream history by presenting that session's Last-Event-ID.
	// Session A emits an event (recording history under A's token); session B then
	// reconnects with A's event id but B's owner token. B MUST receive nothing and
	// be given a FRESH ordinal — no cross-session disclosure.
	import std.string : indexOf, startsWith;
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	string[] aFrames;
	const a = ch.addListener((string f) @safe { aFrames ~= f; }, "",
			SubscriptionFilter.init, "", null, "session-A");
	ch.notify("notifications/message", Json(["s": Json("secretA1")]));
	ch.notify("notifications/message", Json(["s": Json("secretA2")]));
	assert(aFrames.length == 2);
	const aId0 = aFrames[0]["id: ".length .. aFrames[0].indexOf("\n")];
	const aOrdinal = aId0[0 .. aId0.indexOf("-")];
	ch.removeListener(a); // A's connection breaks

	// Session B presents A's Last-Event-ID but B's own token: NO replay, and the
	// fresh ordinal it gets must NOT be A's ordinal.
	string[] bFrames;
	ch.addListener((string f) @safe { bFrames ~= f; }, "",
			SubscriptionFilter.init, aId0, null, "session-B");
	assert(bFrames.length == 0, "session B must not replay session A's history");

	// A subsequent event to B carries a fresh ordinal distinct from A's, confirming
	// B did not resume A's stream.
	string[] bLive;
	const b2 = ch.addListener((string f) @safe { bLive ~= f; }, "",
			SubscriptionFilter.init, aId0, null, "session-B");
	ch.emitTo(b2, makeNotification("notifications/message", Json([
		"s": Json("B")
	])));
	assert(bLive.length == 1);
	const bId0 = bLive[0]["id: ".length .. bLive[0].indexOf("\n")];
	assert(!bId0.startsWith(aOrdinal ~ "-"), "session B must get a fresh ordinal, not A's");
}

unittest  // an unscoped (empty-token) stream remains resumable by anyone (prior behaviour)
{
	// A stream owned by the empty token (stateless / shared mode, no session
	// attribution) keeps the prior resumable-by-anyone behaviour: a reconnect with
	// no owner token still replays the post-cursor events.
	import std.string : indexOf;
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	string[] first;
	const a = ch.addListener((string f) @safe { first ~= f; }); // empty owner token
	ch.notify("notifications/message", Json(["n": Json(1)]));
	ch.notify("notifications/message", Json(["n": Json(2)]));
	assert(first.length == 2);
	const idLine = first[0]["id: ".length .. first[0].indexOf("\n")];
	ch.removeListener(a);

	string[] resumed;
	ch.addListener((string f) @safe { resumed ~= f; }, "", SubscriptionFilter.init, idLine);
	assert(resumed.length == 1);
	assert(resumed[0].canFind("\"n\":2"));
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
	// B registers FIRST to confirm delivery follows the per-stream filter, not
	// registration order.
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

unittest  // emitFilteredPerOwner fans out to every distinct session, once each
{
	// A list_changed broadcast must reach EVERY connected session, but only one
	// stream per session. Two sessions (A, B) each with one plain GET stream: a
	// single emitFilteredPerOwner reaches both.
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	ch.addListener((string f) @safe { aFrame = f; }, "", SubscriptionFilter.init, "", null, "A");
	ch.addListener((string f) @safe { bFrame = f; }, "", SubscriptionFilter.init, "", null, "B");

	const delivered = ch.emitFilteredPerOwner("notifications/tools/list_changed", Json.undefined);
	assert(delivered == 2);
	assert(aFrame.canFind("notifications/tools/list_changed"));
	assert(bFrame.canFind("notifications/tools/list_changed"));
}

unittest  // emitFilteredPerOwner honours Multiple Connections within one session
{
	// Two GET streams of the SAME session: the broadcast lands on exactly one of
	// them (one stream per session), reaching the session once.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	int aCount, bCount;
	ch.addListener((string) @safe { aCount++; }, "", SubscriptionFilter.init, "", null, "S");
	ch.addListener((string) @safe { bCount++; }, "", SubscriptionFilter.init, "", null, "S");

	const delivered = ch.emitFilteredPerOwner("notifications/tools/list_changed", Json.undefined);
	assert(delivered == 1);
	assert(aCount + bCount == 1);
}

unittest  // emitFilteredPerOwner skips a session whose only stream is not eligible
{
	// A session whose active filter did not opt into the type must not be reached,
	// while a session that did is reached.
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	SubscriptionFilter fa;
	fa.active = true;
	fa.toolsListChanged = true;
	SubscriptionFilter fb;
	fb.active = true;
	fb.promptsListChanged = true; // not tools
	ch.addListener((string f) @safe { aFrame = f; }, "listen-A", fa, "", null, "A");
	ch.addListener((string f) @safe { bFrame = f; }, "listen-B", fb, "", null, "B");

	const delivered = ch.emitFilteredPerOwner("notifications/tools/list_changed", Json.undefined);
	assert(delivered == 1);
	assert(aFrame.canFind("notifications/tools/list_changed"));
	assert(bFrame.length == 0);
}

unittest  // connectedOwnerTokens lists distinct non-empty session tokens
{
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	ch.addListener((string) @safe {}, "", SubscriptionFilter.init, "", null, "A");
	ch.addListener((string) @safe {}, "", SubscriptionFilter.init, "", null, "A"); // dup token
	ch.addListener((string) @safe {}, "", SubscriptionFilter.init, "", null, "B");
	ch.addListener((string) @safe {}); // empty token excluded

	auto tokens = ch.connectedOwnerTokens();
	assert(tokens.length == 2);
	assert(tokens.canFind("A"));
	assert(tokens.canFind("B"));
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

unittest  // a per-listener plainEligible gate overrides the mount-wide plainEligible
{
	// Two plain GET streams (inactive filters) bound to DIFFERENT per-session
	// subscription gates: a `resources/updated` for a URI only session A
	// subscribed to must reach A and not B, regardless of the mount-wide flag.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	bool aGate(string method, string uri) @safe
	{
		return method != "notifications/resources/updated" || uri == "file:///a";
	}

	bool bGate(string method, string uri) @safe
	{
		return method != "notifications/resources/updated" || uri == "file:///b";
	}

	ch.addListener((string f) @safe { aFrame = f; }, "", SubscriptionFilter.init, "", &aGate);
	ch.addListener((string f) @safe { bFrame = f; }, "", SubscriptionFilter.init, "", &bGate);

	auto p = Json(["uri": Json("file:///a")]);
	// Mount-wide plainEligible is the default true; the per-listener gates decide.
	const delivered = ch.emitFiltered("notifications/resources/updated", p, "file:///a");
	import std.algorithm : canFind;

	assert(delivered == 1);
	assert(aFrame.canFind("file:///a"), "session A (subscribed) must receive its URI");
	assert(bFrame.length == 0, "session B (unsubscribed) must not receive A's update");
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

unittest  // a disconnect DURING the request write fails the awaiter, not after it
{
	// The request->listener binding must be committed before the
	// blocking write, so a listener that disconnects while the request frame is
	// being written is associated with the in-flight id and its awaiter is failed
	// immediately. Simulate the race: the listener's write callback removes the
	// listener (a mid-write disconnect). With the binding recorded up-front,
	// removeListenerLocked finds the id and fails the pending request.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	const id = coord.alloc();
	coord.register(id);

	long selfId;
	// The write delegate disconnects this very listener mid-write.
	selfId = ch.addListener((string) @safe { ch.removeListener(selfId); });

	// Deliver the request frame WITH the binding (as sendRequest now does). The
	// mid-write removeListener observes the binding and fails the pending id.
	const landed = ch.deliver(makeRequest(Json(id), "ping", Json.emptyObject),
			(ref const ServerPushChannel.Listener) @safe => true, id);
	// The single live candidate was tried; its write tore the connection down.
	assert(landed == selfId || landed < 0);

	// Because the binding was recorded before the blocking write, the mid-write
	// removeListenerLocked scan found the in-flight id and failed its waiter. The
	// waiter is now done+errored, so awaiting it returns immediately with the
	// disconnect McpException instead of parking for the full timeout.
	import mcp.protocol.errors : McpException;

	bool threw;
	try
		coord.await(id, 1.seconds);
	catch (McpException)
		threw = true;
	assert(threw, "a disconnect during the write must fail the awaiter, not strand it");
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
final class HttpStreamContext : RequestContext, ConnectionScoped
{
	private HTTPServerResponse res;
	private StreamCoordinator coord;
	private ClientCapabilities clientCaps;
	private Json progressTok;
	// Per-connection cancellation scope. On the Streamable HTTP
	// transport a request and its later `notifications/cancelled` arrive on
	// SEPARATE POSTs that share only the `Mcp-Session-Id` header, so the token
	// MUST be that session id when sessions are enabled -- a per-request UUID
	// would never match the cancellation's own context and would break
	// cancellation entirely. When sessions are disabled there is no identifier
	// shared across the two POSTs, so the empty (shared) token is kept and
	// cancellation is unscoped (documented on the transport).
	private string token_;
	// The per-session (stateful) / per-request (stateless) ConnectionState this
	// request is bound to. The transport resolves it — looked up by
	// `Mcp-Session-Id` for stateful, freshly built per request for stateless — and
	// hands it here so the server core dispatches against THIS request's state
	// rather than the single bound `activeConnection`. Null when the transport did
	// not resolve one (the server then falls back to `activeConnection`).
	private ConnectionState connState_;
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
	// When true, this context belongs to a `stateless` server over
	// the HTTP transport, so server->client requests (elicitation / sampling /
	// roots / any `sendRequest`) are STRUCTURALLY FORBIDDEN. They would have to
	// ride the mount-global `StreamCoordinator`/GET-push channel, which correlates
	// more than one HTTP call and is exactly the shared state a stateless server
	// must not keep. `sendRequest` therefore throws a clear `McpException` rather
	// than silently dropping. stdio uses a different context (`StdioContext`), so
	// server->client over stdio is unaffected by this gate in any mode.
	private bool serverStateless_;
	// Whether THIS request's `Accept` header admits `text/event-stream` (the
	// transport resolves it from the POST's Accept via `acceptsEventStream`). When
	// false the client provably cannot consume an SSE body, so an attempt to
	// upgrade this response to a stream (progress/log/server-initiated request) is
	// refused rather than emitting a stream the client declared it cannot read
	// (basic/transports §Sending Messages content negotiation). Defaults to true
	// so every existing caller (and the GET/listen paths) keep streaming.
	private bool acceptsEventStream_;
	// Set once `beginStream` has refused an SSE upgrade because the client's Accept
	// excludes `text/event-stream`. The transport reads it after `server.handle`
	// returns to surface a 406 Not Acceptable instead of the would-be SSE body.
	private bool streamRefused_;

	this(HTTPServerResponse res, StreamCoordinator coord, ClientCapabilities caps, Json progressToken,
			TokenInfo auth = TokenInfo.invalid(),
			bool isDraft = false, ProtocolVersion negotiated = latestStable,
			string connectionToken = "",
			ConnectionState connState = null,
			bool serverStateless = false, bool acceptsEventStream = true) @safe
	{
		this.res = res;
		this.coord = coord;
		this.clientCaps = caps;
		this.progressTok = progressToken;
		this.streamId = coord.allocStream();
		this.authInfo = auth;
		this.isDraft_ = isDraft;
		this.version_ = negotiated;
		this.token_ = connectionToken;
		this.connState_ = connState;
		this.serverStateless_ = serverStateless;
		this.acceptsEventStream_ = acceptsEventStream;
		this.connAlive_ = () @safe => res.connected;
	}

	/// Whether an SSE upgrade was refused for this request because the client's
	/// `Accept` provably excludes `text/event-stream`. The transport surfaces this
	/// as a 406 Not Acceptable after dispatch (see `streamable_http.handlePost`).
	bool streamRefused() const @safe
	{
		return streamRefused_;
	}

	/// The per-connection cancellation scope for this request. This is
	/// the `Mcp-Session-Id` when stateful sessions are enabled, so a request and its
	/// later `notifications/cancelled` -- which arrive on SEPARATE POSTs sharing only
	/// that header -- resolve to the SAME `RequestScope` cancellation key. When
	/// sessions are disabled there is no shared identifier across the two POSTs, so
	/// the empty (shared) token is returned and bare-id cancellation is unscoped.
	string connectionToken() @safe
	{
		return token_;
	}

	/// The per-session/per-request `ConnectionState` the transport resolved for
	/// this request: the `SessionManager`-owned state for stateful
	/// HTTP, or the fresh transient state for stateless HTTP. Null when none was
	/// supplied, in which case the server core falls back to `activeConnection`.
	ConnectionState connectionState() @safe
	{
		return connState_;
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
		// Content negotiation (basic/transports §Sending Messages): if the client's
		// Accept provably excludes text/event-stream, do not upgrade to an SSE body
		// it declared it cannot read. Flag the refusal (the transport turns it into a
		// 406 Not Acceptable) and abort the stream before any header/body is written.
		if (!acceptsEventStream_)
		{
			streamRefused_ = true;
			throw invalidRequest(
					"client Accept header does not admit text/event-stream; cannot stream this response");
		}
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
		// `message` was introduced in 2025-03-26; suppress it for a 2024-11-05
		// peer whose ProgressNotification schema has no such field.
		if (message.length && version_.supportsProgressMessage)
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

	Json sampleRaw(Json params) @safe
	{
		return serverRequest("sampling/createMessage", params);
	}

	Json elicitRaw(Json params) @safe
	{
		return serverRequest("elicitation/create", params);
	}

	Json listRootsRaw() @safe
	{
		return serverRequest("roots/list", Json.emptyObject);
	}

	private Json serverRequest(string method, Json params) @safe
	{
		// A stateless server has NO shared state across HTTP calls.
		// A server->client request (elicitation / sampling / roots / any
		// sendRequest) would block on the mount-global StreamCoordinator and ride
		// the GET-push channel — both shared across HTTP calls — so it is
		// structurally forbidden in stateless mode. Fail loudly rather than hang or
		// silently drop. Use McpServer.stateful() to enable it (keys all per-peer
		// state on Mcp-Session-Id). stdio is a single implicit connection and is
		// unaffected (it uses StdioContext, not this class).
		if (serverStateless_)
			throw invalidRequest("server-initiated requests (elicitation/sampling/roots) require a stateful server; construct with McpServer.stateful()");
		const id = coord.alloc();
		// Bind the outbound id to this request's session token so only a response
		// arriving on the same session can resolve it.
		coord.register(id, token_);
		// A failed SSE write (broken pipe on the priming-event or request frame)
		// must deregister the waiter before propagating, otherwise the mount-global
		// coordinator retains a pending entry for the life of the mount.
		try
			writeEvent(makeRequest(Json(id), method, params));
		catch (Exception e)
		{
			coord.cancel(id);
			throw e;
		}
		// Bind the awaiting fiber to this connection's liveness. The response to
		// this server->client request arrives on a SEPARATE POST, so a disconnect of
		// the issuing connection would otherwise leave this fiber parked for the
		// full timeout. Polling `connAlive_` in short slices releases it promptly on
		// disconnect, mirroring the GET path's listener-disconnect handling.
		return coord.awaitLive(id, connAlive_,
				internalError("client disconnected before responding"));
	}

	bool clientSupports(ClientCapability cap) @safe
	{
		return clientCaps.supports(cap);
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

unittest  // a session-scoped push sendRequest is delivered only on the owning session's listener
{
	// Two GET listeners A and B own distinct sessions. A server->client request
	// scoped to session A must land on A's stream, never B's, so B never even sees
	// the request frame it could otherwise answer.
	import std.algorithm : canFind;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	string aFrame, bFrame;
	ch.addListener((string f) @safe { aFrame = f; }, "",
			SubscriptionFilter.init, "", null, "sess-A");
	ch.addListener((string f) @safe { bFrame = f; }, "",
			SubscriptionFilter.init, "", null, "sess-B");

	// Deliver the scoped request frame exactly as sendRequest does (eligibility
	// keyed on the owning token) without blocking on a reply.
	const id = coord.alloc();
	coord.register(id, "sess-A");
	const landed = ch.deliver(makeRequest(Json(id), "ping", Json.emptyObject),
			(ref const ServerPushChannel.Listener l) @safe => l.ownerToken == "sess-A", id);
	assert(landed >= 0, "the scoped request must land on session A's listener");
	assert(aFrame.canFind("\"method\":\"ping\""), "session A's stream must receive the request");
	assert(bFrame.length == 0, "session B's stream must NOT receive a request it does not own");
}

unittest  // a different session's response cannot resolve a push sendRequest waiter
{
	// A server->client request issued on the GET push channel scoped to session A
	// registers its waiter under sess-A. A response POSTed under session B must NOT
	// resolve it -- the same cross-session hijack the POST path already closes.
	auto coord = new StreamCoordinator;
	const id = coord.alloc();
	coord.register(id, "sess-A");
	assert(!coord.resolve(Json(id), Json.emptyObject, Json.undefined, "sess-B"),
			"a session-B response wrongly resolved session A's GET-stream waiter");
	assert(coord.resolve(Json(id), Json.emptyObject, Json.undefined, "sess-A"),
			"the owning session's response must resolve its own GET-stream waiter");
}

unittest  // failPending wakes a single awaiter promptly with an McpException
{
	// Register a waiter, fail just that id, and confirm await throws immediately
	// instead of hanging to the 60s timeout.
	import mcp.protocol.errors : McpException, ErrorCode;

	auto c = new StreamCoordinator;
	const id = c.alloc();
	c.register(id);
	c.failPending(id, internalError("listener disconnected"));
	bool threw;
	try
		c.await(id);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}

unittest  // a response from a different session must not resolve another session's pending request
{
	// Session A issues a server->client request (id 1) bound to its own token.
	// A response carrying id 1 but POSTed by session B must NOT resolve A's
	// waiter: cross-session resolution would let B hijack A's elicitation/sampling.
	auto c = new StreamCoordinator;
	const id = c.alloc();
	c.register(id, "sess-A");
	const matched = c.resolve(Json(id), Json.emptyObject, Json.undefined, "sess-B");
	assert(!matched, "a response from session B wrongly resolved session A's request");
}

unittest  // a response from the owning session resolves the pending request
{
	// The owning session's reply (same token) resolves its own waiter.
	import vibe.core.core : runTask, exitEventLoop, runEventLoop;

	auto c = new StreamCoordinator;
	const id = c.alloc();
	c.register(id, "sess-A");
	bool matched;
	bool awaited;
	runTask(() @safe nothrow{
		Json r;
		try
			r = c.await(id);
		catch (Exception)
			assert(false, "await threw");
		awaited = r.type == Json.Type.object;
		exitEventLoop();
	});
	runTask(() @safe nothrow{
		try
			matched = c.resolve(Json(id), Json.emptyObject, Json.undefined, "sess-A");
		catch (Exception)
			assert(false, "resolve threw");
	});
	runEventLoop();
	assert(matched, "the owning session's response must resolve its own request");
	assert(awaited);
}

unittest  // an unscoped (stateless) waiter is resolvable by any responder
{
	// A waiter registered with an empty owner token (stateless / shared mode)
	// preserves prior behavior: any responder token, including empty, matches.
	auto c = new StreamCoordinator;
	const id = c.alloc();
	c.register(id);
	const matched = c.resolve(Json(id), Json.emptyObject, Json.undefined, "anyone");
	assert(matched, "an unscoped waiter must remain resolvable regardless of responder token");
}

unittest  // a server->client request fails fast when its bound listener disconnects
{
	// sendRequest delivers the request frame on a chosen GET listener and blocks in
	// await. If THAT listener disconnects (removeListener) before the client
	// responds, the awaiter must wake promptly with an McpException rather than
	// hanging for the full timeout.
	import mcp.protocol.errors : McpException;
	import vibe.core.core : runTask, exitEventLoop, runEventLoop;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);
	long lid;
	lid = ch.addListener((string) @safe {}); // captures the request frame, never replies

	bool failedFast;
	void delegate() @safe nothrow initiator = () @safe nothrow{
		try
			ch.sendRequest("ping");
		catch (McpException)
			failedFast = true;
		catch (Exception)
		{
		}
		exitEventLoop();
	};
	void delegate() @safe nothrow disconnector = () @safe nothrow{
		// Simulate the GET stream dropping after the request was delivered onto it.
		try
			ch.removeListener(lid);
		catch (Exception)
			assert(false, "removeListener threw");
	};
	runTask(initiator);
	runTask(disconnector);
	runEventLoop();
	assert(failedFast);
}

unittest  // a slow stream's write must not block delivery to a different stream
{
	// With per-listener write serialization off the channel mutex, a slow write on
	// stream X must NOT delay a concurrent delivery to stream Y. Two listeners: X's
	// write blocks until released; Y's write is instant. Deliver to X and Y
	// concurrently and assert Y finishes BEFORE X — impossible if both serialized on
	// one channel mutex held across the write. Synchronization is event-based (no
	// sleeps), so the head-of-line condition is exercised deterministically.
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.core.sync : createManualEvent;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	int order;
	int slowDoneAt = -1, fastDoneAt = -1;
	auto slowStarted = createManualEvent();
	auto slowRelease = createManualEvent();
	const startEc = slowStarted.emitCount;
	const releaseEc = slowRelease.emitCount;

	// Slow listener: announce its write is in progress, then block until released.
	const slow = ch.addListener((string) @safe {
		() @trusted { slowStarted.emit(); slowRelease.wait(releaseEc); }();
	});
	// Fast listener: completes immediately.
	const fast = ch.addListener((string) @safe {});

	runTask(() nothrow{
		try
		{
			auto tSlow = runTask(() nothrow{
				try
				{
					ch.emitTo(slow, makeNotification("notifications/message",
					Json(["s": Json("slow")])));
					slowDoneAt = ++order;
				}
				catch (Exception)
				{
				}
			});
			// Wait until the slow write is actually in progress (blocked) — no timing
			// guesswork.
			() @trusted { slowStarted.wait(startEc); }();
			auto tFast = runTask(() nothrow{
				try
				{
					ch.emitTo(fast, makeNotification("notifications/message",
					Json(["s": Json("fast")])));
					fastDoneAt = ++order;
				}
				catch (Exception)
				{
				}
			});
			// The fast delivery completed while the slow write is still blocked; now
			// release the slow write and let it finish.
			tFast.join();
			() @trusted { slowRelease.emit(); }();
			tSlow.join();
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();

	assert(fastDoneAt > 0 && slowDoneAt > 0, "both deliveries must complete");
	// The fast stream completed first even though the slow stream started first and
	// was mid-write: the channel mutex is not held across the blocking write.
	assert(fastDoneAt < slowDoneAt,
			"a slow stream's write blocked a concurrent delivery to a different stream");
}

unittest  // concurrent emits to ONE stream keep per-stream seq ids monotonic
{
	// Per-stream event ids are monotonic and gap-free in WRITE order. With writes
	// off the channel mutex, two concurrent emits to the SAME listener could
	// otherwise reserve seqs and write out of order. The per-listener write mutex
	// serializes seq read + write + seq commit, so whichever write reaches the
	// socket first carries the lower seq. Fire many concurrent emits at one listener
	// and assert the captured event ids are exactly 0,1,2,... in the order the
	// frames were written.
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
	import core.time : msecs;
	import std.string : indexOf, splitLines;
	import std.conv : to;
	import std.algorithm : map;
	import std.array : array;

	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	string[] frames;
	// A write that yields mid-frame, so without per-listener serialization a second
	// emit could interleave its seq assignment and write between the two halves.
	const lid = ch.addListener((string f) @safe {
		sleep(2.msecs); // yield while "writing"
		frames ~= f;
	});

	enum N = 8;
	runTask(() nothrow{
		import vibe.core.task : Task;

		try
		{
			Task[] tasks;
			foreach (i; 0 .. N)
			{
				auto t = runTask((int n) nothrow{
					try
						ch.emitTo(lid, makeNotification("notifications/message",
						Json(["n": Json(n)])));
					catch (Exception)
					{
					}
				}, i);
				tasks ~= t;
			}
			foreach (t; tasks)
				t.join();
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();

	assert(frames.length == N, "every emit reached the single stream");
	// Parse the seq half of each "id: <ordinal>-<seq>" line in write order: it must
	// be 0,1,2,...,N-1 — strictly monotonic and gap-free.
	auto seqs = frames.map!((f) {
		const idLine = f[0 .. f.indexOf("\n")];
		const dash = idLine.indexOf("-");
		return idLine[dash + 1 .. $].to!long;
	}).array;
	foreach (i, s; seqs)
		assert(s == cast(long) i,
				"per-stream seq ids reordered under concurrent emits: " ~ seqs.to!string);
}

unittest  // history retains at most maxHistoryStreams ordinals (bounded memory)
{
	// Each plain GET stream that delivers an event records its own ordinal's
	// history. Over many short-lived streams the total retained ordinals must stay
	// bounded by the LRU cap, never growing without limit across the mount lifetime.
	auto coord = new StreamCoordinator;
	auto ch = new ServerPushChannel(coord);

	// Drive far more streams than the cap, each emitting one event then dropping.
	foreach (i; 0 .. 200)
	{
		const id = ch.addListener((string) @safe {});
		ch.notify("notifications/message");
		ch.removeListener(id);
	}
	// The retained history must not grow to one-ordinal-per-stream; it is capped.
	assert(ch.retainedHistoryStreams() <= 64);
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

unittest  // HttpStreamContext exposes its per-connection token via ConnectionScoped
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;

	// With a session id supplied (stateful HTTP), the context's connectionToken IS
	// the Mcp-Session-Id, so connectionTokenOf scopes the cancellation registry per
	// session rather than collapsing every connection onto the shared "" key.
	auto scoped = new HttpStreamContext(res, coord, caps, Json.undefined,
			TokenInfo.invalid(), false, latestStable, "sess-XYZ");
	assert(cast(ConnectionScoped) scoped !is null,
			"HttpStreamContext must implement ConnectionScoped");
	assert(scoped.connectionToken() == "sess-XYZ");
	assert(connectionTokenOf(scoped) == "sess-XYZ");

	// Stateless (sessions disabled): the empty shared token, documented as unscoped.
	auto unscoped = new HttpStreamContext(res, coord, caps, Json.undefined);
	assert(unscoped.connectionToken() == "");
}

unittest  // a cancellation scoped to session B must not suppress session A's same-id request
{
	// This exercises the REAL transport context (HttpStreamContext): two Streamable
	// HTTP sessions A and B share one McpServer and both have an in-flight request
	// id 1. A `notifications/cancelled` for id 1 carried on a session-B-scoped
	// context must only flip B's in-flight key -- A's must survive.
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;
	import mcp.server.server : McpServer;
	import mcp.protocol.jsonrpc : makeNotification, makeRequest;
	import mcp.protocol.types : Tool, CallToolResult, Content;

	auto sinkA = createMemoryOutputStream();
	auto resA = createTestHTTPServerResponse(sinkA, null, TestHTTPResponseMode.bodyOnly);
	auto sinkB = createMemoryOutputStream();
	auto resB = createTestHTTPServerResponse(sinkB, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;

	auto s = new McpServer("t", "1");
	// Build the cancellation context for session B exactly as the transport does:
	// an HttpStreamContext carrying session B's token.
	auto ctxB = new HttpStreamContext(resB, coord, caps, Json.undefined,
			TokenInfo.invalid(), false, latestStable, "sess-B");

	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		// While request id 1 runs on session A, a cancellation for id 1 arrives on
		// session B. With per-connection keying via connectionToken this MUST NOT
		// flip A's token.
		Json p = Json.emptyObject;
		p["requestId"] = 1;
		s.handle(Message(makeNotification("notifications/cancelled", p)), ctxB);
		assert(!ctx.isCancelled, "a cancellation on session B wrongly cancelled session A");
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	Json callP = Json.emptyObject;
	callP["name"] = "slow";
	auto ctxA = new HttpStreamContext(resA, coord, caps, Json.undefined,
			TokenInfo.invalid(), false, latestStable, "sess-A");
	auto resp = s.handle(Message(makeRequest(Json(1), "tools/call", callP)), ctxA);
	// A's response is delivered (not suppressed): cancellation matched only B.
	assert(!resp.isNull);
}

unittest  // a stateless HttpStreamContext FORBIDS server->client requests
{
	// A stateless server keeps no shared state across HTTP calls, so a handler
	// calling ctx.elicit/ctx.sample (any sendRequest) over the HTTP transport must
	// ERROR with the stateless message rather than block on the mount-global
	// coordinator. The tool-call returns an error result (not a hang).
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;
	import mcp.server.server : McpServer;
	import mcp.protocol.jsonrpc : makeRequest;
	import mcp.protocol.types : Tool, CallToolResult, Content;
	import mcp.protocol.errors : McpException;
	import std.algorithm : canFind;

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;
	caps.elicitation = true;
	caps.elicitationForm = true; // client supports form-mode (so the gate is the only block)

	auto s = McpServer.stateless("t", "1");
	bool sawStatelessError;
	Tool ask = {name: "ask"};
	s.registerDynamicTool(ask, (Json args, RequestContext ctx) @safe {
		try
		{
			ctx.elicit("hi", Json.emptyObject);
			assert(false, "elicit() must throw on a stateless HTTP server");
		}
		catch (McpException e)
		{
			sawStatelessError = true;
			assert(e.msg.canFind("stateful"),
				"the stateless gate message must point at McpServer.stateful(): " ~ e.msg);
			CallToolResult r;
			r.content = [Content.makeText("blocked: " ~ e.msg)];
			r.isError = true;
			return r;
		}
	});

	// Construct the context exactly as the stateless HTTP transport does: serverStateless = true.
	auto ctx = new HttpStreamContext(res, coord, caps, Json.undefined,
			TokenInfo.invalid(), false, latestStable, "", null, true);
	Json callP = Json.emptyObject;
	callP["name"] = "ask";
	auto resp = s.handle(Message(makeRequest(Json(1), "tools/call", callP)), ctx);
	assert(sawStatelessError, "the handler's elicit() did not hit the stateless gate");
	assert(!resp.isNull);
	// The tool-call returns an error result rather than hanging.
	assert(resp.get["result"]["isError"].get!bool);
}

unittest  // a stateful HttpStreamContext does NOT gate sendRequest
{
	// The counterpart to the stateless gate: a stateful server (serverStateless =
	// false) leaves sendRequest enabled, so the elicit reaches the coordinator and
	// blocks awaiting the client's reply (it does NOT throw the stateless message).
	// We confirm it is not the stateless gate by checking the elicit does not throw
	// invalidRequest with the stateful-pointer message before any client response.
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.stream.memory : createMemoryOutputStream;
	import vibe.core.core : runTask, exitEventLoop, runEventLoop;
	import mcp.protocol.errors : McpException, ErrorCode;
	import std.algorithm : canFind;

	auto sink = createMemoryOutputStream();
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;
	// serverStateless = false (default): the gate is OFF.
	auto ctx = new HttpStreamContext(res, coord, caps, Json.undefined);

	bool gated;
	void delegate() @safe nothrow initiator = () @safe nothrow{
		try
			ctx.elicitRaw(Json.emptyObject);
		catch (McpException e)
		{
			// A stateful context never throws the stateless-pointer message. It may
			// (here) eventually time out awaiting a reply, which is a DIFFERENT error.
			if (e.msg.canFind("require a stateful server"))
				gated = true;
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	};
	// Resolve the in-flight request id quickly so the initiator does not block for
	// the full timeout (the request frame was written to the SSE stream).
	void delegate() @safe nothrow responder = () @safe nothrow{
		try
			coord.resolve(Json(1), Json.emptyObject, Json.undefined);
		catch (Exception)
		{
		}
	};
	runTask(initiator);
	runTask(responder);
	runEventLoop();
	assert(!gated, "a stateful HttpStreamContext must NOT apply the stateless server->client gate");
}

unittest  // a failed SSE write in sendRequest deregisters the coordinator waiter
{
	import vibe.http.server : createTestHTTPServerResponse, TestHTTPResponseMode;
	import vibe.core.stream : OutputStream, IOMode;

	// A sink whose write/flush always throws, simulating a broken pipe mid-frame.
	static final class ThrowingSink : OutputStream
	{
		size_t write(scope const(ubyte)[], IOMode) @safe
		{
			throw new Exception("broken pipe");
		}

		void flush() @safe
		{
			throw new Exception("broken pipe");
		}

		void finalize() @safe
		{
		}
	}

	auto sink = new ThrowingSink;
	auto res = createTestHTTPServerResponse(sink, null, TestHTTPResponseMode.bodyOnly);
	auto coord = new StreamCoordinator;
	ClientCapabilities caps;
	auto ctx = new HttpStreamContext(res, coord, caps, Json.undefined);

	bool threw;
	try
		ctx.elicitRaw(Json.emptyObject);
	catch (Exception)
		threw = true;
	assert(threw, "a broken-pipe SSE write must propagate out of sendRequest");

	// No waiter may survive the failed write: a later resolve for any plausible id
	// returns false, proving the coordinator table holds no leaked entry.
	foreach (long id; 1 .. 1000)
		assert(!coord.resolve(Json(id), Json.emptyObject, Json.undefined),
				"the waiter registered before the failed write must have been removed");
}
