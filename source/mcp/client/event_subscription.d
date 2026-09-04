/// A mode-neutral handle to one managed event subscription. The same type is
/// returned by `McpClient.subscribePoll`, `subscribeStream`, and
/// `subscribeWebhook` — the SDK owns the delivery loop (poll cadence, stream
/// demux, or webhook TTL refresh) and the caller holds this handle to observe the
/// watermark, liveness, and to tear the subscription down.
module mcp.client.event_subscription;

import std.typecons : Nullable;

import mcp.protocol.events : DeliveryMode;

@safe:

/// One active managed event subscription, independent of delivery mode. Lives on
/// a single vibe fiber under the cooperative scheduler, so the plain flags need no
/// synchronization. The factory wires the teardown; the loop/stream updates the
/// cursor and terminal state through the package seams.
final class EventSubscription
{
	private bool cancelled_;
	private bool terminated_;
	private DeliveryMode mode_;
	private Nullable!string cursor_;
	private void delegate() @safe nothrow teardown_;
	// Bounded `eventId` memory for deduplication: a fixed ring of the most recent
	// ids plus a set for O(1) lookup. When the ring wraps, the id it overwrites is
	// forgotten. A zero capacity disables deduplication.
	private bool[string] seen_;
	private string[] seenRing_;
	private size_t seenHead_;

	/// The latest safe-to-persist watermark seen on this subscription — from a poll
	/// result, a delivered occurrence, or an `active`/`heartbeat`/`gap` control.
	/// Null until the first non-null cursor is observed. Persist it to resume later.
	Nullable!string cursor() @safe
	{
		return cursor_;
	}

	/// The delivery mode this subscription runs on.
	DeliveryMode mode() @safe
	{
		return mode_;
	}

	/// True until `cancel()` is called or a terminal `terminated` control ends the
	/// subscription. Once false it never goes true again.
	bool active() @safe
	{
		return !cancelled_ && !terminated_;
	}

	/// Idempotently stop the subscription: ends the poll loop, closes the push
	/// stream (deregistering its handlers), or unsubscribes the webhook and stops
	/// its refresh loop — whichever the factory wired.
	void cancel() @safe
	{
		if (cancelled_)
			return;
		cancelled_ = true;
		if (teardown_ !is null)
			teardown_();
	}

	// --- factory/loop seams (package-visible) ------------------------------

	/// Size the dedup window: how many recent `eventId`s this subscription
	/// remembers. Zero disables deduplication.
	package void dedupCapacity(size_t cap) @safe
	{
		seenRing_ = new string[](cap);
		seenHead_ = 0;
		seen_ = null;
	}

	/// Whether `eventId` was already delivered on this subscription. A new id is
	/// recorded (evicting the oldest once the window is full). An empty id is never
	/// a duplicate — there is nothing to match on.
	package bool alreadySeen(string eventId) @safe
	{
		if (eventId.length == 0 || seenRing_.length == 0)
			return false;
		if ((eventId in seen_) !is null)
			return true;
		const evicted = seenRing_[seenHead_];
		if (evicted.length)
			seen_.remove(evicted);
		seenRing_[seenHead_] = eventId;
		seenHead_ = (seenHead_ + 1) % seenRing_.length;
		seen_[eventId] = true;
		return false;
	}

	/// Record the delivery mode the factory chose.
	package void setMode(DeliveryMode m) @safe
	{
		mode_ = m;
	}

	/// Advance the watermark, ignoring a null (a null cursor never regresses it).
	package void advanceCursor(Nullable!string c) @safe
	{
		if (!c.isNull)
			cursor_ = c;
	}

	/// Mark the subscription ended by a `terminated` control (no more occurrences).
	package void markTerminated() @safe
	{
		terminated_ = true;
	}

	/// Whether `cancel()` has been called — the loop/refresh task polls this to exit.
	package bool isCancelled() @safe
	{
		return cancelled_;
	}

	/// Wire the idempotent teardown action invoked once on the first `cancel()`.
	package void onTeardown(void delegate() @safe nothrow t) @safe
	{
		teardown_ = t;
	}
}

unittest  // cursor advances only on a non-null value
{
	auto s = new EventSubscription();
	assert(s.cursor.isNull);
	s.advanceCursor(Nullable!string.init);
	assert(s.cursor.isNull);
	s.advanceCursor(Nullable!string("c1"));
	assert(s.cursor.get == "c1");
	s.advanceCursor(Nullable!string.init);
	assert(s.cursor.get == "c1"); // null never regresses the watermark
}

unittest  // cancel is idempotent and runs the teardown exactly once
{
	auto s = new EventSubscription();
	int n;
	s.onTeardown(() @safe nothrow{ n++; });
	assert(s.active);
	s.cancel();
	s.cancel();
	assert(!s.active);
	assert(n == 1);
}

unittest  // alreadySeen reports a repeated eventId and ignores empty ids
{
	auto s = new EventSubscription();
	s.dedupCapacity(8);
	assert(!s.alreadySeen("e1"));
	assert(s.alreadySeen("e1"));
	assert(!s.alreadySeen(""));
	assert(!s.alreadySeen(""));
}

unittest  // the dedup window forgets the oldest id once it wraps
{
	auto s = new EventSubscription();
	s.dedupCapacity(2);
	assert(!s.alreadySeen("a"));
	assert(!s.alreadySeen("b"));
	assert(!s.alreadySeen("c")); // evicts "a"
	assert(!s.alreadySeen("a")); // forgotten, so delivered again
	assert(s.alreadySeen("c"));
}

unittest  // a zero dedup capacity disables deduplication
{
	auto s = new EventSubscription();
	assert(!s.alreadySeen("e1"));
	assert(!s.alreadySeen("e1"));
}

unittest  // a terminated control ends the subscription without a cancel
{
	auto s = new EventSubscription();
	s.markTerminated();
	assert(!s.active);
}
