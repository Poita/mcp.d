/// A mode-neutral handle to one managed event subscription. The same type is
/// returned by `McpClient.subscribePoll`, `subscribeStream`, and
/// `subscribeWebhook` — the SDK owns the delivery loop (poll cadence, stream
/// demux, or webhook TTL refresh) and the caller holds this handle to observe the
/// watermark, liveness, and to tear the subscription down.
module mcp.client.event_subscription;

import core.time : Duration;
import std.typecons : Nullable;

import vibe.core.sync : LocalManualEvent, createManualEvent;

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
	private void delegate() @safe nothrow onEnd_;
	// Bounded `eventId` memory for deduplication: a fixed ring of the most recent
	// ids plus a set for O(1) lookup. When the ring wraps, the id it overwrites is
	// forgotten. A zero capacity disables deduplication.
	private bool[string] seen_;
	private string[] seenRing_;
	private size_t seenHead_;
	// Emitted when the subscription stops, waking a loop parked in `sleepWhileActive`.
	private LocalManualEvent stopped_;
	private bool stoppedInit_;

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
		wakeSleepers();
		if (teardown_ !is null)
			teardown_();
	}

	/// Park the calling task for up to `d`, returning early once the subscription
	/// is cancelled or terminated, so a delivery loop never sleeps out a long
	/// server-chosen interval after it has been stopped.
	package void sleepWhileActive(Duration d) @safe
	{
		if (!active || d <= Duration.zero)
			return;
		if (!stoppedInit_)
		{
			stopped_ = createManualEvent();
			stoppedInit_ = true;
		}
		const ec = stopped_.emitCount;
		stopped_.wait(d, ec);
	}

	private void wakeSleepers() @safe nothrow
	{
		if (stoppedInit_)
			stopped_.emit();
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

	/// Whether `eventId` is in the dedup window, without recording it. An empty
	/// id is never a duplicate — there is nothing to match on.
	package bool isSeen(string eventId) @safe
	{
		return eventId.length && (eventId in seen_) !is null;
	}

	/// Record `eventId` as delivered (evicting the oldest once the window is
	/// full). A no-op for an empty id, a disabled window, or an id already held.
	package void markSeen(string eventId) @safe
	{
		if (eventId.length == 0 || seenRing_.length == 0 || isSeen(eventId))
			return;
		const evicted = seenRing_[seenHead_];
		if (evicted.length)
			seen_.remove(evicted);
		seenRing_[seenHead_] = eventId;
		seenHead_ = (seenHead_ + 1) % seenRing_.length;
		seen_[eventId] = true;
	}

	/// Record the delivery mode the factory chose.
	package void setMode(DeliveryMode m) @safe
	{
		mode_ = m;
	}

	/// Advance the watermark, ignoring a null or empty cursor (neither names a
	/// position, so neither regresses it).
	package void advanceCursor(Nullable!string c) @safe
	{
		if (!c.isNull && c.get.length)
			cursor_ = c;
	}

	/// Mark the subscription ended by the server (a `terminated` control, or a
	/// failure that ends it): no more occurrences. Runs the `onEnd` release once.
	package void markTerminated() @safe
	{
		if (terminated_)
			return;
		terminated_ = true;
		wakeSleepers();
		if (!cancelled_ && onEnd_ !is null)
			onEnd_();
	}

	/// Wire the release of delivery resources (stream, receiver registration) run
	/// once when the server ends the subscription; `cancel()` runs the teardown
	/// instead.
	package void onEnd(void delegate() @safe nothrow e) @safe
	{
		onEnd_ = e;
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

unittest  // an empty cursor is never adopted as the watermark
{
	auto s = new EventSubscription();
	s.advanceCursor(Nullable!string("c1"));
	s.advanceCursor(Nullable!string(""));
	assert(s.cursor.get == "c1");
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

unittest  // isSeen reports a marked eventId and ignores empty ids
{
	auto s = new EventSubscription();
	s.dedupCapacity(8);
	assert(!s.isSeen("e1"));
	s.markSeen("e1");
	assert(s.isSeen("e1"));
	s.markSeen("");
	assert(!s.isSeen(""));
}

unittest  // the dedup window forgets the oldest id once it wraps
{
	auto s = new EventSubscription();
	s.dedupCapacity(2);
	s.markSeen("a");
	s.markSeen("b");
	s.markSeen("c"); // evicts "a"
	assert(!s.isSeen("a")); // forgotten, so delivered again
	assert(s.isSeen("b"));
	assert(s.isSeen("c"));
}

unittest  // a zero dedup capacity disables deduplication
{
	auto s = new EventSubscription();
	s.markSeen("e1");
	assert(!s.isSeen("e1"));
}

unittest  // a terminated control ends the subscription without a cancel
{
	auto s = new EventSubscription();
	s.markTerminated();
	assert(!s.active);
}
