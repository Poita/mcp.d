/// A mode-neutral handle to one managed event subscription. The same type is
/// returned by `McpClient.subscribePoll`, `subscribeStream`, and
/// `subscribeWebhook` — the SDK owns the delivery loop (poll cadence, stream
/// demux, or webhook TTL refresh) and the caller holds this handle to observe the
/// watermark, liveness, and to tear the subscription down.
module mcp.client.event_subscription;

import std.typecons : Nullable;

@safe:

/// One active managed event subscription, independent of delivery mode. Lives on
/// a single vibe fiber under the cooperative scheduler, so the plain flags need no
/// synchronization. The factory wires the teardown; the loop/stream updates the
/// cursor and terminal state through the package seams.
final class EventSubscription
{
	private bool cancelled_;
	private bool terminated_;
	private Nullable!string cursor_;
	private void delegate() @safe nothrow teardown_;

	/// The latest safe-to-persist watermark seen on this subscription — from a poll
	/// result, a delivered occurrence, or an `active`/`heartbeat`/`gap` control.
	/// Null until the first non-null cursor is observed. Persist it to resume later.
	Nullable!string cursor() @safe
	{
		return cursor_;
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

unittest  // a terminated control ends the subscription without a cancel
{
	auto s = new EventSubscription();
	s.markTerminated();
	assert(!s.active);
}
