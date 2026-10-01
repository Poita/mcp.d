module mcp.client.subscription;

import core.atomic : atomicLoad, cas;

import mcp.protocol.errors : McpException;

/// The set of change-notification types a modern client opts into when opening a
/// `subscriptions/listen` stream (2026-07-28 basic/utilities/subscriptions). The three
/// list-changed booleans request `notifications/tools|prompts|resources/list_changed`;
/// `resourceSubscriptions` lists the resource URIs the client wants
/// `notifications/resources/updated` for. This is serialised under
/// `params.notifications` (a `SubscriptionFilter`) by `subscriptionsListen`.
struct SubscriptionFilter
{
	/// Opt into `notifications/tools/list_changed`.
	bool toolsListChanged;
	/// Opt into `notifications/prompts/list_changed`.
	bool promptsListChanged;
	/// Opt into `notifications/resources/list_changed`.
	bool resourcesListChanged;
	/// Resource URIs to receive `notifications/resources/updated` for.
	string[] resourceSubscriptions;
}

/// A handle to an open `subscriptions/listen` stream. The stream runs on a
/// background task, dispatching the leading
/// `notifications/subscriptions/acknowledged` and every subsequent opted-in
/// change notification to the client's `onNotification` (and `onProgress`).
/// Call `cancel()` (alias `close()`) to stop listening; the background task then
/// closes the connection and terminates. When the server ends the stream instead —
/// closing it, answering the listen request, or failing it with an error — `ended`
/// turns true and `error` carries the failure, if any.
final class SubscriptionStream
{
	private shared(bool)* cancelled_;
	// Set by the transport when the server ends the stream (the stream's reader
	// runs on the owning thread's event loop, so no synchronization is needed).
	private bool finished_;
	private McpException error_;
	// Optional transport-supplied action run exactly once on the first cancel().
	// The stdio transport uses it to emit `notifications/cancelled` referencing
	// the listen request id (2026-07-28 basic/utilities/subscriptions Cancellation,
	// stdio); the HTTP transport uses it to force-close the listen stream's socket
	// so a blocked read unblocks immediately.
	private void delegate() @safe nothrow onCancel_;
	// Optional client-supplied cleanup, run once on the first cancel() after the
	// transport's own teardown. `McpClient.streamEvents` uses it to deregister the
	// stream's per-subscription event/control handlers when the stream ends.
	private void delegate() @safe nothrow cleanup_;

	/// Construct a handle wrapping a shared cancellation flag. Created by a
	/// `ClientTransport` when it opens the listen stream. `onCancel`, when
	/// supplied, is invoked exactly once on the first `cancel()` (after the flag
	/// is set) so a single-channel transport can emit its stdio
	/// `notifications/cancelled` for the listen request id.
	package this(shared(bool)* cancelled, void delegate() @safe nothrow onCancel = null) @safe nothrow @nogc
	{
		cancelled_ = cancelled;
		onCancel_ = onCancel;
	}

	/// Request that the stream stop and its background task terminate. Idempotent:
	/// the transport-supplied `onCancel` (if any) runs only on the first call.
	void cancel() @safe nothrow
	{
		// Atomic compare-and-swap so only the thread that flips the flag from
		// false to true runs onCancel_; concurrent cancel() calls see the flag
		// already set and skip it, guaranteeing exactly-once teardown.
		if (cancelled_ !is null && cas(cancelled_, false, true))
		{
			if (onCancel_ !is null)
				onCancel_();
			if (cleanup_ !is null)
				cleanup_();
		}
	}

	/// Attach a cleanup run exactly once on the first `cancel()`/`close()`, after
	/// the transport's own teardown. Set immediately after the stream is opened
	/// (before any cancel can race), so a later cancel deregisters client state.
	void addCleanup(void delegate() @safe nothrow cleanup) @safe nothrow
	{
		cleanup_ = cleanup;
	}

	/// Alias for `cancel()`.
	void close() @safe nothrow
	{
		cancel();
	}

	/// Whether `cancel()`/`close()` has been called.
	bool cancelled() const @safe nothrow @nogc
	{
		return cancelled_ !is null && atomicLoad(*cancelled_);
	}

	/// Whether the stream is over: cancelled locally, or ended by the server.
	bool ended() const @safe nothrow @nogc
	{
		return finished_ || cancelled;
	}

	/// The error the server ended the stream with (an HTTP or JSON-RPC error
	/// response to the listen request, or a broken connection); null while the
	/// stream is open, after a clean end, or after a local cancel.
	McpException error() @safe nothrow @nogc
	{
		return error_;
	}

	/// Record that the server ended the stream, with `error` when it failed. Only
	/// the first end is kept, and an end after a local cancel is ignored.
	package void finish(McpException error = null) @safe nothrow @nogc
	{
		if (finished_ || cancelled)
			return;
		finished_ = true;
		error_ = error;
	}
}

unittest  // finish records the server's end and its error once
{
	auto s = new SubscriptionStream(() @trusted { return new shared bool(false); }());
	assert(!s.ended && s.error is null);
	auto e = new McpException(-32601, "no listen");
	s.finish(e);
	assert(s.ended && s.error is e && !s.cancelled);
	s.finish(null);
	assert(s.error is e, "only the first end is kept");
}

unittest  // an end reported after a local cancel is ignored
{
	auto s = new SubscriptionStream(() @trusted { return new shared bool(false); }());
	s.cancel();
	s.finish(new McpException(-32603, "aborted"));
	assert(s.ended && s.error is null);
}

/// The rendezvous between a transport's `openListen` and the background task
/// reading the stream it opened: the task signals once the stream's leading frame
/// arrives or the stream ends first, and `openListen` waits (bounded) for that.
/// A heap object so the event outlives an `openListen` that has already returned.
package final class ListenGate
{
	import core.time : Duration;
	import vibe.core.sync : LocalManualEvent, createManualEvent;

	private LocalManualEvent event_;
	private int emitCount_;
	private bool waiting_ = true;
	private bool established_;

	this() @safe
	{
		event_ = createManualEvent();
		emitCount_ = event_.emitCount;
	}

	/// Signal the waiter: `frame` is true when the stream's leading frame arrived,
	/// false when the stream ended before one. Only the first signal counts.
	void signal(bool frame) @safe nothrow
	{
		if (!waiting_)
			return;
		waiting_ = false;
		established_ = frame;
		try
			event_.emit();
		catch (Exception)
		{
		}
	}

	/// Wait up to `timeout` for `signal`, returning whether the leading frame
	/// arrived. Later signals are ignored.
	bool wait(Duration timeout) @safe
	{
		if (waiting_)
			() @trusted {
			try
				event_.waitUninterruptible(timeout, emitCount_);
			catch (Exception)
			{
			}
		}();
		waiting_ = false;
		return established_;
	}
}

unittest  // a SubscriptionStream handle reports and toggles its cancelled state
{
	auto cancelled = () @trusted { return new shared bool(false); }();
	auto s = new SubscriptionStream(cancelled);
	assert(!s.cancelled);
	s.cancel();
	assert(s.cancelled);
	assert(*cancelled);
	s.close(); // idempotent
	assert(s.cancelled);
}

unittest  // onCancel fires exactly once even when many threads call cancel() concurrently
{
	import core.thread : Thread;
	import core.atomic : atomicLoad, atomicStore, atomicOp;

	// Repeat to give the read-then-write race ample opportunity to surface.
	foreach (iteration; 0 .. 500)
	{
		auto cancelled = () @trusted { return new shared bool(false); }();
		shared int closes = 0;
		auto s = new SubscriptionStream(cancelled, () @safe nothrow{
			atomicOp!"+="(closes, 1);
		});

		// All threads spin on a shared gate so they enter cancel() together,
		// maximising the overlap of the unguarded read-then-write window.
		shared bool start = false;
		enum threadCount = 16;
		Thread[threadCount] threads;
		foreach (ref t; threads)
		{
			t = new Thread({
				while (!atomicLoad(start))
				{
				}
				s.cancel();
			});
			t.start();
		}
		atomicStore(start, true);
		foreach (t; threads)
			t.join();

		assert(atomicLoad(closes) == 1, "onCancel must fire exactly once under concurrent cancel()");
	}
}

unittest  // a transport onCancel (e.g. HTTP socket close) runs exactly once on first cancel
{
	auto cancelled = () @trusted { return new shared bool(false); }();
	int closes;
	auto s = new SubscriptionStream(cancelled, () @safe nothrow{ closes++; });
	assert(closes == 0);
	s.cancel();
	assert(closes == 1, "onCancel must fire on the first cancel (socket teardown)");
	s.cancel(); // idempotent: no second teardown
	s.close();
	assert(closes == 1, "onCancel must not fire again on a repeat cancel");
}
