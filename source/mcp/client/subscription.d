module mcp.client.subscription;

/// The set of change-notification types a draft client opts into when opening a
/// `subscriptions/listen` stream (draft basic/utilities/subscriptions). The three
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
/// closes the connection and terminates.
final class SubscriptionStream
{
	private shared(bool)* cancelled_;
	// Optional transport-supplied action run exactly once on the first cancel().
	// The stdio transport uses it to emit `notifications/cancelled` referencing
	// the listen request id (draft basic/utilities/subscriptions Cancellation,
	// stdio); the HTTP transport uses it to force-close the listen stream's socket
	// so a blocked read unblocks immediately.
	private void delegate() @safe nothrow onCancel_;

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
		if (cancelled_ !is null && !*cancelled_)
		{
			*cancelled_ = true;
			if (onCancel_ !is null)
				onCancel_();
		}
	}

	/// Alias for `cancel()`.
	void close() @safe nothrow
	{
		cancel();
	}

	/// Whether `cancel()`/`close()` has been called.
	bool cancelled() const @safe nothrow @nogc
	{
		return cancelled_ !is null && *cancelled_;
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
