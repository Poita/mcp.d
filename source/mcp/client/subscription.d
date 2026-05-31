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

	/// Construct a handle wrapping a shared cancellation flag. Created by a
	/// `ClientTransport` when it opens the listen stream.
	package this(shared(bool)* cancelled) @safe nothrow @nogc
	{
		cancelled_ = cancelled;
	}

	/// Request that the stream stop and its background task terminate. Idempotent.
	void cancel() @safe nothrow @nogc
	{
		if (cancelled_ !is null)
			*cancelled_ = true;
	}

	/// Alias for `cancel()`.
	void close() @safe nothrow @nogc
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
