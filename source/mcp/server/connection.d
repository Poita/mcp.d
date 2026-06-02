module mcp.server.connection;

import mcp.protocol.versions : ProtocolVersion, latestStable;
import mcp.protocol.capabilities : ClientCapabilities;
import mcp.server.context : CancellationToken;

@safe:

/// The per-connection (or per-session) mutable state for a single MCP peer.
///
/// This is the designated home for the mutable per-peer state that would
/// otherwise leak across concurrently-served connections that share one server
/// instance. A `McpServer`
/// itself holds only immutable registration data, declared capabilities, the
/// `serverInfo`, and the chosen `ServerMode`; per-peer state lives here.
///
/// Ownership by mode:
///   - stateful: exactly one `ConnectionState` per session, owned by the
///     transport's `SessionManager` keyed by `Mcp-Session-Id`.
///   - stateless: the transport builds a transient `ConnectionState` per
///     request (from the draft `_meta`, or from the `MCP-Protocol-Version`
///     header / default plus empty capabilities for the legacy path) and
///     discards it; nothing is stored across calls.
///   - stdio: a single implicit `ConnectionState` for the process.
final class ConnectionState
{
	/// The protocol version negotiated for this connection (stateful) or the
	/// effective version for the current request (stateless). This is the single
	/// version concept: the server->client push/notification path is driven by
	/// each open listener's own `SubscriptionFilter`, not by a separate
	/// connection-level version (`subscriptions/listen` is an ordinary
	/// request and is not special-cased).
	ProtocolVersion negotiated = latestStable;

	/// The client capabilities declared at `initialize` (stateful) or carried in
	/// the request's `_meta` (stateless draft). Empty when unknown (legacy
	/// stateless): a handler that needs a client capability then errors.
	ClientCapabilities clientCaps;

	/// The minimum log level the client asked for via `logging/setLevel`
	/// (stateful) or the per-request `_meta` log level (stateless draft).
	string logLevel = "info";

	/// The resource URIs this connection has subscribed to (stateful only).
	bool[string] subscriptions;

	/// In-flight cancellation tokens keyed by this connection's request ids.
	/// Scoping the registry to the `ConnectionState` keeps a
	/// cancellation for one session's request id from touching another session's
	/// identically-numbered request.
	CancellationToken[string] inFlight;

	/// Whether `initialize` has completed for this connection (stateful).
	bool initialized;
}

unittest  // two ConnectionStates do not share negotiated version or caps
{
	import mcp.protocol.versions : ProtocolVersion;

	auto a = new ConnectionState;
	auto b = new ConnectionState;

	a.negotiated = ProtocolVersion.v2025_03_26;
	b.negotiated = ProtocolVersion.v2025_11_25;
	a.clientCaps.roots = true;
	// b leaves roots unset.

	assert(a.negotiated == ProtocolVersion.v2025_03_26);
	assert(b.negotiated == ProtocolVersion.v2025_11_25);
	assert(a.clientCaps.roots);
	assert(!b.clientCaps.roots, "session B must not see session A's caps");
}

unittest  // cancellation registries are per-connection
{
	auto a = new ConnectionState;
	auto b = new ConnectionState;

	auto tokA = new CancellationToken;
	auto tokB = new CancellationToken;
	a.inFlight["i:1"] = tokA;
	b.inFlight["i:1"] = tokB;

	// Cancelling session A's id "1" must not touch session B's same-id request.
	a.inFlight["i:1"].cancel();
	assert(tokA.cancelled);
	assert(!tokB.cancelled, "cross-talk: B's in-flight was cancelled by A");
}

unittest  // subscriptions are per-connection
{
	auto a = new ConnectionState;
	auto b = new ConnectionState;
	a.subscriptions["res://x"] = true;
	assert(("res://x" in a.subscriptions) !is null);
	assert(("res://x" in b.subscriptions) is null);
}

unittest  // a fresh ConnectionState carries spec defaults
{
	import mcp.protocol.versions : latestStable;

	auto c = new ConnectionState;
	assert(c.logLevel == "info");
	assert(!c.initialized);
	assert(c.negotiated == latestStable);
	assert(c.subscriptions.length == 0);
	assert(c.inFlight.length == 0);
}
