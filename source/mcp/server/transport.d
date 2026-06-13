module mcp.server.transport;

import std.typecons : Nullable;
import vibe.data.json : Json;

import mcp.protocol.jsonrpc : Message;

public import mcp.server.connection : ConnectionState;
public import mcp.server.context : RequestContext, ConnectionScoped;
public import mcp.server.server : ServerMode;

/// The server-side transport seam, symmetric to `mcp.client.transport`'s
/// `ClientTransport`. A server transport carries JSON-RPC bytes between a peer
/// and an `McpServer` core, which speaks pure protocol logic; the transport
/// drives that core through this contract. `McpServer` implements it, so a
/// transport can hold its server as a `ServerCore` instead of the concrete
/// class.
///
/// Inbound (peer -> server) goes through the `handle` / `handleRaw` family:
///   - `handleRaw(text)` parses a wire payload (single message or batch) and
///     returns the raw response text, or "" when there is nothing to send back
///     (a notification, or an all-notification batch). It is the recipe a
///     stateless or in-process transport needs.
///   - `handleRaw(text, sink)` adds a server->client write `sink` for transports
///     that deliver out-of-band frames on the same channel (stdio): a handler's
///     `ctx.log` / `ctx.reportProgress` are pushed to `sink` as they happen,
///     before the request's reply is returned as the result string. The
///     `serverRequest` overload additionally carries the blocking
///     server->client request channel (`ctx.sample` / `ctx.elicit`).
///   - `handleRaw(text, conn)` dispatches against an explicit per-request
///     `ConnectionState` a session-multiplexing transport resolved itself
///     (Streamable HTTP), instead of the server's single bound connection.
///   - `handle(msg, ctx)` dispatches one already-parsed `Message` against a
///     caller-supplied `RequestContext`, returning the JSON-RPC response for a
///     request or `Nullable.init` for a notification.
///
/// Outbound (server -> peer) is the `RequestContext` interface
/// (`mcp.server.context`): the transport supplies a concrete `RequestContext`
/// to `handle` (or via the `sink` / `serverRequest` overloads of `handleRaw`),
/// and the server calls back into it to emit progress / logging notifications
/// and to issue blocking sampling / elicitation / roots requests while a
/// request is in flight. A transport that multiplexes many sessions over one
/// server also implements `ConnectionScoped` on its `RequestContext` so the
/// core scopes per-connection state (the cancellation registry) correctly.
///
/// Connection / session ownership is deliberately NOT part of this seam.
/// `McpServer.bindConnection` (the fallback `ConnectionState` hook the
/// notify/push path uses) and the `SessionManager` that owns per-session
/// `ConnectionState` are `package(mcp)`-private: server transports are
/// supported in-package only (`mcp.transport.*`). An out-of-package transport
/// can still drive a server through this interface — it builds its own
/// `ConnectionState` and threads it via the `handleRaw(text, conn)` overload or
/// a `ConnectionScoped` `RequestContext` — but it cannot own the fallback
/// connection the out-of-request notify/push path uses. See the README
/// "implementing a custom server transport" recipe.
interface ServerCore
{
	/// The statefulness model the server was constructed with. A transport reads
	/// this to derive session minting: `stateful` mints/tracks an
	/// `Mcp-Session-Id`, `stateless` never does.
	ServerMode mode() const @safe;

	/// Dispatch one parsed message against `ctx` (the server->client channel).
	/// Returns the JSON-RPC response for a request, or `Nullable.init` for a
	/// notification.
	Nullable!Json handle(Message msg, RequestContext ctx) @safe;

	/// `handle` with a `NullContext` (no server->client channel).
	Nullable!Json handle(Message msg) @safe;

	/// Process a raw wire payload (single message or batch) and return the raw
	/// response text, or "" when there is nothing to send back.
	string handleRaw(string text) @safe;

	/// `handleRaw` dispatched against an explicit per-request `ConnectionState`
	/// the transport resolved (session-multiplexing transports). `null` falls
	/// back to the no-arg behaviour.
	string handleRaw(string text, ConnectionState conn) @safe;

	/// `handleRaw` with a server->client write `sink` for transports that deliver
	/// out-of-band frames on the same channel (stdio). `null` sink => no
	/// streaming.
	string handleRaw(string text, scope void delegate(string) @safe sink) @safe;

	/// `handleRaw(text, sink)` plus the blocking server->client request channel:
	/// `serverRequest(method, params)` writes a server->client request and blocks
	/// for the peer's reply (used by `ctx.sample` / `ctx.elicit`). `null`
	/// `serverRequest` => server->client requests throw.
	string handleRaw(string text, scope void delegate(string) @safe sink,
			scope Json delegate(string, Json) @safe serverRequest) @safe;
}

/// `ServerTransport` is published as an alias for `ServerCore`: the core is the
/// object a transport drives, named from the transport's point of view. The two
/// names refer to the same interface so either import reads naturally.
alias ServerTransport = ServerCore;

version (unittest)
{
	import mcp.server.server : McpServer;
	import vibe.data.json : parseJsonString;
}

@safe unittest  // McpServer satisfies the ServerCore seam
{
	ServerCore core = McpServer.stateless("t", "1.0");
	assert(core !is null);
	assert(core.mode == ServerMode.stateless);
}

@safe unittest  // a transport drives the server entirely through the interface
{
	ServerCore core = McpServer.stateless("t", "1.0");
	const outText = core.handleRaw(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	auto j = parseJsonString(outText);
	assert(j["id"].get!int == 1);
	assert(j["result"].type == Json.Type.object);
}

@safe unittest  // a notification yields no reply across the seam
{
	ServerCore core = McpServer.stateless("t", "1.0");
	assert(core.handleRaw(`{"jsonrpc":"2.0","method":"notifications/initialized"}`) == "");
}
