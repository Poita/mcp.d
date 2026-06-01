module mcp.client.transport;

import vibe.data.json : Json;

import mcp.protocol.jsonrpc : Message;

public import mcp.client.subscription : SubscriptionStream, SubscriptionFilter;

/// The transport seam under `McpClient`. The client speaks pure JSON-RPC and
/// protocol logic; a `ClientTransport` carries the bytes — over Streamable HTTP
/// (`HttpClientTransport`) or stdio (`StdioClientTransport`).
///
/// The client installs its inbound dispatcher via `setInboundHandler` (it passes
/// `McpClient.dispatchInbound`); the transport invokes that handler for every
/// interleaved notification and server->client request it reads on any stream.
/// A response to a server->client request, and any client-originated
/// notification, are sent with `sendOneway`. Per-request work goes through
/// `deliver`, which sends the request and returns its correlated result (or
/// throws `McpException` on an error response), dispatching anything else it sees
/// in the meantime to the inbound handler.
/// The protocol-side collaborator an `McpClient` hands to its transport at
/// construction (`ClientTransport.setProtocol`). It lets the transport pull the
/// protocol-derived request headers and consult the cancelled-request set
/// without knowing anything about the client's draft state, tool inputSchema
/// cache, or cancellation bookkeeping — and without the transport having to be a
/// concrete `HttpClientTransport` the client downcasts to. `McpClient`
/// implements this interface.
interface ClientProtocol
{
	/// The protocol-derived headers for an outgoing `message`: the
	/// `MCP-Protocol-Version` header plus, for a draft client, the standard
	/// `Mcp-Method` / `Mcp-Name` headers and any `Mcp-Param-*` mirrored tool
	/// arguments. Called with `Json.undefined` (no message — e.g. the GET server
	/// stream) it returns only the version header. Never includes Accept /
	/// Content-Type / Authorization / Mcp-Session-Id / Last-Event-ID — those are
	/// the transport's own.
	string[string] headersFor(Json message) @safe;

	/// Whether a response with the given JSON-RPC `id` belongs to a request the
	/// client has cancelled (basic/utilities/cancellation): such a response is
	/// dropped rather than returned.
	bool isCancelled(long id) @safe;
}

interface ClientTransport
{
	/// Send a JSON-RPC request `requestMessage` and return its result `Json`
	/// (throwing `McpException` on an error response). The id to await is
	/// `expectId`. Interleaved notifications and server->client requests seen
	/// while awaiting are dispatched to the inbound handler.
	Json deliver(Json requestMessage, long expectId) @safe;

	/// Send a message that expects no correlated reply: a notification, or a
	/// response to a server->client request.
	void sendOneway(Json message) @safe;

	/// Whether a reply to a server->client request may be written *inline* from
	/// the inbound dispatch (synchronously) rather than deferred to a separate
	/// background task. True for a single-channel transport whose inbound dispatch
	/// is not the coroutine holding the awaited response (stdio: the dispatch runs
	/// on the demux task and the reply is just another line written to the child's
	/// stdin, which never blocks the read of the next line). False for a transport
	/// where a nested synchronous send inside the awaiting read loop could deadlock
	/// (HTTP: the reply travels on a different request and must be deferred). When
	/// false, `McpClient` defers the reply with `runTask`. Either way a running
	/// event loop is in play; this only governs whether an extra task is spawned.
	bool repliesSynchronously() @safe;

	/// Open the standalone server->client stream, if the transport has one
	/// (HTTP GET SSE). A no-op on stdio.
	void startServerStream() @safe;

	/// Open a long-lived `subscriptions/listen` stream for `listenMessage`,
	/// dispatching every inbound message on it to the inbound handler. Returns a
	/// handle whose `cancel()`/`close()` stops the stream.
	SubscriptionStream openListen(Json listenMessage) @safe;

	/// Install the client's inbound dispatcher (`McpClient.dispatchInbound`),
	/// invoked for notifications and server->client requests on any stream.
	void setInboundHandler(void delegate(Message) @safe handler) @safe;

	/// Install the client's `ClientProtocol` collaborator, through which the
	/// transport obtains the protocol-derived request headers (`headersFor`) and
	/// the cancelled-response predicate (`isCancelled`). A transport that needs
	/// neither (e.g. stdio) may keep it but ignore it. `McpClient` calls this once
	/// at construction.
	void setProtocol(ClientProtocol protocol) @safe;

	/// Initiate the transport's backward-compatibility fallback after a modern
	/// request was rejected in a way that signals an older server (HTTP: a
	/// 400/404/405 POST -> open the legacy HTTP+SSE GET stream and switch to the
	/// two-endpoint transport). A no-op on transports without a fallback path
	/// (stdio), symmetric with `startServerStream`/`setBearerToken`. The client
	/// follows this with the legacy `initialize` handshake.
	void startLegacyFallback() @safe;

	/// Attach an OAuth bearer access token (HTTP `Authorization: Bearer`); a
	/// no-op on stdio. An empty string clears it.
	void setBearerToken(string token) @safe;

	/// Release transport resources: stdio terminates the subprocess (when one was
	/// spawned); HTTP stops any background streams.
	void close() @safe;
}
