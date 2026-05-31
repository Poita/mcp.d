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

	/// Attach an OAuth bearer access token (HTTP `Authorization: Bearer`); a
	/// no-op on stdio. An empty string clears it.
	void setBearerToken(string token) @safe;

	/// Release transport resources: stdio terminates the subprocess (when one was
	/// spawned); HTTP stops any background streams.
	void close() @safe;
}
