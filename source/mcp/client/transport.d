module mcp.client.transport;

import core.time : Duration;
import vibe.data.json : Json;

import mcp.protocol.errors : McpException;
import mcp.protocol.jsonrpc : Message;
import mcp.protocol.versions : ProtocolVersion;

public import mcp.client.subscription : SubscriptionStream, SubscriptionFilter;

/// The source of the OAuth bearer token an HTTP client sends (`OAuthSession`
/// supplies one through `useOAuth`).
struct BearerProvider
{
	/// Return the access token for the request being sent; called for every
	/// request, so a token refreshed between requests is always the one sent.
	string delegate() @safe token;

	/// Called with the access token a request carried when the server rejected
	/// it as invalid (RFC 6750 §3.1: HTTP 401 whose challenge has no error code
	/// or `error="invalid_token"`). Returns whether a replacement token is
	/// available: when true the request is retried once with a fresh `token()`,
	/// otherwise the 401 is surfaced to the caller with its `WWW-Authenticate`
	/// challenge. Optional; without it a 401 is surfaced to the caller.
	bool delegate(string rejectedToken) @safe onRejected;
}

/// The protocol-side collaborator an `McpClient` hands to its transport at
/// construction (`ClientTransport.setProtocol`). It lets the transport pull the
/// protocol-derived request headers and consult the cancelled-request set
/// without knowing anything about the client's modern state, tool inputSchema
/// cache, or cancellation bookkeeping — and without the transport having to be a
/// concrete `HttpClientTransport` the client downcasts to. `McpClient`
/// implements this interface.
interface ClientProtocol
{
	/// The protocol-derived headers for an outgoing `message`: the
	/// `MCP-Protocol-Version` header plus, for a modern client, the standard
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
/// The modern protocol version request `message` declares in its
/// `_meta.protocolVersion`, so a transport and the client read a request's
/// framing off the request itself rather than off shared session state (which
/// `McpClient.connect`'s probe does not change). False when it declares no
/// modern version.
package bool modernFraming(Json message, out ProtocolVersion version_) @safe nothrow
{
	import mcp.protocol.mrtr : MetaKey;
	import mcp.protocol.versions : isModern, tryParseVersion;

	try
	{
		if (message.type != Json.Type.object || "params" !in message)
			return false;
		auto params = message["params"];
		if (params.type != Json.Type.object || "_meta" !in params)
			return false;
		auto meta = params["_meta"];
		if (meta.type != Json.Type.object || MetaKey.protocolVersion !in meta
				|| meta[MetaKey.protocolVersion].type != Json.Type.string)
			return false;
		return tryParseVersion(meta[MetaKey.protocolVersion].get!string, version_)
			&& version_.isModern;
	}
	catch (Exception)
		return false;
}

interface ClientTransport
{
	/// Send a JSON-RPC request `requestMessage` and return its result `Json`
	/// (throwing `McpException` on an error response). The id to await is
	/// `expectId`. Interleaved notifications and server->client requests seen
	/// while awaiting are dispatched to the inbound handler.
	Json deliver(Json requestMessage, long expectId) @safe;

	/// Stop waiting for the in-flight request `expectId`: wake its blocked
	/// `deliver` (which then throws; `McpClient` substitutes `reason`) and release
	/// any stream dedicated to that request. `McpClient` calls this when a request
	/// times out or is cancelled. A no-op when no such request is in flight.
	void abort(long expectId, McpException reason) @safe;

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

	/// Attach a bearer provider consulted for every request, so a token that is
	/// refreshed between requests is always the one sent. Replaces any static
	/// token set by `setBearerToken` (and vice versa); a no-op on stdio.
	void setBearerProvider(BearerProvider provider) @safe;

	/// Signal whether the negotiated protocol version is modern (2026-07-28).
	/// The HTTP transport uses this to skip Last-Event-ID resumption (GET), which
	/// the modern protocol does not have; a no-op on stdio and on transports where
	/// the flag is irrelevant.
	void setModernProtocol(bool modern) @safe;

	/// Tell the transport the client's request timeout (`Duration.zero` when
	/// requests have no deadline). The client enforces response deadlines itself;
	/// the HTTP transport also bounds each one-way POST by it. A no-op on stdio.
	void setRequestTimeout(Duration timeout) @safe;

	/// Whether this transport signals the cancellation of a modern (2026-07-28)
	/// request by closing the request's stream rather than by sending
	/// `notifications/cancelled`. True for Streamable HTTP: the modern protocol
	/// (basic/transports §Sending Messages, Note) defines no client-to-server
	/// `notifications/cancelled` over Streamable HTTP — closing the SSE response
	/// stream is itself the cancellation signal. stdio and the legacy HTTP+SSE
	/// transport send the notification, so they return false. A request of an
	/// earlier protocol is always cancelled with the notification.
	bool cancelsByStreamClose() @safe;

	/// Release transport resources: stdio terminates the subprocess (when one was
	/// spawned); HTTP stops any background streams.
	void close() @safe;
}
