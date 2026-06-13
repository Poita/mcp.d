module mcp.server.context;

import std.typecons : Nullable;
import vibe.data.json : Json, deserializeJson, parseJsonString;

import mcp.protocol.errors;
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
import mcp.protocol.types : ListRootsResult, ElicitResult, ElicitAction, LogLevel, shouldLog;
import mcp.protocol.capabilities : ClientCapabilities, ClientCapability;
import mcp.protocol.schema : jsonSchemaOf, isFlatElicitationStruct;
import mcp.auth.resource_server : TokenInfo;
import mcp.protocol.jsonrpc : makeNotification;
import mcp.protocol.versions : ProtocolVersion, latestStable, supportsProgressMessage;
import mcp.server.connection : ConnectionState;

@safe:

/// A shared, mutable cancellation flag for one in-flight request. The server
/// hands the same token to the request's `RequestContext` (so the handler can
/// poll `ctx.isCancelled`) and to its in-flight registry (so an inbound
/// `notifications/cancelled` for the matching request id can flip it). It is a
/// class so the flag is observed across the two tasks that a Streamable HTTP
/// transport runs the request and its cancellation on. See
/// basic/utilities/cancellation: a receiver "SHOULD: Stop processing the
/// cancelled request, Free associated resources, Not send a response".
final class CancellationToken
{
	private bool cancelled_;

	/// Whether a cancellation has been requested for this token's request.
	bool cancelled() const @safe nothrow @nogc
	{
		return cancelled_;
	}

	/// Mark the request cancelled. Idempotent.
	void cancel() @safe nothrow @nogc
	{
		cancelled_ = true;
	}
}

/// An optional capability a `RequestContext` may implement to report the
/// connection / session it arrived on. The server core scopes its per-connection
/// state (the in-flight cancellation registry) by this token so that two
/// concurrent clients sharing one `McpServer` over Streamable HTTP cannot collide
/// on a bare JSON-RPC id. A transport that multiplexes many sessions over one
/// server SHOULD have its `RequestContext` implement this and return a
/// per-session token (e.g. derived from `Mcp-Session-Id`, or a per-connection
/// UUID), so a `notifications/cancelled` arriving on connection B only matches
/// in-flight requests registered by connection B. A context that does not
/// implement this interface is treated as the single shared connection (empty
/// token), the behaviour for stdio, in-process, and any transport that does not
/// distinguish connections.
///
/// The McpServer's other per-client state — the negotiated protocol version, the
/// client capabilities, the logging level, and resource subscriptions — lives in
/// shared instance fields, so the supported deployment for stateful HTTP is one
/// McpServer per connection. This `ConnectionScoped` hook isolates the
/// cancellation registry.
interface ConnectionScoped
{
	/// A stable, non-empty identifier for this request's connection / session.
	string connectionToken() @safe;

	/// The per-connection / per-session `ConnectionState` this request is bound to.
	/// A transport that scopes state per peer returns the state it
	/// resolved for THIS request: the `SessionManager`-owned state looked up by
	/// `Mcp-Session-Id` (stateful HTTP), or a fresh per-request state built from the
	/// request's effective version + `_meta` (stateless HTTP). Returns `null` when
	/// the context carries no such state, in which case the server core falls back
	/// to its single bound `activeConnection` (stdio / bare-`handle`).
	ConnectionState connectionState() @safe;
}

/// Resolve the connection token for a context: the context's own token when it
/// implements `ConnectionScoped`, otherwise the empty (shared) token. Centralised
/// here so the server core has one place to derive the cancellation-registry
/// scope.
string connectionTokenOf(RequestContext ctx) @safe
{
	if (auto c = cast(ConnectionScoped) ctx)
		return c.connectionToken();
	return "";
}

/// Resolve the `ConnectionState` a context carries: the context's own state when
/// it implements `ConnectionScoped` and resolved one, otherwise `null`.
/// Centralised here (mirroring `connectionTokenOf`) so the server core has one
/// place to decide per-session/per-request state vs. the single bound
/// `activeConnection` fallback. A `null` result means "this
/// context carries no scoped state" — the dispatcher then uses
/// `activeConnection`.
ConnectionState connectionStateOf(RequestContext ctx) @safe
{
	if (auto c = cast(ConnectionScoped) ctx)
		return c.connectionState();
	return null;
}

/// Per-request context handed to tool handlers. It is the channel through which
/// a handler emits server->client traffic while a request is in flight:
/// progress + logging notifications, and (blocking) sampling / elicitation
/// requests. Transports supply a concrete implementation; the in-process and
/// stdio paths use `NullContext` (notifications are dropped, server->client
/// requests are unsupported).
interface RequestContext
{
	/// Whether the client has sent a `notifications/cancelled` for this request
	/// (basic/utilities/cancellation). A long-running handler SHOULD poll this
	/// and, when true, stop work and free resources promptly; the server
	/// suppresses the late response for a cancelled request regardless. Always
	/// false on transports that cannot deliver an out-of-band cancellation while
	/// a request is in flight (e.g. the in-process / stdio `NullContext`).
	bool isCancelled() @safe;

	/// Emit a `notifications/progress`. No-op if the originating request carried
	/// no `_meta.progressToken`.
	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe;

	/// Emit a `notifications/message` (logging) at the given level. `data` may be
	/// any JSON value (commonly a string or object); `logger` is optional.
	void log(string level, Json data, string logger = null) @safe;

	/// Send `sampling/createMessage` and block until the client responds,
	/// returning the raw result `Json`. The transport primitive behind `sample`;
	/// gating lives in `sample`, so a channel-less context just throws here.
	Json sampleRaw(Json params) @safe;

	/// Send `elicitation/create` and block until the client responds, returning
	/// the raw result `Json`. The transport primitive behind `elicit`/`elicitUrl`.
	Json elicitRaw(Json params) @safe;

	/// Send `roots/list` and block until the client responds, returning the raw
	/// result `Json`. The transport primitive behind `listRoots`.
	Json listRootsRaw() @safe;

	/// Whether the connected client advertised `cap`.
	bool clientSupports(ClientCapability cap) @safe;

	/// True when this request is on a stateless (MRTR) protocol — the draft
	/// revision, where there is no server->client channel. On such requests a
	/// tool handler must NOT call `elicit`/`sample` (they throw); instead it
	/// returns `ToolResponse.inputRequired(...)` and reads the client's answers
	/// from `inputResponses` on the retried request. False on 2025-era requests.
	bool isStateless() @safe;

	/// The input responses the client attached when resubmitting an MRTR
	/// request, keyed by the `InputRequest.id` the server issued on the prior
	/// round. Empty on the first call and on non-stateless requests.
	Json[string] inputResponses() @safe;

	/// The opaque MRTR (SEP-2322) `requestState` the client echoed back from the
	/// server's prior `InputRequiredResult` (`params.requestState`). Empty on the
	/// first call and when the server sent no state. The server owns this value
	/// (the client treats it as opaque), so handlers MUST validate it as
	/// untrusted input.
	string requestState() @safe;

	/// The validated OAuth 2.1 access-token info for this request, when the
	/// transport enforces authorization (Streamable HTTP with a configured
	/// `ResourceServerConfig`). `TokenInfo.valid` is false on transports without
	/// auth (stdio, in-process) or when no token was required; handlers that need
	/// the authenticated subject or token scopes read it here.
	TokenInfo auth() @safe;

	/// Request an LLM completion from the client (`sampling/createMessage`).
	/// Throws on a stateless (MRTR) request — use `ToolResponse.inputRequired`
	/// instead — or if the client does not support sampling.
	final Json sample(Json params) @safe
	{
		if (isStateless)
			throw internalError("sample() is unavailable on a stateless (MRTR) request;"
					~ " return ToolResponse.inputRequired instead, or construct the server with"
					~ " McpServer.stateful() for a blocking server->client round-trip");
		if (!clientSupports(ClientCapability.sampling))
			throw invalidRequest("Client does not support sampling");
		// Per spec, servers MUST NOT send tool-enabled sampling requests to
		// clients that have not declared the `sampling.tools` sub-capability.
		// This covers both the `tools` list and a `toolChoice` directive, since
		// a request that sets `toolChoice` (even `{mode:"none"}`) without any
		// `tools` still exercises the tool-use sampling surface.
		if (params.type == Json.Type.object && ("tools" in params
				|| "toolChoice" in params) && !clientSupports(ClientCapability.samplingTools))
			throw invalidRequest("Client does not support tool use in sampling (sampling.tools)");
		// The soft-deprecated `sampling.context` sub-capability gates the
		// `includeContext` values `thisServer`/`allServers`.
		if (params.type == Json.Type.object && "includeContext" in params
				&& params["includeContext"].type == Json.Type.string)
		{
			const inc = params["includeContext"].get!string;
			if ((inc == "thisServer" || inc == "allServers")
					&& !clientSupports(ClientCapability.samplingContext))
				throw invalidRequest(
						"Client does not support context-enabled sampling (sampling.context)");
		}
		return sampleRaw(params);
	}

	/// Typed convenience over `sample(Json)`: build a `CreateMessageRequest`,
	/// send it, and parse the client's reply into a `CreateMessageResult`. Same
	/// preconditions and exceptions as the JSON overload.
	final CreateMessageResult sample(CreateMessageRequest request) @safe
	{
		return CreateMessageResult.fromJson(sample(request.toJson()));
	}

	/// Request structured user input from the client (`elicitation/create`).
	/// `requestedSchema` must be a JSON Schema object. Throws on a stateless
	/// (MRTR) request — use `ToolResponse.inputRequired` instead — or if the
	/// client does not support elicitation.
	///
	/// This is form-mode elicitation; per spec the `mode` field is omitted and
	/// defaults to `"form"`. For URL-mode elicitation use `elicitUrl`. Throws
	/// when the client did not declare the `elicitation.form` submode (a bare
	/// `elicitation:{}` is treated as form-only for 2025-06-18 compatibility).
	/// Returns the client's reply parsed into a typed `ElicitResult` (branch on
	/// `.action`; read collected values via `.content` or `.contentAs!T`).
	final ElicitResult elicit(string message, Json requestedSchema) @safe
	{
		if (isStateless)
			throw internalError("elicit() is unavailable on a stateless (MRTR) request;"
					~ " return ToolResponse.inputRequired instead, or construct the server with"
					~ " McpServer.stateful() for a blocking server->client round-trip");
		// Per client/elicitation: servers MUST NOT send elicitation requests
		// with modes the client does not support. A bare `elicitation:{}` is
		// form-only, so a generic declaration already sets the form submode.
		if (!clientSupports(ClientCapability.elicitationForm))
			throw invalidRequest("Client does not support form-mode elicitation");
		Json params = Json.emptyObject;
		params["message"] = message;
		params["requestedSchema"] = requestedSchema;
		return ElicitResult.fromJson(elicitRaw(params));
	}

	/// Typed convenience over `elicit(string, Json)`: derive the form
	/// `requestedSchema` from the flat struct `T` via `jsonSchemaOf!T`, send the
	/// elicitation, and return the typed `ElicitResult`. On an `accept`, decode
	/// the collected values with `result.contentAs!T`. `T` must be a flat struct
	/// of scalar fields (string / number / integer / boolean / enum, optionally
	/// `Nullable`) — the elicitation schema restriction (SEP-1034/1330) forbids
	/// nested objects and arrays, enforced here at compile time.
	ElicitResult elicit(T)(string message) @safe
	{
		static assert(isFlatElicitationStruct!T, "elicit!T requires a flat struct of scalar fields (string/number/integer/boolean/enum); " ~ T
				.stringof ~ " has a nested or non-scalar field");
		return elicit(message, jsonSchemaOf!T);
	}

	/// Request URL-mode elicitation from the client (`elicitation/create` with
	/// `mode: "url"`, introduced in 2025-11-25). Directs the user to complete an
	/// out-of-band interaction (e.g. an OAuth consent or a web form) at `url`;
	/// `elicitationId` correlates the request with the outcome the client reports
	/// back. Per spec a URL-mode request MUST specify `mode: "url"`, a `message`,
	/// `url`, and `elicitationId`. Throws when the client did not declare the
	/// `elicitation.url` submode.
	///
	/// Returns the client's response parsed into a typed `ElicitResult` (the
	/// `action` is typically `accept`/`decline`/`cancel`). Throws on a stateless
	/// (MRTR) request — use `ToolResponse.inputRequired` instead — or if the
	/// client does not support elicitation, if `url`/`elicitationId` are empty,
	/// or if `url` is not a valid absolute URI (the spec requires `url` to
	/// contain a valid URL).
	final ElicitResult elicitUrl(string message, string url, string elicitationId) @safe
	{
		if (isStateless)
			throw internalError("elicitUrl() is unavailable on a stateless (MRTR) request;"
					~ " return ToolResponse.inputRequired instead, or construct the server with"
					~ " McpServer.stateful() for a blocking server->client round-trip");
		// Per client/elicitation: servers MUST NOT send a url-mode request to a
		// client that only declared form mode (e.g. a bare `elicitation:{}`).
		if (!clientSupports(ClientCapability.elicitationUrl))
			throw invalidRequest("Client does not support url-mode elicitation");
		if (url.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty url");
		if (!isValidElicitationUrl(url))
			throw invalidParams("URL-mode elicitation requires a valid url (absolute URI): " ~ url);
		if (elicitationId.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty elicitationId");
		Json params = Json.emptyObject;
		params["mode"] = "url";
		params["message"] = message;
		params["url"] = url;
		params["elicitationId"] = elicitationId;
		return ElicitResult.fromJson(elicitRaw(params));
	}

	/// List the client's filesystem roots (`roots/list`). Per client/roots
	/// §Implementation Guidelines, checks the client's `roots` capability before
	/// usage and throws `McpException` if the client does not support it; parses
	/// the client's reply into a typed `ListRootsResult`. Throws on a stateless
	/// (MRTR) request — like `sample`/`elicit`, a server->client round-trip has no
	/// channel on the stateless protocol; use `ToolResponse.inputRequired` instead.
	final ListRootsResult listRoots() @safe
	{
		if (isStateless)
			throw internalError("listRoots() is unavailable on a stateless (MRTR) request;"
					~ " return ToolResponse.inputRequired instead, or construct the server with"
					~ " McpServer.stateful() for a blocking server->client round-trip");
		if (!clientSupports(ClientCapability.roots))
			throw invalidRequest("Client does not support roots");
		return ListRootsResult.fromJson(listRootsRaw());
	}

	/// Typed convenience over `inputResponses`: decode the MRTR answer the client
	/// attached for `id` into `T` via `T.fromJson` (e.g. `ElicitResult`,
	/// `CreateMessageResult`, `ListRootsResult` — matching the `InputRequest`
	/// kind the server issued). Returns `T.fromJson(Json.emptyObject)` when no
	/// answer is present for `id`.
	T inputResponseAs(T)(string id) @safe
	{
		auto m = inputResponses();
		if (auto p = id in m)
			return T.fromJson(*p);
		return T.fromJson(Json.emptyObject);
	}

	/// Decode the opaque MRTR `requestState` as JSON into `T`. The server owns the
	/// `requestState` value (the encoding contract is the server-side
	/// `ToolResponse.inputRequired(reqs, state)`, which carries
	/// `serializeToJson(state).toString()`), so this is the typed inverse: parse
	/// the echoed string and deserialise it into `T`. Returns `T.init` when the
	/// client echoed no state (`requestState` empty). The value is untrusted input
	/// the client round-tripped, so a malformed payload throws.
	T requestStateAs(T)() @safe
	{
		const raw = requestState();
		if (raw.length == 0)
			return T.init;
		return deserializeJson!T(parseJsonString(raw));
	}

	/// Typed convenience over `log(string, Json, string)`: emit a
	/// `notifications/message` at the given `LogLevel` with a plain string payload.
	/// Forwards to the JSON overload with the level's wire string and `Json(message)`.
	final void log(LogLevel level, string message, string logger = null) @safe
	{
		log(cast(string) level, Json(message), logger);
	}

	/// Typed convenience over `log(string, Json, string)`: emit a
	/// `notifications/message` at the given `LogLevel` with an arbitrary JSON
	/// payload (commonly a structured object). Forwards to the string/Json overload
	/// with the level's wire string, so the level cannot be misspelled.
	final void log(LogLevel level, Json data, string logger = null) @safe
	{
		log(cast(string) level, data, logger);
	}

	/// Integer-step convenience over `reportProgress(double, Nullable!double,
	/// string)`: a step counter passes `done`/`total` directly without
	/// `cast(double)` and constructing a `Nullable!double` total.
	final void reportProgress(long done, long total, string message = null) @safe
	{
		reportProgress(cast(double) done, Nullable!double(cast(double) total), message);
	}

	/// Whether the client attached an MRTR answer for `id` on this (resubmitted)
	/// request (`id` present in `inputResponses`).
	final bool hasInputResponse(string id) @safe
	{
		return (id in inputResponses()) !is null;
	}

	/// Whether this is an MRTR resubmission carrying client answers
	/// (`inputResponses` non-empty). False on the first round and on non-stateless
	/// requests.
	final bool isResubmit() @safe
	{
		return inputResponses().length > 0;
	}
}

/// The canonical no-op `RequestContext`: every member has a passive default
/// (never cancelled, notifications dropped, server->client requests rejected, no
/// capabilities, not stateless, no input responses / request state, no auth). A
/// focused context — most of them test fakes — subclasses this and overrides only
/// the one or two members it exercises, instead of re-stubbing the whole 12-method
/// surface. Channel-less production contexts (`NullContext`,
/// `HttpNotifyContext`) override only the server->client reject message.
abstract class BaseRequestContext : RequestContext
{
	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string, Json, string = null) @safe
	{
	}

	Json sampleRaw(Json) @safe
	{
		return noChannel();
	}

	Json elicitRaw(Json) @safe
	{
		return noChannel();
	}

	Json listRootsRaw() @safe
	{
		return noChannel();
	}

	/// The exception thrown by the server->client primitives when this context
	/// has no channel. Overridable so a context can give a transport-specific
	/// message while inheriting the three throwing primitives.
	protected Json noChannel() @safe
	{
		throw invalidRequest("This transport has no server-to-client channel");
	}

	bool clientSupports(ClientCapability) @safe
	{
		return false;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

/// A context with no client channel: notifications are dropped and
/// server->client requests are rejected. Used by transports that do not (yet)
/// support streaming, and as the default when none is supplied.
final class NullContext : BaseRequestContext
{
}

/// A `RequestContext` for the stdio transport. The stdio transport is a single
/// newline-delimited byte stream, and the MCP stdio spec permits the server to
/// write any valid MCP message to stdout at any time — so server->client
/// notifications (`notifications/message` logging and `notifications/progress`)
/// are serialised and pushed to the transport's write sink as the handler emits
/// them, out-of-band of the request's eventual reply.
///
/// The stdio transport runs each request handler in its own cooperative vibe
/// task while the channel's read loop keeps demultiplexing inbound lines, so an
/// out-of-band `notifications/cancelled` is dispatched (flipping the matching
/// in-flight `CancellationToken`) *concurrently* with a running handler — the
/// handler's `ctx.isCancelled()` simply observes the flipped token.
final class StdioContext : RequestContext
{
	private void delegate(string) @safe sink;
	private Json delegate(string, Json) @safe serverRequestFn;
	private ClientCapabilities clientCaps;
	private Json progressTok;
	private ProtocolVersion version_;
	private bool serverStateless_;

	/// `sink` receives one serialised JSON-RPC frame per call (the transport
	/// adds the newline terminator). `progressToken` is the originating request's
	/// `_meta.progressToken`, or `Json.undefined` when it carried none.
	/// `negotiated` is the protocol version agreed for this connection; it gates
	/// version-specific wire fields on the notifications this context emits (e.g.
	/// the `message` field on `notifications/progress`, which only exists from
	/// 2025-03-26 onward). This overload wires no server->client request channel
	/// (`sendRequest` throws, `clientSupports` is false).
	this(void delegate(string) @safe sink, Json progressToken = Json.undefined,
			ProtocolVersion negotiated = latestStable) @safe
	{
		this.sink = sink;
		this.progressTok = progressToken;
		this.version_ = negotiated;
	}

	/// As above, plus a server->client request channel: `serverRequest(method,
	/// params)` writes the request and blocks the current task until the client's
	/// reply (the `DuplexChannel` correlates it on its read loop), returning the
	/// `result` or throwing on error. `clientCaps` are the capabilities the client
	/// declared at `initialize`, so `clientSupports` can gate `sample`/`elicit`.
	/// `serverStateless` mirrors `server.mode == ServerMode.stateless`: when true,
	/// server-initiated requests are refused (a stateless server has no per-peer
	/// connection to carry the round-trip), exactly as on the HTTP transport.
	this(void delegate(string) @safe sink, Json delegate(string, Json) @safe serverRequest,
			ClientCapabilities clientCaps, Json progressToken = Json.undefined,
			ProtocolVersion negotiated = latestStable, bool serverStateless = false) @safe
	{
		this.sink = sink;
		this.serverRequestFn = serverRequest;
		this.clientCaps = clientCaps;
		this.progressTok = progressToken;
		this.version_ = negotiated;
		this.serverStateless_ = serverStateless;
	}

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe
	{
		if (progressTok.type == Json.Type.undefined)
			return;
		Json p = Json.emptyObject;
		p["progressToken"] = progressTok;
		p["progress"] = progress;
		if (!total.isNull)
			p["total"] = total.get;
		// `message` was introduced in 2025-03-26; suppress it for a 2024-11-05
		// peer whose ProgressNotification schema has no such field.
		if (message.length && version_.supportsProgressMessage)
			p["message"] = message;
		emit(makeNotification("notifications/progress", p));
	}

	void log(string level, Json data, string logger = null) @safe
	{
		Json p = Json.emptyObject;
		p["level"] = level;
		if (logger.length)
			p["logger"] = logger;
		// `data` is REQUIRED by server/utilities/logging; emit explicit JSON
		// null for an undefined payload so vibe does not drop the key.
		p["data"] = data.type == Json.Type.undefined ? Json(null) : data;
		emit(makeNotification("notifications/message", p));
	}

	private void emit(Json frame) @safe
	{
		if (sink !is null)
			sink(frame.toString());
	}

	Json sampleRaw(Json params) @safe
	{
		return serverRequest("sampling/createMessage", params);
	}

	Json elicitRaw(Json params) @safe
	{
		return serverRequest("elicitation/create", params);
	}

	Json listRootsRaw() @safe
	{
		return serverRequest("roots/list", Json.emptyObject);
	}

	private Json serverRequest(string method, Json params) @safe
	{
		// Server-initiated requests are a stateful feature: a stateless server keeps
		// no per-peer connection to carry the round-trip, so they are refused on
		// every transport (stdio included), matching the HTTP transport. Use
		// `McpServer.stateful()`; on the modern stateless protocol, return
		// `ToolResponse.inputRequired` (MRTR) instead.
		if (serverStateless_)
			throw invalidRequest("server-initiated requests (elicitation/sampling/roots) require a stateful server; construct with McpServer.stateful()");
		if (serverRequestFn is null)
			throw invalidRequest("The stdio transport has no server-to-client request channel");
		return serverRequestFn(method, params);
	}

	bool clientSupports(ClientCapability cap) @safe
	{
		// No channel wired -> report false (cannot satisfy a server->client
		// request).
		if (serverRequestFn is null)
			return false;
		return clientCaps.supports(cap);
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

/// Wraps a transport-supplied `RequestContext` with the per-request protocol
/// state the server determines only after parsing the message: whether the
/// request is stateless (MRTR), and the input responses the client attached.
/// The server installs this around the transport context before dispatching, so
/// handlers observe correct `isStateless`/`inputResponses` and `elicit`/`sample`
/// fail fast on stateless requests. Notifications and server->client requests
/// delegate to the wrapped context unchanged.
final class RequestScope : RequestContext, ConnectionScoped
{
	private RequestContext inner;
	private bool stateless;
	private Json[string] responses;
	private string requestState_;
	private string minLevel;
	private bool loggingRequested;
	private CancellationToken cancellation;
	private ProtocolVersion effectiveVersion_;

	this(RequestContext inner, bool stateless, Json[string] responses, string minLevel = "info",
			bool loggingRequested = true, CancellationToken cancellation = null,
			string requestState = "", ProtocolVersion effectiveVersion = latestStable) @safe
	{
		this.inner = inner;
		this.stateless = stateless;
		this.responses = responses;
		this.requestState_ = requestState;
		this.minLevel = minLevel;
		this.loggingRequested = loggingRequested;
		this.cancellation = cancellation;
		this.effectiveVersion_ = effectiveVersion;
	}

	/// The protocol version in effect for THIS request (negotiated version on the
	/// stateful 2025-era protocols; the per-request `_meta.protocolVersion` on the
	/// stateless draft). Request-scoped so a concurrent request that yields mid-
	/// handle cannot have its effective version flipped by another in-flight
	/// request: the dispatcher reads it from here, not from a mutable field on the
	/// shared server instance.
	ProtocolVersion effectiveVersion() @safe
	{
		return effectiveVersion_;
	}

	/// Delegate the connection token to the wrapped transport context: the
	/// `RequestScope` is a per-request decorator, so the connection identity is
	/// whatever the underlying transport reported (empty when it is not
	/// connection-scoped).
	string connectionToken() @safe
	{
		return connectionTokenOf(inner);
	}

	/// Delegate the per-session/per-request `ConnectionState` to the wrapped
	/// transport context: the `RequestScope` is a per-request
	/// decorator, so the scoped state is whatever the underlying transport
	/// resolved for this request (null when the transport carries none, e.g. stdio
	/// / in-process, where the server falls back to its single `activeConnection`).
	ConnectionState connectionState() @safe
	{
		return connectionStateOf(inner);
	}

	/// True once the client has cancelled this request via
	/// `notifications/cancelled`. Reads the shared token the server installed for
	/// this request; if none was installed it delegates to the wrapped context.
	bool isCancelled() @safe
	{
		// Every transport delivers inbound concurrently with an in-flight handler
		// (stdio runs handlers in their own task while the channel's read loop
		// dispatches an inbound notifications/cancelled, flipping this shared token;
		// Streamable HTTP delivers the cancellation on a separate request), so
		// observe the token directly.
		if (cancellation !is null && cancellation.cancelled)
			return true;
		return inner.isCancelled();
	}

	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe
	{
		inner.reportProgress(progress, total, message);
	}

	/// Emit a logging notification, but drop it when its severity is below the
	/// client-configured minimum (`logging/setLevel`) per the RFC 5424 ordering.
	/// This is where the server honours "Only sends error level and above".
	///
	/// On the draft (stateless) protocol the server MUST NOT emit
	/// `notifications/message` for a request that did not carry
	/// `_meta["io.modelcontextprotocol/logLevel"]`; the server signals that by
	/// constructing this scope with `loggingRequested = false`, in which case
	/// every log is dropped regardless of severity.
	void log(string level, Json data, string logger = null) @safe
	{
		if (!loggingRequested)
			return;
		if (!shouldLog(level, minLevel))
			return;
		inner.log(level, data, logger);
	}

	Json sampleRaw(Json params) @safe
	{
		return inner.sampleRaw(params);
	}

	Json elicitRaw(Json params) @safe
	{
		return inner.elicitRaw(params);
	}

	Json listRootsRaw() @safe
	{
		return inner.listRootsRaw();
	}

	bool clientSupports(ClientCapability cap) @safe
	{
		return inner.clientSupports(cap);
	}

	bool isStateless() @safe
	{
		return stateless;
	}

	Json[string] inputResponses() @safe
	{
		return responses;
	}

	string requestState() @safe
	{
		return requestState_;
	}

	TokenInfo auth() @safe
	{
		return inner.auth();
	}
}

version (unittest) private final class SamplingProbe : BaseRequestContext
{
	Json lastParams;

	override Json sampleRaw(Json params) @safe
	{
		lastParams = params;
		// Echo back a typed-looking sampling result.
		Json r = Json.emptyObject;
		r["role"] = "assistant";
		Json content = Json.emptyObject;
		content["type"] = "text";
		content["text"] = "echoed";
		r["content"] = content;
		r["model"] = "test-model";
		r["stopReason"] = "endTurn";
		return r;
	}

	override bool clientSupports(ClientCapability cap) @safe
	{
		return cap == ClientCapability.sampling;
	}
}

version (unittest) private final class RootsProbe : BaseRequestContext
{
	string lastMethod;
	Json lastParams;
	bool supportsRoots = true;

	override Json listRootsRaw() @safe
	{
		lastMethod = "roots/list";
		lastParams = Json.emptyObject;
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		Json root = Json.emptyObject;
		root["uri"] = "file:///home/user/project";
		root["name"] = "My Project";
		arr ~= root;
		r["roots"] = arr;
		return r;
	}

	override bool clientSupports(ClientCapability cap) @safe
	{
		return cap == ClientCapability.roots && supportsRoots;
	}
}

version (unittest) private final class ElicitProbe : BaseRequestContext
{
	string lastMethod;
	Json lastParams;
	bool supportsElicitation = true;
	/// Per-mode submodes. When `supportsElicitation` is true these default to
	/// true so a bare elicitation declaration behaves like form+url; tests set
	/// them individually to model form-only / url-only clients.
	bool supportsForm = true;
	bool supportsUrl = true;
	bool stateless = false;
	/// MRTR round-2 answers a test can populate to exercise `inputResponseAs!T`.
	Json[string] responses;

	override Json elicitRaw(Json params) @safe
	{
		lastMethod = "elicitation/create";
		lastParams = params;
		Json r = Json.emptyObject;
		r["action"] = "accept";
		return r;
	}

	override bool clientSupports(ClientCapability cap) @safe
	{
		switch (cap)
		{
		case ClientCapability.elicitation:
			return supportsElicitation;
		case ClientCapability.elicitationForm:
			return supportsElicitation && supportsForm;
		case ClientCapability.elicitationUrl:
			return supportsElicitation && supportsUrl;
		default:
			return false;
		}
	}

	override bool isStateless() @safe
	{
		return stateless;
	}

	override Json[string] inputResponses() @safe
	{
		return responses;
	}
}

unittest  // elicitUrl() emits mode:"url" with message, url, and elicitationId
{
	auto probe = new ElicitProbe;
	auto result = probe.elicitUrl("Authorize access", "https://example.com/consent", "elic-123");

	assert(probe.lastMethod == "elicitation/create");
	assert(probe.lastParams["mode"].get!string == "url");
	assert(probe.lastParams["message"].get!string == "Authorize access");
	assert(probe.lastParams["url"].get!string == "https://example.com/consent");
	assert(probe.lastParams["elicitationId"].get!string == "elic-123");
	assert(result.action == ElicitAction.accept);
}

unittest  // form-mode elicit() does not set a mode field
{
	auto probe = new ElicitProbe;
	probe.elicit("Pick one", Json.emptyObject);

	assert(probe.lastParams["mode"].type == Json.Type.undefined);
	assert(probe.lastParams["message"].get!string == "Pick one");
}

unittest  // elicitUrl() rejects an empty url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "", "elic-1"));
}

unittest  // elicitUrl() rejects an empty elicitationId
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", ""));
}

unittest  // elicitUrl() rejects a malformed (non-URI) url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "not a url", "elic-1"));
}

unittest  // elicitUrl() rejects a relative url without a scheme/authority
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "example.com/path", "elic-1"));
}

unittest  // elicitUrl() throws when the client does not support elicitation
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	probe.supportsElicitation = false;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // elicitUrl() is rejected on a stateless (MRTR) request
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	probe.stateless = true;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // form-mode elicit() throws when the client supports url mode only
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	// Per client/elicitation: "Servers MUST NOT send elicitation requests with
	// modes that are not supported by the client." A url-only client
	// (elicitation:{url:{}}) must not be sent a form-mode request.
	auto probe = new ElicitProbe;
	probe.supportsForm = false;
	probe.supportsUrl = true;
	assertThrown!McpException(probe.elicit("Pick one", Json.emptyObject));
}

unittest  // url-mode elicitUrl() throws when the client supports form mode only
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	// A form-only client (elicitation:{} or {form:{}}) must not be sent a
	// url-mode request.
	auto probe = new ElicitProbe;
	probe.supportsForm = true;
	probe.supportsUrl = false;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // form-mode elicit() succeeds when the client supports form mode
{
	auto probe = new ElicitProbe;
	probe.supportsForm = true;
	probe.supportsUrl = false;
	probe.elicit("Pick one", Json.emptyObject);
	assert(probe.lastMethod == "elicitation/create");
}

unittest  // url-mode elicitUrl() succeeds when the client supports url mode
{
	auto probe = new ElicitProbe;
	probe.supportsForm = false;
	probe.supportsUrl = true;
	auto r = probe.elicitUrl("msg", "https://example.com", "elic-1");
	assert(probe.lastParams["mode"].get!string == "url");
	assert(r.action == ElicitAction.accept);
}

unittest  // form-mode elicit() returns a typed ElicitResult with the parsed action
{
	auto probe = new ElicitProbe;
	ElicitResult r = probe.elicit("Pick one", Json.emptyObject);
	assert(r.action == ElicitAction.accept);
}

unittest  // elicit!T derives requestedSchema from the struct via jsonSchemaOf
{
	import mcp.protocol.schema : jsonSchemaOf;

	static struct TripDetails
	{
		int travelers;
		bool insurance;
	}

	auto probe = new ElicitProbe;
	ElicitResult r = probe.elicit!TripDetails("Trip details?");
	assert(probe.lastMethod == "elicitation/create");
	assert(probe.lastParams["message"].get!string == "Trip details?");
	assert(probe.lastParams["requestedSchema"] == jsonSchemaOf!TripDetails);
	assert(r.action == ElicitAction.accept);
}

unittest  // elicit!T rejects a non-flat (nested) struct at compile time
{
	static struct Inner
	{
		int x;
	}

	static struct Nested
	{
		Inner inner;
	}

	auto probe = new ElicitProbe;
	static assert(!__traits(compiles, probe.elicit!Nested("nope")));
}

unittest  // inputResponseAs!T decodes a typed answer from the MRTR inputResponses map
{
	auto probe = new ElicitProbe;
	Json c = Json.emptyObject;
	c["name"] = "Ada";
	probe.responses["q1"] = ElicitResult.accept(c).toJson();

	auto r = probe.inputResponseAs!ElicitResult("q1");
	assert(r.action == ElicitAction.accept);
	assert(r.content["name"].get!string == "Ada");
}

unittest  // listRoots() sends roots/list and parses the typed result
{
	auto probe = new RootsProbe;
	auto result = probe.listRoots();

	assert(probe.lastMethod == "roots/list");
	assert(result.roots.length == 1);
	assert(result.roots[0].uri == "file:///home/user/project");
	assert(result.roots[0].name.get == "My Project");
}

unittest  // listRoots() throws when client does not support roots
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new RootsProbe;
	probe.supportsRoots = false;
	assertThrown!McpException(probe.listRoots());
}

unittest  // typed sample() builds params and parses the typed result
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage, StopReason;
	import mcp.protocol.types : Content;

	auto probe = new SamplingProbe;
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 50;
	auto result = probe.sample(req);

	// Request was serialized to the wire shape.
	assert(probe.lastParams["messages"][0]["content"]["text"].get!string == "hi");
	assert(probe.lastParams["maxTokens"].get!long == 50);

	// Result parsed into a typed struct.
	assert(result.role == "assistant");
	assert(result.content.text == "echoed");
	assert(result.model == "test-model");
	assert(result.stopReasonEnum.get == StopReason.endTurn);
}

unittest  // sample() gates toolChoice (without tools) on the sampling.tools capability
{
	import std.exception : assertThrown;
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage, ToolChoice;
	import mcp.protocol.types : Content;

	// Probe advertises "sampling" but not "sampling.tools".
	auto probe = new SamplingProbe;
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 50;
	req.toolChoice = ToolChoice(Nullable!string("none")); // toolChoice set, no tools
	assertThrown!McpException(probe.sample(req));
}

version (unittest) private final class LogProbe : BaseRequestContext
{
	string[] emittedLevels;

	override void log(string level, Json, string = null) @safe
	{
		emittedLevels ~= level;
	}
}

unittest  // RequestScope drops log messages below the configured minimum level
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto scope_ = new RequestScope(probe, false, empty, "error");

	scope_.log("debug", Json("d"));
	scope_.log("warning", Json("w"));
	scope_.log("error", Json("e"));
	scope_.log("critical", Json("c"));

	// Only error and above passed through to the inner transport context.
	assert(probe.emittedLevels == ["error", "critical"]);
}

unittest  // RequestScope with the default "info" minimum drops only debug
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto scope_ = new RequestScope(probe, false, empty);

	scope_.log("debug", Json("d"));
	scope_.log("info", Json("i"));
	scope_.log("warning", Json("w"));

	assert(probe.emittedLevels == ["info", "warning"]);
}

unittest  // RequestScope exposes the shared cancellation token via isCancelled
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto token = new CancellationToken;
	auto scope_ = new RequestScope(probe, false, empty, "info", true, token);

	assert(!scope_.isCancelled);
	token.cancel();
	assert(scope_.isCancelled);
}

unittest  // a CancellationToken starts uncancelled and cancel() is idempotent
{
	auto token = new CancellationToken;
	assert(!token.cancelled);
	token.cancel();
	assert(token.cancelled);
	token.cancel();
	assert(token.cancelled);
}

unittest  // NullContext reports never-cancelled (no out-of-band channel)
{
	auto ctx = new NullContext;
	assert(!ctx.isCancelled);
}

unittest  // a stateless server's StdioContext refuses server->client requests on every transport
{
	import mcp.protocol.errors : McpException;
	import std.exception : assertThrown;

	// serverStateless = true mirrors McpServer.stateless(): even though the stdio
	// channel is physically bidirectional, a stateless server has no per-peer
	// connection to carry the round-trip, so elicit/sample/roots are refused —
	// matching the HTTP transport rather than special-casing stdio.
	auto ctx = new StdioContext((string) @safe {}, (string m, Json p) @safe => Json.emptyObject,
			ClientCapabilities.init, Json.undefined, latestStable, true);
	assertThrown!McpException(ctx.sampleRaw(Json.emptyObject));
	assertThrown!McpException(ctx.elicitRaw(Json.emptyObject));
	assertThrown!McpException(ctx.listRootsRaw());
}

unittest  // a stateful StdioContext issues server->client requests through the channel
{
	bool called;
	auto ctx = new StdioContext((string) @safe {}, (string m, Json p) @safe {
		called = true;
		return Json.emptyObject;
	}, ClientCapabilities.init, Json.undefined, latestStable, false);
	ctx.listRootsRaw();
	assert(called);
}

unittest  // StdioContext.log serialises a notifications/message frame to the sink
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("warning", Json("hi"), "lg");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["jsonrpc"].get!string == "2.0");
	assert(j["method"].get!string == "notifications/message");
	assert(j["params"]["level"].get!string == "warning");
	assert(j["params"]["logger"].get!string == "lg");
	assert(j["params"]["data"].get!string == "hi");
	assert("id" !in j);
}

unittest  // StdioContext.log omits the optional logger field when none is given
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("info", Json("plain"));
	auto j = parseJsonString(frames[0]);
	assert("logger" !in j["params"]);
}

unittest  // StdioContext.log always emits the REQUIRED data field, even for an undefined payload
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("info", Json.undefined);
	auto j = parseJsonString(frames[0]);
	// `data` is required by server/utilities/logging; an undefined payload
	// must serialise as an explicit JSON null rather than being dropped.
	assert("data" in j["params"]);
	assert(j["params"]["data"].type == Json.Type.null_);
}

unittest  // StdioContext.reportProgress emits a frame only with a progress token
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto withTok = new StdioContext((string s) @safe { frames ~= s; }, Json("tok"));
	withTok.reportProgress(0.25, nullableProgress(0.5), "quarter");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["method"].get!string == "notifications/progress");
	assert(j["params"]["progressToken"].get!string == "tok");
	assert(j["params"]["progress"].get!double == 0.25);
	assert(j["params"]["total"].get!double == 0.5);
	assert(j["params"]["message"].get!string == "quarter");
}

unittest  // StdioContext.reportProgress omits `message` on a 2024-11-05 peer
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; }, Json("tok"),
			ProtocolVersion.v2024_11_05);
	ctx.reportProgress(0.25, nullableProgress(0.5), "quarter");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["params"]["progressToken"].get!string == "tok");
	assert(j["params"]["progress"].get!double == 0.25);
	assert(j["params"]["total"].get!double == 0.5);
	// 2024-11-05 ProgressNotification params are {progressToken, progress, total?}
	// with NO `message`; the field must be absent.
	assert("message" !in j["params"]);
}

unittest  // StdioContext.reportProgress keeps `message` from 2025-03-26 onward
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; }, Json("tok"),
			ProtocolVersion.v2025_03_26);
	ctx.reportProgress(0.25, Nullable!double.init, "quarter");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["params"]["message"].get!string == "quarter");
}

unittest  // StdioContext.reportProgress is a no-op without a progress token
{
	string[] frames;
	auto noTok = new StdioContext((string s) @safe { frames ~= s; });
	noTok.reportProgress(0.9);
	assert(frames.length == 0);
}

unittest  // StdioContext has no server->client request channel
{
	import mcp.protocol.errors : McpException;

	auto ctx = new StdioContext((string) @safe {});
	assert(!ctx.clientSupports(ClientCapability.sampling));
	assert(!ctx.isCancelled);
	bool threw;
	try
		ctx.sampleRaw(Json.emptyObject);
	catch (McpException)
		threw = true;
	assert(threw);
}

version (unittest) private Nullable!double nullableProgress(double v) @safe
{
	Nullable!double n = v;
	return n;
}

version (unittest) private final class StateProbe : BaseRequestContext
{
	string state;
	Json[string] responses;

	override bool isStateless() @safe
	{
		return true;
	}

	override Json[string] inputResponses() @safe
	{
		return responses;
	}

	override string requestState() @safe
	{
		return state;
	}
}

unittest  // requestStateAs!T decodes a JSON-string requestState into a struct
{
	import vibe.data.json : serializeToJson;

	static struct Cursor
	{
		int step;
		string phase;
	}

	auto probe = new StateProbe;
	// Mirrors the server-side contract: requestState carries
	// serializeToJson(state).toString().
	probe.state = serializeToJson(Cursor(3, "review")).toString();

	auto c = probe.requestStateAs!Cursor;
	assert(c.step == 3);
	assert(c.phase == "review");
}

unittest  // requestStateAs!T returns T.init when requestState is empty
{
	static struct Cursor
	{
		int step;
		string phase;
	}

	auto probe = new StateProbe;
	assert(probe.state.length == 0);

	auto c = probe.requestStateAs!Cursor;
	assert(c == Cursor.init);
}

unittest  // typed log(LogLevel, string) emits the same frame as the string/Json form
{
	auto probe = new LogProbe;
	RequestContext ctx = probe;
	ctx.log(LogLevel.warning, "disk almost full");
	assert(probe.emittedLevels == ["warning"]);
}

unittest  // typed log(LogLevel, string) carries the message as a Json string payload to the inner overload
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	RequestContext ctx = new StdioContext((string str) @safe { frames ~= str; });
	ctx.log(LogLevel.error, "boom", "lg");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["params"]["level"].get!string == "error");
	assert(j["params"]["data"].get!string == "boom");
	assert(j["params"]["logger"].get!string == "lg");
}

unittest  // reportProgress(long, long) forwards integer steps to the double/Nullable form
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	RequestContext ctx = new StdioContext((string str) @safe { frames ~= str; }, Json("tok"));
	ctx.reportProgress(3L, 10L, "step 3 of 10");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["params"]["progress"].to!double == 3.0);
	assert(j["params"]["total"].to!double == 10.0);
	assert(j["params"]["message"].get!string == "step 3 of 10");
}

unittest  // hasInputResponse reports whether the resubmitted request carries an answer for id
{
	auto probe = new StateProbe;
	assert(!probe.hasInputResponse("q1"));
	probe.responses["q1"] = Json.emptyObject;
	assert(probe.hasInputResponse("q1"));
	assert(!probe.hasInputResponse("q2"));
}

unittest  // isResubmit is true exactly when inputResponses is non-empty
{
	auto probe = new StateProbe;
	assert(!probe.isResubmit);
	probe.responses["q1"] = Json.emptyObject;
	assert(probe.isResubmit);
}

unittest  // typed log(LogLevel, Json) carries an arbitrary JSON payload to the inner overload
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	RequestContext ctx = new StdioContext((string str) @safe { frames ~= str; });
	Json payload = Json.emptyObject;
	payload["component"] = "db";
	payload["retries"] = 3;
	ctx.log(LogLevel.warning, payload, "lg");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["params"]["level"].get!string == "warning");
	assert(j["params"]["data"]["component"].get!string == "db");
	assert(j["params"]["data"]["retries"].get!long == 3);
	assert(j["params"]["logger"].get!string == "lg");
}

unittest  // sample() on a stateless (MRTR) request throws an internalError (server fault)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	auto probe = new StateProbe; // isStateless() == true
	bool threw;
	try
		probe.sample(Json.emptyObject);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}

unittest  // listRoots() on a stateless (MRTR) request throws an internalError (server fault)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	// roots/list is a server->client round-trip like sample/elicit, so it has no
	// channel on the stateless protocol and must fail fast (use MRTR instead).
	auto probe = new StateProbe; // isStateless() == true
	bool threw;
	try
		probe.listRoots();
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}

unittest  // elicit() on a stateless (MRTR) request throws an internalError (server fault)
{
	import mcp.protocol.errors : McpException, ErrorCode;
	import std.algorithm.searching : canFind;

	auto probe = new ElicitProbe;
	probe.stateless = true;
	bool threw;
	try
		probe.elicit("Pick one", Json.emptyObject);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
		// The message must name both stateless remedies: the MRTR escape hatch
		// (ToolResponse.inputRequired) and the stateful-server construction.
		assert(e.msg.canFind("ToolResponse.inputRequired"),
				"the stateless elicit error must name ToolResponse.inputRequired");
		assert(e.msg.canFind("McpServer.stateful()"),
				"the stateless elicit error must name McpServer.stateful()");
	}
	assert(threw);
}

unittest  // elicitUrl() on a stateless (MRTR) request throws an internalError (server fault)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	auto probe = new ElicitProbe;
	probe.stateless = true;
	bool threw;
	try
		probe.elicitUrl("msg", "https://example.com", "elic-1");
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}
