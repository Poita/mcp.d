module mcp.server.server;

import core.time : Duration, seconds;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.versions;
import mcp.protocol.errors;
import mcp.protocol.jsonrpc;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.protocol.draft;
import mcp.server.context;
import mcp.transport.sse_context : ServerPushChannel, StreamCoordinator, SubscriptionFilter;

@safe:

/// A tool handler receiving the parsed arguments and the per-request context.
alias ToolHandler = CallToolResult delegate(Json arguments, RequestContext ctx) @safe;

/// A tool handler that may, on a stateless (MRTR) request, ask the client for
/// more input instead of returning a final result. See `ToolResponse`.
alias MrtrToolHandler = ToolResponse delegate(Json arguments, RequestContext ctx) @safe;

/// The outcome of a tool call: either the final `CallToolResult`, or — on a
/// stateless (MRTR) request — a set of `InputRequest`s the client must satisfy
/// and resubmit. There is no suspension or shared state: `inputRequired` simply
/// ends this request, and the client opens a fresh one carrying the answers.
struct ToolResponse
{
	private bool needsInput_;
	private CallToolResult result_;
	private InputRequiredResult required_;

	/// The handler is done; `r` is the final result.
	static ToolResponse complete(CallToolResult r) @safe
	{
		ToolResponse t;
		t.result_ = r;
		return t;
	}

	/// The handler needs input; the client must gather it and resubmit with the
	/// matching `inputResponses`.
	static ToolResponse inputRequired(InputRequest[] requests) @safe
	{
		ToolResponse t;
		t.needsInput_ = true;
		t.required_.inputRequests = requests;
		return t;
	}

	/// As `inputRequired`, but also attaches an opaque `requestState`
	/// (SEP-2322): a stateless draft server encodes whatever context it needs
	/// to resume the call into this blob, which the client echoes verbatim on
	/// the retry and the handler reads back via `RequestContext.requestState`.
	static ToolResponse inputRequired(InputRequest[] requests, string requestState) @safe
	{
		ToolResponse t;
		t.needsInput_ = true;
		t.required_.inputRequests = requests;
		t.required_.requestState = requestState;
		return t;
	}

	/// Whether this outcome asks the client for more input.
	bool needsInput() const @safe
	{
		return needsInput_;
	}

	/// The JSON-RPC `result` payload (a `CallToolResult` or an
	/// `InputRequiredResult`).
	Json toJson() const @safe
	{
		return needsInput_ ? required_.toJson() : result_.toJson();
	}
}

/// A registered tool: its descriptor plus the handler that executes it. The
/// handler always returns a `ToolResponse`; the `CallToolResult`-returning
/// registration overloads are adapted to one that always `complete`s.
struct RegisteredTool
{
	Tool descriptor;
	MrtrToolHandler handler;
}

/// A registered direct resource: descriptor + reader producing its contents.
struct RegisteredResource
{
	Resource descriptor;
	ResourceContents delegate() @safe reader;
	/// Per-resource draft `CacheableResult` freshness hint for `resources/read`.
	Nullable!CacheHint cache;
}

/// A registered resource template: descriptor + reader receiving the concrete
/// URI and the captured `{var}` parameters.
struct RegisteredTemplate
{
	ResourceTemplate descriptor;
	ResourceContents delegate(string uri, string[string] params) @safe reader;
	/// Per-template draft `CacheableResult` freshness hint for `resources/read`.
	Nullable!CacheHint cache;
}

/// A registered prompt: descriptor + handler producing its messages.
struct RegisteredPrompt
{
	Prompt descriptor;
	GetPromptResult delegate(Json arguments) @safe handler;
}

/// The transport-agnostic core of an MCP server.
///
/// `McpServer` owns registration and JSON-RPC dispatch. It has no I/O: feed it
/// parsed messages via `handle` (or raw text via `handleRaw`) and it returns the
/// response to write back. Transports (stdio, HTTP) are thin drivers over this.
final class McpServer
{
	private string serverName;
	private string serverVersion;
	private Implementation serverInfo_;
	private Nullable!string instructions;
	private RegisteredTool[string] tools;
	private RegisteredResource[string] resources;
	private RegisteredTemplate[] templates;
	private RegisteredPrompt[string] prompts;
	private CompleteResult delegate(CompleteRequest request) @safe typedCompletionHandler;
	private bool loggingEnabled;
	private string logLevel = "info";
	private bool resourceSubscriptionsEnabled;
	private bool[string] subscriptions;
	private Nullable!TasksCapability tasksCapability;
	private Json extensions = Json.undefined;
	private ProtocolVersion negotiated = latestStable;
	// The protocol version pinned for this CONNECTION's server-initiated push
	// traffic (the standalone GET SSE stream / stdio listen channel). Set at
	// `initialize` (to the negotiated version) and when a draft stdio
	// `subscriptions/listen` session opens. It governs draft notification
	// suppression/filtering on the unsolicited push path, which fires outside any
	// request, so it cannot be a per-request value. Per-request dispatch no longer
	// touches this field (issue #288): each request's effective version lives on
	// its RequestScope.
	private ProtocolVersion connectionVersion = latestStable;
	private ClientCapabilities clientCaps;
	private bool initialized;
	// Per-list draft `CacheableResult` freshness hints, keyed by the list method
	// ("tools/list", "resources/list", "resources/templates/list", "prompts/list").
	// Set via `setListCacheHint`; applied by the matching `do*` handler.
	private Nullable!CacheHint[string] listCacheHints;
	// Maximum number of items returned per `*/list` page. 0 (the default) means
	// unbounded: the full list is returned in a single response with no cursor.
	private size_t pageSize_;
	private bool[string] listenFilters;
	// The exact resource URIs the client opted into via `subscriptions/listen`
	// (the `resourceSubscriptions` string[] of a draft `SubscriptionFilter`),
	// preserved in request order so the acknowledgement can echo the agreed
	// list. Kept separate from the legacy flat `subscriptions` map (which also
	// holds `resources/subscribe` URIs) so the two cannot be confused.
	private string[] listenResourceUris;
	// The per-stream `SubscriptionFilter` parsed from the most recent
	// `subscriptions/listen` request. The transport reads it right after routing the
	// listen request so it can attach the exact opt-in to that one stream's push
	// listener (draft basic/utilities/subscriptions §Notification Filter / Multiple
	// Concurrent Subscriptions). Kept separate from the global `listenFilters` (which
	// still drives the acknowledgement echo) so concurrent streams do not blur.
	private SubscriptionFilter lastListenFilter_;
	private ServerPushChannel pushChannel;
	// The stdio `subscriptions/listen` delivery channel (draft only). On the
	// stdio transport every message shares the single stdout channel, so there
	// is no separate SSE push stream: when a draft `subscriptions/listen`
	// arrives, the transport installs a raw-JSON-line sink here and the listen
	// request's id becomes the stream's subscriptionId. `notify` then writes
	// each opted-in change notification (stamped with that subscriptionId in
	// `params._meta`, per draft basic/utilities/subscriptions) onto stdout in
	// addition to any HTTP push channel. Null when no stdio listen is active,
	// keeping the HTTP-only behaviour unchanged.
	private void delegate(string) @safe stdioListenSink;
	private string stdioListenSubscriptionId;
	private bool toolListChangedEnabled;
	private bool resourcesListChangedEnabled;
	private bool promptsListChangedEnabled;
	private bool validateOutputSchema_;
	private bool validateInputSchema_;
	// In-flight requests, keyed by their JSON-RPC id (string form), each holding
	// a shared cancellation token. Populated for the duration of a request so an
	// inbound `notifications/cancelled` can flip the matching token and the
	// request's response can be suppressed (basic/utilities/cancellation).
	private CancellationToken[string] inFlight;
	// Observer for inbound client-originated notifications (e.g.
	// `notifications/roots/list_changed`). Invoked from `handleNotification`
	// for any notification the server does not itself consume, giving the
	// application a public surface to react to client notifications. Mirrors
	// the client's `onNotification` hook. Set via
	// `setClientNotificationHandler`.
	private void delegate(string method, Json params) @safe onClientNotification_;
	// Convenience observer for `notifications/roots/list_changed`: when the
	// client signals its root list changed, the application can re-call
	// `ctx.listRoots()` to refresh. Invoked in addition to
	// `onClientNotification_`. Set via `setRootsListChangedHandler`.
	private void delegate() @safe onRootsListChanged_;

	this(string name, string version_, Nullable!string instructions = Nullable!string.init) @safe
	{
		this(Implementation(name, version_), instructions);
	}

	/// Construct a server from a fully-populated `Implementation`, letting the
	/// author advertise a display `title` (>= 2025-06-18) plus `description`,
	/// `websiteUrl`, and `icons` (>= 2025-11-25) in the `initialize` /
	/// `server/discover` `serverInfo`. Fields newer than the negotiated protocol
	/// version are stripped from the wire response (see `Implementation.forVersion`),
	/// so older peers see only what they understand. Mirrors the client's full
	/// `Implementation clientInfo` support.
	this(Implementation serverInfo, Nullable!string instructions = Nullable!string.init) @safe
	{
		this.serverInfo_ = serverInfo;
		this.serverName = serverInfo.name;
		this.serverVersion = serverInfo.version_;
		this.instructions = instructions;
	}

	/// The protocol version negotiated with the client (valid after `initialize`).
	ProtocolVersion negotiatedVersion() const @safe
	{
		return negotiated;
	}

	/// Register a *dynamic* tool with a context-aware handler (progress /
	/// logging / sampling / elicitation available via `ctx`).
	///
	/// This is the explicit escape hatch for runtime-defined tools whose
	/// `inputSchema` is built at runtime and therefore have no compile-time D
	/// type: the handler receives the raw `Json arguments` as they arrived on the
	/// wire. For a statically-typed tool, prefer the UDA layer
	/// (`@tool`-annotated methods registered via `registerTools`), which marshals
	/// typed parameters for you and dispatches through this same dynamic path.
	void registerDynamicTool(Tool descriptor, ToolHandler handler) @safe
	{
		tools[descriptor.name] = RegisteredTool(descriptor, (Json args,
				RequestContext ctx) => ToolResponse.complete(handler(args, ctx)));
	}

	/// Register a *dynamic* tool with a simple handler that ignores the request
	/// context. See `registerDynamicTool(Tool, ToolHandler)` for when to use the
	/// dynamic path versus the typed UDA layer.
	void registerDynamicTool(Tool descriptor, CallToolResult delegate(Json) @safe handler) @safe
	{
		tools[descriptor.name] = RegisteredTool(descriptor, (Json args,
				RequestContext) => ToolResponse.complete(handler(args)));
	}

	/// Register a *dynamic* tool whose handler may ask the client for more input
	/// on a stateless (MRTR) request. The handler branches on `ctx.isStateless`:
	/// when stateless it reads `ctx.inputResponses` and returns either
	/// `ToolResponse.complete` or `ToolResponse.inputRequired`; otherwise it may
	/// call the blocking `ctx.elicit`/`ctx.sample`. A server that wants to serve
	/// both protocol eras handles both branches here.
	void registerDynamicTool(Tool descriptor, MrtrToolHandler handler) @safe
	{
		tools[descriptor.name] = RegisteredTool(descriptor, handler);
	}

	/// Unregister a previously registered tool by name. Returns `true` if a tool
	/// was removed, `false` if no tool with that name was registered. Pair with
	/// `notifyToolsListChanged` to inform connected clients that the tool list
	/// changed.
	bool removeTool(string name) @safe
	{
		if ((name in tools) is null)
			return false;
		tools.remove(name);
		return true;
	}

	/// Advertise the tools `listChanged` capability so `capabilities()` emits
	/// `tools: { listChanged: true }`. Declare this (before `initialize` /
	/// `server/discover`) when the server may add or remove tools at runtime and
	/// will emit `notifications/tools/list_changed` via `notifyToolsListChanged`.
	void enableToolListChanged() @safe
	{
		toolListChangedEnabled = true;
	}

	/// Opt in to validating each tool's `structuredContent` against its
	/// registered `outputSchema` before the result is sent. Per the spec,
	/// "If an output schema is provided: Servers MUST provide structured results
	/// that conform to this schema." With validation enabled, a handler that
	/// emits non-conforming `structuredContent` surfaces a clear internal error
	/// (so the bug is caught at the server) rather than silently shipping bad
	/// output. Tools without an `outputSchema`, and results without
	/// `structuredContent`, are unaffected. Off by default to preserve existing
	/// behaviour.
	void enableOutputSchemaValidation() @safe
	{
		validateOutputSchema_ = true;
	}

	/// Opt in to validating each tool call's `arguments` against the tool's
	/// registered `inputSchema` before the handler is invoked. Per the spec
	/// (server/tools § Security Considerations, all versions), "Servers MUST:
	/// Validate all tool inputs". § Error Handling classifies an inputSchema
	/// violation (missing required property or wrong type) as an
	/// *input-validation* error, i.e. a Tool Execution Error: with validation
	/// enabled, a `tools/call` whose arguments do not conform yields a
	/// `CallToolResult` with `isError:true` and a descriptive text content
	/// block (so the model can self-correct), NOT a JSON-RPC -32602 protocol
	/// error. Tools without an `inputSchema` are unaffected. Off by default to
	/// preserve existing behaviour.
	void enableInputSchemaValidation() @safe
	{
		validateInputSchema_ = true;
	}

	/// Broadcast a `notifications/tools/list_changed` to every client listening
	/// on the standalone GET SSE stream, informing them the set of available
	/// tools changed (per the server/tools List Changed Notification). Returns
	/// the number of listeners reached; `0` when no GET stream is open. Call
	/// after a runtime `registerDynamicTool` / `removeTool`. For the draft protocol,
	/// the notification is suppressed unless a client opted in via
	/// `subscriptions/listen` with `toolsListChanged:true`.
	size_t notifyToolsListChanged() @safe
	{
		return notifyChange("notifications/tools/list_changed", Json.undefined, "");
	}

	/// Broadcast a `notifications/resources/list_changed` to every client
	/// listening on the standalone GET SSE stream, informing them the set of
	/// available resources changed (per the server/resources List Changed
	/// Notification). Returns the number of listeners reached; `0` when no GET
	/// stream is open. Call after a runtime `registerResource` /
	/// `registerResourceTemplate` (or a removal). For the draft protocol, the
	/// notification is suppressed unless a client opted in via
	/// `subscriptions/listen` with `resourcesListChanged:true`.
	size_t notifyResourcesListChanged() @safe
	{
		return notifyChange("notifications/resources/list_changed", Json.undefined, "");
	}

	/// Broadcast a `notifications/prompts/list_changed` to every client listening
	/// on the standalone GET SSE stream, informing them the set of available
	/// prompts changed (per the server/prompts List Changed Notification).
	/// Returns the number of listeners reached; `0` when no GET stream is open.
	/// Call after a runtime `registerDynamicPrompt` (or a removal). For the draft
	/// protocol, the notification is suppressed unless a client opted in via
	/// `subscriptions/listen` with `promptsListChanged:true`.
	size_t notifyPromptsListChanged() @safe
	{
		return notifyChange("notifications/prompts/list_changed", Json.undefined, "");
	}

	/// Notify subscribers that a watched resource changed by emitting a
	/// `notifications/resources/updated` on the standalone GET SSE stream (per
	/// server/resources Subscriptions: "Server delivers
	/// notifications/resources/updated ... whenever a watched resource
	/// changes"). Per `ResourceUpdatedNotificationParams` in every spec version
	/// (2024-11-05 .. 2025-11-25 .. draft) the params carry exactly `{ "uri": ... }`
	/// (plus the inherited optional `_meta`); there is no `title` field on this
	/// notification (a resource's title lives on the `Resource` object in
	/// `resources/list`). It is delivered only when a client is currently
	/// subscribed to `uri` (via `resources/subscribe`); for an unsubscribed URI
	/// it is a no-op returning `0`. For the draft protocol the notification is
	/// additionally suppressed unless a client opted in via `subscriptions/listen`
	/// with `resourceSubscriptions:true`. Returns the number of GET-stream
	/// listeners reached; `0` when no GET stream is open.
	size_t notifyResourceUpdated(string uri) @safe
	{
		if (!isSubscribed(uri))
			return 0;
		if (connectionVersion.isDraft && !listensFor("resourceSubscriptions"))
			return 0;
		Json params = Json.emptyObject;
		params["uri"] = uri;
		return notifyChange("notifications/resources/updated", params, uri);
	}

	/// Emit a `notifications/elicitation/complete` for a URL-mode elicitation,
	/// telling the client an out-of-band interaction it was asked to complete (via
	/// `RequestContext.elicitUrl`) has finished, so the client can stop waiting on
	/// it (basic/utilities/elicitation §"Completion Notifications for URL Mode
	/// Elicitation"). Per spec the notification MUST carry the `elicitationId` that
	/// correlates it with the original request. It is delivered on the standalone
	/// GET SSE stream (the unsolicited server->client channel); returns the number
	/// of listeners reached, or `0` when no GET stream is open (or the server is
	/// not on a Streamable HTTP transport). Throws `invalidParams` on an empty
	/// `elicitationId`.
	size_t notifyElicitationComplete(string elicitationId) @safe
	{
		if (elicitationId.length == 0)
			throw invalidParams(
					"notifications/elicitation/complete requires a non-empty elicitationId");
		Json params = Json.emptyObject;
		params["elicitationId"] = elicitationId;
		return notify("notifications/elicitation/complete", params);
	}

	/// The capabilities advertised by the connected client (valid after
	/// `initialize`).
	ClientCapabilities clientCapabilities() const @safe
	{
		return clientCaps;
	}

	/// The effective input schema of a registered tool (the default empty-object
	/// schema if none was provided), or `Json.undefined` if the tool is unknown.
	/// Used by the transport for draft `x-mcp-header` validation.
	Json toolInputSchema(string name) @safe
	{
		if (auto t = name in tools)
			return t.descriptor.toJson()["inputSchema"];
		return Json.undefined;
	}

	/// Register a direct resource with a reader for its contents. An optional
	/// per-resource draft `CacheableResult` freshness hint is emitted on this
	/// resource's `resources/read` response (draft protocol only).
	void registerResource(Resource descriptor, ResourceContents delegate() @safe reader,
			Nullable!CacheHint cache = Nullable!CacheHint.init) @safe
	{
		resources[descriptor.uri] = RegisteredResource(descriptor, reader, cache);
	}

	/// Register a resource template with a reader receiving the matched URI and
	/// captured `{var}` parameters. An optional per-template draft `CacheableResult`
	/// freshness hint is emitted on a matching `resources/read` (draft only).
	void registerResourceTemplate(ResourceTemplate descriptor, ResourceContents delegate(string uri,
			string[string] params) @safe reader, Nullable!CacheHint cache = Nullable!CacheHint.init) @safe
	{
		templates ~= RegisteredTemplate(descriptor, reader, cache);
	}

	/// Register a *dynamic* prompt with the handler that produces its messages.
	///
	/// Like `registerDynamicTool`, this is the explicit escape hatch for prompts
	/// whose argument set is defined at runtime: the handler receives the raw
	/// `Json arguments`. For statically-typed prompts, prefer the UDA layer
	/// (`@prompt`-annotated methods registered via `registerPrompts`), which
	/// marshals typed parameters and dispatches through this same dynamic path.
	void registerDynamicPrompt(Prompt descriptor, GetPromptResult delegate(Json) @safe handler) @safe
	{
		prompts[descriptor.name] = RegisteredPrompt(descriptor, handler);
	}

	/// Set the handler for `completion/complete`, receiving a parsed, typed
	/// `CompleteRequest` (the `ref`, the `argument` name/value, and any
	/// `context.arguments`) rather than raw Json. Declaring it advertises the
	/// completions capability. Use `request.isPrompt` / `request.isResource` to
	/// route to the appropriate per-target completer.
	void setCompletionRequestHandler(CompleteResult delegate(CompleteRequest request) @safe handler) @safe
	{
		typedCompletionHandler = handler;
	}

	/// Observe inbound client-originated notifications.
	///
	/// The server consumes `notifications/initialized` and
	/// `notifications/cancelled` itself; every other inbound notification
	/// (notably `notifications/roots/list_changed`) is delivered here so the
	/// application can react — for example, re-calling `ctx.listRoots()` after
	/// the client signals its root list changed (client/roots: "Servers SHOULD
	/// ... handle root list changes gracefully"). Mirrors the client-side
	/// `onNotification` observer. Purely an application-facing callback; it does
	/// not affect the JSON-RPC wire output for any protocol version.
	void setClientNotificationHandler(void delegate(string method, Json params) @safe handler) @safe
	{
		onClientNotification_ = handler;
	}

	/// Convenience observer fired specifically on
	/// `notifications/roots/list_changed`. Invoked in addition to any handler
	/// registered via `setClientNotificationHandler`. Set to react to client
	/// root-list changes without inspecting the method string yourself.
	void setRootsListChangedHandler(void delegate() @safe handler) @safe
	{
		onRootsListChanged_ = handler;
	}

	/// Advertise the logging capability and accept `logging/setLevel`.
	void enableLogging() @safe
	{
		loggingEnabled = true;
	}

	/// Advertise the resources `subscribe` capability and accept
	/// `resources/subscribe` + `resources/unsubscribe`.
	void enableResourceSubscriptions() @safe
	{
		resourceSubscriptionsEnabled = true;
	}

	/// Advertise the resources `listChanged` capability so `capabilities()`
	/// emits `resources: { listChanged: true }`. Declare this (before
	/// `initialize` / `server/discover`) when the server may add or remove
	/// resources or resource templates at runtime and will emit
	/// `notifications/resources/list_changed` via `notifyResourcesListChanged`.
	void enableResourcesListChanged() @safe
	{
		resourcesListChangedEnabled = true;
	}

	/// Advertise the prompts `listChanged` capability so `capabilities()` emits
	/// `prompts: { listChanged: true }`. Declare this (before `initialize` /
	/// `server/discover`) when the server may add or remove prompts at runtime
	/// and will emit `notifications/prompts/list_changed` via
	/// `notifyPromptsListChanged`.
	void enablePromptListChanged() @safe
	{
		promptsListChangedEnabled = true;
	}

	/// Advertise the 2025-11-25 `tasks` capability, i.e. support for
	/// task-augmented requests. `list`/`cancel` indicate support for
	/// `tasks/list` and `tasks/cancel`; `requests` is the nested-by-category
	/// object describing which requests may be task-augmented. Its spec shape is
	/// the nested form `{"tools": {"call": {}}}`, NOT a flat `"tools/call"` key.
	/// Build it with `TaskRequests`, for example
	/// `enableTasks(true, true, TaskRequests().tool().toJson())`. The capability
	/// appears in the `tasks` field of the server capabilities sent during
	/// `initialize` / `server/discover`.
	void enableTasks(bool list = true, bool cancel = true, Json requests = Json.undefined) @safe
	{
		TasksCapability t;
		t.list = list;
		t.cancel = cancel;
		t.requests = requests;
		tasksCapability = t;
	}

	/// The `tasks` capability the connected client advertised (valid after
	/// `initialize`). Null if the client advertised none.
	Nullable!TasksCapability clientTasks() const @safe
	{
		return clientCaps.tasks;
	}

	/// Advertise a draft protocol extension (e.g. "io.modelcontextprotocol/tasks")
	/// with an optional per-extension settings object. The identifier and its
	/// settings appear in the `extensions` field of the server capabilities sent
	/// during `initialize` / `server/discover`, per the draft Extension
	/// Negotiation rules. `settings` defaults to an empty object.
	void advertiseExtension(string identifier, Json settings = Json.emptyObject) @safe
	{
		if (extensions.type != Json.Type.object)
			extensions = Json.emptyObject;
		extensions[identifier] = settings;
	}

	/// The extension identifiers and settings the connected client advertised
	/// (valid after `initialize`). `Json.undefined` if the client advertised none.
	Json clientExtensions() const @safe
	{
		return clientCaps.extensions;
	}

	/// Whether a client is currently subscribed to updates for `uri`.
	bool isSubscribed(string uri) const @safe
	{
		return (uri in subscriptions) !is null;
	}

	/// The most recently set log level (default "info").
	string currentLogLevel() const @safe
	{
		return logLevel;
	}

	/// The server->client push channel for *unsolicited* traffic — the messages
	/// a server sends on the standalone SSE stream a client opens with an HTTP
	/// GET to the MCP endpoint (basic/transports §Listening for Messages from the
	/// Server), outside any in-flight POST. The Streamable HTTP transport creates
	/// it (sharing the supplied `StreamCoordinator`) when the mount is set up;
	/// it is created lazily on first access so callers can hold a reference
	/// before mounting. Use `notify` (or the returned channel's `emit`) to deliver
	/// notifications/requests to every connected GET listener.
	ServerPushChannel serverPushChannel(StreamCoordinator coord) @safe
	{
		if (pushChannel is null)
			pushChannel = new ServerPushChannel(coord);
		return pushChannel;
	}

	/// The active server->client push channel, or null if none has been created
	/// (e.g. the server is not mounted on a Streamable HTTP transport).
	ServerPushChannel serverPushChannel() @safe
	{
		return pushChannel;
	}

	/// Send an *unsolicited* JSON-RPC notification to every client currently
	/// listening on the standalone GET SSE stream. This is the public entry point
	/// for server-initiated traffic outside an in-flight request — e.g. a
	/// `notifications/resources/updated` for a subscribed resource, or a
	/// `notifications/tools/list_changed`. Returns the number of listeners the
	/// notification was delivered to; `0` when no GET stream is open (or the
	/// server is not on a Streamable HTTP transport). On a stdio server with an
	/// active draft `subscriptions/listen` it is additionally written to stdout
	/// (stamped with the listen subscriptionId), since that transport shares one
	/// channel for all server->client traffic.
	size_t notify(string method, Json params = Json.undefined) @safe
	{
		size_t delivered;
		// Stdio `subscriptions/listen` channel (draft): the single stdout channel
		// carries notifications too, stamped with the listen request's id as the
		// subscriptionId so the client can correlate them (draft basic/utilities/
		// subscriptions). This is in addition to any HTTP push channel below.
		if (stdioListenSink !is null)
		{
			auto note = withSubscriptionId(makeNotification(method, params),
					stdioListenSubscriptionId);
			stdioListenSink(note.toString());
			delivered++;
		}
		if (pushChannel !is null)
			delivered += pushChannel.notify(method, params);
		return delivered;
	}

	/// If `msg` is a draft `subscriptions/listen` request, serve it on the stdio
	/// transport's single channel and return `true`; otherwise return `false`
	/// (the caller dispatches it normally). On the stdio transport every message
	/// shares one stdout channel, so — unlike Streamable HTTP — there is no
	/// separate SSE stream to open. Per the draft, a `subscriptions/listen`
	/// reply is NOT a `{ acknowledged: true }` JSON-RPC result (the schema defines
	/// no such Result); the acknowledgement is a
	/// `notifications/subscriptions/acknowledged` notification that MUST be the
	/// first message on the stream. This records the opted-in change-notification
	/// filters, installs `writeLine` as the delivery sink (so subsequent
	/// `notify*`/`notifyResourceUpdated` are written to stdout, each stamped with
	/// the listen id as `io.modelcontextprotocol/subscriptionId`), and writes the
	/// stamped acknowledgement as that leading message. Pre-draft versions never
	/// defined `subscriptions/listen`, so they take the normal path (returns
	/// `false`) and the request is answered conventionally.
	bool tryServeStdioListen(Message msg, void delegate(string) @safe writeLine) @safe
	{
		if (msg.kind != MessageKind.request || msg.method != "subscriptions/listen")
			return false;
		auto meta = RequestMeta.fromParams(msg.params);
		ProtocolVersion mv;
		if (!meta.protocolVersion.length
				|| !tryParseVersion(meta.protocolVersion, mv) || !mv.isDraft)
			return false;

		// Pin the effective version so notify-suppression gating (listensFor) and
		// any subscriptionId stamping behave as draft for this listen session.
		connectionVersion = mv;
		clientCaps = meta.clientCapabilities;
		// Record the opted-in filters; the one-shot {acknowledged:true} result is
		// discarded (the spec defines no such Result — the ack is a notification).
		doSubscribeListen(msg.params);

		// The listen request's id is the stream's subscriptionId; every
		// notification on this channel (starting with the acknowledgement) is
		// stamped with it in `params._meta`.
		stdioListenSubscriptionId = rpcIdString(msg.id);
		stdioListenSink = writeLine;

		// First message on the stream: the acknowledgement carrying the agreed-upon
		// subset, stamped with the subscriptionId.
		Json ackParams = Json.emptyObject;
		ackParams["notifications"] = acknowledgedListenSubset();
		auto ack = withSubscriptionId(makeNotification("notifications/subscriptions/acknowledged",
				ackParams), stdioListenSubscriptionId);
		writeLine(ack.toString());
		return true;
	}

	/// Deliver a change notification on the standalone GET / `subscriptions/listen`
	/// push channel. On the draft, delivery is per-stream filtered: the notification
	/// reaches only a stream whose `subscriptions/listen` filter explicitly requested
	/// this type (and, for `notifications/resources/updated`, this `uri`), honouring
	/// draft basic/utilities/subscriptions "The server MUST NOT send notification
	/// types the client has not explicitly requested" under Multiple Concurrent
	/// Subscriptions. On 2025-11-25 / 2025-06-18 / 2025-03-26 (no `subscriptions/
	/// listen`) it is an ordinary single-stream `notify`, so the stable wire output is
	/// unchanged. Returns the number of streams reached (0 or 1).
	private size_t notifyChange(string method, Json params, string uri) @safe
	{
		size_t delivered;
		// Stdio `subscriptions/listen` channel (draft): the single stdout channel
		// carries change notifications too, stamped with the listen subscriptionId.
		// Per-stream filtering still applies — deliver only when this listen
		// stream's recorded filter opted in for the method (mirroring the GET-stream
		// eligibility below). Without this branch a stdio listener receives nothing,
		// since there is no `pushChannel` on the stdio transport.
		if (stdioListenSink !is null && connectionVersion.isDraft && globalListensForMethod(method))
		{
			auto note = withSubscriptionId(makeNotification(method, params),
					stdioListenSubscriptionId);
			stdioListenSink(note.toString());
			delivered++;
		}
		if (pushChannel !is null)
		{
			if (connectionVersion.isDraft)
			{
				// Per-stream filtering: an active `subscriptions/listen` stream receives
				// a type only if its own filter opted in. A plain GET listener (inactive
				// filter, no per-stream opt-in) falls back to the global opt-in,
				// preserving the legacy single-stream draft path while isolating
				// concurrent streams.
				const plainEligible = globalListensForMethod(method);
				delivered += pushChannel.emitFiltered(method, params, uri, plainEligible);
			}
			else
				delivered += pushChannel.notify(method, params);
		}
		return delivered;
	}

	/// Whether the server's *global* `subscriptions/listen` opt-in covers a given
	/// change-notification `method`. Used only as the fallback eligibility for plain
	/// GET listeners on the draft (active per-stream filters decide their own
	/// eligibility); the four list/subscription change methods map to their filter
	/// keys, and any other method is ungated.
	private bool globalListensForMethod(string method) @safe
	{
		switch (method)
		{
		case "notifications/tools/list_changed":
			return listensFor("toolsListChanged");
		case "notifications/prompts/list_changed":
			return listensFor("promptsListChanged");
		case "notifications/resources/list_changed":
			return listensFor("resourcesListChanged");
		case "notifications/resources/updated":
			return listensFor("resourceSubscriptions");
		default:
			return true;
		}
	}

	/// Initiate a server->client `ping` on the standalone GET SSE push channel
	/// and block until a connected client acknowledges with the spec-mandated
	/// empty result (basic/utilities/ping: "Either the client or server can
	/// initiate a ping by sending a `ping` request"). This is the server-side
	/// counterpart to `McpClient.ping()`, exposing the SHOULD-periodic
	/// connection-health probe the spec describes for either party. The probe
	/// rides the same push channel `notify` uses, and the client's reply is
	/// correlated via the shared `StreamCoordinator` when it POSTs the response.
	///
	/// Throws `internalError` when the server is not mounted on a Streamable HTTP
	/// transport (no push channel) or no client is listening on a GET stream, or
	/// on a client error / timeout (treat a timeout as a stale connection per the
	/// spec). The request carries no params, exactly as the spec requires.
	void pingClient(Duration timeout = 60.seconds) @safe
	{
		if (pushChannel is null)
			throw internalError("No server->client push channel; the server is not mounted on a Streamable HTTP transport");
		pushChannel.ping(timeout);
	}

	/// Capabilities this server advertises, derived from what is registered.
	ServerCapabilities capabilities() const @safe
	{
		ServerCapabilities caps;
		if (tools.length > 0 || toolListChangedEnabled)
			caps.tools = ListChangedCapability(toolListChangedEnabled);
		if (resources.length > 0 || templates.length > 0
				|| resourceSubscriptionsEnabled || resourcesListChangedEnabled)
			caps.resources = ResourcesCapability(resourceSubscriptionsEnabled,
					resourcesListChangedEnabled);
		if (prompts.length > 0 || promptsListChangedEnabled)
			caps.prompts = ListChangedCapability(promptsListChangedEnabled);
		if (typedCompletionHandler !is null)
			caps.completions = true;
		if (loggingEnabled)
			caps.logging = true;
		if (!tasksCapability.isNull)
			caps.tasks = tasksCapability;
		if (extensions.type == Json.Type.object && extensions.length > 0)
			caps.extensions = extensions;
		return caps;
	}

	/// Dispatch a single parsed message. Returns the JSON-RPC response for
	/// requests, or `Nullable.init` for notifications (which get no reply).
	/// `ctx` is the channel for any server->client traffic the handler emits;
	/// when omitted, a `NullContext` is used (no streaming).
	Nullable!Json handle(Message msg, RequestContext ctx) @safe
	{
		final switch (msg.kind)
		{
		case MessageKind.request:
			return handleRequest(msg, ctx);
		case MessageKind.notification:
			handleNotification(msg);
			return Nullable!Json.init;
		case MessageKind.response:
		case MessageKind.errorResponse:
			// A server core does not expect inbound responses on this path.
			return Nullable!Json.init;
		}
	}

	/// Convenience overload using a `NullContext` (no server->client channel).
	Nullable!Json handle(Message msg) @safe
	{
		return handle(msg, new NullContext);
	}

	/// Process a raw wire payload (single message or batch) and return the raw
	/// response text, or empty string when there is nothing to send back (e.g.
	/// a notification, or an all-notification batch). Parse/envelope failures
	/// become JSON-RPC error responses with a null id.
	string handleRaw(string text) @safe
	{
		return handleRaw(text, null);
	}

	/// As `handleRaw`, but with a server->client write `sink` for transports (such
	/// as stdio) that can deliver out-of-band frames on the same channel. Each
	/// message is dispatched with a `StdioContext` bound to `sink`, so a handler's
	/// `ctx.log()` / `ctx.reportProgress()` are serialised and pushed to `sink` as
	/// they happen — before the request's reply, which is still returned as the
	/// string result. When `sink` is `null` a `NullContext` is used (no streaming),
	/// preserving the in-process behaviour of the no-argument overload.
	string handleRaw(string text, scope void delegate(string) @safe sink) @safe
	{
		import vibe.data.json : parseJsonString;

		ParsedInput input;
		try
			input = parseAny(text);
		catch (McpException e)
			return makeErrorResponse(Json(null), e).toString();
		catch (Exception e)
			return makeErrorResponse(Json(null), parseError(e.msg)).toString();

		auto dispatch = (Message m) @safe {
			if (sink is null)
				return handle(m);
			return handle(m, new StdioContext(sink, readProgressToken(m.params)));
		};

		if (!input.isBatch)
		{
			auto resp = dispatch(input.messages[0]);
			return resp.isNull ? "" : resp.get.toString();
		}

		Json responses = Json.emptyArray;
		foreach (m; input.messages)
		{
			auto resp = dispatch(m);
			if (!resp.isNull)
				responses ~= resp.get;
		}
		return responses.length == 0 ? "" : responses.toString();
	}

	/// Extract `_meta.progressToken` from a request's params, or `Json.undefined`
	/// when the request carried none.
	private static Json readProgressToken(Json params) @safe
	{
		if (params.type == Json.Type.object && "_meta" in params)
		{
			auto meta = params["_meta"];
			if (meta.type == Json.Type.object && "progressToken" in meta)
				return meta["progressToken"];
		}
		return Json.undefined;
	}

	private Nullable!Json handleRequest(Message msg, RequestContext ctx) @safe
	{
		// Determine the version in effect for THIS request. Draft+ is stateless:
		// each request carries its protocol version, client identity, and
		// capabilities in `params._meta` rather than relying on `initialize`.
		// Computed into a request-local (and the per-request RequestScope) rather
		// than a mutable field on the shared server instance, so a handler that
		// yields mid-flight cannot have its effective version flipped by another
		// concurrently-dispatched request (issue #288).
		ProtocolVersion effective = negotiated;
		auto meta = RequestMeta.fromParams(msg.params);
		// On stateful (2025-era) protocols logging is governed once-per-session by
		// `logging/setLevel`, so emission is always permitted (and filtered by the
		// stored minimum). The draft is stateless: the server MUST NOT emit
		// `notifications/message` for a request that did not carry
		// `_meta["io.modelcontextprotocol/logLevel"]`, and a request whose level is
		// unrecognised SHOULD be rejected with -32602.
		bool loggingRequested = true;
		string requestLogLevel = logLevel;
		if (meta.protocolVersion.length)
		{
			ProtocolVersion mv;
			if (tryParseVersion(meta.protocolVersion, mv))
			{
				effective = mv;
				if (mv.isDraft)
				{
					// Per-request client capabilities (draft, stateless): not stored on the
					// shared instance. clientCapabilities() reflects the negotiated session.
					if (meta.logLevel.isNull)
					{
						// No logLevel field -> the client did not request logging.
						loggingRequested = false;
					}
					else
					{
						const lvl = meta.logLevel.get;
						if (logLevelRank(lvl) < 0)
							return nullable(makeErrorResponse(msg.id,
									invalidParams("Invalid log level: " ~ lvl)));
						requestLogLevel = lvl;
					}
				}
			}
			else
			{
				// Per-request protocol-version negotiation (draft): the client
				// declared a version we do not support -> reject with the list of
				// versions we do support so it can retry with a compatible one.
				return nullable(makeErrorResponse(msg.id,
						unsupportedVersionError(meta.protocolVersion)));
			}
		}

		// Register a cancellation token for this request keyed by its id, so an
		// inbound `notifications/cancelled` can flip it while the handler runs
		// (basic/utilities/cancellation). `initialize` MUST NOT be cancelled, so
		// it is never registered. Deregister on the way out regardless of outcome.
		auto token = new CancellationToken;
		const idKey = cancellationKey(msg.id);
		const trackable = idKey.length && msg.method != "initialize";
		if (trackable)
			inFlight[idKey] = token;
		scope (exit)
			if (trackable)
				inFlight.remove(idKey);

		// Install the per-request scope so handlers see the right statelessness
		// (MRTR vs blocking), the input responses carried on a retried draft
		// request, and the cancellation token, regardless of which transport
		// supplied the base context.
		auto scoped = new RequestScope(ctx, effective.usesMRTR, readInputResponses(msg.params),
				requestLogLevel, loggingRequested, token, readRequestState(msg.params), effective);

		try
		{
			auto result = route(msg.method, msg.params, scoped, effective);
			// Per spec, a receiver of a cancellation "SHOULD NOT send a response
			// for the cancelled request" — suppress it if cancelled meanwhile.
			if (token.cancelled)
				return Nullable!Json.init;
			return nullable(makeResponse(msg.id, stampResultType(result, effective)));
		}
		catch (McpException e)
		{
			if (token.cancelled)
				return Nullable!Json.init;
			return nullable(makeErrorResponse(msg.id, e));
		}
		catch (Exception e)
		{
			if (token.cancelled)
				return Nullable!Json.init;
			return nullable(makeErrorResponse(msg.id, internalError(e.msg)));
		}
	}

	/// The registry key for a request id. JSON-RPC ids are strings or numbers;
	/// `notifications/cancelled` carries the same id under `requestId`, so both
	/// sides normalise to the same string form. Returns an empty string for an
	/// absent/null id (a notification has none and is never tracked).
	private static string cancellationKey(Json id) @safe
	{
		import std.conv : to;

		switch (id.type)
		{
		case Json.Type.string:
			return "s:" ~ id.get!string;
		case Json.Type.int_:
			return "i:" ~ id.get!long
				.to!string;
		case Json.Type.bigInt:
			return "i:" ~ id.toString();
		default:
			return "";
		}
	}

	/// Configure the per-list draft `CacheableResult` freshness hint
	/// (`ttlMs`/`cacheScope`) emitted on a specific `*/list` result when speaking
	/// the draft protocol. `listMethod` MUST be one of `tools/list`,
	/// `resources/list`, `resources/templates/list`, or `prompts/list`. Per-resource
	/// and per-template hints are supplied at registration time instead.
	void setListCacheHint(string listMethod, CacheHint hint) @safe
	{
		assert(listMethod == "tools/list" || listMethod == "resources/list"
				|| listMethod == "resources/templates/list"
				|| listMethod == "prompts/list",
				"setListCacheHint: unknown list method '" ~ listMethod ~ "'");
		listCacheHints[listMethod] = nullable(hint);
	}

	/// Set the maximum number of items returned per `*/list` page
	/// (server/utilities/pagination). When `size > 0`, `tools/list`,
	/// `resources/list`, `resources/templates/list` and `prompts/list` return at
	/// most `size` items per response and emit an opaque `nextCursor` whenever
	/// more results remain; the client passes that cursor back as `params.cursor`
	/// to fetch the next page (the bundled `McpClient` list helpers follow these
	/// cursors automatically). A `size` of `0` (the default) disables pagination:
	/// each list returns its full contents in a single response with no cursor.
	void setPageSize(size_t size) @safe
	{
		pageSize_ = size;
	}

	/// The current `*/list` page size (`0` = unbounded; see `setPageSize`).
	size_t pageSize() const @safe
	{
		return pageSize_;
	}

	/// Apply a per-result draft cacheable-result hint when the effective version is
	/// draft+ AND a hint was supplied for this result. A no-op for earlier versions
	/// or when no hint is set, keeping 2025-11-25 wire output unchanged.
	private Json maybeCache(Json result, Nullable!CacheHint hint, ProtocolVersion ver) @safe
	{
		if (ver.cacheableResults && !hint.isNull)
			return withCache(result, hint.get);
		return result;
	}

	/// Stamp the mandatory draft `resultType` discriminator onto a result.
	///
	/// The draft base `Result` requires a `resultType` field on every result
	/// ("complete" for a finished response, "input_required" for an
	/// `InputRequiredResult`). We add `resultType:"complete"` here, centralized
	/// in the dispatch path, for any object result that does not already
	/// declare one — so an `InputRequiredResult` ("input_required") and
	/// `DiscoverResult` (which set their own) are left untouched. A no-op for
	/// pre-draft versions, keeping the 2025-era wire output unchanged.
	private Json stampResultType(Json result, ProtocolVersion ver) @safe
	{
		if (!ver.isDraft)
			return result;
		if (result.type != Json.Type.object)
			return result;
		if ("resultType" !in result)
			result["resultType"] = "complete";
		return result;
	}

	/// Encode an offset into the opaque pagination cursor handed to the client.
	/// The format is intentionally opaque per spec ("Clients MUST treat cursors
	/// as opaque tokens"); we base64url-encode the decimal offset.
	private static string encodeCursor(size_t offset) @safe
	{
		import std.conv : to;
		import std.string : representation;
		import mcp.auth.oauth : base64UrlNoPad;

		return base64UrlNoPad(offset.to!string.representation);
	}

	/// Decode a pagination cursor previously produced by `encodeCursor`. Throws
	/// `invalidParams` (-32602) for a malformed cursor, per the pagination spec
	/// ("If the cursor is invalid ... SHOULD return ... Invalid params").
	private static size_t decodeCursor(string cursor) @safe
	{
		import std.base64 : Base64URLNoPadding, Base64Exception;
		import std.conv : to, ConvException;

		try
		{
			auto decoded = () @trusted {
				return cast(string) Base64URLNoPadding.decode(cursor);
			}();
			return decoded.to!size_t;
		}
		catch (Base64Exception)
			throw invalidParams("Invalid pagination cursor");
		catch (ConvException)
			throw invalidParams("Invalid pagination cursor");
	}

	/// Compute the slice `[begin, end)` of a sorted list of `total` items for the
	/// page requested by `params.cursor`, honouring the configured page size.
	/// When more items remain after `end`, `next` is set to the cursor for the
	/// following page (otherwise left null). With pagination disabled
	/// (`pageSize_ == 0`) the whole list is returned and `next` stays null.
	/// Throws `invalidParams` for a malformed or out-of-range cursor.
	private void pageBounds(Json params, size_t total, out size_t begin,
			out size_t end, out Nullable!string next) @safe
	{
		begin = 0;
		if (params.type == Json.Type.object && "cursor" in params
				&& params["cursor"].type == Json.Type.string)
		{
			begin = decodeCursor(params["cursor"].get!string);
			// A cursor pointing past the end of the (now possibly shorter) list
			// is invalid rather than silently returning an empty final page.
			if (begin > total)
				throw invalidParams("Invalid pagination cursor");
		}

		if (pageSize_ == 0 || begin + pageSize_ >= total)
		{
			end = total;
		}
		else
		{
			end = begin + pageSize_;
			next = encodeCursor(end);
		}
	}

	/// Build the draft `UnsupportedProtocolVersionError` (-32004) listing the
	/// versions this server supports and the one the client requested.
	private McpException unsupportedVersionError(string requested) @safe
	{
		Json supported = Json.emptyArray;
		foreach (v; supportedVersions)
			supported ~= Json(v.toWire);
		Json data = Json.emptyObject;
		data["supported"] = supported;
		data["requested"] = requested;
		return new McpException(ErrorCode.unsupportedProtocolVersion,
				"Unsupported protocol version", data);
	}

	private void handleNotification(Message msg) @safe
	{
		switch (msg.method)
		{
		case "notifications/initialized":
			initialized = true;
			break;
		case "notifications/cancelled":
			handleCancelled(msg.params);
			break;
		case "notifications/roots/list_changed":
			if (onRootsListChanged_ !is null)
				onRootsListChanged_();
			if (onClientNotification_ !is null)
				onClientNotification_(msg.method, msg.params);
			break;
		default:
			// Unconsumed client notifications are surfaced to the application
			// observer (if any) and otherwise ignored, per JSON-RPC.
			if (onClientNotification_ !is null)
				onClientNotification_(msg.method, msg.params);
			break;
		}
	}

	/// Honour an inbound `notifications/cancelled` (basic/utilities/cancellation):
	/// flip the cancellation token of the named in-flight request so its handler
	/// can stop and its response is suppressed. A cancellation for a request that
	/// is unknown or already completed is ignored, per "This notification
	/// indicates ... the request ... should be terminated" being best-effort.
	private void handleCancelled(Json params) @safe
	{
		if (params.type != Json.Type.object || "requestId" !in params)
			return;
		const key = cancellationKey(params["requestId"]);
		if (key.length == 0)
			return;
		if (auto token = key in inFlight)
			token.cancel();
	}

	private Json route(string method, Json params, RequestContext ctx, ProtocolVersion ver) @safe
	{
		switch (method)
		{
		case "initialize":
			return doInitialize(params);
		case "server/discover":
			return doDiscover();
		case "subscriptions/listen":
			// A draft subscriptions/listen opens a draft server->client push session;
			// pin the connection's push-path version so later notify* gate as draft
			// (issue #288: the per-request path no longer mutates this).
			if (ver.isDraft)
				connectionVersion = ver;
			return doSubscribeListen(params);
		case "ping":
			return Json.emptyObject;
		case "tools/list":
			return doListTools(params, ver);
		case "tools/call":
			return doCallTool(params, ctx);
		case "resources/list":
			return doListResources(params, ver);
		case "resources/templates/list":
			return doListResourceTemplates(params, ver);
		case "resources/read":
			return doReadResource(params, ver);
		case "resources/subscribe":
			return doSubscribe(params);
		case "resources/unsubscribe":
			return doUnsubscribe(params);
		case "prompts/list":
			return doListPrompts(params, ver);
		case "prompts/get":
			return doGetPrompt(params);
		case "completion/complete":
			return doComplete(params);
		case "logging/setLevel":
			return doSetLevel(params, ver);
		default:
			throw methodNotFound(method);
		}
	}

	/// `server/discover` (draft): advertise supported versions, capabilities,
	/// and identity for stateless, up-front version selection.
	private Json doDiscover() @safe
	{
		DiscoverResult d;
		foreach (v; supportedVersions)
			d.protocolVersions ~= v.toWire;
		d.capabilities = capabilities();
		d.serverInfo = serverInfo_.forVersion(ProtocolVersion.draft);
		d.instructions = instructions;
		return d.toJson();
	}

	/// `subscriptions/listen` (draft): record the opted-in change-notification
	/// types and acknowledge. The long-lived delivery stream is provided by the
	/// transport; this records the filter and returns the acknowledgement.
	///
	/// Per draft basic/utilities/subscriptions the filter is nested under
	/// `params.notifications` (a `SubscriptionFilter`): the `toolsListChanged`,
	/// `promptsListChanged` and `resourcesListChanged` flags are booleans, while
	/// `resourceSubscriptions` is a `string[]` of resource URIs the client wants
	/// `notifications/resources/updated` for. Those URIs are recorded as per-URI
	/// subscriptions (so `isSubscribed`/`notifyResourceUpdated` honour them) and
	/// the `resourceSubscriptions` opt-in is flagged when the array is non-empty.
	/// For backward compatibility a flat top-level filter (the pre-spec shape) is
	/// still accepted when no `notifications` object is present.
	private Json doSubscribeListen(Json params) @safe
	{
		Json filter = Json.undefined;
		if (params.type == Json.Type.object && "notifications" in params
				&& params["notifications"].type == Json.Type.object)
			filter = params["notifications"];
		else
			filter = params; // tolerate the legacy flat shape

		// Reset the per-stream filter; it captures exactly THIS listen request's
		// opt-in so the transport can attach it to this one stream's listener.
		SubscriptionFilter perStream;
		perStream.active = true;
		if (filter.type == Json.Type.object)
		{
			static immutable boolKeys = [
				"toolsListChanged", "promptsListChanged", "resourcesListChanged"
			];
			foreach (k; boolKeys)
				if (k in filter && filter[k].type == Json.Type.bool_ && filter[k].get!bool)
				{
					listenFilters[k] = true;
					if (k == "toolsListChanged")
						perStream.toolsListChanged = true;
					else if (k == "promptsListChanged")
						perStream.promptsListChanged = true;
					else if (k == "resourcesListChanged")
						perStream.resourcesListChanged = true;
				}

			if ("resourceSubscriptions" in filter)
			{
				auto rs = filter["resourceSubscriptions"];
				if (rs.type == Json.Type.array)
				{
					bool any;
					foreach (i; 0 .. rs.length)
						if (rs[i].type == Json.Type.string)
						{
							const u = rs[i].get!string;
							subscriptions[u] = true;
							// Preserve the agreed URI list so the acknowledgement
							// can echo `resourceSubscriptions` as the spec's
							// string[] (deduplicated, request order kept).
							import std.algorithm : canFind;

							if (!listenResourceUris.canFind(u))
								listenResourceUris ~= u;
							if (!perStream.resourceUris.canFind(u))
								perStream.resourceUris ~= u;
							any = true;
						}
					if (any)
					{
						listenFilters["resourceSubscriptions"] = true;
						perStream.resourceSubscriptions = true;
					}
				}
				else if (rs.type == Json.Type.bool_ && rs.get!bool)
				{
					// Legacy boolean opt-in (pre-spec): blanket interest in
					// resource-update notifications without per-URI URIs.
					listenFilters["resourceSubscriptions"] = true;
					perStream.resourceSubscriptions = true;
				}
			}
		}
		lastListenFilter_ = perStream;

		Json j = Json.emptyObject;
		j["acknowledged"] = true;
		return j;
	}

	/// Whether the client opted in to a given change-notification type via
	/// `subscriptions/listen`.
	bool listensFor(string changeType) const @safe
	{
		return (changeType in listenFilters) !is null;
	}

	/// The agreed-upon subset of change-notification types the server will deliver
	/// on the `subscriptions/listen` stream (draft basic/utilities/subscriptions).
	/// The three list-changed types appear as booleans (`{ "<type>": true }`)
	/// while `resourceSubscriptions` appears as the agreed `string[]` of URIs (a
	/// `SubscriptionFilter`); an empty object when the client opted into nothing.
	/// This is the payload the transport sends in the leading
	/// `notifications/subscriptions/acknowledged` event when it opens the stream.
	Json acknowledgedListenSubset() const @safe
	{
		Json subset = Json.emptyObject;
		foreach (k, v; listenFilters)
		{
			// `resourceSubscriptions` is a `string[]` of URIs in a
			// `SubscriptionFilter`, not a boolean: echo the agreed URI list the
			// client asked to be notified about (draft basic/utilities/
			// subscriptions Acknowledgment). The three list-changed keys stay
			// booleans.
			if (k == "resourceSubscriptions")
			{
				Json uris = Json.emptyArray;
				foreach (u; listenResourceUris)
					uris ~= Json(u);
				subset[k] = uris;
			}
			else
				subset[k] = v;
		}
		return subset;
	}

	/// The per-stream `SubscriptionFilter` parsed from the most recent
	/// `subscriptions/listen` request handled by this server. The transport reads it
	/// immediately after routing a listen request so it can attach the exact opt-in to
	/// that stream's push-channel listener (draft basic/utilities/subscriptions
	/// §Notification Filter), ensuring a notification is delivered only to a stream
	/// that explicitly requested its type.
	SubscriptionFilter lastListenFilter() @safe
	{
		return lastListenFilter_;
	}

	private Json doListResources(Json params, ProtocolVersion ver) @safe
	{
		import std.algorithm : sort;

		auto uris = resources.keys;
		sort(uris);
		size_t begin, end;
		Nullable!string next;
		pageBounds(params, uris.length, begin, end, next);

		ListResourcesResult result;
		foreach (uri; uris[begin .. end])
			result.resources ~= resources[uri].descriptor;
		result.nextCursor = next;
		return maybeCache(result.toJson(), listHint("resources/list"), ver);
	}

	private Json doListResourceTemplates(Json params, ProtocolVersion ver) @safe
	{
		size_t begin, end;
		Nullable!string next;
		pageBounds(params, templates.length, begin, end, next);

		ListResourceTemplatesResult result;
		foreach (t; templates[begin .. end])
			result.resourceTemplates ~= t.descriptor;
		result.nextCursor = next;
		return maybeCache(result.toJson(), listHint("resources/templates/list"), ver);
	}

	private Json doReadResource(Json params, ProtocolVersion ver) @safe
	{
		if ("uri" !in params || params["uri"].type != Json.Type.string)
			throw invalidParams("resources/read requires a string 'uri'");
		const uri = params["uri"].get!string;

		if (auto direct = uri in resources)
		{
			ReadResourceResult result;
			result.contents = [direct.reader()];
			return maybeCache(result.toJson(), direct.cache, ver);
		}

		foreach (t; templates)
		{
			string[string] captured;
			if (matchUriTemplate(t.descriptor.uriTemplate, uri, captured))
			{
				ReadResourceResult result;
				result.contents = [t.reader(uri, captured)];
				return maybeCache(result.toJson(), t.cache, ver);
			}
		}
		// Draft aligns the code to invalidParams (-32602); older versions -32002.
		// The spec's not-found example carries structured data {"uri": ...} so
		// clients can read the offending URI without parsing the message string.
		Json data = Json.emptyObject;
		data["uri"] = uri;
		throw new McpException(ver.resourceNotFoundCode, "Resource not found: " ~ uri, data);
	}

	private Json doSubscribe(Json params) @safe
	{
		if ("uri" !in params || params["uri"].type != Json.Type.string)
			throw invalidParams("resources/subscribe requires a string 'uri'");
		subscriptions[params["uri"].get!string] = true;
		return Json.emptyObject;
	}

	private Json doUnsubscribe(Json params) @safe
	{
		if ("uri" !in params || params["uri"].type != Json.Type.string)
			throw invalidParams("resources/unsubscribe requires a string 'uri'");
		subscriptions.remove(params["uri"].get!string);
		return Json.emptyObject;
	}

	private Json doListPrompts(Json params, ProtocolVersion ver) @safe
	{
		import std.algorithm : sort;

		auto names = prompts.keys;
		sort(names);
		size_t begin, end;
		Nullable!string next;
		pageBounds(params, names.length, begin, end, next);

		ListPromptsResult result;
		foreach (name; names[begin .. end])
			result.prompts ~= prompts[name].descriptor;
		result.nextCursor = next;
		return maybeCache(result.toJson(), listHint("prompts/list"), ver);
	}

	/// The per-list draft cache hint configured for `listMethod`, or null if none.
	private Nullable!CacheHint listHint(string listMethod) @safe
	{
		if (auto h = listMethod in listCacheHints)
			return *h;
		return Nullable!CacheHint.init;
	}

	private Json doGetPrompt(Json params) @safe
	{
		if ("name" !in params || params["name"].type != Json.Type.string)
			throw invalidParams("prompts/get requires a string 'name'");
		const name = params["name"].get!string;
		auto entry = name in prompts;
		if (entry is null)
			throw invalidParams("Unknown prompt: " ~ name);
		Json args = ("arguments" in params) ? params["arguments"] : Json.emptyObject;
		// Validate declared required arguments before invoking the handler so a
		// missing required argument yields -32602 instead of a default-valued
		// prompt (spec: server/prompts § Error Handling / Implementation
		// Considerations).
		foreach (arg; entry.descriptor.arguments)
		{
			if (!arg.required)
				continue;
			if (args.type != Json.Type.object || arg.name !in args)
				throw invalidParams("Missing required argument '" ~ arg.name
						~ "' for prompt: " ~ name);
		}
		return entry.handler(args).toJson();
	}

	private Json doComplete(Json params) @safe
	{
		if (typedCompletionHandler !is null)
			return typedCompletionHandler(CompleteRequest.fromJson(params)).toJson();
		// No handler registered => the `completions` capability is not advertised.
		// The spec directs servers to answer with -32601 (Capability not
		// supported) rather than a success result in this case.
		throw methodNotFound("completion/complete");
	}

	private Json doSetLevel(Json params, ProtocolVersion ver) @safe
	{
		// The draft (2026-07-28) removed the `logging/setLevel` RPC: log level is
		// now configured purely per-request via `_meta["io.modelcontextprotocol/
		// logLevel"]` (SEP-2575/2577). The method does not exist on the draft, so
		// it MUST be answered with -32601 (method not found) rather than accepted,
		// regardless of whether the logging capability is enabled.
		if (ver.isDraft)
			throw methodNotFound("logging/setLevel");
		// On stable (<= 2025-11-25) versions the logging feature is gated on the
		// declared `logging` capability (server/utilities/logging: "Servers that
		// emit log message notifications MUST declare the `logging` capability").
		// A server that never called enableLogging() advertises no logging
		// capability, so this request is answered with -32601 (Capability not
		// supported) rather than being handled, matching completion/complete's
		// capability gating.
		if (!loggingEnabled)
			throw methodNotFound("logging/setLevel");
		if (!("level" in params) || params["level"].type != Json.Type.string)
			throw invalidParams("logging/setLevel requires a string 'level'");
		const level = params["level"].get!string;
		// The spec mandates -32602 for an unrecognised log level. Valid levels
		// are the eight RFC 5424 syslog severities (logLevelRank returns -1 for
		// anything else).
		if (logLevelRank(level) < 0)
			throw invalidParams("Invalid log level: " ~ level);
		logLevel = level;
		return Json.emptyObject;
	}

	private Json doInitialize(Json params) @safe
	{
		auto p = InitializeParams.fromJson(params);
		negotiated = negotiate(p.protocolVersion);
		clientCaps = p.capabilities;
		// Pin the connection's push-path version so unsolicited server->client
		// notifications gate correctly on draft after initialize (issue #288).
		connectionVersion = negotiated;

		InitializeResult result;
		result.protocolVersion = negotiated.toWire;
		result.capabilities = capabilities();
		result.serverInfo = serverInfo_.forVersion(negotiated);
		result.instructions = instructions;
		return result.toJson();
	}

	private Json doListTools(Json params, ProtocolVersion ver) @safe
	{
		auto names = sortedToolNames();
		size_t begin, end;
		Nullable!string next;
		pageBounds(params, names.length, begin, end, next);

		ListToolsResult result;
		foreach (name; names[begin .. end])
			result.tools ~= tools[name].descriptor;
		result.nextCursor = next;
		return maybeCache(result.toJson(), listHint("tools/list"), ver);
	}

	private Json doCallTool(Json params, RequestContext ctx) @safe
	{
		if ("name" !in params || params["name"].type != Json.Type.string)
			throw invalidParams("tools/call requires a string 'name'");
		const name = params["name"].get!string;
		auto entry = name in tools;
		if (entry is null)
			throw invalidParams("Unknown tool: " ~ name);

		Json args = ("arguments" in params) ? params["arguments"] : Json.emptyObject;
		// Validate the supplied arguments against the tool's declared inputSchema
		// before dispatch (spec: server/tools § Security Considerations,
		// "Servers MUST: Validate all tool inputs"). Per § Error Handling, an
		// argument that violates the tool's own inputSchema (missing required
		// property or wrong type) is an *input-validation* error, classified as
		// a Tool Execution Error: it is reported as a CallToolResult with
		// `isError:true`, NOT a JSON-RPC -32602 protocol error. The
		// CallToolRequest schema only constrains `name`/`arguments`, so such a
		// failure does not make the request malformed. Gated behind the same
		// opt-in style as output-schema validation to preserve existing
		// behaviour.
		if (validateInputSchema_)
		{
			const schemaMsg = checkInputSchema(entry.descriptor, args);
			if (schemaMsg.length)
			{
				CallToolResult err;
				err.content = [Content.makeText(schemaMsg)];
				err.isError = true;
				return err.toJson();
			}
		}
		try
		{
			// CallToolResult or InputRequiredResult.
			auto result = entry.handler(args, ctx).toJson();
			if (validateOutputSchema_)
				checkOutputSchema(entry.descriptor, result);
			return result;
		}
		catch (McpException e)
			throw e; // protocol-level errors propagate as JSON-RPC errors
		catch (Exception e)
		{
			// Tool *execution* failures are reported as isError content, not
			// protocol errors (per the MCP spec).
			CallToolResult err;
			err.content = [Content.makeText(e.msg)];
			err.isError = true;
			return err.toJson();
		}
	}

	/// When input-schema validation is enabled, verify that a tool call's
	/// `arguments` conform to the tool's registered `inputSchema`. Returns an
	/// empty string when the arguments conform (or the tool has no input
	/// schema), otherwise a human-readable description of the violation.
	/// Per the spec's tools § Error Handling, an inputSchema violation is an
	/// input-validation error reported as a tool-execution result with
	/// `isError:true`, NOT a JSON-RPC protocol error, so the caller turns the
	/// returned message into a `CallToolResult` rather than throwing.
	private static string checkInputSchema(ref const Tool descriptor, Json args) @safe
	{
		import mcp.api.schema : validateAgainstSchema;

		if (descriptor.inputSchema.type != Json.Type.object)
			return null;
		const msg = validateAgainstSchema(args, descriptor.inputSchema);
		if (msg.length)
			return "Invalid arguments for tool '" ~ descriptor.name ~ "': " ~ msg;
		return null;
	}

	/// When output-schema validation is enabled, verify that a tool result's
	/// `structuredContent` conforms to the tool's registered `outputSchema`.
	/// No-op when the tool has no output schema or the result carries no
	/// structured content. Throws an internal `McpException` on a violation.
	private static void checkOutputSchema(ref const Tool descriptor, Json result) @safe
	{
		import mcp.api.schema : validateAgainstSchema;

		if (descriptor.outputSchema.type != Json.Type.object)
			return;
		if (result.type != Json.Type.object || "structuredContent" !in result)
			return;
		const msg = validateAgainstSchema(result["structuredContent"], descriptor.outputSchema);
		if (msg.length)
			throw new McpException(ErrorCode.internalError, "Tool '" ~ descriptor.name
					~ "' produced structuredContent that does not conform to its outputSchema: "
					~ msg);
	}

	private string[] sortedToolNames() const @safe
	{
		import std.algorithm : sort;
		import std.array : array;

		auto names = tools.keys;
		sort(names);
		return names;
	}
}

/// Match a concrete `uri` against an RFC 6570-style template containing
/// `{var}` placeholders (each capturing a non-empty run up to the next literal).
/// On success, fills `params` with the captured values and returns true.
bool matchUriTemplate(string tmpl, string uri, out string[string] params) @safe
{
	import std.string : indexOf;

	size_t ti = 0, ui = 0;
	while (ti < tmpl.length)
	{
		if (tmpl[ti] == '{')
		{
			const close = tmpl[ti .. $].indexOf('}');
			if (close < 0)
				return false;
			const varName = tmpl[ti + 1 .. ti + close];
			ti += close + 1;

			const litStart = ti;
			while (ti < tmpl.length && tmpl[ti] != '{')
				ti++;
			const lit = tmpl[litStart .. ti];

			string captured;
			if (lit.length == 0)
			{
				captured = uri[ui .. $];
				ui = uri.length;
			}
			else
			{
				const pos = uri[ui .. $].indexOf(lit);
				if (pos < 0)
					return false;
				captured = uri[ui .. ui + pos];
				ui += pos + lit.length;
			}
			if (captured.length == 0)
				return false;
			params[varName] = captured;
		}
		else
		{
			const litStart = ti;
			while (ti < tmpl.length && tmpl[ti] != '{')
				ti++;
			const lit = tmpl[litStart .. ti];
			if (ui + lit.length > uri.length || uri[ui .. ui + lit.length] != lit)
				return false;
			ui += lit.length;
		}
	}
	return ui == uri.length;
}

unittest  // template matching captures a single parameter
{
	string[string] params;
	assert(matchUriTemplate("test://template/{id}/data", "test://template/123/data", params));
	assert(params["id"] == "123");
}

unittest  // template matching rejects non-matching URIs
{
	string[string] params;
	assert(!matchUriTemplate("test://template/{id}/data", "test://other/123", params));
	assert(!matchUriTemplate("test://template/{id}/data", "test://template//data", params));
}

unittest  // template matching captures a trailing parameter
{
	string[string] params;
	assert(matchUriTemplate("file:///{path}", "file:///a/b/c", params));
	assert(params["path"] == "a/b/c");
}

version (unittest)
{
	private McpServer makeTestServer() @safe
	{
		auto s = new McpServer("test-srv", "0.1.0");
		Tool add = {name: "add", description: nullable("Add two integers")};
		s.registerDynamicTool(add, (Json args) @safe {
			const a = args["a"].get!int;
			const b = args["b"].get!int;
			CallToolResult r;
			r.content = [Content.makeText("sum")];
			r.structuredContent = Json(["result": Json(a + b)]);
			return r;
		});
		return s;
	}

	private Message req(long id, string method, Json params = Json.emptyObject) @safe
	{
		return Message(makeRequest(Json(id), method, params));
	}
}

unittest  // public flagship type uses single-cap Mcp* casing (issue #304)
{
	// The server class must be reachable under the consistent `McpServer`
	// name (matching McpException, MrtrToolHandler, etc.), not `MCPServer`.
	static assert(is(McpServer == class));
	auto s = new McpServer("casing-srv", "0.1.0");
	assert(s !is null);
}

unittest  // initialize negotiates the requested version and reports server info
{
	auto s = makeTestServer();
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = Json.emptyObject;
	params["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);

	auto resp = s.handle(req(1, "initialize", params)).get;
	assert(resp["result"]["protocolVersion"].get!string == "2025-06-18");
	assert(resp["result"]["serverInfo"]["name"].get!string == "test-srv");
	assert(resp["result"]["capabilities"]["tools"].type == Json.Type.object);
}

unittest  // Implementation constructor advertises full serverInfo on 2025-11-25
{
	Implementation info = {
		name: "rich-srv", version_: "2.0", title: nullable("Rich Server"),
		description: nullable("a helpful server"),
		websiteUrl: nullable("https://example.com"), icons: [
				Icon("https://example.com/i.png")
		]
	};
	auto s = new McpServer(info);
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-11-25";
	params["capabilities"] = Json.emptyObject;
	params["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);

	auto resp = s.handle(req(1, "initialize", params)).get;
	auto si = resp["result"]["serverInfo"];
	assert(si["name"].get!string == "rich-srv");
	assert(si["version"].get!string == "2.0");
	assert(si["title"].get!string == "Rich Server");
	assert(si["description"].get!string == "a helpful server");
	assert(si["websiteUrl"].get!string == "https://example.com");
	assert(si["icons"].length == 1);
}

unittest  // serverInfo strips 2025-11-25-only fields when negotiating 2025-06-18
{
	Implementation info = {
		name: "rich-srv", version_: "2.0", title: nullable("Rich Server"),
		description: nullable("a helpful server"),
		websiteUrl: nullable("https://example.com"), icons: [
				Icon("https://example.com/i.png")
		]
	};
	auto s = new McpServer(info);
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = Json.emptyObject;
	params["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);

	auto resp = s.handle(req(1, "initialize", params)).get;
	auto si = resp["result"]["serverInfo"];
	assert(si["title"].get!string == "Rich Server");
	assert("description" !in si);
	assert("websiteUrl" !in si);
	assert("icons" !in si);
}

unittest  // serverInfo strips title when negotiating 2025-03-26 (pre-BaseMetadata.title)
{
	Implementation info = {
		name: "rich-srv", version_: "2.0", title: nullable("Rich Server")
	};
	auto s = new McpServer(info);
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-03-26";
	params["capabilities"] = Json.emptyObject;
	params["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);

	auto resp = s.handle(req(1, "initialize", params)).get;
	auto si = resp["result"]["serverInfo"];
	assert(si["name"].get!string == "rich-srv");
	assert("title" !in si);
}

unittest  // legacy (name, version) constructor still emits a minimal serverInfo
{
	auto s = new McpServer("plain-srv", "1.0");
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-11-25";
	params["capabilities"] = Json.emptyObject;
	params["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);

	auto resp = s.handle(req(1, "initialize", params)).get;
	auto si = resp["result"]["serverInfo"];
	assert(si["name"].get!string == "plain-srv");
	assert(si["version"].get!string == "1.0");
	assert("title" !in si);
	assert("description" !in si);
}

unittest  // server/discover (draft) emits the full stored serverInfo
{
	Implementation info = {
		name: "rich-srv", version_: "2.0", title: nullable("Rich Server"),
		description: nullable("a helpful server"),
		websiteUrl: nullable("https://example.com"), icons: [
				Icon("https://example.com/i.png")
		]
	};
	auto s = new McpServer(info);
	auto resp = s.handle(req(1, "server/discover")).get;
	auto si = resp["result"]["serverInfo"];
	assert(si["name"].get!string == "rich-srv");
	assert(si["title"].get!string == "Rich Server");
	assert(si["description"].get!string == "a helpful server");
	assert(si["websiteUrl"].get!string == "https://example.com");
	assert(si["icons"].length == 1);
}

unittest  // initialize falls back to latest stable for an unknown version
{
	auto s = makeTestServer();
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2099-01-01";
	auto resp = s.handle(req(1, "initialize", params)).get;
	assert(resp["result"]["protocolVersion"].get!string == latestStable.toWire);
}

unittest  // ping returns an empty result object
{
	auto s = makeTestServer();
	auto resp = s.handle(req(2, "ping")).get;
	assert(resp["result"].type == Json.Type.object);
	assert(resp["result"].length == 0);
}

unittest  // pingClient throws when there is no server->client push channel
{
	import mcp.protocol.errors : McpException, ErrorCode;

	auto s = makeTestServer();
	bool threw;
	try
		s.pingClient();
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.internalError);
	}
	assert(threw);
}

unittest  // pingClient drives a ping on the push channel and awaits the empty reply
{
	import std.algorithm : canFind;
	import vibe.core.core : runTask, exitEventLoop, runEventLoop;

	auto srv = makeTestServer();
	auto coord = new StreamCoordinator;
	auto ch = srv.serverPushChannel(coord); // create + attach the GET push channel
	string frame;
	ch.addListener((string f) @safe { frame = f; });

	bool pinged;
	void delegate() @safe nothrow initiator = () @safe nothrow{
		try
			srv.pingClient(); // blocks until the simulated client resolves the request
		catch (Exception)
			assert(false, "pingClient threw");
		pinged = true;
		exitEventLoop();
	};
	void delegate() @safe nothrow responder = () @safe nothrow{
		// The server emitted a JSON-RPC `ping` request on the GET stream.
		assert(frame.canFind("\"method\":\"ping\""));
		assert(frame.canFind("\"id\":1"));
		// Client answers id 1 with the empty result object, via the coordinator.
		bool matched;
		try
			matched = coord.resolve(Json(1), Json.emptyObject, Json.undefined);
		catch (Exception)
			assert(false, "resolve threw");
		assert(matched);
	};
	runTask(initiator);
	runTask(responder);
	runEventLoop();

	assert(pinged);
}

unittest  // notifications produce no response
{
	auto s = makeTestServer();
	auto out_ = s.handle(Message(makeNotification("notifications/initialized")));
	assert(out_.isNull);
}

unittest  // tools/list returns registered tools
{
	auto s = makeTestServer();
	auto resp = s.handle(req(3, "tools/list")).get;
	auto tools = resp["result"]["tools"];
	assert(tools.length == 1);
	assert(tools[0]["name"].get!string == "add");
	assert(tools[0]["inputSchema"]["type"].get!string == "object");
}

unittest  // tools/call invokes the handler and returns its result
{
	auto s = makeTestServer();
	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(2), "b": Json(3)]);
	auto resp = s.handle(req(4, "tools/call", params)).get;
	assert(resp["result"]["structuredContent"]["result"].get!int == 5);
	assert("isError" !in resp["result"]);
}

unittest  // tools/list emits a tool descriptor's _meta
{
	auto s = new McpServer("meta-srv", "0.1.0");
	Tool t = {name: "tagged"};
	Json m = Json.emptyObject;
	m["x.example/group"] = "demo";
	t.meta = m;
	s.registerDynamicTool(t, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});

	auto resp = s.handle(req(1, "tools/list")).get;
	assert(resp["result"]["tools"][0]["_meta"]["x.example/group"].get!string == "demo");
}

unittest  // tools/call propagates a handler's result-level _meta to the wire
{
	auto s = new McpServer("meta-srv", "0.1.0");
	Tool t = {name: "withmeta"};
	s.registerDynamicTool(t, (Json args) @safe {
		Json m = Json.emptyObject;
		m["io.modelcontextprotocol/cacheHit"] = true;
		return CallToolResult([Content.makeText("ok")]).withMeta(m);
	});

	Json params = Json.emptyObject;
	params["name"] = "withmeta";
	auto resp = s.handle(req(2, "tools/call", params)).get;
	assert(resp["result"]["_meta"]["io.modelcontextprotocol/cacheHit"].get!bool);
}

unittest  // tools/call with unknown tool is an invalid-params protocol error
{
	auto s = makeTestServer();
	Json params = Json.emptyObject;
	params["name"] = "missing";
	auto resp = s.handle(req(5, "tools/call", params)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // output-schema validation: conforming structuredContent passes
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddResult
	{
		int result;
	}

	Tool add = {
		name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("sum")];
		r.structuredContent = Json(["result": Json(5)]);
		return r;
	});
	s.enableOutputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = "add";
	auto resp = s.handle(req(7, "tools/call", params)).get;
	assert(resp["result"]["structuredContent"]["result"].get!int == 5);
	assert("error" !in resp);
}

unittest  // output-schema validation: non-conforming structuredContent errors
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddResult
	{
		int result;
	}

	Tool add = {
		name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("sum")];
		// Wrong type: result should be an integer.
		r.structuredContent = Json(["result": Json("oops")]);
		return r;
	});
	s.enableOutputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = "add";
	auto resp = s.handle(req(8, "tools/call", params)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.internalError);
}

unittest  // output-schema validation is off by default: bad output still ships
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddResult
	{
		int result;
	}

	Tool add = {
		name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("sum")];
		r.structuredContent = Json(["result": Json("oops")]);
		return r;
	});

	Json params = Json.emptyObject;
	params["name"] = "add";
	auto resp = s.handle(req(9, "tools/call", params)).get;
	assert("error" !in resp);
	assert(resp["result"]["structuredContent"]["result"].get!string == "oops");
}

unittest  // input-schema validation: a missing required argument yields an isError result
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddArgs
	{
		int a;
		int b;
	}

	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!AddArgs
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.enableInputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(1)]); // missing required 'b'
	auto resp = s.handle(req(20, "tools/call", params)).get;
	// Spec: server/tools § Error Handling lists input-validation failures
	// (missing required property) under Tool Execution Errors, returned as a
	// CallToolResult with isError:true, NOT a JSON-RPC protocol error.
	assert("error" !in resp);
	assert(resp["result"]["isError"].get!bool);
	assert(resp["result"]["content"][0]["text"].get!string.length > 0);
}

unittest  // input-schema validation: a wrong-typed argument yields an isError result
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddArgs
	{
		int a;
	}

	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!AddArgs
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.enableInputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json("not-an-int")]);
	auto resp = s.handle(req(21, "tools/call", params)).get;
	// Spec: a wrong-typed tool argument is an input-validation error, reported
	// as isError:true in the result (Tool Execution Error), not -32602.
	assert("error" !in resp);
	assert(resp["result"]["isError"].get!bool);
	assert(resp["result"]["content"][0]["text"].get!string.length > 0);
}

unittest  // input-schema validation: conforming arguments dispatch normally
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddArgs
	{
		int a;
		int b;
	}

	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!AddArgs
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.enableInputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(1), "b": Json(2)]);
	auto resp = s.handle(req(22, "tools/call", params)).get;
	assert("error" !in resp);
	assert(resp["result"]["content"][0]["text"].get!string == "ok");
}

unittest  // input-schema validation is off by default: missing argument still dispatches
{
	import mcp.api.schema : jsonSchemaOf;

	auto s = new McpServer("vsrv", "0.1.0");
	struct AddArgs
	{
		int a;
		int b;
	}

	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!AddArgs
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});

	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(1)]); // missing 'b', but validation is off
	auto resp = s.handle(req(23, "tools/call", params)).get;
	assert("error" !in resp);
	assert(resp["result"]["content"][0]["text"].get!string == "ok");
}

unittest  // a genuinely malformed CallToolRequest (non-string name) is still -32602
{
	import mcp.api.schema : jsonSchemaOf;

	// The spec reserves protocol errors for requests that fail the
	// CallToolRequest schema itself (name/arguments), so a non-string `name`
	// must remain a JSON-RPC -32602 error even with input-schema validation on.
	auto s = new McpServer("vsrv", "0.1.0");
	struct AddArgs
	{
		int a;
	}

	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!AddArgs
	};
	s.registerDynamicTool(add, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.enableInputSchemaValidation();

	Json params = Json.emptyObject;
	params["name"] = Json(123); // not a string => malformed CallToolRequest
	auto resp = s.handle(req(24, "tools/call", params)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // a tool handler that throws becomes an isError result, not a protocol error
{
	auto s = new McpServer("t", "1");
	Tool boom = {name: "boom"};
	CallToolResult delegate(Json) @safe handler = (Json) {
		throw new Exception("kaboom");
	};
	s.registerDynamicTool(boom, handler);
	Json params = Json.emptyObject;
	params["name"] = "boom";
	auto resp = s.handle(req(6, "tools/call", params)).get;
	assert("error" !in resp);
	assert(resp["result"]["isError"].get!bool);
	assert(resp["result"]["content"][0]["text"].get!string == "kaboom");
}

unittest  // an unknown method yields method-not-found
{
	auto s = makeTestServer();
	auto resp = s.handle(req(7, "does/not/exist")).get;
	assert(resp["error"]["code"].get!int == ErrorCode.methodNotFound);
}

unittest  // notifications/cancelled mid-handler: ctx.isCancelled flips and the response is suppressed
{
	// A handler that, while running, simulates a concurrent cancellation arriving
	// for its own request, then observes ctx.isCancelled and returns. The server
	// MUST NOT send a response for the cancelled request.
	auto s = new McpServer("t", "1");
	bool sawCancelled;
	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		assert(!ctx.isCancelled);
		// Concurrent cancellation for request id 42 (same as the call below).
		Json p = Json.emptyObject;
		p["requestId"] = 42;
		s.handle(Message(makeNotification("notifications/cancelled", p)));
		sawCancelled = ctx.isCancelled;
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	Json callP = Json.emptyObject;
	callP["name"] = "slow";
	auto resp = s.handle(req(42, "tools/call", callP));

	assert(sawCancelled, "handler should observe ctx.isCancelled after cancellation");
	assert(resp.isNull, "no response should be sent for a cancelled request");
}

unittest  // notifications/cancelled for an unknown/completed request id is ignored
{
	auto s = makeTestServer();
	// No request id 999 is in flight: a cancellation for it is a silent no-op.
	Json p = Json.emptyObject;
	p["requestId"] = 999;
	auto out_ = s.handle(Message(makeNotification("notifications/cancelled", p)));
	assert(out_.isNull);

	// A normal subsequent request still completes and replies as usual.
	auto resp = s.handle(req(1, "ping")).get;
	assert(resp["result"].type == Json.Type.object);
}

unittest  // an uncancelled request still receives its normal response
{
	auto s = makeTestServer();
	Json callP = Json.emptyObject;
	callP["name"] = "add";
	callP["arguments"] = Json(["a": Json(1), "b": Json(2)]);
	auto resp = s.handle(req(5, "tools/call", callP));
	assert(!resp.isNull);
	assert(resp.get["result"]["structuredContent"]["result"].get!int == 3);
}

unittest  // cancellation matches string-id requests too
{
	auto s = new McpServer("t", "1");
	bool sawCancelled;
	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		Json p = Json.emptyObject;
		p["requestId"] = "req-abc";
		s.handle(Message(makeNotification("notifications/cancelled", p)));
		sawCancelled = ctx.isCancelled;
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	Json callP = Json.emptyObject;
	callP["name"] = "slow";
	auto resp = s.handle(Message(makeRequest(Json("req-abc"), "tools/call", callP)));
	assert(sawCancelled);
	assert(resp.isNull);
}

unittest  // notifications/roots/list_changed fires the dedicated server hook
{
	auto s = new McpServer("t", "1");
	bool sawRootsChanged;
	s.setRootsListChangedHandler(() @safe { sawRootsChanged = true; });

	auto out_ = s.handle(Message(makeNotification("notifications/roots/list_changed")));
	assert(out_.isNull, "a notification produces no response");
	assert(sawRootsChanged, "server should observe notifications/roots/list_changed");
}

unittest  // notifications/roots/list_changed also reaches the generic client-notification observer
{
	auto s = new McpServer("t", "1");
	string seenMethod;
	s.setClientNotificationHandler((string method, Json params) @safe {
		seenMethod = method;
	});

	s.handle(Message(makeNotification("notifications/roots/list_changed")));
	assert(seenMethod == "notifications/roots/list_changed");
}

unittest  // unrecognised client notifications are surfaced to the generic observer
{
	auto s = new McpServer("t", "1");
	string seenMethod;
	s.setClientNotificationHandler((string method, Json params) @safe {
		seenMethod = method;
	});

	auto out_ = s.handle(Message(makeNotification("notifications/something/unknown")));
	assert(out_.isNull);
	assert(seenMethod == "notifications/something/unknown");
}

unittest  // server-consumed notifications do NOT reach the generic client observer
{
	// notifications/initialized and notifications/cancelled are handled by the
	// server itself and must not be forwarded to the application observer.
	auto s = new McpServer("t", "1");
	bool observed;
	s.setClientNotificationHandler((string method, Json params) @safe {
		observed = true;
	});

	s.handle(Message(makeNotification("notifications/initialized")));
	Json p = Json.emptyObject;
	p["requestId"] = 7;
	s.handle(Message(makeNotification("notifications/cancelled", p)));
	assert(!observed, "initialized/cancelled are consumed internally, not observed");
}

unittest  // handleRaw returns response text for a request
{
	import vibe.data.json : parseJsonString;

	auto s = makeTestServer();
	auto outText = s.handleRaw(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	auto j = parseJsonString(outText);
	assert(j["id"].get!int == 1);
	assert(j["result"].type == Json.Type.object);
}

unittest  // handleRaw returns empty string for a notification
{
	auto s = makeTestServer();
	assert(s.handleRaw(`{"jsonrpc":"2.0","method":"notifications/initialized"}`) == "");
}

unittest  // handleRaw reports malformed JSON as a parse error with null id
{
	import vibe.data.json : parseJsonString;

	auto s = makeTestServer();
	auto j = parseJsonString(s.handleRaw(`{not json`));
	assert(j["error"]["code"].get!int == ErrorCode.parseError);
	assert(j["id"].type == Json.Type.null_);
}

unittest  // handleRaw on a batch returns only the responses (notifications drop out)
{
	import vibe.data.json : parseJsonString;

	auto s = makeTestServer();
	auto outText = s.handleRaw(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"},
		{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`);
	auto arr = parseJsonString(outText);
	assert(arr.type == Json.Type.array);
	assert(arr.length == 2);
	assert(arr[0]["id"].get!int == 1);
	assert(arr[1]["id"].get!int == 2);
}

unittest  // resources/list and resources/read for a direct resource
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "test://x", name: "x", mimeType: nullable("text/plain")};
	s.registerResource(r, () @safe => ResourceContents.makeText("test://x", "text/plain", "hi"));

	auto list = s.handle(req(1, "resources/list")).get;
	assert(list["result"]["resources"][0]["uri"].get!string == "test://x");

	Json p = Json.emptyObject;
	p["uri"] = "test://x";
	auto read = s.handle(req(2, "resources/read", p)).get;
	assert(read["result"]["contents"][0]["text"].get!string == "hi");
}

unittest  // resources/read for an unknown uri is resourceNotFound
{
	auto s = new McpServer("t", "1");
	Json p = Json.emptyObject;
	p["uri"] = "test://missing";
	auto resp = s.handle(req(1, "resources/read", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.resourceNotFound);
}

unittest  // resources/read not-found carries structured data.uri (spec example shape)
{
	auto s = new McpServer("t", "1");
	Json p = Json.emptyObject;
	p["uri"] = "test://missing";
	auto resp = s.handle(req(1, "resources/read", p)).get;
	assert(resp["error"]["data"]["uri"].get!string == "test://missing");
}

unittest  // resource templates resolve and read with captured params
{
	auto s = new McpServer("t", "1");
	ResourceTemplate t = {uriTemplate: "test://tpl/{id}/data", name: "tpl"};
	s.registerResourceTemplate(t, (string uri, string[string] params) @safe {
		return ResourceContents.makeText(uri, "application/json", "id=" ~ params["id"]);
	});

	auto tl = s.handle(req(1, "resources/templates/list")).get;
	assert(tl["result"]["resourceTemplates"][0]["uriTemplate"].get!string == "test://tpl/{id}/data");

	Json p = Json.emptyObject;
	p["uri"] = "test://tpl/99/data";
	auto read = s.handle(req(2, "resources/read", p)).get;
	assert(read["result"]["contents"][0]["text"].get!string == "id=99");
}

unittest  // prompts/list and prompts/get with arguments
{
	auto s = new McpServer("t", "1");
	Prompt pr = {name: "greet", description: nullable("greets")};
	pr.arguments = [PromptArgument("who", nullable("name"), true)];
	s.registerDynamicPrompt(pr, (Json args) @safe {
		const who = ("who" in args) ? args["who"].get!string : "";
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText("Hi " ~ who))];
		return r;
	});

	auto list = s.handle(req(1, "prompts/list")).get;
	assert(list["result"]["prompts"][0]["name"].get!string == "greet");

	Json p = Json.emptyObject;
	p["name"] = "greet";
	p["arguments"] = Json(["who": Json("Sam")]);
	auto get = s.handle(req(2, "prompts/get", p)).get;
	assert(get["result"]["messages"][0]["content"]["text"].get!string == "Hi Sam");
}

unittest  // prompts/get returns -32602 when a required argument is missing
{
	auto s = new McpServer("t", "1");
	Prompt pr = {name: "greet", description: nullable("greets")};
	pr.arguments = [PromptArgument("who", nullable("name"), true)];
	s.registerDynamicPrompt(pr, (Json args) @safe {
		const who = ("who" in args) ? args["who"].get!string : "";
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText("Hi " ~ who))];
		return r;
	});

	// No "arguments" at all -> required "who" is missing.
	Json p = Json.emptyObject;
	p["name"] = "greet";
	auto resp = s.handle(req(2, "prompts/get", p)).get;
	assert("error" in resp, "expected an error for missing required argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);

	// Empty "arguments" object -> still missing.
	Json p2 = Json.emptyObject;
	p2["name"] = "greet";
	p2["arguments"] = Json.emptyObject;
	auto resp2 = s.handle(req(3, "prompts/get", p2)).get;
	assert("error" in resp2);
	assert(resp2["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // prompts/get allows a missing optional argument
{
	auto s = new McpServer("t", "1");
	Prompt pr = {name: "greet", description: nullable("greets")};
	pr.arguments = [PromptArgument("who", nullable("name"), false)];
	s.registerDynamicPrompt(pr, (Json args) @safe {
		const who = ("who" in args) ? args["who"].get!string : "world";
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText("Hi " ~ who))];
		return r;
	});

	Json p = Json.emptyObject;
	p["name"] = "greet";
	auto resp = s.handle(req(2, "prompts/get", p)).get;
	assert("result" in resp);
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "Hi world");
}

unittest  // completion/complete returns -32601 when no completions capability is declared
{
	auto s = new McpServer("t", "1");
	// No completion handler registered => completions capability not advertised.
	auto resp = s.handle(req(1, "completion/complete", Json.emptyObject)).get;
	assert("error" in resp);
	assert("result" !in resp);
	assert(resp["error"]["code"].get!int == ErrorCode.methodNotFound);
}

unittest  // completion/complete uses the registered typed handler
{
	auto s = new McpServer("t", "1");
	s.setCompletionRequestHandler((CompleteRequest) @safe {
		CompleteResult r;
		r.values = ["paris", "park"];
		return r;
	});
	auto resp = s.handle(req(1, "completion/complete", Json.emptyObject)).get;
	assert(resp["result"]["completion"]["values"].length == 2);
}

unittest  // typed completion handler receives a parsed CompleteRequest
{
	auto s = new McpServer("t", "1");
	string seenName;
	string seenArg;
	bool wasPrompt;
	s.setCompletionRequestHandler((CompleteRequest r) @safe {
		seenName = r.reference.name;
		seenArg = r.argumentValue;
		wasPrompt = r.isPrompt;
		CompleteResult res;
		res.values = ["paris"];
		return res;
	});
	Json p = Json.emptyObject;
	p["ref"] = CompletionReference.forPrompt("greet").toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "city";
	arg["value"] = "par";
	p["argument"] = arg;
	auto resp = s.handle(req(1, "completion/complete", p)).get;
	assert(resp["result"]["completion"]["values"][0].get!string == "paris");
	assert(seenName == "greet");
	assert(seenArg == "par");
	assert(wasPrompt);
}

unittest  // typed completion handler receives the resolved context.arguments
{
	auto s = new McpServer("t", "1");
	string[string] seenContext;
	s.setCompletionRequestHandler((CompleteRequest r) @safe {
		seenContext = r.context;
		CompleteResult res;
		res.values = ["main"];
		return res;
	});
	Json p = Json.emptyObject;
	p["ref"] = CompletionReference.forPrompt("greet").toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "branch";
	arg["value"] = "ma";
	p["argument"] = arg;
	Json args = Json.emptyObject;
	args["repo"] = "mcp.d";
	args["owner"] = "Poita";
	Json ctx = Json.emptyObject;
	ctx["arguments"] = args;
	p["context"] = ctx;
	auto resp = s.handle(req(1, "completion/complete", p)).get;
	assert(resp["result"]["completion"]["values"][0].get!string == "main");
	assert(seenContext["repo"] == "mcp.d");
	assert(seenContext["owner"] == "Poita");
}

unittest  // typed completion handler advertises the completions capability
{
	auto s = new McpServer("t", "1");
	s.setCompletionRequestHandler((CompleteRequest) @safe {
		CompleteResult res;
		return res;
	});
	auto init = s.handle(req(1, "initialize", Json.emptyObject)).get;
	assert("completions" in init["result"]["capabilities"]);
}

unittest  // logging/setLevel stores the level and returns an empty object
{
	auto s = new McpServer("t", "1");
	s.enableLogging();
	Json p = Json.emptyObject;
	p["level"] = "debug";
	auto resp = s.handle(req(1, "logging/setLevel", p)).get;
	assert(resp["result"].type == Json.Type.object && resp["result"].length == 0);
	assert(s.currentLogLevel == "debug");
}

unittest  // logging/setLevel rejects an unrecognised level with -32602
{
	auto s = new McpServer("t", "1");
	s.enableLogging();
	Json p = Json.emptyObject;
	p["level"] = "verbose";
	auto resp = s.handle(req(1, "logging/setLevel", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
	// The invalid level must not have been stored.
	assert(s.currentLogLevel == "info");
}

unittest  // logging/setLevel requires a string 'level' param
{
	auto s = new McpServer("t", "1");
	s.enableLogging();
	Json p = Json.emptyObject;
	auto resp = s.handle(req(1, "logging/setLevel", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // logging/setLevel is rejected when the logging capability was never declared
{
	// Per server/utilities/logging, the logging feature is gated on the declared
	// `logging` capability. A server that never called enableLogging() advertises
	// no logging capability, so logging/setLevel MUST NOT be handled: it returns
	// -32601 (Capability not supported), matching completion/complete's gating.
	auto s = new McpServer("t", "1");
	Json p = Json.emptyObject;
	p["level"] = "debug";
	auto resp = s.handle(req(1, "logging/setLevel", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.methodNotFound);
	// The level must not have been mutated by the rejected request.
	assert(s.currentLogLevel == "info");
}

unittest  // draft: logging/setLevel is method-not-found (removed in 2026-07-28)
{
	// The draft (2026-07-28) removed the logging/setLevel RPC in favour of the
	// per-request `_meta["io.modelcontextprotocol/logLevel"]` field (SEP-2575/2577).
	// On the draft the method does not exist, so it MUST return -32601 even when
	// the logging capability is enabled, and MUST NOT mutate session state.
	auto s = makeTestServer();
	s.enableLogging();
	Json p = Json.emptyObject;
	p["level"] = "debug";
	auto resp = s.handle(draftReq(1, "logging/setLevel", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.methodNotFound);
	assert(s.currentLogLevel == "info");
}

unittest  // after setLevel(error), a handler's sub-error logs are dropped
{
	// A context that records every log notification its handler emits.
	static final class RecordingCtx : RequestContext
	{
		string[] emitted;
		bool isCancelled() @safe
		{
			return false;
		}

		void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
		{
		}

		void log(string level, Json, string = null) @safe
		{
			emitted ~= level;
		}

		Json sendRequest(string, Json) @safe
		{
			return Json.undefined;
		}

		bool clientSupports(string) @safe
		{
			return false;
		}

		bool isStateless() @safe
		{
			return false;
		}

		Json[string] inputResponses() @safe
		{
			Json[string] e;
			return e;
		}

		string requestState() @safe
		{
			return "";
		}

		import mcp.auth.resource_server : TokenInfo;

		TokenInfo auth() @safe
		{
			return TokenInfo.invalid();
		}
	}

	auto s = new McpServer("t", "1");
	s.enableLogging();

	// A tool that emits a log at every severity.
	Tool t = {name: "noisy"};
	s.registerDynamicTool(t, (Json args, RequestContext ctx) @safe {
		ctx.log("debug", Json("d"));
		ctx.log("warning", Json("w"));
		ctx.log("error", Json("e"));
		ctx.log("emergency", Json("x"));
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});

	// Raise the client-set minimum to "error".
	Json p = Json.emptyObject;
	p["level"] = "error";
	s.handle(req(1, "logging/setLevel", p));

	auto ctx = new RecordingCtx;
	Json callP = Json.emptyObject;
	callP["name"] = "noisy";
	s.handle(req(2, "tools/call", callP), ctx);

	// Only error and above reached the transport context.
	assert(ctx.emitted == ["error", "emergency"]);
}

version (unittest) private final class DraftLogCtx : RequestContext
{
	string[] emitted;
	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string level, Json, string = null) @safe
	{
		emitted ~= level;
	}

	Json sendRequest(string, Json) @safe
	{
		return Json.undefined;
	}

	bool clientSupports(string) @safe
	{
		return false;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] e;
		return e;
	}

	string requestState() @safe
	{
		return "";
	}

	import mcp.auth.resource_server : TokenInfo;

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

version (unittest) private McpServer makeNoisyLogServer() @safe
{
	auto s = new McpServer("t", "1");
	s.enableLogging();
	Tool t = {name: "noisy"};
	s.registerDynamicTool(t, (Json args, RequestContext ctx) @safe {
		ctx.log("debug", Json("d"));
		ctx.log("warning", Json("w"));
		ctx.log("error", Json("e"));
		ctx.log("emergency", Json("x"));
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	return s;
}

unittest  // draft request WITHOUT logLevel emits no notifications/message at all
{
	auto s = makeNoisyLogServer();
	auto ctx = new DraftLogCtx;
	Json callP = Json.emptyObject;
	callP["name"] = "noisy";
	// draftReq with no logLevel argument => no io.modelcontextprotocol/logLevel.
	s.handle(draftReq(2, "tools/call", callP), ctx);

	// The MUST-NOT-emit-without-the-field requirement: nothing was emitted.
	assert(ctx.emitted.length == 0);
}

unittest  // draft request WITH logLevel emits only at or above that level
{
	auto s = makeNoisyLogServer();
	auto ctx = new DraftLogCtx;
	Json callP = Json.emptyObject;
	callP["name"] = "noisy";
	s.handle(draftReq(2, "tools/call", callP, "error"), ctx);

	assert(ctx.emitted == ["error", "emergency"]);
}

unittest  // draft request with an unrecognised logLevel is rejected with -32602
{
	auto s = makeNoisyLogServer();
	auto ctx = new DraftLogCtx;
	Json callP = Json.emptyObject;
	callP["name"] = "noisy";
	auto resp = s.handle(draftReq(2, "tools/call", callP, "verbose"), ctx).get;

	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
	// The handler must not have run / emitted anything.
	assert(ctx.emitted.length == 0);
}

unittest  // a draft request's logLevel does not leak into a later request
{
	auto s = makeNoisyLogServer();
	// First, a draft request that requests debug-level logging.
	auto ctx1 = new DraftLogCtx;
	Json call1 = Json.emptyObject;
	call1["name"] = "noisy";
	s.handle(draftReq(1, "tools/call", call1, "debug"), ctx1);
	assert(ctx1.emitted == ["debug", "warning", "error", "emergency"]);

	// A subsequent draft request without a logLevel must emit nothing — the
	// previous request's level must not have been stored as shared state.
	auto ctx2 = new DraftLogCtx;
	Json call2 = Json.emptyObject;
	call2["name"] = "noisy";
	s.handle(draftReq(2, "tools/call", call2), ctx2);
	assert(ctx2.emitted.length == 0);
}

unittest  // capabilities reflect registered features
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "u", name: "u"};
	s.registerResource(r, () @safe => ResourceContents.makeText("u", "text/plain", "x"));
	s.enableLogging();
	auto caps = s.capabilities();
	assert(!caps.resources.isNull);
	assert(caps.logging);
	assert(caps.prompts.isNull);
}

unittest  // advertised extensions appear in initialize capabilities
{
	auto s = new McpServer("t", "1");
	Json settings = Json.emptyObject;
	settings["maxConcurrent"] = 4;
	s.advertiseExtension("io.modelcontextprotocol/tasks", settings);

	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	auto resp = s.handle(req(1, "initialize", params)).get;
	auto ext = resp["result"]["capabilities"]["extensions"];
	assert(ext.type == Json.Type.object);
	assert(ext["io.modelcontextprotocol/tasks"]["maxConcurrent"].get!int == 4);
}

unittest  // enableTasks advertises the `tasks` capability at initialize
{
	auto s = new McpServer("t", "1");
	// Spec 2025-11-25: nested-by-category `requests`, i.e. {"tools": {"call": {}}}.
	s.enableTasks(true, true, TaskRequests().tool().toJson());

	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-11-25";
	auto resp = s.handle(req(1, "initialize", params)).get;
	auto t = resp["result"]["capabilities"]["tasks"];
	assert(t.type == Json.Type.object);
	assert(t["list"].type == Json.Type.object);
	assert(t["cancel"].type == Json.Type.object);
	assert(t["requests"]["tools"]["call"].type == Json.Type.object);
	assert("tools/call" !in t["requests"]);
}

unittest  // server reads the `tasks` capability a client advertises at initialize
{
	auto s = new McpServer("t", "1");
	Json caps = Json.emptyObject;
	Json t = Json.emptyObject;
	// Client advertises nested-by-category requests per spec 2025-11-25.
	t["requests"] = TaskRequests().samplingCreateMessage().toJson();
	caps["tasks"] = t;

	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-11-25";
	params["capabilities"] = caps;
	s.handle(req(1, "initialize", params));

	assert(!s.clientTasks.isNull);
	assert(s.clientTasks.get.requests["sampling"]["createMessage"].type == Json.Type.object);
}

unittest  // server reads the extensions a client advertises at initialize
{
	auto s = new McpServer("t", "1");
	Json caps = Json.emptyObject;
	Json ext = Json.emptyObject;
	ext["io.modelcontextprotocol/ui"] = Json.emptyObject;
	caps["extensions"] = ext;

	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = caps;
	s.handle(req(1, "initialize", params));

	assert(s.clientExtensions.type == Json.Type.object);
	assert("io.modelcontextprotocol/ui" in s.clientExtensions);
	assert("io.modelcontextprotocol/ui" in s.clientCapabilities.extensions);
}

unittest  // resources/subscribe and unsubscribe track URIs and return {}
{
	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	Json p = Json.emptyObject;
	p["uri"] = "test://w";
	auto sub = s.handle(req(1, "resources/subscribe", p)).get;
	assert(sub["result"].type == Json.Type.object && sub["result"].length == 0);
	assert(s.isSubscribed("test://w"));

	auto unsub = s.handle(req(2, "resources/unsubscribe", p)).get;
	assert(unsub["result"].length == 0);
	assert(!s.isSubscribed("test://w"));
}

unittest  // subscribe capability is advertised only when enabled
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "u", name: "u"};
	s.registerResource(r, () @safe => ResourceContents.makeText("u", "text/plain", "x"));
	assert(!s.capabilities().resources.get.subscribe);
	s.enableResourceSubscriptions();
	assert(s.capabilities().resources.get.subscribe);
}

version (unittest)
{
	// A request carrying draft per-request _meta (protocolVersion 2026-07-28).
	private Message draftReq(long id, string method,
			Json params = Json.emptyObject, string logLevel = null) @safe
	{
		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = "2026-07-28";
		meta[MetaKey.clientInfo] = Json([
			"name": Json("c"),
			"version": Json("1")
		]);
		meta[MetaKey.clientCapabilities] = Json.emptyObject;
		if (logLevel.length)
			meta[MetaKey.logLevel] = logLevel;
		params["_meta"] = meta;
		return Message(makeRequest(Json(id), method, params));
	}
}

unittest  // server/discover advertises all supported versions + identity
{
	auto s = makeTestServer();
	auto resp = s.handle(draftReq(1, "server/discover")).get;
	assert(resp["result"]["resultType"].get!string == "complete");
	auto pv = resp["result"]["supportedVersions"];
	bool hasDraft, hasFirst;
	foreach (i; 0 .. pv.length)
	{
		if (pv[i].get!string == "2026-07-28")
			hasDraft = true;
		if (pv[i].get!string == "2024-11-05")
			hasFirst = true;
	}
	assert(hasDraft && hasFirst);
	assert(resp["result"]["serverInfo"]["name"].get!string == "test-srv");
}

unittest  // per-list setListCacheHint: draft tools/list carries CacheableResult fields
{
	auto s = makeTestServer();
	s.setListCacheHint("tools/list", CacheHint(5000, CacheScope.private_));
	auto resp = s.handle(draftReq(2, "tools/list")).get;
	assert(resp["result"]["ttlMs"].get!long == 5000);
	assert(resp["result"]["cacheScope"].get!string == "private");
}

unittest  // per-list setListCacheHint: pre-draft tools/list has no cache fields
{
	auto s = makeTestServer();
	s.setListCacheHint("tools/list", CacheHint(5000));
	auto resp = s.handle(req(2, "tools/list")).get; // no draft _meta -> latestStable
	assert("ttlMs" !in resp["result"]);
}

unittest  // per-list hint only emits on the matching list, not on others
{
	auto s = makeTestServer();
	s.setListCacheHint("resources/list", CacheHint(7000));
	// tools/list has no hint configured, so no cache fields appear.
	auto tools = s.handle(draftReq(2, "tools/list")).get;
	assert("ttlMs" !in tools["result"]);
}

unittest  // per-resource registerResource hint emits ttlMs/cacheScope on a draft resources/read
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "test://r", name: "r", mimeType: nullable("text/plain")};
	s.registerResource(r, () @safe => ResourceContents.makeText("test://r",
			"text/plain", "x"), nullable(CacheHint(9000, CacheScope.private_)));
	Json p = Json.emptyObject;
	p["uri"] = "test://r";
	auto resp = s.handle(draftReq(2, "resources/read", p)).get;
	assert(resp["result"]["ttlMs"].get!long == 9000);
	assert(resp["result"]["cacheScope"].get!string == "private");
}

unittest  // per-resource hint is NOT emitted on a non-draft (2025-11-25) resources/read
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "test://r", name: "r", mimeType: nullable("text/plain")};
	s.registerResource(r, () @safe => ResourceContents.makeText("test://r",
			"text/plain", "x"), nullable(CacheHint(9000, CacheScope.private_)));
	Json p = Json.emptyObject;
	p["uri"] = "test://r";
	auto resp = s.handle(req(2, "resources/read", p)).get; // no draft _meta -> latestStable
	assert("ttlMs" !in resp["result"]);
}

unittest  // per-template registerResourceTemplate hint emits on a matching draft resources/read
{
	auto s = new McpServer("t", "1");
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "tmpl"};
	s.registerResourceTemplate(t, (string uri, string[string] params) @safe {
		return ResourceContents.makeText(uri, "text/plain", "y");
	}, nullable(CacheHint(4200)));
	Json p = Json.emptyObject;
	p["uri"] = "test://abc";
	auto resp = s.handle(draftReq(2, "resources/read", p)).get;
	assert(resp["result"]["ttlMs"].get!long == 4200);
	assert(resp["result"]["cacheScope"].get!string == "public");
}

// issue #288: a concurrent (reentrant) request must not corrupt the effective
// protocol version of an in-flight request. A draft tools/call whose handler
// dispatches a pre-draft request mid-flight (standing in for a handler that
// yields while another request is dispatched on the shared server) must still
// have ITS result stamped per the draft (resultType:"complete"), and the
// reentrant pre-draft request must stay unstamped. Before the fix both shared a
// single mutable effectiveVersion field, so the inner pre-draft request flipped
// it and the outer draft response lost its resultType.
unittest
{
	auto s = new McpServer("t", "1");
	Json innerResp = Json.undefined;
	Tool yielder = {name: "yielder", description: nullable("reentrant")};
	s.registerDynamicTool(yielder, (Json args, RequestContext ctx) @safe {
		// Mid-handle: dispatch a DIFFERENT-version request on the same server.
		// This is the interleave a yielding handler would expose under concurrency.
		innerResp = s.handle(req(99, "tools/list")).get; // pre-draft (latestStable)
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	// Outer request is on the draft protocol (per-request _meta).
	auto outer = s.handle(draftCall(1, "yielder", [])).get;
	assert("error" !in outer);
	// The outer draft response keeps its own effective version: resultType present.
	assert(outer["result"]["resultType"].get!string == "complete");
	// The reentrant pre-draft response is independent: no draft stamping leaked in.
	assert("error" !in innerResp);
	assert("resultType" !in innerResp["result"]);
}

unittest  // draft results carry the mandatory resultType:"complete" discriminator
{
	auto s = makeTestServer();
	// A representative success result built through the central dispatch path.
	auto resp = s.handle(draftReq(2, "tools/list")).get;
	assert("error" !in resp);
	assert(resp["result"]["resultType"].get!string == "complete");
}

unittest  // pre-draft results never emit resultType (wire output unchanged)
{
	auto s = makeTestServer();
	auto resp = s.handle(req(2, "tools/list")).get; // no draft _meta -> latestStable
	assert("error" !in resp);
	assert("resultType" !in resp["result"]);
}

unittest  // draft InputRequiredResult is stamped resultType:"input_required", not "complete"
{
	auto s = new McpServer("t", "1");
	registerBookTool(s);
	auto resp = s.handle(draftCall(1, "book", [])).get;
	assert("error" !in resp);
	assert(resp["result"]["resultType"].get!string == "input_required");
}

unittest  // draft resources/read unknown uri uses invalidParams (-32602)
{
	auto s = new McpServer("t", "1");
	Json p = Json.emptyObject;
	p["uri"] = "test://missing";
	auto resp = s.handle(draftReq(3, "resources/read", p)).get;
	assert(resp["error"]["code"].get!int == -32602);
}

unittest  // subscriptions/listen reads the spec-shaped filter nested under params.notifications
{
	auto s = makeTestServer();
	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;
	filter["resourceSubscriptions"] = Json([Json("file:///project/config.json")]);
	Json p = Json.emptyObject;
	p["notifications"] = filter;
	auto resp = s.handle(draftReq(4, "subscriptions/listen", p)).get;
	assert(resp["result"]["acknowledged"].get!bool);
	assert(s.listensFor("toolsListChanged"));
	assert(s.listensFor("resourceSubscriptions"));
	assert(!s.listensFor("promptsListChanged"));
	// resourceSubscriptions URIs are tracked as per-URI subscriptions.
	assert(s.isSubscribed("file:///project/config.json"));
}

unittest  // subscriptions/listen still accepts the legacy flat (top-level) filter shape
{
	auto s = makeTestServer();
	Json p = Json.emptyObject;
	p["toolsListChanged"] = true;
	p["resourceSubscriptions"] = true;
	auto resp = s.handle(draftReq(4, "subscriptions/listen", p)).get;
	assert(resp["result"]["acknowledged"].get!bool);
	assert(s.listensFor("toolsListChanged"));
	assert(s.listensFor("resourceSubscriptions"));
	assert(!s.listensFor("promptsListChanged"));
}

unittest  // subscriptions/listen with an empty resourceSubscriptions array does not opt in
{
	auto s = makeTestServer();
	Json filter = Json.emptyObject;
	filter["resourceSubscriptions"] = Json.emptyArray;
	Json p = Json.emptyObject;
	p["notifications"] = filter;
	s.handle(draftReq(4, "subscriptions/listen", p));
	assert(!s.listensFor("resourceSubscriptions"));
}

unittest  // acknowledgedListenSubset reflects exactly the opted-in change types
{
	auto s = makeTestServer();
	// Nothing opted in yet -> empty object.
	assert(s.acknowledgedListenSubset().type == Json.Type.object);
	assert(s.acknowledgedListenSubset().length == 0);

	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;
	filter["resourceSubscriptions"] = Json([Json("file:///project/config.json")]);
	filter["promptsListChanged"] = false; // explicitly not opted in
	Json p = Json.emptyObject;
	p["notifications"] = filter;
	s.handle(draftReq(7, "subscriptions/listen", p));

	auto subset = s.acknowledgedListenSubset();
	assert(subset["toolsListChanged"].get!bool);
	// `resourceSubscriptions` is the agreed string[] of URIs (a SubscriptionFilter),
	// not a boolean (draft basic/utilities/subscriptions Acknowledgment).
	assert(subset["resourceSubscriptions"].type == Json.Type.array);
	assert(subset["resourceSubscriptions"].length == 1);
	assert(subset["resourceSubscriptions"][0].get!string == "file:///project/config.json");
	assert("promptsListChanged" !in subset);
}

unittest  // ack echoes every opted-in resourceSubscriptions URI in request order
{
	auto s = makeTestServer();
	Json filter = Json.emptyObject;
	filter["resourceSubscriptions"] = Json([
		Json("file:///a.txt"), Json("file:///b.txt")
	]);
	Json p = Json.emptyObject;
	p["notifications"] = filter;
	s.handle(draftReq(8, "subscriptions/listen", p));

	auto subset = s.acknowledgedListenSubset();
	assert(subset["resourceSubscriptions"].type == Json.Type.array);
	assert(subset["resourceSubscriptions"].length == 2);
	assert(subset["resourceSubscriptions"][0].get!string == "file:///a.txt");
	assert(subset["resourceSubscriptions"][1].get!string == "file:///b.txt");
}

unittest  // draft is stateless: tools/call works without a prior initialize
{
	auto s = makeTestServer();
	Json p = Json.emptyObject;
	p["name"] = "add";
	p["arguments"] = Json(["a": Json(20), "b": Json(22)]);
	auto resp = s.handle(draftReq(5, "tools/call", p)).get;
	assert(resp["result"]["structuredContent"]["result"].get!int == 42);
}

version (unittest)
{
	// A request whose _meta declares an arbitrary protocol version.
	private Message versionedReq(long id, string method, string ver) @safe
	{
		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = ver;
		Json params = Json.emptyObject;
		params["_meta"] = meta;
		return Message(makeRequest(Json(id), method, params));
	}
}

unittest  // draft negotiation: unsupported version -> UnsupportedProtocolVersionError
{
	auto s = makeTestServer();
	auto resp = s.handle(versionedReq(1, "tools/list", "1900-01-01")).get;
	assert(resp["error"]["code"].get!int == ErrorCode.unsupportedProtocolVersion);
	assert(resp["error"]["data"]["requested"].get!string == "1900-01-01");
	// The supported list advertises our versions, including the draft revision.
	auto sup = resp["error"]["data"]["supported"];
	bool hasDraft;
	foreach (i; 0 .. sup.length)
		if (sup[i].get!string == "2026-07-28")
			hasDraft = true;
	assert(hasDraft);
}

unittest  // draft negotiation: a supported version is accepted (no error)
{
	auto s = makeTestServer();
	auto resp = s.handle(versionedReq(2, "tools/list", "2025-11-25")).get;
	assert("error" !in resp);
	assert(resp["result"]["tools"].length == 1);
}

unittest  // requests without a per-request version are unaffected (legacy path)
{
	auto s = makeTestServer();
	auto resp = s.handle(req(3, "tools/list")).get;
	assert("error" !in resp);
}

// ---------------------------------------------------------------------------
// MRTR (draft) tool handling: the handler branches on ctx.isStateless and either
// returns ToolResponse.inputRequired(...) (stateless) or calls ctx.elicit()
// (2025-era). No framework version-dispatch and no replay.
// ---------------------------------------------------------------------------

unittest  // ToolResponse.complete serializes to the tool result
{
	CallToolResult r;
	r.content = [Content.makeText("hi")];
	auto tr = ToolResponse.complete(r);
	assert(!tr.needsInput);
	assert(tr.toJson()["content"][0]["text"].get!string == "hi");
}

unittest  // ToolResponse.inputRequired serializes the input requests
{
	auto tr = ToolResponse.inputRequired([
		InputRequest("q1", "elicitation", Json.emptyObject)
	]);
	assert(tr.needsInput);
	auto j = tr.toJson();
	// SEP-2322 map shape: keyed by id, value is a `{ method, params }` object.
	assert(j["inputRequests"].type == Json.Type.object);
	assert("q1" in j["inputRequests"]);
	assert(j["inputRequests"]["q1"]["method"].get!string == "elicitation/create");
}

version (unittest)
{
	// A fake transport context: server->client requests return a canned answer.
	private final class FakeCtx : RequestContext
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

		Json sendRequest(string, Json) @safe
		{
			return Json([
				"action": Json("accept"),
				"content": Json(["day": Json("tuesday")])
			]);
		}

		bool clientSupports(string) @safe
		{
			return true;
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

		import mcp.auth.resource_server : TokenInfo;

		TokenInfo auth() @safe
		{
			return TokenInfo.invalid();
		}
	}

	// Register a tool that books a flight, asking for the date either via MRTR
	// (stateless) or a blocking elicit() (2025-era).
	private void registerBookTool(McpServer s) @safe
	{
		Tool book = {name: "book"};
		s.registerDynamicTool(book, (Json args, RequestContext ctx) @safe {
			if (ctx.isStateless)
			{
				auto answers = ctx.inputResponses();
				if ("date" !in answers)
				{
					Json ep = Json.emptyObject;
					ep["message"] = "When?";
					return ToolResponse.inputRequired([
						InputRequest("date", "elicitation", ep)
					]);
				}
				CallToolResult r;
				r.content = [
					Content.makeText("booked " ~ answers["date"]["content"]["day"].get!string)
				];
				return ToolResponse.complete(r);
			}
			else
			{
				auto answer = ctx.elicit("When?", Json.emptyObject);
				CallToolResult r;
				r.content = [
					Content.makeText("booked " ~ answer["content"]["day"].get!string)
				];
				return ToolResponse.complete(r);
			}
		});
	}

	// A draft tools/call carrying the given input responses in the top-level
	// params.inputResponses map (SEP-2322), with per-request _meta for the
	// stateless handshake fields.
	private Message draftCall(long id, string tool, InputResponse[] responses) @safe
	{
		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = "2026-07-28";
		meta[MetaKey.clientInfo] = Json([
			"name": Json("c"),
			"version": Json("1")
		]);
		meta[MetaKey.clientCapabilities] = Json.emptyObject;
		Json params = Json.emptyObject;
		params["name"] = tool;
		params["arguments"] = Json.emptyObject;
		params["_meta"] = meta;
		// SEP-2322: input responses are a top-level params field, not in _meta.
		if (responses.length)
			params["inputResponses"] = inputResponsesToJson(responses);
		return Message(makeRequest(Json(id), "tools/call", params));
	}
}

unittest  // draft (stateless) first round: handler returns an InputRequiredResult
{
	auto s = new McpServer("t", "1");
	registerBookTool(s);
	auto resp = s.handle(draftCall(1, "book", [])).get;
	assert("error" !in resp);
	// The MRTR `inputRequests` payload is a map keyed by the server id.
	assert(resp["result"]["inputRequests"].type == Json.Type.object);
	assert("date" in resp["result"]["inputRequests"]);
	assert(resp["result"]["inputRequests"]["date"]["method"].get!string == "elicitation/create");
}

unittest  // draft (stateless) retry with input responses: handler completes
{
	auto s = new McpServer("t", "1");
	registerBookTool(s);
	auto answer = InputResponse("date", Json([
			"content": Json(["day": Json("monday")])
	]));
	auto resp = s.handle(draftCall(2, "book", [answer])).get;
	assert("inputRequests" !in resp["result"]);
	assert(resp["result"]["content"][0]["text"].get!string == "booked monday");
}

unittest  // SEP-2322: a stateless server emits requestState and reads it back on retry
{
	auto s = new McpServer("t", "1");
	// A tool that stashes its progress entirely in the opaque requestState: on
	// the first round it asks for a date and attaches state "awaiting-date";
	// on retry it reads ctx.requestState() to know how to finish.
	Tool book = {name: "statebook"};
	s.registerDynamicTool(book, (Json args, RequestContext ctx) @safe {
		if (ctx.requestState() == "awaiting-date")
		{
			auto answers = ctx.inputResponses();
			CallToolResult r;
			r.content = [
				Content.makeText("resumed:" ~ ctx.requestState() ~ " day:"
					~ answers["date"]["content"]["day"].get!string)
			];
			return ToolResponse.complete(r);
		}
		Json ep = Json.emptyObject;
		ep["message"] = "When?";
		return ToolResponse.inputRequired([
			InputRequest("date", "elicitation", ep)
		], "awaiting-date");
	});

	// First round: the server attaches requestState onto the InputRequiredResult.
	auto first = s.handle(draftCall(10, "statebook", [])).get;
	assert(first["result"]["requestState"].get!string == "awaiting-date");

	// Retry: client echoes both the input responses and the opaque requestState.
	auto answer = InputResponse("date", Json([
			"content": Json(["day": Json("friday")])
	]));
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	Json params = Json.emptyObject;
	params["name"] = "statebook";
	params["arguments"] = Json.emptyObject;
	params["requestState"] = "awaiting-date";
	params["inputResponses"] = inputResponsesToJson([answer]);
	params["_meta"] = meta;
	auto retry = s.handle(Message(makeRequest(Json(11), "tools/call", params))).get;
	assert("inputRequests" !in retry["result"]);
	assert(retry["result"]["content"][0]["text"].get!string == "resumed:awaiting-date day:friday");
}

unittest  // elicit() is rejected on a stateless (draft) request
{
	auto s = new McpServer("t", "1");
	Tool bad = {name: "bad"};
	s.registerDynamicTool(bad, (Json args, RequestContext ctx) @safe {
		ctx.elicit("x", Json.emptyObject); // illegal under MRTR
		CallToolResult r;
		return ToolResponse.complete(r);
	});
	Json p = Json.emptyObject;
	auto resp = s.handle(draftReq(3, "tools/call", buildName(p, "bad"))).get;
	assert("error" in resp);
	assert(resp["error"]["code"].get!int == ErrorCode.invalidRequest);
}

unittest  // 2025-era request: ctx.elicit() blocks and the handler completes
{
	auto s = new McpServer("t", "1");
	registerBookTool(s);
	Json p = Json.emptyObject;
	auto resp = s.handle(req(4, "tools/call", buildName(p, "book")), new FakeCtx).get;
	assert("error" !in resp);
	assert(resp["result"]["content"][0]["text"].get!string == "booked tuesday");
}

version (unittest)
{
	private Json buildName(Json p, string tool) @safe
	{
		p["name"] = tool;
		p["arguments"] = Json.emptyObject;
		return p;
	}
}

unittest  // notify is a no-op (returns 0) before a push channel exists
{
	auto s = new McpServer("t", "1");
	assert(s.serverPushChannel() is null);
	assert(s.notify("notifications/message") == 0);
}

unittest  // notify delivers unsolicited notifications to GET-stream listeners
{
	auto s = new McpServer("t", "1");
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	assert(s.serverPushChannel() is ch); // same instance returned thereafter

	string[] received;
	ch.addListener((string f) @safe { received ~= f; });
	const n = s.notify("notifications/resources/updated", Json([
		"uri": Json("test://x")
	]));
	assert(n == 1);
	assert(received.length == 1);
	import std.algorithm : canFind;

	assert(received[0].canFind("notifications/resources/updated"));
}

unittest  // notifyResourceUpdated emits resources/updated for a subscribed uri
{
	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });

	Json p = Json.emptyObject;
	p["uri"] = "test://w";
	s.handle(req(1, "resources/subscribe", p));

	const n = s.notifyResourceUpdated("test://w");
	assert(n == 1);
	import std.algorithm : canFind;

	assert(received.length == 1);
	assert(received[0].canFind("notifications/resources/updated"));
	assert(received[0].canFind("test://w"));
}

unittest  // notifyResourceUpdated is a no-op for a uri nobody subscribed to
{
	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });

	const n = s.notifyResourceUpdated("test://never");
	assert(n == 0);
	assert(received.length == 0);
}

unittest  // notifyResourceUpdated emits params that are exactly { uri } (no non-spec title)
{
	import std.algorithm : canFind;

	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });

	Json p = Json.emptyObject;
	p["uri"] = "test://w";
	s.handle(req(1, "resources/subscribe", p));

	const n = s.notifyResourceUpdated("test://w");
	assert(n == 1);

	// No MCP spec version defines a `title` field on
	// ResourceUpdatedNotificationParams; params must be exactly { uri }.
	assert(received[0].canFind("test://w"));
	assert(!received[0].canFind("\"title\""));
}

unittest  // notifyResourceUpdated has no title overload (title is not a spec param)
{
	auto s = new McpServer("t", "1");
	// The single-argument (uri only) form must exist.
	static assert(__traits(compiles, s.notifyResourceUpdated("test://w")));
	// A `title` argument is NOT part of any spec version, so the two-argument
	// overload must NOT exist.
	static assert(!__traits(compiles, s.notifyResourceUpdated("test://w", nullable("X"))));
}

unittest  // notifyResourceUpdated is a no-op before a push channel exists
{
	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	Json p = Json.emptyObject;
	p["uri"] = "test://w";
	s.handle(req(1, "resources/subscribe", p));
	assert(s.notifyResourceUpdated("test://w") == 0);
}

unittest  // notifyElicitationComplete emits notifications/elicitation/complete with the id
{
	auto s = new McpServer("t", "1");
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });

	const n = s.notifyElicitationComplete("elic-123");
	assert(n == 1);
	import std.algorithm : canFind;

	assert(received.length == 1);
	assert(received[0].canFind("notifications/elicitation/complete"));
	assert(received[0].canFind("elicitationId"));
	assert(received[0].canFind("elic-123"));
}

unittest  // notifyElicitationComplete is a no-op before a push channel exists
{
	auto s = new McpServer("t", "1");
	assert(s.notifyElicitationComplete("elic-1") == 0);
}

unittest  // notifyElicitationComplete rejects an empty elicitationId
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	assertThrown!McpException(s.notifyElicitationComplete(""));
}

unittest  // tools listChanged is not advertised by default
{
	auto s = new McpServer("t", "1");
	Tool add = {name: "add"};
	s.registerDynamicTool(add, (Json) @safe { return CallToolResult(); });
	auto caps = s.capabilities();
	assert(!caps.tools.isNull);
	assert(!caps.tools.get.listChanged);
}

unittest  // enableToolListChanged advertises listChanged:true for tools
{
	auto s = new McpServer("t", "1");
	Tool add = {name: "add"};
	s.registerDynamicTool(add, (Json) @safe { return CallToolResult(); });
	s.enableToolListChanged();
	auto caps = s.capabilities();
	assert(!caps.tools.isNull);
	assert(caps.tools.get.listChanged);
	assert(caps.toJson()["tools"]["listChanged"].get!bool);
}

unittest  // enableToolListChanged advertises tools capability with zero tools registered
{
	// A server that will add tools at runtime declares enableToolListChanged()
	// before any tool is registered. Per 2025-11-25 tools §Capabilities, it MUST
	// still advertise the tools capability so clients call tools/list and expect
	// notifications/tools/list_changed.
	auto s = new McpServer("t", "1");
	s.enableToolListChanged();
	auto caps = s.capabilities();
	assert(!caps.tools.isNull);
	assert(caps.tools.get.listChanged);
	assert(caps.toJson()["tools"]["listChanged"].get!bool);
}

unittest  // removeTool unregisters a previously registered tool
{
	auto s = new McpServer("t", "1");
	Tool add = {name: "add"};
	s.registerDynamicTool(add, (Json) @safe { return CallToolResult(); });
	assert(s.removeTool("add"));
	auto resp = s.handle(req(1, "tools/list")).get;
	assert(resp["result"]["tools"].length == 0);
	assert(!s.removeTool("add")); // already gone
}

unittest  // notifyToolsListChanged broadcasts notifications/tools/list_changed
{
	auto s = new McpServer("t", "1");
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });
	const n = s.notifyToolsListChanged();
	assert(n == 1);
	import std.algorithm : canFind;

	assert(received.length == 1);
	assert(received[0].canFind("notifications/tools/list_changed"));
}

unittest  // notifyToolsListChanged is a no-op before a push channel exists
{
	auto s = new McpServer("t", "1");
	assert(s.notifyToolsListChanged() == 0);
}

unittest  // resources listChanged is not advertised by default
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "test://r", name: "r"};
	s.registerResource(r, () @safe => ResourceContents.makeText("test://r", "text/plain", "x"));
	auto caps = s.capabilities();
	assert(!caps.resources.isNull);
	assert(!caps.resources.get.listChanged);
}

unittest  // enableResourcesListChanged advertises listChanged:true for resources
{
	auto s = new McpServer("t", "1");
	Resource r = {uri: "test://r", name: "r"};
	s.registerResource(r, () @safe => ResourceContents.makeText("test://r", "text/plain", "x"));
	s.enableResourcesListChanged();
	auto caps = s.capabilities();
	assert(!caps.resources.isNull);
	assert(caps.resources.get.listChanged);
	assert(caps.toJson()["resources"]["listChanged"].get!bool);
}

unittest  // enableResourcesListChanged advertises resources capability with zero resources registered
{
	// A server that will add resources at runtime declares enableResourcesListChanged()
	// before any resource is registered. Per 2025-11-25 resources §Capabilities, it
	// MUST still advertise the resources capability so clients call resources/list and
	// expect notifications/resources/list_changed.
	auto s = new McpServer("t", "1");
	s.enableResourcesListChanged();
	auto caps = s.capabilities();
	assert(!caps.resources.isNull);
	assert(caps.resources.get.listChanged);
	assert(caps.toJson()["resources"]["listChanged"].get!bool);
}

unittest  // enableResourceSubscriptions advertises resources capability with zero resources registered
{
	// A server that supports resource update subscriptions declares
	// enableResourceSubscriptions() so clients learn they may resources/subscribe,
	// even before any resource is registered (per 2025-11-25 resources §Capabilities).
	auto s = new McpServer("t", "1");
	s.enableResourceSubscriptions();
	auto caps = s.capabilities();
	assert(!caps.resources.isNull);
	assert(caps.resources.get.subscribe);
	assert(caps.toJson()["resources"]["subscribe"].get!bool);
}

unittest  // notifyResourcesListChanged broadcasts notifications/resources/list_changed
{
	auto s = new McpServer("t", "1");
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });
	const n = s.notifyResourcesListChanged();
	assert(n == 1);
	import std.algorithm : canFind;

	assert(received.length == 1);
	assert(received[0].canFind("notifications/resources/list_changed"));
}

unittest  // notifyResourcesListChanged is a no-op before a push channel exists
{
	auto s = new McpServer("t", "1");
	assert(s.notifyResourcesListChanged() == 0);
}

unittest  // prompts listChanged is not advertised by default
{
	auto s = new McpServer("t", "1");
	Prompt pr = {name: "greet"};
	s.registerDynamicPrompt(pr, (Json) @safe { return GetPromptResult(); });
	auto caps = s.capabilities();
	assert(!caps.prompts.isNull);
	assert(!caps.prompts.get.listChanged);
}

unittest  // enablePromptListChanged advertises prompts capability with zero prompts registered
{
	// A server that will add prompts at runtime declares enablePromptListChanged()
	// before any prompt is registered. Per 2025-11-25 prompts §Capabilities, it
	// MUST still advertise the prompts capability so clients call prompts/list and
	// expect notifications/prompts/list_changed.
	auto s = new McpServer("t", "1");
	s.enablePromptListChanged();
	auto caps = s.capabilities();
	assert(!caps.prompts.isNull);
	assert(caps.prompts.get.listChanged);
	assert(caps.toJson()["prompts"]["listChanged"].get!bool);
}

unittest  // enablePromptListChanged advertises listChanged:true for prompts
{
	auto s = new McpServer("t", "1");
	Prompt pr = {name: "greet"};
	s.registerDynamicPrompt(pr, (Json) @safe { return GetPromptResult(); });
	s.enablePromptListChanged();
	auto caps = s.capabilities();
	assert(!caps.prompts.isNull);
	assert(caps.prompts.get.listChanged);
	assert(caps.toJson()["prompts"]["listChanged"].get!bool);
}

unittest  // notifyPromptsListChanged broadcasts notifications/prompts/list_changed
{
	auto s = new McpServer("t", "1");
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });
	const n = s.notifyPromptsListChanged();
	assert(n == 1);
	import std.algorithm : canFind;

	assert(received.length == 1);
	assert(received[0].canFind("notifications/prompts/list_changed"));
}

unittest  // notifyPromptsListChanged is a no-op before a push channel exists
{
	auto s = new McpServer("t", "1");
	assert(s.notifyPromptsListChanged() == 0);
}

unittest  // draft: concurrent listen streams only receive the type each opted into
{
	// Regression for per-stream notification filtering (draft basic/utilities/
	// subscriptions): "The server MUST NOT send notification types the client has not
	// explicitly requested." Two concurrent subscriptions/listen streams: A opted into
	// toolsListChanged only, B into resourceSubscriptions only. notifyToolsListChanged
	// MUST reach A and never B, even though B registered first.
	import std.algorithm : canFind;

	auto s = makeTestServer();
	auto coord = new StreamCoordinator;
	auto push = s.serverPushChannel(coord);

	// Stream B (resourceSubscriptions only) opens FIRST.
	Json nb = Json.emptyObject;
	nb["resourceSubscriptions"] = Json([Json("file:///b")]);
	Json pb = Json.emptyObject;
	pb["notifications"] = nb;
	s.handle(draftReq(10, "subscriptions/listen", pb));
	string bFrame;
	push.addListener((string f) @safe { bFrame = f; }, "10", s.lastListenFilter());

	// Stream A (toolsListChanged only) opens second.
	Json na = Json.emptyObject;
	na["toolsListChanged"] = true;
	Json pa = Json.emptyObject;
	pa["notifications"] = na;
	s.handle(draftReq(11, "subscriptions/listen", pa));
	string aFrame;
	push.addListener((string f) @safe { aFrame = f; }, "11", s.lastListenFilter());

	// A tools/list_changed must land on A (which requested it), not B.
	const n = s.notifyToolsListChanged();
	assert(n == 1);
	assert(aFrame.canFind("notifications/tools/list_changed"));
	assert(aFrame.canFind("11")); // stamped with A's subscriptionId
	assert(bFrame.length == 0); // B never requested toolsListChanged

	// And a resources/updated for file:///b must land on B, not A.
	aFrame = null;
	bFrame = null;
	const r = s.notifyResourceUpdated("file:///b");
	assert(r == 1);
	assert(bFrame.canFind("notifications/resources/updated"));
	assert(bFrame.canFind("file:///b"));
	assert(aFrame.length == 0); // A did not subscribe to resources
}

unittest  // draft: notifyPromptsListChanged suppressed unless client opted in
{
	auto s = new McpServer("t", "1");
	s.connectionVersion = ProtocolVersion.draft;
	auto coord = new StreamCoordinator;
	auto ch = s.serverPushChannel(coord);
	string[] received;
	ch.addListener((string f) @safe { received ~= f; });
	// No subscriptions/listen opt-in: suppressed.
	assert(s.notifyPromptsListChanged() == 0);
	assert(received.length == 0);
	// After opting in via subscriptions/listen, it is delivered.
	Json p = Json.emptyObject;
	p["promptsListChanged"] = true;
	s.handle(req(1, "subscriptions/listen", p));
	assert(s.notifyPromptsListChanged() == 1);
}

version (unittest)
{
	// Extract the names from a list result's items array (handler returns @safe).
	private string[] itemNames(Json items, string field) @safe
	{
		string[] names;
		foreach (i; 0 .. items.length)
			names ~= items[i][field].get!string;
		return names;
	}
}

unittest  // setPageSize paginates tools/list across cursor-following pages
{
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 5)
	{
		Tool tool = {name: "tool" ~ i.to!string};
		s.registerDynamicTool(tool, (Json) @safe {
			CallToolResult r;
			r.content = [Content.makeText("ok")];
			return r;
		});
	}
	s.setPageSize(2);

	// First page: 2 tools + a nextCursor.
	auto page1 = s.handle(req(1, "tools/list")).get;
	assert(page1["result"]["tools"].length == 2);
	assert(page1["result"]["nextCursor"].type == Json.Type.string);
	const cursor1 = page1["result"]["nextCursor"].get!string;

	// Second page via the cursor: next 2 + another nextCursor.
	Json p2 = Json.emptyObject;
	p2["cursor"] = cursor1;
	auto page2 = s.handle(req(2, "tools/list", p2)).get;
	assert(page2["result"]["tools"].length == 2);
	assert(page2["result"]["nextCursor"].type == Json.Type.string);
	const cursor2 = page2["result"]["nextCursor"].get!string;

	// Final page: the last tool, no nextCursor.
	Json p3 = Json.emptyObject;
	p3["cursor"] = cursor2;
	auto page3 = s.handle(req(3, "tools/list", p3)).get;
	assert(page3["result"]["tools"].length == 1);
	assert("nextCursor" !in page3["result"]);
}

unittest  // without setPageSize, tools/list returns everything in one page (no cursor)
{
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 5)
	{
		Tool tool = {name: "tool" ~ i.to!string};
		s.registerDynamicTool(tool, (Json) @safe {
			CallToolResult r;
			r.content = [Content.makeText("ok")];
			return r;
		});
	}
	auto resp = s.handle(req(1, "tools/list")).get;
	assert(resp["result"]["tools"].length == 5);
	assert("nextCursor" !in resp["result"]);
}

unittest  // setPageSize paginates resources/list
{
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 3)
	{
		Resource r = {uri: "test://r" ~ i.to!string, name: "r"};
		s.registerResource(r, () @safe => ResourceContents.makeText("test://r", "text/plain", "x"));
	}
	s.setPageSize(2);

	auto p1 = s.handle(req(1, "resources/list")).get;
	assert(p1["result"]["resources"].length == 2);
	const c = p1["result"]["nextCursor"].get!string;

	Json p = Json.emptyObject;
	p["cursor"] = c;
	auto p2 = s.handle(req(2, "resources/list", p)).get;
	assert(p2["result"]["resources"].length == 1);
	assert("nextCursor" !in p2["result"]);
}

unittest  // setPageSize paginates prompts/list
{
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 3)
	{
		Prompt pr = {name: "p" ~ i.to!string};
		s.registerDynamicPrompt(pr, (Json) @safe { GetPromptResult r; return r; });
	}
	s.setPageSize(2);

	auto p1 = s.handle(req(1, "prompts/list")).get;
	assert(p1["result"]["prompts"].length == 2);
	const c = p1["result"]["nextCursor"].get!string;

	Json p = Json.emptyObject;
	p["cursor"] = c;
	auto p2 = s.handle(req(2, "prompts/list", p)).get;
	assert(p2["result"]["prompts"].length == 1);
	assert("nextCursor" !in p2["result"]);
}

unittest  // setPageSize paginates resources/templates/list
{
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 3)
	{
		ResourceTemplate t = {
			uriTemplate: "test://t" ~ i.to!string ~ "/{id}", name: "t"
		};
		s.registerResourceTemplate(t, (string uri, string[string] params) @safe {
			return ResourceContents.makeText(uri, "text/plain", "x");
		});
	}
	s.setPageSize(2);

	auto p1 = s.handle(req(1, "resources/templates/list")).get;
	assert(p1["result"]["resourceTemplates"].length == 2);
	const c = p1["result"]["nextCursor"].get!string;

	Json p = Json.emptyObject;
	p["cursor"] = c;
	auto p2 = s.handle(req(2, "resources/templates/list", p)).get;
	assert(p2["result"]["resourceTemplates"].length == 1);
	assert("nextCursor" !in p2["result"]);
}

unittest  // an invalid pagination cursor yields invalidParams (-32602)
{
	auto s = new McpServer("t", "1");
	Tool tool = {name: "only"};
	s.registerDynamicTool(tool, (Json) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.setPageSize(1);
	Json p = Json.emptyObject;
	p["cursor"] = "!!!not-a-valid-cursor!!!";
	auto resp = s.handle(req(1, "tools/list", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // a stale cursor pointing past the end of the list yields invalidParams (-32602)
{
	import std.string : representation;
	import mcp.auth.oauth : base64UrlNoPad;

	auto s = new McpServer("t", "1");
	Tool tool = {name: "only"};
	s.registerDynamicTool(tool, (Json) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	s.setPageSize(1);
	// A well-formed cursor encoding an offset far beyond the single registered
	// tool: the client may be replaying a stale cursor from a longer, earlier
	// result set. This MUST be rejected with -32602 rather than silently
	// returning an empty final page.
	Json p = Json.emptyObject;
	p["cursor"] = base64UrlNoPad("999".representation);
	auto resp = s.handle(req(1, "tools/list", p)).get;
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
}

unittest  // a full roundtrip through cursor-following pagination yields every tool exactly once
{
	import std.algorithm : sort, uniq;
	import std.array : array;
	import std.conv : to;

	auto s = new McpServer("t", "1");
	foreach (i; 0 .. 7)
	{
		Tool tool = {name: "tool" ~ i.to!string};
		s.registerDynamicTool(tool, (Json) @safe {
			CallToolResult r;
			r.content = [Content.makeText("ok")];
			return r;
		});
	}
	s.setPageSize(3);

	string[] collected;
	Nullable!string cursor;
	do
	{
		Json p = Json.emptyObject;
		if (!cursor.isNull)
			p["cursor"] = cursor.get;
		auto resp = s.handle(req(1, "tools/list", p)).get;
		collected ~= itemNames(resp["result"]["tools"], "name");
		if ("nextCursor" in resp["result"])
			cursor = resp["result"]["nextCursor"].get!string;
		else
			cursor.nullify();
	}
	while (!cursor.isNull);

	assert(collected.length == 7);
	auto deduped = collected.dup.sort.uniq.array;
	assert(deduped.length == 7);
}

// --- issue #298: the whole handler surface is typed; raw-Json registration is
// confined to a single, explicitly-named dynamic escape hatch ----------------

unittest  // the raw-Json register*/completion entry points are gone (no backwards-compat)
{
	auto s = new McpServer("t", "1");
	Tool t;
	t.name = "x";
	Prompt p;
	p.name = "x";
	// The old raw-Json names must no longer compile: the only Json-typed
	// registration is the explicit dynamic hatch.
	static assert(!__traits(hasMember, s, "registerTool"));
	static assert(!__traits(hasMember, s, "registerPrompt"));
	static assert(!__traits(hasMember, s, "setCompletionHandler"));
}

unittest  // the dynamic tool hatch accepts a raw-Json handler and dispatches it
{
	auto s = new McpServer("t", "1");
	Tool t;
	t.name = "shout";
	s.registerDynamicTool(t, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText(args["msg"].get!string)];
		return r;
	});
	Json p = Json.emptyObject;
	p["name"] = "shout";
	Json a = Json.emptyObject;
	a["msg"] = "hi";
	p["arguments"] = a;
	auto resp = s.handle(req(1, "tools/call", p)).get;
	assert(resp["result"]["content"][0]["text"].get!string == "hi");
}

unittest  // the dynamic prompt hatch accepts a raw-Json handler and dispatches it
{
	auto s = new McpServer("t", "1");
	Prompt pr;
	pr.name = "greet";
	s.registerDynamicPrompt(pr, (Json args) @safe {
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText("hello"))];
		return r;
	});
	Json p = Json.emptyObject;
	p["name"] = "greet";
	auto resp = s.handle(req(1, "prompts/get", p)).get;
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "hello");
}

unittest  // the only completion entry point is the typed CompleteRequest one
{
	auto s = new McpServer("t", "1");
	static assert(__traits(compiles, s.setCompletionRequestHandler((CompleteRequest) @safe {
				CompleteResult r;
				return r;
			})));
	// A raw-Json completion handler must not compile any more.
	static assert(!__traits(compiles, s.setCompletionHandler((Json) @safe {
				CompleteResult r;
				return r;
			})));
}
