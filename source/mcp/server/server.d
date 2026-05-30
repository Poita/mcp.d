module mcp.server.server;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.versions;
import mcp.protocol.errors;
import mcp.protocol.jsonrpc;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.protocol.draft;
import mcp.server.context;
import mcp.transport.sse_context : ServerPushChannel, StreamCoordinator;

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
}

/// A registered resource template: descriptor + reader receiving the concrete
/// URI and the captured `{var}` parameters.
struct RegisteredTemplate
{
    ResourceTemplate descriptor;
    ResourceContents delegate(string uri, string[string] params) @safe reader;
}

/// A registered prompt: descriptor + handler producing its messages.
struct RegisteredPrompt
{
    Prompt descriptor;
    GetPromptResult delegate(Json arguments) @safe handler;
}

/// The transport-agnostic core of an MCP server.
///
/// `MCPServer` owns registration and JSON-RPC dispatch. It has no I/O: feed it
/// parsed messages via `handle` (or raw text via `handleRaw`) and it returns the
/// response to write back. Transports (stdio, HTTP) are thin drivers over this.
final class MCPServer
{
    private string serverName;
    private string serverVersion;
    private Nullable!string instructions;
    private RegisteredTool[string] tools;
    private RegisteredResource[string] resources;
    private RegisteredTemplate[] templates;
    private RegisteredPrompt[string] prompts;
    private CompleteResult delegate(Json params) @safe completionHandler;
    private bool loggingEnabled;
    private string logLevel = "info";
    private bool resourceSubscriptionsEnabled;
    private bool[string] subscriptions;
    private Nullable!TasksCapability tasksCapability;
    private Json extensions = Json.undefined;
    private ProtocolVersion negotiated = latestStable;
    private ProtocolVersion effectiveVersion = latestStable;
    private ClientCapabilities clientCaps;
    private bool initialized;
    private long cacheTtlMs;
    private CacheScope cacheScope_ = CacheScope.public_;
    private bool[string] listenFilters;
    private ServerPushChannel pushChannel;
    private bool toolListChangedEnabled;
    private bool resourcesListChangedEnabled;
    private bool validateOutputSchema_;

    this(string name, string version_, Nullable!string instructions = Nullable!string.init) @safe
    {
        this.serverName = name;
        this.serverVersion = version_;
        this.instructions = instructions;
    }

    /// The protocol version negotiated with the client (valid after `initialize`).
    ProtocolVersion negotiatedVersion() const @safe
    {
        return negotiated;
    }

    /// Register a tool with a context-aware handler (progress / logging /
    /// sampling / elicitation available via `ctx`).
    void registerTool(Tool descriptor, ToolHandler handler) @safe
    {
        tools[descriptor.name] = RegisteredTool(descriptor, (Json args,
                RequestContext ctx) => ToolResponse.complete(handler(args, ctx)));
    }

    /// Register a tool with a simple handler that ignores the request context.
    void registerTool(Tool descriptor, CallToolResult delegate(Json) @safe handler) @safe
    {
        tools[descriptor.name] = RegisteredTool(descriptor, (Json args,
                RequestContext) => ToolResponse.complete(handler(args)));
    }

    /// Register a tool whose handler may ask the client for more input on a
    /// stateless (MRTR) request. The handler branches on `ctx.isStateless`:
    /// when stateless it reads `ctx.inputResponses` and returns either
    /// `ToolResponse.complete` or `ToolResponse.inputRequired`; otherwise it may
    /// call the blocking `ctx.elicit`/`ctx.sample`. A server that wants to serve
    /// both protocol eras handles both branches here.
    void registerTool(Tool descriptor, MrtrToolHandler handler) @safe
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

    /// Broadcast a `notifications/tools/list_changed` to every client listening
    /// on the standalone GET SSE stream, informing them the set of available
    /// tools changed (per the server/tools List Changed Notification). Returns
    /// the number of listeners reached; `0` when no GET stream is open. Call
    /// after a runtime `registerTool` / `removeTool`. For the draft protocol,
    /// the notification is suppressed unless a client opted in via
    /// `subscriptions/listen` with `toolsListChanged:true`.
    size_t notifyToolsListChanged() @safe
    {
        if (effectiveVersion.isDraft && !listensFor("toolsListChanged"))
            return 0;
        return notify("notifications/tools/list_changed");
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
        if (effectiveVersion.isDraft && !listensFor("resourcesListChanged"))
            return 0;
        return notify("notifications/resources/list_changed");
    }

    /// Notify subscribers that a watched resource changed by emitting a
    /// `notifications/resources/updated` on the standalone GET SSE stream (per
    /// server/resources Subscriptions: "Server delivers
    /// notifications/resources/updated ... whenever a watched resource
    /// changes"). The notification carries `{ "uri": ... }`, plus an optional
    /// `title` (2025-11-25). It is delivered only when a client is currently
    /// subscribed to `uri` (via `resources/subscribe`); for an unsubscribed URI
    /// it is a no-op returning `0`. For the draft protocol the notification is
    /// additionally suppressed unless a client opted in via `subscriptions/listen`
    /// with `resourceSubscriptions:true`. Returns the number of GET-stream
    /// listeners reached; `0` when no GET stream is open.
    size_t notifyResourceUpdated(string uri, Nullable!string title = Nullable!string.init) @safe
    {
        if (!isSubscribed(uri))
            return 0;
        if (effectiveVersion.isDraft && !listensFor("resourceSubscriptions"))
            return 0;
        Json params = Json.emptyObject;
        params["uri"] = uri;
        if (!title.isNull)
            params["title"] = title.get;
        return notify("notifications/resources/updated", params);
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

    /// Register a direct resource with a reader for its contents.
    void registerResource(Resource descriptor, ResourceContents delegate() @safe reader) @safe
    {
        resources[descriptor.uri] = RegisteredResource(descriptor, reader);
    }

    /// Register a resource template with a reader receiving the matched URI and
    /// captured `{var}` parameters.
    void registerResourceTemplate(ResourceTemplate descriptor,
            ResourceContents delegate(string uri, string[string] params) @safe reader) @safe
    {
        templates ~= RegisteredTemplate(descriptor, reader);
    }

    /// Register a prompt with the handler that produces its messages.
    void registerPrompt(Prompt descriptor, GetPromptResult delegate(Json) @safe handler) @safe
    {
        prompts[descriptor.name] = RegisteredPrompt(descriptor, handler);
    }

    /// Set the handler for `completion/complete`. Declaring it advertises the
    /// completions capability.
    void setCompletionHandler(CompleteResult delegate(Json params) @safe handler) @safe
    {
        completionHandler = handler;
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

    /// Advertise the 2025-11-25 `tasks` capability (support for task-augmented
    /// requests). `list`/`cancel` indicate support for `tasks/list` and
    /// `tasks/cancel`; `requests` is a map of request method names (e.g.
    /// "tools/call") to per-request settings objects. The capability appears in
    /// the `tasks` field of the server capabilities sent during `initialize` /
    /// `server/discover`.
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
    /// server is not on a Streamable HTTP transport).
    size_t notify(string method, Json params = Json.undefined) @safe
    {
        if (pushChannel is null)
            return 0;
        return pushChannel.notify(method, params);
    }

    /// Capabilities this server advertises, derived from what is registered.
    ServerCapabilities capabilities() const @safe
    {
        ServerCapabilities caps;
        if (tools.length > 0)
            caps.tools = ListChangedCapability(toolListChangedEnabled);
        if (resources.length > 0 || templates.length > 0)
            caps.resources = ResourcesCapability(resourceSubscriptionsEnabled,
                    resourcesListChangedEnabled);
        if (prompts.length > 0)
            caps.prompts = ListChangedCapability(false);
        if (completionHandler !is null)
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
            return nullable(handleRequest(msg, ctx));
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
        import vibe.data.json : parseJsonString;

        ParsedInput input;
        try
            input = parseAny(text);
        catch (McpException e)
            return makeErrorResponse(Json(null), e).toString();
        catch (Exception e)
            return makeErrorResponse(Json(null), parseError(e.msg)).toString();

        if (!input.isBatch)
        {
            auto resp = handle(input.messages[0]);
            return resp.isNull ? "" : resp.get.toString();
        }

        Json responses = Json.emptyArray;
        foreach (m; input.messages)
        {
            auto resp = handle(m);
            if (!resp.isNull)
                responses ~= resp.get;
        }
        return responses.length == 0 ? "" : responses.toString();
    }

    private Json handleRequest(Message msg, RequestContext ctx) @safe
    {
        // Determine the version in effect for THIS request. Draft+ is stateless:
        // each request carries its protocol version, client identity, and
        // capabilities in `params._meta` rather than relying on `initialize`.
        effectiveVersion = negotiated;
        auto meta = RequestMeta.fromParams(msg.params);
        if (meta.protocolVersion.length)
        {
            ProtocolVersion mv;
            if (tryParseVersion(meta.protocolVersion, mv))
            {
                effectiveVersion = mv;
                if (mv.isDraft)
                {
                    clientCaps = meta.clientCapabilities;
                    if (!meta.logLevel.isNull)
                        logLevel = meta.logLevel.get;
                }
            }
            else
            {
                // Per-request protocol-version negotiation (draft): the client
                // declared a version we do not support -> reject with the list of
                // versions we do support so it can retry with a compatible one.
                return makeErrorResponse(msg.id, unsupportedVersionError(meta.protocolVersion));
            }
        }

        // Install the per-request scope so handlers see the right statelessness
        // (MRTR vs blocking) and the input responses carried on a retried draft
        // request, regardless of which transport supplied the base context.
        auto scoped = new RequestScope(ctx, effectiveVersion.usesMRTR,
                readInputResponses(msg.params));

        try
        {
            auto result = route(msg.method, msg.params, scoped);
            return makeResponse(msg.id, result);
        }
        catch (McpException e)
            return makeErrorResponse(msg.id, e);
        catch (Exception e)
            return makeErrorResponse(msg.id, internalError(e.msg));
    }

    /// Configure the `CacheableResult` freshness hint (`ttlMs`/`cacheScope`)
    /// added to list/read results when speaking the draft protocol.
    void setCacheHint(long ttlMs, CacheScope scope_ = CacheScope.public_) @safe
    {
        cacheTtlMs = ttlMs;
        cacheScope_ = scope_;
    }

    /// Apply the draft cacheable-result fields when the effective version is
    /// draft+. A no-op for earlier versions.
    private Json maybeCache(Json result) @safe
    {
        if (effectiveVersion.cacheableResults)
            return withCache(result, cacheTtlMs, cacheScope_);
        return result;
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
        default:
            break; // unknown notifications are ignored per JSON-RPC
        }
    }

    private Json route(string method, Json params, RequestContext ctx) @safe
    {
        switch (method)
        {
        case "initialize":
            return doInitialize(params);
        case "server/discover":
            return doDiscover();
        case "subscriptions/listen":
            return doSubscribeListen(params);
        case "ping":
            return Json.emptyObject;
        case "tools/list":
            return doListTools(params);
        case "tools/call":
            return doCallTool(params, ctx);
        case "resources/list":
            return doListResources(params);
        case "resources/templates/list":
            return doListResourceTemplates(params);
        case "resources/read":
            return doReadResource(params);
        case "resources/subscribe":
            return doSubscribe(params);
        case "resources/unsubscribe":
            return doUnsubscribe(params);
        case "prompts/list":
            return doListPrompts(params);
        case "prompts/get":
            return doGetPrompt(params);
        case "completion/complete":
            return doComplete(params);
        case "logging/setLevel":
            return doSetLevel(params);
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
        d.serverInfo = Implementation(serverName, serverVersion);
        d.instructions = instructions;
        return d.toJson();
    }

    /// `subscriptions/listen` (draft): record the opted-in change-notification
    /// types and acknowledge. The long-lived delivery stream is provided by the
    /// transport; this records the filter and returns the acknowledgement.
    private Json doSubscribeListen(Json params) @safe
    {
        static immutable known = [
            "toolsListChanged", "promptsListChanged", "resourcesListChanged",
            "resourceSubscriptions"
        ];
        foreach (k; known)
            if (params.type == Json.Type.object && k in params
                    && params[k].type == Json.Type.bool_ && params[k].get!bool)
                listenFilters[k] = true;
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

    private Json doListResources(Json /* params */ ) @safe
    {
        import std.algorithm : sort;

        ListResourcesResult result;
        auto uris = resources.keys;
        sort(uris);
        foreach (uri; uris)
            result.resources ~= resources[uri].descriptor;
        return maybeCache(result.toJson());
    }

    private Json doListResourceTemplates(Json /* params */ ) @safe
    {
        ListResourceTemplatesResult result;
        foreach (t; templates)
            result.resourceTemplates ~= t.descriptor;
        return maybeCache(result.toJson());
    }

    private Json doReadResource(Json params) @safe
    {
        if ("uri" !in params || params["uri"].type != Json.Type.string)
            throw invalidParams("resources/read requires a string 'uri'");
        const uri = params["uri"].get!string;

        if (auto direct = uri in resources)
        {
            ReadResourceResult result;
            result.contents = [direct.reader()];
            return maybeCache(result.toJson());
        }

        foreach (t; templates)
        {
            string[string] captured;
            if (matchUriTemplate(t.descriptor.uriTemplate, uri, captured))
            {
                ReadResourceResult result;
                result.contents = [t.reader(uri, captured)];
                return maybeCache(result.toJson());
            }
        }
        // Draft aligns the code to invalidParams (-32602); older versions -32002.
        // The spec's not-found example carries structured data {"uri": ...} so
        // clients can read the offending URI without parsing the message string.
        Json data = Json.emptyObject;
        data["uri"] = uri;
        throw new McpException(effectiveVersion.resourceNotFoundCode,
                "Resource not found: " ~ uri, data);
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

    private Json doListPrompts(Json /* params */ ) @safe
    {
        import std.algorithm : sort;

        ListPromptsResult result;
        auto names = prompts.keys;
        sort(names);
        foreach (name; names)
            result.prompts ~= prompts[name].descriptor;
        return maybeCache(result.toJson());
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
        return entry.handler(args).toJson();
    }

    private Json doComplete(Json params) @safe
    {
        if (completionHandler is null)
        {
            CompleteResult empty;
            return empty.toJson();
        }
        return completionHandler(params).toJson();
    }

    private Json doSetLevel(Json params) @safe
    {
        if ("level" in params && params["level"].type == Json.Type.string)
            logLevel = params["level"].get!string;
        return Json.emptyObject;
    }

    private Json doInitialize(Json params) @safe
    {
        auto p = InitializeParams.fromJson(params);
        negotiated = negotiate(p.protocolVersion);
        clientCaps = p.capabilities;

        InitializeResult result;
        result.protocolVersion = negotiated.toWire;
        result.capabilities = capabilities();
        result.serverInfo = Implementation(serverName, serverVersion);
        result.instructions = instructions;
        return result.toJson();
    }

    private Json doListTools(Json /* params */ ) @safe
    {
        ListToolsResult result;
        foreach (name; sortedToolNames())
            result.tools ~= tools[name].descriptor;
        return maybeCache(result.toJson());
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
    private MCPServer makeTestServer() @safe
    {
        auto s = new MCPServer("test-srv", "0.1.0");
        Tool add = {name: "add", description: nullable("Add two integers")};
        s.registerTool(add, (Json args) @safe {
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

    auto s = new MCPServer("vsrv", "0.1.0");
    struct AddResult
    {
        int result;
    }

    Tool add = {
        name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
    };
    s.registerTool(add, (Json args) @safe {
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

    auto s = new MCPServer("vsrv", "0.1.0");
    struct AddResult
    {
        int result;
    }

    Tool add = {
        name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
    };
    s.registerTool(add, (Json args) @safe {
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

    auto s = new MCPServer("vsrv", "0.1.0");
    struct AddResult
    {
        int result;
    }

    Tool add = {
        name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!AddResult
    };
    s.registerTool(add, (Json args) @safe {
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

unittest  // a tool handler that throws becomes an isError result, not a protocol error
{
    auto s = new MCPServer("t", "1");
    Tool boom = {name: "boom"};
    CallToolResult delegate(Json) @safe handler = (Json) {
        throw new Exception("kaboom");
    };
    s.registerTool(boom, handler);
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
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    Json p = Json.emptyObject;
    p["uri"] = "test://missing";
    auto resp = s.handle(req(1, "resources/read", p)).get;
    assert(resp["error"]["code"].get!int == ErrorCode.resourceNotFound);
}

unittest  // resources/read not-found carries structured data.uri (spec example shape)
{
    auto s = new MCPServer("t", "1");
    Json p = Json.emptyObject;
    p["uri"] = "test://missing";
    auto resp = s.handle(req(1, "resources/read", p)).get;
    assert(resp["error"]["data"]["uri"].get!string == "test://missing");
}

unittest  // resource templates resolve and read with captured params
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    Prompt pr = {name: "greet", description: nullable("greets")};
    pr.arguments = [PromptArgument("who", nullable("name"), true)];
    s.registerPrompt(pr, (Json args) @safe {
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

unittest  // completion/complete uses the registered handler
{
    auto s = new MCPServer("t", "1");
    s.setCompletionHandler((Json) @safe {
        CompleteResult r;
        r.values = ["paris", "park"];
        return r;
    });
    auto resp = s.handle(req(1, "completion/complete", Json.emptyObject)).get;
    assert(resp["result"]["completion"]["values"].length == 2);
}

unittest  // logging/setLevel stores the level and returns an empty object
{
    auto s = new MCPServer("t", "1");
    s.enableLogging();
    Json p = Json.emptyObject;
    p["level"] = "debug";
    auto resp = s.handle(req(1, "logging/setLevel", p)).get;
    assert(resp["result"].type == Json.Type.object && resp["result"].length == 0);
    assert(s.currentLogLevel == "debug");
}

unittest  // capabilities reflect registered features
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    Json reqs = Json.emptyObject;
    reqs["tools/call"] = Json.emptyObject;
    s.enableTasks(true, true, reqs);

    Json params = Json.emptyObject;
    params["protocolVersion"] = "2025-11-25";
    auto resp = s.handle(req(1, "initialize", params)).get;
    auto t = resp["result"]["capabilities"]["tasks"];
    assert(t.type == Json.Type.object);
    assert(t["list"].type == Json.Type.object);
    assert(t["cancel"].type == Json.Type.object);
    assert("tools/call" in t["requests"]);
}

unittest  // server reads the `tasks` capability a client advertises at initialize
{
    auto s = new MCPServer("t", "1");
    Json caps = Json.emptyObject;
    Json t = Json.emptyObject;
    Json reqs = Json.emptyObject;
    reqs["sampling/createMessage"] = Json.emptyObject;
    t["requests"] = reqs;
    caps["tasks"] = t;

    Json params = Json.emptyObject;
    params["protocolVersion"] = "2025-11-25";
    params["capabilities"] = caps;
    s.handle(req(1, "initialize", params));

    assert(!s.clientTasks.isNull);
    assert("sampling/createMessage" in s.clientTasks.get.requests);
}

unittest  // server reads the extensions a client advertises at initialize
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    Resource r = {uri: "u", name: "u"};
    s.registerResource(r, () @safe => ResourceContents.makeText("u", "text/plain", "x"));
    assert(!s.capabilities().resources.get.subscribe);
    s.enableResourceSubscriptions();
    assert(s.capabilities().resources.get.subscribe);
}

version (unittest)
{
    // A request carrying draft per-request _meta (protocolVersion 2026-07-28).
    private Message draftReq(long id, string method, Json params = Json.emptyObject) @safe
    {
        Json meta = Json.emptyObject;
        meta[MetaKey.protocolVersion] = "2026-07-28";
        meta[MetaKey.clientInfo] = Json([
            "name": Json("c"),
            "version": Json("1")
        ]);
        meta[MetaKey.clientCapabilities] = Json.emptyObject;
        params["_meta"] = meta;
        return Message(makeRequest(Json(id), method, params));
    }
}

unittest  // server/discover advertises all supported versions + identity
{
    auto s = makeTestServer();
    auto resp = s.handle(draftReq(1, "server/discover")).get;
    auto pv = resp["result"]["protocolVersions"];
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

unittest  // draft tools/list carries CacheableResult fields
{
    auto s = makeTestServer();
    s.setCacheHint(5000, CacheScope.private_);
    auto resp = s.handle(draftReq(2, "tools/list")).get;
    assert(resp["result"]["ttlMs"].get!long == 5000);
    assert(resp["result"]["cacheScope"].get!string == "private");
}

unittest  // pre-draft tools/list has no cache fields
{
    auto s = makeTestServer();
    s.setCacheHint(5000);
    auto resp = s.handle(req(2, "tools/list")).get; // no draft _meta -> latestStable
    assert("ttlMs" !in resp["result"]);
}

unittest  // draft resources/read unknown uri uses invalidParams (-32602)
{
    auto s = new MCPServer("t", "1");
    Json p = Json.emptyObject;
    p["uri"] = "test://missing";
    auto resp = s.handle(draftReq(3, "resources/read", p)).get;
    assert(resp["error"]["code"].get!int == -32602);
}

unittest  // subscriptions/listen records the opted-in filter and acknowledges
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
    assert(j["inputRequests"][0]["id"].get!string == "q1");
    assert(j["inputRequests"][0]["type"].get!string == "elicitation");
}

version (unittest)
{
    // A fake transport context: server->client requests return a canned answer.
    private final class FakeCtx : RequestContext
    {
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

        import mcp.auth.resource_server : TokenInfo;

        TokenInfo auth() @safe
        {
            return TokenInfo.invalid();
        }
    }

    // Register a tool that books a flight, asking for the date either via MRTR
    // (stateless) or a blocking elicit() (2025-era).
    private void registerBookTool(MCPServer s) @safe
    {
        Tool book = {name: "book"};
        s.registerTool(book, (Json args, RequestContext ctx) @safe {
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

    // A draft tools/call whose _meta also carries the given input responses.
    private Message draftCall(long id, string tool, InputResponse[] responses) @safe
    {
        Json meta = Json.emptyObject;
        meta[MetaKey.protocolVersion] = "2026-07-28";
        meta[MetaKey.clientInfo] = Json([
            "name": Json("c"),
            "version": Json("1")
        ]);
        meta[MetaKey.clientCapabilities] = Json.emptyObject;
        if (responses.length)
        {
            Json arr = Json.emptyArray;
            foreach (resp; responses)
                arr ~= resp.toJson();
            meta[MetaKey.inputResponses] = arr;
        }
        Json params = Json.emptyObject;
        params["name"] = tool;
        params["arguments"] = Json.emptyObject;
        params["_meta"] = meta;
        return Message(makeRequest(Json(id), "tools/call", params));
    }
}

unittest  // draft (stateless) first round: handler returns an InputRequiredResult
{
    auto s = new MCPServer("t", "1");
    registerBookTool(s);
    auto resp = s.handle(draftCall(1, "book", [])).get;
    assert("error" !in resp);
    assert(resp["result"]["inputRequests"][0]["type"].get!string == "elicitation");
    assert(resp["result"]["inputRequests"][0]["id"].get!string == "date");
}

unittest  // draft (stateless) retry with input responses: handler completes
{
    auto s = new MCPServer("t", "1");
    registerBookTool(s);
    auto answer = InputResponse("date", Json([
            "content": Json(["day": Json("monday")])
    ]));
    auto resp = s.handle(draftCall(2, "book", [answer])).get;
    assert("inputRequests" !in resp["result"]);
    assert(resp["result"]["content"][0]["text"].get!string == "booked monday");
}

unittest  // elicit() is rejected on a stateless (draft) request
{
    auto s = new MCPServer("t", "1");
    Tool bad = {name: "bad"};
    s.registerTool(bad, (Json args, RequestContext ctx) @safe {
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
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    assert(s.serverPushChannel() is null);
    assert(s.notify("notifications/message") == 0);
}

unittest  // notify delivers unsolicited notifications to GET-stream listeners
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    s.enableResourceSubscriptions();
    auto coord = new StreamCoordinator;
    auto ch = s.serverPushChannel(coord);
    string[] received;
    ch.addListener((string f) @safe { received ~= f; });

    const n = s.notifyResourceUpdated("test://never");
    assert(n == 0);
    assert(received.length == 0);
}

unittest  // notifyResourceUpdated includes the optional title param when given
{
    auto s = new MCPServer("t", "1");
    s.enableResourceSubscriptions();
    auto coord = new StreamCoordinator;
    auto ch = s.serverPushChannel(coord);
    string[] received;
    ch.addListener((string f) @safe { received ~= f; });

    Json p = Json.emptyObject;
    p["uri"] = "test://w";
    s.handle(req(1, "resources/subscribe", p));

    const n = s.notifyResourceUpdated("test://w", nullable("My Resource"));
    assert(n == 1);
    import std.algorithm : canFind;

    assert(received[0].canFind("\"title\""));
    assert(received[0].canFind("My Resource"));
}

unittest  // notifyResourceUpdated is a no-op before a push channel exists
{
    auto s = new MCPServer("t", "1");
    s.enableResourceSubscriptions();
    Json p = Json.emptyObject;
    p["uri"] = "test://w";
    s.handle(req(1, "resources/subscribe", p));
    assert(s.notifyResourceUpdated("test://w") == 0);
}

unittest  // tools listChanged is not advertised by default
{
    auto s = new MCPServer("t", "1");
    Tool add = {name: "add"};
    s.registerTool(add, (Json) @safe { return CallToolResult(); });
    auto caps = s.capabilities();
    assert(!caps.tools.isNull);
    assert(!caps.tools.get.listChanged);
}

unittest  // enableToolListChanged advertises listChanged:true for tools
{
    auto s = new MCPServer("t", "1");
    Tool add = {name: "add"};
    s.registerTool(add, (Json) @safe { return CallToolResult(); });
    s.enableToolListChanged();
    auto caps = s.capabilities();
    assert(!caps.tools.isNull);
    assert(caps.tools.get.listChanged);
    assert(caps.toJson()["tools"]["listChanged"].get!bool);
}

unittest  // removeTool unregisters a previously registered tool
{
    auto s = new MCPServer("t", "1");
    Tool add = {name: "add"};
    s.registerTool(add, (Json) @safe { return CallToolResult(); });
    assert(s.removeTool("add"));
    auto resp = s.handle(req(1, "tools/list")).get;
    assert(resp["result"]["tools"].length == 0);
    assert(!s.removeTool("add")); // already gone
}

unittest  // notifyToolsListChanged broadcasts notifications/tools/list_changed
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    assert(s.notifyToolsListChanged() == 0);
}

unittest  // resources listChanged is not advertised by default
{
    auto s = new MCPServer("t", "1");
    Resource r = {uri: "test://r", name: "r"};
    s.registerResource(r, () @safe => ResourceContents.makeText("test://r", "text/plain", "x"));
    auto caps = s.capabilities();
    assert(!caps.resources.isNull);
    assert(!caps.resources.get.listChanged);
}

unittest  // enableResourcesListChanged advertises listChanged:true for resources
{
    auto s = new MCPServer("t", "1");
    Resource r = {uri: "test://r", name: "r"};
    s.registerResource(r, () @safe => ResourceContents.makeText("test://r", "text/plain", "x"));
    s.enableResourcesListChanged();
    auto caps = s.capabilities();
    assert(!caps.resources.isNull);
    assert(caps.resources.get.listChanged);
    assert(caps.toJson()["resources"]["listChanged"].get!bool);
}

unittest  // notifyResourcesListChanged broadcasts notifications/resources/list_changed
{
    auto s = new MCPServer("t", "1");
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
    auto s = new MCPServer("t", "1");
    assert(s.notifyResourcesListChanged() == 0);
}
