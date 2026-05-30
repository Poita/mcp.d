module mcp.client.client;

import std.algorithm : canFind, startsWith;
import std.typecons : Nullable, nullable;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8, readLine;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.protocol.sampling : validateSamplingMessages;
import mcp.protocol.draft;

/// Internal signal that the modern single-endpoint POST returned an HTTP
/// 400/404/405, the trigger for the legacy HTTP+SSE (2024-11-05) fallback.
private final class LegacyFallbackException : Exception
{
    int status;
    this(int status) @safe
    {
        import std.conv : to;

        super("legacy HTTP+SSE fallback (HTTP " ~ status.to!string ~ ")");
        this.status = status;
    }
}

/// A progress token attached to an outgoing request so the server may emit
/// `notifications/progress` for it. Per basic/utilities/progress, "Progress
/// tokens MUST be a string or integer value" and "MUST be unique across all
/// active requests". Construct one from either a `string` or a `long`; an
/// unset token is omitted from the request.
struct ProgressToken
{
    private Json value_ = Json.undefined;

    /// A string-valued progress token.
    this(string token) @safe nothrow
    {
        value_ = Json(token);
    }

    /// An integer-valued progress token.
    this(long token) @safe nothrow
    {
        value_ = Json(token);
    }

    /// Whether a token has been set (false for a default-constructed token).
    bool isSet() const @safe nothrow
    {
        return value_.type != Json.Type.undefined;
    }

    /// The token as JSON (a string or integer), or `Json.undefined` when unset.
    Json toJson() const @safe nothrow
    {
        return value_;
    }
}

/// Merge `progressToken` into a request's `params._meta.progressToken`, per
/// basic/utilities/progress ("a party ... includes a progressToken in the
/// request metadata", at `params._meta.progressToken`). Returns `params`
/// unchanged when the token is unset. Any existing `_meta` keys are preserved.
/// Exposed so callers can attach a progress token to a hand-built params object
/// (e.g. for request methods without a dedicated progress-token overload).
Json withProgressToken(Json params, ProgressToken token) @safe
{
    if (!token.isSet)
        return params;
    if (params.type != Json.Type.object)
        params = Json.emptyObject;
    Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
        : Json.emptyObject;
    meta["progressToken"] = token.toJson();
    params["_meta"] = meta;
    return params;
}

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

    private this(shared(bool)* cancelled) @safe nothrow @nogc
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

/// A Model Context Protocol client over the Streamable HTTP transport.
///
/// Drives the lifecycle (`initialize` + `notifications/initialized`) and the
/// server features (tools, resources, prompts, completion, logging,
/// subscriptions) with auto-pagination. Server->client requests received on a
/// POST's SSE stream (sampling / elicitation / roots) are dispatched to the
/// user-supplied handlers and answered on a fresh POST.
final class MCPClient
{
    private string url;
    private string sessionId;
    private ProtocolVersion negotiated = latestStable;
    private bool didInitialize;
    private bool useDraft;
    private string bearerToken;
    private long nextId = 1;
    // SSE resumability: the most recent `id:`/`retry:` seen on a response stream,
    // and the Last-Event-ID to send when retrying after a premature stream close.
    private string sseLastEventId;
    private long sseRetryMs;
    private string pendingLastEventId;
    // Legacy HTTP+SSE (2024-11-05) transport state. When `legacyMode` is set,
    // JSON-RPC messages are POSTed to `legacyEndpoint` (discovered from the GET
    // stream's `endpoint` event) and responses arrive on the standalone GET SSE
    // stream rather than on the POST response.
    private bool legacyMode;
    private string legacyEndpoint;
    // The most recent HTTP status seen on a POST, so the lifecycle code can
    // detect the 400/404/405 backward-compatibility trigger.
    private int lastPostStatus;
    // When awaiting a legacy response on the GET stream, the id we expect and
    // the slot the GET-stream reader fills in.
    private long legacyExpectId;
    private Json legacyResult;
    private bool legacyGot;
    private McpException legacyErr;
    // Opt-in: validate tool results against the tool's outputSchema (client side).
    private bool validateOutputSchema_;
    // URL-mode elicitation correlation: ids the server asked us to complete via
    // an `elicitation/create` with `mode:"url"`, mapped to whether we have already
    // observed their `notifications/elicitation/complete`. Used to honour the spec
    // rule "Clients MUST ignore notifications referencing unknown or
    // already-completed IDs."
    private bool[string] elicitationIds_;
    // Request ids this client has cancelled via notifications/cancelled. Per
    // basic/utilities/cancellation, "The sender of the cancellation notification
    // SHOULD ignore any response to the request that arrives afterward", so a
    // late response correlated to one of these ids is dropped rather than
    // returned. Keyed by the JSON-RPC id under which the request was POSTed.
    private bool[long] cancelledRequests_;
    // The JSON-RPC id used for the `initialize` request, so cancel() can enforce
    // the spec rule that clients MUST NOT cancel initialize. 0 until sent.
    private long initializeRequestId;
    // Tool inputSchemas seen via tools/list, keyed by tool name. Used by the
    // draft client to mirror x-mcp-header-annotated tool-call arguments into
    // Mcp-Param-{Name} headers (draft basic/transports, "Custom Headers from
    // Tool Parameters"). Populated by listTools; consumed by addDraftHeaders.
    private Json[string] toolInputSchemas_;

    /// Capabilities this client advertises at initialize.
    ClientCapabilities capabilities;
    /// This client's identity.
    Implementation clientInfo;

    /// Handler for `sampling/createMessage`; returns the result. Null => unsupported.
    Json delegate(Json params) @safe onSampling;
    /// Handler for `elicitation/create`; returns `{action, content?}`. Null => unsupported.
    ///
    /// `params` carries the full request. Form-mode requests (the default, when
    /// `mode` is absent or `"form"`) include `message` and `requestedSchema`;
    /// the handler collects input and returns `{action, content}`. URL-mode
    /// requests (2025-11-25+) set `mode: "url"` and include `url` and
    /// `elicitationId` instead of a schema — the handler should present the URL
    /// for the user to complete out-of-band and return `{action}` (no content).
    Json delegate(Json params) @safe onElicitation;
    /// Handler for `roots/list`; returns `{roots: [...]}`. Null => unsupported.
    Json delegate(Json params) @safe onListRoots;
    /// Observer for inbound notifications (progress, message, resource updates).
    void delegate(string method, Json params) @safe onNotification;
    /// Typed observer for `notifications/progress` (basic/utilities/progress).
    ///
    /// When set, an inbound `notifications/progress` is parsed into a
    /// `ProgressNotification` and delivered here in addition to the generic
    /// `onNotification`. Correlate `n.progressToken` against the
    /// `ProgressToken` you attached to the originating request (see the
    /// `callTool`/`readResource`/`getPrompt` overloads taking a `ProgressToken`)
    /// to track an individual request's progress.
    void delegate(ProgressNotification n) @safe onProgress;

    this(string url, Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
    {
        this.url = url;
        this.clientInfo = clientInfo;
    }

    /// The protocol version negotiated with the server (valid after initialize).
    ProtocolVersion protocolVersion() const @safe
    {
        return negotiated;
    }

    /// Switch to the stateless draft (2026-07-28) protocol: no `initialize`
    /// handshake; every request carries `_meta` (protocolVersion / clientInfo /
    /// clientCapabilities) and the standard `Mcp-Method` / `Mcp-Name` /
    /// `MCP-Protocol-Version` headers. Call `discover()` for up-front version
    /// selection, or just issue requests.
    void enableDraft() @safe
    {
        useDraft = true;
        negotiated = ProtocolVersion.draft;
    }

    /// `server/discover` (draft): fetch the server's supported versions,
    /// capabilities, and identity.
    DiscoverResult discover() @safe
    {
        return DiscoverResult.fromJson(rpc("server/discover", Json.emptyObject));
    }

    /// Attach an OAuth bearer access token, sent as `Authorization: Bearer
    /// <token>` on every subsequent request. Pass an empty string to clear it.
    void setBearerToken(string token) @safe
    {
        bearerToken = token;
    }

    /// Perform the initialize handshake and send `notifications/initialized`.
    InitializeResult initialize(string requestedVersion = latestStable.toWire) @safe
    {
        InitializeParams params;
        params.protocolVersion = requestedVersion;
        params.capabilities = capabilities;
        params.clientInfo = clientInfo;

        // Record the id the initialize request will use so cancel() can refuse
        // to cancel it (clients MUST NOT cancel initialize).
        initializeRequestId = nextId;
        auto result = rpc("initialize", params.toJson());
        auto init = InitializeResult.fromJson(result);
        // Per the Lifecycle / Version Negotiation rules: if the client does not
        // support the version in the server's response it SHOULD disconnect.
        // Validate before completing the handshake so we never silently proceed
        // under a version the server did not agree to.
        negotiated = resolveNegotiatedVersion(init.protocolVersion);
        didInitialize = true;
        notify("notifications/initialized", Json.emptyObject);
        return init;
    }

    /// Connect to a server whose protocol era is unknown, per the transport
    /// backward-compatibility rules. Probes `server/discover` first:
    ///   - success → modern server; switch to the newest mutually-supported
    ///     version (stateless draft mode if that version uses per-request
    ///     `_meta`, otherwise an `initialize` handshake for that stable version);
    ///   - `Method not found` (-32601) → legacy server; fall back to the
    ///     `initialize` handshake;
    ///   - `UnsupportedProtocolVersionError` (-32004) → modern server; pick from
    ///     the advertised `supported` list rather than falling back.
    /// Returns the negotiated protocol version. Throws if there is no mutually
    /// supported version, or on any other error.
    ProtocolVersion connect() @safe
    {
        string[] serverVersions;
        try
        {
            serverVersions = discover().protocolVersions;
        }
        catch (LegacyFallbackException)
        {
            // Modern POST rejected with 400/404/405: this is (or may be) an old
            // HTTP+SSE server. Open the GET SSE stream, read its `endpoint`
            // event, and drive the two-endpoint legacy transport.
            startLegacyHttpSse();
            initialize(ProtocolVersion.v2024_11_05.toWire);
            return negotiated;
        }
        catch (McpException e)
        {
            if (e.code == ErrorCode.methodNotFound)
            {
                initialize(); // legacy initialize-based server
                return negotiated;
            }
            if (e.code == ErrorCode.unsupportedProtocolVersion)
                serverVersions = supportedListFromError(e);
            else
                throw e;
        }

        ProtocolVersion chosen;
        if (!selectMutualVersion(serverVersions, chosen))
            throw new McpException(ErrorCode.unsupportedProtocolVersion,
                    "No mutually supported protocol version");

        if (chosen.isDraft)
        {
            useDraft = true;
            negotiated = chosen;
        }
        else
            initialize(chosen.toWire); // modern discovery, pre-draft version
        return negotiated;
    }

    /// Extract the `supported` wire-version list from an
    /// `UnsupportedProtocolVersionError`. `errorFrom` stores the whole JSON-RPC
    /// error object in `data`, so the list lives at `data.data.supported`.
    private static string[] supportedListFromError(McpException e) @safe
    {
        auto d = e.data;
        if (d.type == Json.Type.object && "data" in d && d["data"].type == Json.Type.object)
            d = d["data"];
        string[] versions;
        if (d.type == Json.Type.object && "supported" in d && d["supported"].type == Json
                .Type.array)
        {
            auto arr = d["supported"];
            foreach (i; 0 .. arr.length)
                if (arr[i].type == Json.Type.string)
                    versions ~= arr[i].get!string;
        }
        return versions;
    }

    /// `ping` — returns when the server acknowledges.
    void ping() @safe
    {
        rpc("ping", Json.emptyObject);
    }

    /// `tools/list`, following pagination cursors to completion.
    Tool[] listTools() @safe
    {
        Tool[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListToolsResult.fromJson(rpc("tools/list", p));
            all ~= res.tools;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        // Cache each tool's inputSchema so a subsequent tools/call can mirror any
        // x-mcp-header-annotated arguments into Mcp-Param-{Name} headers (draft
        // basic/transports, "Custom Headers from Tool Parameters").
        foreach (t; all)
            cacheToolSchema(t.name, t.inputSchema);
        return all;
    }

    /// Record a tool's `inputSchema` (keyed by tool name) so the draft client can
    /// mirror its x-mcp-header-annotated arguments into `Mcp-Param-*` headers on a
    /// later `tools/call`. Normally populated automatically by `listTools`; exposed
    /// so callers that obtain a `Tool` descriptor by other means (e.g. a cached
    /// `tools/list` result, or a `notifications/tools/list_changed` refresh) can
    /// register it too. A non-object schema is ignored.
    void cacheToolSchema(string name, Json inputSchema) @safe
    {
        if (name.length && inputSchema.type == Json.Type.object)
            toolInputSchemas_[name] = inputSchema;
    }

    /// `tools/call`.
    ///
    /// Against a draft (MRTR / SEP-2322) server this transparently completes a
    /// Multi Round-Trip Request: if the server answers with an
    /// `InputRequiredResult` (the result carries `inputRequests`), each request is
    /// dispatched to the matching `onSampling` / `onElicitation` / `onListRoots`
    /// handler and the original `tools/call` is resubmitted with the answers
    /// attached under `_meta["io.modelcontextprotocol/inputResponses"]`, looping
    /// until the server returns a completed `CallToolResult`. The loop only
    /// engages when draft mode is enabled (see `enableDraft`/`connect`); other
    /// protocol versions never see `inputRequests`.
    CallToolResult callTool(string name, Json arguments = Json.emptyObject) @safe
    {
        return callToolLoop(name, arguments, ProgressToken.init);
    }

    /// `tools/call`, requesting progress updates for the call. The server may
    /// then emit `notifications/progress` carrying `progressToken`, observable
    /// via `onNotification`. Per basic/utilities/progress, the token is sent in
    /// `params._meta.progressToken`. Drives the same MRTR loop as the no-token
    /// overload (see `callTool`).
    CallToolResult callTool(string name, Json arguments, ProgressToken progressToken) @safe
    {
        return callToolLoop(name, arguments, progressToken);
    }

    /// Issue `tools/call` and, against a draft server, complete any MRTR
    /// (SEP-2322) round-trips by satisfying each `InputRequest` and resubmitting
    /// the request with the answers. Returns the first completed `CallToolResult`.
    ///
    /// A bound is placed on the number of rounds so a misbehaving server that
    /// keeps asking for input cannot loop forever. If a handler for a requested
    /// input type is missing, or the loop bound is exceeded, the (still
    /// `inputRequired`) result is returned so the caller can inspect it via
    /// `CallToolResult.isInputRequired`.
    private CallToolResult callToolLoop(string name, Json arguments, ProgressToken progressToken) @safe
    {
        enum maxRounds = 16;
        InputResponse[] responses;
        foreach (round; 0 .. maxRounds)
        {
            auto params = buildToolCallParams(name, arguments, progressToken, responses);
            auto result = CallToolResult.fromJson(rpc("tools/call", params));
            if (!result.isInputRequired)
                return result;
            // Gather an answer for each requested input. If any cannot be
            // satisfied (no handler registered), stop and hand the
            // inputRequired result back to the caller.
            InputResponse[] answers;
            foreach (req; result.inputRequests)
            {
                InputResponse answer;
                if (!resolveInputRequest(req, answer))
                    return result;
                answers ~= answer;
            }
            responses = answers;
        }
        // Bound exceeded: return whatever the last round produced (still an
        // inputRequired result) rather than looping forever.
        return CallToolResult.fromJson(rpc("tools/call",
                buildToolCallParams(name, arguments, progressToken, responses)));
    }

    /// Satisfy one MRTR `InputRequest` by dispatching it to the matching client
    /// handler, writing the answer into `answer` (keyed by `req.id`). Returns
    /// `false` (leaving `answer` untouched) when no handler is registered for the
    /// request's type, so the caller can surface the unanswered
    /// `InputRequiredResult`. `req.type` maps to the server-initiated request the
    /// MRTR round replaces: `"sampling"`→`onSampling`, `"elicitation"`→
    /// `onElicitation`, `"roots"`→`onListRoots`.
    private bool resolveInputRequest(InputRequest req, out InputResponse answer) @safe
    {
        Json result;
        switch (req.type)
        {
        case "sampling":
            if (onSampling is null)
                return false;
            validateSamplingMessages(req.params);
            result = onSampling(req.params);
            break;
        case "elicitation":
            if (onElicitation is null)
                return false;
            result = onElicitation(req.params);
            break;
        case "roots":
            if (onListRoots is null)
                return false;
            result = onListRoots(req.params);
            break;
        default:
            return false;
        }
        answer = InputResponse(req.id, result);
        return true;
    }

    /// Build the `tools/call` params, optionally attaching a progress token.
    /// Separated so the param shaping (including `_meta.progressToken`) can be
    /// unit-tested without a live server.
    package static Json buildToolCallParams(string name, Json arguments,
            ProgressToken progressToken) @safe
    {
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return withProgressToken(p, progressToken);
    }

    /// Build the `tools/call` params with any gathered MRTR (SEP-2322) input
    /// responses attached under `_meta["io.modelcontextprotocol/inputResponses"]`
    /// (`MetaKey.inputResponses`), the reserved key a draft server reads via
    /// `readInputResponses`. With no responses this is identical to the plain
    /// `buildToolCallParams`. Separated as a package static so the resubmission
    /// param shaping can be unit-tested without a live server.
    package static Json buildToolCallParams(string name, Json arguments,
            ProgressToken progressToken, InputResponse[] responses) @safe
    {
        Json p = buildToolCallParams(name, arguments, progressToken);
        return withInputResponses(p, responses);
    }

    /// Attach MRTR (SEP-2322) input responses to a request's
    /// `params._meta["io.modelcontextprotocol/inputResponses"]`
    /// (`MetaKey.inputResponses`), preserving any existing `_meta` entries. An
    /// empty `responses` list returns `params` unchanged. Exposed so callers can
    /// attach answers to a hand-built params object.
    static Json withInputResponses(Json params, InputResponse[] responses) @safe
    {
        if (responses.length == 0)
            return params;
        if (params.type != Json.Type.object)
            params = Json.emptyObject;
        Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
            : Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (resp; responses)
            arr ~= resp.toJson();
        meta[MetaKey.inputResponses] = arr;
        params["_meta"] = meta;
        return params;
    }

    /// `tools/call` for a tool whose descriptor (and therefore `outputSchema`) is
    /// known — typically one returned by `listTools`. When the client has output-
    /// schema validation enabled (see `enableOutputSchemaValidation`) and `tool`
    /// carries an `outputSchema`, the returned `structuredContent` is validated
    /// against it: per the spec, "Clients SHOULD validate structured results
    /// against this schema." A non-conforming result raises a clear
    /// `McpException` rather than being accepted silently.
    CallToolResult callTool(const Tool tool, Json arguments = Json.emptyObject) @safe
    {
        auto result = callTool(tool.name, arguments);
        if (validateOutputSchema_)
        {
            const msg = validateOutput(tool, result);
            if (msg.length)
                throw new McpException(ErrorCode.invalidParams,
                        "Tool '" ~ tool.name
                        ~ "' returned structuredContent that does not conform to its outputSchema: "
                        ~ msg);
        }
        return result;
    }

    /// Opt in to validating tool results against the tool's `outputSchema` when
    /// calling `callTool(Tool, ...)`. Off by default; existing call sites are
    /// unaffected.
    void enableOutputSchemaValidation() @safe
    {
        validateOutputSchema_ = true;
    }

    /// Validate a `CallToolResult`'s `structuredContent` against `tool`'s
    /// `outputSchema`, independent of the opt-in flag. Returns an empty string
    /// when it conforms (including when the tool has no output schema or the
    /// result has no structured content), otherwise a description of the first
    /// violation. Exposed so callers can validate explicitly without enabling
    /// automatic validation.
    static string validateOutput(const Tool tool, const CallToolResult result) @safe
    {
        import mcp.api.schema : validateAgainstSchema;

        if (tool.outputSchema.type != Json.Type.object)
            return "";
        if (result.structuredContent.type == Json.Type.undefined)
            return "";
        return validateAgainstSchema(result.structuredContent, tool.outputSchema);
    }

    /// `resources/list`, auto-paginated.
    Resource[] listResources() @safe
    {
        Resource[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListResourcesResult.fromJson(rpc("resources/list", p));
            all ~= res.resources;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        return all;
    }

    /// `resources/read`.
    ReadResourceResult readResource(string uri) @safe
    {
        return ReadResourceResult.fromJson(rpc("resources/read",
                buildReadResourceParams(uri, ProgressToken.init)));
    }

    /// `resources/read`, requesting progress updates for the read (see
    /// `callTool` with a `ProgressToken`).
    ReadResourceResult readResource(string uri, ProgressToken progressToken) @safe
    {
        return ReadResourceResult.fromJson(rpc("resources/read",
                buildReadResourceParams(uri, progressToken)));
    }

    /// Build the `resources/read` params, optionally attaching a progress token.
    package static Json buildReadResourceParams(string uri, ProgressToken progressToken) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        return withProgressToken(p, progressToken);
    }

    /// `prompts/list`, auto-paginated.
    Prompt[] listPrompts() @safe
    {
        Prompt[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListPromptsResult.fromJson(rpc("prompts/list", p));
            all ~= res.prompts;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        return all;
    }

    /// `prompts/get`.
    GetPromptResult getPrompt(string name, Json arguments = Json.emptyObject) @safe
    {
        return GetPromptResult.fromJson(rpc("prompts/get",
                buildGetPromptParams(name, arguments, ProgressToken.init)));
    }

    /// `prompts/get`, requesting progress updates for the request (see
    /// `callTool` with a `ProgressToken`).
    GetPromptResult getPrompt(string name, Json arguments, ProgressToken progressToken) @safe
    {
        return GetPromptResult.fromJson(rpc("prompts/get",
                buildGetPromptParams(name, arguments, progressToken)));
    }

    /// Build the `prompts/get` params, optionally attaching a progress token.
    package static Json buildGetPromptParams(string name, Json arguments,
            ProgressToken progressToken) @safe
    {
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return withProgressToken(p, progressToken);
    }

    /// `completion/complete` — request autocompletion suggestions for an
    /// argument of a prompt or resource template, per server/utilities/completion
    /// §"Requesting Completions". `reference` identifies what is being completed
    /// (use `CompletionReference.forPrompt` / `forResource`); `argumentName` and
    /// `argumentValue` are the argument being filled in and its partial value.
    /// `context`, when non-null, supplies previously-resolved argument values
    /// (`{name: value}`) so the server can give context-aware completions.
    CompleteResult complete(CompletionReference reference, string argumentName,
            string argumentValue, string[string] context = null) @safe
    {
        return CompleteResult.fromJson(rpc("completion/complete",
                buildCompleteParams(reference, argumentName, argumentValue, context)));
    }

    /// Build the `completion/complete` request params. Separated from `complete`
    /// so the param shaping can be unit-tested without a live server.
    package static Json buildCompleteParams(CompletionReference reference,
            string argumentName, string argumentValue, string[string] context) @safe
    {
        Json p = Json.emptyObject;
        p["ref"] = reference.toJson();
        Json arg = Json.emptyObject;
        arg["name"] = argumentName;
        arg["value"] = argumentValue;
        p["argument"] = arg;
        if (context.length)
        {
            Json args = Json.emptyObject;
            foreach (k, v; context)
                args[k] = v;
            Json ctx = Json.emptyObject;
            ctx["arguments"] = args;
            p["context"] = ctx;
        }
        return p;
    }

    /// `resources/subscribe` / `resources/unsubscribe`.
    void subscribe(string uri) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        rpc("resources/subscribe", p);
    }

    void unsubscribe(string uri) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        rpc("resources/unsubscribe", p);
    }

    /// Open a draft `subscriptions/listen` notification stream (draft
    /// basic/utilities/subscriptions). This replaces the removed
    /// `resources/subscribe` RPC and the standalone HTTP GET notification
    /// endpoint: it POSTs `subscriptions/listen` with a `{notifications:{...}}`
    /// filter (built from `filter`), the server upgrades the response to a
    /// long-lived `text/event-stream`, and this client reads it on a background
    /// task — delivering the leading `notifications/subscriptions/acknowledged`
    /// and every subsequent opted-in change notification to `onNotification`
    /// (and `onProgress` for progress). Returns a `SubscriptionStream` handle;
    /// call its `cancel()`/`close()` to stop listening and close the stream.
    ///
    /// Only meaningful for draft servers (call `enableDraft`/`connect` first);
    /// pre-draft servers do not implement `subscriptions/listen`.
    SubscriptionStream subscriptionsListen(SubscriptionFilter filter) @safe
    {
        import vibe.core.core : runTask;

        const id = nextId++;
        Json params = buildSubscriptionsListenParams(filter);
        if (useDraft)
            params = injectDraftMeta(params);
        auto message = makeRequest(Json(id), "subscriptions/listen", params);

        auto cancelled = () @trusted { return new shared bool(false); }();
        auto stream = new SubscriptionStream(cancelled);
        runTask(() nothrow{
            try
                runListenStream(message, cancelled);
            catch (Exception)
            {
            }
        });
        return stream;
    }

    /// Build the `subscriptions/listen` params, nesting the filter under
    /// `params.notifications` exactly as the draft spec's `SubscriptionFilter`
    /// requires (boolean list-changed flags emitted only when set;
    /// `resourceSubscriptions` as a string array of URIs). Separated so the param
    /// shaping can be unit-tested without a live server.
    package static Json buildSubscriptionsListenParams(SubscriptionFilter filter) @safe
    {
        Json notifications = Json.emptyObject;
        if (filter.toolsListChanged)
            notifications["toolsListChanged"] = true;
        if (filter.promptsListChanged)
            notifications["promptsListChanged"] = true;
        if (filter.resourcesListChanged)
            notifications["resourcesListChanged"] = true;
        if (filter.resourceSubscriptions.length)
        {
            Json uris = Json.emptyArray;
            foreach (uri; filter.resourceSubscriptions)
                uris ~= Json(uri);
            notifications["resourceSubscriptions"] = uris;
        }
        Json p = Json.emptyObject;
        p["notifications"] = notifications;
        return p;
    }

    /// `logging/setLevel`.
    void setLogLevel(string level) @safe
    {
        Json p = Json.emptyObject;
        p["level"] = level;
        rpc("logging/setLevel", p);
    }

    // --- transport internals -------------------------------------------------

    /// Send a request and return its result (or throw `McpException`).
    private Json rpc(string method, Json params) @safe
    {
        const id = nextId++;
        if (useDraft)
            params = injectDraftMeta(params);
        auto message = makeRequest(Json(id), method, params);
        if (legacyMode)
            return legacyRpc(message, id);
        return postAndAwait(message, id);
    }

    /// Add the draft per-request `_meta` (protocol version, client identity,
    /// capabilities) to a request's params.
    private Json injectDraftMeta(Json params) @safe
    {
        if (params.type != Json.Type.object)
            params = Json.emptyObject;
        Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
            : Json.emptyObject;
        meta[MetaKey.protocolVersion] = negotiated.toWire;
        meta[MetaKey.clientInfo] = clientInfo.toJson();
        meta[MetaKey.clientCapabilities] = capabilities.toJson();
        params["_meta"] = meta;
        return params;
    }

    /// Test seam: when set, `notify` routes the built notification message here
    /// instead of POSTing it, so the public notification API can be exercised
    /// without a live server. Production code never sets this.
    package void delegate(Json message) @safe onNotifyForTest;

    /// Send a notification (no reply expected).
    private void notify(string method, Json params) @safe
    {
        auto message = makeNotification(method, params);
        if (onNotifyForTest !is null)
        {
            onNotifyForTest(message);
            return;
        }
        post(message);
    }

    /// Send an arbitrary client-originated JSON-RPC notification to the server
    /// (no reply expected). This is the public entry point for client→server
    /// notifications such as `notifications/roots/list_changed`; the lifecycle's
    /// `notifications/initialized` is sent automatically by `initialize`.
    void sendNotification(string method, Json params = Json.emptyObject) @safe
    {
        notify(method, params);
    }

    /// The JSON-RPC id assigned to the most recently issued request. Useful to
    /// learn the id of an in-flight request so it can be `cancel`led from another
    /// task (the blocking `rpc` does not otherwise surface it). Returns `0`
    /// before any request has been sent.
    long lastRequestId() const @safe nothrow @nogc
    {
        return nextId - 1;
    }

    /// Cancel an in-flight request by sending `notifications/cancelled` for
    /// `requestId` (basic/utilities/cancellation: "Either side can send a
    /// cancellation notification ... to indicate that a previously-issued request
    /// should be terminated"). After this call, any response the server still
    /// sends for `requestId` is ignored, per "The sender of the cancellation
    /// notification SHOULD ignore any response to the request that arrives
    /// afterward". `reason` is an optional free-form explanation included in the
    /// notification when non-empty.
    ///
    /// Per spec, the `initialize` request MUST NOT be cancelled by clients;
    /// attempting to cancel the id of the `initialize` request throws.
    void cancel(long requestId, string reason = null) @safe
    {
        if (requestId == initializeRequestId && initializeRequestId != 0)
            throw invalidRequest("The initialize request MUST NOT be cancelled by clients");
        cancelledRequests_[requestId] = true;
        Json params = Json.emptyObject;
        params["requestId"] = requestId;
        if (reason.length)
            params["reason"] = reason;
        notify("notifications/cancelled", params);
    }

    /// Register the client's filesystem roots using the typed `Root` API,
    /// mirroring the typed result types the SDK provides for tools, resources
    /// and prompts. This installs an `onListRoots` handler that answers
    /// `roots/list` with a properly-shaped `{roots: [{uri, name}]}` envelope, so
    /// callers no longer have to hand-construct the raw JSON. Each `uri` MUST be
    /// a `file://` URI per client/roots §Data Types.
    void setRoots(Root[] roots) @safe
    {
        auto rs = roots.dup;
        onListRoots = (Json params) @safe {
            ListRootsResult result;
            result.roots = rs;
            return result.toJson();
        };
    }

    /// Emit `notifications/roots/list_changed`, informing the server that this
    /// client's set of roots has changed. Per client/roots §Root List Changes,
    /// a client that advertises the roots `listChanged` capability MUST send
    /// this notification whenever its roots change. Call this after updating the
    /// roots returned by `onListRoots` (or after `setRoots`).
    void notifyRootsListChanged() @safe
    {
        notify("notifications/roots/list_changed", Json.emptyObject);
    }

    /// POST a message that expects no correlated reply (notification/response).
    /// In legacy HTTP+SSE mode, messages go to the server-supplied endpoint URI.
    private void post(Json message) @safe
    {
        const target = legacyMode ? legacyEndpoint : url;
        () @trusted {
            requestHTTP(target, (scope HTTPClientRequest req) {
                setupRequest(req, message);
            }, (scope HTTPClientResponse res) {
                captureSession(res);
                res.dropBody();
            });
        }();
    }

    /// POST a request and await the response with id `expectId`, processing any
    /// SSE notifications and server->client requests in between. If the response
    /// SSE stream closes before the final response and carried an SSE `retry:`
    /// hint, wait that long and reconnect (resuming with `Last-Event-ID`), per
    /// the Streamable HTTP resumability rules.
    private Json postAndAwait(Json message, long expectId) @safe
    {
        import core.time : msecs;
        import vibe.core.core : sleep;

        Json result = Json.undefined;
        bool got;
        McpException err;
        sseRetryMs = 0;
        sseLastEventId = null;

        () @trusted {
            requestHTTP(url, (scope HTTPClientRequest req) {
                setupRequest(req, message);
            }, (scope HTTPClientResponse res) {
                captureSession(res);
                lastPostStatus = res.statusCode;
                if (isLegacyFallbackStatus(res.statusCode))
                {
                    res.dropBody();
                    return; // signalled below via lastPostStatus
                }
                const ct = res.headers.get("Content-Type", "");
                if (ct.canFind("text/event-stream"))
                {
                    readSse(res, expectId, result, got, err);
                }
                else
                {
                    auto body = res.bodyReader.readAllUTF8();
                    auto msg = parseMessage(body);
                    if (msg.kind == MessageKind.errorResponse)
                        err = errorFrom(msg.error);
                    else
                    {
                        result = msg.result;
                        got = true;
                    }
                }
            });
        }();

        // An HTTP 400/404/405 on the modern single endpoint is the signal to try
        // the legacy HTTP+SSE (2024-11-05) transport. Surface it as a typed
        // exception so the lifecycle code (`connect`) can drive the fallback.
        if (isLegacyFallbackStatus(lastPostStatus) && !got && err is null)
            throw new LegacyFallbackException(lastPostStatus);

        if (err !is null)
            throw err;
        if (got)
            return result;

        // Premature stream close with an SSE `retry:` hint: wait the prescribed
        // delay, then RESUME the stream with a GET carrying `Last-Event-ID`
        // (per Streamable HTTP resumability — not a re-POST of the request).
        if (sseRetryMs > 0)
        {
            sleep(sseRetryMs.msecs);
            resumeViaGet(expectId, sseLastEventId, result, got, err);
            if (err !is null)
                throw err;
            if (got)
                return result;
        }
        throw internalError("No response received for request " ~ method2(expectId));
    }

    /// Resume a closed response stream via `GET` with `Last-Event-ID`, reading
    /// the resumed SSE stream until the awaited response (`expectId`) arrives.
    private void resumeViaGet(long expectId, string lastEventId, ref Json result,
            ref bool got, ref McpException err) @safe
    {
        import vibe.core.net : connectTCP;
        import vibe.stream.operations : readLine;
        import vibe.core.stream : IOMode;
        import std.string : indexOf, startsWith, strip, toLower;
        import std.conv : to, parse;

        auto rest = url;
        const sep = rest.indexOf("://");
        if (sep >= 0)
            rest = rest[sep + 3 .. $];
        const slash = rest.indexOf('/');
        const hostPort = (slash < 0) ? rest : rest[0 .. slash];
        const path = (slash < 0) ? "/" : rest[slash .. $];
        const colon = hostPort.indexOf(':');
        const host = (colon < 0) ? hostPort : hostPort[0 .. colon];
        const port = (colon < 0) ? 80 : hostPort[colon + 1 .. $].to!ushort;

        () @trusted {
            try
            {
                auto conn = connectTCP(host, port);
                scope (exit)
                    conn.close();
                string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
                    ~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
                if (sessionId.length)
                    req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
                if (didInitialize)
                    req ~= "MCP-Protocol-Version: " ~ negotiated.toWire ~ "\r\n";
                if (lastEventId.length)
                    req ~= "Last-Event-ID: " ~ lastEventId ~ "\r\n";
                req ~= "\r\n";
                conn.write(cast(const(ubyte)[]) req);

                auto statusLine = cast(string) readLine(conn).idup;
                if (statusLine.indexOf(" 200") < 0)
                    return;
                bool chunked;
                for (;;)
                {
                    auto h = cast(string) readLine(conn).idup;
                    if (h.length && h[$ - 1] == '\r')
                        h = h[0 .. $ - 1];
                    if (h.toLower.indexOf("transfer-encoding:") == 0
                            && h.toLower.indexOf("chunked") >= 0)
                        chunked = true;
                    if (h.length == 0)
                        break;
                }

                string acc, data;
                bool done;
                void parseSse()
                {
                    for (;;)
                    {
                        const nl = acc.indexOf('\n');
                        if (nl < 0)
                            break;
                        auto line = acc[0 .. nl];
                        acc = acc[nl + 1 .. $];
                        if (line.length && line[$ - 1] == '\r')
                            line = line[0 .. $ - 1];
                        if (line.length == 0)
                        {
                            if (data.length)
                            {
                                try
                                {
                                    auto m = Message(parseJsonString(data));
                                    if ((m.kind == MessageKind.response
                                            || m.kind == MessageKind.errorResponse)
                                            && m.id.type == Json.Type.int_
                                            && m.id.get!long == expectId)
                                    {
                                        if (m.kind == MessageKind.errorResponse)
                                            err = errorFrom(m.error);
                                        else
                                        {
                                            result = m.result;
                                            got = true;
                                        }
                                        done = true;
                                    }
                                    else
                                        dispatchInbound(m);
                                }
                                catch (Exception)
                                {
                                }
                                data = null;
                            }
                        }
                        else if (line.startsWith("data:"))
                        {
                            auto d = line["data:".length .. $];
                            if (d.startsWith(" "))
                                d = d[1 .. $];
                            data ~= (data.length ? "\n" : "") ~ d;
                        }
                    }
                }

                for (;;)
                {
                    if (done)
                        break;
                    if (chunked)
                    {
                        auto sizeLine = (cast(string) readLine(conn).idup).strip;
                        if (sizeLine.length == 0)
                            continue;
                        uint sz;
                        try
                            sz = parse!uint(sizeLine, 16);
                        catch (Exception)
                            break;
                        if (sz == 0)
                            break;
                        auto chunk = new ubyte[sz];
                        conn.read(chunk, IOMode.all);
                        acc ~= cast(string) chunk.idup;
                        readLine(conn);
                        parseSse();
                    }
                    else
                    {
                        const avail = conn.leastSize;
                        if (avail == 0)
                            break;
                        const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
                        auto buf = new ubyte[toRead];
                        conn.read(buf, IOMode.once);
                        acc ~= cast(string) buf.idup;
                        parseSse();
                    }
                }
            }
            catch (Exception)
            {
            }
        }();
    }

    private static string method2(long id) @safe
    {
        import std.conv : to;

        return id.to!string;
    }

    private void setupRequest(scope HTTPClientRequest req, Json message) @safe
    {
        req.method = HTTPMethod.POST;
        req.headers["Accept"] = "application/json, text/event-stream";
        req.contentType = "application/json";
        if (bearerToken.length)
            req.headers["Authorization"] = "Bearer " ~ bearerToken;
        if (sessionId.length)
            req.headers["Mcp-Session-Id"] = sessionId;
        if (useDraft)
            addDraftHeaders(req, message);
        else if (didInitialize)
            req.headers["MCP-Protocol-Version"] = negotiated.toWire;
        if (pendingLastEventId.length)
            req.headers["Last-Event-ID"] = pendingLastEventId;
        req.writeBody(cast(const(ubyte)[]) message.toString());
    }

    /// Add the draft standard request headers (`MCP-Protocol-Version`,
    /// `Mcp-Method`, and `Mcp-Name` for tools/call, resources/read, prompts/get)
    /// derived from the outgoing message.
    private void addDraftHeaders(scope HTTPClientRequest req, Json message) @safe
    {
        req.headers[HttpHeader.protocolVersion] = negotiated.toWire;
        if ("method" !in message)
            return; // a response to a server-initiated input request
        const method = message["method"].get!string;
        req.headers[HttpHeader.method] = method;
        auto params = ("params" in message) ? message["params"] : Json.emptyObject;
        string name;
        if (method == "tools/call" || method == "prompts/get")
        {
            if ("name" in params && params["name"].type == Json.Type.string)
                name = params["name"].get!string;
        }
        else if (method == "resources/read")
        {
            if ("uri" in params && params["uri"].type == Json.Type.string)
                name = params["uri"].get!string;
        }
        if (name.length)
            req.headers[HttpHeader.name] = name;

        // Mirror x-mcp-header-annotated tool arguments into Mcp-Param-{Name}
        // headers (draft basic/transports, "Custom Headers from Tool
        // Parameters"): clients MUST inspect the tool's inputSchema and append a
        // header for each annotated argument that is present and non-null.
        if (method == "tools/call" && name.length)
        {
            auto schema = name in toolInputSchemas_;
            if (schema !is null)
            {
                auto args = ("arguments" in params) ? params["arguments"] : Json.emptyObject;
                foreach (header, value; paramHeaders(*schema, args))
                    req.headers[header] = value;
            }
        }
    }

    /// Compute the `Mcp-Param-*` headers to emit for a `tools/call`, given the
    /// tool's `inputSchema` and the call `arguments`. For each top-level property
    /// annotated with `x-mcp-header` (see `paramHeaderMap`), the matching argument
    /// value is encoded with `encodeHeaderValue` and mapped to its
    /// `Mcp-Param-{Name}` header. Per the draft spec's mirroring table, an
    /// argument that is absent or `null` produces no header. Non-string scalars
    /// (numbers, booleans) are stringified; object/array values are emitted as
    /// their compact JSON. Separated as a pure static helper so the mirroring can
    /// be unit-tested without a live server.
    package static string[string] paramHeaders(Json inputSchema, Json arguments) @safe
    {
        string[string] headers;
        auto map = paramHeaderMap(inputSchema);
        if (map.length == 0 || arguments.type != Json.Type.object)
            return headers;
        foreach (param, header; map)
        {
            if (param !in arguments)
                continue; // absent -> no header
            auto v = arguments[param];
            if (v.type == Json.Type.null_ || v.type == Json.Type.undefined)
                continue; // null -> no header
            string raw;
            final switch (v.type)
            {
            case Json.Type.string:
                raw = v.get!string;
                break;
            case Json.Type.int_:
            case Json.Type.bigInt:
            case Json.Type.float_:
            case Json.Type.bool_:
                raw = v.toString();
                break;
            case Json.Type.object:
            case Json.Type.array:
                raw = v.toString();
                break;
            case Json.Type.null_:
            case Json.Type.undefined:
                continue;
            }
            headers[header] = encodeHeaderValue(raw);
        }
        return headers;
    }

    private void captureSession(scope HTTPClientResponse res) @safe
    {
        if ("Mcp-Session-Id" in res.headers)
            sessionId = res.headers["Mcp-Session-Id"];
    }

    /// Read an SSE stream, dispatching messages until the awaited response.
    ///
    /// Blocks on `readLine` rather than polling `empty`: an SSE stream may stay
    /// open and idle between events (e.g. while the server awaits our reply to a
    /// server->client request), and `empty` can spuriously report end-of-stream
    /// in that window. A read exception signals the stream has closed.
    private void readSse(scope HTTPClientResponse res, long expectId,
            ref Json result, ref bool got, ref McpException err) @safe
    {
        string dataBuf;
        for (;;)
        {
            string line;
            bool eof;
            () @trusted {
                try
                    line = cast(string) readLine(res.bodyReader, size_t.max, "\n").idup;
                catch (Exception)
                    eof = true;
            }();
            if (eof)
                break;
            if (line.length && line[$ - 1] == '\r')
                line = line[0 .. $ - 1];

            if (line.length == 0)
            {
                if (dataBuf.length)
                {
                    dispatchSse(dataBuf, expectId, result, got, err);
                    dataBuf = null;
                    if (got || err !is null)
                        return;
                }
                continue;
            }
            if (line.startsWith("data:"))
            {
                auto d = line["data:".length .. $];
                if (d.startsWith(" "))
                    d = d[1 .. $];
                dataBuf ~= (dataBuf.length ? "\n" : "") ~ d;
            }
            else if (line.startsWith("id:"))
            {
                import std.string : strip;

                sseLastEventId = line["id:".length .. $].strip;
            }
            else if (line.startsWith("retry:"))
            {
                import std.string : strip;
                import std.conv : to;

                try
                    sseRetryMs = line["retry:".length .. $].strip.to!long;
                catch (Exception)
                {
                }
            }
        }
        // Flush a trailing event with no terminating blank line.
        if (dataBuf.length && !got && err is null)
            dispatchSse(dataBuf, expectId, result, got, err);
    }

    private void dispatchSse(string data, long expectId, ref Json result,
            ref bool got, ref McpException err) @safe
    {
        Message msg;
        try
            msg = Message(parseJsonString(data));
        catch (Exception)
            return; // ignore non-JSON SSE comments/heartbeats

        // A response for a request we have cancelled is ignored per spec, even if
        // it matches the id we are awaiting.
        if ((msg.kind == MessageKind.response || msg.kind == MessageKind.errorResponse)
                && msg.id.type == Json.Type.int_ && isResponseCancelled(msg.id.get!long))
            return;

        final switch (msg.kind)
        {
        case MessageKind.response:
            if (msg.id.type == Json.Type.int_ && msg.id.get!long == expectId)
            {
                result = msg.result;
                got = true;
            }
            break;
        case MessageKind.errorResponse:
            if (msg.id.type == Json.Type.int_
                    && msg.id.get!long == expectId)
                err = errorFrom(msg.error);
            break;
        case MessageKind.request:
            handleServerRequest(msg);
            break;
        case MessageKind.notification:
            dispatchNotification(msg.method, msg.params);
            break;
        }
    }

    /// Forward an inbound notification to `onNotification`, applying the protocol
    /// rules for notifications the SDK understands. Currently this enforces the
    /// URL-mode elicitation rule (basic/utilities/elicitation §"Completion
    /// Notifications for URL Mode Elicitation"): "Clients MUST ignore
    /// notifications referencing unknown or already-completed IDs." A
    /// `notifications/elicitation/complete` for an `elicitationId` we never issued
    /// a URL-mode request for, or one we have already seen completed, is dropped
    /// (never forwarded); the first valid completion for a known id is forwarded
    /// and then marked completed. Every other notification is forwarded unchanged.
    private void dispatchNotification(string method, Json params) @safe
    {
        if (method == "notifications/elicitation/complete")
        {
            if (params.type != Json.Type.object || "elicitationId" !in params
                    || params["elicitationId"].type != Json.Type.string)
                return; // malformed: no id to correlate -> ignore
            const eid = params["elicitationId"].get!string;
            auto seen = eid in elicitationIds_;
            if (seen is null || *seen)
                return; // unknown or already-completed id -> ignore per spec
            elicitationIds_[eid] = true; // mark completed
        }
        // Deliver progress updates as a typed value to the dedicated observer,
        // in addition to the generic catch-all below.
        if (method == "notifications/progress" && onProgress !is null)
            onProgress(ProgressNotification.fromJson(params));
        if (onNotification !is null)
            onNotification(method, params);
    }

    /// Dispatch a message arriving on the standalone GET SSE stream: server->
    /// client requests and notifications (never an awaited response).
    private void dispatchInbound(Message msg) @safe
    {
        final switch (msg.kind)
        {
        case MessageKind.request:
            handleServerRequest(msg);
            break;
        case MessageKind.notification:
            dispatchNotification(msg.method, msg.params);
            break;
        case MessageKind.response:
        case MessageKind.errorResponse:
            break; // not expected on the listening stream
        }
    }

    /// Open the standalone server->client SSE stream (`GET /mcp`) in a background
    /// task, so the server can deliver sampling / elicitation / roots requests
    /// and notifications outside of any POST response. A server that does not
    /// offer this stream (e.g. responds 405) is tolerated as a no-op.
    void startServerStream() @safe
    {
        import vibe.core.core : runTask;

        runTask(() nothrow{
            try
                runServerStream();
            catch (Exception)
            {
            }
        });
    }

    /// Extract complete SSE events (terminated by a blank line) from `acc`,
    /// dispatch each as an inbound message, and return the unconsumed remainder.
    private string drainSseEvents(string acc) @safe
    {
        import std.array : replace;
        import std.string : indexOf, splitLines, startsWith;

        acc = acc.replace("\r\n", "\n");
        for (;;)
        {
            const b = acc.indexOf("\n\n");
            if (b < 0)
                break;
            auto event = acc[0 .. b];
            acc = acc[b + 2 .. $];
            string data;
            foreach (line; event.splitLines())
            {
                if (line.startsWith("data:"))
                {
                    auto d = line["data:".length .. $];
                    if (d.startsWith(" "))
                        d = d[1 .. $];
                    data ~= (data.length ? "\n" : "") ~ d;
                }
            }
            if (data.length)
            {
                try
                    dispatchInbound(Message(parseJsonString(data)));
                catch (Exception)
                {
                }
            }
        }
        return acc;
    }

    /// Open the standalone server->client SSE stream over a raw TCP connection
    /// (vibe's pooled `requestHTTP` does not reliably surface a long-lived,
    /// idle-then-active SSE body). Honors the SSE `retry:` field and resumes with
    /// `Last-Event-ID` on reconnect, up to a few attempts.
    private void runServerStream() @safe
    {
        import vibe.core.net : connectTCP;
        import vibe.stream.operations : readLine;
        import std.string : indexOf, startsWith, strip;
        import std.conv : to;
        import core.time : msecs;
        import vibe.core.core : sleep;

        // Parse scheme://host[:port]/path.
        auto rest = url;
        const sep = rest.indexOf("://");
        if (sep >= 0)
            rest = rest[sep + 3 .. $];
        const slash = rest.indexOf('/');
        const hostPort = (slash < 0) ? rest : rest[0 .. slash];
        const path = (slash < 0) ? "/" : rest[slash .. $];
        const colon = hostPort.indexOf(':');
        const host = (colon < 0) ? hostPort : hostPort[0 .. colon];
        const port = (colon < 0) ? 80 : hostPort[colon + 1 .. $].to!ushort;

        string lastEventId;
        long retryMs = 0;
        foreach (attempt; 0 .. 2)
        {
            bool sawData;
            () @trusted {
                try
                {
                    auto conn = connectTCP(host, port);
                    scope (exit)
                        conn.close();

                    string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
                        ~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
                    if (sessionId.length)
                        req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
                    if (didInitialize)
                        req ~= "MCP-Protocol-Version: " ~ negotiated.toWire ~ "\r\n";
                    if (lastEventId.length)
                        req ~= "Last-Event-ID: " ~ lastEventId ~ "\r\n";
                    req ~= "\r\n";
                    conn.write(cast(const(ubyte)[]) req);

                    import vibe.core.stream : IOMode;
                    import std.conv : parse;

                    // Status line + headers (note chunked transfer-encoding).
                    auto statusLine = cast(string) readLine(conn).idup;
                    if (statusLine.indexOf(" 200") < 0)
                        return;
                    bool chunked;
                    for (;;)
                    {
                        auto h = cast(string) readLine(conn).idup;
                        if (h.length && h[$ - 1] == '\r')
                            h = h[0 .. $ - 1];
                        import std.string : toLower;

                        if (h.toLower.indexOf("transfer-encoding:") == 0
                                && h.toLower.indexOf("chunked") >= 0)
                            chunked = true;
                        if (h.length == 0)
                            break;
                    }

                    // SSE parser shared across chunk boundaries.
                    string acc, data;
                    void parseSse()
                    {
                        for (;;)
                        {
                            const nl = acc.indexOf('\n');
                            if (nl < 0)
                                break;
                            auto line = acc[0 .. nl];
                            acc = acc[nl + 1 .. $];
                            if (line.length && line[$ - 1] == '\r')
                                line = line[0 .. $ - 1];
                            if (line.length == 0)
                            {
                                if (data.length)
                                {
                                    sawData = true;
                                    try
                                        dispatchInbound(Message(parseJsonString(data)));
                                    catch (Exception)
                                    {
                                    }
                                    data = null;
                                }
                            }
                            else if (line.startsWith("data:"))
                            {
                                auto d = line["data:".length .. $];
                                if (d.startsWith(" "))
                                    d = d[1 .. $];
                                data ~= (data.length ? "\n" : "") ~ d;
                            }
                            else if (line.startsWith("id:"))
                                lastEventId = line["id:".length .. $].strip;
                            else if (line.startsWith("retry:"))
                            {
                                try
                                    retryMs = line["retry:".length .. $].strip.to!long;
                                catch (Exception)
                                {
                                }
                            }
                        }
                    }

                    // Body loop: decode chunked transfer-encoding (each chunk is a
                    // hex size line, that many bytes, then CRLF), feeding the SSE
                    // parser; or read raw to EOF when not chunked.
                    for (;;)
                    {
                        if (chunked)
                        {
                            auto sizeLine = (cast(string) readLine(conn).idup).strip;
                            if (sizeLine.length == 0)
                                continue;
                            uint sz;
                            try
                            {
                                auto sl = sizeLine;
                                sz = parse!uint(sl, 16);
                            }
                            catch (Exception)
                                break;
                            if (sz == 0)
                                break; // last chunk
                            auto chunk = new ubyte[sz];
                            conn.read(chunk, IOMode.all);
                            acc ~= cast(string) chunk.idup;
                            readLine(conn); // trailing CRLF after the chunk data
                            parseSse();
                        }
                        else
                        {
                            const avail = conn.leastSize;
                            if (avail == 0)
                                break;
                            const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
                            auto buf = new ubyte[toRead];
                            conn.read(buf, IOMode.once);
                            acc ~= cast(string) buf.idup;
                            parseSse();
                        }
                    }
                }
                catch (Exception)
                {
                }
            }();

            // Reconnect honoring the server-provided retry delay (SSE `retry:`).
            if (retryMs > 0)
                sleep(retryMs.msecs);
            else if (!sawData)
                break; // stream unavailable and no retry hint: stop
        }
    }

    /// Drive a `subscriptions/listen` stream over a raw TCP connection: POST the
    /// listen request, read the server's long-lived `text/event-stream` response,
    /// and dispatch every inbound message (the leading
    /// `notifications/subscriptions/acknowledged` and subsequent change
    /// notifications) via `dispatchInbound`. The loop checks `*cancelled` between
    /// reads and on each SSE event, closing the connection promptly once the
    /// caller cancels. A raw TCP POST is used (rather than vibe's pooled
    /// `requestHTTP`) for the same reason as `runServerStream`: a long-lived,
    /// idle-then-active SSE body is not reliably surfaced by the pooled client.
    private void runListenStream(Json message, shared(bool)* cancelled) @safe
    {
        import vibe.core.net : connectTCP;
        import vibe.stream.operations : readLine;
        import vibe.core.stream : IOMode;
        import std.string : indexOf, startsWith, strip, toLower;
        import std.conv : to, parse;

        auto rest = url;
        const sep = rest.indexOf("://");
        if (sep >= 0)
            rest = rest[sep + 3 .. $];
        const slash = rest.indexOf('/');
        const hostPort = (slash < 0) ? rest : rest[0 .. slash];
        const path = (slash < 0) ? "/" : rest[slash .. $];
        const colon = hostPort.indexOf(':');
        const host = (colon < 0) ? hostPort : hostPort[0 .. colon];
        const port = (colon < 0) ? 80 : hostPort[colon + 1 .. $].to!ushort;

        const 
        body = message.toString();
        () @trusted {
            auto conn = connectTCP(host, port);
            scope (exit)
                conn.close();

            string req = "POST " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
                ~ "\r\nAccept: text/event-stream\r\nContent-Type: application/json\r\n"
                ~ "Connection: keep-alive\r\n";
            if (bearerToken.length)
                req ~= "Authorization: Bearer " ~ bearerToken ~ "\r\n";
            if (sessionId.length)
                req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
            req ~= "MCP-Protocol-Version: " ~ negotiated.toWire ~ "\r\n";
            if (useDraft)
            {
                req ~= HttpHeader.protocolVersion ~ ": " ~ negotiated.toWire ~ "\r\n";
                req ~= HttpHeader.method ~ ": subscriptions/listen\r\n";
            }
            import std.conv : to;

            req ~= "Content-Length: " ~ body.length.to!string ~ "\r\n\r\n";
            req ~= body;
            conn.write(cast(const(ubyte)[]) req);

            auto statusLine = cast(string) readLine(conn).idup;
            if (statusLine.indexOf(" 200") < 0)
                return;
            bool chunked;
            for (;;)
            {
                auto h = cast(string) readLine(conn).idup;
                if (h.length && h[$ - 1] == '\r')
                    h = h[0 .. $ - 1];
                if (h.toLower.indexOf("transfer-encoding:") == 0 && h.toLower.indexOf(
                        "chunked") >= 0)
                    chunked = true;
                if (h.length == 0)
                    break;
            }

            string acc, data;
            void parseSse()
            {
                for (;;)
                {
                    const nl = acc.indexOf('\n');
                    if (nl < 0)
                        break;
                    auto line = acc[0 .. nl];
                    acc = acc[nl + 1 .. $];
                    if (line.length && line[$ - 1] == '\r')
                        line = line[0 .. $ - 1];
                    if (line.length == 0)
                    {
                        if (data.length)
                        {
                            try
                                dispatchInbound(Message(parseJsonString(data)));
                            catch (Exception)
                            {
                            }
                            data = null;
                        }
                    }
                    else if (line.startsWith("data:"))
                    {
                        auto d = line["data:".length .. $];
                        if (d.startsWith(" "))
                            d = d[1 .. $];
                        data ~= (data.length ? "\n" : "") ~ d;
                    }
                }
            }

            for (;;)
            {
                if (*cancelled)
                    break;
                if (chunked)
                {
                    auto sizeLine = (cast(string) readLine(conn).idup).strip;
                    if (sizeLine.length == 0)
                        continue;
                    uint sz;
                    try
                    {
                        auto sl = sizeLine;
                        sz = parse!uint(sl, 16);
                    }
                    catch (Exception)
                        break;
                    if (sz == 0)
                        break; // last chunk
                    auto chunk = new ubyte[sz];
                    conn.read(chunk, IOMode.all);
                    acc ~= cast(string) chunk.idup;
                    readLine(conn); // trailing CRLF after the chunk data
                    parseSse();
                }
                else
                {
                    const avail = conn.leastSize;
                    if (avail == 0)
                        break;
                    const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
                    auto buf = new ubyte[toRead];
                    conn.read(buf, IOMode.once);
                    acc ~= cast(string) buf.idup;
                    parseSse();
                }
            }
        }();
    }

    /// Establish the legacy HTTP+SSE (2024-11-05) two-endpoint transport:
    /// open the GET SSE stream at the server URL, read the first `endpoint`
    /// event to learn the message-POST URI, then keep the stream open in a
    /// background task to receive JSON-RPC responses and server notifications.
    /// Throws if the `endpoint` event is not received.
    private void startLegacyHttpSse() @safe
    {
        import vibe.core.core : runTask, sleep;
        import core.time : msecs;

        legacyMode = true;
        legacyEndpoint = null;

        // The GET SSE stream is long-lived: run its reader on a background task
        // so this method can return once the `endpoint` event has arrived.
        runTask(() nothrow{
            try
                runLegacyStream();
            catch (Exception)
            {
            }
        });

        // Wait (bounded) for the background task to discover the endpoint URI.
        foreach (_; 0 .. 200) // up to ~10s at 50ms granularity
        {
            if (legacyEndpoint.length)
                break;
            () @trusted { sleep(50.msecs); }();
        }
        if (legacyEndpoint.length == 0)
        {
            legacyMode = false;
            throw internalError(
                    "legacy HTTP+SSE server did not send an `endpoint` event on the GET stream");
        }
    }

    /// Send a JSON-RPC request over the legacy transport: POST it to the
    /// server-supplied endpoint URI, then await the correlated response, which
    /// arrives asynchronously on the standalone GET SSE stream.
    private Json legacyRpc(Json message, long expectId) @safe
    {
        import vibe.core.core : sleep;
        import core.time : msecs;

        legacyExpectId = expectId;
        legacyResult = Json.undefined;
        legacyGot = false;
        legacyErr = null;

        post(message); // POST to legacyEndpoint; server replies on the GET stream

        foreach (_; 0 .. 1200) // up to ~60s at 50ms granularity
        {
            if (legacyGot || legacyErr !is null)
                break;
            () @trusted { sleep(50.msecs); }();
        }
        legacyExpectId = 0;
        if (legacyErr !is null)
            throw legacyErr;
        if (legacyGot)
            return legacyResult;
        throw internalError("No legacy HTTP+SSE response for request " ~ method2(expectId));
    }

    /// Read the legacy GET SSE stream over a raw TCP connection, dispatching
    /// each event by type: an `endpoint` event sets the message-POST URI; a
    /// `message` (or default) event is a JSON-RPC message routed to the awaited
    /// response slot or to the inbound dispatcher.
    private void runLegacyStream() @safe
    {
        import vibe.core.net : connectTCP;
        import vibe.stream.operations : readLine;
        import vibe.core.stream : IOMode;
        import std.string : indexOf, startsWith, strip, toLower;
        import std.conv : to, parse;

        auto rest = url;
        const sep = rest.indexOf("://");
        if (sep >= 0)
            rest = rest[sep + 3 .. $];
        const slash = rest.indexOf('/');
        const hostPort = (slash < 0) ? rest : rest[0 .. slash];
        const path = (slash < 0) ? "/" : rest[slash .. $];
        const colon = hostPort.indexOf(':');
        const host = (colon < 0) ? hostPort : hostPort[0 .. colon];
        const port = (colon < 0) ? 80 : hostPort[colon + 1 .. $].to!ushort;

        () @trusted {
            try
            {
                auto conn = connectTCP(host, port);
                scope (exit)
                    conn.close();

                string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
                    ~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
                if (bearerToken.length)
                    req ~= "Authorization: Bearer " ~ bearerToken ~ "\r\n";
                if (sessionId.length)
                    req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
                req ~= "\r\n";
                conn.write(cast(const(ubyte)[]) req);

                auto statusLine = cast(string) readLine(conn).idup;
                if (statusLine.indexOf(" 200") < 0)
                    return;
                bool chunked;
                for (;;)
                {
                    auto h = cast(string) readLine(conn).idup;
                    if (h.length && h[$ - 1] == '\r')
                        h = h[0 .. $ - 1];
                    if (h.toLower.indexOf("transfer-encoding:") == 0
                            && h.toLower.indexOf("chunked") >= 0)
                        chunked = true;
                    if (h.length == 0)
                        break;
                }

                string acc, data, eventType;
                void handleEvent()
                {
                    scope (exit)
                    {
                        data = null;
                        eventType = null;
                    }
                    if (data.length == 0)
                        return;
                    if (eventType == "endpoint")
                    {
                        legacyEndpoint = resolveEndpointUri(url, data.strip);
                        return;
                    }
                    // `message` event (or untyped): a JSON-RPC message.
                    try
                    {
                        auto m = Message(parseJsonString(data));
                        if ((m.kind == MessageKind.response
                                || m.kind == MessageKind.errorResponse)
                                && m.id.type == Json.Type.int_ && m.id.get!long == legacyExpectId)
                        {
                            if (m.kind == MessageKind.errorResponse)
                                legacyErr = errorFrom(m.error);
                            else
                            {
                                legacyResult = m.result;
                                legacyGot = true;
                            }
                        }
                        else
                            dispatchInbound(m);
                    }
                    catch (Exception)
                    {
                    }
                }

                void parseSse()
                {
                    for (;;)
                    {
                        const nl = acc.indexOf('\n');
                        if (nl < 0)
                            break;
                        auto line = acc[0 .. nl];
                        acc = acc[nl + 1 .. $];
                        if (line.length && line[$ - 1] == '\r')
                            line = line[0 .. $ - 1];
                        if (line.length == 0)
                            handleEvent();
                        else if (line.startsWith("event:"))
                        {
                            auto v = line["event:".length .. $];
                            if (v.startsWith(" "))
                                v = v[1 .. $];
                            eventType = v;
                        }
                        else if (line.startsWith("data:"))
                        {
                            auto d = line["data:".length .. $];
                            if (d.startsWith(" "))
                                d = d[1 .. $];
                            data ~= (data.length ? "\n" : "") ~ d;
                        }
                    }
                }

                for (;;)
                {
                    if (chunked)
                    {
                        auto sizeLine = (cast(string) readLine(conn).idup).strip;
                        if (sizeLine.length == 0)
                            continue;
                        uint sz;
                        try
                            sz = parse!uint(sizeLine, 16);
                        catch (Exception)
                            break;
                        if (sz == 0)
                            break;
                        auto chunk = new ubyte[sz];
                        conn.read(chunk, IOMode.all);
                        acc ~= cast(string) chunk.idup;
                        readLine(conn);
                        parseSse();
                    }
                    else
                    {
                        const avail = conn.leastSize;
                        if (avail == 0)
                            break;
                        const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
                        auto buf = new ubyte[toRead];
                        conn.read(buf, IOMode.once);
                        acc ~= cast(string) buf.idup;
                        parseSse();
                    }
                }
            }
            catch (Exception)
            {
            }
        }();
    }

    /// Answer a server->client request by dispatching to the matching handler
    /// and POSTing the response on a *separate* task. Posting on its own task is
    /// essential: we are currently inside the SSE-read callback of the original
    /// request, and the server will not send that request's final response until
    /// it receives this one — a synchronous nested POST here would deadlock.
    private void handleServerRequest(Message msg) @safe
    {
        import vibe.core.core : runTask;

        Json response;
        try
        {
            Json result = dispatchServerMethod(msg.method, msg.params);
            response = makeResponse(msg.id, result);
        }
        catch (McpException e)
            response = makeErrorResponse(msg.id, e);
        catch (Exception e)
            response = makeErrorResponse(msg.id, internalError(e.msg));

        runTask((Json r) nothrow{
            try
                post(r);
            catch (Exception)
            {
            }
        }, response);
    }

    private Json dispatchServerMethod(string method, Json params) @safe
    {
        switch (method)
        {
        case "sampling/createMessage":
            if (onSampling is null)
                throw methodNotFound(method);
            // Enforce the spec's tool-result message-content constraints
            // before handing off to the delegate: a tool_result user message
            // must contain only tool results, and every assistant tool_use
            // must be answered by a matching tool_result. Violations surface
            // as -32602 (Invalid params) per client/sampling §Error Handling.
            validateSamplingMessages(params);
            return onSampling(params);
        case "elicitation/create":
            if (onElicitation is null)
                throw methodNotFound(method);
            // Per client/elicitation §Error Handling (2025-11-25): reject a
            // request whose `mode` was not declared in client capabilities with
            // -32602 (Invalid params). `mode` defaults to "form" when absent.
            // A bare `elicitation` declaration is equivalent to form-mode only,
            // so `elicitation` alone satisfies the form case.
            {
                const mode = ("mode" in params && params["mode"].type == Json.Type.string) ? params["mode"]
                    .get!string : "form";
                bool supported;
                switch (mode)
                {
                case "form":
                    supported = capabilities.elicitationForm || capabilities.elicitation;
                    break;
                case "url":
                    supported = capabilities.elicitationUrl;
                    break;
                default:
                    supported = false;
                    break;
                }
                if (!supported)
                    throw invalidParams("Unsupported elicitation mode: " ~ mode);
                // Remember the id of a URL-mode request so a later
                // notifications/elicitation/complete can be correlated; an
                // unknown id is ignored per the spec.
                if (mode == "url" && "elicitationId" in params
                        && params["elicitationId"].type == Json.Type.string)
                {
                    const eid = params["elicitationId"].get!string;
                    if (eid.length && eid !in elicitationIds_)
                        elicitationIds_[eid] = false; // tracked, not yet completed
                }
            }
            return onElicitation(params);
        case "roots/list":
            if (onListRoots is null)
                throw methodNotFound(method);
            return onListRoots(params);
        case "ping":
            return Json.emptyObject;
        default:
            throw methodNotFound(method);
        }
    }

    /// Whether a response with JSON-RPC id `id` belongs to a request this client
    /// has cancelled (and so should be ignored per basic/utilities/cancellation).
    /// Exposed for tests; cheap membership check on the cancelled-id set.
    package bool isResponseCancelled(long id) const @safe nothrow
    {
        return (id in cancelledRequests_) !is null;
    }

    /// Test seam: set the id `cancel()` treats as the (uncancellable) initialize
    /// request, without driving the live `initialize` handshake.
    package void setInitializeRequestIdForTest(long id) @safe nothrow @nogc
    {
        initializeRequestId = id;
    }

    private static McpException errorFrom(Json error) @safe
    {
        const code = ("code" in error) ? error["code"].get!int : ErrorCode.internalError;
        const m = ("message" in error) ? error["message"].get!string : "server error";
        return new McpException(code, m, error);
    }
}

/// Pick the newest protocol version both this SDK and the server support, given
/// the server's advertised wire-string list (from `server/discover` or the
/// `supported` field of an `UnsupportedProtocolVersionError`). Returns false
/// when there is no overlap. Used by `MCPClient.connect` for modern-vs-legacy
/// server detection per the transport backward-compatibility rules.
bool selectMutualVersion(const string[] serverVersions, out ProtocolVersion chosen) @safe
{
    import std.range : retro;

    foreach (cand; supportedVersions.retro) // newest (draft) first
    {
        foreach (s; serverVersions)
        {
            ProtocolVersion sv;
            if (tryParseVersion(s, sv) && sv == cand)
            {
                chosen = cand;
                return true;
            }
        }
    }
    return false;
}

/// Whether an HTTP status from the initial modern POST should trigger the
/// legacy HTTP+SSE (2024-11-05) backward-compatibility fallback. Per
/// basic/transports §Backwards Compatibility, a client probing a single modern
/// endpoint should fall back when the POST fails with 400 Bad Request, 404 Not
/// Found, or 405 Method Not Allowed.
bool isLegacyFallbackStatus(int status) pure nothrow @safe @nogc
{
    return status == 400 || status == 404 || status == 405;
}

/// Parse a legacy HTTP+SSE event stream looking for the first `endpoint` event,
/// returning its `data:` payload (the message-POST URI) in `uri`. Returns false
/// if no `endpoint` event is found in the supplied buffer. Handles CRLF and LF
/// line endings and the optional single leading space after `data:`.
bool parseEndpointEvent(string sse, out string uri) @safe
{
    import std.string : startsWith, splitLines;

    string eventType;
    string data;
    bool haveData;

    bool flush()
    {
        if (eventType == "endpoint" && haveData)
        {
            uri = data;
            return true;
        }
        eventType = null;
        data = null;
        haveData = false;
        return false;
    }

    foreach (raw; sse.splitLines())
    {
        auto line = raw;
        if (line.length && line[$ - 1] == '\r')
            line = line[0 .. $ - 1];
        if (line.length == 0)
        {
            if (flush())
                return true;
            continue;
        }
        if (line.startsWith("event:"))
        {
            auto v = line["event:".length .. $];
            if (v.startsWith(" "))
                v = v[1 .. $];
            eventType = v;
        }
        else if (line.startsWith("data:"))
        {
            auto d = line["data:".length .. $];
            if (d.startsWith(" "))
                d = d[1 .. $];
            data ~= (haveData ? "\n" : "") ~ d;
            haveData = true;
        }
    }
    // A trailing event without a terminating blank line.
    return flush();
}

/// Resolve a legacy `endpoint` event URI (which may be absolute, root-relative,
/// or document-relative) against the GET-SSE base URL, yielding the absolute URL
/// to POST subsequent JSON-RPC messages to.
string resolveEndpointUri(string baseUrl, string endpoint) @safe
{
    import std.string : indexOf, startsWith, lastIndexOf;

    if (endpoint.startsWith("http://") || endpoint.startsWith("https://"))
        return endpoint;

    // Split base into scheme://authority and path.
    const sep = baseUrl.indexOf("://");
    if (sep < 0)
        return endpoint;
    const afterScheme = sep + 3;
    const slash = baseUrl[afterScheme .. $].indexOf('/');
    string origin = (slash < 0) ? baseUrl : baseUrl[0 .. afterScheme + slash];
    string basePath = (slash < 0) ? "/" : baseUrl[afterScheme + slash .. $];

    if (endpoint.startsWith("/"))
        return origin ~ endpoint;

    // Document-relative: replace the last path segment of the base.
    const lastSlash = basePath.lastIndexOf('/');
    string dir = (lastSlash < 0) ? "/" : basePath[0 .. lastSlash + 1];
    return origin ~ dir ~ endpoint;
}

/// Validate the protocol version the server returned in its `initialize`
/// response and return the version to operate under. Per the Lifecycle /
/// Version Negotiation requirement ("If the client does not support the version
/// in the server's response, it SHOULD disconnect"), throws an
/// `UnsupportedProtocolVersionError` `McpException` when the server's version is
/// unparseable or not in `supportedVersions`, rather than silently proceeding
/// under a stale negotiated version.
ProtocolVersion resolveNegotiatedVersion(string serverVersion) @safe
{
    ProtocolVersion v;
    if (!tryParseVersion(serverVersion, v))
        throw new McpException(ErrorCode.unsupportedProtocolVersion,
                "Server returned unsupported protocol version: " ~ serverVersion);
    return v;
}

unittest  // resolveNegotiatedVersion accepts a supported server version
{
    assert(resolveNegotiatedVersion("2025-06-18") == ProtocolVersion.v2025_06_18);
    assert(resolveNegotiatedVersion("2026-07-28") == ProtocolVersion.draft);
}

unittest  // resolveNegotiatedVersion throws on an unparseable server version
{
    import std.exception : assertThrown;

    assertThrown!McpException(resolveNegotiatedVersion("1999-01-01"));
}

unittest  // resolveNegotiatedVersion throws with the unsupported-version error code
{
    bool threw;
    try
        resolveNegotiatedVersion("not-a-version");
    catch (McpException e)
    {
        threw = true;
        assert(e.code == ErrorCode.unsupportedProtocolVersion);
    }
    assert(threw);
}

unittest  // selectMutualVersion prefers the newest mutually-supported version
{
    ProtocolVersion v;
    assert(selectMutualVersion(["2025-11-25", "2026-07-28"], v) && v == ProtocolVersion.draft);
    assert(selectMutualVersion(["2024-11-05", "2025-03-26"], v) && v == ProtocolVersion.v2025_03_26);
}

unittest  // selectMutualVersion reports no overlap
{
    ProtocolVersion v;
    assert(!selectMutualVersion(["1999-01-01"], v));
    assert(!selectMutualVersion([], v));
}

unittest  // isLegacyFallbackStatus recognises the spec's 400/404/405 triggers
{
    assert(isLegacyFallbackStatus(400));
    assert(isLegacyFallbackStatus(404));
    assert(isLegacyFallbackStatus(405));
}

unittest  // isLegacyFallbackStatus ignores success and other errors
{
    assert(!isLegacyFallbackStatus(200));
    assert(!isLegacyFallbackStatus(202));
    assert(!isLegacyFallbackStatus(401));
    assert(!isLegacyFallbackStatus(500));
}

unittest  // parseEndpointEvent extracts the message URI from a legacy SSE endpoint event
{
    // A real 2024-11-05 HTTP+SSE server's first event on the GET stream.
    string sse = "event: endpoint\ndata: /messages?sessionId=abc123\n\n";
    string uri;
    assert(parseEndpointEvent(sse, uri));
    assert(uri == "/messages?sessionId=abc123");
}

unittest  // parseEndpointEvent handles CRLF line endings and leading data space
{
    string sse = "event: endpoint\r\ndata:/messages\r\n\r\n";
    string uri;
    assert(parseEndpointEvent(sse, uri));
    assert(uri == "/messages");
}

unittest  // parseEndpointEvent ignores a message event and finds a later endpoint event
{
    string sse = "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n"
        ~ "event: endpoint\ndata: /post\n\n";
    string uri;
    assert(parseEndpointEvent(sse, uri));
    assert(uri == "/post");
}

unittest  // parseEndpointEvent returns false when no endpoint event is present
{
    string sse = "event: message\ndata: {}\n\n";
    string uri;
    assert(!parseEndpointEvent(sse, uri));
}

unittest  // resolveEndpointUri keeps an absolute URI unchanged
{
    assert(resolveEndpointUri("http://host:8080/mcp",
            "http://other:9000/messages") == "http://other:9000/messages");
}

unittest  // resolveEndpointUri resolves a root-relative path against the server origin
{
    assert(resolveEndpointUri("http://host:8080/sse",
            "/messages?sessionId=abc") == "http://host:8080/messages?sessionId=abc");
}

unittest  // resolveEndpointUri resolves a relative path against the base directory
{
    assert(resolveEndpointUri("http://host:8080/api/sse",
            "messages") == "http://host:8080/api/messages");
}

unittest  // validateOutput passes a conforming structured result
{
    import mcp.api.schema : jsonSchemaOf;

    struct AddResult
    {
        int result;
    }

    Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
    CallToolResult r;
    r.structuredContent = Json(["result": Json(5)]);
    assert(MCPClient.validateOutput(t, r) == "");
}

unittest  // validateOutput rejects a non-conforming structured result
{
    import mcp.api.schema : jsonSchemaOf;

    struct AddResult
    {
        int result;
    }

    Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
    CallToolResult r;
    r.structuredContent = Json(["result": Json("oops")]);
    assert(MCPClient.validateOutput(t, r).length > 0);
}

unittest  // validateOutput is a no-op when the tool has no output schema
{
    Tool t = {name: "noschema"};
    CallToolResult r;
    r.structuredContent = Json(["anything": Json(1)]);
    assert(MCPClient.validateOutput(t, r) == "");
}

unittest  // validateOutput is a no-op when there is no structured content
{
    import mcp.api.schema : jsonSchemaOf;

    struct AddResult
    {
        int result;
    }

    Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
    CallToolResult r; // structuredContent stays undefined
    assert(MCPClient.validateOutput(t, r) == "");
}

unittest  // sampling dispatch rejects an unbalanced tool_use with -32602
{
    auto c = new MCPClient("http://localhost");
    bool delegateCalled;
    c.onSampling = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    // assistant tool_use with no following tool_result user message.
    Json tu = Json.emptyObject;
    tu["type"] = "tool_use";
    tu["id"] = "call_1";
    tu["name"] = "get_weather";
    tu["input"] = Json.emptyObject;
    Json m = Json.emptyObject;
    m["role"] = "assistant";
    m["content"] = Json([tu]);
    Json params = Json.emptyObject;
    params["messages"] = Json([m]);

    bool threw;
    try
        c.dispatchServerMethod("sampling/createMessage", params);
    catch (McpException e)
    {
        threw = true;
        assert(e.code == ErrorCode.invalidParams);
        assert(e.msg == "Tool result missing in request");
    }
    assert(threw);
    assert(!delegateCalled); // validation runs before the delegate
}

unittest  // notifyRootsListChanged emits the spec notification method
{
    auto c = new MCPClient("http://localhost");
    Json sent = Json.undefined;
    c.onNotifyForTest = (Json message) @safe { sent = message; };

    c.notifyRootsListChanged();

    assert(sent.type == Json.Type.object);
    assert(sent["jsonrpc"].get!string == "2.0");
    assert("id" !in sent); // a notification has no id
    assert(sent["method"].get!string == "notifications/roots/list_changed");
}

unittest  // setRoots answers roots/list with the typed envelope
{
    auto c = new MCPClient("http://localhost");
    c.setRoots([
        Root("file:///home/user/project", nullable("My Project")),
        Root("file:///tmp")
    ]);

    assert(c.onListRoots !is null);
    auto result = c.onListRoots(Json.emptyObject);
    assert(result["roots"].type == Json.Type.array);
    assert(result["roots"].length == 2);
    assert(result["roots"][0]["uri"].get!string == "file:///home/user/project");
    assert(result["roots"][0]["name"].get!string == "My Project");
    assert(result["roots"][1]["uri"].get!string == "file:///tmp");
    assert("name" !in result["roots"][1]);

    // The typed result parses back into a ListRootsResult.
    auto parsed = ListRootsResult.fromJson(result);
    assert(parsed.roots.length == 2);
    assert(parsed.roots[0].name.get == "My Project");
}

unittest  // sendNotification sends an arbitrary client-originated notification
{
    auto c = new MCPClient("http://localhost");
    Json sent = Json.undefined;
    c.onNotifyForTest = (Json message) @safe { sent = message; };

    Json params = Json.emptyObject;
    params["progressToken"] = "tok-1";
    params["progress"] = 42;
    c.sendNotification("notifications/progress", params);

    assert(sent.type == Json.Type.object);
    assert(sent["method"].get!string == "notifications/progress");
    assert("id" !in sent);
    assert(sent["params"]["progressToken"].get!string == "tok-1");
    assert(sent["params"]["progress"].get!int == 42);
}

unittest  // cancel() emits notifications/cancelled with the requestId and reason
{
    auto c = new MCPClient("http://localhost");
    Json sent = Json.undefined;
    c.onNotifyForTest = (Json message) @safe { sent = message; };

    c.cancel(7, "user aborted");

    assert(sent.type == Json.Type.object);
    assert(sent["jsonrpc"].get!string == "2.0");
    assert("id" !in sent); // a notification has no id
    assert(sent["method"].get!string == "notifications/cancelled");
    assert(sent["params"]["requestId"].get!long == 7);
    assert(sent["params"]["reason"].get!string == "user aborted");
}

unittest  // cancel() without a reason omits the reason field
{
    auto c = new MCPClient("http://localhost");
    Json sent = Json.undefined;
    c.onNotifyForTest = (Json message) @safe { sent = message; };

    c.cancel(3);

    assert(sent["params"]["requestId"].get!long == 3);
    assert("reason" !in sent["params"]);
}

unittest  // after cancel(), a response for that id is treated as cancelled (ignored)
{
    auto c = new MCPClient("http://localhost");
    c.onNotifyForTest = (Json message) @safe {};

    assert(!c.isResponseCancelled(11));
    c.cancel(11);
    assert(c.isResponseCancelled(11));
    // Unrelated ids are unaffected.
    assert(!c.isResponseCancelled(12));
}

unittest  // cancel() refuses to cancel the initialize request per spec
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto c = new MCPClient("http://localhost");
    c.onNotifyForTest = (Json message) @safe {};
    // Simulate that the initialize request used id 5.
    c.setInitializeRequestIdForTest(5);
    assertThrown!McpException(c.cancel(5));
    // A different in-flight request id is still cancellable.
    c.cancel(6);
    assert(c.isResponseCancelled(6));
}

unittest  // sampling dispatch forwards a valid request to the delegate
{
    auto c = new MCPClient("http://localhost");
    bool delegateCalled;
    c.onSampling = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    Json b = Json.emptyObject;
    b["type"] = "text";
    b["text"] = "hi";
    Json m = Json.emptyObject;
    m["role"] = "user";
    m["content"] = Json([b]);
    Json params = Json.emptyObject;
    params["messages"] = Json([m]);

    c.dispatchServerMethod("sampling/createMessage", params);
    assert(delegateCalled);
}

unittest  // elicitation/create rejects a mode the client did not advertise (-32602)
{
    auto c = new MCPClient("http://localhost");
    // Advertise form mode only (the default bare elicitation declaration).
    c.capabilities.elicitation = true;
    c.capabilities.elicitationForm = true;

    bool delegateCalled;
    c.onElicitation = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    Json params = Json.emptyObject;
    params["mode"] = "url"; // not advertised
    params["url"] = "https://example.com/elicit";
    params["elicitationId"] = "e1";

    bool threw;
    try
        c.dispatchServerMethod("elicitation/create", params);
    catch (McpException e)
    {
        threw = true;
        assert(e.code == ErrorCode.invalidParams);
    }
    assert(threw);
    assert(!delegateCalled); // validation runs before the delegate
}

unittest  // elicitation/create rejects an unknown mode (-32602)
{
    auto c = new MCPClient("http://localhost");
    c.capabilities.elicitation = true;
    c.capabilities.elicitationForm = true;

    bool delegateCalled;
    c.onElicitation = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    Json params = Json.emptyObject;
    params["mode"] = "telepathy"; // not a known mode

    bool threw;
    try
        c.dispatchServerMethod("elicitation/create", params);
    catch (McpException e)
    {
        threw = true;
        assert(e.code == ErrorCode.invalidParams);
    }
    assert(threw);
    assert(!delegateCalled);
}

unittest  // elicitation/create forwards an advertised mode to the delegate
{
    auto c = new MCPClient("http://localhost");
    c.capabilities.elicitation = true;
    c.capabilities.elicitationForm = true;
    c.capabilities.elicitationUrl = true;

    bool delegateCalled;
    c.onElicitation = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    Json params = Json.emptyObject;
    params["mode"] = "url";
    params["url"] = "https://example.com/elicit";
    params["elicitationId"] = "e1";

    c.dispatchServerMethod("elicitation/create", params);
    assert(delegateCalled);
}

unittest  // elicitation/complete for a known id is forwarded once, then ignored
{
    auto c = new MCPClient("http://localhost");
    c.capabilities.elicitation = true;
    c.capabilities.elicitationForm = true;
    c.capabilities.elicitationUrl = true;
    c.onElicitation = (Json) @safe { return Json.emptyObject; };

    // The server issues a URL-mode request; the client records the id.
    Json create = Json.emptyObject;
    create["mode"] = "url";
    create["url"] = "https://example.com/elicit";
    create["elicitationId"] = "e-known";
    c.dispatchServerMethod("elicitation/create", create);

    string[] seenMethods;
    c.onNotification = (string method, Json) @safe { seenMethods ~= method; };

    Json note = Json.emptyObject;
    note["elicitationId"] = "e-known";
    c.dispatchNotification("notifications/elicitation/complete", note);
    assert(seenMethods.length == 1); // forwarded once

    // A second completion for the same (already-completed) id is ignored.
    c.dispatchNotification("notifications/elicitation/complete", note);
    assert(seenMethods.length == 1);
}

unittest  // elicitation/complete for an unknown id is ignored
{
    auto c = new MCPClient("http://localhost");
    bool forwarded;
    c.onNotification = (string, Json) @safe { forwarded = true; };

    Json note = Json.emptyObject;
    note["elicitationId"] = "never-issued";
    c.dispatchNotification("notifications/elicitation/complete", note);
    assert(!forwarded);
}

unittest  // elicitation/complete without an elicitationId is ignored
{
    auto c = new MCPClient("http://localhost");
    bool forwarded;
    c.onNotification = (string, Json) @safe { forwarded = true; };

    c.dispatchNotification("notifications/elicitation/complete", Json.emptyObject);
    assert(!forwarded);
}

unittest  // other notifications are forwarded unchanged
{
    auto c = new MCPClient("http://localhost");
    string forwarded;
    c.onNotification = (string method, Json) @safe { forwarded = method; };

    c.dispatchNotification("notifications/message", Json.emptyObject);
    assert(forwarded == "notifications/message");
}

unittest  // notifications/progress is delivered to the typed onProgress observer
{
    auto c = new MCPClient("http://localhost");
    ProgressNotification got;
    bool called;
    c.onProgress = (ProgressNotification n) @safe { got = n; called = true; };

    Json p = Json.emptyObject;
    p["progressToken"] = "job-1";
    p["progress"] = 3;
    p["total"] = 4;
    p["message"] = "working";
    c.dispatchNotification("notifications/progress", p);

    assert(called);
    assert(got.progressToken.get!string == "job-1");
    assert(got.progress == 3);
    assert(!got.total.isNull && got.total.get == 4);
    assert(!got.message.isNull && got.message.get == "working");
}

unittest  // a non-progress notification does not invoke onProgress
{
    auto c = new MCPClient("http://localhost");
    bool called;
    c.onProgress = (ProgressNotification) @safe { called = true; };
    c.dispatchNotification("notifications/message", Json.emptyObject);
    assert(!called);
}

unittest  // progress is still forwarded to the generic onNotification observer
{
    auto c = new MCPClient("http://localhost");
    string forwarded;
    c.onNotification = (string method, Json) @safe { forwarded = method; };
    c.dispatchNotification("notifications/progress", Json.emptyObject);
    assert(forwarded == "notifications/progress");
}

unittest  // elicitation/create defaults to form mode when mode is absent
{
    auto c = new MCPClient("http://localhost");
    c.capabilities.elicitation = true;
    c.capabilities.elicitationForm = true;

    bool delegateCalled;
    c.onElicitation = (Json params) @safe {
        delegateCalled = true;
        return Json.emptyObject;
    };

    Json params = Json.emptyObject;
    params["message"] = "Please fill this in";
    params["requestedSchema"] = Json.emptyObject;

    c.dispatchServerMethod("elicitation/create", params);
    assert(delegateCalled);
}

unittest  // buildCompleteParams shapes a prompt completion request
{
    auto p = MCPClient.buildCompleteParams(CompletionReference.forPrompt("greet"),
            "name", "pa", null);
    assert(p["ref"]["type"].get!string == "ref/prompt");
    assert(p["ref"]["name"].get!string == "greet");
    assert(p["argument"]["name"].get!string == "name");
    assert(p["argument"]["value"].get!string == "pa");
    assert("context" !in p);
}

unittest  // buildCompleteParams shapes a resource completion request
{
    auto p = MCPClient.buildCompleteParams(
            CompletionReference.forResource("file:///{path}"), "path", "/ho", null);
    assert(p["ref"]["type"].get!string == "ref/resource");
    assert(p["ref"]["uri"].get!string == "file:///{path}");
    assert(p["argument"]["value"].get!string == "/ho");
}

unittest  // buildCompleteParams includes the resolved-argument context when given
{
    string[string] ctx = ["owner": "octocat"];
    auto p = MCPClient.buildCompleteParams(CompletionReference.forPrompt("pr"), "repo", "m", ctx);
    assert(p["context"]["arguments"]["owner"].get!string == "octocat");
}

unittest  // a string progress token serialises as a string under _meta
{
    auto t = ProgressToken("tok-1");
    assert(t.isSet);
    assert(t.toJson().type == Json.Type.string);
    assert(t.toJson().get!string == "tok-1");
}

unittest  // an integer progress token serialises as an integer
{
    auto t = ProgressToken(42L);
    assert(t.isSet);
    assert(t.toJson().type == Json.Type.int_);
    assert(t.toJson().get!long == 42);
}

unittest  // a default-constructed progress token is unset
{
    ProgressToken t;
    assert(!t.isSet);
    assert(t.toJson().type == Json.Type.undefined);
}

unittest  // withProgressToken merges the token into params._meta
{
    Json p = Json.emptyObject;
    p["name"] = "x";
    auto out_ = withProgressToken(p, ProgressToken("abc"));
    assert(out_["_meta"]["progressToken"].get!string == "abc");
    assert(out_["name"].get!string == "x"); // domain fields preserved
}

unittest  // withProgressToken preserves existing _meta keys
{
    Json meta = Json.emptyObject;
    meta["existing"] = "keep";
    Json p = Json.emptyObject;
    p["_meta"] = meta;
    auto out_ = withProgressToken(p, ProgressToken(7L));
    assert(out_["_meta"]["existing"].get!string == "keep");
    assert(out_["_meta"]["progressToken"].get!long == 7);
}

unittest  // withProgressToken leaves params untouched when the token is unset
{
    Json p = Json.emptyObject;
    p["name"] = "x";
    auto out_ = withProgressToken(p, ProgressToken.init);
    assert("_meta" !in out_);
}

unittest  // buildToolCallParams attaches a progressToken under _meta
{
    auto p = MCPClient.buildToolCallParams("add", Json(["a": Json(1)]), ProgressToken("p1"));
    assert(p["name"].get!string == "add");
    assert(p["_meta"]["progressToken"].get!string == "p1");
}

unittest  // buildToolCallParams omits _meta when no progress token is requested
{
    auto p = MCPClient.buildToolCallParams("add", Json.emptyObject, ProgressToken.init);
    assert("_meta" !in p);
}

unittest  // buildReadResourceParams attaches a progressToken under _meta
{
    auto p = MCPClient.buildReadResourceParams("file:///x", ProgressToken(99L));
    assert(p["uri"].get!string == "file:///x");
    assert(p["_meta"]["progressToken"].get!long == 99);
}

unittest  // buildSubscriptionsListenParams nests the boolean list-changed flags under notifications
{
    SubscriptionFilter f;
    f.toolsListChanged = true;
    f.resourcesListChanged = true;
    auto p = MCPClient.buildSubscriptionsListenParams(f);
    assert(p["notifications"]["toolsListChanged"].get!bool == true);
    assert(p["notifications"]["resourcesListChanged"].get!bool == true);
    // Flags left false are omitted (not sent as false) per the spec filter shape.
    assert("promptsListChanged" !in p["notifications"]);
}

unittest  // buildSubscriptionsListenParams nests resourceSubscriptions URIs as a string array
{
    SubscriptionFilter f;
    f.resourceSubscriptions = ["file:///a", "file:///b"];
    auto p = MCPClient.buildSubscriptionsListenParams(f);
    auto rs = p["notifications"]["resourceSubscriptions"];
    assert(rs.type == Json.Type.array);
    assert(rs.length == 2);
    assert(rs[0].get!string == "file:///a");
    assert(rs[1].get!string == "file:///b");
}

unittest  // buildSubscriptionsListenParams emits an empty notifications filter for an empty subscription
{
    SubscriptionFilter f;
    auto p = MCPClient.buildSubscriptionsListenParams(f);
    assert(p["notifications"].type == Json.Type.object);
    assert(p["notifications"].length == 0);
}

unittest  // a subscriptions/listen stream delivers the acknowledgement + change notifications to onNotification
{
    // Exercise the delivery path the listen stream uses (dispatchInbound):
    // the leading subscriptions/acknowledged event and a subsequent list-changed
    // notification must both reach onNotification.
    auto c = new MCPClient("http://localhost");
    string[] seen;
    c.onNotification = (string method, Json params) @safe { seen ~= method; };

    c.dispatchInbound(Message(parseJsonString(
            `{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"toolsListChanged":true}}`)));
    c.dispatchInbound(Message(parseJsonString(
            `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)));

    assert(seen.length == 2);
    assert(seen[0] == "notifications/subscriptions/acknowledged");
    assert(seen[1] == "notifications/tools/list_changed");
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

unittest  // buildGetPromptParams attaches a progressToken under _meta
{
    auto p = MCPClient.buildGetPromptParams("greet", Json.emptyObject, ProgressToken("g1"));
    assert(p["name"].get!string == "greet");
    assert(p["_meta"]["progressToken"].get!string == "g1");
}

unittest  // paramHeaders mirrors an x-mcp-header-annotated argument into Mcp-Param-{Name}
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["region"] = Json([
        "type": Json("string"),
        "x-mcp-header": Json("Region")
    ]);
    props["query"] = Json(["type": Json("string")]);
    schema["properties"] = props;

    Json args = Json.emptyObject;
    args["region"] = "us-west1";
    args["query"] = "weather";

    auto headers = MCPClient.paramHeaders(schema, args);
    assert("Mcp-Param-Region" in headers);
    assert(headers["Mcp-Param-Region"] == "us-west1");
    // A non-annotated argument never becomes a header.
    assert("Mcp-Param-query" !in headers);
}

unittest  // paramHeaders omits headers for absent or null annotated arguments
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["region"] = Json([
        "type": Json("string"),
        "x-mcp-header": Json("Region")
    ]);
    props["zone"] = Json(["type": Json("string"), "x-mcp-header": Json("Zone")]);
    schema["properties"] = props;

    Json args = Json.emptyObject;
    args["zone"] = null; // explicit null -> no header
    // region absent entirely -> no header

    auto headers = MCPClient.paramHeaders(schema, args);
    assert("Mcp-Param-Region" !in headers);
    assert("Mcp-Param-Zone" !in headers);
}

unittest  // paramHeaders base64-encodes a non-ASCII annotated value
{
    import mcp.protocol.draft : decodeHeaderValue;

    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["label"] = Json([
        "type": Json("string"),
        "x-mcp-header": Json("Label")
    ]);
    schema["properties"] = props;

    Json args = Json.emptyObject;
    args["label"] = "Hello, 世界";

    auto headers = MCPClient.paramHeaders(schema, args);
    assert("Mcp-Param-Label" in headers);
    assert(headers["Mcp-Param-Label"][0 .. 9] == "=?base64?");
    assert(decodeHeaderValue(headers["Mcp-Param-Label"]) == "Hello, 世界");
}

unittest  // paramHeaders stringifies a non-string scalar annotated value
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["limit"] = Json([
        "type": Json("integer"),
        "x-mcp-header": Json("Limit")
    ]);
    schema["properties"] = props;

    Json args = Json.emptyObject;
    args["limit"] = 42;

    auto headers = MCPClient.paramHeaders(schema, args);
    assert(headers["Mcp-Param-Limit"] == "42");
}

unittest  // paramHeaders yields nothing when the schema has no x-mcp-header annotations
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["query"] = Json(["type": Json("string")]);
    schema["properties"] = props;

    Json args = Json.emptyObject;
    args["query"] = "x";

    auto headers = MCPClient.paramHeaders(schema, args);
    assert(headers.length == 0);
}

unittest  // cacheToolSchema records a schema and ignores a non-object one
{
    auto c = new MCPClient("http://localhost/mcp");
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    c.cacheToolSchema("search", schema);
    assert("search" in c.toolInputSchemas_);
    // Non-object schema is ignored.
    c.cacheToolSchema("bad", Json("not-an-object"));
    assert("bad" !in c.toolInputSchemas_);
}

unittest  // MRTR: withInputResponses attaches answers under the reserved _meta key
{
    auto resp = InputResponse("date", Json([
            "content": Json(["day": Json("monday")])
    ]));
    auto params = MCPClient.buildToolCallParams("book", Json.emptyObject,
            ProgressToken.init, [resp]);
    auto arr = params["_meta"][MetaKey.inputResponses];
    assert(arr.type == Json.Type.array);
    assert(arr.length == 1);
    assert(arr[0]["id"].get!string == "date");
    assert(arr[0]["result"]["content"]["day"].get!string == "monday");
}

unittest  // MRTR: withInputResponses with no answers leaves params untouched
{
    auto params = MCPClient.buildToolCallParams("book", Json.emptyObject, ProgressToken.init, [
    ]);
    assert("_meta" !in params);
}

unittest  // MRTR: withInputResponses preserves existing _meta entries
{
    Json p = Json.emptyObject;
    Json meta = Json.emptyObject;
    meta["progressToken"] = "p1";
    p["_meta"] = meta;
    auto resp = InputResponse("q1", Json(["action": Json("accept")]));
    auto out_ = MCPClient.withInputResponses(p, [resp]);
    assert(out_["_meta"]["progressToken"].get!string == "p1");
    assert(out_["_meta"][MetaKey.inputResponses].length == 1);
}

unittest  // MRTR: resolveInputRequest routes an elicitation request to onElicitation
{
    auto c = new MCPClient("http://localhost/mcp");
    Json seen = Json.undefined;
    c.onElicitation = (Json params) @safe {
        seen = params;
        return Json([
            "action": Json("accept"),
            "content": Json(["day": Json("tuesday")])
        ]);
    };
    Json ep = Json.emptyObject;
    ep["message"] = "When?";
    InputResponse answer;
    const ok = c.resolveInputRequest(InputRequest("date", "elicitation", ep), answer);
    assert(ok);
    assert(seen["message"].get!string == "When?");
    assert(answer.id == "date");
    assert(answer.result["content"]["day"].get!string == "tuesday");
}

unittest  // MRTR: resolveInputRequest routes a sampling request to onSampling
{
    auto c = new MCPClient("http://localhost/mcp");
    c.onSampling = (Json params) @safe {
        return Json(["role": Json("assistant")]);
    };
    InputResponse answer;
    const ok = c.resolveInputRequest(InputRequest("s1", "sampling", Json.emptyObject), answer);
    assert(ok);
    assert(answer.id == "s1");
    assert(answer.result["role"].get!string == "assistant");
}

unittest  // MRTR: resolveInputRequest routes a roots request to onListRoots
{
    auto c = new MCPClient("http://localhost/mcp");
    c.onListRoots = (Json params) @safe {
        return Json(["roots": Json.emptyArray]);
    };
    InputResponse answer;
    const ok = c.resolveInputRequest(InputRequest("r1", "roots", Json.emptyObject), answer);
    assert(ok);
    assert(answer.id == "r1");
    assert(answer.result["roots"].type == Json.Type.array);
}

unittest  // MRTR: resolveInputRequest fails (no answer) when no handler is registered
{
    auto c = new MCPClient("http://localhost/mcp");
    InputResponse answer;
    // onElicitation is null by default -> cannot satisfy the request.
    const ok = c.resolveInputRequest(InputRequest("x", "elicitation", Json.emptyObject), answer);
    assert(!ok);
    assert(answer.id.length == 0);
}

unittest  // MRTR: resolveInputRequest fails for an unknown input type
{
    auto c = new MCPClient("http://localhost/mcp");
    c.onElicitation = (Json) @safe { return Json.emptyObject; };
    InputResponse answer;
    const ok = c.resolveInputRequest(InputRequest("x", "bogus", Json.emptyObject), answer);
    assert(!ok);
}
