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

    /// Capabilities this client advertises at initialize.
    ClientCapabilities capabilities;
    /// This client's identity.
    Implementation clientInfo;

    /// Handler for `sampling/createMessage`; returns the result. Null => unsupported.
    Json delegate(Json params) @safe onSampling;
    /// Handler for `elicitation/create`; returns `{action, content?}`. Null => unsupported.
    Json delegate(Json params) @safe onElicitation;
    /// Handler for `roots/list`; returns `{roots: [...]}`. Null => unsupported.
    Json delegate(Json params) @safe onListRoots;
    /// Observer for inbound notifications (progress, message, resource updates).
    void delegate(string method, Json params) @safe onNotification;

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
        return all;
    }

    /// `tools/call`.
    CallToolResult callTool(string name, Json arguments = Json.emptyObject) @safe
    {
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return CallToolResult.fromJson(rpc("tools/call", p));
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
        Json p = Json.emptyObject;
        p["uri"] = uri;
        return ReadResourceResult.fromJson(rpc("resources/read", p));
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
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return GetPromptResult.fromJson(rpc("prompts/get", p));
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

    /// Send a notification (no reply expected).
    private void notify(string method, Json params) @safe
    {
        post(makeNotification(method, params));
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
            if (onNotification !is null)
                onNotification(msg.method, msg.params);
            break;
        }
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
            if (onNotification !is null)
                onNotification(msg.method, msg.params);
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
            return onSampling(params);
        case "elicitation/create":
            if (onElicitation is null)
                throw methodNotFound(method);
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
