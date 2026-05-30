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
        ProtocolVersion v;
        if (tryParseVersion(init.protocolVersion, v))
            negotiated = v;
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
        return postAndAwait(makeRequest(Json(id), method, params), id);
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
    private void post(Json message) @safe
    {
        () @trusted {
            requestHTTP(url, (scope HTTPClientRequest req) {
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
