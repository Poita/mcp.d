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
    /// SSE notifications and server->client requests in between.
    private Json postAndAwait(Json message, long expectId) @safe
    {
        Json result = Json.undefined;
        bool got;
        McpException err;

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
        if (!got)
            throw internalError("No response received for request " ~ method2(expectId));
        return result;
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
            // `event:`, `id:`, `retry:` lines are ignored for now.
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

    private void runServerStream() @safe
    {
        () @trusted {
            requestHTTP(url, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.GET;
                req.headers["Accept"] = "text/event-stream";
                if (sessionId.length)
                    req.headers["Mcp-Session-Id"] = sessionId;
                if (didInitialize)
                    req.headers["MCP-Protocol-Version"] = negotiated.toWire;
            }, (scope HTTPClientResponse res) {
                if (res.statusCode != 200)
                {
                    res.dropBody();
                    return;
                }
                string dataBuf;
                for (;;)
                {
                    string line;
                    bool eof;
                    try
                        line = cast(string) readLine(res.bodyReader, size_t.max, "\n").idup;
                    catch (Exception)
                        eof = true;
                    if (eof)
                        break;
                    if (line.length && line[$ - 1] == '\r')
                        line = line[0 .. $ - 1];
                    if (line.length == 0)
                    {
                        if (dataBuf.length)
                        {
                            try
                                dispatchInbound(Message(parseJsonString(dataBuf)));
                            catch (Exception e)
                                dataBuf = null;
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
                }
            });
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
