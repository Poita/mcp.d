module mcp.server.server;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.versions;
import mcp.protocol.errors;
import mcp.protocol.jsonrpc;
import mcp.protocol.capabilities;
import mcp.protocol.types;

@safe:

/// A registered tool: its descriptor plus the handler that executes it.
struct RegisteredTool
{
    Tool descriptor;
    CallToolResult delegate(Json arguments) @safe handler;
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
    private ProtocolVersion negotiated = latestStable;
    private bool initialized;

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

    /// Register a tool with its execution handler.
    void registerTool(Tool descriptor, CallToolResult delegate(Json) @safe handler) @safe
    {
        tools[descriptor.name] = RegisteredTool(descriptor, handler);
    }

    /// Capabilities this server advertises, derived from what is registered.
    ServerCapabilities capabilities() const @safe
    {
        ServerCapabilities caps;
        if (tools.length > 0)
            caps.tools = ListChangedCapability(false);
        return caps;
    }

    /// Dispatch a single parsed message. Returns the JSON-RPC response for
    /// requests, or `Nullable.init` for notifications (which get no reply).
    Nullable!Json handle(Message msg) @safe
    {
        final switch (msg.kind)
        {
        case MessageKind.request:
            return nullable(handleRequest(msg));
        case MessageKind.notification:
            handleNotification(msg);
            return Nullable!Json.init;
        case MessageKind.response:
        case MessageKind.errorResponse:
            // A server core does not expect inbound responses on this path.
            return Nullable!Json.init;
        }
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

    private Json handleRequest(Message msg) @safe
    {
        try
        {
            auto result = route(msg.method, msg.params);
            return makeResponse(msg.id, result);
        }
        catch (McpException e)
            return makeErrorResponse(msg.id, e);
        catch (Exception e)
            return makeErrorResponse(msg.id, internalError(e.msg));
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

    private Json route(string method, Json params) @safe
    {
        switch (method)
        {
        case "initialize":
            return doInitialize(params);
        case "ping":
            return Json.emptyObject;
        case "tools/list":
            return doListTools(params);
        case "tools/call":
            return doCallTool(params);
        default:
            throw methodNotFound(method);
        }
    }

    private Json doInitialize(Json params) @safe
    {
        auto p = InitializeParams.fromJson(params);
        negotiated = negotiate(p.protocolVersion);

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
        return result.toJson();
    }

    private Json doCallTool(Json params) @safe
    {
        if ("name" !in params || params["name"].type != Json.Type.string)
            throw invalidParams("tools/call requires a string 'name'");
        const name = params["name"].get!string;
        auto entry = name in tools;
        if (entry is null)
            throw invalidParams("Unknown tool: " ~ name);

        Json args = ("arguments" in params) ? params["arguments"] : Json.emptyObject;
        try
            return entry.handler(args).toJson();
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

    private string[] sortedToolNames() const @safe
    {
        import std.algorithm : sort;
        import std.array : array;

        auto names = tools.keys;
        sort(names);
        return names;
    }
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
