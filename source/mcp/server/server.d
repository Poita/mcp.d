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

    /// The most recently set log level (default "info").
    string currentLogLevel() const @safe
    {
        return logLevel;
    }

    /// Capabilities this server advertises, derived from what is registered.
    ServerCapabilities capabilities() const @safe
    {
        ServerCapabilities caps;
        if (tools.length > 0)
            caps.tools = ListChangedCapability(false);
        if (resources.length > 0 || templates.length > 0)
            caps.resources = ResourcesCapability(false, false);
        if (prompts.length > 0)
            caps.prompts = ListChangedCapability(false);
        if (completionHandler !is null)
            caps.completions = true;
        if (loggingEnabled)
            caps.logging = true;
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
        case "resources/list":
            return doListResources(params);
        case "resources/templates/list":
            return doListResourceTemplates(params);
        case "resources/read":
            return doReadResource(params);
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

    private Json doListResources(Json /* params */ ) @safe
    {
        import std.algorithm : sort;

        ListResourcesResult result;
        auto uris = resources.keys;
        sort(uris);
        foreach (uri; uris)
            result.resources ~= resources[uri].descriptor;
        return result.toJson();
    }

    private Json doListResourceTemplates(Json /* params */ ) @safe
    {
        ListResourceTemplatesResult result;
        foreach (t; templates)
            result.resourceTemplates ~= t.descriptor;
        return result.toJson();
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
            return result.toJson();
        }

        foreach (t; templates)
        {
            string[string] captured;
            if (matchUriTemplate(t.descriptor.uriTemplate, uri, captured))
            {
                ReadResourceResult result;
                result.contents = [t.reader(uri, captured)];
                return result.toJson();
            }
        }
        throw resourceNotFound(uri);
    }

    private Json doListPrompts(Json /* params */ ) @safe
    {
        import std.algorithm : sort;

        ListPromptsResult result;
        auto names = prompts.keys;
        sort(names);
        foreach (name; names)
            result.prompts ~= prompts[name].descriptor;
        return result.toJson();
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
