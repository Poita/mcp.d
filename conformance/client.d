/**
 * Conformance client target.
 *
 * The `@modelcontextprotocol/conformance` client harness launches this binary
 * with the test server URL appended to the command and the scenario in the
 * `MCP_CONFORMANCE_SCENARIO` environment variable. It connects, initializes,
 * and performs the scenario-appropriate operations.
 */
module conformance_client;

import std.algorithm : canFind, startsWith;
import std.process : environment;
import std.stdio : stderr;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;

int main(string[] args)
{
    string url;
    foreach (a; args[1 .. $])
        if (a.startsWith("http://") || a.startsWith("https://"))
            url = a;
    if (url.length == 0 && args.length > 1)
        url = args[$ - 1];

    const scenario = environment.get("MCP_CONFORMANCE_SCENARIO", "");

    int rc;
    runTask(() nothrow{
        scope (exit)
            exitEventLoop();
        try
            rc = runScenario(url, scenario);
        catch (Exception e)
        {
            try
                stderr.writeln("conformance-client error: ", e.msg);
            catch (Exception)
            {
            }
            rc = 1;
        }
    });
    runEventLoop();
    return rc;
}

private bool draftRequested() @trusted
{
    import std.process : environment;

    return environment.get("MCP_DRAFT", "").length > 0;
}

private int runScenario(string url, string scenario) @safe
{
    auto client = new MCPClient(url);
    client.capabilities.sampling = true;
    client.capabilities.elicitation = true;
    client.capabilities.roots = true;

    // Draft mode (stateless): MCP_DRAFT=1 exercises server/discover + per-request
    // _meta + standard headers against a draft-capable server.
    if (draftRequested())
    {
        client.enableDraft();
        auto d = client.discover();
        () @trusted {
            import std.stdio : stderr;

            stderr.writefln("draft discover: versions=%s server=%s",
                    d.protocolVersions, d.serverInfo.name);
        }();
        auto tools = client.listTools();
        // Exercise a plain request/response tool (the streaming/sampling tools use
        // the older server-initiated mechanism, not draft MRTR).
        foreach (t; tools)
            if (t.name == "test_simple_text")
                client.callTool(t.name, Json.emptyObject);
        () @trusted { import std.stdio : stderr;

        stderr.writeln("draft flow OK"); }();
        return 0;
    }

    client.onSampling = (Json params) @safe => handleSampling(params);
    client.onElicitation = (Json params) @safe => handleElicitation(params);
    client.onListRoots = (Json params) @safe {
        Json roots = Json.emptyArray;
        roots ~= Json([
            "uri": Json("file:///workspace"),
            "name": Json("Workspace")
        ]);
        return Json(["roots": roots]);
    };

    client.initialize();

    // The `initialize` scenario only exercises the handshake. Every other
    // scenario drives behavior by having the client call a tool (which the test
    // server uses to trigger elicitation/sampling/progress, delivered either on
    // the POST response stream or on the standalone GET stream we open here).
    if (scenario != "initialize")
    {
        import core.time : msecs;
        import vibe.core.core : sleep;

        client.startServerStream();
        sleep(150.msecs); // let the GET stream connect before driving tools
        auto tools = client.listTools();
        foreach (t; tools)
            client.callTool(t.name, defaultArgs(t));
    }
    return 0;
}

/// Build minimal arguments for a tool from its input schema (empty unless the
/// schema declares required string properties, which get placeholder values).
private Json defaultArgs(Tool tool) @safe
{
    Json args = Json.emptyObject;
    if (tool.inputSchema.type == Json.Type.object && "properties" in tool.inputSchema)
    {
        auto props = tool.inputSchema["properties"];
        string[] required;
        if ("required" in tool.inputSchema && tool.inputSchema["required"].type == Json.Type.array)
        {
            auto req = tool.inputSchema["required"];
            foreach (i; 0 .. req.length)
                required ~= req[i].get!string;
        }
        foreach (name; required)
            args[name] = "test";
    }
    return args;
}

/// Answer a `sampling/createMessage` request with a canned assistant reply.
private Json handleSampling(Json params) @safe
{
    Json result = Json.emptyObject;
    result["role"] = "assistant";
    result["content"] = Json([
        "type": Json("text"),
        "text": Json("Sampled response")
    ]);
    result["model"] = "dlang-mcp-test-model";
    result["stopReason"] = "endTurn";
    return result;
}

/// Answer an `elicitation/create` request: accept, applying schema defaults.
private Json handleElicitation(Json params) @safe
{
    Json content = Json.emptyObject;
    if ("requestedSchema" in params)
    {
        auto schema = params["requestedSchema"];
        if (schema.type == Json.Type.object && "properties" in schema)
        {
            auto props = schema["properties"];
            () @trusted {
                foreach (string key, Json prop; props)
                    if ("default" in prop)
                        content[key] = prop["default"];
            }();
        }
    }
    Json result = Json.emptyObject;
    result["action"] = "accept";
    result["content"] = content;
    return result;
}
