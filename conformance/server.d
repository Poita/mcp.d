/**
 * Conformance server target.
 *
 * Starts an MCP server over the Streamable HTTP transport so the official
 * `@modelcontextprotocol/conformance` harness can test it:
 *
 *   dub build -c conformance-server
 *   ./conformance-server --port 3000 &
 *   npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3000/mcp
 */
module conformance_server;

import std.getopt : getopt;
import std.stdio : writefln, stderr;
import std.typecons : nullable;

import vibe.data.json : Json;

import mcp;

void main(string[] args)
{
    ushort port = 3000;
    string host = "127.0.0.1";
    getopt(args, "port|p", "Port to listen on (default 3000)", &port,
            "host|h", "Address to bind (default 127.0.0.1)", &host);

    auto server = new MCPServer("dlang-mcp-conformance", "0.1.0",
            nullable("Conformance test server for dlang-mcp-sdk."));

    registerEchoTool(server);
    registerAddTool(server);
    registerConformanceFixtures(server);

    StreamableHttpOptions opts;
    opts.bindAddresses = [host];
    () @trusted {
        stderr.writefln("conformance-server listening on http://%s:%d/mcp", host, port);
    }();
    runStreamableHttp(server, port, opts);
}

/// A tool that echoes its `text` argument back as text content.
private void registerEchoTool(MCPServer server) @safe
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["text"] = Json(["type": Json("string")]);
    schema["properties"] = props;
    schema["required"] = Json([Json("text")]);

    Tool echo = {
        name: "echo", description: nullable("Echo back the provided text"), inputSchema: schema
    };
    server.registerTool(echo, (Json args) @safe {
        const text = ("text" in args) ? args["text"].get!string : "";
        CallToolResult r;
        r.content = [Content.makeText(text)];
        return r;
    });
}

/// A tool that adds two integers and returns the sum as text.
private void registerAddTool(MCPServer server) @safe
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["a"] = Json(["type": Json("integer")]);
    props["b"] = Json(["type": Json("integer")]);
    schema["properties"] = props;
    schema["required"] = Json([Json("a"), Json("b")]);

    Tool add = {
        name: "add", description: nullable("Add two integers"), inputSchema: schema
    };
    server.registerTool(add, (Json args) @safe {
        import std.conv : to;

        const a = args["a"].get!int;
        const b = args["b"].get!int;
        CallToolResult r;
        r.content = [Content.makeText((a + b).to!string)];
        return r;
    });
}

/// Tools whose names and outputs match the conformance harness fixtures.
private void registerConformanceFixtures(MCPServer server) @safe
{
    // tools-call-simple-text: no args -> a fixed text content block.
    Tool simpleText = {
        name: "test_simple_text", description: nullable("Returns a simple text response")
    };
    server.registerTool(simpleText, (Json args) @safe {
        CallToolResult r;
        r.content = [
            Content.makeText("This is a simple text response for testing.")
        ];
        return r;
    });

    // tools-call-error: no args -> isError result with a fixed message.
    Tool errorTool = {
        name: "test_error_handling", description: nullable("Always returns a tool error")
    };
    server.registerTool(errorTool, (Json args) @safe {
        CallToolResult r;
        r.content = [
            Content.makeText("This tool intentionally returns an error for testing")
        ];
        r.isError = true;
        return r;
    });
}
