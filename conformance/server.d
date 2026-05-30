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
    registerResourceFixtures(server);
    registerPromptFixtures(server);
    server.enableLogging();
    server.setCompletionHandler((Json params) @safe {
        CompleteResult r;
        r.values = ["paris", "park", "party"];
        r.total = 150;
        return r;
    });

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

    // tools-call-image: a minimal 1x1 PNG.
    Tool imageTool = {
        name: "test_image_content", description: nullable("Returns image content")
    };
    server.registerTool(imageTool, (Json args) @safe {
        CallToolResult r;
        r.content = [Content.makeImage(onePixelPng, "image/png")];
        return r;
    });

    // tools-call-audio: a minimal silent WAV.
    Tool audioTool = {
        name: "test_audio_content", description: nullable("Returns audio content")
    };
    server.registerTool(audioTool, (Json args) @safe {
        CallToolResult r;
        r.content = [Content.makeAudio(minimalWav, "audio/wav")];
        return r;
    });

    // tools-call-embedded-resource: an embedded text resource.
    Tool embeddedTool = {
        name: "test_embedded_resource", description: nullable("Returns an embedded resource")
    };
    server.registerTool(embeddedTool, (Json args) @safe {
        CallToolResult r;
        r.content = [
            Content.makeEmbeddedText("test://embedded-resource", "text/plain",
                "This is an embedded resource content.")
        ];
        return r;
    });

    // tools-call-mixed-content: text + image + embedded resource.
    Tool mixedTool = {
        name: "test_multiple_content_types", description: nullable("Returns multiple content types")
    };
    server.registerTool(mixedTool, (Json args) @safe {
        CallToolResult r;
        r.content = [
            Content.makeText("Multiple content types test:"),
            Content.makeImage(onePixelPng, "image/png"),
            Content.makeEmbeddedText("test://mixed-content-resource",
                "application/json", `{"test":"data","value":123}`)
        ];
        return r;
    });
}

/// A base64-encoded 1x1 PNG (used by image/mixed-content fixtures).
private enum onePixelPng = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/// A base64-encoded minimal 44-byte PCM WAV header (no samples), computed once.
private string minimalWav() @safe
{
    import std.base64 : Base64;

    immutable ubyte[] wav = [
        'R', 'I', 'F', 'F', 36, 0, 0, 0, 'W', 'A', 'V', 'E', 'f', 'm', 't',
        ' ', 16, 0, 0, 0, 1, 0, 1, 0, 0x40, 0x1f, 0, 0, 0x40, 0x1f, 0, 0, 1,
        0, 8, 0, 'd', 'a', 't', 'a', 0, 0, 0, 0
    ];
    return Base64.encode(wav);
}

/// Resource + resource-template fixtures matching the conformance harness.
private void registerResourceFixtures(MCPServer server) @safe
{
    Resource staticText = {
        uri: "test://static-text", name: "Static Text", description: nullable(
                "A static text resource"), mimeType: nullable("text/plain")
    };
    server.registerResource(staticText, () @safe => ResourceContents.makeText("test://static-text",
            "text/plain", "This is the content of the static text resource."));

    Resource staticBinary = {
        uri: "test://static-binary", name: "Static Binary", description: nullable(
                "A static binary resource"), mimeType: nullable("image/png")
    };
    server.registerResource(staticBinary, () @safe => ResourceContents.makeBlob(
            "test://static-binary", "image/png", onePixelPng));

    ResourceTemplate tpl = {
        uriTemplate: "test://template/{id}/data", name: "Template Data", description: nullable(
                "Parameterized data resource"), mimeType: nullable("application/json")
    };
    server.registerResourceTemplate(tpl, (string uri, string[string] params) @safe {
        const id = ("id" in params) ? params["id"] : "";
        const 
        body = `{"id":"` ~ id ~ `","templateTest":true,"data":"Data for ID: ` ~ id ~ `"}`;
        return ResourceContents.makeText(uri, "application/json", body);
    });
}

/// Prompt fixtures matching the conformance harness.
private void registerPromptFixtures(MCPServer server) @safe
{
    Prompt simple = {
        name: "test_simple_prompt", description: nullable("A simple test prompt")
    };
    server.registerPrompt(simple, (Json args) @safe {
        GetPromptResult r;
        r.messages = [
            PromptMessage("user", Content.makeText("This is a simple prompt for testing."))
        ];
        return r;
    });

    Prompt withArgs = {
        name: "test_prompt_with_arguments", description: nullable("A prompt that takes arguments")
    };
    withArgs.arguments = [
        PromptArgument("arg1", nullable("First test argument"), true),
        PromptArgument("arg2", nullable("Second test argument"), true)
    ];
    server.registerPrompt(withArgs, (Json args) @safe {
        const a1 = ("arg1" in args) ? args["arg1"].get!string : "";
        const a2 = ("arg2" in args) ? args["arg2"].get!string : "";
        GetPromptResult r;
        r.messages = [
            PromptMessage("user",
                Content.makeText("Prompt with arguments: arg1='" ~ a1 ~ "', arg2='" ~ a2 ~ "'"))
        ];
        return r;
    });

    Prompt withEmbedded = {
        name: "test_prompt_with_embedded_resource", description: nullable(
                "A prompt with an embedded resource")
    };
    withEmbedded.arguments = [
        PromptArgument("resourceUri", nullable("URI of the resource to embed"), true)
    ];
    server.registerPrompt(withEmbedded, (Json args) @safe {
        const uri = ("resourceUri" in args) ? args["resourceUri"].get!string : "";
        GetPromptResult r;
        r.messages = [
            PromptMessage("user", Content.makeEmbeddedText(uri, "text/plain",
                "Embedded resource content for testing.")),
            PromptMessage("user",
                Content.makeText("Please process the embedded resource above."))
        ];
        return r;
    });

    Prompt withImage = {
        name: "test_prompt_with_image", description: nullable("A prompt that includes an image")
    };
    server.registerPrompt(withImage, (Json args) @safe {
        GetPromptResult r;
        r.messages = [
            PromptMessage("user", Content.makeImage(onePixelPng, "image/png")),
            PromptMessage("user", Content.makeText("Please analyze the image above."))
        ];
        return r;
    });
}
