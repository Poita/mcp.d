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
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

void main(string[] args)
{
	ushort port = 3000;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 3000)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

	// #550 Stage 3: the conformance harness is a correlated multi-call client that
	// exercises subscribe + elicitation + sampling and echoes Mcp-Session-Id, so
	// the conformance server runs in STATEFUL mode (those features require it).
	auto server = McpServer.stateful("dlang-mcp-conformance", "0.1.0",
			nullable("Conformance test server for dlang-mcp-sdk."));

	registerEchoTool(server);
	registerAddTool(server);
	registerConformanceFixtures(server);
	registerResourceFixtures(server);
	registerPromptFixtures(server);
	registerStreamingFixtures(server);
	registerElicitationSepFixtures(server);
	server.enableLogging();
	server.enableResourceSubscriptions();
	server.setCompletionRequestHandler((CompleteRequest request) @safe {
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
private void registerEchoTool(McpServer server) @safe
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
	server.registerDynamicTool(echo, (Json args) @safe {
		const text = ("text" in args) ? args["text"].get!string : "";
		CallToolResult r;
		r.content = [Content.makeText(text)];
		return r;
	});
}

/// A tool that adds two integers and returns the sum as text.
private void registerAddTool(McpServer server) @safe
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
	server.registerDynamicTool(add, (Json args) @safe {
		import std.conv : to;

		const a = args["a"].get!int;
		const b = args["b"].get!int;
		CallToolResult r;
		r.content = [Content.makeText((a + b).to!string)];
		return r;
	});
}

/// Tools whose names and outputs match the conformance harness fixtures.
private void registerConformanceFixtures(McpServer server) @safe
{
	// tools-call-simple-text: no args -> a fixed text content block.
	Tool simpleText = {
		name: "test_simple_text", description: nullable("Returns a simple text response")
	};
	server.registerDynamicTool(simpleText, (Json args) @safe {
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
	server.registerDynamicTool(errorTool, (Json args) @safe {
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
	server.registerDynamicTool(imageTool, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeImage(onePixelPng, "image/png")];
		return r;
	});

	// tools-call-audio: a minimal silent WAV.
	Tool audioTool = {
		name: "test_audio_content", description: nullable("Returns audio content")
	};
	server.registerDynamicTool(audioTool, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeAudio(minimalWav, "audio/wav")];
		return r;
	});

	// tools-call-embedded-resource: an embedded text resource.
	Tool embeddedTool = {
		name: "test_embedded_resource", description: nullable("Returns an embedded resource")
	};
	server.registerDynamicTool(embeddedTool, (Json args) @safe {
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
	server.registerDynamicTool(mixedTool, (Json args) @safe {
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
private void registerResourceFixtures(McpServer server) @safe
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
private void registerPromptFixtures(McpServer server) @safe
{
	Prompt simple = {
		name: "test_simple_prompt", description: nullable("A simple test prompt")
	};
	server.registerDynamicPrompt(simple, (Json args) @safe {
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
	server.registerDynamicPrompt(withArgs, (Json args) @safe {
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
	server.registerDynamicPrompt(withEmbedded, (Json args) @safe {
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
	server.registerDynamicPrompt(withImage, (Json args) @safe {
		GetPromptResult r;
		r.messages = [
			PromptMessage("user", Content.makeImage(onePixelPng, "image/png")),
			PromptMessage("user", Content.makeText("Please analyze the image above."))
		];
		return r;
	});
}

/// Streaming fixtures: progress, logging, sampling, elicitation.
private void registerStreamingFixtures(McpServer server) @safe
{
	import core.time : msecs;
	import vibe.core.core : sleep;
	import std.typecons : nullable, Nullable;

	// tools-call-with-progress: emit 0/50/100 progress (when a token is present).
	Tool progressTool = {
		name: "test_tool_with_progress", description: nullable("Reports progress")
	};
	server.registerDynamicTool(progressTool, (Json args, RequestContext ctx) @safe {
		ctx.reportProgress(0, nullable(100.0));
		sleep(50.msecs);
		ctx.reportProgress(50, nullable(100.0));
		sleep(50.msecs);
		ctx.reportProgress(100, nullable(100.0));
		CallToolResult r;
		r.content = [Content.makeText("Progress complete")];
		return r;
	});

	// tools-call-with-logging: 3 info logs during execution.
	Tool loggingTool = {
		name: "test_tool_with_logging", description: nullable("Logs during execution")
	};
	server.registerDynamicTool(loggingTool, (Json args, RequestContext ctx) @safe {
		ctx.log("info", Json("Tool execution started"));
		sleep(50.msecs);
		ctx.log("info", Json("Tool processing data"));
		sleep(50.msecs);
		ctx.log("info", Json("Tool execution completed"));
		CallToolResult r;
		r.content = [Content.makeText("Logging complete")];
		return r;
	});

	// tools-call-sampling: ask the client to sample an LLM completion.
	Tool samplingTool = {
		name: "test_sampling", description: nullable("Requests LLM sampling")
	};
	server.registerDynamicTool(samplingTool, (Json args, RequestContext ctx) @safe {
		const prompt = ("prompt" in args) ? args["prompt"].get!string : "";
		Json msg = Json.emptyObject;
		msg["role"] = "user";
		msg["content"] = Json(["type": Json("text"), "text": Json(prompt)]);
		Json params = Json.emptyObject;
		params["messages"] = Json([msg]);
		params["maxTokens"] = 100;
		auto result = ctx.sample(params);
		string text;
		if ("content" in result && "text" in result["content"])
			text = result["content"]["text"].get!string;
		CallToolResult r;
		r.content = [Content.makeText("LLM response: " ~ text)];
		return r;
	});

	// tools-call-elicitation: ask the client to elicit user input.
	Tool elicitTool = {
		name: "test_elicitation", description: nullable("Requests user input")
	};
	server.registerDynamicTool(elicitTool, (Json args, RequestContext ctx) @safe {
		const message = ("message" in args) ? args["message"].get!string : "";
		Json schema = Json.emptyObject;
		schema["type"] = "object";
		Json props = Json.emptyObject;
		props["username"] = Json([
			"type": Json("string"),
			"description": Json("User's response")
		]);
		props["email"] = Json([
			"type": Json("string"),
			"description": Json("User's email address")
		]);
		schema["properties"] = props;
		schema["required"] = Json([Json("username"), Json("email")]);

		auto result = ctx.elicit(message, schema).toJson();
		const action = ("action" in result) ? result["action"].get!string : "";
		const content = ("content" in result) ? result["content"] : Json.emptyObject;
		CallToolResult r;
		r.content = [
			Content.makeText("User response: action: " ~ action ~ ", content: " ~ content.toString())
		];
		return r;
	});
}

/// SEP-1034 (defaults) and SEP-1330 (enum variants) elicitation fixtures.
private void registerElicitationSepFixtures(McpServer server) @safe
{
	import std.typecons : nullable;

	Tool defaults = {
		name: "test_elicitation_sep1034_defaults", description: nullable(
				"Elicitation with default values for all primitive types")
	};
	server.registerDynamicTool(defaults, (Json args, RequestContext ctx) @safe {
		Json props = Json.emptyObject;
		props["name"] = Json([
			"type": Json("string"),
			"default": Json("John Doe")
		]);
		props["age"] = Json(["type": Json("integer"), "default": Json(30)]);
		props["score"] = Json(["type": Json("number"), "default": Json(95.5)]);
		Json status = Json.emptyObject;
		status["type"] = "string";
		status["enum"] = Json([
			Json("active"), Json("inactive"), Json("pending")
		]);
		status["default"] = "active";
		props["status"] = status;
		props["verified"] = Json([
			"type": Json("boolean"),
			"default": Json(true)
		]);

		Json schema = Json.emptyObject;
		schema["type"] = "object";
		schema["properties"] = props;

		auto result = ctx.elicit("Please provide your details", schema).toJson();
		return elicitationResultText(result);
	});

	Tool enums = {
		name: "test_elicitation_sep1330_enums", description: nullable(
				"Elicitation with all enum schema variants")
	};
	server.registerDynamicTool(enums, (Json args, RequestContext ctx) @safe {
		Json props = Json.emptyObject;

		// 1. Untitled single-select.
		props["untitledSingle"] = Json([
			"type": Json("string"),
			"enum": Json([Json("option1"), Json("option2"), Json("option3")])
		]);

		// 2. Titled single-select (oneOf with const+title).
		Json titledSingle = Json.emptyObject;
		titledSingle["type"] = "string";
		titledSingle["oneOf"] = Json([
			Json(["const": Json("value1"), "title": Json("First Option")]),
			Json(["const": Json("value2"), "title": Json("Second Option")]),
			Json(["const": Json("value3"), "title": Json("Third Option")])
		]);
		props["titledSingle"] = titledSingle;

		// 3. Single-select with enumNames.
		Json named = Json.emptyObject;
		named["type"] = "string";
		named["enum"] = Json([Json("a"), Json("b"), Json("c")]);
		named["enumNames"] = Json([Json("Alpha"), Json("Beta"), Json("Gamma")]);
		props["legacyEnum"] = named;

		// 4. Untitled multi-select.
		Json multi = Json.emptyObject;
		multi["type"] = "array";
		multi["items"] = Json([
			"type": Json("string"),
			"enum": Json([Json("option1"), Json("option2"), Json("option3")])
		]);
		props["untitledMulti"] = multi;

		// 5. Titled multi-select (items.anyOf with const+title).
		Json titledMulti = Json.emptyObject;
		titledMulti["type"] = "array";
		Json items = Json.emptyObject;
		items["anyOf"] = Json([
			Json(["const": Json("value1"), "title": Json("First Choice")]),
			Json(["const": Json("value2"), "title": Json("Second Choice")]),
			Json(["const": Json("value3"), "title": Json("Third Choice")])
		]);
		titledMulti["items"] = items;
		props["titledMulti"] = titledMulti;

		Json schema = Json.emptyObject;
		schema["type"] = "object";
		schema["properties"] = props;

		auto result = ctx.elicit("Please make your selections", schema).toJson();
		return elicitationResultText(result);
	});
}

/// Format an elicitation result as the text the SEP scenarios expect.
private CallToolResult elicitationResultText(Json result) @safe
{
	const action = ("action" in result) ? result["action"].get!string : "";
	const content = ("content" in result) ? result["content"] : Json.emptyObject;
	CallToolResult r;
	r.content = [
		Content.makeText(
				"Elicitation completed: action=" ~ action ~ ", content=" ~ content.toString())
	];
	return r;
}
