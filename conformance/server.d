/**
 * Conformance server target.
 *
 * Starts an MCP server over the Streamable HTTP transport so the official
 * `@modelcontextprotocol/conformance` harness can test it:
 *
 *   dub build -c conformance-server
 *   ./conformance-server --port 3000 &              # stateful: 2025-11-25 lane
 *   ./conformance-server --port 3001 --stateless &  # modern:   2026-07-28 lane
 *   npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3000/mcp --requirements 2025-11-25
 *   npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3001/mcp --requirements 2026-07-28
 */
module conformance_server;

import std.getopt : getopt;
import std.stdio : writefln, stderr;
import std.typecons : nullable;

import vibe.data.json : Json;

import mcp;
import mcp.protocol.errors : invalidParams, internalError, McpException, ErrorCode;
import mcp.protocol.mrtr : InputRequest;
import mcp.protocol.tasks : TaskSupport;
import mcp.server.task_context : TaskContext;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

void main(string[] args)
{
	ushort port = 3000;
	string host = "127.0.0.1";
	bool stateless;
	getopt(args, "port|p", "Port to listen on (default 3000)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host, "stateless",
			"Serve the modern (2026-07-28) stateless lifecycle instead of the "
			~ "stateful initialize handshake the dated revisions use", &stateless);

	// Two lanes, matching the harness's per-revision requirement sets. The dated
	// revisions through 2025-11-25 are a correlated multi-call client that
	// exercises subscribe + blocking elicitation + sampling and echoes
	// Mcp-Session-Id, so that lane runs STATEFUL. 2026-07-28 has no initialize
	// handshake: per-request _meta, server/discover, MRTR input, so that lane runs
	// the (default) stateless server.
	auto server = stateless ? new McpServer("dlang-mcp-conformance", "0.1.0",
			nullable("Conformance test server for dlang-mcp-sdk.")) : McpServer.stateful(
			"dlang-mcp-conformance",
			"0.1.0", nullable("Conformance test server for dlang-mcp-sdk."));

	registerEchoTool(server);
	registerAddTool(server);
	registerConformanceFixtures(server);
	registerResourceFixtures(server);
	registerPromptFixtures(server);
	registerStreamingFixtures(server);
	registerElicitationSepFixtures(server);
	registerModernFixtures(server);
	registerMrtrFixtures(server);
	registerSkillFixtures(server);
	server.enableLogging();
	// Resource subscriptions correlate HTTP calls and exist only on the stateful
	// lane; the modern lane advertises the list-changed capabilities its
	// subscriptions/listen checks exercise instead.
	if (stateless)
	{
		server.enableToolsListChanged();
		server.enablePromptsListChanged();
		// The Tasks extension is modern-only; its fixtures run on an in-process
		// fiber dispatcher so cancellation can be observed mid-run.
		server.enableTasks();
		registerTaskFixtures(server);
	}
	else
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
	server.registerTool(echo, (Json args) @safe {
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
	server.registerTool(add, (Json args) @safe {
		import std.conv : to;

		// Tolerate absent operands: the http-header-validation scenario calls the
		// alphabetically first tool with no arguments and expects a result.
		const a = ("a" in args && args["a"].type == Json.Type.int_) ? args["a"].get!int : 0;
		const b = ("b" in args && args["b"].type == Json.Type.int_) ? args["b"].get!int : 0;
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

/// Streaming fixtures: progress, logging, sampling, elicitation.
private void registerStreamingFixtures(McpServer server) @safe
{
	import core.time : Duration, msecs;
	import vibe.core.core : sleep;
	import std.typecons : nullable, Nullable;

	// tools-call-with-progress: emit 0/50/100 progress (when a token is present).
	Tool progressTool = {
		name: "test_tool_with_progress", description: nullable("Reports progress")
	};
	server.registerTool(progressTool, (Json args, RequestContext ctx) @safe {
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
	server.registerTool(loggingTool, (Json args, RequestContext ctx) @safe {
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
	server.registerTool(samplingTool, (Json args, RequestContext ctx) @safe {
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
	server.registerTool(elicitTool, (Json args, RequestContext ctx) @safe {
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
	server.registerTool(defaults, (Json args, RequestContext ctx) @safe {
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
	server.registerTool(enums, (Json args, RequestContext ctx) @safe {
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

// ===========================================================================
// 2026-07-28 (modern) fixtures: server-stateless, http header validation,
// JSON Schema 2020-12 preservation.
// ===========================================================================

private CallToolResult textResult(string text) @safe
{
	CallToolResult r;
	r.content = [Content.makeText(text)];
	return r;
}

/// Tools the `server-stateless`, `http-header-validation`,
/// `http-custom-header-server-validation`, and `json-schema-2020-12` scenarios
/// name.
private void registerModernFixtures(McpServer server) @safe
{
	import vibe.data.json : parseJsonString;

	// server-stateless: a tool that requires the `sampling` client capability, so a
	// call whose _meta declares none is -32021 with data.requiredCapabilities.
	Tool missingCap = {
		name: "test_missing_capability", description: nullable(
				"Requires the sampling client capability")
	};
	server.registerTool(missingCap, (Json args) @safe => textResult("capability present"));
	ClientCapabilities needsSampling;
	needsSampling.sampling = true;
	server.setToolRequiredClientCapabilities("test_missing_capability", needsSampling);

	// server-stateless: an elicitation that MUST travel as an InputRequiredResult
	// (MRTR), never as a server->client request on the response stream.
	Tool streamingElicit = {
		name: "test_streaming_elicitation", description: nullable("Asks for confirmation via MRTR")
	};
	server.registerTool(streamingElicit, (Json args, RequestContext ctx) @safe {
		if ("answer" in ctx.inputResponses())
			return ToolResponse.complete(textResult("confirmed"));
		return ToolResponse.inputRequired([
			InputRequest.elicitation("answer", "Please confirm")
		]);
	});

	// server-stateless: logs during execution; on a modern request that set no
	// _meta logLevel the server MUST NOT emit notifications/message.
	Tool loggingTool = {
		name: "test_logging_tool", description: nullable("Logs while it runs")
	};
	server.registerTool(loggingTool, (Json args, RequestContext ctx) @safe {
		ctx.log("info", Json("test_logging_tool ran"));
		return textResult("logged");
	});

	// server-stateless: mutate the tool / prompt lists so a subscriptions/listen
	// stream opted into the matching list-changed type receives the notification.
	Tool triggerTool = {
		name: "test_trigger_tool_change", description: nullable("Adds or removes test_dynamic_tool")
	};
	server.registerTool(triggerTool, (Json args) @safe {
		if (!server.removeTool("test_dynamic_tool"))
		{
			Tool dynamic = {
				name: "test_dynamic_tool", description: nullable("Appears and disappears")
			};
			server.registerTool(dynamic, (Json) @safe => textResult("dynamic"));
		}
		server.notifyToolsListChanged();
		return textResult("tool list changed");
	});
	Tool triggerPrompt = {
		name: "test_trigger_prompt_change", description: nullable(
				"Adds or removes test_dynamic_prompt")
	};
	server.registerTool(triggerPrompt, (Json args) @safe {
		if (!server.removePrompt("test_dynamic_prompt"))
		{
			Prompt dynamic = {
				name: "test_dynamic_prompt", description: nullable("Appears and disappears")
			};
			server.registerPrompt(dynamic, (Json) @safe {
				GetPromptResult r;
				r.messages = [
					PromptMessage("user", Content.makeText("dynamic"))
				];
				return r;
			});
		}
		server.notifyPromptsListChanged();
		return textResult("prompt list changed");
	});

	// http-custom-header-server-validation: the only tool with an x-mcp-header
	// annotation, on a string property.
	Tool customHeader = {
		name: "test_custom_header_tool", description: nullable("Mirrors its tenant argument into Mcp-Param-Tenant"),
		inputSchema: parseJsonString(`{"type":"object","properties":{`
					~ `"tenant":{"type":"string","x-mcp-header":"Tenant"}}}`)
	};
	server.registerTool(customHeader, (Json args) @safe {
		const tenant = ("tenant" in args && args["tenant"].type == Json.Type.string) ? args["tenant"]
			.get!string : "";
		return textResult("tenant: " ~ tenant);
	});

	// json-schema-2020-12: the inputSchema must reach tools/list verbatim, every
	// 2020-12 keyword intact. The tool is listed, never called.
	Tool schemaTool = {
		name: "json_schema_2020_12_tool", description: nullable(
				"Tool with JSON Schema 2020-12 features"), inputSchema: parseJsonString(`{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"$defs": {"address": {"$anchor": "addressDef", "type": "object",
				"properties": {"street": {"type": "string"}, "city": {"type": "string"}}}},
			"properties": {
				"name": {"type": "string"},
				"address": {"$ref": "#/$defs/address"},
				"contactMethod": {"type": "string", "enum": ["phone", "email"]},
				"phone": {"type": "string"},
				"email": {"type": "string"}
			},
			"allOf": [{"anyOf": [{"required": ["phone"]}, {"required": ["email"]}]}],
			"if": {"properties": {"contactMethod": {"const": "phone"}}, "required": ["contactMethod"]},
			"then": {"required": ["phone"]},
			"else": {"required": ["email"]},
			"additionalProperties": false
		}`)
	};
	server.registerTool(schemaTool, (Json args) @safe => textResult("schema ok"));
}

// ===========================================================================
// SEP-2322 (MRTR) fixtures: the input-required-result-* scenarios.
// ===========================================================================

/// Sign a request-state payload so a tampered echo is detected: the wire value
/// is `base64(payload) "." hmac-sha256-hex`. The harness appends a suffix to the
/// echoed state and expects the retry to be rejected.
private string signState(string payload) @safe
{
	import std.base64 : Base64;
	import std.digest.hmac : hmac;
	import std.digest.sha : SHA256;
	import std.digest : toHexString, LetterCase;
	import std.string : representation;

	auto mac = hmac!SHA256("conformance-fixture-secret".representation);
	mac.put(payload.representation);
	return Base64.encode(payload.representation)
		.idup ~ "." ~ toHexString!(LetterCase.lower)(mac.finish()).idup;
}

/// The payload of a state produced by `signState`, or throw -32602 when the
/// value is absent, malformed, or fails its signature.
private string verifyState(string state) @safe
{
	import std.base64 : Base64;
	import std.string : lastIndexOf;

	const dot = state.lastIndexOf('.');
	if (dot <= 0)
		throw invalidParams("requestState is malformed");
	string payload;
	try
		payload = () @trusted { return cast(string) Base64.decode(state[0 .. dot]); }();
	catch (Exception)
		throw invalidParams("requestState is malformed");
	if (signState(payload) != state)
		throw invalidParams("requestState failed integrity verification");
	return payload;
}

private Json elicitSchema(string field, string type) @safe
{
	Json props = Json.emptyObject;
	props[field] = Json(["type": Json(type)]);
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	schema["properties"] = props;
	schema["required"] = Json([Json(field)]);
	return schema;
}

private InputRequest samplingRequest(string id, string prompt, int maxTokens) @safe
{
	Json msg = Json.emptyObject;
	msg["role"] = "user";
	msg["content"] = Json(["type": Json("text"), "text": Json(prompt)]);
	Json params = Json.emptyObject;
	params["messages"] = Json([msg]);
	params["maxTokens"] = maxTokens;
	return InputRequest(id, "sampling", params);
}

/// The `content.<field>` string of an accepted elicitation answer, or throw
/// -32602 when the answer is not a well-formed ElicitResult (validate-input).
private string acceptedText(Json answer, string field) @safe
{
	if (answer.type != Json.Type.object || "action" !in answer
			|| answer["action"].type != Json.Type.string)
		throw invalidParams("inputResponses entry is not an ElicitResult");
	if ("content" in answer && answer["content"].type == Json.Type.object
			&& field in answer["content"] && answer["content"][field].type == Json.Type.string)
		return answer["content"][field].get!string;
	return "";
}

private void registerMrtrFixtures(McpServer server) @safe
{
	Tool elicit = {
		name: "test_input_required_result_elicitation", description: nullable(
				"Asks for the user's name via MRTR")
	};
	server.registerTool(elicit, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("user_name" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.elicitation("user_name", "What is your name?",
				elicitSchema("name", "string"))
		]);
		return ToolResponse.complete(textResult("Hello, " ~ acceptedText(answers["user_name"],
			"name") ~ "!"));
	});

	Tool sampling = {
		name: "test_input_required_result_sampling", description: nullable(
				"Asks the client's model a question via MRTR")
	};
	server.registerTool(sampling, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("capital_question" !in answers)
			return ToolResponse.inputRequired([
			samplingRequest("capital_question", "What is the capital of France?", 100)
		]);
		auto a = answers["capital_question"];
		const text = (a.type == Json.Type.object && "content" in a
			&& a["content"].type == Json.Type.object && "text" in a["content"]) ? a["content"]["text"]
			.get!string : "";
		return ToolResponse.complete(textResult("Model said: " ~ text));
	});

	Tool roots = {
		name: "test_input_required_result_list_roots", description: nullable(
				"Asks for the client's roots via MRTR")
	};
	server.registerTool(roots, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("client_roots" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.roots("client_roots")
		]);
		auto a = answers["client_roots"];
		const n = (a.type == Json.Type.object && "roots" in a && a["roots"].type == Json.Type.array) ? a["roots"]
			.length : 0;
		import std.conv : to;

		return ToolResponse.complete(textResult("roots: " ~ n.to!string));
	});

	Tool state = {
		name: "test_input_required_result_request_state", description: nullable(
				"Round-trips a signed requestState")
	};
	server.registerTool(state, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("confirm" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.elicitation("confirm", "Please confirm", elicitSchema("ok", "boolean"))
		], signState("request-state"));
		verifyState(ctx.requestState());
		return ToolResponse.complete(textResult("state-ok"));
	});

	Tool multiple = {
		name: "test_input_required_result_multiple_inputs", description: nullable(
				"Asks for three inputs at once via MRTR")
	};
	server.registerTool(multiple, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("user_name" !in answers || "greeting" !in answers || "client_roots" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.elicitation("user_name", "What is your name?",
				elicitSchema("name", "string")),
			samplingRequest("greeting", "Generate a greeting", 50),
			InputRequest.roots("client_roots")
		], signState("multiple"));
		verifyState(ctx.requestState());
		return ToolResponse.complete(textResult("all inputs received"));
	});

	Tool multiRound = {
		name: "test_input_required_result_multi_round", description: nullable(
				"Two sequential MRTR rounds with distinct requestState")
	};
	server.registerTool(multiRound, (Json args, RequestContext ctx) @safe {
		import std.algorithm : startsWith;

		// Each retry carries only the answers to the previous round's requests, so
		// the round is tracked in the signed requestState: round 1 asks step1 and
		// stores the name in the state for round 2, which asks step2.
		auto answers = ctx.inputResponses();
		const state = ctx.requestState();
		if (state.length == 0)
		{
			if ("step1" in answers)
				throw invalidParams("a step1 answer requires the round-1 requestState");
			return ToolResponse.inputRequired([
				InputRequest.elicitation("step1", "Step 1: What is your name?",
					elicitSchema("name", "string"))
			], signState("round-1"));
		}
		const payload = verifyState(state);
		if (payload == "round-1")
		{
			if ("step1" !in answers)
				throw invalidParams("round 2 requires the step1 answer");
			return ToolResponse.inputRequired([
				InputRequest.elicitation("step2", "Step 2: What is your favorite color?",
					elicitSchema("color", "string"))
			], signState("round-2:" ~ acceptedText(answers["step1"], "name")));
		}
		if (!payload.startsWith("round-2:") || "step2" !in answers)
			throw invalidParams("round 3 requires the step2 answer");
		return ToolResponse.complete(textResult(
			"Hello, " ~ payload["round-2:".length .. $] ~ "; your favorite color is " ~ acceptedText(
			answers["step2"], "color")));
	});

	Tool tampered = {
		name: "test_input_required_result_tampered_state", description: nullable(
				"Rejects a modified requestState")
	};
	server.registerTool(tampered, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("confirm" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.elicitation("confirm", "Please confirm", elicitSchema("ok", "boolean"))
		], signState("tamper-check"));
		verifyState(ctx.requestState()); // throws -32602 on any modification
		return ToolResponse.complete(textResult("state intact"));
	});

	Tool caps = {
		name: "test_input_required_result_capabilities", description: nullable(
				"Requests only the inputs the client can answer")
	};
	server.registerTool(caps, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		InputRequest[] wanted;
		if (ctx.clientSupports(ClientCapability.elicitation) && "user_name" !in answers)
			wanted ~= InputRequest.elicitation("user_name",
				"What is your name?", elicitSchema("name", "string"));
		if (ctx.clientSupports(ClientCapability.sampling) && "greeting" !in answers)
			wanted ~= samplingRequest("greeting", "Generate a greeting", 50);
		if (ctx.clientSupports(ClientCapability.roots) && "client_roots" !in answers)
			wanted ~= InputRequest.roots("client_roots");
		if (wanted.length)
			return ToolResponse.inputRequired(wanted);
		return ToolResponse.complete(textResult("inputs satisfied"));
	});

	// non-tool-request: prompts/get may also answer with an InputRequiredResult.
	Prompt prompt = {
		name: "test_input_required_result_prompt", description: nullable(
				"A prompt that asks for its context via MRTR")
	};
	server.registerPrompt(prompt, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("user_context" !in answers)
			return PromptResponse.inputRequired([
			InputRequest.elicitation("user_context",
				"What context should the prompt use?", elicitSchema("context", "string"))
		]);
		GetPromptResult r;
		r.messages = [
			PromptMessage("user",
				Content.makeText("Context: " ~ acceptedText(answers["user_context"], "context")))
		];
		return PromptResponse.complete(r);
	});
}

// ===========================================================================
// SEP-2663 (Tasks extension) fixtures: the tasks-* scenarios.
// ===========================================================================

private Json taskText(string text, bool isError = false) @safe
{
	Json r = Json.emptyObject;
	r["content"] = Json([Json(["type": Json("text"), "text": Json(text)])]);
	if (isError)
		r["isError"] = true;
	return r;
}

private void registerTaskFixtures(McpServer server) @safe
{
	import core.time : Duration, msecs;
	import std.conv : to;
	import std.typecons : Nullable;
	import vibe.core.core : sleep;
	import vibe.data.json : parseJsonString;

	// greet: sync-only; a task-capable client still gets a plain result.
	Tool greet = {
		name: "greet", description: nullable("Greets by name"), inputSchema: parseJsonString(
				`{"type":"object","properties":{"name":{"type":"string"}}}`)
	};
	server.registerTool(greet, (Json args) @safe {
		const name = ("name" in args && args["name"].type == Json.Type.string) ? args["name"]
			.get!string : "world";
		return textResult("Hello, " ~ name ~ "!");
	});

	// slow_compute: sleeps `seconds`, polling for cancellation so a tasks/cancel
	// while running settles the task as cancelled rather than completed.
	Tool slow = {
		name: "slow_compute", description: nullable("Sleeps then returns"), inputSchema: parseJsonString(
				`{"type":"object","properties":{"seconds":{"type":"integer"}}}`)
	};
	server.registerTaskTool(slow, (TaskContext tc) @safe {
		auto input = tc.inputJson();
		const secs = (input.type == Json.Type.object && "seconds" in input
			&& input["seconds"].type == Json.Type.int_) ? input["seconds"].get!int : 0;
		foreach (i; 0 .. secs * 10)
		{
			if (tc.cancelRequested())
				return Json.emptyObject; // the runner marks the task cancelled
			sleep(100.msecs);
		}
		return taskText("computed after " ~ secs.to!string ~ "s");
	});

	// failing_job: a tool execution error (completed + isError), after ~1s. It
	// requires the extension, so a client without it is answered with -32021.
	Tool failing = {
		name: "failing_job", description: nullable("Always fails as a tool error")
	};
	server.registerTaskTool(failing, (TaskContext tc) @safe {
		sleep(1000.msecs);
		return taskText("the job failed", true);
	}, Nullable!Duration.init, Nullable!Duration.init, TaskSupport.required);

	// protocol_error_job: a protocol-level failure (status failed + error).
	Tool protoErr = {
		name: "protocol_error_job", description: nullable("Fails with a protocol error")
	};
	server.registerTaskTool(protoErr, (TaskContext tc) @safe {
		throw new McpException(ErrorCode.internalError, "protocol_error_job exploded");
		return Json.emptyObject;
	});

	// confirm_delete: parks for one elicitation, resumes on tasks/update.
	Tool confirm = {
		name: "confirm_delete", description: nullable("Asks for confirmation before deleting")
	};
	server.registerTaskTool(confirm, (TaskContext tc) @safe {
		if (!tc.hasInput("confirm"))
			return tc.requireInput([
			InputRequest.elicitation("confirm", "Confirm deletion?",
				elicitSchema("ok", "boolean"))
		]);
		return taskText("deleted");
	});

	// multi_input: two simultaneous inputs; answering one at a time leaves only
	// the unanswered key outstanding.
	Tool multi = {name: "multi_input", description: nullable("Needs two inputs")};
	server.registerTaskTool(multi, (TaskContext tc) @safe {
		InputRequest[] missing;
		if (!tc.hasInput("first"))
			missing ~= InputRequest.elicitation("first", "First input?",
				elicitSchema("value", "string"));
		if (!tc.hasInput("second"))
			missing ~= InputRequest.elicitation("second", "Second input?",
				elicitSchema("value", "string"));
		if (missing.length)
			return tc.requireInput(missing);
		return taskText("both inputs received");
	});

	// test_tool_with_task: an MRTR round gathers user_name, then the final round
	// escalates to a task whose result carries the gathered name.
	server.registerTaskExecutor("test_tool_with_task", (TaskContext tc) @safe {
		auto input = tc.inputJson();
		const name = (input.type == Json.Type.object && "user_name" in input
			&& input["user_name"].type == Json.Type.string) ? input["user_name"].get!string : "";
		return taskText("Hello, " ~ name ~ "! (from the task)");
	});
	Tool composed = {
		name: "test_tool_with_task", description: nullable(
				"Gathers a name via MRTR, then runs as a task")
	};
	server.registerTool(composed, (Json args, RequestContext ctx) @safe {
		auto answers = ctx.inputResponses();
		if ("user_name" !in answers)
			return ToolResponse.inputRequired([
			InputRequest.elicitation("user_name", "What is your name?",
				elicitSchema("name", "string"))
		]);
		Json input = Json.emptyObject;
		input["user_name"] = acceptedText(answers["user_name"], "name");
		return server.startTask("test_tool_with_task", input, ctx);
	});
	server.setToolTaskSupport("test_tool_with_task", TaskSupport.required);
}

// ===========================================================================
// SEP-2640 (Skills extension) fixtures: the sep-2640-skills-* scenarios.
// ===========================================================================

/// One static skill with a supporting file in a subdirectory (so a directory
/// read sees both a file and a subdirectory child) and one dynamic skill, all
/// published through skills/list and skills/get.
private void registerSkillFixtures(McpServer server) @safe
{
	Skill pdf = {
		path: "office/pdf-forms", description: "Fill in PDF forms using the field reference", instructions: "# PDF Forms\n\nConsult `references/FORMS.md`, then fill each field.\n",
		metadata: ["version": "1.0.0"], files: [
				SkillFile("references/FORMS.md", "text/markdown",
						"# Form fields\n\n- applicant_name\n")
		]
	};
	registerSkill(server, pdf);

	DynamicSkill daily = {
		path: "reports/daily", description: "Assemble today's operational report",
		instructions: () @safe => "# Daily report\n\nGenerated on demand.\n"
	};
	registerDynamicSkill(server, daily);
}
