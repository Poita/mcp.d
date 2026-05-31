module mcp.api.reflection;

import std.traits;
import std.typecons : Tuple, Nullable, nullable;
import std.meta : AliasSeq;

import vibe.data.json : Json, serializeToJson, deserializeJson;

import mcp.protocol.types;
import mcp.protocol.capabilities : Icon;
import mcp.protocol.draft : CacheHint, CacheScope;
import mcp.server.server : McpServer, ToolResponse;
import mcp.server.context;
import mcp.api.attributes;
import mcp.api.schema;

@safe:

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated method of `obj` on `server`, deriving JSON schemas and argument
/// marshalling from the method signatures (FastMCP-style ergonomics).
void registerHandlers(T)(McpServer server, T obj) @safe
{
	static foreach (memberName; __traits(allMembers, T))
	{
		static if (__traits(compiles, __traits(getOverloads, T, memberName)))
		{
			static foreach (overload; __traits(getOverloads, T, memberName))
			{
				static foreach (attr; __traits(getAttributes, overload))
				{
					static if (is(typeof(attr) == tool))
						registerToolMethod!(memberName, overload, obj)(server, attr);
					else static if (is(typeof(attr) == prompt))
						registerPromptMethod!(memberName, overload, obj)(server, attr);
					else static if (is(typeof(attr) == resource))
						registerResourceMethod!(memberName, overload, obj)(server, attr);
					else static if (is(typeof(attr) == resourceTemplate))
						registerTemplateMethod!(memberName, overload, obj)(server, attr);
				}
			}
		}
	}
}

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated **free function** in module `mod` on `server`, mirroring
/// `registerHandlers` but targeting module-scope symbols rather than the
/// methods of an instance (FastMCP-style module decoration).
///
/// Free functions cannot receive a `RequestContext` via `this`, so a context
/// must be taken as an explicit parameter (exactly as opt-in methods do).
/// Non-function members and functions without a recognized UDA are skipped.
void registerModule(alias mod)(McpServer server) @safe
{
	static foreach (memberName; __traits(allMembers, mod))
	{
		static if (__traits(compiles, __traits(getOverloads, mod, memberName)))
		{
			static foreach (overload; __traits(getOverloads, mod, memberName))
			{
				static foreach (attr; __traits(getAttributes, overload))
				{
					static if (is(typeof(attr) == tool))
						registerToolMethod!(memberName, overload, mod)(server, attr);
					else static if (is(typeof(attr) == prompt))
						registerPromptMethod!(memberName, overload, mod)(server, attr);
					else static if (is(typeof(attr) == resource))
						registerResourceMethod!(memberName, overload, mod)(server, attr);
					else static if (is(typeof(attr) == resourceTemplate))
						registerTemplateMethod!(memberName, overload, mod)(server, attr);
				}
			}
		}
	}
}

/// Convenience variadic form of `registerModule`: register the annotated free
/// functions of several modules in one call.
void registerModules(mods...)(McpServer server) @safe
{
	static foreach (mod; mods)
		registerModule!mod(server);
}

/// Build the `{type:object, properties, required}` schema for a method's
/// parameters, skipping any `RequestContext` parameter.
private Json parametersSchema(alias func)() @safe
{
	import mcp.protocol.draft : validateHeaderName;
	import std.traits : isFloatingPoint;

	alias names = ParameterIdentifierTuple!func;
	alias types = Parameters!func;

	Json props = Json.emptyObject;
	Json required = Json.emptyArray;
	static foreach (i, P; types)
	{
		static if (!is(P : RequestContext))
		{
			{
				Json ps = jsonSchemaOf!P;
				// Draft x-mcp-header: a parameter tagged @mcpHeader is mirrored
				// into an `Mcp-Param-<name>` request header; emit the extension
				// property so the transport can validate it (see draft.paramHeaders).
				// The header name and parameter type are checked against the draft
				// `x-mcp-header` constraints at compile time: the value MUST be a
				// valid HTTP token (non-empty, 1*tchar, no CR/LF) and the parameter
				// MUST be a primitive type (string/integral/bool); `number`
				// (floating point) is NOT permitted.
				static foreach (attr; __traits(getAttributes, types[i .. i + 1]))
					static if (is(typeof(attr) == mcpHeader))
						{
						static assert(validateHeaderName(attr.name) is null,
								"@mcpHeader(\"" ~ attr.name ~ "\") is not a valid x-mcp-header value: "
								~ validateHeaderName(attr.name));
						static assert(!isFloatingPoint!P, "@mcpHeader cannot be applied to a floating-point ('number') parameter '" ~ names[i] ~ "'; x-mcp-header permits only integer/string/boolean");
						ps["x-mcp-header"] = attr.name;
					}
				props[names[i]] = ps;
			}
			static if (!isInstanceOf!(Nullable, P))
				required ~= Json(names[i]);
		}
	}
	Json s = Json.emptyObject;
	s["type"] = "object";
	s["properties"] = props;
	if (required.length > 0)
		s["required"] = required;
	return s;
}

/// Convert one JSON argument value into the parameter type `P`.
private P marshalArg(P)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else static if (isInstanceOf!(Nullable, P))
	{
		alias Inner = TemplateArgsOf!P[0];
		if (name in args && args[name].type != Json.Type.null_
				&& args[name].type != Json.Type.undefined)
			return P(marshalScalar!Inner(args[name]));
		return P.init;
	}
	else
	{
		if (name in args)
			return marshalScalar!P(args[name]);
		return P.init;
	}
}

private P marshalScalar(P)(Json v) @safe
{
	static if (is(P == enum))
	{
		import std.conv : to;

		return to!P(v.get!string);
	}
	else
		return () @trusted { return deserializeJson!P(v); }();
}

/// The JSON Schema describing a tool's structured output, derived from its
/// return type — or `Json.undefined` when the tool produces unstructured text
/// (a `string`) or supplies its own `CallToolResult`. Aggregate (`struct`)
/// returns map to their object schema directly; scalar/array/enum returns are
/// wrapped under a `result` property so `structuredContent` is always an object.
private Json outputSchemaOf(R)() @safe
{
	static if (is(R == CallToolResult) || is(R == ToolResponse) || isSomeString!R || is(R == void))
		return Json.undefined;
	else static if (is(R == struct))
		return jsonSchemaOf!R;
	else
	{
		Json s = Json.emptyObject;
		s["type"] = "object";
		Json props = Json.emptyObject;
		props["result"] = jsonSchemaOf!R;
		s["properties"] = props;
		s["required"] = Json([Json("result")]);
		return s;
	}
}

/// Wrap a tool method's return value into a `CallToolResult`. The structured
/// result mirrors `outputSchemaOf!R`: structs serialize to an object; scalars,
/// arrays, and enums are wrapped under a `result` key; strings become text
/// content with no structured output.
private CallToolResult toToolResult(R)(R ret) @safe
{
	static if (is(R == CallToolResult))
		return ret;
	else static if (isSomeString!R)
	{
		CallToolResult r;
		r.content = [Content.makeText(ret)];
		return r;
	}
	else
	{
		CallToolResult r;
		static if (is(R == struct))
			auto structured = () @trusted { return serializeToJson(ret); }();
		else
		{
			Json structured = Json.emptyObject;
			structured["result"] = () @trusted { return serializeToJson(ret); }();
		}
		r.structuredContent = structured;
		r.content = [Content.makeText(structured.toString())];
		return r;
	}
}

/// Collect every `@icon` UDA on a method into the descriptor `Icon[]` shape.
private Icon[] collectIcons(alias overload)() @safe
{
	Icon[] icons;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == icon))
		{
			{
				Icon ic;
				ic.src = a.src;
				if (a.mimeType.length)
					ic.mimeType = nullable(a.mimeType);
				ic.sizes = a.sizes;
				icons ~= ic;
			}
		}
	}
	return icons;
}

/// Collect a `@meta` UDA's object into a descriptor `_meta` Json (undefined when
/// absent or when the supplied value is not an object).
private Json collectMeta(alias overload)() @safe
{
	Json m = Json.undefined;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == meta))
		{
			if (a.value.type == Json.Type.object)
				m = a.value;
		}
	}
	return m;
}

/// Collect a `@cache` UDA into a `Nullable!CacheHint` for resource/template
/// registration; null when absent.
private Nullable!CacheHint collectCache(alias overload)() @safe
{
	Nullable!CacheHint hint;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == cache))
		{
			{
				CacheHint h;
				h.ttlMs = a.ttlMs;
				h.cacheScope = (a.scope_ == "private") ? CacheScope.private_ : CacheScope.public_;
				hint = h;
			}
		}
	}
	return hint;
}

private void registerToolMethod(string memberName, alias overload, alias parent)(
		McpServer server, tool attr) @safe
{
	import std.traits : ReturnType;

	Tool descriptor;
	descriptor.name = attr.name;
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	descriptor.inputSchema = parametersSchema!overload();
	auto outSchema = outputSchemaOf!(ReturnType!overload)();
	if (outSchema.type == Json.Type.object)
		descriptor.outputSchema = outSchema;

	// Fold any @toolAnnotations UDA on the same method into typed
	// ToolAnnotations, then serialize into the descriptor's annotations field.
	ToolAnnotations anns;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == toolAnnotations))
		{
			anns.readOnlyHint = a.readOnlyHint;
			anns.destructiveHint = a.destructiveHint;
			anns.idempotentHint = a.idempotentHint;
			anns.openWorldHint = a.openWorldHint;
			if (a.title.length)
				anns.title = a.title;
		}
	}
	if (!anns.empty)
		descriptor.annotations = anns.toJson();

	// Fold any @toolExecution UDA into the descriptor's `execution` field
	// (2025-11-25 per-tool task-augmented execution negotiation).
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == toolExecution))
		{
			if (a.taskSupport.length)
				descriptor.execution = ToolExecution(nullable(a.taskSupport));
		}
	}

	// @icon UDAs -> descriptor.icons; @meta UDA -> descriptor._meta.
	descriptor.icons = collectIcons!overload();
	{
		auto m = collectMeta!overload();
		if (m.type == Json.Type.object)
			descriptor.meta = m;
	}

	static if (is(ReturnType!overload == ToolResponse))
	{
		// MRTR-capable tool: the method itself returns a ToolResponse, so it may
		// answer `inputRequired` (stateless elicitation) as well as `complete`.
		server.registerDynamicTool(descriptor, (Json args, RequestContext ctx) @safe {
			alias names = ParameterIdentifierTuple!overload;
			Tuple!(Parameters!overload) argv;
			static foreach (i, P; Parameters!overload)
			{
				static if (is(P : RequestContext))
					argv[i] = ctx;
				else
					argv[i] = marshalArg!P(args, names[i]);
			}
			return __traits(getMember, parent, memberName)(argv.expand);
		});
	}
	else
	{
		server.registerDynamicTool(descriptor, (Json args, RequestContext ctx) @safe {
			alias names = ParameterIdentifierTuple!overload;
			Tuple!(Parameters!overload) argv;
			static foreach (i, P; Parameters!overload)
			{
				static if (is(P : RequestContext))
					argv[i] = ctx;
				else
					argv[i] = marshalArg!P(args, names[i]);
			}
			return toToolResult(__traits(getMember, parent, memberName)(argv.expand));
		});
	}
}

/// Wrap a prompt method's return value into a `GetPromptResult`.
private GetPromptResult toPromptResult(R)(R ret) @safe
{
	static if (is(R == GetPromptResult))
		return ret;
	else static if (is(R == PromptMessage[]))
	{
		GetPromptResult r;
		r.messages = ret;
		return r;
	}
	else static if (isSomeString!R)
	{
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText(ret))];
		return r;
	}
	else
		static assert(false,
				"@prompt method must return GetPromptResult, PromptMessage[], or string");
}

private void registerPromptMethod(string memberName, alias overload, alias parent)(
		McpServer server, prompt attr) @safe
{
	Prompt descriptor;
	descriptor.name = attr.name;
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	alias names = ParameterIdentifierTuple!overload;
	static foreach (i, P; Parameters!overload)
	{
		static if (!is(P : RequestContext))
			descriptor.arguments ~= PromptArgument(names[i],
					Nullable!string.init, !isInstanceOf!(Nullable, P));
	}

	server.registerDynamicPrompt(descriptor, (Json args) @safe {
		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P : RequestContext))
				argv[i] = new NullContext;
			else
				argv[i] = marshalArg!P(args, names[i]);
		}
		return toPromptResult(__traits(getMember, parent, memberName)(argv.expand));
	});
}

private ResourceContents toResourceContents(R)(R ret, string uri, string mimeType) @safe
{
	static if (is(R == ResourceContents))
		return ret;
	else static if (isSomeString!R)
		return ResourceContents.makeText(uri, mimeType, ret);
	else
		static assert(false, "@resource method must return ResourceContents or string");
}

private void registerResourceMethod(string memberName, alias overload, alias parent)(
		McpServer server, resource attr) @safe
{
	Resource descriptor;
	descriptor.uri = attr.uri;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);

	// Fold any @resourceAnnotations UDA on the same method into the descriptor.
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == resourceAnnotations))
		{
			descriptor.annotations.audience = a.audience;
			descriptor.annotations.priority = a.priority;
			descriptor.annotations.lastModified = a.lastModified;
		}
	}

	// @icon UDAs -> descriptor.icons; @meta UDA -> descriptor._meta.
	descriptor.icons = collectIcons!overload();
	{
		auto m = collectMeta!overload();
		if (m.type == Json.Type.object)
			descriptor.meta = m;
	}

	server.registerResource(descriptor, () @safe {
		return toResourceContents(__traits(getMember, parent, memberName)(),
			attr.uri, attr.mimeType);
	}, collectCache!overload());
}

private void registerTemplateMethod(string memberName, alias overload, alias parent)(
		McpServer server, resourceTemplate attr) @safe
{
	ResourceTemplate descriptor;
	descriptor.uriTemplate = attr.uriTemplate;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);

	// Fold any @resourceAnnotations UDA on the same method into the descriptor.
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == resourceAnnotations))
		{
			descriptor.annotations.audience = a.audience;
			descriptor.annotations.priority = a.priority;
			descriptor.annotations.lastModified = a.lastModified;
		}
	}

	// @icon UDAs -> descriptor.icons; @meta UDA -> descriptor._meta.
	descriptor.icons = collectIcons!overload();
	{
		auto m = collectMeta!overload();
		if (m.type == Json.Type.object)
			descriptor.meta = m;
	}

	server.registerResourceTemplate(descriptor, (string uri, string[string] params) @safe {
		alias names = ParameterIdentifierTuple!overload;
		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P == string))
				argv[i] = (names[i] in params) ? params[names[i]] : "";
			else
				argv[i] = P.init;
		}
		auto ret = __traits(getMember, parent, memberName)(argv.expand);
		return toResourceContents(ret, uri, attr.mimeType);
	}, collectCache!overload());
}

version (unittest)
{
	private enum Priority
	{
		low,
		high
	}

	private struct Stats
	{
		int count;
		double total;
	}

	private final class DemoApi
	{
		@tool("add", "Add two integers")
		int add(int a, int b) @safe
		{
			return a + b;
		}

		@tool("stats", "Summarize a list of integers")
		Stats stats(int[] values) @safe
		{
			Stats s;
			foreach (v; values)
			{
				s.count++;
				s.total += v;
			}
			return s;
		}

		@tool("greet", "Greet someone")
		string greet(string name) @safe
		{
			return "Hello, " ~ name ~ "!";
		}

		@tool("classify", "Classify with an enum + optional note")
		string classify(Priority p, Nullable!string note) @safe
		{
			return note.isNull ? "p" : "n";
		}

		@tool("erase", "Erase a record", "Erase Record")
		@toolAnnotations(destructiveHint : true.nullable, idempotentHint:
				true.nullable) string erase(string id) @safe
		{
			return "erased " ~ id;
		}

		@tool("render", "Render a long report")
		@toolExecution("optional") string render(string spec) @safe
		{
			return "rendered " ~ spec;
		}

		@resource("test://doc", "Doc", "text/plain")
		string doc() @safe
		{
			return "document body";
		}

		@resource("test://readme", "Readme", "text/markdown") @resourceAnnotations(audience
				: ["user"], priority:
				0.9.nullable) string readme() @safe
		{
			return "readme body";
		}

		@tool("query", "Query a region")
		string query(@mcpHeader("Region") string region, int limit)@safe
		{
			return region;
		}

		@prompt("intro", "Intro prompt")
		string intro(string topic) @safe
		{
			return "Tell me about " ~ topic;
		}

		@prompt("summary", "Summary prompt", "Summarize Text")
		string summary(string topic) @safe
		{
			return "Summarize " ~ topic;
		}
	}

	import vibe.data.json : parseJsonString;
	import mcp.server.server : ToolResponse;
	import mcp.protocol.draft : InputRequest;

	// Separate fixture exercising the UDAs added for issue #295: icons, _meta,
	// annotation title, per-resource cache hint, and MRTR (ToolResponse) tools.
	private final class ExtApi
	{
		@tool("draw", "Draw something")
		@icon("https://example.com/draw.png", "image/png", ["48x48"])
		@meta(parseJsonString(`{"category":"art"}`))
		@toolAnnotations(readOnlyHint : true.nullable, title:
				"Draw Tool") string draw(string spec) @safe
		{
			return "drew " ~ spec;
		}

		@tool("ask", "MRTR tool that may ask for more input")
		ToolResponse ask(string seed) @safe
		{
			if (seed.length == 0)
				return ToolResponse.inputRequired([
				InputRequest("req1", "elicitation", Json.emptyObject)
			]);
			CallToolResult r;
			r.content = [Content.makeText("seeded " ~ seed)];
			return ToolResponse.complete(r);
		}

		@resource("ext://cached", "Cached", "application/json")
		@icon("https://example.com/res.svg")
		@meta(parseJsonString(`{"origin":"db"}`))
		@cache(5000, "private")
		string cached() @safe
		{
			return "{}";
		}
	}
}

unittest  // @tool reflection: schema derivation + typed dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json lp = Json.emptyObject;
	auto list = s.handle(Message(makeRequest(Json(1), "tools/list", lp))).get;
	assert(list["result"]["tools"].length == 7);

	// add -> scalar return wrapped under `result`, with an inferred outputSchema.
	Json p = Json.emptyObject;
	p["name"] = "add";
	p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!int == 9);
}

unittest  // @tool reflection: outputSchema is inferred from the return type
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json addSchema, statsSchema, greetTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "add")
			addSchema = tools[i]["outputSchema"];
		else if (name == "stats")
			statsSchema = tools[i]["outputSchema"];
		else if (name == "greet")
			greetTool = tools[i];
	}

	// Scalar return -> object schema wrapping the value under `result`.
	assert(addSchema["type"].get!string == "object");
	assert(addSchema["properties"]["result"]["type"].get!string == "integer");

	// Struct return -> the struct's object schema directly.
	assert(statsSchema["type"].get!string == "object");
	assert(statsSchema["properties"]["count"]["type"].get!string == "integer");
	assert(statsSchema["properties"]["total"]["type"].get!string == "number");

	// String return -> unstructured text, no outputSchema.
	assert("outputSchema" !in greetTool);
}

unittest  // @tool reflection: struct return produces matching structuredContent
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "stats";
	p["arguments"] = Json(["values": Json([Json(2), Json(3), Json(5)])]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["count"].get!int == 3);
	// `total` (a double) serializes as a JSON number; just confirm it's present
	// and numeric (int/float representation is vibe's choice for whole values).
	auto total = r["result"]["structuredContent"]["total"];
	assert(total.type == Json.Type.float_ || total.type == Json.Type.int_);
}

unittest  // @tool reflection: string return becomes text content
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "greet";
	p["arguments"] = Json(["name": Json("Sam")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "Hello, Sam!");
}

unittest  // @tool reflection: enum param schema + optional Nullable param
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	// find classify
	bool found;
	foreach (i; 0 .. tools.length)
	{
		if (tools[i]["name"].get!string == "classify")
		{
			found = true;
			auto schema = tools[i]["inputSchema"];
			assert(schema["properties"]["p"]["type"].get!string == "string");
			assert(schema["properties"]["p"]["enum"].length == 2);
			// only p is required (note is Nullable)
			assert(schema["required"].length == 1);
		}
	}
	assert(found);
}

unittest  // @resource and @prompt reflection register and dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json rp = Json.emptyObject;
	rp["uri"] = "test://doc";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "document body");

	Json pp = Json.emptyObject;
	pp["name"] = "intro";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Tell me about MCP");
}

unittest  // @prompt reflection: optional title is emitted in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	bool foundIntro, foundSummary;
	foreach (i; 0 .. prompts.length)
	{
		auto name = prompts[i]["name"].get!string;
		if (name == "intro")
		{
			foundIntro = true;
			// A prompt without a title carries none on the wire.
			assert("title" !in prompts[i]);
		}
		else if (name == "summary")
		{
			foundSummary = true;
			assert(prompts[i]["title"].get!string == "Summarize Text");
		}
	}
	assert(foundIntro && foundSummary);
}

unittest  // @resourceAnnotations reflection: annotations appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	bool foundReadme, foundDoc;
	foreach (i; 0 .. res.length)
	{
		auto uri = res[i]["uri"].get!string;
		if (uri == "test://readme")
		{
			foundReadme = true;
			assert(res[i]["annotations"]["audience"][0].get!string == "user");
			assert(res[i]["annotations"]["priority"].get!double == 0.9);
		}
		else if (uri == "test://doc")
		{
			foundDoc = true;
			// A resource without @resourceAnnotations carries no annotations.
			assert("annotations" !in res[i]);
		}
	}
	assert(foundReadme && foundDoc);
}

unittest  // @tool reflection: optional title is emitted in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "erase")
			eraseTool = tools[i];
	assert(eraseTool.type == Json.Type.object);
	assert(eraseTool["title"].get!string == "Erase Record");
}

unittest  // @toolAnnotations reflection: hints are serialized into annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool, addTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "erase")
			eraseTool = tools[i];
		else if (name == "add")
			addTool = tools[i];
	}

	auto anns = eraseTool["annotations"];
	assert(anns["destructiveHint"].get!bool == true);
	assert(anns["idempotentHint"].get!bool == true);
	// Unset hints are omitted entirely.
	assert("readOnlyHint" !in anns);
	assert("openWorldHint" !in anns);

	// A tool without @toolAnnotations carries no annotations object.
	assert("annotations" !in addTool);
}

unittest  // @toolExecution reflection: execution.taskSupport appears in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json renderTool, addTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "render")
			renderTool = tools[i];
		else if (name == "add")
			addTool = tools[i];
	}

	assert(renderTool.type == Json.Type.object);
	assert(renderTool["execution"]["taskSupport"].get!string == "optional");
	// A tool without @toolExecution carries no execution object.
	assert("execution" !in addTool);
}

unittest  // @mcpHeader reflection: x-mcp-header is emitted into the param schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.draft : paramHeaderMap;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json queryTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "query")
			queryTool = tools[i];
	assert(queryTool.type == Json.Type.object);

	auto schema = queryTool["inputSchema"];
	// The annotated parameter carries the x-mcp-header property.
	assert(schema["properties"]["region"]["x-mcp-header"].get!string == "Region");
	// The non-annotated parameter does not.
	assert("x-mcp-header" !in schema["properties"]["limit"]);

	// The consumer side (draft.paramHeaderMap) now reads it from the UDA-driven schema.
	auto m = paramHeaderMap(schema);
	assert(m["region"] == "Mcp-Param-Region");
}

unittest  // ToolAnnotations: typed struct round-trips through JSON
{
	ToolAnnotations a;
	a.title = "Display";
	a.readOnlyHint = true;
	a.openWorldHint = false;
	auto j = a.toJson();
	auto b = ToolAnnotations.fromJson(j);
	assert(b.title.get == "Display");
	assert(b.readOnlyHint.get == true);
	assert(b.openWorldHint.get == false);
	assert(b.destructiveHint.isNull);
}

unittest  // ToolAnnotations: empty struct produces an empty object
{
	ToolAnnotations a;
	assert(a.empty);
	assert(a.toJson().length == 0);
}

version (unittest) private auto MakeListMessage()
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	return Message(makeRequest(Json(99), "tools/list", Json.emptyObject));
}

unittest  // #295 @icon UDA: tool icons appear in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool.type == Json.Type.object);
	assert(drawTool["icons"].length == 1);
	assert(drawTool["icons"][0]["src"].get!string == "https://example.com/draw.png");
	assert(drawTool["icons"][0]["mimeType"].get!string == "image/png");
	assert(drawTool["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // #295 @meta UDA: tool descriptor `_meta` appears in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool["_meta"]["category"].get!string == "art");
}

unittest  // #295 @toolAnnotations title: annotation-level title appears in annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	// The annotation-level title is distinct from tool.title and lives under annotations.
	assert(drawTool["annotations"]["title"].get!string == "Draw Tool");
	assert(drawTool["annotations"]["readOnlyHint"].get!bool == true);
}

unittest  // #295 MRTR UDA tool: returning ToolResponse.inputRequired surfaces inputRequests
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// Empty seed -> the tool asks for more input (MRTR InputRequiredResult).
	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("")]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	// An InputRequiredResult carries `inputRequests` (a map keyed by id), not content.
	assert(r["result"]["inputRequests"].type == Json.Type.object);
	assert(r["result"]["inputRequests"]["req1"]["method"].get!string == "elicitation/create");
}

unittest  // #295 MRTR UDA tool: returning ToolResponse.complete produces a normal result
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("X")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert("inputRequests" !in r["result"]);
	assert(r["result"]["content"][0]["text"].get!string == "seeded X");
}

unittest  // #295 @icon / @meta UDA on a resource: appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json cachedRes;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "ext://cached")
			cachedRes = res[i];
	assert(cachedRes.type == Json.Type.object);
	assert(cachedRes["icons"][0]["src"].get!string == "https://example.com/res.svg");
	assert(cachedRes["_meta"]["origin"].get!string == "db");
}

version (unittest) private auto draftRead(string uri) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.draft : MetaKey;

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	Json params = Json.emptyObject;
	params["uri"] = uri;
	params["_meta"] = meta;
	return Message(makeRequest(Json(1), "resources/read", params));
}

unittest  // #295 @cache UDA on a resource: draft resources/read carries CacheableResult fields
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A draft request (carrying the protocol-version _meta) gets cache fields.
	auto rr = s.handle(draftRead("ext://cached")).get;
	assert(rr["result"]["ttlMs"].get!long == 5000);
	assert(rr["result"]["cacheScope"].get!string == "private");
}

unittest  // #295 @cache UDA: pre-draft resources/read has NO cache fields (no wire regression)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A plain (non-draft) request must NOT carry any cache fields.
	Json rp = Json.emptyObject;
	rp["uri"] = "ext://cached";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert("ttlMs" !in rr["result"]);
	assert("cacheScope" !in rr["result"]);
}
