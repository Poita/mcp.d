/// Test fixtures and unit tests for module-scope UDA registration
/// (`registerModule` / `registerModules`). The annotated free functions below
/// exercise `@tool`, `@resource`, `@prompt`, and a tool taking an explicit
/// `RequestContext`. Everything here is `version (unittest)` only.
module mcp.api.module_reflection_test;

version (unittest)
{
	import std.typecons : Nullable;

	import vibe.data.json : Json;

	import mcp.api.attributes;
	import mcp.api.reflection;
	import mcp.server.server;
	import mcp.server.context;
	import mcp.protocol.types;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// --- Module-scope free functions decorated with the public UDAs. ---

	@tool("mod_add", "Add two integers (free function)")
	long modAdd(long a, long b) @safe
	{
		return a + b;
	}

	@tool("mod_ctx", "Echo whether a RequestContext was injected")
	string modCtx(RequestContext ctx, string msg) @safe
	{
		return (ctx is null) ? "no-ctx: " ~ msg : "ctx: " ~ msg;
	}

	@resource("test://mod-doc", "ModuleDoc", "text/plain")
	string modDoc() @safe
	{
		return "module document body";
	}

	@prompt("mod_intro", "Module intro prompt")
	string modIntro(string topic) @safe
	{
		return "Tell me about " ~ topic;
	}
}

unittest  // registerModule: a module-level @tool is registered and dispatches
{
	auto s = new MCPServer("t", "1");
	registerModule!(mcp.api.module_reflection_test)(s);

	Json p = Json.emptyObject;
	p["name"] = "mod_add";
	p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!long == 9);
}

unittest  // registerModule: a module-level @resource is registered and dispatches
{
	auto s = new MCPServer("t", "1");
	registerModule!(mcp.api.module_reflection_test)(s);

	Json rp = Json.emptyObject;
	rp["uri"] = "test://mod-doc";
	auto rr = s.handle(Message(makeRequest(Json(2), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "module document body");
}

unittest  // registerModule: a module-level @prompt is registered and dispatches
{
	auto s = new MCPServer("t", "1");
	registerModule!(mcp.api.module_reflection_test)(s);

	Json pp = Json.emptyObject;
	pp["name"] = "mod_intro";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Tell me about MCP");
}

unittest  // registerModule: a free-function @tool taking RequestContext still works
{
	auto s = new MCPServer("t", "1");
	registerModule!(mcp.api.module_reflection_test)(s);

	// The context parameter is omitted from the public input schema.
	auto tools = s.handle(Message(makeRequest(Json(4), "tools/list",
			Json.emptyObject))).get["result"]["tools"];
	Json ctxTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "mod_ctx")
			ctxTool = tools[i];
	assert(ctxTool.type == Json.Type.object);
	assert("ctx" !in ctxTool["inputSchema"]["properties"]);
	assert("msg" in ctxTool["inputSchema"]["properties"]);

	// And the tool dispatches, receiving an injected context (NullContext in-process).
	Json p = Json.emptyObject;
	p["name"] = "mod_ctx";
	p["arguments"] = Json(["msg": Json("hi")]);
	auto r = s.handle(Message(makeRequest(Json(5), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "ctx: hi");
}

unittest  // registerModules: variadic form registers across modules
{
	auto s = new MCPServer("t", "1");
	registerModules!(mcp.api.module_reflection_test)(s);

	auto tools = s.handle(Message(makeRequest(Json(6), "tools/list",
			Json.emptyObject))).get["result"]["tools"];
	bool foundAdd;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "mod_add")
			foundAdd = true;
	assert(foundAdd);
}
