/// MCP Tools example client + self-verifying e2e test (#348) — dual-transport.
///
/// Drives the `tools-example` server over EITHER transport, with the SAME
/// transport-agnostic assertions:
///   - STDIO (default): spawns the built `tools-server` binary (without --http)
///     and speaks newline-delimited JSON-RPC over its stdin/stdout via
///     `McpClient.stdio`;
///   - HTTP (`--http <url>`): connects to a running server's Streamable HTTP
///     endpoint via `McpClient.http(url)`.
///
/// It then asserts the server's tool surface and behavior:
///   - `tools/list` contains the expected tool names;
///   - inferred input schemas carry the typed args (enum members, the optional
///     Nullable arg is NOT required, the struct arg is an object sub-schema);
///   - the `@readOnly`/`@destructive`/`@idempotent`/`@hintTitle` marker UDAs are
///     reflected into each tool's `ToolAnnotations`, read via the ergonomic
///     `tool.toolAnnotations()` accessor (#469);
///   - calling `calc` yields the expected `structuredContent` (struct return),
///     decoded with the typed `result.structuredContentAs!T` (#464);
///   - the optional `round` arg flows through;
///   - a scalar-returning tool wraps its value under `result`;
///   - a string tool returns plain text content (no structuredContent);
///   - a tool returning a typed `CallToolResult` yields the expected text +
///     resource-link content blocks (typed `Content.make*` factories);
///   - a bad call (unknown tool) raises the expected JSON-RPC error code.
///
/// Where the call arguments are static, it uses the typed
/// `client.callTool(name, T args)` overload (#468) instead of hand-building a
/// Json arguments object; where an argument is genuinely optional/dynamic it
/// keeps a Json object.
///
/// Prints "OK: ..." and exits 0 on success; on ANY mismatch it prints what
/// differed and exits non-zero. This makes the example double as a CI e2e test
/// over every supported transport.
module tools_client;

import std.getopt : getopt;
import std.math : isClose;

import vibe.data.json : Json;

import mcp.client.client : McpClient;
import mcp.protocol.errors : ErrorCode, McpException;
import mcp.protocol.types : CallToolResult, ContentKind, Tool, ToolAnnotations;

private int failures;

/// `stderr.writeln` is `@system`; wrap it so the rest can stay `@safe`.
private void logFail(string msg) @trusted
{
	import std.stdio : stderr;

	stderr.writeln("FAIL: ", msg);
}

private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
	{
		failures++;
		logFail(msg);
	}
}

/// Locate a tool by name in a list, or fail.
private Tool find(Tool[] tools, string name) @safe
{
	foreach (t; tools)
		if (t.name == name)
			return t;
	failures++;
	logFail("tool not found in tools/list: " ~ name);
	return Tool.init;
}

/// Typed `calc` arguments — passed straight to `client.callTool("calc", CalcArgs(...))`
/// (#468), which serializes to the same wire object as a hand-built Json. `op` is
/// the server's `Op` enum member as a string.
struct CalcArgs
{
	string op;
	double a;
	double b;
}

/// Typed `magnitude` arguments — a nested `Vec2` struct serialized for the call.
struct Vec2Arg
{
	double x;
	double y;
}

struct MagnitudeArgs
{
	Vec2Arg v;
}

/// Typed view of `calc`'s structured output, decoded via `structuredContentAs!T`
/// (#464). The enum return field serializes as its ordinal, so `op` is an int
/// (Op.add == 0).
struct CalcOutput
{
	int op;
	double result;
}

/// Typed view of a scalar tool's structured output (scalar returns are wrapped
/// under a `result` key).
struct ScalarOutput
{
	double result;
}

/// Parse the `--http <url>` option. `getopt` takes `&httpUrl`, which the
/// compiler infers `@system`, so it lives in a `@trusted` shim to keep `main`
/// `@safe`.
private string parseHttpUrl(ref string[] args) @trusted
{
	string httpUrl;
	getopt(args, "http", "Connect to a running Streamable HTTP server at <url> "
		~ "(e.g. http://127.0.0.1:8530/mcp); default spawns the stdio server", &httpUrl);
	return httpUrl;
}

int main(string[] args) @safe
{
	// Transport selection: --http <url> connects to a running HTTP server;
	// absent, we spawn the built server binary and speak stdio. The assertions
	// below are identical for both — the SAME client verifies every transport.
	string httpUrl = parseHttpUrl(args);

	McpClient client;
	if (httpUrl.length)
	{
		client = McpClient.http(httpUrl);
	}
	else
	{
		// Resolve the server binary next to this client binary (dub writes both
		// into the package root), independent of the current working directory,
		// and let `McpClient.spawn` own the subprocess + its stdio channel.
		client = McpClient.spawn([serverBinaryPath()]);
	}
	// Both transports release the same way: stdio runs the SIGTERM->SIGKILL
	// subprocess shutdown, HTTP stops any background streams.
	scope (exit)
		client.close();

	auto init = client.initialize();
	check(init.serverInfo.name == "tools-example",
		"serverInfo.name = " ~ init.serverInfo.name ~ " (want tools-example)");

	// --- tools/list ---------------------------------------------------------
	auto tools = client.listTools().tools;
	import std.algorithm : map, canFind;
	import std.array : array;

	auto names = tools.map!(t => t.name).array;
	foreach (want; ["calc", "magnitude", "greet", "erase", "describe_doc"])
		check(names.canFind(want), "tools/list missing tool: " ~ want);

	// --- input schema of `calc` --------------------------------------------
	auto calc = find(tools, "calc");
	{
		auto props = calc.inputSchema["properties"];
		check(("op" in props) !is null, "calc.inputSchema missing 'op'");
		check(("a" in props) !is null && ("b" in props) !is null,
			"calc.inputSchema missing 'a'/'b'");
		check(("round" in props) !is null, "calc.inputSchema missing optional 'round'");
		// The enum parameter must expose its members.
		auto opEnum = props["op"]["enum"];
		check(opEnum.type == Json.Type.array && opEnum.length == 3,
			"calc.op enum should have 3 members");
		// The optional Nullable!int arg must NOT be required.
		bool roundRequired;
		if (("required" in calc.inputSchema) !is null)
			foreach (i; 0 .. calc.inputSchema["required"].length)
				if (calc.inputSchema["required"][i].get!string == "round")
					roundRequired = true;
		check(!roundRequired, "optional 'round' must not be in required[]");
	}

	// --- struct argument schema of `magnitude` -----------------------------
	auto mag = find(tools, "magnitude");
	{
		auto vProp = mag.inputSchema["properties"]["v"];
		check(vProp["type"].get!string == "object", "magnitude.v should be object schema");
		check(("x" in vProp["properties"]) !is null && ("y" in vProp["properties"]) !is null,
			"magnitude.v should expose x/y fields");
	}

	// --- behavioral annotations (marker UDAs) ------------------------------
	// `tool.toolAnnotations()` (#469) decodes the raw annotations Json into the
	// typed `ToolAnnotations` — no `ToolAnnotations.fromJson(tool.annotations)`.
	{
		auto a = calc.toolAnnotations();
		check(!a.readOnlyHint.isNull && a.readOnlyHint.get, "calc should be readOnlyHint:true");
		check(!a.idempotentHint.isNull && a.idempotentHint.get, "calc should be idempotentHint:true");
		check(!a.title.isNull && a.title.get == "Calculator",
			"calc hintTitle should be 'Calculator'");

		auto er = find(tools, "erase").toolAnnotations();
		check(!er.destructiveHint.isNull && er.destructiveHint.get,
			"erase should be destructiveHint:true");
	}

	// --- call `calc` (struct return -> structuredContent) ------------------
	// Pass typed args (#468) and decode the typed structured output (#464).
	{
		auto r = client.callTool("calc", CalcArgs("add", 3.0, 4.0));
		check(!r.isError, "calc add should not be an error");
		auto calcOut = r.structuredContentAs!CalcOutput;
		// The enum return field serializes as its ordinal: Op.add == 0.
		check(calcOut.op == 0, "calc structuredContent.op should be Op.add (0)");
		check(isClose(calcOut.result, 7.0), "calc 3+4 should be 7");
	}

	// --- optional `round` argument flows through ---------------------------
	// `round` is genuinely optional, so keep a dynamic Json arg object here.
	{
		Json a = Json.emptyObject;
		a["op"] = "mul";
		a["a"] = 1.0 / 3.0;
		a["b"] = 1.0;
		a["round"] = 2;
		auto r = client.callTool("calc", a);
		check(isClose(r.structuredContentAs!CalcOutput.result, 0.33),
			"calc (1/3) rounded to 2 dp should be 0.33");
	}

	// --- scalar return wrapped under `result` ------------------------------
	{
		auto r = client.callTool("magnitude", MagnitudeArgs(Vec2Arg(3.0, 4.0)));
		check(isClose(r.structuredContentAs!ScalarOutput.result, 5.0),
			"magnitude(3,4) should be 5");
	}

	// --- string return -> plain text content, no structuredContent ---------
	{
		Json a = Json.emptyObject;
		a["name"] = "Ada";
		auto r = client.callTool("greet", a);
		check(r.content.length == 1 && r.content[0].text == "Hello, Ada!",
			"greet should return text 'Hello, Ada!'");
		check(r.structuredContent.type == Json.Type.undefined,
			"greet should not have structuredContent");
	}

	// --- typed CallToolResult: text + resource-link content blocks ---------
	{
		Json a = Json.emptyObject;
		a["id"] = "42";
		auto r = client.callTool("describe_doc", a);
		check(!r.isError, "describe_doc should not be an error");
		check(r.content.length == 2,
			"describe_doc should return 2 content blocks (text + resource link)");
		if (r.content.length == 2)
		{
			check(r.content[0].kind == ContentKind.text
				&& r.content[0].text == "Document 42 is available.",
				"describe_doc block 0 should be the expected text");
			check(r.content[1].kind == ContentKind.resourceLink
				&& r.content[1].uri == "doc://42",
				"describe_doc block 1 should be a resource_link to doc://42");
		}
	}

	// --- bad call: unknown tool raises invalidParams (-32602) --------------
	{
		int code;
		bool threw;
		try
			client.callTool("does_not_exist", Json.emptyObject);
		catch (McpException e)
		{
			threw = true;
			code = e.code;
		}
		check(threw, "calling an unknown tool should raise McpException");
		check(code == ErrorCode.invalidParams,
			"unknown tool error code should be invalidParams (-32602)");
	}

	import std.stdio : writeln;

	if (failures)
	{
		logFail(failuresMsg());
		return 1;
	}
	auto transport = httpUrl.length ? "http" : "stdio";
	writeln("OK: tools example e2e passed over ", transport,
		" — listTools names, enum/struct/optional schemas, ",
		"readOnly/destructive/idempotent annotations, struct+scalar+string results, ",
		"typed Content.make* (text+resource_link), and unknown-tool error code all verified.");
	return 0;
}

/// Absolute path to the `tools-server` binary, resolved next to this executable.
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "tools-server");
}

private string failuresMsg() @safe
{
	import std.conv : to;

	return to!string(failures) ~ " assertion(s) failed";
}
