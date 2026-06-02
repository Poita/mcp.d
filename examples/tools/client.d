/// MCP Tools example client + self-verifying e2e test — dual-transport.
///
/// Drives the `tools-example` server over EITHER transport, with the SAME
/// transport-agnostic assertions, using the shared examples/common scaffold:
///   - STDIO (default): `connectFromArgs` spawns the sibling `tools-server`
///     binary (without --http) via `McpClient.spawnSibling` and speaks
///     newline-delimited JSON-RPC over its stdin/stdout;
///   - HTTP (`--http <url>`): `connectFromArgs` connects to a running server's
///     Streamable HTTP endpoint via `McpClient.http(url)`.
///
/// The whole scenario runs inside the scaffold's `runClient`, which drives the
/// vibe event loop uniformly so the identical body works over both transports.
///
/// It then asserts the server's tool surface and behavior:
///   - `tools/list` contains the expected tool names;
///   - inferred input schemas carry the typed args (enum members, the optional
///     Nullable arg is NOT required, the struct arg is an object sub-schema);
///   - the `@readOnly`/`@destructive`/`@idempotent`/`@hintTitle` marker UDAs are
///     reflected into each tool's `ToolAnnotations`, read via the ergonomic
///     `tool.toolAnnotations()` accessor;
///   - calling `calc` yields the expected `structuredContent` (struct return),
///     decoded with the typed `result.structuredContentAs!T`;
///   - the optional `round` arg flows through;
///   - a scalar-returning tool wraps its value under `result`;
///   - a string tool returns plain text content (no structuredContent);
///   - a tool returning a typed `CallToolResult` yields the expected text +
///     resource-link content blocks (typed `Content.make*` factories);
///   - a bad call (unknown tool) raises the expected JSON-RPC error code.
///
/// Where the call arguments are static, it uses the typed
/// `client.callTool(name, T args)` overload instead of hand-building a
/// Json arguments object; where an argument is genuinely optional/dynamic it
/// keeps a Json object.
///
/// Prints "OK: ..." and exits 0 on success; on ANY mismatch the scaffold's
/// `check`/`checkEq` print a FAIL line and throw, which `runClient` maps to a
/// non-zero exit. This makes the example double as a CI e2e test over every
/// supported transport.
module tools_client;

import std.math : isClose;

import vibe.data.json : Json;

import examples_common : check, checkEq, connectFromArgs, runClient;

import mcp.client.client : McpClient;
import mcp.protocol.errors : ErrorCode, McpException;
import mcp.protocol.types : CallToolResult, ContentKind, Tool, ToolAnnotations;

/// Locate a tool by name in a list, or fail (the scaffold's `check` throws).
private Tool find(Tool[] tools, string name) @safe
{
	foreach (t; tools)
		if (t.name == name)
			return t;
	check(false, "tool not found in tools/list: " ~ name);
	return Tool.init;
}

/// Typed `calc` arguments — passed straight to `client.callTool("calc", CalcArgs(...))`,
/// which serializes to the same wire object as a hand-built Json. `op` is
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

/// Typed view of `calc`'s structured output, decoded via `structuredContentAs!T`.
/// The server's `Op` enum return field serializes by MEMBER NAME (e.g.
/// "add") to match the tool's string `enum` outputSchema, so `op` is read
/// here as a `string` carrying that schema-declared member name.
struct CalcOutput
{
	string op;
	double result;
}

/// Typed view of a scalar tool's structured output (scalar returns are wrapped
/// under a `result` key).
struct ScalarOutput
{
	double result;
}

int main(string[] args) @safe
{
	return runClient(() @safe {
		// Transport selection lives in the scaffold: `--http <url>` connects to a
		// running HTTP server, otherwise it spawns the sibling `tools-server`
		// binary and speaks stdio. The assertions below are identical for both.
		auto client = connectFromArgs(args, "tools-server");
		// Both transports release the same way: stdio runs the SIGTERM->SIGKILL
		// subprocess shutdown, HTTP stops any background streams.
		scope (exit)
			client.close();

		auto init = client.initialize();
		checkEq(init.serverInfo.name, "tools-example", "serverInfo.name");

		// --- tools/list -----------------------------------------------------
		auto tools = client.listTools().tools;
		import std.algorithm : map, canFind;
		import std.array : array;

		auto names = tools.map!(t => t.name).array;
		foreach (want; ["calc", "magnitude", "greet", "erase", "describe_doc"])
			check(names.canFind(want), "tools/list missing tool: " ~ want);

		// --- input schema of `calc` ----------------------------------------
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

			// outputSchema: the enum return field `op` must be declared as a
			// STRING enum (member names), matching the by-name structuredContent the
			// server emits — schema and wire must agree on the type.
			auto outProps = calc.outputSchema["properties"];
			check(("op" in outProps) !is null, "calc.outputSchema missing 'op'");
			checkEq(outProps["op"]["type"].get!string, "string",
				"calc.outputSchema.op must be declared as a string enum");
			auto outOpEnum = outProps["op"]["enum"];
			check(outOpEnum.type == Json.Type.array && outOpEnum.length == 3,
				"calc.outputSchema.op enum should list the 3 member names");
		}

		// --- struct argument schema of `magnitude` -------------------------
		auto mag = find(tools, "magnitude");
		{
			auto vProp = mag.inputSchema["properties"]["v"];
			checkEq(vProp["type"].get!string, "object", "magnitude.v schema type");
			check(("x" in vProp["properties"]) !is null
				&& ("y" in vProp["properties"]) !is null, "magnitude.v should expose x/y fields");
		}

		// --- behavioral annotations (marker UDAs) --------------------------
		// `tool.toolAnnotations()` decodes the raw annotations Json into the
		// typed `ToolAnnotations`.
		{
			auto a = calc.toolAnnotations();
			check(!a.readOnlyHint.isNull && a.readOnlyHint.get, "calc should be readOnlyHint:true");
			check(!a.idempotentHint.isNull && a.idempotentHint.get,
				"calc should be idempotentHint:true");
			check(!a.title.isNull && a.title.get == "Calculator",
				"calc hintTitle should be 'Calculator'");

			auto er = find(tools, "erase").toolAnnotations();
			check(!er.destructiveHint.isNull && er.destructiveHint.get,
				"erase should be destructiveHint:true");
		}

		// --- call `calc` (struct return -> structuredContent) --------------
		// Pass typed args and decode the typed structured output.
		{
			auto r = client.callTool("calc", CalcArgs("add", 3.0, 4.0));
			check(!r.isError, "calc add should not be an error");
			auto calcOut = r.structuredContentAs!CalcOutput;
			// The enum return field serializes by member name, so `op` is the string
			// "add" (matching the tool's string `enum` outputSchema), NOT an ordinal.
			checkEq(calcOut.op, "add",
				"calc structuredContent.op should be the \"add\" enum member name");
			check(isClose(calcOut.result, 7.0), "calc 3+4 should be 7");
		}

		// --- optional `round` argument flows through -----------------------
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

		// --- scalar return wrapped under `result` --------------------------
		{
			auto r = client.callTool("magnitude", MagnitudeArgs(Vec2Arg(3.0, 4.0)));
			check(isClose(r.structuredContentAs!ScalarOutput.result, 5.0),
				"magnitude(3,4) should be 5");
		}

		// --- string return -> plain text content, no structuredContent -----
		{
			Json a = Json.emptyObject;
			a["name"] = "Ada";
			auto r = client.callTool("greet", a);
			check(r.content.length == 1 && r.content[0].text == "Hello, Ada!",
				"greet should return text 'Hello, Ada!'");
			check(r.structuredContent.type == Json.Type.undefined,
				"greet should not have structuredContent");
		}

		// --- typed CallToolResult: text + resource-link content blocks -----
		{
			Json a = Json.emptyObject;
			a["id"] = "42";
			auto r = client.callTool("describe_doc", a);
			check(!r.isError, "describe_doc should not be an error");
			checkEq(r.content.length, 2UL,
				"describe_doc should return 2 content blocks (text + resource link)");
			check(r.content[0].kind == ContentKind.text
				&& r.content[0].text == "Document 42 is available.",
				"describe_doc block 0 should be the expected text");
			check(r.content[1].kind == ContentKind.resourceLink && r.content[1].uri == "doc://42",
				"describe_doc block 1 should be a resource_link to doc://42");
		}

		// --- bad call: unknown tool raises invalidParams (-32602) ----------
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
			checkEq(code, cast(int) ErrorCode.invalidParams,
				"unknown tool error code should be invalidParams (-32602)");
		}

		import std.stdio : writeln;

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: tools example e2e passed over ", http ? "http" : "stdio",
			" — listTools names, enum/struct/optional schemas, ",
			"readOnly/destructive/idempotent annotations, struct+scalar+string results, ",
			"typed Content.make* (text+resource_link), and unknown-tool error code all verified.");
		return 0;
	});
}
