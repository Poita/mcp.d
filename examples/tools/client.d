/// MCP Tools example client + self-verifying e2e test (#348).
///
/// Spawns the built `tools-server` binary over stdio, initializes, then asserts
/// the server's tool surface and behavior:
///   - `tools/list` contains the expected tool names;
///   - inferred input schemas carry the typed args (enum members, the optional
///     Nullable arg is NOT required, the struct arg is an object sub-schema);
///   - the `@readOnly`/`@destructive`/`@idempotent`/`@hintTitle` marker UDAs are
///     reflected into each tool's `ToolAnnotations`;
///   - calling `calc` yields the expected `structuredContent` (struct return);
///   - the optional `round` arg flows through;
///   - a scalar-returning tool wraps its value under `result`;
///   - a string tool returns plain text content (no structuredContent);
///   - a bad call (unknown tool) raises the expected JSON-RPC error code.
///
/// Prints "OK: ..." and exits 0 on success; on ANY mismatch it prints what
/// differed and exits non-zero. This makes the example double as a CI e2e test.
module tools_client;

import std.math : isClose;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.string : stripRight;

import vibe.data.json : Json;

import mcp.client.client : McpClient;
import mcp.protocol.errors : ErrorCode, McpException;
import mcp.protocol.types : CallToolResult, Tool, ToolAnnotations;

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

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client (a stack
/// value would be destructed when the spawning helper returns).
final class ServerProcess
{
	private ProcessPipes pipes;

	this(string[] command) @trusted
	{
		pipes = pipeProcess(command, Redirect.stdin | Redirect.stdout);
	}

	/// Read one response line (terminator stripped), or null at EOF.
	string readLine() @trusted
	{
		auto f = pipes.stdout;
		if (f.eof)
			return null;
		auto ln = f.readln();
		if (ln.length == 0 && f.eof)
			return null;
		return ln.stripRight("\r\n");
	}

	/// Write one request line (the channel appends the terminator).
	void writeLine(string s) @trusted
	{
		pipes.stdin.writeln(s);
		pipes.stdin.flush();
	}

	/// Close stdin and reap the child.
	void shutdown() @trusted
	{
		pipes.stdin.close();
		wait(pipes.pid);
	}
}

/// Read a JSON number as a double, tolerating integral encodings (vibe encodes a
/// whole-valued double like 7.0 as an int).
private double asDouble(Json j) @safe
{
	if (j.type == Json.Type.int_)
		return cast(double) j.get!long;
	return j.get!double;
}

int main(string[] args) @safe
{
	// Resolve the server binary next to this client binary (dub writes both into
	// the package root), independent of the current working directory.
	auto proc = new ServerProcess([serverBinaryPath()]);
	scope (exit)
		proc.shutdown();

	auto client = McpClient.stdio(&proc.readLine, &proc.writeLine);

	auto init = client.initialize();
	check(init.serverInfo.name == "tools-example",
		"serverInfo.name = " ~ init.serverInfo.name ~ " (want tools-example)");

	// --- tools/list ---------------------------------------------------------
	auto tools = client.listTools().tools;
	import std.algorithm : map, canFind;
	import std.array : array;

	auto names = tools.map!(t => t.name).array;
	foreach (want; ["calc", "magnitude", "greet", "erase"])
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
	{
		auto a = ToolAnnotations.fromJson(calc.annotations);
		check(!a.readOnlyHint.isNull && a.readOnlyHint.get, "calc should be readOnlyHint:true");
		check(!a.idempotentHint.isNull && a.idempotentHint.get, "calc should be idempotentHint:true");
		check(!a.title.isNull && a.title.get == "Calculator",
			"calc hintTitle should be 'Calculator'");

		auto er = ToolAnnotations.fromJson(find(tools, "erase").annotations);
		check(!er.destructiveHint.isNull && er.destructiveHint.get,
			"erase should be destructiveHint:true");
	}

	// --- call `calc` (struct return -> structuredContent) ------------------
	{
		Json a = Json.emptyObject;
		a["op"] = "add";
		a["a"] = 3.0;
		a["b"] = 4.0;
		auto r = client.callTool("calc", a);
		check(!r.isError, "calc add should not be an error");
		auto sc = r.structuredContent;
		// The enum return field serializes as its ordinal: Op.add == 0.
		check(sc["op"].get!int == 0, "calc structuredContent.op should be Op.add (0)");
		check(isClose(asDouble(sc["result"]), 7.0), "calc 3+4 should be 7");
	}

	// --- optional `round` argument flows through ---------------------------
	{
		Json a = Json.emptyObject;
		a["op"] = "mul";
		a["a"] = 1.0 / 3.0;
		a["b"] = 1.0;
		a["round"] = 2;
		auto r = client.callTool("calc", a);
		check(isClose(asDouble(r.structuredContent["result"]), 0.33),
			"calc (1/3) rounded to 2 dp should be 0.33");
	}

	// --- scalar return wrapped under `result` ------------------------------
	{
		Json a = Json.emptyObject;
		Json v = Json.emptyObject;
		v["x"] = 3.0;
		v["y"] = 4.0;
		a["v"] = v;
		auto r = client.callTool("magnitude", a);
		check(isClose(asDouble(r.structuredContent["result"]), 5.0),
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
	writeln("OK: tools example e2e passed — listTools names, enum/struct/optional schemas, ",
		"readOnly/destructive/idempotent annotations, struct+scalar+string results, and ",
		"unknown-tool error code all verified.");
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
