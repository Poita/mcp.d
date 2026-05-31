module mcp.transport.stdio;

import mcp.server.server;

@safe:

/// Drive an `MCPServer` over a newline-delimited JSON-RPC channel.
///
/// `readLine` returns the next line (without its terminator), or `null` at
/// end-of-input. `writeLine` emits one response line (a terminator is added by
/// the caller's sink). Blank input lines are ignored. This is transport-pure —
/// `runStdio` wires it to the process's real stdin/stdout.
void serveStdio(MCPServer server, scope string delegate() @safe readLine,
		scope void delegate(string) @safe writeLine)
{
	for (;;)
	{
		auto line = readLine();
		if (line is null)
			break; // end of input
		if (line.length == 0)
			continue;
		const response = server.handleRaw(line);
		if (response.length)
			writeLine(response);
	}
}

/// Serve `server` over the process's standard input/output: read JSON-RPC
/// messages from stdin (one per line) and write responses to stdout. Per the
/// MCP stdio transport, only valid MCP messages are written to stdout; use
/// stderr for logging. Blocks until stdin reaches end-of-file.
void runStdio(MCPServer server)
{
	() @trusted {
		import std.stdio : stdin, stdout;

		serveStdio(server, () @trusted {
			auto ln = stdin.readln();
			if (ln.length == 0 && stdin.eof)
				return null;
			import std.string : stripRight;

			return ln.stripRight("\r\n");
		}, (string s) @trusted { stdout.writeln(s); stdout.flush(); });
	}();
}

version (unittest)
{
	import std.typecons : nullable;
	import vibe.data.json : Json, parseJsonString;
	import mcp.protocol.types : Tool, CallToolResult, Content;
}

unittest  // serveStdio processes newline-delimited requests and writes responses
{
	auto s = new MCPServer("stdio-srv", "1.0");
	Tool echo = {name: "echo"};
	s.registerTool(echo, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});

	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`, ``, // blank line ignored
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // no reply
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// ping (id 1) and tools/list (id 2) produce responses; the notification does not.
	assert(outputs.length == 2);
	auto r0 = parseJsonString(outputs[0]);
	assert(r0["id"].get!int == 1);
	auto r1 = parseJsonString(outputs[1]);
	assert(r1["id"].get!int == 2);
	assert(r1["result"]["tools"][0]["name"].get!string == "echo");
}

unittest  // serveStdio stops at end-of-input (null line)
{
	auto s = new MCPServer("t", "1");
	size_t calls;
	serveStdio(s, () @safe { calls++; return cast(string) null; }, (string) @safe {
	});
	assert(calls == 1);
}
