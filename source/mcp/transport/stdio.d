module mcp.transport.stdio;

import mcp.server.server;

@safe:

/// Drive an `MCPServer` over a newline-delimited JSON-RPC channel.
///
/// `readLine` returns the next line (without its terminator), or `null` at
/// end-of-input. `writeLine` emits one response line (a terminator is added by
/// the caller's sink). Blank input lines are ignored. This is transport-pure —
/// `runStdio` wires it to the process's real stdin/stdout.
///
/// The MCP stdio transport permits the server to write any valid MCP message to
/// stdout at any time, not only direct request replies. A tool handler that
/// emits `notifications/message` (logging) or `notifications/progress` through
/// its `RequestContext` therefore has those frames written to `writeLine`
/// out-of-band, before the originating request's response — so a server that
/// advertises the `logging` capability over stdio can actually deliver it.
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
		// `writeLine` is the server->client channel: handlers' notifications are
		// emitted through it as they happen, and the request's reply (if any)
		// follows.
		const response = server.handleRaw(line, writeLine);
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
	import mcp.server.context : RequestContext;
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

unittest  // a tool handler's ctx.log() is delivered as a notifications/message frame over stdio
{
	auto s = new MCPServer("logsrv", "1.0");
	s.enableLogging();
	Tool logger = {name: "logit"};
	s.registerTool(logger, (Json args, RequestContext ctx) @safe {
		ctx.log("error", Json("boom"), "mylogger");
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"logit"}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// The log notification is written out-of-band BEFORE the request's response.
	assert(outputs.length == 2);
	auto note = parseJsonString(outputs[0]);
	assert(note["method"].get!string == "notifications/message");
	assert(note["params"]["level"].get!string == "error");
	assert(note["params"]["logger"].get!string == "mylogger");
	assert(note["params"]["data"].get!string == "boom");
	assert("id" !in note); // a notification carries no id
	// The tool response follows.
	auto resp = parseJsonString(outputs[1]);
	assert(resp["id"].get!int == 1);
}

unittest  // logging below the configured minimum level is dropped over stdio
{
	auto s = new MCPServer("logsrv", "1.0");
	s.enableLogging();
	Tool logger = {name: "logit"};
	s.registerTool(logger, (Json args, RequestContext ctx) @safe {
		ctx.log("debug", Json("noise")); // below minimum -> dropped
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	// Raise the minimum to "error" via logging/setLevel, then call the tool.
	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"error"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"logit"}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// Two responses (setLevel + tools/call); the sub-minimum log is filtered out
	// so no notifications/message frame appears.
	assert(outputs.length == 2);
	foreach (o; outputs)
		assert(parseJsonString(o)["method"].type == Json.Type.undefined);
	assert(parseJsonString(outputs[1])["id"].get!int == 2);
}

unittest  // reportProgress is delivered over stdio when the request carries a progressToken
{
	auto s = new MCPServer("progsrv", "1.0");
	Tool worker = {name: "work"};
	s.registerTool(worker, (Json args, RequestContext ctx) @safe {
		ctx.reportProgress(0.5, nullable(1.0), "halfway");
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"work","_meta":{"progressToken":"p1"}}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	assert(outputs.length == 2);
	auto note = parseJsonString(outputs[0]);
	assert(note["method"].get!string == "notifications/progress");
	assert(note["params"]["progressToken"].get!string == "p1");
	assert(note["params"]["progress"].get!double == 0.5);
	auto resp = parseJsonString(outputs[1]);
	assert(resp["id"].get!int == 1);
}

unittest  // reportProgress without a progressToken emits nothing over stdio
{
	auto s = new MCPServer("progsrv", "1.0");
	Tool worker = {name: "work"};
	s.registerTool(worker, (Json args, RequestContext ctx) @safe {
		ctx.reportProgress(0.5); // no token on the request -> dropped
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"work"}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	assert(outputs.length == 1);
	auto resp = parseJsonString(outputs[0]);
	assert(resp["id"].get!int == 1);
}
