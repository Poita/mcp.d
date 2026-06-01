module mcp.transport.stdio;

import mcp.server.server;

@safe:

/// Drive an `McpServer` over a newline-delimited JSON-RPC channel.
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
void serveStdio(McpServer server, scope string delegate() @safe readLine,
		scope void delegate(string) @safe writeLine)
{
	import vibe.data.json : Json, parseJsonString;
	import mcp.protocol.errors : McpException, internalError, ErrorCode;

	long serverReqId = 0;

	// True when `idJson` is the integer id we assigned to an outstanding
	// server->client request.
	static bool idMatches(Json idJson, long want) @safe
	{
		return idJson.type == Json.Type.int_ && idJson.get!long == want;
	}

	// The server->client request channel. The MCP stdio transport is
	// bidirectional, so a tool handler may issue a request (sampling/elicitation)
	// mid-flight: write the request frame, then pump stdin until the matching-id
	// reply arrives, returning its `result` (or throwing on `error`). Any
	// interleaved inbound client message (a notification such as
	// `notifications/cancelled`, or another request) read while waiting is
	// dispatched through the normal path, recursing this same channel so a nested
	// server->client request also works.
	Json serverRequest(string method, Json params) @safe
	{
		serverReqId++;
		const myId = serverReqId;
		Json req = Json.emptyObject;
		req["jsonrpc"] = "2.0";
		req["id"] = myId;
		req["method"] = method;
		if (params.type != Json.Type.undefined)
			req["params"] = params;
		writeLine(req.toString());

		for (;;)
		{
			auto resp = readLine();
			if (resp is null)
				throw internalError("client closed stdin during a server->client request");
			if (resp.length == 0)
				continue;
			Json j;
			bool parsed = true;
			try
				j = parseJsonString(resp);
			catch (Exception)
				parsed = false;
			if (parsed && j.type == Json.Type.object && "method" !in j && "id" in j
					&& idMatches(j["id"], myId))
			{
				if ("error" in j && j["error"].type == Json.Type.object)
				{
					const err = j["error"];
					const code = ("code" in err) ? err["code"].get!int : cast(
							int) ErrorCode.internalError;
					const msg = ("message" in err) ? err["message"].get!string : "client error";
					throw new McpException(code, msg, err);
				}
				return ("result" in j) ? j["result"] : Json.emptyObject;
			}
			// An interleaved inbound message (not our reply): dispatch it normally.
			const inner = server.handleRaw(resp, writeLine, &serverRequest);
			if (inner.length)
				writeLine(inner);
		}
	}

	for (;;)
	{
		auto line = readLine();
		if (line is null)
			break; // end of input
		if (line.length == 0)
			continue;
		// Draft `subscriptions/listen` shares the single stdout channel here, so
		// it is not a one-shot request/reply: the server records the opted-in
		// filters and writes a `notifications/subscriptions/acknowledged`
		// notification (the spec's leading message, stamped with the listen id as
		// the subscriptionId) instead of the non-spec `{ acknowledged: true }`
		// JSON-RPC result. Subsequent `notify*` output is then routed to
		// `writeLine`, stamped with the same subscriptionId. A non-listen line (or
		// a pre-draft listen) falls through to the normal request/reply path.
		if (tryServeStdioListen(server, line, writeLine))
			continue;
		// `writeLine` is the server->client channel: handlers' notifications are
		// emitted through it as they happen, and the request's reply (if any)
		// follows. `serverRequest` lets a handler issue a blocking server->client
		// request (sampling/elicitation) that the client answers on stdin.
		const response = server.handleRaw(line, writeLine, &serverRequest);
		if (response.length)
			writeLine(response);
	}
}

/// Transport-side shim: parse a single stdio line and, if it is a draft
/// `subscriptions/listen` request, serve it on the shared stdout channel via
/// `McpServer.tryServeStdioListen` (writing the leading
/// `notifications/subscriptions/acknowledged` notification instead of a
/// non-spec `{ acknowledged: true }` result). Returns `true` when the line was
/// consumed as a listen request; `false` (including on a parse failure or a
/// batch) so the caller dispatches it through the normal request/reply path.
private bool tryServeStdioListen(McpServer server, string line,
		void delegate(string) @safe writeLine) @safe
{
	import mcp.protocol.jsonrpc : parseAny;

	try
	{
		auto input = parseAny(line);
		if (input.isBatch || input.messages.length != 1)
			return false;
		return server.tryServeStdioListen(input.messages[0], writeLine);
	}
	catch (Exception)
		return false; // let handleRaw produce the proper parse-error response
}

/// Serve `server` over the process's standard input/output: read JSON-RPC
/// messages from stdin (one per line) and write responses to stdout. Per the
/// MCP stdio transport, only valid MCP messages are written to stdout; use
/// stderr for logging. Blocks until stdin reaches end-of-file.
void runStdio(McpServer server)
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
	auto s = new McpServer("stdio-srv", "1.0");
	Tool echo = {name: "echo"};
	s.registerDynamicTool(echo, (Json args) @safe {
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

unittest  // stdio: a tool calling ctx.elicit is answered over the same stdio channel
{
	import mcp.protocol.types : ElicitAction;

	auto s = new McpServer("stdio-peer", "1.0");
	Tool ask = {name: "ask"};
	s.registerDynamicTool(ask, (Json args, RequestContext ctx) @safe {
		auto schema = Json(["type": Json("object")]);
		auto reply = ctx.elicit("What is your name?", schema);
		const name = (reply.action == ElicitAction.accept) ? reply.content["name"].get!string
			: "(declined)";
		CallToolResult r;
		r.content = [Content.makeText("hi:" ~ name)];
		return r;
	});

	// The client declares elicitation at initialize, then calls the tool. When
	// the server emits its server->client elicitation request (server-assigned
	// id 1), the NEXT input line is the client's reply on the same channel.
	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"action":"accept","content":{"name":"Ada"}}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// The server must have emitted an elicitation/create request frame...
	bool sawElicitRequest;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if (j.type == Json.Type.object && "method" in j
				&& j["method"].get!string == "elicitation/create")
			sawElicitRequest = true;
	}
	assert(sawElicitRequest, "server never emitted a server->client elicitation/create request");

	// ...and the tools/call (id 2) reply must reflect the elicited value.
	bool sawResult;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if (j.type == Json.Type.object && "id" in j && j["id"].get!int == 2 && "result" in j)
		{
			assert(j["result"]["content"][0]["text"].get!string == "hi:Ada");
			sawResult = true;
		}
	}
	assert(sawResult, "tools/call reply with the elicited value was never produced");
}

unittest  // serveStdio stops at end-of-input (null line)
{
	auto s = new McpServer("t", "1");
	size_t calls;
	serveStdio(s, () @safe { calls++; return cast(string) null; }, (string) @safe {
	});
	assert(calls == 1);
}

unittest  // a tool handler's ctx.log() is delivered as a notifications/message frame over stdio
{
	auto s = new McpServer("logsrv", "1.0");
	s.enableLogging();
	Tool logger = {name: "logit"};
	s.registerDynamicTool(logger, (Json args, RequestContext ctx) @safe {
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
	auto s = new McpServer("logsrv", "1.0");
	s.enableLogging();
	Tool logger = {name: "logit"};
	s.registerDynamicTool(logger, (Json args, RequestContext ctx) @safe {
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
	auto s = new McpServer("progsrv", "1.0");
	Tool worker = {name: "work"};
	s.registerDynamicTool(worker, (Json args, RequestContext ctx) @safe {
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
	auto s = new McpServer("progsrv", "1.0");
	Tool worker = {name: "work"};
	s.registerDynamicTool(worker, (Json args, RequestContext ctx) @safe {
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

version (unittest)
{
	import mcp.protocol.draft : MetaKey;

	// A draft `subscriptions/listen` request line carrying per-request _meta
	// (protocolVersion draft) and a nested `notifications` SubscriptionFilter.
	private string draftListenLine(long id, Json filter) @safe
	{
		import mcp.protocol.jsonrpc : makeRequest;

		Json meta = Json.emptyObject;
		meta[MetaKey.protocolVersion] = "2026-07-28";
		meta[MetaKey.clientCapabilities] = Json.emptyObject;
		Json params = Json.emptyObject;
		params["notifications"] = filter;
		params["_meta"] = meta;
		return makeRequest(Json(id), "subscriptions/listen", params).toString();
	}
}

unittest  // draft subscriptions/listen over stdio sends the acknowledged notification, not a {acknowledged:true} result
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;

	string[] inputs = [draftListenLine(7, filter)];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// Exactly one message: the leading acknowledgement notification.
	assert(outputs.length == 1);
	auto ack = parseJsonString(outputs[0]);
	// It is a notification (no id), with the spec method, NOT a JSON-RPC result.
	assert(ack["method"].get!string == "notifications/subscriptions/acknowledged");
	assert("id" !in ack);
	assert("result" !in ack);
	// The invented {acknowledged:true} result must never appear over stdio.
	assert(ack["params"]["notifications"].type == Json.Type.object);
	assert("acknowledged" !in ack["params"]);
	// The agreed subset echoes the opted-in toolsListChanged.
	assert(ack["params"]["notifications"]["toolsListChanged"].get!bool);
}

unittest  // the stdio acknowledged notification is stamped with the listen id as the subscriptionId
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;

	string[] inputs = [draftListenLine(42, filter)];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	assert(outputs.length == 1);
	auto ack = parseJsonString(outputs[0]);
	assert(ack["params"]["_meta"][MetaKey.subscriptionId].get!string == "42");
}

unittest  // after a stdio subscriptions/listen, notify* change notifications flow on stdout, stamped with the subscriptionId
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;

	string[] inputs = [draftListenLine(5, filter)];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// The ack arrived first.
	assert(outputs.length == 1);

	// A runtime change now emits tools/list_changed onto the same stdout channel,
	// stamped with the subscriptionId. (Before the fix, pushChannel was null over
	// stdio so this delivered nothing.)
	const delivered = s.notifyToolsListChanged();
	assert(delivered == 1);
	assert(outputs.length == 2);
	auto note = parseJsonString(outputs[1]);
	assert(note["method"].get!string == "notifications/tools/list_changed");
	assert("id" !in note);
	assert(note["params"]["_meta"][MetaKey.subscriptionId].get!string == "5");
}

unittest  // a pre-draft (no protocolVersion) subscriptions/listen still takes the normal request/reply path over stdio
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	// No draft _meta: opensListenStream is false, so this is dispatched normally.
	string[] inputs = [
		`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`,
	];
	size_t i;
	string[] outputs;
	serveStdio(s, () @safe { return i < inputs.length ? inputs[i++] : null; }, (string line) @safe {
		outputs ~= line;
	});

	// One ordinary JSON-RPC response with the legacy {acknowledged:true} result.
	assert(outputs.length == 1);
	auto resp = parseJsonString(outputs[0]);
	assert(resp["id"].get!int == 1);
	assert(resp["result"]["acknowledged"].get!bool);
}
