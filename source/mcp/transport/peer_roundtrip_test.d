/// End-to-end test of the server->client request round-trip between THIS SDK's
/// own `McpServer` and `McpClient`, over a real Streamable HTTP transport.
///
/// This is the gap the conformance suite never exercised (issue #377): the
/// server suite answers OUR server with the harness client, and the client suite
/// answers the harness server with OUR client, but neither runs OUR server and
/// OUR client against each other. A tool that calls `ctx.sample`/`ctx.elicit`
/// emits a server->client request on its POST's SSE stream and blocks in
/// `StreamCoordinator.await`; the client must answer it on a SEPARATE POST while
/// its own fiber is still reading that SSE stream. With vibe.d's keep-alive
/// connection pool the reply POST would block waiting for the in-flight request's
/// connection to be released -- a deadlock that timed out the server after 60s.
module mcp.transport.peer_roundtrip_test;

version (unittest)
{
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.data.json : Json;
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerSettings, listenHTTP;

	import mcp.server.server : McpServer;
	import mcp.server.context : RequestContext;
	import mcp.client.client : McpClient;
	import mcp.protocol.types : CallToolResult, Content, Tool;
	import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
	import mcp.protocol.types : ElicitParams, ElicitResult, ElicitAction;
	import mcp.transport.streamable_http : mountMcp, StreamableHttpOptions;
}

// Round-trip: OUR server runs a tool that calls ctx.sample; OUR HTTP client
// answers the sampling request via its onSampling handler. The whole call must
// complete (no 60s coordinator timeout). Before the fix the client's reply POST
// deadlocked on the keep-alive connection still held by the in-flight tool-call
// SSE read, so the server's coord.await never resolved.
unittest
{
	// #550 Stage 3: a server->client request (ctx.sample) over HTTP requires a
	// session, so this round-trip server is STATEFUL (a stateless server forbids
	// it). OUR HTTP client captures + echoes Mcp-Session-Id, so the round trip
	// works end to end.
	auto server = McpServer.stateful("peer-e2e", "1.0.0");

	Tool tool;
	tool.name = "echo_sample";
	tool.description = "Echoes the client's sampled text";
	bool toolReached;
	server.registerDynamicTool(tool, (Json args, RequestContext ctx) @safe {
		toolReached = true;
		Json sp = Json.emptyObject;
		Json messages = Json.emptyArray;
		Json m = Json.emptyObject;
		m["role"] = "user";
		Json c = Json.emptyObject;
		c["type"] = "text";
		c["text"] = "ping";
		m["content"] = c;
		messages ~= m;
		sp["messages"] = messages;
		sp["maxTokens"] = 16;
		auto reply = ctx.sample(sp); // server->client request; blocks on coord.await
		auto text = reply["content"]["text"].get!string;
		return CallToolResult([Content.makeText("sampled:" ~ text)]);
	});

	auto router = new URLRouter;
	mountMcp(router, server);
	auto settings = new HTTPServerSettings;
	settings.port = 0; // ephemeral
	settings.bindAddresses = ["127.0.0.1"];

	bool completed;
	string finalText;
	string failure;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddresses[0].port;
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/mcp";

			auto client = McpClient.http(url);
			client.onSampling = (CreateMessageRequest request) @safe {
				CreateMessageResult r;
				r.role = "assistant";
				r.content = Content.makeText("pong");
				r.model = "test-model";
				r.stopReason = "endTurn";
				return r;
			};
			// Pin a stable (2025-era) version so the BLOCKING sampling path is
			// exercised (the draft would route through MRTR / inputRequired).
			client.initialize("2025-11-25");

			auto res = client.callTool("echo_sample", Json.emptyObject);
			if (res.content.length)
				finalText = res.content[0].text;
			completed = true;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	import vibe.core.core : runTask;

	runTask(body_);
	runEventLoop();

	assert(toolReached, "tool handler was never reached");
	assert(failure.length == 0, "round-trip failed: " ~ failure);
	assert(completed, "callTool never completed (server->client deadlock)");
	assert(finalText == "sampled:pong", "unexpected tool result: " ~ finalText);
}

// Round-trip: a tool that calls ctx.elicit must be answered by the client's
// onElicitation handler over HTTP (the elicitation counterpart of the sampling
// test above; covers the elicitation half of #377 / example #355).
unittest
{
	// #550 Stage 3: ctx.elicit is a server->client request; over HTTP it requires
	// a session, so this round-trip server is STATEFUL (see the sampling test above).
	auto server = McpServer.stateful("peer-e2e-elicit", "1.0.0");

	Tool tool;
	tool.name = "ask_name";
	tool.description = "Asks the client for the user's name";
	server.registerDynamicTool(tool, (Json args, RequestContext ctx) @safe {
		Json schema = Json.emptyObject;
		schema["type"] = "object";
		auto reply = ctx.elicit("What is your name?", schema); // server->client request
		auto name = (reply.action == ElicitAction.accept) ? reply.content["name"].get!string
			: "(declined)";
		return CallToolResult([Content.makeText("hello:" ~ name)]);
	});

	auto router = new URLRouter;
	mountMcp(router, server);
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];

	bool completed;
	string finalText;
	string failure;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddresses[0].port;
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/mcp";

			auto client = McpClient.http(url);
			// Advertise form-mode elicitation explicitly (the client validates inbound
			// requests against its declared capabilities, not the auto-derived set).
			client.capabilities.elicitation = true;
			client.capabilities.elicitationForm = true;
			client.onElicitation = (ElicitParams params) @safe {
				Json content = Json.emptyObject;
				content["name"] = "Ada";
				return ElicitResult.accept(content);
			};
			client.initialize("2025-11-25");

			auto res = client.callTool("ask_name", Json.emptyObject);
			if (res.content.length)
				finalText = res.content[0].text;
			completed = true;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "elicitation round-trip failed: " ~ failure);
	assert(completed, "callTool never completed (server->client deadlock)");
	assert(finalText == "hello:Ada", "unexpected tool result: " ~ finalText);
}
