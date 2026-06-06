/// End-to-end coverage for the `HttpClientTransport` SSE/streaming flows that the
/// modern POST-and-await round-trip (see `mcp.transport.peer_roundtrip_test`) does
/// not exercise: the legacy 2024-11-05 HTTP+SSE two-endpoint fallback, the
/// standalone server->client GET SSE stream, the draft `subscriptions/listen`
/// stream, and Last-Event-ID resumption of a dropped POST response stream.
///
/// Each test drives a real `McpClient.http` against a real HTTP server over a
/// loopback socket. Where the SDK's own server implements the server side of a
/// flow it is used directly (true SDK-client <-> SDK-server e2e); resumability,
/// which requires a server that drops a POST stream mid-response and replays the
/// reply on a later GET, is driven against a purpose-built fake server.
///
/// Protocol-version constraints these tests pin (verified against the spec):
///   - Legacy HTTP+SSE two-endpoint transport is the 2024-11-05 transport.
///   - The standalone GET SSE stream and Last-Event-ID resumability exist in the
///     Streamable HTTP revisions 2025-03-26 / 2025-06-18 / 2025-11-25, and were
///     REMOVED in the draft/modern (2026-07-28) redesign.
///   - `subscriptions/listen` is a draft/modern feature; it does not exist before.
module mcp.client.http_streaming_test;

version (unittest)
{
	import std.conv : to;
	import core.time : msecs, MonoTime;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
	import vibe.data.json : Json, parseJsonString;
	import vibe.stream.operations : readAllUTF8;
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	import mcp.server.server : McpServer;
	import mcp.server.context : RequestContext;
	import mcp.client.client : McpClient;
	import mcp.protocol.types : CallToolResult, Content, Tool;
	import mcp.protocol.versions : ProtocolVersion;
	import mcp.client.subscription : SubscriptionFilter, SubscriptionStream;
	import mcp.transport.streamable_http : mountMcp, StreamableHttpOptions;

	// Release a client's connections from a nothrow event-loop body without
	// letting close() throw out of it.
	void closeQuietly(McpClient c) @safe nothrow
	{
		try
			c.close();
		catch (Exception)
		{
		}
	}
}

// Legacy HTTP+SSE (2024-11-05) two-endpoint fallback: a client pointed at a URL
// that only speaks the old transport must POST (and be 404'd), open the GET SSE
// stream, read the `endpoint` event, then run every request as a POST-to-endpoint
// whose response arrives asynchronously on the GET stream. Driven against the
// SDK's own server with `legacyHttpSse` enabled.
unittest
{
	// The legacy two-endpoint transport correlates a POST's reply to its GET
	// stream via a per-stream session token, so the server is stateful.
	auto server = McpServer.stateful("legacy-e2e", "1.0.0");

	Tool tool;
	tool.name = "echo";
	tool.description = "Returns a fixed string";
	server.registerDynamicTool(tool, (Json args, RequestContext ctx) @safe {
		return CallToolResult([Content.makeText("legacy-ok")]);
	});

	auto router = new URLRouter;
	StreamableHttpOptions opts;
	// Also host the deprecated 2024-11-05 GET /sse + POST /message endpoints.
	opts.legacyHttpSse = true;
	mountMcp(router, server, opts);

	auto settings = new HTTPServerSettings;
	settings.port = 0; // ephemeral
	settings.bindAddresses = ["127.0.0.1"];

	bool completed;
	string finalText;
	string failure;
	ProtocolVersion negotiated;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddresses[0].port;
			// Point the client at the LEGACY SSE endpoint. A POST to /sse has no
			// route (only GET), so the server answers 404 -> the client's modern
			// POST-and-await raises LegacyFallbackException -> connect() opens the
			// legacy two-endpoint transport.
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/sse";

			auto client = McpClient.http(url);
			scope (exit)
				closeQuietly(client);

			negotiated = client.connect();

			auto res = client.callTool("echo", Json.emptyObject);
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

	assert(failure.length == 0, "legacy fallback failed: " ~ failure);
	assert(negotiated == ProtocolVersion.v2024_11_05,
			"expected to negotiate 2024-11-05 over the legacy transport");
	assert(completed, "legacy round-trip never completed");
	assert(finalText == "legacy-ok", "unexpected tool result: " ~ finalText);
}

// Standalone server->client GET SSE stream (Streamable HTTP, 2025-11-25): after
// initialize, the client opens a standalone GET SSE stream; a server-initiated
// broadcast notification (`notifications/tools/list_changed`) must arrive on that
// stream and reach the client's inbound `onNotification` handler. This stream is a
// stable-revision feature gated by `getOpensSseStream` (2025-03-26 / 2025-06-18 /
// 2025-11-25) and requires a stateful server; the draft removed it.
unittest
{
	// `getOpensSseStream` requires a stateful server: a stateless one answers the
	// standalone GET with 405, so there is no stream to push onto.
	auto server = McpServer.stateful("server-stream-e2e", "1.0.0");

	auto router = new URLRouter;
	mountMcp(router, server);

	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];

	bool received;
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
			scope (exit)
				closeQuietly(client);

			client.onNotification = (string method, Json params) @safe {
				if (method == "notifications/tools/list_changed")
					received = true;
			};

			// Pin a stable revision that opens the standalone GET stream.
			client.initialize("2025-11-25");
			client.startServerStream();

			// Broadcast until the client reports receipt (bounded). Re-broadcasting
			// closes the race where the first notify is emitted before the client's
			// background GET stream has registered as a listener server-side.
			const deadline = MonoTime.currTime + 5000.msecs;
			while (!received && MonoTime.currTime < deadline)
			{
				server.notifyToolsListChanged();
				sleep(50.msecs);
			}
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "server-stream test failed: " ~ failure);
	assert(received,
			"client never received the server-initiated notification on the standalone GET stream");
}

// Draft `subscriptions/listen` stream (draft/modern, 2026-07-28): the client POSTs
// `subscriptions/listen`, the server upgrades the response to a long-lived SSE
// stream whose FIRST event is `notifications/subscriptions/acknowledged`, and
// every subsequent opted-in change notification streams down the SAME response.
// Both must reach the client's `onNotification`. This RPC does not exist before
// the draft, so the client negotiates draft via `connect()`. The draft transport
// is stateless-only, so the server is stateless.
unittest
{
	auto server = McpServer.stateless("listen-e2e", "1.0.0");
	// Advertise tools listChanged so the server (a) emits the capability the client
	// opts into and (b) honours `toolsListChanged:true` in the listen filter; an
	// opt-in for an unadvertised capability is correctly dropped server-side.
	server.enableToolsListChanged();

	auto router = new URLRouter;
	mountMcp(router, server);

	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];

	bool acked;
	bool changed;
	string failure;
	ProtocolVersion negotiated;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddresses[0].port;
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/mcp";

			auto client = McpClient.http(url);
			scope (exit)
				closeQuietly(client);

			client.onNotification = (string method, Json params) @safe {
				if (method == "notifications/subscriptions/acknowledged")
					acked = true;
				else if (method == "notifications/tools/list_changed")
					changed = true;
			};

			// Auto-negotiate: a draft-framed server/discover probe resolves to the
			// modern (draft) revision, the only one that implements this RPC.
			negotiated = client.connect();

			SubscriptionFilter filter;
			filter.toolsListChanged = true;
			auto stream = client.subscriptionsListen(filter);
			scope (exit)
				stream.close();

			// The acknowledgement is the stream's leading event; once the listen
			// stream is registered server-side, a notify reaches it as a change event.
			// Re-broadcasting closes the connect/register race.
			const deadline = MonoTime.currTime + 5000.msecs;
			while (!(acked && changed) && MonoTime.currTime < deadline)
			{
				server.notifyToolsListChanged();
				sleep(50.msecs);
			}
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "subscriptions/listen test failed: " ~ failure);
	assert(negotiated == ProtocolVersion.modern,
			"expected to negotiate the draft/modern revision for subscriptions/listen");
	assert(acked,
			"client never received the leading subscriptions/acknowledged event on the listen stream");
	assert(changed, "client never received a change notification on the listen stream");
}

// Last-Event-ID resumption of a dropped POST response stream (Streamable HTTP,
// 2025-11-25). When a request's POST opens an SSE response that emits a `retry:`
// hint and an event `id:` but then closes WITHOUT the JSON-RPC response, the
// client MUST wait the retry delay and resume by re-issuing the request as an HTTP
// GET carrying `Last-Event-ID`; the server replays the response on that stream
// (basic/transports §Resumability and Redelivery). Resumability exists only in the
// stable Streamable HTTP revisions (2025-03-26 / 2025-06-18 / 2025-11-25) and was
// removed in the draft; `postAndAwait` skips the GET resume when the negotiated
// version is draft. Driven against a purpose-built fake server: the SDK's own
// server never drops a POST stream mid-response, so it cannot exercise this path.
unittest
{
	bool getResumed;
	bool completed;
	string failure;
	size_t toolCount = size_t.max;
	// Carries the dropped request's JSON-RPC id from the POST handler to the GET
	// handler so the replayed response correlates to the awaited request.
	long droppedId = -1;

	auto router = new URLRouter;
	router.post("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		const payload = () @trusted { return req.bodyReader.readAllUTF8(); }();
		auto j = parseJsonString(payload);
		const method = ("method" in j) ? j["method"].get!string : "";

		if (method == "initialize")
		{
			auto resp = parseJsonString(
				`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25",`
				~ `"capabilities":{},"serverInfo":{"name":"resume-fake","version":"1.0"}}}`);
			resp["id"] = j["id"];
			res.writeBody(resp.toString(), "application/json");
			return;
		}
		if (method == "tools/list")
		{
			// Open an SSE response, emit a `retry:` delay and an event `id:`, then
			// close the connection WITHOUT the JSON-RPC response — the trigger for
			// the client's Last-Event-ID resume.
			droppedId = j["id"].get!long;
			res.contentType = "text/event-stream";
			() @trusted {
				res.bodyWriter.write(cast(const(ubyte)[]) "retry: 50\r\nid: evt-1\r\n");
				res.bodyWriter.flush();
			}();
			return; // handler returns -> stream closes (EOF) with no response
		}
		// notifications/initialized and any other oneway: just acknowledge.
		res.statusCode = 202;
		res.writeBody("", "text/plain");
	});
	router.get("/mcp", (HTTPServerRequest req, HTTPServerResponse res) @safe {
		// The resume GET must carry the Last-Event-ID the dropped stream emitted.
		const lastId = req.headers.get("Last-Event-ID", "");
		if (lastId != "evt-1")
		{
			res.statusCode = 405;
			res.writeBody("", "text/plain");
			return;
		}
		getResumed = true;
		auto resp = parseJsonString(`{"jsonrpc":"2.0","id":0,"result":{"tools":[]}}`);
		resp["id"] = Json(droppedId);
		res.contentType = "text/event-stream";
		const frame = "id: evt-2\r\ndata: " ~ resp.toString() ~ "\r\n\r\n";
		() @trusted {
			res.bodyWriter.write(cast(const(ubyte)[]) frame);
			res.bodyWriter.flush();
		}();
	});

	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddresses[0].port;
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/mcp";

			auto client = McpClient.http(url);
			scope (exit)
				closeQuietly(client);

			// A stable revision: the draft skips Last-Event-ID resume entirely.
			client.initialize("2025-11-25");
			// The POST for this request is dropped mid-stream; the result can only
			// arrive via the client's Last-Event-ID GET resume.
			auto res = client.listTools();
			toolCount = res.tools.length;
			completed = true;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "resume test failed: " ~ failure);
	assert(getResumed, "client never issued the Last-Event-ID resume GET");
	assert(completed, "listTools never completed; the dropped response was not resumed");
	assert(toolCount == 0, "resumed response did not decode as the empty tool list");
}
