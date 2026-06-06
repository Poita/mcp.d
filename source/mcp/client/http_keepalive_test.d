/// Coverage for the `HttpClientTransport` keep-alive connection reuse on the
/// ordinary request/response path. When the owning client has registered no
/// server->client handler (sampling / elicitation / roots), a tool call cannot
/// trigger a server->client request that must be answered on a separate POST
/// while this POST's SSE response is still being read, so the request/response
/// path is carried over vibe's pooled keep-alive connection and reused across
/// calls rather than torn down per request.
///
/// The test points the transport at a raw TCP server that counts accepted
/// connections and answers each POST with a single JSON-RPC body, honouring the
/// request's `Connection` header (closing on `close`, keeping the socket alive
/// otherwise). It then issues several sequential `deliver` calls and asserts
/// that only one connection was accepted — proving the pooled keep-alive
/// connection was reused rather than a fresh `Connection: close` socket opened
/// per call.
module mcp.client.http_keepalive_test;

version (unittest)
{
	import std.conv : to;
	import std.string : toLower, startsWith, indexOf, strip;
	import core.time : msecs;

	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.core.net : listenTCP, TCPConnection;
	import vibe.core.stream : IOMode;
	import vibe.stream.operations : readLine;
	import vibe.data.json : Json;

	import mcp.client.http_transport : HttpClientTransport;
}

// With no server->client handler registered, sequential request/response calls
// reuse a single pooled keep-alive connection rather than opening (and tearing
// down) a fresh `Connection: close` socket per call.
unittest
{
	int connectionCount;
	TCPConnection[] accepted;
	string failure;
	int delivered;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto listener = listenTCP(0, (TCPConnection conn) @safe nothrow{
				connectionCount++;
				accepted ~= conn;
				try
				{
					for (;;)
					{
						// Request line; a closed connection ends the loop.
						readLine(conn);
						size_t contentLength;
						bool wantsClose;
						// Header block up to the blank line; capture Content-Length and
						// whether the client asked to close the connection.
						for (;;)
						{
							auto h = cast(string) readLine(conn).idup;
							if (h.length && h[$ - 1] == '\r')
								h = h[0 .. $ - 1];
							if (h.length == 0)
								break;
							const lower = h.toLower;
							if (lower.startsWith("content-length:"))
								contentLength = lower["content-length:".length .. $]
									.strip.to!size_t;
							else if (lower.startsWith("connection:") && lower.indexOf("close") >= 0)
								wantsClose = true;
						}
						if (contentLength)
						{
							auto buf = new ubyte[contentLength];
							conn.read(buf, IOMode.all);
						}
						const bodyText = `{"jsonrpc":"2.0","id":1,"result":{}}`;
						const connHeader = wantsClose ? "close" : "keep-alive";
						const resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
							~ "Content-Length: " ~ bodyText.length.to!string
							~ "\r\nConnection: " ~ connHeader ~ "\r\n\r\n" ~ bodyText;
						conn.write(cast(const(ubyte)[]) resp);
						if (wantsClose)
						{
							conn.close();
							break;
						}
					}
				}
				catch (Exception)
				{
					// Peer closed (or the connection was torn down): stop serving it.
				}
			}, "127.0.0.1");
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const port = listener.bindAddress.port;
			auto url = "http://127.0.0.1:" ~ port.to!string ~ "/mcp";

			// A bare transport with no `ClientProtocol` installed advertises no
			// server->client handlers, so the pooled keep-alive path is selected.
			auto t = new HttpClientTransport(url);

			foreach (i; 1 .. 4)
			{
				Json m = Json.emptyObject;
				m["jsonrpc"] = "2.0";
				m["id"] = i;
				m["method"] = "ping";
				m["params"] = Json.emptyObject;
				t.deliver(m, i);
				delivered++;
			}

			// Release every still-open server-side socket so no parked reader fiber
			// leaks past the event loop.
			foreach (c; accepted)
				if (c.connected)
					c.close();
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "keep-alive reuse round-trip failed: " ~ failure);
	assert(delivered == 3, "expected three deliveries");
	assert(connectionCount == 1,
			"request/response path with no server->client handler must reuse one pooled "
			~ "connection; accepted " ~ connectionCount.to!string ~ " connections");
}
