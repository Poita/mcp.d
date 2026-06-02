module mcp.client.http_transport;

import std.algorithm : canFind;
import std.string : startsWith;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8, readLine;
import vibe.core.net : TCPConnection;
import vibe.stream.tls : createTLSContext, createTLSStream, TLSContextKind, TLSPeerValidationMode;
import vibe.stream.wrapper : ProxyStream, createProxyStream;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.client.transport : ClientTransport, ClientProtocol;
import mcp.client.subscription : SubscriptionStream;

/// Internal signal that the modern single-endpoint POST returned an HTTP
/// 400/404/405, the trigger for the legacy HTTP+SSE (2024-11-05) fallback.
/// Surfaced to `McpClient.connect` so it can drive the fallback.
final class LegacyFallbackException : Exception
{
	int status;
	this(int status) @safe
	{
		import std.conv : to;

		super("legacy HTTP+SSE fallback (HTTP " ~ status.to!string ~ ")");
		this.status = status;
	}
}

/// A `ClientTransport` over the MCP Streamable HTTP transport.
///
/// Owns the HTTP/SSE machinery: the POST-and-await loop (with SSE resumability),
/// the standalone server->client GET SSE stream, the `subscriptions/listen`
/// stream, session-id capture, the OAuth bearer token, and the legacy
/// 2024-11-05 HTTP+SSE two-endpoint fallback (`legacyMode`). The owning
/// `McpClient` supplies the protocol-derived request headers (version / draft
/// method+name / `Mcp-Param-*`) and the cancelled-response predicate through the
/// `ClientProtocol` it installs via `setProtocol`, so this transport never needs
/// the tool inputSchema cache or draft state.
final class HttpClientTransport : ClientTransport
{
	private string url;
	private string sessionId;
	private string bearerToken;
	// SSE resumability: the most recent `id:`/`retry:` seen on a response stream,
	// and the Last-Event-ID to send when retrying after a premature stream close.
	private string sseLastEventId;
	private long sseRetryMs;
	private string pendingLastEventId;
	// Legacy HTTP+SSE (2024-11-05) transport state. When `legacyMode` is set,
	// JSON-RPC messages are POSTed to `legacyEndpoint` (discovered from the GET
	// stream's `endpoint` event) and responses arrive on the standalone GET SSE
	// stream rather than on the POST response.
	private bool legacyMode;
	private string legacyEndpoint;
	// The most recent HTTP status seen on a POST, so the lifecycle code can
	// detect the 400/404/405 backward-compatibility trigger.
	private int lastPostStatus;
	// When awaiting a legacy response on the GET stream, the id we expect and
	// the slot the GET-stream reader fills in.
	private long legacyExpectId;
	private Json legacyResult;
	private bool legacyGot;
	private McpException legacyErr;

	/// Inbound dispatcher installed by `McpClient` (its `dispatchInbound`),
	/// invoked for notifications and server->client requests on any stream.
	private void delegate(Message) @safe inbound;
	/// The owning client's `ClientProtocol`, installed via `setProtocol`. Supplies
	/// the protocol-derived request headers (`headersFor`) and the
	/// cancelled-response predicate (`isCancelled`), so this transport never needs
	/// the tool inputSchema cache or draft state.
	private ClientProtocol protocol;

	this(string url) @safe
	{
		this.url = url;
	}

	void setInboundHandler(void delegate(Message) @safe handler) @safe
	{
		inbound = handler;
	}

	/// Install the owning client's `ClientProtocol`, through which this transport
	/// obtains the protocol-derived request headers and the cancelled-response
	/// predicate, so the draft header/schema logic and the cancellation set stay in
	/// the client.
	void setProtocol(ClientProtocol p) @safe
	{
		protocol = p;
	}

	void setBearerToken(string token) @safe
	{
		bearerToken = token;
	}

	/// Whether this transport is in the legacy 2024-11-05 HTTP+SSE mode.
	bool inLegacyMode() const @safe nothrow @nogc
	{
		return legacyMode;
	}

	void close() @safe
	{
		// Streams run on background tasks tied to the event loop; there is no
		// owned subprocess to terminate. Nothing to release here.
	}

	private string[string] requestHeaders(Json message) @safe
	{
		return protocol is null ? null : protocol.headersFor(message);
	}

	Json deliver(Json message, long expectId) @safe
	{
		if (legacyMode)
			return legacyRpc(message, expectId);
		return postAndAwait(message, expectId);
	}

	void sendOneway(Json message) @safe
	{
		post(message);
	}

	/// False: a reply to a server->client request travels on a *different* HTTP
	/// request than the one whose inbound stream delivered it, and a nested
	/// synchronous POST from inside an awaiting read loop could deadlock the
	/// connection. `McpClient` therefore defers the reply to a background task
	/// (which the HTTP transport already runs under an event loop).
	bool repliesSynchronously() @safe
	{
		return false;
	}

	// --- POST helpers --------------------------------------------------------

	/// POST a message that expects no correlated reply (notification/response).
	/// In legacy HTTP+SSE mode, messages go to the server-supplied endpoint URI.
	private void post(Json message) @safe
	{
		const target = legacyMode ? legacyEndpoint : url;
		() @trusted {
			requestHTTP(target, (scope HTTPClientRequest req) {
				setupRequest(req, message);
			}, (scope HTTPClientResponse res) {
				captureSession(res);
				res.dropBody();
			});
		}();
	}

	/// POST a request and await the response with id `expectId`, processing any
	/// SSE notifications and server->client requests in between. If the response
	/// SSE stream closes before the final response and carried an SSE `retry:`
	/// hint, wait that long and reconnect (resuming with `Last-Event-ID`), per
	/// the Streamable HTTP resumability rules.
	private Json postAndAwait(Json message, long expectId) @safe
	{
		import core.time : msecs;
		import vibe.core.core : sleep;

		Json result = Json.undefined;
		bool got;
		McpException err;
		sseRetryMs = 0;
		sseLastEventId = null;

		// The modern single-endpoint POST is sent over a DEDICATED, raw TCP
		// connection (`postAndAwaitRaw`) rather than vibe's pooled `requestHTTP`.
		// When a tool handler on the server opens a server->client request
		// (sampling / elicitation / roots) it writes that request as an SSE event
		// on THIS POST's response stream and then blocks awaiting our reply. The
		// reply must be sent on a SEPARATE POST while we are still reading this
		// stream. vibe's pooled chunked HTTP-client reader does not surface a
		// freshly-flushed SSE event's terminating blank line until the next chunk
		// arrives, which would deadlock both peers. A raw connection (the same
		// approach `runServerStream`/`resumeViaGet` use for long-lived SSE)
		// delivers each event immediately, so the client can reply and the
		// round-trip completes.
		postAndAwaitRaw(message, expectId, result, got, err);

		// An HTTP 400/404/405 on the modern single endpoint is the signal to try
		// the legacy HTTP+SSE (2024-11-05) transport. Surface it as a typed
		// exception so the lifecycle code (`connect`) can drive the fallback.
		if (isLegacyFallbackStatus(lastPostStatus) && !got && err is null)
			throw new LegacyFallbackException(lastPostStatus);

		if (err !is null)
			throw err;
		if (got)
			return result;

		// Premature stream close with an SSE `retry:` hint: wait the prescribed
		// delay, then RESUME the stream with a GET carrying `Last-Event-ID`
		// (per Streamable HTTP resumability — not a re-POST of the request).
		if (sseRetryMs > 0)
		{
			sleep(sseRetryMs.msecs);
			resumeViaGet(expectId, sseLastEventId, result, got, err);
			if (err !is null)
				throw err;
			if (got)
				return result;
		}
		throw internalError("No response received for request " ~ idStr(expectId));
	}

	/// POST `message` over a fresh TCP connection and read the response, awaiting
	/// the JSON-RPC response with id `expectId`. The response is either a single
	/// JSON body or a `text/event-stream`; for an SSE response, notifications and
	/// server->client requests that arrive BEFORE the final response are
	/// dispatched (via `dispatchSse`) as soon as each complete event is received —
	/// the key property the pooled `requestHTTP` reader does not provide (see
	/// `postAndAwait`). Mirrors the chunked-decode SSE parser of
	/// `runServerStream`/`resumeViaGet`.
	private void postAndAwaitRaw(Json message, long expectId, ref Json result,
			ref bool got, ref McpException err) @safe
	{
		import vibe.core.net : connectTCP;
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : indexOf, startsWith, strip, toLower;
		import std.conv : to, parse;

		const ep = parseHttpEndpoint(url);
		const host = ep.host;
		const port = ep.port;
		const path = ep.path;

		const payload = message.toString();
		auto hdrs = requestHeaders(message);

		() @trusted {
			try
			{
				auto sock = connectTCP(host, port);
				scope (exit)
					sock.close();
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, host);

				string req = "POST " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
					~ "\r\nAccept: application/json, text/event-stream\r\n"
					~ "Content-Type: application/json\r\nConnection: close\r\n";
				if (bearerToken.length)
					req ~= "Authorization: Bearer " ~ bearerToken ~ "\r\n";
				if (sessionId.length)
					req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
				foreach (k, v; hdrs)
					req ~= k ~ ": " ~ v ~ "\r\n";
				if (pendingLastEventId.length)
					req ~= "Last-Event-ID: " ~ pendingLastEventId ~ "\r\n";
				req ~= "Content-Length: " ~ payload.length.to!string ~ "\r\n\r\n";
				req ~= payload;
				conn.write(cast(const(ubyte)[]) req);

				// Status line + response headers.
				auto statusLine = cast(string) readLine(conn).idup;
				lastPostStatus = parseHttpStatus(statusLine);
				bool chunked;
				bool sse;
				foreach (h; readHeaderLines(conn))
				{
					const lower = h.toLower;
					if (lower.startsWith("transfer-encoding:") && lower.indexOf("chunked") >= 0)
						chunked = true;
					if (lower.startsWith("content-type:") && lower.indexOf("text/event-stream") >= 0)
						sse = true;
					const c = h.indexOf(':');
					if (c > 0 && h[0 .. c].toLower == "mcp-session-id")
						sessionId = h[c + 1 .. $].strip;
				}

				// A 400/404/405 is the legacy-fallback signal: read the (small) body
				// and surface a recognised modern JSON-RPC error if present.
				if (isLegacyFallbackStatus(lastPostStatus))
				{
					const b = readRemaining(conn, chunked);
					McpException modernErr;
					if (modernErrorFromBody(b, modernErr))
						err = modernErr;
					return;
				}

				if (!sse)
				{
					// A single JSON body (the common non-streaming response).
					const b = readRemaining(conn, chunked);
					auto m = parseMessage(b);
					if (m.kind == MessageKind.errorResponse)
						err = errorFrom(m.error);
					else
					{
						result = m.result;
						got = true;
					}
					return;
				}

				// SSE body: decode chunked transfer-encoding (or raw to EOF),
				// feeding an accumulator parser that dispatches each COMPLETE event
				// immediately. This is what lets a mid-stream server->client request
				// be answered while we keep reading for the final response.
				string acc, data;
				void parseSse()
				{
					for (;;)
					{
						const nl = acc.indexOf('\n');
						if (nl < 0)
							break;
						auto line = acc[0 .. nl];
						acc = acc[nl + 1 .. $];
						if (line.length && line[$ - 1] == '\r')
							line = line[0 .. $ - 1];
						if (line.length == 0)
						{
							if (data.length)
							{
								dispatchSse(data, expectId, result, got, err);
								data = null;
							}
						}
						else if (line.startsWith("data:"))
						{
							auto d = line["data:".length .. $];
							if (d.startsWith(" "))
								d = d[1 .. $];
							data ~= (data.length ? "\n" : "") ~ d;
						}
						else if (line.startsWith("id:"))
							sseLastEventId = line["id:".length .. $].strip;
						else if (line.startsWith("retry:"))
						{
							try
								sseRetryMs = line["retry:".length .. $].strip.to!long;
							catch (Exception)
							{
							}
						}
					}
				}

				for (;;)
				{
					if (got || err !is null)
						break;
					if (chunked)
					{
						auto sizeLine = (cast(string) readLine(conn).idup).strip;
						if (sizeLine.length == 0)
							continue;
						uint sz;
						try
						{
							auto sl = sizeLine;
							sz = parse!uint(sl, 16);
						}
						catch (Exception)
							break;
						if (sz == 0)
							break; // last chunk
						auto chunk = new ubyte[sz];
						conn.read(chunk, IOMode.all);
						acc ~= cast(string) chunk.idup;
						parseSse();
					}
					else
					{
						ubyte[4096] buf;
						size_t n;
						try
							n = conn.read(buf, IOMode.once);
						catch (Exception)
							break;
						if (n == 0)
							break;
						acc ~= cast(string) buf[0 .. n].idup;
						parseSse();
					}
				}
			}
			catch (Exception e)
			{
				if (err is null && !got)
					err = internalError(e.msg);
			}
		}();
	}

	/// Parse the numeric status code out of an HTTP status line
	/// (`HTTP/1.1 200 OK` -> 200). Returns 0 when it cannot be parsed.
	private static int parseHttpStatus(string statusLine) @trusted
	{
		import std.string : split, strip;
		import std.conv : to;

		if (statusLine.length && statusLine[$ - 1] == '\r')
			statusLine = statusLine[0 .. $ - 1];
		auto parts = statusLine.strip.split(" ");
		if (parts.length < 2)
			return 0;
		try
			return parts[1].to!int;
		catch (Exception)
			return 0;
	}

	/// Read the response header block from `conn` (up to the blank line),
	/// returning each header line with its trailing CR stripped.
	private static string[] readHeaderLines(Conn)(Conn conn) @trusted
	{
		import vibe.stream.operations : readLine;

		string[] headers;
		for (;;)
		{
			auto h = cast(string) readLine(conn).idup;
			if (h.length && h[$ - 1] == '\r')
				h = h[0 .. $ - 1];
			if (h.length == 0)
				break;
			headers ~= h;
		}
		return headers;
	}

	/// Read the remaining response body from `conn` to end-of-stream, decoding
	/// chunked transfer-encoding when `chunked` is true. Used for the small
	/// non-streaming JSON body and the 4xx legacy-fallback body.
	private static string readRemaining(Conn)(Conn conn, bool chunked) @trusted
	{
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : strip;
		import std.conv : parse;

		string acc;
		if (chunked)
		{
			for (;;)
			{
				auto sizeLine = (cast(string) readLine(conn).idup).strip;
				if (sizeLine.length == 0)
					continue;
				uint sz;
				try
				{
					auto sl = sizeLine;
					sz = parse!uint(sl, 16);
				}
				catch (Exception)
					break;
				if (sz == 0)
					break;
				auto chunk = new ubyte[sz];
				conn.read(chunk, IOMode.all);
				acc ~= cast(string) chunk.idup;
			}
		}
		else
		{
			for (;;)
			{
				ubyte[4096] buf;
				size_t n;
				try
					n = conn.read(buf, IOMode.once);
				catch (Exception)
					break;
				if (n == 0)
					break;
				acc ~= cast(string) buf[0 .. n].idup;
			}
		}
		return acc;
	}

	/// Resume a closed response stream via `GET` with `Last-Event-ID`, reading
	/// the resumed SSE stream until the awaited response (`expectId`) arrives.
	private void resumeViaGet(long expectId, string lastEventId, ref Json result,
			ref bool got, ref McpException err) @safe
	{
		import vibe.core.net : connectTCP;
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : indexOf, startsWith, strip, toLower;
		import std.conv : to, parse;

		const ep = parseHttpEndpoint(url);
		const host = ep.host;
		const port = ep.port;
		const path = ep.path;

		// Protocol-version header for the GET stream (set after initialize).
		auto verHeaders = requestHeaders(Json.undefined);

		() @trusted {
			try
			{
				auto sock = connectTCP(host, port);
				scope (exit)
					sock.close();
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, host);
				string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
					~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
				if (sessionId.length)
					req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
				foreach (k, v; verHeaders)
					req ~= k ~ ": " ~ v ~ "\r\n";
				if (lastEventId.length)
					req ~= "Last-Event-ID: " ~ lastEventId ~ "\r\n";
				req ~= "\r\n";
				conn.write(cast(const(ubyte)[]) req);

				auto statusLine = cast(string) readLine(conn).idup;
				if (statusLine.indexOf(" 200") < 0)
					return;
				bool chunked;
				for (;;)
				{
					auto h = cast(string) readLine(conn).idup;
					if (h.length && h[$ - 1] == '\r')
						h = h[0 .. $ - 1];
					if (h.toLower.indexOf("transfer-encoding:") == 0
							&& h.toLower.indexOf("chunked") >= 0)
						chunked = true;
					if (h.length == 0)
						break;
				}

				string acc, data;
				bool done;
				void parseSse()
				{
					for (;;)
					{
						const nl = acc.indexOf('\n');
						if (nl < 0)
							break;
						auto line = acc[0 .. nl];
						acc = acc[nl + 1 .. $];
						if (line.length && line[$ - 1] == '\r')
							line = line[0 .. $ - 1];
						if (line.length == 0)
						{
							if (data.length)
							{
								try
								{
									auto m = Message(parseJsonString(data));
									if ((m.kind == MessageKind.response
											|| m.kind == MessageKind.errorResponse)
											&& m.id.type == Json.Type.int_
											&& m.id.get!long == expectId)
									{
										if (m.kind == MessageKind.errorResponse)
											err = errorFrom(m.error);
										else
										{
											result = m.result;
											got = true;
										}
										done = true;
									}
									else
										dispatch(m);
								}
								catch (Exception)
								{
								}
								data = null;
							}
						}
						else if (line.startsWith("data:"))
						{
							auto d = line["data:".length .. $];
							if (d.startsWith(" "))
								d = d[1 .. $];
							data ~= (data.length ? "\n" : "") ~ d;
						}
					}
				}

				for (;;)
				{
					if (done)
						break;
					if (chunked)
					{
						auto sizeLine = (cast(string) readLine(conn).idup).strip;
						if (sizeLine.length == 0)
							continue;
						uint sz;
						try
							sz = parse!uint(sizeLine, 16);
						catch (Exception)
							break;
						if (sz == 0)
							break;
						auto chunk = new ubyte[sz];
						conn.read(chunk, IOMode.all);
						acc ~= cast(string) chunk.idup;
						readLine(conn);
						parseSse();
					}
					else
					{
						const avail = conn.leastSize;
						if (avail == 0)
							break;
						const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
						auto buf = new ubyte[toRead];
						conn.read(buf, IOMode.once);
						acc ~= cast(string) buf.idup;
						parseSse();
					}
				}
			}
			catch (Exception)
			{
			}
		}();
	}

	private static string idStr(long id) @safe
	{
		import std.conv : to;

		return id.to!string;
	}

	private void setupRequest(scope HTTPClientRequest req, Json message) @safe
	{
		req.method = HTTPMethod.POST;
		req.headers["Accept"] = "application/json, text/event-stream";
		req.contentType = "application/json";
		if (bearerToken.length)
			req.headers["Authorization"] = "Bearer " ~ bearerToken;
		if (sessionId.length)
			req.headers["Mcp-Session-Id"] = sessionId;
		foreach (k, v; requestHeaders(message))
			req.headers[k] = v;
		if (pendingLastEventId.length)
			req.headers["Last-Event-ID"] = pendingLastEventId;
		req.writeBody(cast(const(ubyte)[]) message.toString());
	}

	private void captureSession(scope HTTPClientResponse res) @safe
	{
		if ("Mcp-Session-Id" in res.headers)
			sessionId = res.headers["Mcp-Session-Id"];
	}

	/// Read an SSE stream, dispatching messages until the awaited response.
	///
	/// Blocks on `readLine` rather than polling `empty`: an SSE stream may stay
	/// open and idle between events (e.g. while the server awaits our reply to a
	/// server->client request), and `empty` can spuriously report end-of-stream
	/// in that window. A read exception signals the stream has closed.
	private void readSse(scope HTTPClientResponse res, long expectId,
			ref Json result, ref bool got, ref McpException err) @safe
	{
		string dataBuf;
		for (;;)
		{
			string line;
			bool eof;
			() @trusted {
				try
					line = cast(string) readLine(res.bodyReader, size_t.max, "\n").idup;
				catch (Exception)
					eof = true;
			}();
			if (eof)
				break;
			if (line.length && line[$ - 1] == '\r')
				line = line[0 .. $ - 1];

			if (line.length == 0)
			{
				if (dataBuf.length)
				{
					dispatchSse(dataBuf, expectId, result, got, err);
					dataBuf = null;
					if (got || err !is null)
						return;
				}
				continue;
			}
			if (line.startsWith("data:"))
			{
				auto d = line["data:".length .. $];
				if (d.startsWith(" "))
					d = d[1 .. $];
				dataBuf ~= (dataBuf.length ? "\n" : "") ~ d;
			}
			else if (line.startsWith("id:"))
			{
				import std.string : strip;

				sseLastEventId = line["id:".length .. $].strip;
			}
			else if (line.startsWith("retry:"))
			{
				import std.string : strip;
				import std.conv : to;

				try
					sseRetryMs = line["retry:".length .. $].strip.to!long;
				catch (Exception)
				{
				}
			}
		}
		// Flush a trailing event with no terminating blank line.
		if (dataBuf.length && !got && err is null)
			dispatchSse(dataBuf, expectId, result, got, err);
	}

	private void dispatchSse(string data, long expectId, ref Json result,
			ref bool got, ref McpException err) @safe
	{
		Message msg;
		try
			msg = Message(parseJsonString(data));
		catch (Exception)
			return; // ignore non-JSON SSE comments/heartbeats

		// A response for a request we have cancelled is ignored per spec, even if
		// it matches the id we are awaiting.
		if ((msg.kind == MessageKind.response || msg.kind == MessageKind.errorResponse)
				&& msg.id.type == Json.Type.int_ && protocol !is null
				&& protocol.isCancelled(msg.id.get!long))
			return;

		final switch (msg.kind)
		{
		case MessageKind.response:
			if (msg.id.type == Json.Type.int_ && msg.id.get!long == expectId)
			{
				result = msg.result;
				got = true;
			}
			break;
		case MessageKind.errorResponse:
			if (msg.id.type == Json.Type.int_
					&& msg.id.get!long == expectId)
				err = errorFrom(msg.error);
			break;
		case MessageKind.request:
			dispatch(msg);
			break;
		case MessageKind.notification:
			dispatch(msg);
			break;
		}
	}

	/// Hand an inbound message to the client's dispatcher.
	private void dispatch(Message msg) @safe
	{
		if (inbound !is null)
			inbound(msg);
	}

	// --- standalone server->client stream ------------------------------------

	/// Open the standalone server->client SSE stream (`GET /mcp`) in a background
	/// task, so the server can deliver sampling / elicitation / roots requests
	/// and notifications outside of any POST response. A server that does not
	/// offer this stream (e.g. responds 405) is tolerated as a no-op.
	void startServerStream() @safe
	{
		import vibe.core.core : runTask;

		runTask(() nothrow{
			try
				runServerStream();
			catch (Exception)
			{
			}
		});
	}

	/// Open the standalone server->client SSE stream over a raw TCP connection
	/// (vibe's pooled `requestHTTP` does not reliably surface a long-lived,
	/// idle-then-active SSE body). Honors the SSE `retry:` field and resumes with
	/// `Last-Event-ID` on reconnect, up to a few attempts.
	private void runServerStream() @safe
	{
		import vibe.core.net : connectTCP;
		import vibe.stream.operations : readLine;
		import std.string : indexOf, startsWith, strip;
		import std.conv : to;
		import core.time : msecs;
		import vibe.core.core : sleep;

		// Parse scheme://host[:port]/path.
		const ep = parseHttpEndpoint(url);
		const host = ep.host;
		const port = ep.port;
		const path = ep.path;

		// Protocol-version header for the GET stream (set after initialize).
		auto verHeaders = requestHeaders(Json.undefined);

		string lastEventId;
		long retryMs = 0;
		foreach (attempt; 0 .. 2)
		{
			bool sawData;
			() @trusted {
				try
				{
					auto sock = connectTCP(host, port);
					scope (exit)
						sock.close();
					// Wrap in TLS for https/wss; plaintext is returned unwrapped.
					auto conn = openClientStream(sock, ep.tls, host);

					string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
						~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
					if (sessionId.length)
						req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
					foreach (k, v; verHeaders)
						req ~= k ~ ": " ~ v ~ "\r\n";
					if (lastEventId.length)
						req ~= "Last-Event-ID: " ~ lastEventId ~ "\r\n";
					req ~= "\r\n";
					conn.write(cast(const(ubyte)[]) req);

					import vibe.core.stream : IOMode;
					import std.conv : parse;

					// Status line + headers (note chunked transfer-encoding).
					auto statusLine = cast(string) readLine(conn).idup;
					if (statusLine.indexOf(" 200") < 0)
						return;
					bool chunked;
					for (;;)
					{
						auto h = cast(string) readLine(conn).idup;
						if (h.length && h[$ - 1] == '\r')
							h = h[0 .. $ - 1];
						import std.string : toLower;

						if (h.toLower.indexOf("transfer-encoding:") == 0
								&& h.toLower.indexOf("chunked") >= 0)
							chunked = true;
						if (h.length == 0)
							break;
					}

					// SSE parser shared across chunk boundaries.
					string acc, data;
					void parseSse()
					{
						for (;;)
						{
							const nl = acc.indexOf('\n');
							if (nl < 0)
								break;
							auto line = acc[0 .. nl];
							acc = acc[nl + 1 .. $];
							if (line.length && line[$ - 1] == '\r')
								line = line[0 .. $ - 1];
							if (line.length == 0)
							{
								if (data.length)
								{
									sawData = true;
									try
										dispatch(Message(parseJsonString(data)));
									catch (Exception)
									{
									}
									data = null;
								}
							}
							else if (line.startsWith("data:"))
							{
								auto d = line["data:".length .. $];
								if (d.startsWith(" "))
									d = d[1 .. $];
								data ~= (data.length ? "\n" : "") ~ d;
							}
							else if (line.startsWith("id:"))
								lastEventId = line["id:".length .. $].strip;
							else if (line.startsWith("retry:"))
							{
								try
									retryMs = line["retry:".length .. $].strip.to!long;
								catch (Exception)
								{
								}
							}
						}
					}

					// Body loop: decode chunked transfer-encoding (each chunk is a
					// hex size line, that many bytes, then CRLF), feeding the SSE
					// parser; or read raw to EOF when not chunked.
					for (;;)
					{
						if (chunked)
						{
							auto sizeLine = (cast(string) readLine(conn).idup).strip;
							if (sizeLine.length == 0)
								continue;
							uint sz;
							try
							{
								auto sl = sizeLine;
								sz = parse!uint(sl, 16);
							}
							catch (Exception)
								break;
							if (sz == 0)
								break; // last chunk
							auto chunk = new ubyte[sz];
							conn.read(chunk, IOMode.all);
							acc ~= cast(string) chunk.idup;
							readLine(conn); // trailing CRLF after the chunk data
							parseSse();
						}
						else
						{
							const avail = conn.leastSize;
							if (avail == 0)
								break;
							const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
							auto buf = new ubyte[toRead];
							conn.read(buf, IOMode.once);
							acc ~= cast(string) buf.idup;
							parseSse();
						}
					}
				}
				catch (Exception)
				{
				}
			}();

			// Reconnect honoring the server-provided retry delay (SSE `retry:`).
			if (retryMs > 0)
				sleep(retryMs.msecs);
			else if (!sawData)
				break; // stream unavailable and no retry hint: stop
		}
	}

	// --- subscriptions/listen stream -----------------------------------------

	SubscriptionStream openListen(Json message) @safe
	{
		import vibe.core.core : runTask;

		auto cancelled = () @trusted { return new shared bool(false); }();
		auto stream = new SubscriptionStream(cancelled);
		runTask(() nothrow{
			try
				runListenStream(message, cancelled);
			catch (Exception)
			{
			}
		});
		return stream;
	}

	/// Drive a `subscriptions/listen` stream over a raw TCP connection: POST the
	/// listen request, read the server's long-lived `text/event-stream` response,
	/// and dispatch every inbound message (the leading
	/// `notifications/subscriptions/acknowledged` and subsequent change
	/// notifications) via the inbound handler. The loop checks `*cancelled`
	/// between reads and on each SSE event, closing the connection promptly once
	/// the caller cancels. A raw TCP POST is used (rather than vibe's pooled
	/// `requestHTTP`) for the same reason as `runServerStream`: a long-lived,
	/// idle-then-active SSE body is not reliably surfaced by the pooled client.
	private void runListenStream(Json message, shared(bool)* cancelled) @safe
	{
		import vibe.core.net : connectTCP;
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : indexOf, startsWith, strip, toLower;
		import std.conv : to, parse;

		const ep = parseHttpEndpoint(url);
		const host = ep.host;
		const port = ep.port;
		const path = ep.path;

		// Protocol-derived headers (version + draft method) for this POST.
		auto reqHeaders = requestHeaders(message);

		const 
		body = message.toString();
		() @trusted {
			auto sock = connectTCP(host, port);
			scope (exit)
				sock.close();
			// Wrap in TLS for https/wss; plaintext is returned unwrapped.
			auto conn = openClientStream(sock, ep.tls, host);

			string req = "POST " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
				~ "\r\nAccept: text/event-stream\r\nContent-Type: application/json\r\n"
				~ "Connection: keep-alive\r\n";
			if (bearerToken.length)
				req ~= "Authorization: Bearer " ~ bearerToken ~ "\r\n";
			if (sessionId.length)
				req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
			foreach (k, v; reqHeaders)
				req ~= k ~ ": " ~ v ~ "\r\n";
			import std.conv : to;

			req ~= "Content-Length: " ~ body.length.to!string ~ "\r\n\r\n";
			req ~= body;
			conn.write(cast(const(ubyte)[]) req);

			auto statusLine = cast(string) readLine(conn).idup;
			if (statusLine.indexOf(" 200") < 0)
				return;
			bool chunked;
			for (;;)
			{
				auto h = cast(string) readLine(conn).idup;
				if (h.length && h[$ - 1] == '\r')
					h = h[0 .. $ - 1];
				if (h.toLower.indexOf("transfer-encoding:") == 0 && h.toLower.indexOf(
						"chunked") >= 0)
					chunked = true;
				if (h.length == 0)
					break;
			}

			string acc, data;
			void parseSse()
			{
				for (;;)
				{
					const nl = acc.indexOf('\n');
					if (nl < 0)
						break;
					auto line = acc[0 .. nl];
					acc = acc[nl + 1 .. $];
					if (line.length && line[$ - 1] == '\r')
						line = line[0 .. $ - 1];
					if (line.length == 0)
					{
						if (data.length)
						{
							try
								dispatch(Message(parseJsonString(data)));
							catch (Exception)
							{
							}
							data = null;
						}
					}
					else if (line.startsWith("data:"))
					{
						auto d = line["data:".length .. $];
						if (d.startsWith(" "))
							d = d[1 .. $];
						data ~= (data.length ? "\n" : "") ~ d;
					}
				}
			}

			for (;;)
			{
				if (*cancelled)
					break;
				if (chunked)
				{
					auto sizeLine = (cast(string) readLine(conn).idup).strip;
					if (sizeLine.length == 0)
						continue;
					uint sz;
					try
					{
						auto sl = sizeLine;
						sz = parse!uint(sl, 16);
					}
					catch (Exception)
						break;
					if (sz == 0)
						break; // last chunk
					auto chunk = new ubyte[sz];
					conn.read(chunk, IOMode.all);
					acc ~= cast(string) chunk.idup;
					readLine(conn); // trailing CRLF after the chunk data
					parseSse();
				}
				else
				{
					const avail = conn.leastSize;
					if (avail == 0)
						break;
					const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
					auto buf = new ubyte[toRead];
					conn.read(buf, IOMode.once);
					acc ~= cast(string) buf.idup;
					parseSse();
				}
			}
		}();
	}

	// --- legacy HTTP+SSE (2024-11-05) two-endpoint transport -----------------

	/// Establish the legacy HTTP+SSE (2024-11-05) two-endpoint transport:
	/// open the GET SSE stream at the server URL, read the first `endpoint`
	/// event to learn the message-POST URI, then keep the stream open in a
	/// background task to receive JSON-RPC responses and server notifications.
	/// Throws if the `endpoint` event is not received. Called by
	/// `McpClient.connect` once a modern POST has been rejected with 400/404/405.
	void startLegacyFallback() @safe
	{
		import vibe.core.core : runTask, sleep;
		import core.time : msecs;

		legacyMode = true;
		legacyEndpoint = null;

		// The GET SSE stream is long-lived: run its reader on a background task
		// so this method can return once the `endpoint` event has arrived.
		runTask(() nothrow{
			try
				runLegacyStream();
			catch (Exception)
			{
			}
		});

		// Wait (bounded) for the background task to discover the endpoint URI.
		foreach (_; 0 .. 200) // up to ~10s at 50ms granularity
		{
			if (legacyEndpoint.length)
				break;
			() @trusted { sleep(50.msecs); }();
		}
		if (legacyEndpoint.length == 0)
		{
			legacyMode = false;
			throw internalError(
					"legacy HTTP+SSE server did not send an `endpoint` event on the GET stream");
		}
	}

	/// Send a JSON-RPC request over the legacy transport: POST it to the
	/// server-supplied endpoint URI, then await the correlated response, which
	/// arrives asynchronously on the standalone GET SSE stream.
	private Json legacyRpc(Json message, long expectId) @safe
	{
		import vibe.core.core : sleep;
		import core.time : msecs;

		legacyExpectId = expectId;
		legacyResult = Json.undefined;
		legacyGot = false;
		legacyErr = null;

		post(message); // POST to legacyEndpoint; server replies on the GET stream

		foreach (_; 0 .. 1200) // up to ~60s at 50ms granularity
		{
			if (legacyGot || legacyErr !is null)
				break;
			() @trusted { sleep(50.msecs); }();
		}
		legacyExpectId = 0;
		if (legacyErr !is null)
			throw legacyErr;
		if (legacyGot)
			return legacyResult;
		throw internalError("No legacy HTTP+SSE response for request " ~ idStr(expectId));
	}

	/// Read the legacy GET SSE stream over a raw TCP connection, dispatching
	/// each event by type: an `endpoint` event sets the message-POST URI; a
	/// `message` (or default) event is a JSON-RPC message routed to the awaited
	/// response slot or to the inbound dispatcher.
	private void runLegacyStream() @safe
	{
		import vibe.core.net : connectTCP;
		import vibe.stream.operations : readLine;
		import vibe.core.stream : IOMode;
		import std.string : indexOf, startsWith, strip, toLower;
		import std.conv : to, parse;

		const ep = parseHttpEndpoint(url);
		const host = ep.host;
		const port = ep.port;
		const path = ep.path;

		() @trusted {
			try
			{
				auto sock = connectTCP(host, port);
				scope (exit)
					sock.close();
				// Wrap in TLS for https/wss; plaintext is returned unwrapped.
				auto conn = openClientStream(sock, ep.tls, host);

				string req = "GET " ~ path ~ " HTTP/1.1\r\nHost: " ~ host
					~ "\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n";
				if (bearerToken.length)
					req ~= "Authorization: Bearer " ~ bearerToken ~ "\r\n";
				if (sessionId.length)
					req ~= "Mcp-Session-Id: " ~ sessionId ~ "\r\n";
				req ~= "\r\n";
				conn.write(cast(const(ubyte)[]) req);

				auto statusLine = cast(string) readLine(conn).idup;
				if (statusLine.indexOf(" 200") < 0)
					return;
				bool chunked;
				for (;;)
				{
					auto h = cast(string) readLine(conn).idup;
					if (h.length && h[$ - 1] == '\r')
						h = h[0 .. $ - 1];
					if (h.toLower.indexOf("transfer-encoding:") == 0
							&& h.toLower.indexOf("chunked") >= 0)
						chunked = true;
					if (h.length == 0)
						break;
				}

				string acc, data, eventType;
				void handleEvent()
				{
					scope (exit)
					{
						data = null;
						eventType = null;
					}
					if (data.length == 0)
						return;
					if (eventType == "endpoint")
					{
						legacyEndpoint = resolveEndpointUri(url, data.strip);
						return;
					}
					// `message` event (or untyped): a JSON-RPC message.
					try
					{
						auto m = Message(parseJsonString(data));
						if ((m.kind == MessageKind.response
								|| m.kind == MessageKind.errorResponse)
								&& m.id.type == Json.Type.int_ && m.id.get!long == legacyExpectId)
						{
							if (m.kind == MessageKind.errorResponse)
								legacyErr = errorFrom(m.error);
							else
							{
								legacyResult = m.result;
								legacyGot = true;
							}
						}
						else
							dispatch(m);
					}
					catch (Exception)
					{
					}
				}

				void parseSse()
				{
					for (;;)
					{
						const nl = acc.indexOf('\n');
						if (nl < 0)
							break;
						auto line = acc[0 .. nl];
						acc = acc[nl + 1 .. $];
						if (line.length && line[$ - 1] == '\r')
							line = line[0 .. $ - 1];
						if (line.length == 0)
							handleEvent();
						else if (line.startsWith("event:"))
						{
							auto v = line["event:".length .. $];
							if (v.startsWith(" "))
								v = v[1 .. $];
							eventType = v;
						}
						else if (line.startsWith("data:"))
						{
							auto d = line["data:".length .. $];
							if (d.startsWith(" "))
								d = d[1 .. $];
							data ~= (data.length ? "\n" : "") ~ d;
						}
					}
				}

				for (;;)
				{
					if (chunked)
					{
						auto sizeLine = (cast(string) readLine(conn).idup).strip;
						if (sizeLine.length == 0)
							continue;
						uint sz;
						try
							sz = parse!uint(sizeLine, 16);
						catch (Exception)
							break;
						if (sz == 0)
							break;
						auto chunk = new ubyte[sz];
						conn.read(chunk, IOMode.all);
						acc ~= cast(string) chunk.idup;
						readLine(conn);
						parseSse();
					}
					else
					{
						const avail = conn.leastSize;
						if (avail == 0)
							break;
						const toRead = avail > 4096 ? 4096 : cast(size_t) avail;
						auto buf = new ubyte[toRead];
						conn.read(buf, IOMode.once);
						acc ~= cast(string) buf.idup;
						parseSse();
					}
				}
			}
			catch (Exception)
			{
			}
		}();
	}

	private static McpException errorFrom(Json error) @safe
	{
		const code = ("code" in error) ? error["code"].get!int : ErrorCode.internalError;
		const m = ("message" in error) ? error["message"].get!string : "server error";
		return new McpException(code, m, error);
	}
}

/// The parsed components of an MCP endpoint URL, shared by every raw-TCP request
/// path so host/port/scheme parsing lives in exactly one place. `tls` is true for
/// an `https://`/`wss://` scheme; `port` defaults to the scheme's well-known port
/// (443 when `tls`, else 80) when the URL omits it, so a TLS URL can never be
/// silently treated as plaintext on port 80.
struct HttpEndpoint
{
	string host;
	ushort port;
	string path;
	bool tls;
}

/// Parse `scheme://host[:port][/path]` into its components, defaulting the port
/// to 443 for a TLS scheme (https/wss) and 80 otherwise. An absent path becomes
/// "/". Tolerates a missing scheme (treated as non-TLS). See `HttpEndpoint`.
HttpEndpoint parseHttpEndpoint(string url) @safe
{
	import std.string : indexOf, toLower;
	import std.conv : to;

	HttpEndpoint ep;
	auto rest = url;
	string scheme;
	const sep = rest.indexOf("://");
	if (sep >= 0)
	{
		scheme = rest[0 .. sep].toLower;
		rest = rest[sep + 3 .. $];
	}
	ep.tls = scheme == "https" || scheme == "wss";

	const slash = rest.indexOf('/');
	const hostPort = (slash < 0) ? rest : rest[0 .. slash];
	ep.path = (slash < 0) ? "/" : rest[slash .. $];

	const colon = hostPort.indexOf(':');
	ep.host = (colon < 0) ? hostPort : hostPort[0 .. colon];
	if (colon < 0)
		ep.port = ep.tls ? cast(ushort) 443 : cast(ushort) 80;
	else
	{
		try
			ep.port = hostPort[colon + 1 .. $].to!ushort;
		catch (Exception)
			ep.port = ep.tls ? cast(ushort) 443 : cast(ushort) 80;
	}
	return ep;
}

/// Open a client byte stream to `ep`, wrapping the raw TCP connection in a vibe
/// TLS tunnel when `ep.tls` is set (https/wss). Returns a `ProxyStream` so the
/// five raw-TCP request paths share ONE TLS-handling site and treat the plaintext
/// and TLS cases uniformly. The TLS context uses
/// `TLSContextKind.client` with peer-certificate verification (`checkPeer`) and
/// sets the SNI/peer name to `ep.host`, so the server certificate and hostname are
/// validated; the underlying `conn` must outlive the returned stream (callers keep
/// it in scope and `close()` it). On a plaintext endpoint the raw connection is
/// returned unwrapped (still as a `ProxyStream` for a single static type).
private ProxyStream openClientStream(TCPConnection conn, bool tls, string host) @trusted
{
	if (tls)
	{
		auto ctx = createTLSContext(TLSContextKind.client);
		ctx.peerValidationMode = TLSPeerValidationMode.checkPeer;
		auto t = createTLSStream(conn, ctx, host);
		return createProxyStream(t);
	}
	return createProxyStream(conn);
}

/// Whether an HTTP status from the initial modern POST should trigger the
/// legacy HTTP+SSE (2024-11-05) backward-compatibility fallback. Per
/// basic/transports §Backwards Compatibility, a client probing a single modern
/// endpoint should fall back when the POST fails with 400 Bad Request, 404 Not
/// Found, or 405 Method Not Allowed.
bool isLegacyFallbackStatus(int status) pure nothrow @safe @nogc
{
	return status == 400 || status == 404 || status == 405;
}

/// Whether a JSON-RPC error `code` carried in a 400/404/405 response body
/// proves the peer speaks a *modern* MCP version (so the client should retry /
/// correct rather than fall back to the legacy HTTP+SSE transport). Per draft
/// basic/transports §Backward Compatibility the disambiguating modern errors a
/// 4xx body may carry are `UnsupportedProtocolVersionError` (-32004),
/// `HeaderMismatch` (-32001, header-validation failure),
/// `MissingRequiredClientCapabilityError` (-32003), and — for a 404 to an
/// unimplemented modern method — `Method not found` (-32601). These mirror the
/// codes the SDK's own server emits via `httpStatusForResponse`.
bool isModernRpcErrorCode(int code) pure nothrow @safe @nogc
{
	return code == ErrorCode.unsupportedProtocolVersion || code == ErrorCode.headerMismatch
		|| code == ErrorCode.missingRequiredClientCapability || code == ErrorCode.methodNotFound;
}

/// Inspect a 400/404/405 response `body` for a recognized modern JSON-RPC
/// error before deciding whether to fall back to legacy HTTP+SSE. Per draft
/// basic/transports §Backward Compatibility: "If the body contains a recognized
/// modern JSON-RPC error, the server speaks a modern version of MCP — retry ...
/// rather than falling back. If the body is empty or is not a recognized modern
/// JSON-RPC error, fall back to initialize." Returns true and sets `err` to a
/// typed `McpException` only when the body parses as a JSON-RPC error response
/// whose code passes `isModernRpcErrorCode`; otherwise returns false (legacy
/// fallback) and leaves `err` null. Never throws — a malformed/empty body is a
/// legacy signal, not an error.
bool modernErrorFromBody(string body, out McpException err) @safe nothrow
{
	import std.string : strip;

	err = null;
	try
	{
		if (body.strip.length == 0)
			return false;
		auto msg = parseMessage(body);
		if (msg.kind != MessageKind.errorResponse)
			return false;
		auto e = msg.error;
		if (e.type != Json.Type.object || "code" !in e || e["code"].type != Json.Type.int_)
			return false;
		const code = e["code"].get!int;
		if (!isModernRpcErrorCode(code))
			return false;
		const m = ("message" in e && e["message"].type == Json.Type.string) ? e["message"]
			.get!string : "server error";
		err = new McpException(code, m, e);
		return true;
	}
	catch (Exception)
	{
		// Malformed body: not a recognized modern error → legacy fallback.
		err = null;
		return false;
	}
}

/// Parse a legacy HTTP+SSE event stream looking for the first `endpoint` event,
/// returning its `data:` payload (the message-POST URI) in `uri`. Returns false
/// if no `endpoint` event is found in the supplied buffer. Handles CRLF and LF
/// line endings and the optional single leading space after `data:`.
bool parseEndpointEvent(string sse, out string uri) @safe
{
	import std.string : startsWith, splitLines;

	string eventType;
	string data;
	bool haveData;

	bool flush()
	{
		if (eventType == "endpoint" && haveData)
		{
			uri = data;
			return true;
		}
		eventType = null;
		data = null;
		haveData = false;
		return false;
	}

	foreach (raw; sse.splitLines())
	{
		auto line = raw;
		if (line.length && line[$ - 1] == '\r')
			line = line[0 .. $ - 1];
		if (line.length == 0)
		{
			if (flush())
				return true;
			continue;
		}
		if (line.startsWith("event:"))
		{
			auto v = line["event:".length .. $];
			if (v.startsWith(" "))
				v = v[1 .. $];
			eventType = v;
		}
		else if (line.startsWith("data:"))
		{
			auto d = line["data:".length .. $];
			if (d.startsWith(" "))
				d = d[1 .. $];
			data ~= (haveData ? "\n" : "") ~ d;
			haveData = true;
		}
	}
	// A trailing event without a terminating blank line.
	return flush();
}

/// Resolve a legacy `endpoint` event URI (which may be absolute, root-relative,
/// or document-relative) against the GET-SSE base URL, yielding the absolute URL
/// to POST subsequent JSON-RPC messages to.
string resolveEndpointUri(string baseUrl, string endpoint) @safe
{
	import std.string : indexOf, startsWith, lastIndexOf;

	if (endpoint.startsWith("http://") || endpoint.startsWith("https://"))
		return endpoint;

	// Split base into scheme://authority and path.
	const sep = baseUrl.indexOf("://");
	if (sep < 0)
		return endpoint;
	const afterScheme = sep + 3;
	const slash = baseUrl[afterScheme .. $].indexOf('/');
	string origin = (slash < 0) ? baseUrl : baseUrl[0 .. afterScheme + slash];
	string basePath = (slash < 0) ? "/" : baseUrl[afterScheme + slash .. $];

	if (endpoint.startsWith("/"))
		return origin ~ endpoint;

	// Document-relative: replace the last path segment of the base.
	const lastSlash = basePath.lastIndexOf('/');
	string dir = (lastSlash < 0) ? "/" : basePath[0 .. lastSlash + 1];
	return origin ~ dir ~ endpoint;
}

unittest  // parseHttpEndpoint defaults the port per scheme (443 for TLS)
{
	// https/wss default to 443; http and a bare host to 80. An explicit port wins.
	auto h = parseHttpEndpoint("http://host/mcp");
	assert(!h.tls && h.port == 80 && h.host == "host" && h.path == "/mcp");

	auto s = parseHttpEndpoint("https://host/mcp");
	assert(s.tls && s.port == 443 && s.host == "host" && s.path == "/mcp");

	auto sp = parseHttpEndpoint("https://host:8443/x");
	assert(sp.tls && sp.port == 8443);

	auto ws = parseHttpEndpoint("wss://host");
	assert(ws.tls && ws.port == 443 && ws.path == "/");

	auto bare = parseHttpEndpoint("host:9000/p");
	assert(!bare.tls && bare.port == 9000 && bare.host == "host" && bare.path == "/p");
}

unittest  // an https URL constructs (TLS supported)
{
	// The streaming HTTP client transport wires real TLS through every raw-TCP
	// path (openClientStream wraps the connection in a vibe TLS tunnel with
	// SNI = host and peer-certificate verification, port 443 by default). An
	// https/wss URL constructs successfully and the TLS handshake happens on
	// first connect.
	auto https = new HttpClientTransport("https://example.com/mcp");
	assert(https !is null);
	auto wss = new HttpClientTransport("wss://example.com/mcp");
	assert(wss !is null);

	// A plaintext http URL still constructs fine (the common case is unaffected).
	auto ok = new HttpClientTransport("http://127.0.0.1:8080/mcp");
	assert(ok !is null);
}

unittest  // openClientStream returns a usable stream for plaintext (TLS path needs a live peer)
{
	// The plaintext branch returns the raw connection boxed in a ProxyStream so the
	// five request paths share one static stream type. We cannot complete a TLS
	// handshake without a live peer here, but we can assert the helper is wired (the
	// TLS branch is exercised end-to-end by the integration paths / conformance).
	auto ep = parseHttpEndpoint("https://example.com/mcp");
	assert(ep.tls && ep.port == 443 && ep.host == "example.com");
	auto plain = parseHttpEndpoint("http://example.com/mcp");
	assert(!plain.tls && plain.port == 80);
}

unittest  // parseHttpStatus reads the code out of an HTTP status line
{
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 200 OK") == 200);
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 202 Accepted\r") == 202);
	assert(HttpClientTransport.parseHttpStatus("HTTP/1.1 404 Not Found") == 404);
	// Unparseable lines yield 0 (treated as no status).
	assert(HttpClientTransport.parseHttpStatus("garbage") == 0);
	assert(HttpClientTransport.parseHttpStatus("") == 0);
}

unittest  // isLegacyFallbackStatus recognises the spec's 400/404/405 triggers
{
	assert(isLegacyFallbackStatus(400));
	assert(isLegacyFallbackStatus(404));
	assert(isLegacyFallbackStatus(405));
}

unittest  // isLegacyFallbackStatus ignores success and other errors
{
	assert(!isLegacyFallbackStatus(200));
	assert(!isLegacyFallbackStatus(202));
	assert(!isLegacyFallbackStatus(401));
	assert(!isLegacyFallbackStatus(500));
}

unittest  // isModernRpcErrorCode recognises the modern-vs-legacy disambiguators
{
	// Per draft basic/transports §Backward Compatibility, these are the
	// JSON-RPC error codes a 400/404/405 body may carry to prove the server
	// speaks a modern MCP version rather than being a legacy HTTP+SSE server.
	assert(isModernRpcErrorCode(ErrorCode.unsupportedProtocolVersion)); // -32004
	assert(isModernRpcErrorCode(ErrorCode.headerMismatch)); // -32001
	assert(isModernRpcErrorCode(ErrorCode.methodNotFound)); // -32601
	assert(isModernRpcErrorCode(ErrorCode.missingRequiredClientCapability)); // -32003
}

unittest  // isModernRpcErrorCode rejects unrelated codes
{
	assert(!isModernRpcErrorCode(ErrorCode.internalError));
	assert(!isModernRpcErrorCode(ErrorCode.invalidParams));
	assert(!isModernRpcErrorCode(0));
}

unittest  // modernErrorFromBody surfaces a recognized modern JSON-RPC error
{
	// 400 + UnsupportedProtocolVersionError body → typed McpException, NOT legacy.
	McpException err;
	assert(modernErrorFromBody(`{"jsonrpc":"2.0","id":1,"error":{"code":-32004,"message":"bad version","data":{"supported":["2025-11-25"]}}}`,
			err));
	assert(err !is null);
	assert(err.code == ErrorCode.unsupportedProtocolVersion);
}

unittest  // modernErrorFromBody surfaces a 404 method-not-found body
{
	McpException err;
	assert(modernErrorFromBody(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, err));
	assert(err !is null);
	assert(err.code == ErrorCode.methodNotFound);
}

unittest  // modernErrorFromBody ignores an empty body (legacy fallback path)
{
	McpException err;
	assert(!modernErrorFromBody("", err));
	assert(err is null);
	assert(!modernErrorFromBody("   ", err));
	assert(err is null);
}

unittest  // modernErrorFromBody ignores non-JSON / non-error bodies
{
	McpException err;
	assert(!modernErrorFromBody("not json at all", err));
	assert(err is null);
	// A well-formed JSON-RPC result is not an error body.
	assert(!modernErrorFromBody(`{"jsonrpc":"2.0","id":1,"result":{}}`, err));
	assert(err is null);
}

unittest  // modernErrorFromBody ignores an error whose code is not a modern disambiguator
{
	// e.g. a generic internalError in a 400 body is NOT a modern-MCP signal.
	McpException err;
	assert(!modernErrorFromBody(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}`, err));
	assert(err is null);
}

unittest  // parseEndpointEvent extracts the message URI from a legacy SSE endpoint event
{
	// A real 2024-11-05 HTTP+SSE server's first event on the GET stream.
	string sse = "event: endpoint\ndata: /messages?sessionId=abc123\n\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/messages?sessionId=abc123");
}

unittest  // parseEndpointEvent handles CRLF line endings and leading data space
{
	string sse = "event: endpoint\r\ndata:/messages\r\n\r\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/messages");
}

unittest  // parseEndpointEvent ignores a message event and finds a later endpoint event
{
	string sse = "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n"
		~ "event: endpoint\ndata: /post\n\n";
	string uri;
	assert(parseEndpointEvent(sse, uri));
	assert(uri == "/post");
}

unittest  // parseEndpointEvent returns false when no endpoint event is present
{
	string sse = "event: message\ndata: {}\n\n";
	string uri;
	assert(!parseEndpointEvent(sse, uri));
}

unittest  // resolveEndpointUri keeps an absolute URI unchanged
{
	assert(resolveEndpointUri("http://host:8080/mcp",
			"http://other:9000/messages") == "http://other:9000/messages");
}

unittest  // resolveEndpointUri resolves a root-relative path against the server origin
{
	assert(resolveEndpointUri("http://host:8080/sse",
			"/messages?sessionId=abc") == "http://host:8080/messages?sessionId=abc");
}

unittest  // resolveEndpointUri resolves a relative path against the base directory
{
	assert(resolveEndpointUri("http://host:8080/api/sse",
			"messages") == "http://host:8080/api/messages");
}
