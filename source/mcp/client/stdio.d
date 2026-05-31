module mcp.client.stdio;

import std.typecons : Nullable;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.client.transport : ClientTransport, ClientProtocol;
import mcp.client.subscription : SubscriptionStream;

@safe:

/// A `ClientTransport` over the MCP **stdio** transport.
///
/// Per the MCP stdio transport, the host launches the MCP server as a
/// subprocess and exchanges newline-delimited JSON-RPC messages over its
/// `stdin`/`stdout`; only valid MCP messages are written to the server's
/// `stdin` (newlines are never embedded in a message), and `stderr` is used by
/// the server for logging.
///
/// This class is transport-pure: it is constructed with a `readLine`/`writeLine`
/// pair (symmetric to `mcp.transport.stdio.serveStdio` on the server side) and
/// carries the bytes for an owning `McpClient`. There is no standalone
/// server->client stream, no bearer token, and no backward-compatibility
/// fallback over stdio, so `startServerStream`, `setBearerToken`, and
/// `startLegacyFallback` are no-ops. `close()` terminates the subprocess when
/// one was spawned (see `McpClient.spawn`).
final class StdioClientTransport : ClientTransport
{
	import std.process : ProcessPipes;
	import core.time : Duration, seconds, msecs;

	private string delegate() @safe readLine;
	private void delegate(string) @safe writeLine;
	private void delegate(Message) @safe inbound;
	// When spawned via `McpClient.spawn`, the owned subprocess pipes so `close()`
	// can run the MCP stdio shutdown sequence (close stdin -> SIGTERM -> SIGKILL).
	private Nullable!ProcessPipes pipes;

	/// Construct over a newline-delimited JSON-RPC channel. `readLine` returns
	/// the next line from the server (without its terminator) or `null` at
	/// end-of-input; `writeLine` emits one request/notification line to the
	/// server (the sink appends the terminator).
	this(string delegate() @safe readLine, void delegate(string) @safe writeLine) @safe
	{
		this.readLine = readLine;
		this.writeLine = writeLine;
	}

	void setInboundHandler(void delegate(Message) @safe handler) @safe
	{
		inbound = handler;
	}

	/// The stdio transport needs neither protocol-derived headers nor the
	/// cancelled-response predicate (it has no HTTP headers and correlates
	/// responses by id on a single channel), so it ignores the installed
	/// `ClientProtocol`.
	void setProtocol(ClientProtocol protocol) @safe
	{
	}

	/// No-op: there is no HTTP+SSE backward-compatibility fallback over stdio.
	void startLegacyFallback() @safe
	{
	}

	/// No-op: there is no OAuth bearer token over stdio.
	void setBearerToken(string token) @safe
	{
	}

	/// No-op: there is no standalone server->client stream over stdio.
	void startServerStream() @safe
	{
	}

	/// Unsupported over stdio: the draft `subscriptions/listen` long-lived stream
	/// is an HTTP-transport feature. Returns an inert, already-usable handle.
	SubscriptionStream openListen(Json message) @safe
	{
		auto cancelled = () @trusted { return new shared bool(false); }();
		return new SubscriptionStream(cancelled);
	}

	/// Send a request and return its result (or throw `McpException`). Inbound
	/// notifications and server->client requests received while waiting are
	/// dispatched until the correlated response (`expectId`) arrives.
	Json deliver(Json message, long expectId) @safe
	{
		send(message);
		return await(expectId);
	}

	/// Send a message that expects no correlated reply (notification, or a
	/// response to a server->client request).
	void sendOneway(Json message) @safe
	{
		send(message);
	}

	/// Serialize a single message and write it as one newline-delimited line.
	/// `Json.toString` never emits a raw newline, so the line framing holds and
	/// only a valid MCP message is written to the server's stdin.
	private void send(Json message) @safe
	{
		writeLine(message.toString());
	}

	/// Read lines until the response correlated with `expectId` arrives,
	/// dispatching notifications (and ignoring stray server messages) along the
	/// way. Throws on end-of-input before the response or on a JSON-RPC error.
	private Json await(long expectId) @safe
	{
		for (;;)
		{
			auto line = readLine();
			if (line is null)
				throw internalError(
						"Server closed stdout before responding to request " ~ idStr(expectId));
			if (line.length == 0)
				continue; // blank line, ignore

			Message msg;
			try
				msg = parseMessage(line);
			catch (Exception)
				continue; // not a JSON-RPC message (e.g. stray stdout); ignore

			final switch (msg.kind)
			{
			case MessageKind.response:
				if (msg.id.type == Json.Type.int_
						&& msg.id.get!long == expectId)
					return msg.result;
				break;
			case MessageKind.errorResponse:
				if (msg.id.type == Json.Type.int_
						&& msg.id.get!long == expectId)
					throw errorFrom(msg.error);
				break;
			case MessageKind.notification:
				dispatch(msg);
				break;
			case MessageKind.request:
				// The server initiated a request (e.g. ping). Hand it to the
				// client's inbound dispatcher, which replies via sendOneway.
				dispatch(msg);
				break;
			}
		}
	}

	/// Hand an inbound message to the client's dispatcher.
	private void dispatch(Message msg) @safe
	{
		if (inbound !is null)
			inbound(msg);
	}

	/// Attach owned subprocess pipes so `close()` runs the stdio shutdown
	/// sequence. Set by `McpClient.spawn`.
	package void attachProcess(ProcessPipes pipes) @safe
	{
		this.pipes = pipes;
	}

	/// Release transport resources. When this transport owns a spawned
	/// subprocess (`McpClient.spawn`), run the MCP stdio Shutdown sequence
	/// (basic/lifecycle §Shutdown -> stdio): close the child's stdin, escalate to
	/// `SIGTERM`, then `SIGKILL` if it does not exit within the grace periods.
	/// A no-op when there is no owned subprocess (a custom `readLine`/`writeLine`
	/// channel).
	void close() @safe
	{
		if (!pipes.isNull)
			closeProcess(5.seconds, 5.seconds);
	}

	/// Shut the owned child down per the MCP stdio Shutdown sequence and return
	/// its exit status (a process killed by signal reports a negative status per
	/// `std.process.wait`). Safe to call once.
	package int closeProcess(Duration termGrace, Duration killGrace) @safe
	{
		auto p = pipes.get;
		() @trusted { p.stdin.close(); }();

		// Step 1+2: wait for a clean exit, escalating to SIGTERM on timeout.
		auto status = waitUntil(termGrace);
		if (!status.isNull)
			return status.get;

		version (Posix)
		{
			import std.process : kill;
			import core.sys.posix.signal : SIGTERM, SIGKILL;

			() @trusted { kill(p.pid, SIGTERM); }();
			status = waitUntil(killGrace);
			if (!status.isNull)
				return status.get;

			// Step 3: still alive after SIGTERM -- force kill and reap.
			() @trusted { kill(p.pid, SIGKILL); }();
		}
		else
		{
			import std.process : kill;

			// On Windows there is no SIGTERM/SIGKILL distinction; TerminateProcess
			// is the forceful equivalent of SIGKILL.
			() @trusted { kill(p.pid); }();
		}

		import std.process : wait;

		return () @trusted { return wait(p.pid); }();
	}

	/// Poll `tryWait` until the child exits or `grace` elapses. Returns the exit
	/// status if it exited within the deadline, or null if it is still running.
	private Nullable!int waitUntil(Duration grace) @safe
	{
		import std.process : tryWait;
		import std.datetime.stopwatch : StopWatch, AutoStart;
		import core.thread : Thread;

		auto p = pipes.get;
		auto sw = StopWatch(AutoStart.yes);
		for (;;)
		{
			auto r = () @trusted { return tryWait(p.pid); }();
			if (r.terminated)
				return Nullable!int(r.status);
			if (sw.peek >= grace)
				return Nullable!int.init;
			() @trusted { Thread.sleep(10.msecs); }();
		}
	}

	private static McpException errorFrom(Json error) @safe
	{
		const code = ("code" in error) ? error["code"].get!int : ErrorCode.internalError;
		const m = ("message" in error) ? error["message"].get!string : "server error";
		return new McpException(code, m, error);
	}

	private static string idStr(long id) @safe
	{
		import std.conv : to;

		return id.to!string;
	}
}

/// Launch an MCP server as a subprocess and wire a `StdioClientTransport` to its
/// stdin/stdout. `args` is the command line (`args[0]` is the executable);
/// newline-delimited JSON-RPC requests are written to the child's stdin and
/// responses are read from its stdout; the child's stderr is inherited for
/// logging. The returned transport owns the subprocess: its `close()` runs the
/// stdio shutdown sequence. Used by `McpClient.spawn`.
StdioClientTransport spawnStdioTransport(string[] args) @safe
{
	import std.process : pipeProcess, Redirect;
	import std.string : stripRight;

	// Redirect stdin and stdout (frame the JSON-RPC channel); leave stderr
	// attached to ours so the server's logging is visible.
	auto pipes = () @trusted {
		return pipeProcess(args, Redirect.stdin | Redirect.stdout);
	}();

	auto transport = new StdioClientTransport(() @trusted {
		auto f = pipes.stdout;
		if (f.eof)
			return cast(string) null;
		auto ln = f.readln();
		if (ln.length == 0 && f.eof)
			return cast(string) null;
		return ln.stripRight("\r\n");
	}, (string s) @trusted { pipes.stdin.writeln(s); pipes.stdin.flush(); });
	transport.attachProcess(pipes);
	return transport;
}

version (unittest)
{
	import mcp.server.server : McpServer;
	import mcp.client.client : McpClient;
	import mcp.protocol.types : Tool, Content, CallToolResult;
}

unittest  // McpClient over a stdio transport drives an in-process server (initialize + tools)
{
	// Wire a stdio-transport McpClient to an McpServer through two queues, pumping
	// the server synchronously: every request the client writes is handled
	// immediately and its response queued for the client to read back.
	auto server = new McpServer("stdio-client-srv", "1.0");
	Tool echo = {name: "echo"};
	server.registerDynamicTool(echo, (Json args) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});

	string[] toServer; // lines written by the client, awaiting the server
	string[] toClient; // response lines queued for the client to read

	auto client = McpClient.stdio(() @safe {
		// Drain pending server work so a response is available before we read.
		while (toClient.length == 0 && toServer.length)
		{
			auto req = toServer[0];
			toServer = toServer[1 .. $];
			auto resp = server.handleRaw(req);
			if (resp.length)
				toClient ~= resp;
		}
		if (toClient.length == 0)
			return cast(string) null;
		auto line = toClient[0];
		toClient = toClient[1 .. $];
		return line;
	}, (string s) @safe { toServer ~= s; });

	auto init = client.initialize();
	assert(init.serverInfo.name == "stdio-client-srv");

	auto tools = client.listTools().tools;
	assert(tools.length == 1);
	assert(tools[0].name == "echo");

	auto res = client.callTool("echo");
	assert(res.content[0].text == "ok");
}

unittest  // stdio transport surfaces a correlated server error response as an McpException
{
	// The server answers our request (id 1) with a JSON-RPC error carrying the
	// matching id; the client must raise it as an McpException with that code.
	string[] toClient = [
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
	];

	auto client = McpClient.stdio(() @safe {
		if (toClient.length == 0)
			return cast(string) null;
		auto line = toClient[0];
		toClient = toClient[1 .. $];
		return line;
	}, (string) @safe {});

	int code;
	bool threw;
	try
		client.ping();
	catch (McpException e)
	{
		threw = true;
		code = e.code;
	}
	assert(threw);
	assert(code == ErrorCode.methodNotFound);
}

unittest  // stdio transport throws when the server closes stdout before responding
{
	auto client = McpClient.stdio(() @safe { return cast(string) null; }, (string) @safe {
	});
	bool threw;
	try
		client.ping();
	catch (McpException)
		threw = true;
	assert(threw);
}

unittest  // stdio transport dispatches inbound notifications while awaiting a response
{
	string[] toClient = [
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
	];
	string[] gotMethods;

	auto client = McpClient.stdio(() @safe {
		if (toClient.length == 0)
			return cast(string) null;
		auto line = toClient[0];
		toClient = toClient[1 .. $];
		return line;
	}, (string) @safe {});
	client.onNotification = (string method, Json params) @safe {
		gotMethods ~= method;
	};

	client.ping(); // id 1; the notification precedes the response
	assert(gotMethods == ["notifications/message"]);
}

unittest  // stdio transport answers a server-initiated ping while awaiting its own response
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	string[] toServer;
	string[] toClient = [
		`{"jsonrpc":"2.0","id":100,"method":"ping"}`, // server pings us first
		`{"jsonrpc":"2.0","id":1,"result":{}}`, // then answers our request
	];

	auto client = McpClient.stdio(() @safe {
		if (toClient.length == 0)
			return cast(string) null;
		auto line = toClient[0];
		toClient = toClient[1 .. $];
		return line;
	}, (string s) @safe { toServer ~= s; });

	// The reply to a server->client request is sent on a separate task, so drive
	// the client under the event loop and let pending tasks flush.
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			client.ping();
			import vibe.core.core : yield;

			foreach (_; 0 .. 4)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// We should have replied to the server's ping (id 100) in addition to
	// sending our own request (id 1).
	assert(toServer.length == 2);
	bool repliedToPing;
	foreach (line; toServer)
	{
		auto m = parseJsonString(line);
		if ("id" in m && m["id"].get!int == 100 && "result" in m)
			repliedToPing = true;
	}
	assert(repliedToPing);
}

version (Posix) unittest  // close() escalates to SIGTERM when the child ignores stdin EOF
{
	import std.process : pipeProcess, Redirect;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import core.time : seconds, msecs;
	import core.sys.posix.signal : SIGTERM;

	// `sleep 30` does not exit when its stdin is closed, so closing stdin alone
	// would hang forever; the escalating shutdown must SIGTERM it.
	auto transport = spawnStdioTransport(["sh", "-c", "sleep 30"]);

	auto sw = StopWatch(AutoStart.yes);
	auto status = transport.closeProcess(200.msecs, 2.seconds);
	// Must return well before the 30s sleep would have finished.
	assert(sw.peek < 5.seconds);
	// Killed by SIGTERM => negative status reporting the signal.
	assert(status == -SIGTERM);
}

version (Posix) unittest  // close() escalates to SIGKILL when the child also ignores SIGTERM
{
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import core.time : seconds, msecs;
	import core.sys.posix.signal : SIGKILL;

	// Trap (ignore) SIGTERM, then sleep; only SIGKILL can stop this child.
	auto transport = spawnStdioTransport(["sh", "-c", "trap '' TERM; sleep 30"]);

	auto sw = StopWatch(AutoStart.yes);
	auto status = transport.closeProcess(200.msecs, 200.msecs);
	assert(sw.peek < 5.seconds);
	// SIGTERM was ignored, so the kill must have come from SIGKILL.
	assert(status == -SIGKILL);
}

version (Posix) unittest  // close() returns the child's clean exit status when it exits on stdin EOF
{
	import core.time : seconds;

	// `cat` exits 0 once its stdin reaches EOF, so step 1 (close stdin) suffices.
	auto transport = spawnStdioTransport(["cat"]);

	auto status = transport.closeProcess(5.seconds, 5.seconds);
	assert(status == 0);
}
