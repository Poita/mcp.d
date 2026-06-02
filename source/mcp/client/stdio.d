module mcp.client.stdio;

import std.typecons : Nullable;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.client.transport : ClientTransport, ClientProtocol;
import mcp.client.subscription : SubscriptionStream;
import mcp.transport.duplex : DuplexChannel, defaultMaxLineBytes;

@safe:

/// A `ClientTransport` over the MCP **stdio** transport, built on the shared
/// full-duplex `DuplexChannel`.
///
/// Per the MCP stdio transport, the host launches the MCP server as a subprocess
/// and exchanges newline-delimited JSON-RPC messages over its `stdin`/`stdout`;
/// only valid MCP messages are written to the server's `stdin` (newlines are
/// never embedded in a message), and `stderr` is used by the server for logging.
///
/// This class is transport-pure: it is constructed with a `readLine`/`writeLine`
/// pair (symmetric to `mcp.transport.stdio.serveStdio` on the server side) that a
/// running event loop drives cooperatively. The `DuplexChannel`'s read loop
/// demultiplexes inbound lines, so several requests can be in flight at once and
/// the server may push notifications (or server->client requests) at any time —
/// each is routed to the owning `McpClient`'s inbound dispatcher. There is no
/// bearer token and no backward-compatibility fallback over stdio, so
/// `setBearerToken`, `startServerStream`, and `startLegacyFallback` are no-ops.
/// `close()` terminates the subprocess when one was spawned (see
/// `McpClient.spawn`).
///
/// Concurrency requires a running vibe event loop: the supplied `readLine`/
/// `writeLine` MUST be async (non-blocking on a vibe stream). `McpClient.spawn`
/// wires that automatically; the `McpClient.stdio(readLine, writeLine)` delegate
/// overload is for custom channels and the caller is responsible for supplying
/// async delegates.
final class StdioClientTransport : ClientTransport
{
	import vibe.core.process : ProcessPipes;
	import core.time : Duration, seconds, msecs;

	private string delegate() @safe readLine;
	private void delegate(string) @safe writeLine;
	private void delegate(Message) @safe inbound;
	private DuplexChannel channel;
	private bool started;
	// When spawned via `McpClient.spawn`, the owned subprocess pipes so `close()`
	// can run the MCP stdio shutdown sequence (close stdin -> SIGTERM -> SIGKILL).
	private ProcessPipes* pipes;

	/// Construct over a newline-delimited JSON-RPC channel. `readLine` returns the
	/// next line from the server (without its terminator) or `null` at
	/// end-of-input; `writeLine` emits one request/notification line to the server
	/// (the sink appends the terminator). Both MUST be async (cooperative) when the
	/// client is driven under an event loop.
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

	/// No-op: there is no standalone server->client stream over stdio (the single
	/// duplex channel already carries server->client traffic).
	void startServerStream() @safe
	{
	}

	/// Lazily build and start the duplex channel on first use. The channel needs
	/// the inbound dispatcher (`setInboundHandler`) installed first, and a running
	/// event loop for its read-loop task — both true by the time `McpClient` issues
	/// its first `deliver`.
	private DuplexChannel chan() @safe
	{
		if (channel is null)
			channel = new DuplexChannel(readLine, writeLine, (Message m) @safe {
				if (inbound !is null)
					inbound(m);
			});
		if (!started)
		{
			channel.start();
			started = true;
		}
		return channel;
	}

	/// Open a draft `subscriptions/listen` stream over stdio. Unlike Streamable
	/// HTTP — where the listen stream is a separate long-lived SSE response — stdio
	/// shares one channel, so opening a subscription is just writing the
	/// `subscriptions/listen` request line; the server delivers the leading
	/// `notifications/subscriptions/acknowledged` and every subsequent change
	/// notification on the same stdout channel, each stamped with
	/// `io.modelcontextprotocol/subscriptionId` (the listen request id), and they
	/// reach the client's inbound dispatcher through the channel's read loop (draft
	/// basic/utilities/subscriptions: "On stdio ... clients MUST use this field to
	/// correlate notifications"). The returned handle's `cancel()`/`close()` ends
	/// the subscription by sending `notifications/cancelled` referencing the listen
	/// request id, per the draft stdio cancellation rule.
	SubscriptionStream openListen(Json message) @safe
	{
		// Write the real listen request on the single channel (the previous no-op
		// dropped it, so a stdio client could never subscribe).
		send(message);

		// The listen request id is the subscriptionId; cancel() references it.
		Json listenId = ("id" in message) ? message["id"] : Json(null);
		auto cancelled = () @trusted { return new shared bool(false); }();
		void delegate() @safe nothrow onCancel = () @safe nothrow{
			try
			{
				Json params = Json.emptyObject;
				params["requestId"] = listenId;
				sendOneway(makeNotification("notifications/cancelled", params));
			}
			catch (Exception)
			{
			}
		};
		return new SubscriptionStream(cancelled, onCancel);
	}

	/// Send a request and return its result (or throw `McpException`). The channel
	/// correlates the reply by `expectId` while its read loop concurrently
	/// dispatches any interleaved notifications and server->client requests, so
	/// multiple `deliver` calls may be in flight at once.
	Json deliver(Json message, long expectId) @safe
	{
		return chan().deliver(message, expectId);
	}

	/// Send a message that expects no correlated reply (notification, or a
	/// response to a server->client request).
	void sendOneway(Json message) @safe
	{
		send(message);
	}

	/// False: a reply to a server->client request MUST NOT be written inline from
	/// the channel's read-loop task. Although the write is serialized by the
	/// channel's `writeMutex`, writing the reply inline blocks the single read-loop
	/// task until the OS pipe buffer accepts the whole frame. With a spawned
	/// subprocess that can deadlock: the child may be blocked writing more stdout
	/// (because we have stopped draining it while writing the reply) while we are
	/// blocked writing the reply into its stdin (because the child has stopped
	/// draining its stdin to write that stdout). Returning false makes
	/// `McpClient.handleServerRequest` dispatch the reply on its own vibe task, so
	/// the read loop keeps draining the child's stdout and the two directions cannot
	/// wedge each other. The stdio transport always runs its read loop as a vibe
	/// task (`DuplexChannel.start` -> `runTask`), so an event loop is always
	/// available for that deferred task — both in the spawned-subprocess model and
	/// the custom `McpClient.stdio(readLine, writeLine)` delegate channel.
	bool repliesSynchronously() @safe
	{
		return false;
	}

	/// Serialize a single message and write it as one newline-delimited line
	/// through the channel's serialized writer. `Json.toString` never emits a raw
	/// newline, so the line framing holds and only a valid MCP message is written
	/// to the server's stdin.
	private void send(Json message) @safe
	{
		chan().send(message);
	}

	/// Attach owned subprocess pipes so `close()` runs the stdio shutdown
	/// sequence. Set by `McpClient.spawn`.
	package void attachProcess(ProcessPipes* pipes) @safe
	{
		this.pipes = pipes;
	}

	/// Release transport resources. When this transport owns a spawned subprocess
	/// (`McpClient.spawn`), run the MCP stdio Shutdown sequence (basic/lifecycle
	/// §Shutdown -> stdio): close the child's stdin, escalate to `SIGTERM`, then
	/// `SIGKILL` if it does not exit within the grace periods. A no-op when there is
	/// no owned subprocess (a custom `readLine`/`writeLine` channel).
	void close() @safe
	{
		if (channel !is null)
			channel.close();
		if (pipes !is null)
			closeProcess(5.seconds, 5.seconds);
	}

	/// Shut the owned child down per the MCP stdio Shutdown sequence and return its
	/// exit status (a process killed by signal reports a negative status, matching
	/// the prior `std.process.wait` convention: `-SIGTERM` / `-SIGKILL`). Safe to
	/// call once.
	package int closeProcess(Duration termGrace, Duration killGrace) @safe
	{
		import core.sys.posix.signal : SIGTERM, SIGKILL;

		auto p = pipes;
		// Step 0: close the child's stdin so a well-behaved server sees EOF and exits.
		() @trusted { p.stdin.close(); }();

		// Step 1: wait for a clean exit within the SIGTERM grace.
		auto status = () @trusted { return p.process.wait(termGrace); }();
		if (!status.isNull)
			return status.get;

		version (Posix)
		{
			// Step 2: escalate to SIGTERM and wait again.
			() @trusted { p.process.kill(SIGTERM); }();
			status = () @trusted { return p.process.wait(killGrace); }();
			if (!status.isNull)
				return -SIGTERM;

			// Step 3: still alive -> force kill (SIGKILL) and reap.
			() @trusted { p.process.kill(SIGKILL); }();
			() @trusted { p.process.wait(); }();
			return -SIGKILL;
		}
		else
		{
			() @trusted { p.process.forceKill(); }();
			return () @trusted { return p.process.wait(); }();
		}
	}
}

/// Launch an MCP server as a subprocess and wire a `StdioClientTransport` to its
/// stdin/stdout via vibe's async process pipes. `args` is the command line
/// (`args[0]` is the executable); newline-delimited JSON-RPC requests are written
/// to the child's stdin and responses are read from its stdout; the child's
/// stderr is inherited for logging. The read/write delegates are async
/// (cooperative on the vibe event loop) so the duplex read loop never blocks the
/// loop. The returned transport owns the subprocess: its `close()` runs the stdio
/// shutdown sequence. Used by `McpClient.spawn`. REQUIRES a running event loop.
StdioClientTransport spawnStdioTransport(string[] args, size_t maxLineBytes = defaultMaxLineBytes) @safe
{
	import vibe.core.process : pipeProcess, ProcessPipes, Redirect;
	import eventcore.driver : IOMode;

	// Heap-box the pipes so the read/write closures capture a stable, long-lived
	// handle past this function's return (`attachProcess` keeps the same pointer
	// for the shutdown sequence).
	auto pipes = () @trusted { return new ProcessPipes; }();
	() @trusted { *pipes = pipeProcess(args, Redirect.stdin | Redirect.stdout); }();

	// Async, cooperative line read over the child's stdout: accumulate bytes until
	// '\n' (stripping a trailing '\r'); a 0-byte read is EOF -> return null so the
	// duplex read loop ends. (The byte source is already buffered by vibe's
	// PipeInputStream, so single-byte reads here do not hit the OS per byte.) If a
	// single line exceeds `maxLineBytes` the child is producing an unbounded,
	// newline-less stream — treat it as a transport error and return null to end the
	// duplex read loop rather than grow the accumulator without limit.
	string readLine() @safe
	{
		ubyte[1] one;
		ubyte[] acc;
		for (;;)
		{
			size_t n;
			n = () @trusted { return pipes.stdout.read(one[], IOMode.once); }();
			if (n == 0)
				return acc.length ? () @trusted { return cast(string) acc.idup; }() : null;
			if (one[0] == '\n')
				break;
			acc ~= one[0];
			if (acc.length > maxLineBytes)
				return null; // over-long, newline-less frame -> end the read loop
		}
		if (acc.length && acc[$ - 1] == '\r')
			acc = acc[0 .. $ - 1];
		return () @trusted { return cast(string) acc.idup; }();
	}

	void writeLine(string s) @safe
	{
		auto bytes = cast(const(ubyte)[])(s ~ "\n");
		() @trusted { pipes.stdin.write(bytes); pipes.stdin.flush(); }();
	}

	auto transport = new StdioClientTransport(&readLine, &writeLine);
	transport.attachProcess(pipes);
	return transport;
}

version (unittest)
{
	import mcp.server.server : McpServer;
	import mcp.client.client : McpClient;
	import mcp.protocol.types : Tool, Content, CallToolResult;
	import mcp.client.subscription : SubscriptionFilter;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, yield;
}

// Run `body` inside a vibe task + event loop, exiting the loop when it returns.
version (unittest) private void inLoop(scope void delegate() @safe body) @trusted
{
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			body();
		catch (Exception)
		{
		}
	});
	runEventLoop();
}

unittest  // stdio openListen writes the subscriptions/listen request to the server (draft)
{
	// Per draft basic/utilities/subscriptions, a stdio client opens a subscription
	// by sending a real `subscriptions/listen` request on the single stdin channel.
	string[] toServer;

	inLoop(() @safe {
		auto client = McpClient.stdio(() @safe { return cast(string) null; }, (string s) @safe {
			toServer ~= s;
		});
		client.enableDraft();

		SubscriptionFilter filter = {toolsListChanged: true};
		client.subscriptionsListen(filter);
		foreach (_; 0 .. 4)
			yield();
	});

	assert(toServer.length == 1, "listen request must be written to the server");
	auto m = parseJsonString(toServer[0]);
	assert(m["method"].get!string == "subscriptions/listen");
	assert("id" in m, "listen is a request and MUST carry an id");
	assert(m["params"]["notifications"]["toolsListChanged"].get!bool == true);
}

unittest  // stdio listen cancel() emits notifications/cancelled referencing the listen request id
{
	string[] toServer;

	inLoop(() @safe {
		auto client = McpClient.stdio(() @safe { return cast(string) null; }, (string s) @safe {
			toServer ~= s;
		});
		client.enableDraft();

		SubscriptionFilter filter = {resourcesListChanged: true};
		auto stream = client.subscriptionsListen(filter);
		foreach (_; 0 .. 4)
			yield();

		auto listenMsg = parseJsonString(toServer[0]);
		auto listenId = listenMsg["id"].get!long;

		toServer = null;
		stream.cancel();
		foreach (_; 0 .. 4)
			yield();

		assert(toServer.length == 1, "cancel() must write notifications/cancelled");
		auto c = parseJsonString(toServer[0]);
		assert(c["method"].get!string == "notifications/cancelled");
		assert(c["params"]["requestId"].get!long == listenId);
		assert("id" !in c, "a notification MUST NOT carry an id");
		assert(stream.cancelled);

		// Idempotent: a second cancel must not emit another notification.
		stream.cancel();
		foreach (_; 0 .. 2)
			yield();
		assert(toServer.length == 1);
	});
}

version (Posix) unittest  // close() escalates to SIGTERM when the child ignores stdin EOF
{
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import core.time : seconds, msecs;
	import core.sys.posix.signal : SIGTERM;

	inLoop(() @safe {
		// `sleep 30` does not exit when its stdin is closed, so the escalating
		// shutdown must SIGTERM it.
		auto transport = spawnStdioTransport(["sh", "-c", "sleep 30"]);
		auto sw = StopWatch(AutoStart.yes);
		auto status = transport.closeProcess(200.msecs, 2.seconds);
		assert(sw.peek < 5.seconds);
		assert(status == -SIGTERM);
	});
}

version (Posix) unittest  // close() escalates to SIGKILL when the child also ignores SIGTERM
{
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import core.time : seconds, msecs;
	import core.sys.posix.signal : SIGKILL;

	inLoop(() @safe {
		auto transport = spawnStdioTransport([
			"sh", "-c", "trap '' TERM; sleep 30"
		]);
		auto sw = StopWatch(AutoStart.yes);
		auto status = transport.closeProcess(200.msecs, 200.msecs);
		assert(sw.peek < 5.seconds);
		assert(status == -SIGKILL);
	});
}

version (Posix) unittest  // close() returns the child's clean exit status when it exits on stdin EOF
{
	import core.time : seconds;

	inLoop(() @safe {
		// `cat` exits 0 once its stdin reaches EOF, so step 0 (close stdin) suffices.
		auto transport = spawnStdioTransport(["cat"]);
		auto status = transport.closeProcess(5.seconds, 5.seconds);
		assert(status == 0);
	});
}

version (Posix) unittest  // spawned transport round-trips a request/response over async pipes
{
	import core.time : seconds;

	inLoop(() @safe {
		// A trivial "server": read one request line, reply with a response
		// correlated to id 1.
		auto transport = spawnStdioTransport([
			"sh", "-c",
			`read line; printf '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'`
		]);
		Json req = parseJsonString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
		auto result = transport.deliver(req, 1);
		assert(result["ok"].get!bool == true);
		transport.closeProcess(5.seconds, 5.seconds);
	});
}

version (Posix) unittest  // #32: an over-long newline-less stream ends the read loop instead of growing unbounded
{
	import core.time : seconds, msecs;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import std.algorithm.searching : canFind;

	inLoop(() @safe {
		// The child floods stdout with newline-less bytes. With a small
		// maxLineBytes the reader must hit the bound and return null (EOF to the
		// duplex loop), so the in-flight deliver fails via failPending ("channel
		// closed") promptly — NOT by accumulating without limit until the 60s
		// deliver timeout.
		auto transport = spawnStdioTransport([
			"sh", "-c", "yes A | tr -d \"\\n\""
		], 4096);

		string msg;
		auto sw = StopWatch(AutoStart.yes);
		try
		{
			Json req = parseJsonString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
			transport.deliver(req, 1);
		}
		catch (McpException e)
			msg = e.msg;
		// The bound must have closed the channel (failPending), not timed out.
		assert(msg.canFind("closed"),
			"over-long newline-less stream must end the read loop via channel close, got: " ~ msg);
		assert(sw.peek < 30.seconds,
			"the over-long-line bound must trip promptly, well under the 60s deliver timeout");
		transport.closeProcess(200.msecs, 200.msecs);
	});
}

unittest  // #31: a server->client reply is NOT written inline from the read-loop task
{
	// A reply written inline from the single read-loop task can deadlock a spawned
	// subprocess (the child blocks writing stdout while we block writing the reply
	// into its stdin). `McpClient.handleServerRequest` only defers the reply to its
	// own task when the transport reports it does NOT reply synchronously, so the
	// stdio transport must report false to keep the read loop draining.
	auto transport = new StdioClientTransport(() @safe { return cast(string) null; },
			(string) @safe {});
	assert(!transport.repliesSynchronously(),
			"stdio reply must be deferred (not inline) so the read loop keeps draining the child");
}
