module mcp.transport.stdio;

import vibe.data.json : Json;

import mcp.server.server;
import mcp.transport.duplex : DuplexChannel, defaultMaxLineBytes;

@safe:

// Module-level guard enforcing runStdio's documented "at most once per process"
// invariant independent of eventcore fd/refcount state (covers both a concurrent
// and a sequential second call).
private __gshared bool _ranStdio;

/// Drive an `McpServer` over a newline-delimited JSON-RPC channel using the
/// shared full-duplex `DuplexChannel`.
///
/// `readLine` returns the next line (without its terminator), or `null` at
/// end-of-input. `writeLine` emits one line (a terminator is added by the
/// caller's sink). Blank input lines are ignored. This is transport-pure —
/// `runStdio` wires it to the process's real stdin/stdout via async pipes.
///
/// The MCP stdio transport is bidirectional and permits the server to write any
/// valid MCP message to stdout at any time, not only direct request replies. The
/// channel's read loop demultiplexes inbound lines:
///
///   - a *request* is dispatched in its OWN cooperative vibe task, so several
///     tool handlers can be in flight concurrently and a handler that blocks on a
///     server->client request (`ctx.sample`/`ctx.elicit`) or polls
///     `ctx.isCancelled` does not stall the read loop. Notifications the handler
///     emits (`notifications/message`, `notifications/progress`) and the request's
///     reply are written through `channel.send` (serialized against other
///     writers);
///   - a *notification* (e.g. `notifications/cancelled`, `notifications/initialized`)
///     is handled inline; an inbound `notifications/cancelled` flips the matching
///     in-flight request's `CancellationToken` concurrently with its running
///     handler task, which then observes `ctx.isCancelled()` and has its response
///     suppressed (basic/utilities/cancellation, draft Transport-Specific
///     Cancellation over stdio);
///   - a draft `subscriptions/listen` request is served on the single channel
///     (its acknowledgement and subsequent change notifications go through
///     `channel.send`).
///
/// Requires a running vibe event loop; `serveStdio` runs the read loop on the
/// CURRENT task and blocks until end-of-input.
void serveStdio(McpServer server, string delegate() @safe readLine,
		void delegate(string) @safe writeLine)
{
	import vibe.core.core : runTask;
	import vibe.data.json : Json;
	import mcp.protocol.jsonrpc : Message, MessageKind;
	import mcp.server.connection : ConnectionState;

	// stdio is single-connection (one implicit peer per process), so this
	// transport owns exactly one `ConnectionState`, which the server core threads
	// through dispatch and reads back for the notify path. Binding it here (before
	// the read loop starts) makes it the state for every request on this process;
	// HTTP instead resolves per-session state per request.
	server.bindConnection(new ConnectionState);

	DuplexChannel channel;

	// The server->client write sink and request channel both go through the one
	// serialized writer on `channel`.
	void sink(string line) @safe
	{
		channel.send(parseToJson(line));
	}

	Json serverRequest(string method, Json params) @safe
	{
		return channel.request(method, params);
	}

	void onInbound(Message m) @safe
	{
		final switch (m.kind)
		{
		case MessageKind.request:
			// Draft `subscriptions/listen` shares the single stdout channel: the
			// server records the opted-in filters and writes a leading
			// `notifications/subscriptions/acknowledged` (the spec's first message,
			// stamped with the listen id as the subscriptionId) instead of a
			// non-spec `{ acknowledged: true }` result; subsequent `notify*` output
			// is routed to the same sink. A non-listen request falls through to the
			// normal concurrent request/reply path.
			if (server.tryServeStdioListen(m, &sink))
				return;
			// Dispatch the request in its own task so a blocking/long-running handler
			// (server->client request, cancellation poll loop) does not stall the
			// read loop. The handler's notifications + reply ride `channel.send`.
			runTask((Message msg) nothrow{
				try
				{
					auto ctx = new StdioContextFactoryReply(server, &sink, &serverRequest, msg);
					ctx.run(channel);
				}
				catch (Exception)
				{
				}
			}, m);
			break;
		case MessageKind.notification:
			// Notifications (initialized / cancelled / roots-changed / progress) are
			// handled inline; they are quick and a cancellation must flip its token
			// promptly for any concurrently-running handler task to observe.
			server.handle(m);
			break;
		case MessageKind.response:
		case MessageKind.errorResponse:
			// A reply to a server->client request: the channel correlates it itself,
			// so this branch is unreachable (the read loop routes responses to the
			// coordinator before calling onInbound). Ignore defensively.
			break;
		}
	}

	channel = new DuplexChannel(readLine, writeLine, &onInbound);
	channel.runReadLoop();
}

/// Helper that dispatches one inbound stdio request through the server with a
/// `StdioContext`, then writes the reply (if any) on the channel. Kept as a small
/// class so the per-request closure captured by `runTask` has a stable `this`.
private final class StdioContextFactoryReply
{
	import vibe.data.json : Json;
	import mcp.protocol.jsonrpc : Message;

	private McpServer server;
	private void delegate(string) @safe sink;
	private Json delegate(string, Json) @safe serverRequest;
	private Message msg;

	this(McpServer server, void delegate(string) @safe sink, Json delegate(string,
			Json) @safe serverRequest, Message msg) @safe
	{
		this.server = server;
		this.sink = sink;
		this.serverRequest = serverRequest;
		this.msg = msg;
	}

	void run(DuplexChannel channel) @safe
	{
		auto reply = server.handleRaw(msg.raw.toString(), sink, serverRequest);
		if (reply.length)
			channel.send(parseToJson(reply));
	}
}

/// Parse a serialized JSON-RPC line back into a `Json` for the channel's
/// serialized writer (which takes a `Json` and re-serializes it). Cheap and keeps
/// `serveStdio`'s sink symmetric with `DuplexChannel.send`.
private Json parseToJson(string line) @safe
{
	import vibe.data.json : parseJsonString;

	return parseJsonString(line);
}

/// Serve `server` over the process's standard input/output: read JSON-RPC
/// messages from stdin (one per line) and write responses to stdout. Per the MCP
/// stdio transport, only valid MCP messages are written to stdout; use stderr for
/// logging. Blocks until stdin reaches end-of-file.
///
/// `runStdio` drives the process's standard input/output and MUST be called at
/// most once per process (enforced by an explicit module-level guard that throws
/// on any second call, concurrent or sequential). Rather than adopting fd 0/1
/// directly -- which would let `releaseRef` `close()` the process's real
/// stdin/stdout, and which sets `O_NONBLOCK` on their shared open file
/// description -- it `dup()`s fd 0/1 first and adopts the dups. On return the
/// saved descriptor flags are restored on fd 0/1 (clearing the O_NONBLOCK that
/// `adopt` set on the dup's shared open file description) and only then are the
/// adopted dups released (their fds closed). fd 0/1 themselves are never adopted
/// and never closed, so a caller that keeps running after `runStdio` returns
/// inherits an open, blocking stdin/stdout.
///
/// stdin (fd 0) and stdout (fd 1) are adopted as vibe-async pipes
/// (`eventDriver.pipes.adopt`, the same mechanism `vibe.core.process` uses for a
/// spawned child), so the read loop is a plain cooperative vibe task — there is
/// NO dedicated OS reader thread and therefore no OS-thread ⇄ event-loop seam to
/// race on. Background notifications (`notifyResourceUpdated`, `notify*ListChanged`)
/// and concurrent tool handlers work because every write goes through the
/// channel's serialized writer.
///
/// `maxLineBytes` bounds a single inbound line; an oversized frame is dropped (its
/// bytes are skipped up to the next newline) and the loop continues so one
/// misbehaving frame neither exhausts memory nor kills the server.
void runStdio(McpServer server, size_t maxLineBytes = defaultMaxLineBytes)
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import eventcore.core : eventDriver;
	import eventcore.driver : IOMode, IOStatus, PipeFD, PipeIOCallback;
	import vibe.internal.async : asyncAwaitUninterruptible;
	import core.sys.posix.unistd : dup, close;
	import core.sys.posix.fcntl : fcntl, F_GETFL, F_SETFL;

	// Enforce the documented "at most once per process" invariant explicitly, so it
	// holds for both a concurrent second call and a sequential one and does not
	// depend on eventcore's adopt()/refCount side effects.
	synchronized
	{
		if (()@trusted { return _ranStdio; }())
			throw new Exception("runStdio: must be called at most once per process");
		() @trusted { _ranStdio = true; }();
	}

	// Adopt dup()'d copies of fd 0/1 rather than fd 0/1 themselves. `releaseRef`
	// close()s the adopted fd on return; by adopting dups we close only the dups,
	// leaving the process's real stdin/stdout OPEN for any code that runs after.
	// Adopting fd 0/1 directly would close the real stdin/stdout.
	const in2 = () @trusted { return dup(0); }();
	const out2 = () @trusted { return dup(1); }();
	if (in2 == -1 || out2 == -1)
	{
		() @trusted {
			if (in2 != -1)
				close(in2);
			if (out2 != -1)
				close(out2);
		}();
		throw new Exception("runStdio: dup(stdin/stdout) failed");
	}

	// A dup shares its open file description (and thus its O_NONBLOCK bit) with the
	// original fd, so the O_NONBLOCK that `adopt` sets is visible on fd 0/1 too. Save
	// the original flags now and restore them BEFORE releasing so fd 0/1 are not left
	// non-blocking for code that keeps running after runStdio returns (fd 0/1 may be a
	// terminal or a pipe shared with other processes -- leaking O_NONBLOCK there
	// breaks blocking readers/writers elsewhere).
	const inFlags = () @trusted { return fcntl(0, F_GETFL); }();
	const outFlags = () @trusted { return fcntl(1, F_GETFL); }();

	auto inFD = () @trusted { return eventDriver.pipes.adopt(in2); }();
	auto outFD = () @trusted { return eventDriver.pipes.adopt(out2); }();

	// Fail fast: if adopt rejected a dup (returned an invalid handle), close the
	// dups we still own and bail rather than silently operating on invalid handles.
	if (!()@trusted { return eventDriver.pipes.isValid(inFD); }() || !()@trusted {
			return eventDriver.pipes.isValid(outFD);
		}())
	{
		() @trusted {
			if (eventDriver.pipes.isValid(inFD))
				eventDriver.pipes.releaseRef(inFD);
			else
				close(in2);
			if (eventDriver.pipes.isValid(outFD))
				eventDriver.pipes.releaseRef(outFD);
			else
				close(out2);
		}();
		throw new Exception("runStdio: failed to adopt stdin/stdout dups");
	}

	// On return restore the saved flags on fd 0/1 FIRST (clearing the O_NONBLOCK that
	// adopt set on the shared open file description), THEN release the adopted dups
	// (which close()s the dup'd fds, never the real fd 0/1). Order matters: restoring
	// before release operates on still-valid descriptors.
	scope (exit)
	{
		() @trusted {
			if (inFlags != -1)
				fcntl(0, F_SETFL, inFlags);
			if (outFlags != -1)
				fcntl(1, F_SETFL, outFlags);
			eventDriver.pipes.releaseRef(inFD);
			eventDriver.pipes.releaseRef(outFD);
		}();
	}

	// A small persistent buffer so stdin is read in 64 KiB chunks (IOMode.once)
	// rather than one syscall + fiber suspend/resume per byte: `readLine` scans the
	// filled region for '\n', returns the line up to it, and retains the bytes
	// after the newline for the next call.
	enum size_t chunk = 64 * 1024;
	ubyte[] buf; // bytes read but not yet consumed
	size_t bufPos; // index of the next unconsumed byte in `buf`

	// Async, cooperative line read over stdin: return the next line (without its
	// '\n', stripping a trailing '\r'); a 0-byte read (disconnected) is EOF -> the
	// partial accumulator if any, else null. An over-long line (> maxLineBytes) is
	// dropped and reading resumes after the next newline.
	string readLine() @safe
	{
		ubyte[] acc;
		bool dropping; // true once `acc` exceeded maxLineBytes: skip to next '\n'
		for (;;)
		{
			if (bufPos >= buf.length)
			{
				// Refill from the pipe.
				if (buf.length < chunk)
					buf.length = chunk;
				bufPos = 0;
				auto res = () @trusted {
					return asyncAwaitUninterruptible!(PipeIOCallback, (cb) {
						eventDriver.pipes.read(inFD, buf, IOMode.once, cb);
					});
				}();
				const status = res[1];
				const nbytes = res[2];
				if (nbytes == 0 || (status != IOStatus.ok && status != IOStatus.wouldBlock))
				{
					buf = null;
					bufPos = 0;
					if (dropping)
						return null; // EOF in the middle of an over-long, dropped line
					return acc.length ? () @trusted {
						return cast(string) acc.idup;
					}() : null;
				}
				buf = buf[0 .. nbytes];
			}

			// Scan the filled region for a newline.
			const rest = buf[bufPos .. $];
			size_t nl = size_t.max;
			foreach (i, b; rest)
				if (b == '\n')
				{
					nl = i;
					break;
				}

			if (nl == size_t.max)
			{
				// No newline yet: accumulate (unless dropping) and refill.
				if (!dropping)
				{
					acc ~= rest;
					if (acc.length > maxLineBytes)
					{
						acc = null;
						dropping = true;
					}
				}
				bufPos = buf.length;
				continue;
			}

			// Found a newline at rest[nl]; consume through it.
			if (!dropping)
				acc ~= rest[0 .. nl];
			bufPos += nl + 1;
			if (dropping)
			{
				// Drop this over-long line and start a fresh one.
				dropping = false;
				acc = null;
				continue;
			}
			if (acc.length && acc[$ - 1] == '\r')
				acc = acc[0 .. $ - 1];
			return () @trusted { return cast(string) acc.idup; }();
		}
	}

	void writeLine(string s) @safe
	{
		auto bytes = cast(const(ubyte)[])(s ~ "\n");
		// Write the whole frame (IOMode.all loops internally until done).
		() @trusted {
			asyncAwaitUninterruptible!(PipeIOCallback, (cb) {
				eventDriver.pipes.write(outFD, bytes, IOMode.all, cb);
			});
		}();
	}

	() @trusted {
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				serveStdio(server, &readLine, &writeLine);
			catch (Exception)
			{
			}
		});
		runEventLoop();
	}();
}

unittest  // runStdio's adopt/releaseRef cycle leaves the original fd open with its O_NONBLOCK bit unchanged
{
	// Mirrors runStdio's fd lifecycle: save the original flags, dup the fd,
	// adopt the dup, then on teardown restore the saved flags BEFORE releaseRef.
	// Because the dup -- not the original -- is what releaseRef close()s, the
	// original fd must remain OPEN; and because a dup shares its open file
	// description (and O_NONBLOCK bit) with the original, the restore-before-release
	// must leave the original fd's O_NONBLOCK bit equal to its pre-adopt value.
	import eventcore.core : eventDriver;
	import core.sys.posix.unistd : dup, close, pipe;
	import core.sys.posix.fcntl : fcntl, F_GETFL, F_SETFL, O_NONBLOCK;

	int[2] fds;
	assert(() @trusted { return pipe(fds); }() == 0, "pipe() failed");
	const readEnd = fds[0];
	const writeEnd = fds[1];
	scope (exit)
		() @trusted { close(readEnd); close(writeEnd); }();

	const preFlags = () @trusted { return fcntl(readEnd, F_GETFL); }();
	assert(preFlags != -1, "pre-adopt fcntl(F_GETFL) failed");
	const preNonBlock = (preFlags & O_NONBLOCK) != 0;

	// dup-then-adopt, exactly as runStdio does for fd 0/1.
	const dupFd = () @trusted { return dup(readEnd); }();
	assert(dupFd != -1, "dup() failed");
	auto handle = () @trusted { return eventDriver.pipes.adopt(dupFd); }();
	assert(() @trusted { return eventDriver.pipes.isValid(handle); }(),
			"adopt() of the dup should yield a valid handle");
	// Restore the saved flags on the original fd FIRST (clearing the O_NONBLOCK that
	// adopt set on the shared open file description), THEN release the adopted dup.
	() @trusted {
		if (preFlags != -1)
			fcntl(readEnd, F_SETFL, preFlags);
		eventDriver.pipes.releaseRef(handle);
	}();

	// The original fd is still open (releaseRef closed only the dup).
	const postFlags = () @trusted { return fcntl(readEnd, F_GETFL); }();
	assert(postFlags != -1, "original fd was closed by the adopt/releaseRef cycle");
	// And its O_NONBLOCK bit equals the pre-adopt value (restore cleared the leak).
	const postNonBlock = (postFlags & O_NONBLOCK) != 0;
	assert(postNonBlock == preNonBlock,
			"original fd's O_NONBLOCK bit changed across the adopt/releaseRef cycle");
}

unittest  // runStdio enforces its "at most once per process" invariant via the module guard
{
	// The guard is independent of eventcore fd/refcount state: once _ranStdio is set,
	// any further call throws synchronously before touching fd 0/1 (so a sequential
	// second call cannot silently re-adopt fresh dups). Simulate a prior call by
	// setting the guard, then assert the next runStdio throws immediately.
	const saved = () @trusted { return _ranStdio; }();
	scope (exit)
		() @trusted { _ranStdio = saved; }();
	() @trusted { _ranStdio = true; }();

	auto s = new McpServer("guard-srv", "1.0");
	bool threw;
	try
		runStdio(s);
	catch (Exception e)
		threw = true;
	assert(threw, "a second runStdio call must throw the at-most-once guard");
}

version (unittest)
{
	import std.typecons : nullable;
	import vibe.data.json : parseJsonString;
	import mcp.protocol.types : Tool, CallToolResult, Content;
	import mcp.server.context : RequestContext;
	import mcp.client.client : McpClient;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, yield;
	import vibe.core.sync : LocalManualEvent, createManualEvent;
}

// A back-to-back line link feeding `serveStdio` its inbound lines and capturing
// its outbound lines, so a unittest can drive the server under the event loop.
version (unittest) private final class ServerLink
{
	string[] inbound; // lines fed to the server (its readLine source)
	size_t inPos;
	string[] outbound; // lines the server wrote
	LocalManualEvent inEvt;
	bool inClosed;

	this() @safe
	{
		inEvt = createManualEvent();
	}

	void feed(string s) @safe
	{
		inbound ~= s;
		inEvt.emit();
	}

	void closeInput() @safe
	{
		inClosed = true;
		inEvt.emit();
	}

	string readLine() @safe
	{
		while (inPos >= inbound.length && !inClosed)
		{
			auto ec = inEvt.emitCount;
			() @trusted { inEvt.wait(ec); }();
		}
		if (inPos >= inbound.length)
			return null; // EOF
		return inbound[inPos++];
	}

	void writeLine(string s) @safe
	{
		outbound ~= s;
	}
}

// Run a server over a ServerLink inside one event loop; `drive` feeds inputs and
// asserts. `serveStdio` runs as its own task; `drive` as another; the loop exits
// when `drive` returns and the server task is told to stop (closeInput).
version (unittest) private void withServer(McpServer server,
		scope void delegate(ServerLink) @safe drive) @trusted
{
	auto link = new ServerLink;
	runTask(() nothrow{
		try
			serveStdio(server, &link.readLine, &link.writeLine);
		catch (Exception)
		{
		}
	});
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			drive(link);
			link.closeInput();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
		link.feed(``); // blank line ignored
		link.feed(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); // no reply
		link.feed(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`);
		foreach (_; 0 .. 16)
			yield();
		outputs = link.outbound.dup;
	});

	// ping (id 1) and tools/list (id 2) produce responses; the notification does not.
	assert(outputs.length == 2);
	bool sawId1, sawId2;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if ("id" in j && j["id"].get!int == 1)
			sawId1 = true;
		if ("id" in j && j["id"].get!int == 2)
		{
			sawId2 = true;
			assert(j["result"]["tools"][0]["name"].get!string == "echo");
		}
	}
	assert(sawId1 && sawId2);
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}},"clientInfo":{"name":"t","version":"1"}}}`);
		link.feed(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
		link.feed(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask"}}`);
		// Let the handler run until it emits the elicitation/create request.
		foreach (_; 0 .. 12)
			yield();
		// Find the server->client elicitation request id and answer it.
		long elicitId = -1;
		foreach (o; link.outbound)
		{
			auto j = parseJsonString(o);
			if ("method" in j && j["method"].get!string == "elicitation/create" && "id" in j)
				elicitId = j["id"].get!long;
		}
		assert(elicitId >= 0, "server never emitted a server->client elicitation/create request");
		import vibe.data.json : Json;

		Json reply = Json.emptyObject;
		reply["jsonrpc"] = "2.0";
		reply["id"] = elicitId;
		Json content = Json.emptyObject;
		content["name"] = "Ada";
		reply["result"] = Json(["action": Json("accept"), "content": content]);
		link.feed(reply.toString());
		foreach (_; 0 .. 12)
			yield();
		outputs = link.outbound.dup;
	});

	bool sawResult;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if ("id" in j && j["id"].get!int == 2 && "result" in j)
		{
			assert(j["result"]["content"][0]["text"].get!string == "hi:Ada");
			sawResult = true;
		}
	}
	assert(sawResult, "tools/call reply with the elicited value was never produced");
}

unittest  // stdio: notifications/cancelled mid-handler is observed via the in-flight token
{
	auto s = new McpServer("stdio-cancel", "1.0");
	auto entered = createManualEvent();
	bool observedCancel;
	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		// Signal that the handler is running, then poll ctx.isCancelled while
		// yielding so the read loop can dispatch the inbound notifications/cancelled.
		entered.emit();
		foreach (i; 0 .. 1000)
		{
			if (ctx.isCancelled)
			{
				observedCancel = true;
				break;
			}
			yield();
		}
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow"}}`);
		// Wait until the handler is actually running, then cancel it.
		auto ec = entered.emitCount;
		() @trusted { entered.wait(ec); }();
		link.feed(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`);
		foreach (_; 0 .. 16)
			yield();
		outputs = link.outbound.dup;
	});

	assert(observedCancel,
			"handler should observe ctx.isCancelled after a mid-flight notifications/cancelled");
	// Spec: "Not send a response for the cancelled request."
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if ("id" in j && j["id"].get!int == 2)
			assert("result" !in j, "no response should be sent for the cancelled request");
	}
}

unittest  // serveStdio stops at end-of-input (null line) after servicing pending requests
{
	auto s = new McpServer("t", "1");
	size_t outCount = size_t.max;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
		foreach (_; 0 .. 8)
			yield();
		// closeInput (after drive returns) makes readLine return null -> loop ends.
		outCount = link.outbound.length;
	});
	// The read loop serviced the ping and then exited cleanly on EOF (the event
	// loop returning is what lets us reach here).
	assert(outCount == 1);
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"logit"}}`);
		foreach (_; 0 .. 12)
			yield();
		outputs = link.outbound.dup;
	});

	// The log notification is written out-of-band BEFORE the request's response.
	assert(outputs.length == 2);
	auto note = parseJsonString(outputs[0]);
	assert(note["method"].get!string == "notifications/message");
	assert(note["params"]["level"].get!string == "error");
	assert(note["params"]["logger"].get!string == "mylogger");
	assert(note["params"]["data"].get!string == "boom");
	assert("id" !in note);
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(
			`{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"error"}}`);
		foreach (_; 0 .. 8)
			yield();
		link.feed(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"logit"}}`);
		foreach (_; 0 .. 12)
			yield();
		outputs = link.outbound.dup;
	});

	// Two responses (setLevel + tools/call); the sub-minimum log is filtered out.
	assert(outputs.length == 2);
	foreach (o; outputs)
		assert(parseJsonString(o)["method"].type == Json.Type.undefined);
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"work","_meta":{"progressToken":"p1"}}}`);
		foreach (_; 0 .. 12)
			yield();
		outputs = link.outbound.dup;
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"work"}}`);
		foreach (_; 0 .. 12)
			yield();
		outputs = link.outbound.dup;
	});

	assert(outputs.length == 1);
	auto resp = parseJsonString(outputs[0]);
	assert(resp["id"].get!int == 1);
}

unittest  // background push: notify* with no request in flight reaches a stdio listen stream
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(draftListenLine(5, () @safe {
				Json f = Json.emptyObject;
				f["toolsListChanged"] = true;
				return f;
			}()));
		foreach (_; 0 .. 8)
			yield();
		// No request is in flight now; a background change still pushes.
		const delivered = s.notifyToolsListChanged();
		assert(delivered == 1);
		foreach (_; 0 .. 8)
			yield();
		outputs = link.outbound.dup;
	});

	// outputs[0] = ack, outputs[1] = the change notification.
	assert(outputs.length == 2);
	auto note = parseJsonString(outputs[1]);
	assert(note["method"].get!string == "notifications/tools/list_changed");
	assert("id" !in note);
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(draftListenLine(7, filter));
		foreach (_; 0 .. 8)
			yield();
		outputs = link.outbound.dup;
	});

	assert(outputs.length == 1);
	auto ack = parseJsonString(outputs[0]);
	assert(ack["method"].get!string == "notifications/subscriptions/acknowledged");
	assert("id" !in ack);
	assert("result" !in ack);
	assert(ack["params"]["notifications"].type == Json.Type.object);
	assert("acknowledged" !in ack["params"]);
	assert(ack["params"]["notifications"]["toolsListChanged"].get!bool);
}

unittest  // the stdio acknowledged notification is stamped with the listen id as the subscriptionId
{
	auto s = new McpServer("listen-srv", "1.0");
	s.enableToolsListChanged();

	Json filter = Json.emptyObject;
	filter["toolsListChanged"] = true;

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(draftListenLine(42, filter));
		foreach (_; 0 .. 8)
			yield();
		outputs = link.outbound.dup;
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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(draftListenLine(5, filter));
		foreach (_; 0 .. 8)
			yield();
		const delivered = s.notifyToolsListChanged();
		assert(delivered == 1);
		foreach (_; 0 .. 8)
			yield();
		outputs = link.outbound.dup;
	});

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

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`);
		foreach (_; 0 .. 8)
			yield();
		outputs = link.outbound.dup;
	});

	assert(outputs.length == 1);
	auto resp = parseJsonString(outputs[0]);
	assert(resp["id"].get!int == 1);
	assert(resp["result"]["acknowledged"].get!bool);
}

unittest  // two tool handlers overlap concurrently over the duplex (barrier proves they are not serialized)
{
	auto s = new McpServer("concurrent-srv", "1.0");
	auto barrier = createManualEvent();
	shared int entered = 0;
	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		// Each handler increments the entered count, signals, then waits until
		// BOTH have entered. If handlers were serialized the second would never
		// enter and this would hang (the test's event loop would time out).
		() @trusted { import core.atomic : atomicOp;

		atomicOp!"+="(entered, 1); }();
		barrier.emit();
		while (()@trusted {
				import core.atomic : atomicLoad;

				return atomicLoad(entered);
			}() < 2)
		{
			auto ec = barrier.emitCount;
			() @trusted { barrier.wait(ec); }();
		}
		CallToolResult r;
		r.content = [Content.makeText("done")];
		return r;
	});

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`);
		link.feed(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow"}}`);
		foreach (_; 0 .. 40)
			yield();
		outputs = link.outbound.dup;
	});

	// Both completed -> handlers overlapped (a serialized server would deadlock).
	assert(outputs.length == 2);
	bool sawId1, sawId2;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if ("id" in j && j["id"].get!int == 1)
			sawId1 = true;
		if ("id" in j && j["id"].get!int == 2)
			sawId2 = true;
	}
	assert(sawId1 && sawId2, "both concurrent tools/call must complete");
}

// A pair of unidirectional line queues wiring a real McpClient to a real
// McpServer (over serveStdio) back to back, all inside one event loop. Used by
// the end-to-end concurrency / sampling round-trip acceptance tests.
version (unittest) private final class DuplexLink
{
	string[] queue;
	size_t pos;
	LocalManualEvent evt;
	bool closed;

	this() @safe
	{
		evt = createManualEvent();
	}

	void put(string s) @safe
	{
		queue ~= s;
		evt.emit();
	}

	void closeEnd() @safe
	{
		closed = true;
		evt.emit();
	}

	string take() @safe
	{
		while (pos >= queue.length && !closed)
		{
			auto ec = evt.emitCount;
			() @trusted { evt.wait(ec); }();
		}
		if (pos >= queue.length)
			return null;
		return queue[pos++];
	}
}

unittest  // END-TO-END: McpClient over stdio drives an McpServer; two concurrent callTool get distinct results
{
	auto s = new McpServer("e2e-srv", "1.0");
	Tool echo = {name: "echo"};
	s.registerDynamicTool(echo, (Json args) @safe {
		CallToolResult r;
		const which = ("which" in args) ? args["which"].get!string : "?";
		r.content = [Content.makeText("echo:" ~ which)];
		return r;
	});

	auto c2s = new DuplexLink; // client -> server
	auto s2c = new DuplexLink; // server -> client

	string got1, got2;
	() @trusted {
		// Server task.
		runTask(() nothrow{
			try
				serveStdio(s, () @safe { return c2s.take(); }, (string line) @safe {
					s2c.put(line);
				});
			catch (Exception)
			{
			}
		});
		// Client task.
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
			{
				auto client = McpClient.stdio(() @safe { return s2c.take(); }, (string line) @safe {
					c2s.put(line);
				});
				client.initialize();

				// Fire two concurrent callTool in their own tasks.
				auto done = createManualEvent();
				int remaining = 2;
				runTask(() nothrow{
					try
					{
						auto r = client.callTool("echo", Json([
							"which": Json("one")
						]));
						got1 = r.content[0].text;
					}
					catch (Exception)
					{
					}
					if (--remaining == 0)
						done.emit();
				});
				runTask(() nothrow{
					try
					{
						auto r = client.callTool("echo", Json([
							"which": Json("two")
						]));
						got2 = r.content[0].text;
					}
					catch (Exception)
					{
					}
					if (--remaining == 0)
						done.emit();
				});
				auto ec = done.emitCount;
				if (remaining > 0)
					done.wait(ec);
				c2s.closeEnd();
			}
			catch (Exception)
			{
			}
		});
		runEventLoop();
	}();

	assert(got1 == "echo:one", "first concurrent callTool must get its own result");
	assert(got2 == "echo:two", "second concurrent callTool must get its own result");
}

unittest  // END-TO-END: a server tool's ctx.sample round-trips to the client's onSampling over stdio
{
	import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
	import mcp.protocol.types : Content;

	auto s = new McpServer("e2e-sample", "1.0");
	Tool ask = {name: "ask"};
	s.registerDynamicTool(ask, (Json args, RequestContext ctx) @safe {
		Json p = Json.emptyObject;
		p["messages"] = Json.emptyArray;
		p["maxTokens"] = 16;
		auto reply = ctx.sample(p);
		CallToolResult r;
		r.content = [
			Content.makeText("got:" ~ reply["content"]["text"].get!string)
		];
		return r;
	});

	auto c2s = new DuplexLink;
	auto s2c = new DuplexLink;

	string toolText;
	() @trusted {
		runTask(() nothrow{
			try
				serveStdio(s, () @safe { return c2s.take(); }, (string line) @safe {
					s2c.put(line);
				});
			catch (Exception)
			{
			}
		});
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
			{
				auto client = McpClient.stdio(() @safe { return s2c.take(); }, (string line) @safe {
					c2s.put(line);
				});
				client.onSampling = (CreateMessageRequest request) @safe {
					CreateMessageResult res;
					res.role = "assistant";
					res.content = Content.makeText("sampled");
					res.model = "test";
					return res;
				};
				client.initialize();
				auto r = client.callTool("ask");
				toolText = r.content[0].text;
				c2s.closeEnd();
			}
			catch (Exception)
			{
			}
		});
		runEventLoop();
	}();

	assert(toolText == "got:sampled",
			"server ctx.sample must round-trip to the client's onSampling over stdio");
}
