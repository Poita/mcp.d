module mcp.client.stdio;

import std.typecons : Nullable;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.client.transport : BearerProvider, ClientTransport, ClientProtocol, InboundOrigin;
import mcp.client.subscription : SubscriptionStream, ListenGate;
import mcp.transport.duplex : ChannelWriteException, DuplexChannel, defaultMaxLineBytes;
import mcp.transport.lines : FrameHead, LineReader, frameHeadScanBytes, scanFrameHead;
import mcp.protocol.mrtr : MetaKey;

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
	version (Posix) import vibe.core.process : ProcessPipes;
	import core.time : Duration, seconds, msecs;

	private string delegate() @safe readLine;
	private void delegate(string) @safe writeLine;
	private void delegate(Message, InboundOrigin) @safe inbound;
	private DuplexChannel channel;
	private bool started;
	private bool closed_;
	// Listen streams awaiting their leading frame, keyed by the listen request id
	// (rendered as JSON): the action run when a notification stamped with that
	// subscriptionId arrives.
	private void delegate() @safe nothrow[string] pendingListens_;
	// How long `openListen` waits for a listen stream's leading frame.
	package Duration listenTimeout_ = 10.seconds;
	// Counts how many times the child-shutdown sequence ran; exists so the
	// idempotency of `close()` is directly observable. The sequence must run at
	// most once per transport.
	private int closeProcessRuns_;
	// When spawned via `McpClient.spawn`, the owned subprocess pipes so `close()`
	// can run the MCP stdio shutdown sequence (close stdin -> SIGTERM -> SIGKILL).
	// Windows has no eventcore pipe driver, so it owns a `WinChild` (std.process
	// pid + blocking reader and writer threads) and shuts down via close-stdin -> terminate.
	version (Posix) private ProcessPipes* pipes;
	version (Posix)
		private bool stdinClosed_;
	else version (Windows)
		private WinChild* winChild;
	// The owned child's exit status, once it is known to have exited on its own.
	private Nullable!int childExitStatus_;
	// How long end-of-input waits for the owned child to exit, so a request it
	// leaves unanswered can report the child's exit status.
	private enum Duration exitStatusGrace = 500.msecs;

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

	void setInboundHandler(void delegate(Message, InboundOrigin) @safe handler) @safe
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

	/// No-op: there is no OAuth bearer token over stdio.
	void setBearerProvider(BearerProvider provider) @safe
	{
	}

	/// No-op: the modern-protocol flag has no effect on stdio (no SSE GET streams).
	void setModernProtocol(bool modern) @safe
	{
	}

	/// No-op: `McpClient` enforces request deadlines, and stdio sends need none.
	void setRequestTimeout(Duration timeout) @safe
	{
	}

	/// stdio signals cancellation with `notifications/cancelled` (it has no
	/// per-request stream to close), so cancellation is never by stream close.
	bool cancelsByStreamClose() @safe
	{
		return false;
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
				noteListenFrame(m);
				if (inbound !is null)
					inbound(m, InboundOrigin.init);
			});
		if (!started)
		{
			channel.start();
			started = true;
		}
		return channel;
	}

	/// Open a modern `subscriptions/listen` stream over stdio. Unlike Streamable
	/// HTTP — where the listen stream is a separate long-lived SSE response — stdio
	/// shares one channel, so opening a subscription is just writing the
	/// `subscriptions/listen` request line; the server delivers the leading
	/// `notifications/subscriptions/acknowledged` and every subsequent change
	/// notification on the same stdout channel, each stamped with
	/// `io.modelcontextprotocol/subscriptionId` (the listen request id), and they
	/// reach the client's inbound dispatcher through the channel's read loop (modern
	/// basic/utilities/subscriptions: "On stdio ... clients MUST use this field to
	/// correlate notifications"). The returned handle's `cancel()`/`close()` ends
	/// the subscription by sending `notifications/cancelled` referencing the listen
	/// request id, per the modern stdio cancellation rule. The server answers the
	/// listen request only when the stream ends: an error reply before the leading
	/// frame is thrown from here, and a later reply ends the handle (`ended`,
	/// `error`). When no leading frame arrives within the listen timeout (ten
	/// seconds) the stream is cancelled and this throws `RequestTimeoutException`.
	SubscriptionStream openListen(Json message) @safe
	{
		import vibe.core.core : runTask;

		// The listen request id is the subscriptionId; cancel() references it.
		Json listenId = ("id" in message) ? message["id"] : Json(null);
		const key = listenId.toString();
		auto ch = chan();
		auto cancelled = new shared bool(false);
		void delegate() @safe nothrow onCancel = () @safe nothrow{
			try
			{
				Json params = Json.emptyObject;
				params["requestId"] = listenId;
				// Posted, not sent: cancelling (as `McpClient.close` does) must not
				// park behind a server that has stopped reading its stdin.
				ch.post(makeNotification("notifications/cancelled", params));
				// Release the task awaiting the listen reply; the server sends none
				// for a cancelled stream.
				if (listenId.type == Json.Type.int_)
					ch.abort(listenId.get!long, internalError("subscription cancelled"));
			}
			catch (Exception)
			{
			}
		};
		auto stream = new SubscriptionStream(cancelled, onCancel);

		// Await the listen request's reply on a background task: the server
		// answers it only when the stream ends, with an error when it refuses or
		// fails the stream. Return once the stream's leading frame (stamped with
		// the listen id) arrives, or it ends first — then throw its error. A server
		// that sends no leading frame within `listenTimeout_` has the stream
		// cancelled and the open fails with a timeout.
		auto gate = new ListenGate;
		pendingListens_[key] = () @safe nothrow{ gate.signal(true); };
		scope (exit)
			pendingListens_.remove(key);
		if (listenId.type == Json.Type.int_)
		{
			runTask(() nothrow{
				McpException failure;
				try
					ch.deliver(message, listenId.get!long, Duration.max);
				catch (McpException e)
					failure = closedOr(e);
				catch (Exception e)
					failure = internalError(e.msg);
				stream.finish(failure);
				gate.signal(false);
			});
		}
		else
			send(message);
		if (!gate.wait(listenTimeout_))
		{
			if (stream.error !is null)
				throw stream.error;
			if (!stream.ended)
			{
				import mcp.protocol.errors : RequestTimeoutException;

				stream.cancel();
				throw new RequestTimeoutException(
						"subscriptions/listen received no leading frame within "
						~ listenTimeout_.toString());
			}
		}
		return stream;
	}

	/// Mark the listen stream a notification belongs to (by its subscriptionId)
	/// as established, waking the `openListen` awaiting its leading frame.
	private void noteListenFrame(Message m) @safe
	{
		if (pendingListens_.length == 0 || m.kind != MessageKind.notification
				|| m.params.type != Json.Type.object || "_meta" !in m.params)
			return;
		auto meta = m.params["_meta"];
		if (meta.type != Json.Type.object || MetaKey.subscriptionId !in meta)
			return;
		const key = meta[MetaKey.subscriptionId].toString();
		if (auto action = key in pendingListens_)
		{
			auto run = *action;
			pendingListens_.remove(key);
			run();
		}
	}

	/// Send a request and return its result (or throw `McpException`). The channel
	/// correlates the reply by `expectId` while its read loop concurrently
	/// dispatches any interleaved notifications and server->client requests, so
	/// multiple `deliver` calls may be in flight at once.
	Json deliver(Json message, long expectId) @safe
	{
		import core.time : Duration;

		// `McpClient` owns the request deadline (and aborts through `abort`), so the
		// channel waits without a timeout of its own.
		auto ch = chan();
		try
			return ch.deliver(message, expectId, Duration.max);
		catch (McpException e)
			throw closedOr(e);
	}

	/// `e`, or a `TransportClosedException` carrying its message when the channel
	/// has closed or a write to the server failed, so the client can tell a dead
	/// server from a failed request.
	private McpException closedOr(McpException e) @safe nothrow
	{
		import mcp.client.client : TransportClosedException;

		const writeFailed = cast(ChannelWriteException) e !is null;
		bool closed = writeFailed;
		try
			closed = closed || (channel !is null && channel.closed);
		catch (Exception)
		{
		}
		if (!closed || cast(TransportClosedException) e || e.code != ErrorCode.internalError)
			return e;
		// A failed write can precede the read loop seeing end-of-input, so the
		// child's exit status is collected here too.
		if (writeFailed && childExitStatus_.isNull && !closed_)
			noteChildEndOfInput();
		if (!childExitStatus_.isNull)
			return new TransportClosedException(
					e.msg ~ " (the server process exited with status " ~ statusText(
					childExitStatus_.get) ~ ")");
		return new TransportClosedException(e.msg);
	}

	private static string statusText(int status) @safe nothrow
	{
		import std.conv : to;

		try
			return status.to!string;
		catch (Exception)
			return "?";
	}

	/// The owned child closed its stdout: wait briefly for it to exit and record
	/// its exit status, before the read loop fails the requests it left
	/// unanswered. A child still running after the grace is left to `close()`.
	private void noteChildEndOfInput() @safe nothrow
	{
		version (Posix)
		{
			if (pipes is null)
				return;
			try
				childExitStatus_ = pipes.process.wait(exitStatusGrace);
			catch (Exception)
			{
			}
		}
		else version (Windows)
		{
			import std.process : tryWait;
			import vibe.core.core : sleep;

			if (winChild is null)
				return;
			try
			{
				Duration waited;
				for (;;)
				{
					auto t = () @trusted { return tryWait(winChild.pid); }();
					if (t.terminated)
					{
						childExitStatus_ = t.status;
						return;
					}
					if (waited >= exitStatusGrace)
						return;
					sleep(10.msecs);
					waited += 10.msecs;
				}
			}
			catch (Exception)
			{
			}
		}
	}

	/// A line from the server longer than `maxLineBytes` was dropped, `head`
	/// being what its first bytes reveal. Report it, and fail the request it
	/// answers or refuse the request it carries when its id is among those bytes.
	private void noteOversized(FrameHead head, size_t maxLineBytes) @safe nothrow
	{
		import std.conv : to;

		if (channel is null)
			return;
		string msg = "the server's message exceeds the ";
		string id;
		try
		{
			msg ~= maxLineBytes.to!string ~ "-byte line limit";
			if (head.id.type != Json.Type.null_)
				id = head.id.toString();
		}
		catch (Exception)
		{
		}
		channel.reportError(msg ~ (id.length ? " (id " ~ id ~ ")" : "") ~ "; it was dropped");
		try
		{
			if (head.hasMethod && id.length)
				channel.post(makeErrorResponse(head.id, invalidRequest(msg)));
			else if (head.id.type == Json.Type.int_)
				channel.abort(head.id.get!long, internalError(msg));
		}
		catch (Exception)
		{
		}
	}

	void abort(long expectId, McpException reason) @safe
	{
		if (channel !is null)
			channel.abort(expectId, reason);
	}

	/// Send a message that expects no correlated reply (notification, or a
	/// response to a server->client request).
	void sendOneway(Json message) @safe
	{
		send(message);
	}

	/// Serialize a single message and write it as one newline-delimited line
	/// through the channel's serialized writer. `Json.toString` never emits a raw
	/// newline, so the line framing holds and only a valid MCP message is written
	/// to the server's stdin.
	private void send(Json message) @safe
	{
		try
			chan().send(message);
		catch (McpException e)
			throw closedOr(e);
	}

	/// Attach owned subprocess pipes so `close()` runs the stdio shutdown
	/// sequence. Set by `McpClient.spawn` (POSIX uses vibe's process pipes).
	version (Posix) package void attachProcess(ProcessPipes* pipes) @safe
	{
		this.pipes = pipes;
	}

	/// Attach the owned Windows child (std.process pid + pipe threads) so
	/// `close()` runs the close-stdin -> terminate shutdown. Set by the Windows
	/// `spawnStdioTransport`.
	version (Windows) package void attachWinChild(WinChild* c) @safe
	{
		this.winChild = c;
	}

	/// Release transport resources. When this transport owns a spawned subprocess
	/// (`McpClient.spawn`), run the MCP stdio Shutdown sequence (basic/lifecycle
	/// §Shutdown -> stdio): close the child's stdin, escalate to `SIGTERM`, then
	/// `SIGKILL` if it does not exit within the grace periods. A no-op when there is
	/// no owned subprocess (a custom `readLine`/`writeLine` channel).
	void close() @safe
	{
		if (closed_)
			return;
		closed_ = true;
		if (channel !is null)
			channel.close();
		version (Posix)
		{
			if (pipes !is null)
				closeProcess(5.seconds, 5.seconds);
		}
		else version (Windows)
		{
			if (winChild !is null)
				closeWinChild(5.seconds);
		}
	}

	/// How many times the child-shutdown sequence has run (for tests asserting
	/// `close()` idempotency).
	package int closeProcessRuns() @safe
	{
		return closeProcessRuns_;
	}

	/// Shut the owned child down per the MCP stdio Shutdown sequence and return its
	/// exit status (a process killed by signal reports a negative status:
	/// `-SIGTERM` / `-SIGKILL`). Call it at most once, since it releases the
	/// pipes; `close()` runs it only on the first close.
	version (Posix) package int closeProcess(Duration termGrace, Duration killGrace) @safe
	{
		++closeProcessRuns_;
		const status = stopProcess(termGrace, killGrace);
		releaseProcess();
		return status;
	}

	/// Release the reaped child's stdout pipe and process handle, so the event
	/// driver holds no handle for them at exit. The read loop reads that pipe, so
	/// it is stopped first; closing the pipe under a pending read is unsafe.
	version (Posix) private void releaseProcess() @safe
	{
		import vibe.core.core : sleep;

		// The child is gone, so a write it left undrained can never complete. Not
		// every event loop reports the dead reader (epoll does not), so the write
		// is interrupted; once it has failed, the child's stdin can be closed.
		if (!stdinClosed_)
		{
			if (channel !is null)
				channel.interruptWrite();
			foreach (_; 0 .. 100)
			{
				if (!writePending())
					break;
				sleep(10.msecs);
			}
			if (writePending())
				return;
			pipes.stdin.close();
			stdinClosed_ = true;
		}
		// Its stdout is at end-of-input too, so the loop exits promptly; the
		// grace only bounds a grandchild still holding the pipe.
		if (channel !is null && started && !channel.stopReadLoop(1.seconds))
			return;
		pipes.stdout.close();
		destroy(*pipes);
	}

	/// Whether a line is being written to the child's stdin right now.
	private bool writePending() const @safe nothrow
	{
		return channel !is null && channel.writing;
	}

	/// Run the stdio shutdown sequence on the owned child and return its exit
	/// status.
	version (Posix) private int stopProcess(Duration termGrace, Duration killGrace) @safe
	{
		import core.sys.posix.signal : SIGTERM, SIGKILL;

		auto p = pipes;
		// Step 0: close the child's stdin so a well-behaved server sees EOF and
		// exits. A write still parked on it means the child has stopped reading;
		// closing the pipe under that write would strand the writer, so stdin is
		// left open (and closed by `releaseProcess` once the child is gone).
		if (!writePending())
		{
			p.stdin.close();
			stdinClosed_ = true;
		}

		// Step 1: wait for a clean exit within the SIGTERM grace.
		auto status = p.process.wait(termGrace);
		if (!status.isNull)
			return status.get;

		// Step 2: escalate to SIGTERM and wait again.
		() { p.process.kill(SIGTERM); }();
		status = p.process.wait(killGrace);
		if (!status.isNull)
			return status.get;

		// Step 3: still alive -> force kill (SIGKILL) and reap.
		() { p.process.kill(SIGKILL); }();
		p.process.wait();
		return -SIGKILL;
	}

	/// Windows child shutdown. Windows has no SIGTERM/SIGKILL distinction, so the
	/// sequence is: close the child's stdin (a well-behaved server sees EOF and
	/// exits), poll for a clean exit within `grace` (yielding the fiber between
	/// polls so the loop keeps running), then forcibly terminate and reap.
	version (Windows) package int closeWinChild(Duration grace) @safe
	{
		import std.process : wait, tryWait, kill;
		import core.time : msecs;
		import vibe.core.core : sleep;

		++closeProcessRuns_;
		auto c = winChild;
		c.writer.close();

		int status;
		bool reaped;
		Duration waited;
		while (waited < grace)
		{
			auto t = () @trusted { return tryWait(c.pid); }();
			if (t.terminated)
			{
				status = t.status;
				reaped = true;
				break;
			}
			() @trusted { sleep(50.msecs); }();
			waited += 50.msecs;
		}
		if (!reaped)
			status = () @trusted { kill(c.pid); return wait(c.pid); }();

		// The child is gone, so its stdout write end is closed and the daemon reader
		// thread runs to EOF. Wait for it to exit before returning: a GC-touching
		// daemon thread left alive into druntime shutdown faults (0xC0000005) on
		// Windows and discards buffered stdout, e.g. an example's final "OK:" line.
		// The wait is cooperative -- a non-blocking channel drain each pass (so the
		// reader never parks on a full buffer) plus a vibe `sleep` yield -- because
		// the channel's wakeups are fiber-based: a blocking OS-level `join` here
		// would stall the event loop the reader's channel-close notification needs.
		// The trailing `join` runs only once the thread has already exited, so it
		// returns immediately and just reclaims the thread.
		() @trusted {
			if (c.reader !is null)
			{
				PumpedLine discard;
				while (c.reader.isRunning)
				{
					while (c.lines.tryConsumeOne(discard, Duration.zero))
					{
					}
					sleep(5.msecs);
				}
				c.reader.join(false);
			}
			// The writer thread ends once its queue is written or, for a child
			// that stopped reading, once the child's exit fails its write.
			while (c.writer.thread.isRunning)
			{
				c.writer.drain();
				sleep(5.msecs);
			}
			c.writer.thread.join(false);
		}();
		return status;
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
version (Posix) StdioClientTransport spawnStdioTransport(string[] args,
		size_t maxLineBytes = defaultMaxLineBytes) @safe
{
	import vibe.core.process : pipeProcess, ProcessPipes, Redirect;
	import eventcore.driver : IOMode;

	// Heap-box the pipes so the read/write closures capture a stable, long-lived
	// handle past this function's return (`attachProcess` keeps the same pointer
	// for the shutdown sequence).
	auto pipes = new ProcessPipes;
	*pipes = pipeProcess(args, Redirect.stdin | Redirect.stdout);
	StdioClientTransport transport;

	// Async, cooperative line read over the child's stdout, in chunks through a
	// `LineReader`. End-of-input returns null (ending the duplex read loop) once
	// `empty` reports the child closed its stdout, after a final unterminated
	// line, which is still a complete message, so only a genuine read failure
	// surfaces as an exception. A line longer than `maxLineBytes` is reported
	// (`noteOversized`) as soon as it passes the bound, and its remaining bytes
	// are skipped up to the next newline rather than accumulated without limit.
	auto reader = LineReader(maxLineBytes);
	reader.onOversized = (FrameHead head) @safe {
		transport.noteOversized(head, maxLineBytes);
	};
	bool stopping() @safe
	{
		return transport.channel !is null && transport.channel.stopping;
	}

	size_t readStdout(ubyte[] dst) @safe
	{
		// Checked before each read so `stopReadLoop` also ends a loop skipping a
		// flood the pipe never runs dry of.
		import vibe.core.core : yield;

		if (stopping() || pipes.stdout.empty)
			return 0;
		const n = pipes.stdout.read(dst, IOMode.once);
		// A read of buffered data completes without suspending, so a child that
		// keeps the pipe full would otherwise hold the event loop; yielding lets
		// other tasks (including the shutdown sequence) run between chunks.
		yield();
		return n;
	}

	string readLine() @safe
	{
		auto line = reader.next(&readStdout);
		FrameHead ignored;
		reader.takeOversized(ignored);
		if (line is null && !stopping())
			transport.noteChildEndOfInput();
		return line;
	}

	void writeLine(string s) @safe
	{
		auto bytes = cast(const(ubyte)[])(s ~ "\n");
		pipes.stdin.write(bytes);
		pipes.stdin.flush();
	}

	transport = new StdioClientTransport(&readLine, &writeLine);
	transport.attachProcess(pipes);
	return transport;
}

version (Windows)
{
	import core.sys.windows.windef : HANDLE;
	import vibe.core.channel : Channel, createChannel;
}

/// Owned Windows child: the std.process pid, the thread writing its stdin, and
/// the thread reading its stdout. `close()` routes through
/// `StdioClientTransport.closeWinChild`, which closes stdin (EOF), terminates the
/// process, then drains both threads' channels and joins them (see
/// `pumpChildStdout`, `ChildStdinWriter`) so neither can touch the GC during
/// druntime shutdown.
version (Windows) private struct WinChild
{
	import std.process : Pid;
	import core.thread : Thread;

	Pid pid;
	ChildStdinWriter writer;
	// The daemon thread pumping the child's stdout, and the channel it feeds.
	// closeWinChild drains the channel and joins the thread so no GC-touching
	// daemon thread survives into druntime shutdown, which faults on Windows.
	Thread reader;
	Channel!PumpedLine lines;
}

/// What the Windows stdout reader thread hands the read loop: a complete line,
/// or the first bytes of an over-long one it dropped.
version (Windows) private struct PumpedLine
{
	string text;
	bool oversized;
}

/// The thread writing the Windows child's stdin. Each line is handed to it
/// through `jobs` and written with a blocking `WriteFile` on a handle the thread
/// owns, so a child that stops reading parks only the writing fiber, never the
/// event loop (whose read loop must keep draining the child's stdout for the
/// child to make progress). Outcomes come back through `results` tagged with
/// their line's sequence number, so a caller interrupted while waiting never
/// leaves its outcome for the next caller.
version (Windows) private final class ChildStdinWriter
{
	import core.thread : Thread;
	import core.time : Duration;
	import vibe.core.sync : TaskMutex;

	private static struct Job
	{
		ulong seq;
		immutable(ubyte)[] bytes;
	}

	private static struct Outcome
	{
		ulong seq;
		bool ok;
	}

	private HANDLE handle;
	private Channel!Job jobs;
	private Channel!Outcome results;
	private TaskMutex mtx;
	private ulong nextSeq;
	Thread thread;

	this(HANDLE h) @trusted
	{
		handle = h;
		jobs = createChannel!Job();
		results = createChannel!Outcome();
		mtx = new TaskMutex;
		thread = new Thread(&pump);
		thread.isDaemon = true;
		thread.start();
	}

	/// Write `bytes` on the writer thread, parking the calling fiber (not the
	/// event-loop thread) until they are written. Throws when the write fails
	/// or the writer has stopped.
	void write(const(ubyte)[] bytes) @trusted
	{
		synchronized (mtx)
		{
			const seq = ++nextSeq;
			jobs.put(Job(seq, bytes.idup));
			Outcome r;
			do
			{
				if (!results.tryConsumeOne(r))
					throw new Exception("the child's stdin is closed");
			}
			while (r.seq < seq);
			if (!r.ok)
				throw new Exception("writing to the child's stdin failed");
		}
	}

	/// Stop accepting lines; the thread closes the handle (EOF for the child)
	/// once the queued ones are written.
	void close() @trusted nothrow
	{
		try
			jobs.close();
		catch (Exception)
		{
		}
	}

	/// Discard outcomes nobody awaits, so the thread never parks handing one
	/// back while it is being joined.
	void drain() @trusted
	{
		Outcome r;
		while (results.tryConsumeOne(r, Duration.zero))
		{
		}
	}

	private void pump() @system
	{
		import core.sys.windows.windef : DWORD;
		import core.sys.windows.winbase : WriteFile, CloseHandle;

		Job job;
		while (jobs.tryConsumeOne(job))
		{
			bool ok = true;
			size_t off;
			while (ok && off < job.bytes.length)
			{
				DWORD wrote;
				ok = WriteFile(handle, cast(const(void)*)(job.bytes.ptr + off),
						cast(DWORD)(job.bytes.length - off), &wrote, null) != 0 && wrote != 0;
				off += wrote;
			}
			results.put(Outcome(job.seq, ok));
			if (!ok)
				break;
		}
		CloseHandle(handle);
		results.close();
	}
}

/// Windows counterpart to the POSIX `spawnStdioTransport`. eventcore has no
/// working pipe driver, so the child is launched with std.process, its stdout is
/// read by a dedicated daemon thread that assembles newline-delimited lines and
/// hands them to the cooperative read loop through a thread-safe vibe `Channel`
/// (`readLine` drains it, yielding the fiber), and its stdin is written by a
/// dedicated thread (`ChildStdinWriter`) that `writeLine` hands each line to.
version (Windows) StdioClientTransport spawnStdioTransport(string[] args,
		size_t maxLineBytes = defaultMaxLineBytes) @safe
{
	import std.process : pipeProcess, Redirect;
	import core.thread : Thread;

	import core.sys.windows.windef : HANDLE, FALSE;
	import core.sys.windows.winbase : DuplicateHandle, GetCurrentProcess;
	import core.sys.windows.winnt : DUPLICATE_SAME_ACCESS;

	auto child = () @trusted { return new WinChild; }();

	// std.stdio.File is not safe to share across threads: its reference count is
	// non-atomic, so handing a child-pipe File to a worker thread races the
	// refcount and can close the handle under it. Instead, duplicate each pipe
	// handle into one its thread owns outright (and closes when done), and let
	// the original Files close here. The duplicates keep the pipe ends open,
	// mirroring the server's raw-HANDLE pumps.
	HANDLE readHandle, writeHandle;
	() @trusted {
		auto pp = pipeProcess(args, Redirect.stdin | Redirect.stdout);
		child.pid = pp.pid;
		auto proc = GetCurrentProcess();
		DuplicateHandle(proc, pp.stdout.windowsHandle, proc, &readHandle, 0,
				FALSE, DUPLICATE_SAME_ACCESS);
		DuplicateHandle(proc, pp.stdin.windowsHandle, proc, &writeHandle, 0,
				FALSE, DUPLICATE_SAME_ACCESS);
		pp.stdin.close();
	}();

	child.writer = new ChildStdinWriter(writeHandle);
	StdioClientTransport transport;

	// Daemon reader: blocking ReadFile on the duplicated stdout handle, lines pushed
	// to `lines`.
	auto lines = createChannel!PumpedLine();
	auto chan = lines;
	child.lines = lines;
	() @trusted {
		auto t = new Thread({ pumpChildStdout(readHandle, chan, maxLineBytes); });
		t.isDaemon = true;
		t.start();
		child.reader = t;
	}();

	string readLine() @safe
	{
		for (;;)
		{
			PumpedLine got;
			if (!()@trusted { return lines.tryConsumeOne(got); }())
			{
				// The channel closed: the child's stdout reached end-of-input.
				transport.noteChildEndOfInput();
				return null;
			}
			if (!got.oversized)
				return got.text;
			transport.noteOversized(scanFrameHead(cast(const(ubyte)[]) got.text), maxLineBytes);
		}
	}

	void writeLine(string s) @safe
	{
		child.writer.write(cast(const(ubyte)[])(s ~ "\n"));
	}

	transport = new StdioClientTransport(&readLine, &writeLine);
	transport.attachWinChild(child);
	return transport;
}

/// Reader-thread body (Windows client): blocking reads on the child's stdout,
/// assembling newline-delimited lines with a trailing '\r' stripped. Each complete
/// line is pushed to `chan`. A line longer than `maxLineBytes` is dropped: its
/// first bytes are pushed marked `oversized` as soon as it passes the bound, and
/// the rest is skipped up to the next newline. EOF closes the channel, which
/// surfaces to the duplex read loop as end-of-input; a final unterminated line is
/// still a complete message and is pushed first.
version (Windows) private void pumpChildStdout(HANDLE h,
		Channel!PumpedLine chan, size_t maxLineBytes) @system
{
	import core.sys.windows.windef : DWORD;
	import core.sys.windows.winbase : ReadFile, CloseHandle;

	scope (exit)
		CloseHandle(h);
	ubyte[32 * 1024] buf;
	ubyte[] acc;
	bool dropping;
	for (;;)
	{
		DWORD n;
		const ok = ReadFile(h, cast(void*) buf.ptr, cast(DWORD) buf.length, &n, null) != 0;
		if (!ok || n == 0)
		{
			if (acc.length && acc[$ - 1] == '\r')
				acc = acc[0 .. $ - 1];
			if (acc.length && !dropping)
				chan.put(PumpedLine(cast(string) acc.idup));
			break;
		}
		auto got = buf[0 .. n];
		size_t i;
		while (i < got.length)
		{
			size_t nl = size_t.max;
			foreach (j; i .. got.length)
				if (got[j] == '\n')
				{
					nl = j;
					break;
				}
			const end = nl == size_t.max ? got.length : nl;
			if (!dropping)
			{
				acc ~= got[i .. end];
				if (acc.length > maxLineBytes)
				{
					const head = acc.length < frameHeadScanBytes ? acc.length : frameHeadScanBytes;
					chan.put(PumpedLine(cast(string) acc[0 .. head].idup, true));
					acc = null;
					dropping = true;
				}
			}
			if (nl == size_t.max)
				break; // need more data
			i = nl + 1;
			if (dropping)
			{
				dropping = false;
				continue;
			}
			if (acc.length && acc[$ - 1] == '\r')
				acc = acc[0 .. $ - 1];
			// A blank line is "" rather than null, which the read loop takes as EOF.
			chan.put(PumpedLine(acc.length ? cast(string) acc.idup : ""));
			acc = null;
		}
	}
	chan.close();
}

version (unittest)
{
	import mcp.server.server : McpServer;
	import mcp.client.client : McpClient;
	import mcp.protocol.types : Tool, Content, CallToolResult;
	import mcp.client.subscription : SubscriptionFilter;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, yield;
}

// Run `body` inside a vibe task + event loop, exiting the loop when it returns,
// and rethrow anything it threw so the calling test fails.
version (unittest) private void inLoop(scope void delegate() @safe body) @trusted
{
	Exception failure;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			body();
		catch (Exception e)
			failure = e;
	});
	runEventLoop();
	if (failure !is null)
		throw failure;
}

unittest  // inLoop propagates an exception thrown by its body
{
	import std.exception : assertThrown;

	assertThrown!Exception(inLoop(() @safe { throw new Exception("boom"); }));
}

unittest  // stdio openListen writes the subscriptions/listen request to the server (2026-07-28)
{
	// Per 2026-07-28 basic/utilities/subscriptions, a stdio client opens a subscription
	// by sending a real `subscriptions/listen` request on the single stdin channel.
	string[] toServer;
	auto toClient = new TestLines;

	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string s) @safe {
			toServer ~= s;
			acknowledgeListen(toClient, s);
		});
		client.enableModern();

		SubscriptionFilter filter = {toolsListChanged: true};
		client.subscriptionsListen(filter);
		toClient.closeEnd();
	});

	assert(failure.length == 0, failure);

	assert(toServer.length == 1, "listen request must be written to the server");
	auto m = parseJsonString(toServer[0]);
	assert(m["method"].get!string == "subscriptions/listen");
	assert("id" in m, "listen is a request and MUST carry an id");
	assert(m["params"]["notifications"]["toolsListChanged"].get!bool == true);
}

unittest  // stdio listen cancel() emits notifications/cancelled referencing the listen request id
{
	string[] toServer;
	auto toClient = new TestLines;

	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string s) @safe {
			toServer ~= s;
			acknowledgeListen(toClient, s);
		});
		client.enableModern();

		SubscriptionFilter filter = {resourcesListChanged: true};
		auto stream = client.subscriptionsListen(filter);

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
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
}

version (unittest)
{
	/// Answer a `subscriptions/listen` request line with the leading
	/// `notifications/subscriptions/acknowledged` a server sends when it opens
	/// the stream, stamped with the listen id; other lines are ignored.
	private void acknowledgeListen(TestLines toClient, string line) @safe
	{
		auto m = parseJsonString(line);
		if ("method" !in m || m["method"].get!string != "subscriptions/listen")
			return;
		Json meta = Json.emptyObject;
		meta[MetaKey.subscriptionId] = m["id"];
		Json params = Json.emptyObject;
		params["notifications"] = Json.emptyObject;
		params["_meta"] = meta;
		toClient.put(makeNotification("notifications/subscriptions/acknowledged",
				params).toString());
	}
}

unittest  // a stdio subscriptions/listen answered with an error reply fails subscriptionsListen
{
	auto toClient = new TestLines;
	int code;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string s) @safe {
			auto m = parseJsonString(s);
			if ("id" in m)
				toClient.put(makeErrorResponse(m["id"],
				new McpException(-32601, "no listen")).toString());
		});
		client.enableModern();
		SubscriptionFilter filter = {toolsListChanged: true};
		try
			client.subscriptionsListen(filter);
		catch (McpException e)
			code = e.code;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(code == -32601, "an error reply to the listen request must fail subscriptionsListen");
}

unittest  // a stdio listen stream the server ends with an error records it on the handle
{
	auto toClient = new TestLines;
	McpException streamError;
	bool ended;
	const failure = inLoopCapturing(() @safe {
		long listenId;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string s) @safe {
			acknowledgeListen(toClient, s);
			auto m = parseJsonString(s);
			if ("id" in m)
				listenId = m["id"].get!long;
		});
		client.enableModern();
		SubscriptionFilter filter = {toolsListChanged: true};
		auto stream = client.subscriptionsListen(filter);
		toClient.put(makeErrorResponse(Json(listenId), new McpException(-32603,
			"gone")).toString());
		foreach (_; 0 .. 8)
			yield();
		ended = stream.ended;
		streamError = stream.error;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(ended, "the server's error reply must end the stream");
	assert(streamError !is null && streamError.code == -32603);
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

version (Posix) unittest  // close() returns real exit code (0) when child handles SIGTERM gracefully
{
	import core.time : seconds, msecs;

	inLoop(() @safe {
		// This child ignores stdin EOF but catches SIGTERM and exits 0, simulating
		// a graceful shutdown handler. The spin loop keeps the shell alive and in
		// signal-dispatch mode so the TERM trap fires reliably. closeProcess must
		// return 0 (the real exit code from the trap's exit(0)), not -SIGTERM,
		// because eventcore already encodes truly signal-killed processes as negative
		// codes; returning -SIGTERM here discards the actual clean exit status.
		auto transport = spawnStdioTransport([
			"sh", "-c", "trap 'exit 0' TERM; while :; do sleep 0.1; done"
		]);
		auto status = transport.closeProcess(200.msecs, 2.seconds);
		assert(status == 0,
			"graceful SIGTERM handler that calls exit(0) must report status 0, not -SIGTERM");
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

version (Posix) unittest  // a blank line from the server is skipped, not taken as end-of-input
{
	import core.time : seconds;

	bool ok;
	string err;
	inLoop(() @safe {
		// The child stays alive after replying so the reply is not racing its exit.
		auto transport = spawnStdioTransport([
			"sh", "-c",
			`read line; printf '\n\r\n{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'; cat >/dev/null`
		]);
		scope (exit)
			transport.closeProcess(5.seconds, 5.seconds);
		Json req = parseJsonString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
		try
			ok = transport.deliver(req, 1)["ok"].get!bool;
		catch (Exception e)
			err = e.msg;
	});
	assert(ok, "the reply after blank lines must arrive, got: " ~ err);
}

version (Posix) unittest  // an over-long newline-less stream is reported and skipped, not accumulated
{
	import core.time : seconds, msecs;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import std.algorithm.searching : canFind;
	import vibe.core.core : sleep;

	string[] reported;
	bool closedPromptly;
	inLoop(() @safe {
		// The child floods stdout with newline-less bytes. With a small
		// maxLineBytes the reader reports the line once it passes the bound and
		// then skips its bytes rather than accumulating them without limit.
		// One exec'd process, so terminating the child ends the flood; a shell
		// pipeline would leave its stages writing to the pipe.
		auto transport = spawnStdioTransport([
			"sh", "-c", "exec tr '\\000' A < /dev/zero"
		], 4096);
		transport.chan().onError = (string m) @safe nothrow{ reported ~= m; };
		auto sw = StopWatch(AutoStart.yes);
		while (reported.length == 0 && sw.peek < 30.seconds)
			sleep(10.msecs);
		sw.reset();
		transport.closeProcess(200.msecs, 200.msecs);
		closedPromptly = sw.peek < 10.seconds;
	});
	assert(reported.length == 1 && reported[0].canFind("4096-byte line limit"),
			"the over-long line must be reported once, naming the limit");
	assert(closedPromptly, "close() must stop a read loop skipping a flood");
}

version (Posix) unittest  // McpClient.spawn bounds the server's stdout lines by ClientSettings.maxMessageBytes
{
	import core.time : Duration;
	import std.algorithm.searching : canFind;
	import mcp.client.client : ClientSettings;

	string msg;
	inLoop(() @safe {
		// The child answers the request with a response line far longer than the
		// cap, then waits for stdin to close.
		ClientSettings settings;
		settings.maxMessageBytes = 4096;
		settings.requestTimeout = Duration.zero;
		auto client = McpClient.spawn([
			"sh", "-c",
			`read line; id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/'); ` ~ `printf '{"jsonrpc":"2.0","id":%s,"result":{"pad":"%08192d"}}\n' "$id" 0; cat >/dev/null`
		], settings);
		try
			client.ping();
		catch (McpException e)
			msg = e.msg;
		client.close();
	});
	assert(msg.canFind("4096-byte line limit"),
			"an over-long reply must fail its request naming the limit, got: " ~ msg);
}

version (Posix) unittest  // an over-long server line is skipped and the connection keeps working
{
	import core.time : msecs;
	import std.algorithm.searching : canFind;

	string firstMsg;
	string[] reported;
	Json second;
	inLoop(() @safe {
		auto transport = spawnStdioTransport([
			"sh", "-c",
			`read line; printf '{"jsonrpc":"2.0","id":1,"result":{"pad":"%0200d"}}\n' 0; ` ~ `read line; printf '{"jsonrpc":"2.0","id":2,"result":{"ok":true}}\n'; cat >/dev/null`
		], 64);
		transport.chan().onError = (string m) @safe nothrow{ reported ~= m; };
		try
			transport.deliver(parseJsonString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), 1);
		catch (McpException e)
			firstMsg = e.msg;
		second = transport.deliver(parseJsonString(`{"jsonrpc":"2.0","id":2,"method":"ping"}`), 2);
		transport.closeProcess(200.msecs, 200.msecs);
	});
	assert(firstMsg.canFind("64-byte line limit"), firstMsg);
	assert(second["ok"].get!bool, "the line after an over-long one must still be read");
	assert(reported.length == 1 && reported[0].canFind("64-byte line limit"),
			"the dropped line must be reported through onError");
}

version (Posix) unittest  // close() releases the child's stdout pipe and process handle after the read loop stops
{
	import eventcore.core : eventDriver;

	inLoop(() @safe {
		// `cat` echoes the notification, so the read loop is live (parked reading
		// stdout) when close() runs.
		auto transport = spawnStdioTransport(["cat"]);
		transport.sendOneway(parseJsonString(`{"jsonrpc":"2.0","method":"notifications/x"}`));
		auto stdoutFd = transport.pipes.stdout.tupleof[0];
		auto pid = transport.pipes.process.tupleof[0];
		assert(eventDriver.pipes.isValid(stdoutFd) && eventDriver.processes.isValid(pid));
		transport.close();
		assert(!transport.channel.readLoopRunning, "the read loop must have stopped");
		assert(!eventDriver.pipes.isValid(stdoutFd), "the stdout pipe must be released");
		assert(!eventDriver.processes.isValid(pid), "the process handle must be released");
	});
}

version (Posix) unittest  // close() stops a read loop parked on a stdout pipe a grandchild keeps open
{
	import core.time : seconds;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import eventcore.core : eventDriver;

	inLoop(() @safe {
		// The backgrounded `sleep` inherits stdout and outlives the child, so the
		// read loop never sees end-of-input and has to be interrupted.
		auto transport = spawnStdioTransport(["sh", "-c", "sleep 3 & cat"]);
		transport.sendOneway(parseJsonString(`{"jsonrpc":"2.0","method":"notifications/x"}`));
		auto stdoutFd = transport.pipes.stdout.tupleof[0];
		auto sw = StopWatch(AutoStart.yes);
		transport.close();
		assert(sw.peek < 3.seconds, "close() must not wait for the grandchild");
		assert(!transport.channel.readLoopRunning);
		assert(!eventDriver.pipes.isValid(stdoutFd));
	});
}

version (Posix) unittest  // close() is idempotent: a second call does not re-run the child shutdown
{
	inLoop(() @safe {
		// `cat` exits 0 on stdin EOF, so the first close() reaps it cleanly. A second
		// close() must short-circuit rather than re-close stdin and re-wait/re-signal
		// the already-reaped process.
		auto transport = spawnStdioTransport(["cat"]);
		transport.close();
		assert(transport.closeProcessRuns() == 1, "first close() runs the shutdown once");
		transport.close();
		assert(transport.closeProcessRuns() == 1, "second close() must be a no-op");
	});
}

version (Posix) unittest  // a request to a server that exits on its own fails with its exit status
{
	import core.time : Duration;
	import std.algorithm.searching : canFind;
	import mcp.client.client : ClientSettings, TransportClosedException;

	string msg;
	inLoop(() @safe {
		ClientSettings settings;
		settings.requestTimeout = Duration.zero;
		auto client = McpClient.spawn(["sh", "-c", "read line; exit 3"], settings);
		try
			client.ping();
		catch (TransportClosedException e)
			msg = e.msg;
		client.close();
	});
	assert(msg.canFind("exited with status 3"), "the exit status must be reported, got: " ~ msg);
}

version (Posix) unittest  // a final reply the server leaves unterminated at EOF is still delivered
{
	import core.time : msecs;

	// The child answers the request without a trailing newline and exits; the
	// last line is complete at end-of-input, as it is for the stdio server.
	Json result;
	inLoop(() @safe {
		auto transport = spawnStdioTransport([
			"sh", "-c",
			`read line; printf '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'`
		]);
		result = transport.deliver(parseJsonString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), 1);
		transport.closeProcess(200.msecs, 200.msecs);
	});
	assert(result["ok"].get!bool, "an unterminated final line must not be dropped");
}

// An in-memory server->client line queue so a test can play the server side of
// a stdio client without a subprocess.
version (unittest) private final class TestLines
{
	import vibe.core.sync : LocalManualEvent, createManualEvent;

	string[] queue;
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
		while (queue.length == 0 && !closed)
		{
			auto ec = evt.emitCount;
			evt.wait(ec);
		}
		if (queue.length == 0)
			return null;
		auto s = queue[0];
		queue = queue[1 .. $];
		return s;
	}
}

// Run `body` inside a vibe task + event loop and return what it threw (empty
// when it completed).
version (unittest) private string inLoopCapturing(scope void delegate() @safe body) @trusted
{
	string failure;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			body();
		catch (Exception e)
			failure = e.msg.length ? e.msg : "exception";
	});
	runEventLoop();
	return failure;
}

unittest  // stdio openListen with no leading frame times out, cancels the stream and throws
{
	import core.time : msecs;
	import mcp.protocol.errors : RequestTimeoutException;

	auto toClient = new TestLines;
	string[] toServer;
	bool timedOut;
	const failure = inLoopCapturing(() @safe {
		auto t = new StdioClientTransport(() @safe => toClient.take(), (string s) @safe {
			toServer ~= s;
		});
		t.listenTimeout_ = 50.msecs;
		auto listen = makeRequest(Json(7), "subscriptions/listen", Json.emptyObject);
		try
			t.openListen(listen);
		catch (RequestTimeoutException)
			timedOut = true;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut, "a listen with no leading frame must fail with RequestTimeoutException");
	assert(toServer.length == 2, "the timed-out listen must be cancelled on the server");
	auto c = parseJsonString(toServer[1]);
	assert(c["method"].get!string == "notifications/cancelled");
	assert(c["params"]["requestId"].get!long == 7);
}

unittest  // a stdio request with no reply fails after ClientSettings.requestTimeout and sends notifications/cancelled
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import mcp.client.client : ClientSettings;

	auto toClient = new TestLines;
	string[] toServer;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 200.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer ~= l;
		}, s);
		const start = MonoTime.currTime;
		try
			client.ping();
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		foreach (_; 0 .. 8)
			yield();
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut, "an unanswered request must fail with RequestTimeoutException");
	assert(took < 5.seconds);
	assert(toServer.length == 2, "the timeout must send notifications/cancelled");
	auto req = parseJsonString(toServer[0]);
	auto cancelled = parseJsonString(toServer[1]);
	assert(cancelled["method"].get!string == "notifications/cancelled");
	assert(cancelled["params"]["requestId"] == req["id"]);
}

unittest  // progress for a stdio request resets its timeout
{
	import core.time : msecs;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings, RequestOptions;
	import mcp.protocol.types : ProgressNotification;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	int progressSeen;
	bool completed;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 500.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		// The server reports progress every 200ms for 1.2s, then answers.
		runTask(() nothrow{
			try
			{
				auto req = parseJsonString(toServer.take());
				auto token = req["params"]["_meta"]["progressToken"];
				foreach (i; 0 .. 6)
				{
					sleep(200.msecs);
					Json p = Json.emptyObject;
					p["progressToken"] = token;
					p["progress"] = i;
					toClient.put(makeNotification("notifications/progress", p).toString());
				}
				Json result = Json.emptyObject;
				result["content"] = Json.emptyArray;
				toClient.put(makeResponse(req["id"], result).toString());
			}
			catch (Exception)
			{
			}
		});
		client.callTool("slow", Json.emptyObject,
			RequestOptions.withProgress((ProgressNotification n) @safe {
				progressSeen++;
			}));
		completed = true;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(completed);
	assert(progressSeen == 6);
}

unittest  // server pings do not hold a stdio request's deadline open
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 400.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		// The server never answers, but pings the client every 100ms for 2s.
		runTask(() nothrow{
			try
			{
				toServer.take();
				foreach (i; 0 .. 20)
				{
					sleep(100.msecs);
					toClient.put(makeRequest(Json(1000 + i), "ping", Json.emptyObject).toString());
				}
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.callTool("hang", Json.emptyObject);
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		sleep(2.seconds);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut);
	assert(took < 1200.msecs, "pings must not extend the deadline");
}

unittest  // a server request pauses a stdio deadline and resumes it with the time that was left
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;
	import mcp.protocol.types : ListRootsResult;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 800.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		// Answering roots/list takes 400ms, during which the deadline is paused.
		client.onListRoots = () @safe {
			sleep(400.msecs);
			return ListRootsResult.init;
		};
		runTask(() nothrow{
			try
			{
				toServer.take();
				sleep(500.msecs);
				toClient.put(makeRequest(Json(1000), "roots/list", Json.emptyObject).toString());
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.callTool("hang", Json.emptyObject);
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		sleep(200.msecs);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut);
	// 500ms elapsed + 400ms paused + the remaining 300ms.
	assert(took >= 1100.msecs, "the paused time must not count against the deadline");
	assert(took < 1500.msecs, "resuming must not restart the full timeout");
}

unittest  // ClientSettings.maxTotalTimeout caps a stdio request that keeps reporting progress
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings, RequestOptions;
	import mcp.protocol.types : ProgressNotification;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 300.msecs;
		s.maxTotalTimeout = 700.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		// The server reports progress every 100ms for 2s and never answers.
		runTask(() nothrow{
			try
			{
				auto req = parseJsonString(toServer.take());
				auto token = req["params"]["_meta"]["progressToken"];
				foreach (i; 0 .. 20)
				{
					sleep(100.msecs);
					Json p = Json.emptyObject;
					p["progressToken"] = token;
					p["progress"] = i;
					toClient.put(makeNotification("notifications/progress", p).toString());
				}
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.callTool("slow", Json.emptyObject,
				RequestOptions.withProgress((ProgressNotification) @safe {}));
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		sleep(2.seconds);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut);
	assert(took >= 600.msecs);
	assert(took < 1200.msecs, "progress must not extend a request past maxTotalTimeout");
}

unittest  // maxTotalTimeout fails a stdio request while a server request on its behalf is unanswered
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;
	import mcp.protocol.types : ListRootsResult;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = Duration.zero;
		s.maxTotalTimeout = 400.msecs;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		// The roots/list handler stands in for one waiting on an absent user.
		client.onListRoots = () @safe {
			sleep(2.seconds);
			return ListRootsResult.init;
		};
		runTask(() nothrow{
			try
			{
				toServer.take();
				toClient.put(makeRequest(Json(1000), "roots/list", Json.emptyObject).toString());
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.callTool("hang", Json.emptyObject);
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		sleep(2.seconds);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut);
	assert(took < 1200.msecs,
			"a pending server request must not hold a request past maxTotalTimeout");
}

unittest  // a stdio request whose write the server never drains still times out
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;

	auto toClient = new TestLines;
	bool timedOut;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 300.msecs;
		// A server that has stopped reading stdin: each write stalls for 2s.
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			sleep(2.seconds);
		}, s);
		const start = MonoTime.currTime;
		try
			client.callTool("big", Json.emptyObject);
		catch (RequestTimeoutException)
			timedOut = true;
		took = MonoTime.currTime - start;
		sleep(5.seconds);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timedOut);
	assert(took < 1200.msecs, "a stalled write must not hold a request past its timeout");
}

unittest  // a stdio request that times out before its line is written is never sent
{
	import core.time : msecs, seconds;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;

	auto toClient = new TestLines;
	string[] written;
	int timeouts;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = 300.msecs;
		// The first line written stalls for 1s, holding the channel's writer.
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			if (written.length == 0)
				sleep(1.seconds);
			written ~= l;
		}, s);
		runTask(() nothrow{
			try
				client.callTool("first", Json.emptyObject);
			catch (Exception)
				timeouts++;
		});
		try
			client.callTool("second", Json.emptyObject);
		catch (RequestTimeoutException)
			timeouts++;
		sleep(2.seconds);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(timeouts == 2);
	foreach (l; written)
		assert(parseJsonString(l)["params"]["name"].opt!string != "second",
				"a request abandoned before it was written must not reach the server");
}

unittest  // a server request the server cancels signals its handler and gets no reply
{
	import core.time : msecs, seconds, MonoTime;
	import vibe.core.core : sleep;
	import mcp.protocol.types : ListRootsResult;

	auto toClient = new TestLines;
	string[] toServer;
	bool sawCancel;
	string reason;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer ~= l;
		});
		// Stands in for a handler waiting on a user, giving up once cancelled.
		client.onListRoots = () @safe {
			auto token = client.serverRequestCancellation();
			const start = MonoTime.currTime;
			while (!token.isCancelled && MonoTime.currTime - start < 2.seconds)
				sleep(10.msecs);
			sawCancel = token.isCancelled;
			reason = token.reason;
			return ListRootsResult.init;
		};
		client.sendNotification("notifications/initialized"); // starts the read loop
		toClient.put(makeRequest(Json(5), "roots/list", Json.emptyObject).toString());
		sleep(100.msecs);
		Json p = Json.emptyObject;
		p["requestId"] = 5;
		p["reason"] = "user went away";
		toClient.put(makeNotification("notifications/cancelled", p).toString());
		sleep(500.msecs);
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(sawCancel, "the handler must see the server's cancellation");
	assert(reason == "user went away");
	foreach (l; toServer)
	{
		auto m = parseJsonString(l);
		assert("id" !in m || m["id"] != Json(5), "a cancelled server request must not be answered");
	}
}

unittest  // cancelling a call's CancellationToken fails it at once and sends notifications/cancelled
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings, RequestOptions, CancellationToken;
	import mcp.protocol.errors : ErrorCode;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	int code;
	Duration took;
	Json cancelled;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = Duration.zero;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		auto token = new CancellationToken;
		RequestOptions opts;
		opts.cancellation = token;
		runTask(() nothrow{
			try
			{
				sleep(100.msecs);
				token.cancel("user aborted");
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.callTool("slow", Json.emptyObject, opts);
		catch (McpException e)
			code = e.code;
		took = MonoTime.currTime - start;
		auto req = parseJsonString(toServer.take());
		cancelled = parseJsonString(toServer.take());
		assert(cancelled["params"]["requestId"] == req["id"]);
		// A late response for the cancelled request is ignored.
		Json result = Json.emptyObject;
		result["content"] = Json.emptyArray;
		toClient.put(makeResponse(req["id"], result).toString());
		foreach (_; 0 .. 4)
			yield();
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(code == ErrorCode.requestCancelled, "a cancelled call must fail with requestCancelled");
	assert(took < 5.seconds);
	assert(cancelled["method"].get!string == "notifications/cancelled");
	assert(cancelled["params"]["reason"].get!string == "user aborted");
}

unittest  // a request on a stdio channel the server closed fails with TransportClosedException
{
	import mcp.client.client : TransportClosedException;

	auto toClient = new TestLines;
	bool closedError;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
		});
		toClient.closeEnd();
		foreach (_; 0 .. 2)
		{
			try
				client.ping();
			catch (TransportClosedException)
				closedError = true;
			catch (McpException)
			{
			}
		}
	});
	assert(failure.length == 0, failure);
	assert(closedError, "a closed channel must surface as TransportClosedException");
}

unittest  // a call whose CancellationToken is already cancelled sends nothing
{
	import mcp.client.client : RequestOptions, CancellationToken;
	import mcp.protocol.errors : ErrorCode;

	string[] toServer;
	int code;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => cast(string) null, (string l) @safe {
			toServer ~= l;
		});
		auto token = new CancellationToken;
		token.cancel();
		RequestOptions opts;
		opts.cancellation = token;
		try
			client.listTools(opts);
		catch (McpException e)
			code = e.code;
	});
	assert(failure.length == 0, failure);
	assert(code == ErrorCode.requestCancelled);
	assert(toServer.length == 0);
}

unittest  // cancel(id) on an in-flight stdio request wakes its caller at once
{
	import core.time : msecs, seconds, MonoTime, Duration;
	import vibe.core.core : sleep;
	import mcp.client.client : ClientSettings;
	import mcp.protocol.errors : ErrorCode;

	auto toClient = new TestLines;
	auto toServer = new TestLines;
	int code;
	Duration took;
	const failure = inLoopCapturing(() @safe {
		ClientSettings s;
		s.requestTimeout = Duration.zero;
		auto client = McpClient.stdio(() @safe => toClient.take(), (string l) @safe {
			toServer.put(l);
		}, s);
		runTask(() nothrow{
			try
			{
				auto req = parseJsonString(toServer.take());
				client.cancel(req["id"].get!long);
			}
			catch (Exception)
			{
			}
		});
		const start = MonoTime.currTime;
		try
			client.ping();
		catch (McpException e)
			code = e.code;
		took = MonoTime.currTime - start;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(code == ErrorCode.requestCancelled);
	assert(took < 5.seconds);
}

unittest  // McpClient.close() returns while a stdio write is stalled on a server that stopped reading
{
	import core.time : msecs, seconds;
	import vibe.core.core : sleep;
	import vibe.core.sync : createManualEvent;

	auto toClient = new TestLines;
	auto unstall = createManualEvent();
	bool stall, closed, closedInTime;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string s) @safe {
			if (stall)
			{
				const ec = unstall.emitCount;
				unstall.wait(ec);
				return;
			}
			acknowledgeListen(toClient, s);
		});
		client.enableModern();
		SubscriptionFilter filter = {toolsListChanged: true};
		client.subscriptionsListen(filter);
		// The server stops reading: the next write parks holding the writer.
		stall = true;
		runTask(() nothrow{
			try
				client.ping();
			catch (Exception)
			{
			}
		});
		yield();
		runTask(() nothrow{
			try
				client.close();
			catch (Exception)
			{
			}
			closed = true;
		});
		sleep(300.msecs);
		closedInTime = closed;
		unstall.emit();
		toClient.closeEnd();
		sleep(50.msecs);
	});
	assert(failure.length == 0, failure);
	assert(closedInTime, "close() must not wait on a stalled write");
}

version (Posix) unittest  // closeProcess() with a write parked on a child that never reads stdin
{
	import core.time : msecs, seconds;
	import std.array : replicate;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import core.sys.posix.signal : SIGTERM;
	import vibe.core.core : sleep;

	bool parked, writeEnded, timely;
	int status;
	inLoop(() @safe {
		auto transport = spawnStdioTransport(["sh", "-c", "sleep 30"]);
		Json big = Json.emptyObject;
		big["jsonrpc"] = "2.0";
		big["method"] = "notifications/x";
		big["params"] = Json(["pad": Json("x".replicate(1 << 20))]);
		runTask(() nothrow{
			try
				transport.sendOneway(big);
			catch (Exception)
			{
			}
			writeEnded = true;
		});
		sleep(50.msecs);
		parked = !writeEnded;
		auto sw = StopWatch(AutoStart.yes);
		status = transport.closeProcess(200.msecs, 2.seconds);
		timely = sw.peek < 5.seconds;
		sleep(50.msecs);
	});
	assert(parked, "the write must be parked on the full pipe");
	assert(timely);
	assert(status == -SIGTERM);
	assert(writeEnded, "the parked write must fail once the child is gone");
}

unittest  // a stdio write that fails because the server stopped reading surfaces as TransportClosedException
{
	import mcp.client.client : TransportClosedException;

	auto toClient = new TestLines;
	bool requestClosed, notifyClosed;
	const failure = inLoopCapturing(() @safe {
		auto client = McpClient.stdio(() @safe => toClient.take(), (string) @safe {
			throw new Exception("Broken pipe");
		});
		try
			client.ping();
		catch (TransportClosedException)
			requestClosed = true;
		try
			client.sendNotification("notifications/x");
		catch (TransportClosedException)
			notifyClosed = true;
		toClient.closeEnd();
	});
	assert(failure.length == 0, failure);
	assert(requestClosed, "a failed request write must raise TransportClosedException");
	assert(notifyClosed, "a failed notification write must raise TransportClosedException");
}
