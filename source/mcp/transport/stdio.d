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
	import vibe.core.core : runTask, yield;
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

	// Count of dispatched-but-not-yet-finished request handler tasks. Cooperative
	// vibe tasks on one thread never preempt each other between yield points, so a
	// plain counter (incremented before runTask, decremented in the handler's
	// finally) needs no atomics. After the read loop ends at EOF we drain this to
	// zero under a bounded grace period so an already-computed reply still flushes
	// through channel.sendRaw before the loop tears down.
	size_t inflight;

	// The server->client write sink and request channel both go through the one
	// serialized writer on `channel`.
	void sink(string line) @safe
	{
		channel.sendRaw(line);
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
			// Track it as in-flight so EOF cannot abandon a handler that has computed
			// its reply but not yet written it.
			++inflight;
			runTask((Message msg) nothrow{
				try
				{
					auto ctx = new StdioContextFactoryReply(server, &sink, &serverRequest, msg);
					ctx.run(channel);
				}
				catch (Exception)
				{
				}
				finally
					--inflight;
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
			// A reply to a server->client request is correlated by the coordinator in
			// `routeMessage`, which only ever hands request/notification kinds to
			// `onInbound`. Reaching here means that dispatch contract was broken; assert
			// rather than silently drop the reply (compiled out in release builds).
			assert(false,
					"onInbound receives request/notification only; responses are coordinator-routed");
		}
	}

	// An inbound JSON-RPC batch array is dispatched as a whole through the server's
	// `handleRaw`, so its negotiated-version gate (reject a batch with a null-id
	// -32600 on 2025-06-18+) and its single JSON-array response framing both apply —
	// splitting the batch into separate lines would bypass both. The batch runs in
	// its own task (tracked as in-flight) so a long-running member handler cannot
	// stall the read loop, and `handleRaw` returns the one aggregated array frame.
	void onInboundBatch(string raw) @safe
	{
		++inflight;
		runTask((string text) nothrow{
			try
			{
				auto reply = server.handleRaw(text, &sink, &serverRequest);
				if (reply.length)
					channel.sendRaw(reply);
			}
			catch (Exception)
			{
			}
			finally
				--inflight;
		}, raw);
	}

	channel = new DuplexChannel(readLine, writeLine, &onInbound, &onInboundBatch);
	channel.runReadLoop();

	// The read loop has ended at stdin EOF. failPending (inside runReadLoop) already
	// released any handler blocked in a server->client request, but a handler that
	// has computed its reply still needs to be scheduled so its sendRaw runs. Yield
	// until every dispatched handler task has finished, bounded so a handler stuck
	// in unbounded local work cannot hold the process open forever.
	enum size_t drainYields = 4096;
	for (size_t i = 0; i < drainYields && inflight > 0; ++i)
		yield();
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
			channel.sendRaw(reply);
	}
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

	// Enforce the documented "at most once per process" invariant explicitly, so it
	// holds for both a concurrent second call and a sequential one and does not
	// depend on eventcore's adopt()/refCount side effects.
	synchronized
	{
		if (()@trusted { return _ranStdio; }())
			throw new Exception("runStdio: must be called at most once per process");
		() @trusted { _ranStdio = true; }();
	}

	// dup-then-adopt fd 0/1 and save their flags; restored + released on scope exit.
	auto adopted = AdoptedStdio.acquire();
	scope (exit)
		adopted.release();
	auto inFD = adopted.inFD;
	auto outFD = adopted.outFD;

	auto reader = StdinLineReader(inFD, maxLineBytes);

	string readLine() @safe
	{
		return reader.next();
	}

	void writeLine(string s) @safe
	{
		auto bytes = cast(const(ubyte)[])(s ~ "\n");
		// Write the whole frame (IOMode.all loops internally until done). Inspect
		// the result symmetrically with readLine: a status that is neither ok nor
		// wouldBlock, or a short write, means the peer closed its read end (EPIPE /
		// IOStatus.error) and the channel is broken. Throw so DuplexChannel.send
		// observes the failure instead of producing replies that are silently lost.
		// On POSIX a broken-pipe write may also raise SIGPIPE; a server using this
		// transport should ignore SIGPIPE (signal(SIGPIPE, SIG_IGN)) so the failure
		// surfaces here as IOStatus.error rather than terminating the process.
		auto res = outFD.writeAll(bytes);
		if (writeFailed(res.status, res.nbytes, bytes.length))
			throw new Exception("runStdio: write to stdout failed (peer closed its read end?)");
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

/// Result of one `StdioEnd` read/write: the eventcore status and byte count,
/// surfaced uniformly whether the underlying fd is a pipe or a socket.
private struct IoResult
{
	import eventcore.driver : IOStatus;

	IOStatus status;
	size_t nbytes;
}

/// One end (stdin or stdout) of the stdio transport, abstracting over whether the
/// adopted fd is a pipe/FIFO or a stream socket. This matters because a child
/// process launched by a libuv-based host (Node — the MCP Inspector, Claude
/// Desktop, VS Code, …) is given a unix-domain SOCKET as fd 0/1, not a pipe, and
/// eventcore's pipe read path does not deliver readability for data that arrives
/// after the read is parked on a socket fd. Adopting the fd through the matching
/// eventcore API (pipes vs sockets) makes server->client requests (elicit/sample)
/// work over stdio with both kinds of host.
///
/// POSIX adopts the dup'd fd into eventcore (pipe or socket). Windows has no
/// working eventcore pipe driver for an inherited stdio handle, so its `StdioEnd`
/// (defined below) bridges a blocking reader thread to the loop instead.
version (Posix)
	private struct StdioEnd
{
	import eventcore.driver : PipeFD, StreamSocketFD;

	private bool isSocket_;
	private PipeFD pipe_;
	private StreamSocketFD sock_;

	/// Adopt `fd` into eventcore, picking the socket or pipe driver by inspecting
	/// the fd's type. Returns an end whose `valid` is false if adoption failed.
	static StdioEnd adopt(int fd) @safe
	{
		import eventcore.core : eventDriver;
		import core.sys.posix.sys.stat : fstat, stat_t, S_ISSOCK;

		StdioEnd e;
		stat_t st;
		e.isSocket_ = () @trusted {
			return fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode);
		}();
		if (e.isSocket_)
			e.sock_ = () @trusted { return eventDriver.sockets.adoptStream(fd); }();
		else
			e.pipe_ = () @trusted { return eventDriver.pipes.adopt(fd); }();
		return e;
	}

	/// Whether adoption produced a usable eventcore handle.
	bool valid() @safe
	{
		import eventcore.core : eventDriver;

		if (isSocket_)
			return () @trusted { return eventDriver.sockets.isValid(sock_); }();
		return () @trusted { return eventDriver.pipes.isValid(pipe_); }();
	}

	/// Release the adopted handle (closes the dup'd fd eventcore owns).
	void releaseRef() @safe
	{
		import eventcore.core : eventDriver;

		if (isSocket_)
			() @trusted { eventDriver.sockets.releaseRef(sock_); }();
		else
			() @trusted { eventDriver.pipes.releaseRef(pipe_); }();
	}

	/// Read whatever is currently available into `buf` (`IOMode.once`), blocking
	/// the calling fiber until at least one byte arrives or the peer closes.
	IoResult readOnce(ubyte[] buf) @safe
	{
		import eventcore.core : eventDriver;
		import eventcore.driver : IOMode, IOCallback, PipeIOCallback;
		import vibe.internal.async : asyncAwaitUninterruptible;

		if (isSocket_)
		{
			auto res = () @trusted {
				return asyncAwaitUninterruptible!(IOCallback, (cb) {
					eventDriver.sockets.read(sock_, buf, IOMode.once, cb);
				});
			}();
			return IoResult(res[1], res[2]);
		}
		auto res = () @trusted {
			return asyncAwaitUninterruptible!(PipeIOCallback, (cb) {
				eventDriver.pipes.read(pipe_, buf, IOMode.once, cb);
			});
		}();
		return IoResult(res[1], res[2]);
	}

	/// Write the whole `bytes` frame (`IOMode.all` loops internally until done).
	IoResult writeAll(const(ubyte)[] bytes) @safe
	{
		import eventcore.core : eventDriver;
		import eventcore.driver : IOMode, IOCallback, PipeIOCallback;
		import vibe.internal.async : asyncAwaitUninterruptible;

		if (isSocket_)
		{
			auto res = () @trusted {
				return asyncAwaitUninterruptible!(IOCallback, (cb) {
					eventDriver.sockets.write(sock_, bytes, IOMode.all, cb);
				});
			}();
			return IoResult(res[1], res[2]);
		}
		auto res = () @trusted {
			return asyncAwaitUninterruptible!(PipeIOCallback, (cb) {
				eventDriver.pipes.write(pipe_, bytes, IOMode.all, cb);
			});
		}();
		return IoResult(res[1], res[2]);
	}
}

/// Windows stdin/stdout end. eventcore's WinAPI pipe driver is unimplemented, so
/// an inherited console/pipe HANDLE cannot be adopted as an async pipe. The read
/// end is pumped by a dedicated daemon thread doing blocking `ReadFile`, which
/// hands byte chunks to the cooperative read loop through a thread-safe vibe
/// `Channel`; `readOnce` drains that channel, yielding the calling fiber (not the
/// event-loop thread) until a chunk arrives or stdin reaches end-of-input. The
/// write end issues a blocking `WriteFile` inline -- MCP frames are small and the
/// host drains stdout promptly, so the brief loop stall is acceptable.
else version (Windows)
	private struct StdioEnd
{
	import core.sys.windows.windef : HANDLE, DWORD;
	import core.sys.windows.winbase : INVALID_HANDLE_VALUE, ReadFile, WriteFile;
	import vibe.core.channel : Channel, createChannel;
	import core.thread : Thread;

	private HANDLE handle_;
	private bool valid_;
	private bool isRead_;
	// Read end only: the chunk channel fed by the reader thread.
	private Channel!(immutable(ubyte)[]) chan_;

	/// Adopt `h` (the process's stdin) and start pumping it on a daemon thread.
	static StdioEnd adoptRead(HANDLE h) @safe
	{
		StdioEnd e;
		e.handle_ = h;
		e.isRead_ = true;
		e.valid_ = isValidHandle(h);
		if (!e.valid_)
			return e;
		e.chan_ = createChannel!(immutable(ubyte)[])();
		auto chan = e.chan_;
		() @trusted {
			auto t = new Thread({ pumpStdin(h, chan); });
			t.isDaemon = true;
			t.start();
		}();
		return e;
	}

	/// Adopt `h` (the process's stdout) for blocking writes; no thread needed.
	static StdioEnd adoptWrite(HANDLE h) @safe
	{
		StdioEnd e;
		e.handle_ = h;
		e.valid_ = isValidHandle(h);
		return e;
	}

	/// Whether the adopted handle is usable.
	bool valid() @safe
	{
		return valid_;
	}

	/// Close the read channel so a parked `readOnce` observes end-of-input. The
	/// daemon reader thread exits when stdin reaches EOF (or with the process); it
	/// is never joined, so a thread still parked in `ReadFile` cannot hold teardown.
	void releaseRef() @safe
	{
		if (isRead_ && valid_)
			() @trusted { chan_.close(); }();
	}

	/// Drain the next chunk the reader thread produced into `buf`, blocking the
	/// calling fiber (not the event-loop thread) until a chunk arrives or stdin
	/// reaches EOF (channel closed -> `disconnected`, mirroring a 0-byte POSIX read).
	IoResult readOnce(ubyte[] buf) @safe
	{
		import eventcore.driver : IOStatus;

		immutable(ubyte)[] chunk;
		const got = () @trusted { return chan_.tryConsumeOne(chunk); }();
		if (!got)
			return IoResult(IOStatus.disconnected, 0);
		const n = chunk.length <= buf.length ? chunk.length : buf.length;
		buf[0 .. n] = chunk[0 .. n];
		return IoResult(IOStatus.ok, n);
	}

	/// Write the whole `bytes` frame with a blocking `WriteFile` loop. A failed or
	/// short write surfaces as `IOStatus.error` so `DuplexChannel.send` observes the
	/// broken channel rather than silently dropping replies.
	IoResult writeAll(const(ubyte)[] bytes) @safe
	{
		import eventcore.driver : IOStatus;

		size_t off;
		while (off < bytes.length)
		{
			DWORD wrote;
			const ok = () @trusted {
				return WriteFile(handle_, cast(const(void)*)(bytes.ptr + off),
						cast(DWORD)(bytes.length - off), &wrote, null) != 0;
			}();
			if (!ok || wrote == 0)
				return IoResult(IOStatus.error, off);
			off += wrote;
		}
		return IoResult(IOStatus.ok, off);
	}

	private static bool isValidHandle(HANDLE h) @safe
	{
		return h !is null && h !is INVALID_HANDLE_VALUE;
	}

	/// Reader-thread body: blocking `ReadFile` into 32 KiB chunks, each handed to
	/// the fiber through the channel; a failed/0-byte read closes the channel to
	/// signal EOF. Chunks are <= the reader loop's refill buffer (64 KiB), so
	/// `readOnce` never has to split a chunk across calls.
	private static void pumpStdin(HANDLE h, Channel!(immutable(ubyte)[]) chan) @system
	{
		ubyte[32 * 1024] buf;
		for (;;)
		{
			DWORD got;
			const ok = ReadFile(h, cast(void*) buf.ptr, cast(DWORD) buf.length, &got, null) != 0;
			if (!ok || got == 0)
				break;
			chan.put(buf[0 .. got].idup);
		}
		chan.close();
	}
}

/// Owns the dup()'d, vibe-adopted copies of fd 0/1 plus the saved descriptor flags
/// of the real fd 0/1, encapsulating runStdio's fd lifecycle ceremony.
///
/// `acquire` dup()s fd 0/1, saves the originals' flags, and adopts the dups as
/// vibe-async pipes; `release` restores the saved flags on fd 0/1 and then releases
/// the adopted dups. The exact ordering runStdio relies on is preserved: restore
/// the flags BEFORE releasing, so the restore operates on still-valid descriptors.
version (Posix)
	private struct AdoptedStdio
{
	StdioEnd inFD;
	StdioEnd outFD;
	private int inFlags;
	private int outFlags;

	/// Adopt dup()'d copies of fd 0/1 rather than fd 0/1 themselves. `releaseRef`
	/// close()s the adopted fd on return; by adopting dups we close only the dups,
	/// leaving the process's real stdin/stdout OPEN for any code that runs after.
	/// Adopting fd 0/1 directly would close the real stdin/stdout.
	static AdoptedStdio acquire() @safe
	{
		import core.sys.posix.unistd : dup, close;
		import core.sys.posix.fcntl : fcntl, F_GETFL;

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
		AdoptedStdio a;
		a.inFlags = () @trusted { return fcntl(0, F_GETFL); }();
		a.outFlags = () @trusted { return fcntl(1, F_GETFL); }();

		// Adopt each dup through the eventcore driver matching its fd type (pipe vs
		// socket): a libuv-based host hands the child a socket as fd 0/1, which must
		// be driven through the sockets API to receive readability for late-arriving
		// replies (the server->client elicit/sample case).
		a.inFD = StdioEnd.adopt(in2);
		a.outFD = StdioEnd.adopt(out2);

		// Fail fast: if adopt rejected a dup (returned an invalid handle), close the
		// dups we still own and bail rather than silently operating on invalid handles.
		if (!a.inFD.valid() || !a.outFD.valid())
		{
			if (a.inFD.valid())
				a.inFD.releaseRef();
			else
				() @trusted { close(in2); }();
			if (a.outFD.valid())
				a.outFD.releaseRef();
			else
				() @trusted { close(out2); }();
			throw new Exception("runStdio: failed to adopt stdin/stdout dups");
		}
		return a;
	}

	/// On return restore the saved flags on fd 0/1 FIRST (clearing the O_NONBLOCK that
	/// adopt set on the shared open file description), THEN release the adopted dups
	/// (which close()s the dup'd fds, never the real fd 0/1). Order matters: restoring
	/// before release operates on still-valid descriptors.
	void release() @safe
	{
		import core.sys.posix.fcntl : fcntl, F_SETFL;

		() @trusted {
			if (inFlags != -1)
				fcntl(0, F_SETFL, inFlags);
			if (outFlags != -1)
				fcntl(1, F_SETFL, outFlags);
		}();
		inFD.releaseRef();
		outFD.releaseRef();
	}
}

/// Windows counterpart: there is no fd dup/`O_NONBLOCK` ceremony because the
/// transport does not adopt the handles into eventcore. `acquire` takes the
/// process's stdin/stdout handles via `GetStdHandle` (the read end spins up its
/// pump thread); `release` closes the read channel so the read loop ends. The
/// real stdin/stdout handles are never closed, so code running after `runStdio`
/// still inherits them.
else version (Windows)
	private struct AdoptedStdio
{
	StdioEnd inFD;
	StdioEnd outFD;

	static AdoptedStdio acquire() @safe
	{
		import core.sys.windows.winbase : GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE;

		AdoptedStdio a;
		auto hIn = () @trusted { return GetStdHandle(STD_INPUT_HANDLE); }();
		auto hOut = () @trusted { return GetStdHandle(STD_OUTPUT_HANDLE); }();
		a.inFD = StdioEnd.adoptRead(hIn);
		a.outFD = StdioEnd.adoptWrite(hOut);
		if (!a.inFD.valid() || !a.outFD.valid())
		{
			a.inFD.releaseRef();
			throw new Exception("runStdio: failed to acquire Windows stdin/stdout handles");
		}
		return a;
	}

	void release() @safe
	{
		inFD.releaseRef();
		outFD.releaseRef();
	}
}

/// Buffered, cooperative line reader over a vibe-adopted stdin pipe, extracted from
/// runStdio so its CR-strip and over-long-drop edge cases are unit-testable.
///
/// A small persistent buffer so stdin is read in 64 KiB chunks (IOMode.once) rather
/// than one syscall + fiber suspend/resume per byte: `next` scans the filled region
/// for '\n', returns the line up to it, and retains the bytes after the newline for
/// the next call.
private struct StdinLineReader
{
	private StdioEnd inEnd;
	private size_t maxLineBytes;
	private enum size_t chunk = 64 * 1024;
	private ubyte[] buf; // bytes read but not yet consumed
	private size_t bufPos; // index of the next unconsumed byte in `buf`

	this(StdioEnd inEnd, size_t maxLineBytes) @safe
	{
		this.inEnd = inEnd;
		this.maxLineBytes = maxLineBytes;
	}

	// Refill `buf` from stdin (IOMode.once into a chunk-sized buffer): return
	// false on EOF/error (a 0-byte or non-ok/non-wouldBlock read) with `buf` cleared,
	// else true with `buf` trimmed to the bytes read and `bufPos` reset to 0.
	private bool refill() @safe
	{
		import eventcore.driver : IOStatus;

		if (buf.length < chunk)
			buf.length = chunk;
		bufPos = 0;
		auto res = inEnd.readOnce(buf);
		if (res.nbytes == 0 || (res.status != IOStatus.ok && res.status != IOStatus.wouldBlock))
		{
			buf = null;
			bufPos = 0;
			return false;
		}
		buf = buf[0 .. res.nbytes];
		return true;
	}

	// Async, cooperative line read over stdin: return the next line (without its
	// '\n', stripping a trailing '\r'); a 0-byte read (disconnected) is EOF -> null.
	// A partial, unterminated fragment accumulated before EOF is unrecoverable and
	// is discarded (null is returned) rather than forwarded as a malformed line.
	// An over-long line (> maxLineBytes) is dropped and reading resumes after the
	// next newline.
	string next() @safe
	{
		return nextWith(&refill);
	}

	// The pure line-assembly state machine, parameterised on the buffer-refill
	// source so the CR-strip and over-long-drop paths are unit-testable with a fake
	// refill (no real eventcore pipe I/O). `refillFn` fills `buf`/`bufPos` and
	// returns false at EOF, exactly as `refill` does.
	private string nextWith(scope bool delegate() @safe refillFn) @safe
	{
		ubyte[] acc;
		bool dropping; // true once `acc` exceeded maxLineBytes: skip to next '\n'
		for (;;)
		{
			if (bufPos >= buf.length)
			{
				// Refill from the pipe.
				if (!refillFn())
					return null; // EOF — partial fragment is unrecoverable
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
			// Enforce the size cap here too: when the line and its newline land in the
			// same chunk the no-newline accumulation path above never runs, so the cap
			// must also be checked on the newline-found path. An over-long line (already
			// dropping, or only now over the cap) is discarded and a fresh one started.
			if (dropping || acc.length > maxLineBytes)
			{
				dropping = false;
				acc = null;
				continue;
			}
			if (acc.length && acc[$ - 1] == '\r')
				acc = acc[0 .. $ - 1];
			return () @trusted { return cast(string) acc.idup; }();
		}
	}
}

/// Decide whether a stdout write is a failure the channel must surface. A status
/// that is neither `ok` nor `wouldBlock`, or a short write (fewer bytes than the
/// frame), means the peer closed its read end (EPIPE / `IOStatus.error`); the
/// channel is broken and the write must not be silently swallowed.
private bool writeFailed(ECStatus)(ECStatus status, size_t nbytes, size_t expected) @safe pure nothrow @nogc
{
	import eventcore.driver : IOStatus;

	if (status != IOStatus.ok && status != IOStatus.wouldBlock)
		return true;
	return nbytes < expected;
}

unittest  // writeFailed flags a non-ok status and a short write, accepts a full ok write
{
	import eventcore.driver : IOStatus;

	assert(!writeFailed(IOStatus.ok, 10, 10));
	assert(!writeFailed(IOStatus.wouldBlock, 10, 10));
	assert(writeFailed(IOStatus.error, 10, 10));
	assert(writeFailed(IOStatus.disconnected, 0, 10));
	assert(writeFailed(IOStatus.ok, 4, 10));
}

version (unittest)
{
	// Drive StdinLineReader.nextWith over an in-memory byte feed (no real pipe / no
	// event loop): each refill hands the reader the next pre-chunked slice, and
	// returns false (EOF) once the chunks are exhausted -- exactly the contract
	// StdinLineReader.refill has. Lets the line-assembly edge cases be unit-tested.
	private string[] drainLineReader(size_t maxLineBytes, ubyte[][] chunks) @safe
	{
		auto reader = StdinLineReader.init;
		reader.maxLineBytes = maxLineBytes;
		size_t ci;
		bool refill() @safe
		{
			if (ci >= chunks.length)
			{
				reader.buf = null;
				reader.bufPos = 0;
				return false;
			}
			reader.buf = chunks[ci++];
			reader.bufPos = 0;
			return true;
		}

		string[] lines;
		for (;;)
		{
			auto s = reader.nextWith(&refill);
			if (s is null)
				break;
			lines ~= s;
		}
		return lines;
	}
}

unittest  // StdinLineReader strips a trailing CR on a CRLF-terminated line
{
	auto lines = drainLineReader(64, [cast(ubyte[]) "ok\r\n".dup]);
	assert(lines.length == 1);
	assert(lines[0] == "ok", "trailing CR must be stripped");
}

unittest  // StdinLineReader drops an over-long line and resumes reading after the next newline
{
	// maxLineBytes = 8. The middle line's bytes arrive newline-free across refills so
	// the accumulator crosses maxLineBytes (the over-long drop path) before its
	// terminating newline; the surrounding short lines still come through. The drop is
	// triggered while accumulating without a newline, mirroring a real chunked pipe.
	auto lines = drainLineReader(8, [
		cast(ubyte[]) "a\n11111".dup, cast(ubyte[]) "1111".dup,
		cast(ubyte[]) "1111\ntail\n".dup
	]);
	assert(lines == ["a", "tail"], "over-long line dropped, reading resumes after its newline");
}

unittest  // StdinLineReader drops an over-long line whose terminating newline shares its chunk
{
	// maxLineBytes = 8. The over-long line and its newline arrive in the SAME chunk,
	// so the no-newline accumulation path (which enforces the cap) is never taken.
	// The size cap must still be enforced on the newline-found path: the over-long
	// line is dropped and the following short line still comes through.
	auto lines = drainLineReader(8, [cast(ubyte[]) "aaaaaaaaaaaa\ntail\n".dup]);
	assert(lines == ["tail"], "over-long line with same-chunk newline must still be dropped");
}

unittest  // StdinLineReader reassembles a line split across two refills
{
	auto lines = drainLineReader(64, [
		cast(ubyte[]) "hel".dup, cast(ubyte[]) "lo\nworld\n".dup
	]);
	assert(lines == ["hello", "world"], "a line spanning two refills is reassembled");
}

unittest  // StdinLineReader discards a partial (unterminated) fragment at EOF and returns null
{
	// A newline-less fragment at EOF is unrecoverable: passing it to the line
	// dispatcher would trigger a malformed-JSON parse error and a spurious
	// null-id error-response write to the already-closed peer. null is returned
	// to signal end-of-input cleanly.
	auto lines = drainLineReader(64, [cast(ubyte[]) "noeol".dup]);
	assert(lines == [], "a trailing line without a newline must be discarded at EOF");
}

version (Posix) unittest  // runStdio's adopt/releaseRef cycle leaves the original fd open with its O_NONBLOCK bit unchanged
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

version (Posix) unittest  // StdioEnd.adopt routes a socket fd through the sockets driver, a pipe fd through pipes
{
	// A libuv/Node host (the MCP Inspector, Claude Desktop, …) hands the child a
	// unix-domain socket as stdin; a pipe-based host / vibe spawn hands a FIFO. The
	// fd must be adopted through the matching eventcore driver, otherwise a reply
	// that arrives after a handler parks (server->client elicit/sample) is never
	// read. Adopt dups (as runStdio does) so the originals stay ours to close.
	import core.sys.posix.sys.socket : socketpair, AF_UNIX, SOCK_STREAM;
	import core.sys.posix.unistd : dup, pipe, close;

	int[2] sp;
	assert(() @trusted { return socketpair(AF_UNIX, SOCK_STREAM, 0, sp); }() == 0,
			"socketpair() failed");
	scope (exit)
		() @trusted { close(sp[0]); close(sp[1]); }();
	const sdup = () @trusted { return dup(sp[0]); }();
	auto sockEnd = StdioEnd.adopt(sdup);
	scope (exit)
		sockEnd.releaseRef();
	assert(sockEnd.valid(), "adopting a socket end should yield a valid handle");
	assert(sockEnd.isSocket_, "a socketpair fd must be detected and adopted as a socket");

	int[2] pp;
	assert(() @trusted { return pipe(pp); }() == 0, "pipe() failed");
	scope (exit)
		() @trusted { close(pp[0]); close(pp[1]); }();
	const pdup = () @trusted { return dup(pp[0]); }();
	auto pipeEnd = StdioEnd.adopt(pdup);
	scope (exit)
		pipeEnd.releaseRef();
	assert(pipeEnd.valid(), "adopting a pipe end should yield a valid handle");
	assert(!pipeEnd.isSocket_, "a pipe fd must be detected and adopted as a pipe");
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

unittest  // stdio: a batch on a negotiated 2025-06-18+ session is rejected with one null-id -32600
{
	auto s = new McpServer("stdio-srv", "1.0");

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		// Negotiate a version where JSON-RPC batching was removed.
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":` ~ `{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`);
		link.feed(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
		foreach (_; 0 .. 8)
			yield();
		// A two-member batch must be rejected as a whole, not silently processed.
		link.feed(`[{"jsonrpc":"2.0","id":2,"method":"ping"},`
			~ `{"jsonrpc":"2.0","id":3,"method":"ping"}]`);
		foreach (_; 0 .. 16)
			yield();
		outputs = link.outbound.dup;
	});

	// Exactly one extra frame after the initialize reply: a single null-id -32600
	// error, not two per-member replies (which the split path would have produced).
	bool sawReject;
	size_t pingReplies;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if ("error" in j && j["error"]["code"].get!int == -32600 && j["id"].type == Json.Type.null_)
			sawReject = true;
		if ("id" in j && (j["id"].type == Json.Type.int_)
				&& (j["id"].get!int == 2 || j["id"].get!int == 3))
			pingReplies++;
	}
	assert(sawReject, "a batch on 2025-06-18+ must be rejected with a null-id -32600");
	assert(pingReplies == 0, "no batch member may be processed on 2025-06-18+");
}

unittest  // stdio: a batch on a pre-2025-06-18 session is answered with ONE JSON array frame
{
	auto s = new McpServer("stdio-srv", "1.0");

	string[] outputs;
	withServer(s, (ServerLink link) @safe {
		// Negotiate 2025-03-26, where batching is legal.
		link.feed(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":` ~ `{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`);
		link.feed(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
		foreach (_; 0 .. 8)
			yield();
		link.feed(`[{"jsonrpc":"2.0","id":2,"method":"ping"},`
			~ `{"jsonrpc":"2.0","id":3,"method":"ping"}]`);
		foreach (_; 0 .. 16)
			yield();
		outputs = link.outbound.dup;
	});

	// The batch produced exactly one outbound frame, and it is a JSON array carrying
	// both replies — not two separate newline-delimited response objects.
	bool sawArrayWithBoth;
	foreach (o; outputs)
	{
		auto j = parseJsonString(o);
		if (j.type != Json.Type.array)
			continue;
		bool id2, id3;
		foreach (i; 0 .. j.length)
		{
			auto e = j[i];
			if ("id" in e && e["id"].type == Json.Type.int_ && e["id"].get!int == 2)
				id2 = true;
			if ("id" in e && e["id"].type == Json.Type.int_ && e["id"].get!int == 3)
				id3 = true;
		}
		if (id2 && id3 && j.length == 2)
			sawArrayWithBoth = true;
	}
	assert(sawArrayWithBoth, "a legal batch must yield one JSON-array frame with both replies");
}

unittest  // stdio: a tool calling ctx.elicit is answered over the same stdio channel
{
	import mcp.protocol.types : ElicitAction;

	auto s = McpServer.stateful("stdio-peer", "1.0");
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

unittest  // a handler still running when stdin EOFs is drained: its reply is not dropped
{
	// Reproduces the EOF/in-flight race: a tool handler blocks until after stdin
	// reaches EOF, then computes its reply. Without a drain after the read loop the
	// reply task is never scheduled again and the response is silently lost.
	auto s = new McpServer("eof-drain", "1.0");
	auto release = createManualEvent();
	auto entered = createManualEvent();
	Tool slow = {name: "slow"};
	s.registerDynamicTool(slow, (Json args, RequestContext ctx) @safe {
		entered.emit();
		auto ec = release.emitCount;
		() @trusted { release.wait(ec); }();
		CallToolResult r;
		r.content = [Content.makeText("late")];
		return r;
	});

	auto link = new ServerLink;
	string[] outputs;
	() @trusted {
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				serveStdio(s, &link.readLine, &link.writeLine);
			catch (Exception)
			{
			}
		});
		runTask(() nothrow{
			try
			{
				link.feed(
					`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`);
				// Wait until the handler is actually running, then EOF stdin while it
				// is still blocked (reply not yet computed or written).
				auto ec = entered.emitCount;
				entered.wait(ec);
				link.closeInput();
				foreach (_; 0 .. 4)
					yield();
				// Now let the handler finish: its reply must still flush during the
				// post-EOF drain rather than being abandoned.
				release.emit();
			}
			catch (Exception)
			{
			}
		});
		runEventLoop();
		outputs = link.outbound.dup;
	}();

	assert(outputs.length == 1, "the in-flight handler's reply must survive stdin EOF");
	auto resp = parseJsonString(outputs[0]);
	assert(resp["id"].get!int == 1);
	assert(resp["result"]["content"][0]["text"].get!string == "late");
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
	auto s = McpServer.stateful("logsrv", "1.0");
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
	import mcp.protocol.modern : MetaKey;

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

unittest  // a pre-draft (no protocolVersion) subscriptions/listen is method-not-found on the normal request/reply path over stdio
{
	// `subscriptions/listen` is a draft-only RPC. The genuine draft stdio listen
	// stream is served before route() by tryServeStdioListen; a request carrying no
	// (or a non-draft) protocol version is not a draft listen, so it falls through
	// to the normal request/reply path where the non-draft negotiated session
	// reports the method as -32601 rather than answering {acknowledged:true}.
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
	assert(resp["error"]["code"].get!int == -32601);
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

	auto s = McpServer.stateful("e2e-sample", "1.0");
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
