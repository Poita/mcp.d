module mcp.transport.duplex;

import core.time : Duration, seconds;

import vibe.core.core : runTask;
import vibe.core.sync : TaskMutex;
import vibe.core.task : Task;
import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.server.context : CancellationToken, CancelRegistration;
import mcp.transport.coordinator : DuplexCoordinator, cancelledNotification;

@safe:

/// A generous default upper bound (16 MiB) on a single inbound JSON-RPC line for
/// the stdio transport, guarding against unbounded line accumulation: a peer that
/// never sends a newline would otherwise grow the read accumulator without limit
/// (a memory-exhaustion DoS). `runStdio` and `spawnStdioTransport` accept an
/// override; pass `size_t.max` to effectively disable the bound.
enum size_t defaultMaxLineBytes = 16 * 1024 * 1024;

/// The shared full-duplex core of the MCP **stdio** transport, used by BOTH the
/// client and the server. The stdio transport is a single newline-delimited
/// JSON-RPC byte stream carrying traffic in both directions at once
/// (basic/transports §stdio), so concurrency is structured as one cooperative
/// vibe read-loop task that demultiplexes inbound lines, plus a serialized
/// writer:
///
///   - a *response* / *errorResponse* line resolves the matching outbound request
///     in the shared `DuplexCoordinator`, waking whichever task is blocked in
///     `await` (so several requests can be in flight concurrently and replies may
///     arrive out of order);
///   - a *request* / *notification* line is handed to `onInbound` (the client's
///     or server's inbound dispatcher) on its own task, so a handler that blocks
///     never stalls the read loop and inbound requests run concurrently.
///
/// The read loop is a plain cooperative vibe task over an async `readLine`
/// delegate — there is NO dedicated OS reader thread, so there is no OS-thread ⇄
/// event-loop seam to race on. All writes go through one `TaskMutex` so two tasks
/// emitting at once cannot interleave bytes of different frames on the wire (the
/// stdio transport requires each message to be a single newline-delimited line).
///
/// Construct it with async delegates supplied by the concrete transport:
/// `readLine` (returns the next line without its terminator, or `null` at
/// end-of-input), `writeLine` (emits one line; the delegate appends the
/// terminator), `onInbound` (dispatches an inbound request/notification), and
/// optionally `onInboundBatch` (dispatches an inbound batch line whole, as the
/// server does; without it a batch is split into its members).
final class DuplexChannel
{
	private string delegate() @safe readLineDg;
	private void delegate(string) @safe writeLineDg;
	private void delegate(Message) @safe onInbound;
	private void delegate(string) @safe onInboundBatch;
	private DuplexCoordinator coord;
	private TaskMutex writeMutex;
	// The lines `deliver` has handed to its writer tasks and not yet written,
	// keyed by request id, so `abort` can withdraw one.
	private PendingWrite[long] pendingWrites_;
	private bool closed_;
	// Set by `close`: nothing more is written.
	private bool shut_;
	// How many lines are being written right now (0 or 1: writes are serialized).
	private size_t writing_;
	// The task performing the write in progress, so `interruptWrite` can end it.
	private Task writer_;
	private Task readTask_;
	// The task running the read loop while it runs, however it was started.
	private Task readingTask_;
	// Set by `stopReadLoop` and `close`: the read loop exits at its next
	// iteration and a read it was interrupted out of is not reported as a failure.
	private bool stopping_;
	// Tasks running inbound notification handlers, and the notifications waiting
	// for one (see `maxNotificationTasks`).
	private size_t notificationTasks_;
	private Message[] notificationBacklog_;
	// Tasks running inbound request handlers, and the requests waiting for one
	// (see `maxRequestTasks`).
	private size_t requestTasks_;
	private Message[] requestBacklog_;
	private PostQueue posts_;

	/// Receives a description of each failure the read loop survives or ends on
	/// (an unreadable input, a line whose handling threw). Defaults to stderr, the
	/// stdio transport's logging channel, when null; stderr is written on a thread
	/// of its own, so a host not reading it cannot stall the event loop (past 256
	/// waiting lines, further ones are dropped and counted). It is called on the
	/// event loop, so a delegate set here must not block.
	void delegate(string) @safe nothrow onError;

	/// Whether an inbound line that is not a valid JSON-RPC message, and carries
	/// no id to answer under, is answered with a null-id JSON-RPC error. The
	/// server's inbound path sets this, as JSON-RPC asks of a server. A client
	/// leaves it unset: such a line (a banner a server prints on stdout, say) is
	/// reported to `onError` instead, since writing an error into the server's
	/// stdin would only add a second malformed exchange.
	bool answersMalformed;

	/// The most inbound notifications handled at once (`0`: unbounded), so a
	/// peer cannot spawn handler tasks without bound. Up to this many more wait,
	/// in arrival order, for a running one to finish; a `list_changed`
	/// notification already waiting absorbs a later one of the same kind, and
	/// one arriving while the wait list is full is dropped and reported to
	/// `onError`. `notifications/cancelled` is never held back.
	size_t maxNotificationTasks = 64;

	/// The most inbound requests handled at once (`0`: unbounded), so a peer
	/// cannot spawn handler tasks without bound (a server flooding a client with
	/// elicitation or sampling requests, say). Up to this many more wait, in
	/// arrival order, for a running one to finish, and a `notifications/cancelled`
	/// naming one withdraws it unanswered; one arriving while the wait list is
	/// full is answered with a -32603 error. A transport that admits requests
	/// itself (the stdio server, under `StdioOptions.maxInFlight`) sets `0`.
	size_t maxRequestTasks = 64;

	/// The most posted lines (error replies to malformed input, teardown
	/// `notifications/cancelled`) held waiting for the peer to read at once
	/// (`0`: unbounded). Past it a posted line is dropped and reported to
	/// `onError`, so a peer that floods input while not reading its own cannot
	/// park writer tasks without bound.
	@property size_t maxPostedWrites() const @safe nothrow
	{
		return posts_.cap;
	}

	/// ditto
	@property void maxPostedWrites(size_t cap) @safe nothrow
	{
		posts_.cap = cap;
	}

	/// Report `msg` to `onError`, or to stderr when it is null.
	void reportError(string msg) @safe nothrow
	{
		if (onError !is null)
		{
			onError(msg);
			return;
		}
		stderrLog.put("[mcp.transport.duplex] " ~ msg);
	}

	/// `readLine` returns the next inbound line (without terminator) or `null` at
	/// EOF (and the read loop ends). `writeLine` emits one outbound line. `onInbound`
	/// is invoked for every inbound request / notification line (never for a
	/// response, which the channel correlates itself).
	this(string delegate() @safe readLine, void delegate(string) @safe writeLine,
			void delegate(Message) @safe onInbound) @safe
	{
		this(readLine, writeLine, onInbound, null);
	}

	/// As the three-argument constructor, but with `onInboundBatch`: an optional
	/// handler for an inbound JSON-RPC batch *array* line, given the line's raw text.
	/// The SERVER inbound path supplies this so a batch is dispatched as a whole
	/// through `server.handleRaw` — preserving the protocol-version batch gate and
	/// the single JSON-array response framing that JSON-RPC 2.0 requires. When it is
	/// `null` (the CLIENT read path) a batch line is split into its members and each
	/// is routed individually, so per-id response correlation still works.
	this(string delegate() @safe readLine, void delegate(string) @safe writeLine,
			void delegate(Message) @safe onInbound, void delegate(string) @safe onInboundBatch) @safe
	{
		this.readLineDg = readLine;
		this.writeLineDg = writeLine;
		this.onInbound = onInbound;
		this.onInboundBatch = onInboundBatch;
		this.coord = new DuplexCoordinator;
		this.writeMutex = new TaskMutex;
		this.posts_ = new PostQueue((string text) @safe {
			this.writeLine(text, null);
		}, 64, (string) @safe nothrow{
			reportError("dropped an outbound message: " ~ intToString(
				posts_.cap) ~ " writes are already waiting for the peer to read");
		});
	}

	/// Start the cooperative read loop as a vibe task. Requires a running event
	/// loop (`runEventLoop`).
	void start() @safe
	{
		readTask_ = runTask(&readLoop);
	}

	/// Whether the read loop started by `start` is still running.
	bool readLoopRunning() const @safe nothrow
	{
		return readTask_.running;
	}

	/// End the read loop started by `start` and wait for it to exit, so the
	/// transport can release the byte stream the loop reads without racing it.
	/// The loop gets `grace` to reach end-of-input by itself; a read still
	/// pending after that is interrupted. Returns false only when called from
	/// the read loop itself, which cannot wait for its own exit.
	bool stopReadLoop(Duration grace) @safe
	{
		import core.time : msecs;
		import std.datetime.stopwatch : StopWatch, AutoStart;
		import vibe.core.core : sleep;
		import vibe.core.task : Task;

		if (!readTask_.running)
			return true;
		if (readTask_ == Task.getThis())
			return false;
		stopping_ = true;
		auto sw = StopWatch(AutoStart.yes);
		while (readTask_.running && sw.peek < grace)
			sleep(1.msecs);
		if (readTask_.running)
			readTask_.interrupt();
		readTask_.joinUninterruptible();
		return true;
	}

	/// Whether `stopReadLoop` or `close` is ending the read loop. A `readLine` that keeps
	/// consuming input without completing a line (a peer flooding an over-long
	/// one) checks it to give up and return null.
	bool stopping() const @safe nothrow
	{
		return stopping_;
	}

	/// Run the read loop inline on the current task (does not spawn a task).
	/// `runStdio`/`serveStdio` call this so the server's main task IS the read
	/// loop and the function blocks until stdin reaches EOF.
	void runReadLoop() @safe
	{
		readLoop();
	}

	private void readLoop() @safe nothrow
	{
		readingTask_ = Task.getThis();
		scope (exit)
			readingTask_ = Task.init;
		while (!stopping_)
		{
			string line;
			try
				line = readLineDg();
			catch (Exception e)
			{
				// An unreadable input cannot recover, so the loop ends as at
				// end-of-input, but the failure is reported rather than hidden.
				if (!stopping_)
					reportError("readLoop: read failed: " ~ e.msg);
				break;
			}
			if (line is null || stopping_)
				break;
			if (isBlankLine(line))
				continue;
			try
				handleLine(line);
			catch (Exception e)
			{
				// One malformed/erroring line must not kill the loop; report the failure
				// so it is visible rather than silently discarded, then continue.
				reportError("readLoop: " ~ e.msg);
			}
		}
		closed_ = true;
		// Wake every still-pending request so awaiting callers get an exception
		// instead of hanging until their timeout.
		try
			coord.failPending(internalError("stdio channel closed before the peer responded"));
		catch (Exception)
		{
		}
	}

	/// Whether `line` holds only JSON whitespace (space, tab, CR, LF), which
	/// carries no message and is skipped rather than answered as malformed.
	private static bool isBlankLine(string line) @safe pure nothrow @nogc
	{
		foreach (c; line)
			if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
				return false;
		return true;
	}

	private void handleLine(string line) @safe
	{
		// One inbound line is either a single JSON-RPC message or a 2024-11-05 /
		// 2025-03-26 batch array; `parseAny` classifies both.
		ParsedInput input;
		try
			input = parseAny(line);
		catch (McpException e)
		{
			Json item;
			try
				item = parseJsonBounded(line);
			catch (Exception)
			{
			}
			answerMalformed(item, e);
			return;
		}
		// A batch array on the server inbound path must be dispatched as a unit so the
		// negotiated-version batch gate and the single JSON-array response framing
		// apply; splitting it into members would bypass both. The client read path
		// (no batch handler) instead routes each member individually, since responses
		// are correlated one-by-one by id.
		if (input.isBatch && onInboundBatch !is null)
		{
			onInboundBatch(line);
			return;
		}
		foreach (m; input.messages)
			routeMessage(m);
		foreach (e; input.errors)
			answerMalformed(e.item, e.error);
	}

	/// Answer an inbound message `item` that failed validation with `error`. A
	/// malformed request is answered under its own id. Anything else carrying
	/// the id of a pending outbound request wakes that waiter with `error`, so
	/// the caller fails fast instead of blocking until its timeout. Otherwise
	/// the peer gets a null-id JSON-RPC error when `answersMalformed` is set, and
	/// the line is reported to `onError` when it is not. Replies are posted, so
	/// the read loop never waits on a peer that has stopped reading.
	private void answerMalformed(Json item, McpException error) @safe
	{
		const replyId = errorReplyId(error);
		if (replyId.type != Json.Type.null_)
		{
			post(makeErrorResponse(replyId, error));
			return;
		}
		Json id = (item.type == Json.Type.object && "id" in item) ? item["id"] : Json(null);
		if (id.type != Json.Type.null_ && id.type != Json.Type.undefined
				&& coord.resolve(id, Json.undefined, toErrorJson(error)))
			return;
		if (answersMalformed)
			post(makeErrorResponse(Json(null), error));
		else
			reportError("malformed message from the peer: " ~ error.msg);
	}

	/// Wake the outbound request that `reply` (a response or error response)
	/// answers. A batch handed to `onInboundBatch` passes its reply members here,
	/// since the handler dispatches requests and notifications only.
	void resolveReply(Message reply) @safe
	{
		if (reply.kind == MessageKind.response)
			coord.resolve(reply.id, reply.result, Json.undefined);
		else if (reply.kind == MessageKind.errorResponse)
			coord.resolve(reply.id, Json.undefined, reply.error);
	}

	private void routeMessage(Message m) @safe
	{
		final switch (m.kind)
		{
		case MessageKind.response:
			coord.resolve(m.id, m.result, Json.undefined);
			break;
		case MessageKind.errorResponse:
			coord.resolve(m.id, Json.undefined, m.error);
			break;
		case MessageKind.request:
		case MessageKind.notification:
			// Request/notification is the sole `onInbound` entry point: responses and
			// error responses are always correlated by the coordinator above and never
			// reach the delegate.
			if (onInbound !is null)
				dispatchInbound(m);
			break;
		}
	}

	/// Run `onInbound` for `m` on its own task so a handler that blocks — on user
	/// work, or on a reply to a request it sends back over this channel — never
	/// stalls the read loop that must deliver that reply. `runTask` switches to the
	/// new task immediately, so a handler that does not block runs to completion
	/// before the next line is read and arrival order is preserved (e.g.
	/// `notifications/initialized` is handled before the request that follows it).
	private void dispatchInbound(Message m) @safe
	{
		if (m.kind == MessageKind.request)
		{
			dispatchRequest(m);
			return;
		}
		if (m.method != "notifications/cancelled")
		{
			dispatchNotification(m);
			return;
		}
		withdrawRequest(m.params);
		runTask((Message msg) nothrow{ runInbound(msg); }, m);
	}

	/// Run request `m` on a task of its own when fewer than `maxRequestTasks`
	/// are running, else queue it, or refuse it when the queue is full.
	private void dispatchRequest(Message m) @safe
	{
		if (maxRequestTasks == 0 || requestTasks_ < maxRequestTasks)
		{
			++requestTasks_;
			runTask((Message first) nothrow{ runRequests(first); }, m);
			return;
		}
		if (requestBacklog_.length < maxRequestTasks)
		{
			requestBacklog_ ~= m;
			return;
		}
		// Posted: this runs on the read loop, which must not wait on a peer that
		// is not reading.
		post(makeErrorResponse(m.id, internalError("busy: " ~ intToString(
				requestTasks_) ~ " requests are in progress and " ~ intToString(
				requestBacklog_.length) ~ " are queued")));
	}

	/// Handle request `first`, then whatever requests are waiting, on the
	/// current task, which holds one request slot until it returns.
	private void runRequests(Message first) @safe nothrow
	{
		scope (exit)
			--requestTasks_;
		for (auto m = first;;)
		{
			runInbound(m);
			if (requestBacklog_.length == 0)
				break;
			m = requestBacklog_[0];
			requestBacklog_ = requestBacklog_[1 .. $];
		}
	}

	/// Drop the queued request a `notifications/cancelled` with `params` names:
	/// it has not started, so it is never run and, per the cancellation rules,
	/// gets no reply.
	private void withdrawRequest(Json params) @safe
	{
		if (requestBacklog_.length == 0 || params.type != Json.Type.object || "requestId" !in params)
			return;
		const id = params["requestId"];
		foreach (i, q; requestBacklog_)
			if (q.id == id)
			{
				requestBacklog_ = requestBacklog_[0 .. i] ~ requestBacklog_[i + 1 .. $];
				return;
			}
	}

	private void runInbound(Message m) @safe nothrow
	{
		try
			onInbound(m);
		catch (Exception e)
			reportError("inbound handler: " ~ e.msg);
	}

	/// Run notification `m` on a task of its own when fewer than
	/// `maxNotificationTasks` are running, else queue, coalesce or drop it.
	private void dispatchNotification(Message m) @safe
	{
		import std.algorithm : any, endsWith;

		const method = m.method;
		if (maxNotificationTasks == 0 || notificationTasks_ < maxNotificationTasks)
		{
			++notificationTasks_;
			runTask((Message first) nothrow{ runNotifications(first); }, m);
			return;
		}
		if (method.endsWith("/list_changed")
				&& notificationBacklog_.any!((ref Message q) => q.method == method))
			return;
		if (notificationBacklog_.length >= maxNotificationTasks)
		{
			reportError("dropped inbound " ~ method ~ ": too many notifications in progress");
			return;
		}
		notificationBacklog_ ~= m;
	}

	/// Handle `first`, then whatever notifications are waiting, on the current
	/// task, which holds one notification slot until it returns.
	private void runNotifications(Message first) @safe nothrow
	{
		scope (exit)
			--notificationTasks_;
		for (auto m = first;;)
		{
			runInbound(m);
			if (notificationBacklog_.length == 0)
				break;
			m = notificationBacklog_[0];
			notificationBacklog_ = notificationBacklog_[1 .. $];
		}
	}

	/// Send a request whose id was already chosen by the caller (the CLIENT path:
	/// `McpClient` pre-allocates the id), and block the current task until the
	/// correlated reply arrives or `timeout` elapses (`Duration.max`: no limit).
	/// Returns its result, or throws `McpException` on an error reply / channel
	/// close, what writing the line threw, or `RequestTimeoutException`.
	///
	/// The line is written on a task of its own while the caller awaits the reply,
	/// so a peer that stops reading parks only that writer: `abort` (a timeout or
	/// cancellation) still releases the caller. Interrupting the write instead
	/// would leave a partial line on the wire and break the framing of every
	/// later message. A line still queued behind another writer when its request
	/// is aborted or times out is never written; one already being written when
	/// it times out is followed by a posted `notifications/cancelled`.
	Json deliver(Json message, long expectId, Duration timeout) @safe
	{
		if (closed_)
			throw internalError("stdio channel closed");
		coord.register(expectId);
		return awaitReply(expectId, startWrite(message, expectId), timeout);
	}

	/// Wait up to `timeout` for the reply to request `id`, whose line `write` is
	/// writing. On a timeout the line is withdrawn if not yet being written, and
	/// otherwise followed by a posted `notifications/cancelled`. A failure is
	/// reported as what writing the line threw, when it threw.
	private Json awaitReply(long id, PendingWrite write, Duration timeout) @safe
	{
		try
			return coord.await(id, timeout);
		catch (RequestTimeoutException e)
		{
			abandon(id, write, "request timed out");
			throw e;
		}
		catch (McpException e)
		{
			if (write.failure !is null)
				throw write.failure;
			throw e;
		}
	}

	/// Write request `id`'s line on a writer task of its own. A write that
	/// fails resolves `id` with the failure.
	private PendingWrite startWrite(Json message, long id) @safe
	{
		auto write = new PendingWrite;
		pendingWrites_[id] = write;
		runTask((Json msg, long id, PendingWrite w) nothrow{
			try
				writeLine(msg.toString(), w);
			catch (Exception e)
			{
				w.failure = e;
				try
					coord.resolve(Json(id), Json.undefined, toErrorJson(internalError(e.msg)));
				catch (Exception)
				{
				}
			}
			if (auto p = id in pendingWrites_)
				if (*p is w)
					pendingWrites_.remove(id);
		}, message, id, write);
		return write;
	}

	/// Wake the task blocked awaiting request `id` with `reason` as its error, as
	/// if the peer had replied with it, and withdraw its line if it is not yet
	/// being written. A later reply for `id` is then ignored. A no-op when `id`
	/// is not pending.
	void abort(long id, McpException reason) @safe
	{
		if (auto w = id in pendingWrites_)
			(*w).abandoned = true;
		coord.resolve(Json(id), Json.undefined, toErrorJson(reason));
	}

	/// Originate a server->client request (the SERVER path: sampling / elicitation
	/// / roots / ping), allocating a fresh id, and block until the peer replies.
	/// Returns its result, or throws `McpException` on an error reply / channel
	/// close, what writing the line threw, or `RequestTimeoutException` after
	/// `timeout`. As in `deliver`, the line is written on a task of its own, so
	/// the timeout also bounds a write the peer does not drain: a line not yet
	/// being written then is withdrawn, and one that was is followed by a posted
	/// `notifications/cancelled`.
	///
	/// `cancellation` is the token of the inbound request this one is made on
	/// behalf of (null: none). Cancelling it ends the wait at once with a
	/// `requestCancelled` error, handled like a timeout: the line is withdrawn
	/// or followed by a posted `notifications/cancelled`.
	Json request(string method, Json params, Duration timeout, CancellationToken cancellation = null) @safe
	{
		if (closed_)
			throw internalError("stdio channel closed");
		const id = coord.alloc();
		coord.register(id);
		auto write = startWrite(makeRequest(Json(id), method, params), id);
		bool settled;
		CancelRegistration onCancelled;
		scope (exit)
		{
			settled = true;
			onCancelled.remove();
		}
		if (cancellation !is null)
			onCancelled = cancellation.onCancel(() @safe nothrow{
				if (settled)
					return;
				abandon(id, write, "the request it serves was cancelled");
				try
					coord.resolve(Json(id), Json.undefined,
						toErrorJson(new McpException(ErrorCode.requestCancelled,
						"request cancelled")));
				catch (Exception)
				{
				}
			});
		return awaitReply(id, write, timeout);
	}

	/// Stop writing request `id`'s line: withdraw it if not yet being written,
	/// else tell the peer with a posted `notifications/cancelled`.
	private void abandon(long id, PendingWrite write, string reason) @safe nothrow
	{
		if (write.abandoned)
			return;
		write.abandoned = true;
		if (write.started)
		{
			try
				post(cancelledNotification(id, reason));
			catch (Exception)
			{
			}
		}
	}

	/// Write one JSON-RPC `message` as a single newline-delimited line, serialized
	/// against concurrent writers. `Json.toString` never emits a raw newline, so the
	/// line framing holds and only a valid MCP message is written.
	void send(Json message) @safe
	{
		sendRaw(message.toString());
	}

	/// `send`, waiting at most `timeout` for the line to be written
	/// (`Duration.max` or a non-positive timeout: no limit). The line is written
	/// on a task of its own, so a peer that stops reading parks only that writer;
	/// past the timeout this throws `RequestTimeoutException`, and a line still
	/// queued behind another writer is never written. One already being written
	/// is left to finish, since interrupting it would break the framing of every
	/// later line.
	void send(Json message, Duration timeout) @safe
	{
		import core.time : MonoTime;
		import vibe.core.sync : LocalManualEvent, createManualEvent;

		if (timeout == Duration.max || timeout <= Duration.zero)
			return send(message);
		if (shut_)
			throw internalError("stdio channel closed");
		// The writer task may outlive this call, so what it signals through
		// lives on the heap rather than in this frame.
		static final class Wait
		{
			PendingWrite write;
			bool finished;
			LocalManualEvent done;
		}

		auto w = new Wait;
		w.write = new PendingWrite;
		w.done = createManualEvent();
		auto write = w.write;
		auto ec = w.done.emitCount;
		runTask((string text, Wait w) nothrow{
			try
				writeLine(text, w.write);
			catch (Exception e)
				w.write.failure = e;
			w.finished = true;
			w.done.emit();
		}, message.toString(), w);
		const deadline = MonoTime.currTime + timeout;
		while (!w.finished)
		{
			const now = MonoTime.currTime;
			if (now >= deadline)
			{
				write.abandoned = true;
				throw new RequestTimeoutException(
						"writing to the peer timed out after " ~ timeout.toString());
			}
			ec = w.done.wait(deadline - now, ec);
		}
		if (write.failure !is null)
			throw write.failure;
	}

	/// Write an already-serialized JSON-RPC line as a single newline-delimited line,
	/// serialized against concurrent writers. Used by callers that already hold the
	/// serialized text (the stdio server sink and reply path) so the line is not
	/// parsed back to `Json` only to be re-serialized. The caller is responsible for
	/// the text being one valid MCP message with no embedded newline.
	void sendRaw(string text) @safe
	{
		writeLine(text, null);
	}

	/// Write `message` on a task of its own and return at once, without waiting
	/// for the line to be written or learning whether it was. For teardown
	/// traffic (a `notifications/cancelled`) that must not park its caller
	/// behind a peer that stopped reading. Nothing is written once the channel
	/// has closed.
	void post(Json message) @safe nothrow
	{
		if (shut_)
			return;
		string text;
		try
			text = message.toString();
		catch (Exception e)
		{
			reportError("post: " ~ e.msg);
			return;
		}
		posts_.post(text);
	}

	/// Wait until every line handed to `post` has been written (or its write has
	/// failed), or `timeout` elapses.
	void awaitPosted(Duration timeout) @safe nothrow
	{
		import core.time : MonoTime;

		posts_.awaitIdle(MonoTime.currTime + timeout);
	}

	/// Whether a line is being written right now. A write the peer does not
	/// drain stays in progress until the peer reads or goes away.
	bool writing() const @safe nothrow
	{
		return writing_ != 0;
	}

	/// End a write in progress by interrupting the task performing it, which then
	/// fails as a write failure. Only for a peer known to be gone: the line may be
	/// left partly written, and an event loop may never report a pipe whose
	/// reader has exited (epoll does not wake a write parked on it), so such a
	/// write would otherwise never end. A no-op when nothing is being written.
	void interruptWrite() @safe nothrow
	{
		if (writing_ != 0 && writer_ != Task.init && writer_.running)
		{
			try
				writer_.interrupt();
			catch (Exception)
			{
			}
		}
	}

	/// Write `text` under the writer lock, unless `write` was abandoned while it
	/// waited for the lock. Throws once `close` has been called, including for a
	/// line that was waiting for the lock then.
	private void writeLine(string text, PendingWrite write) @safe
	{
		if (shut_)
			throw internalError("stdio channel closed");
		writeMutex.lock();
		scope (exit)
			writeMutex.unlock();
		if (shut_)
			throw internalError("stdio channel closed");
		if (write !is null)
		{
			if (write.abandoned)
				return;
			write.started = true;
		}
		++writing_;
		writer_ = Task.getThis();
		scope (exit)
		{
			--writing_;
			writer_ = Task.init;
		}
		try
			writeLineDg(text);
		catch (Exception e)
			throw new ChannelWriteException("writing to the peer failed: " ~ e.msg);
	}

	/// Whether the channel has closed: the read loop ended (EOF or read error) or
	/// `close` was called. Once closed, `deliver`/`request` fail fast instead of
	/// blocking on a reply that can never arrive.
	bool closed() @safe
	{
		return closed_;
	}

	/// Close the channel. Marks it closed and fails every still-pending request so
	/// awaiting callers are released immediately instead of waiting out their
	/// timeout; any request issued after this point also fails fast, and every
	/// send throws. The read loop ends without dispatching another line: it exits
	/// once its pending read returns (the owning transport ends that read by
	/// closing the byte stream, or with `stopReadLoop`). `close` is idempotent.
	void close() @safe
	{
		if (shut_)
			return;
		shut_ = true;
		stopping_ = true;
		closed_ = true;
		coord.failPending(internalError("stdio channel closed"));
	}

	/// Close the channel, as `close` does, and end the read loop now: a read it
	/// is parked in is interrupted rather than left to return the next inbound
	/// line. For a peer known to be gone, such as one whose input pipe broke.
	void closeAndStopReading() @safe
	{
		close();
		if (readingTask_ != Task.init && readingTask_ != Task.getThis())
			readingTask_.interrupt();
	}
}

/// Writes lines on tasks of their own, so the caller never waits on a peer that
/// has stopped reading, with at most `cap` such writes outstanding at once
/// (`0`: unbounded). A line posted past the cap is handed to `onDrop` instead,
/// so a flood cannot park writer tasks without bound. A write that throws is
/// ignored: a posted line carries nothing its sender waits on.
package(mcp) final class PostQueue
{
	import core.time : MonoTime;
	import vibe.core.sync : LocalManualEvent, createManualEvent;

	/// The most writes outstanding at once.
	size_t cap;
	private void delegate(string) @safe write;
	private void delegate(string) @safe nothrow onDrop;
	private size_t pending_;
	private LocalManualEvent finished_;

	this(void delegate(string) @safe write, size_t cap, void delegate(string) @safe nothrow onDrop) @safe nothrow
	{
		this.write = write;
		this.cap = cap;
		this.onDrop = onDrop;
		finished_ = createManualEvent();
	}

	/// Wait until no posted write is outstanding or `deadline` passes.
	void awaitIdle(MonoTime deadline) @safe nothrow
	{
		while (pending_ > 0)
		{
			const now = MonoTime.currTime;
			if (now >= deadline)
				return;
			const ec = finished_.emitCount;
			try
				finished_.wait(deadline - now, ec);
			catch (Exception)
				return;
		}
	}

	/// Write `line` on a task of its own, or drop it when `cap` writes are
	/// already outstanding.
	void post(string line) @safe nothrow
	{
		if (cap != 0 && pending_ >= cap)
		{
			if (onDrop !is null)
				onDrop(line);
			return;
		}
		++pending_;
		runTask((string l) nothrow{
			scope (exit)
			{
				--pending_;
				finished_.emit();
			}
			try
				write(l);
			catch (Exception)
			{
			}
		}, line);
	}

	/// Writes posted and not yet finished.
	size_t pending() const @safe nothrow
	{
		return pending_;
	}
}

/// Writes log lines on a thread of its own, so reporting a failure never waits
/// on the destination: a host that does not drain the process's stderr pipe
/// cannot stall the event loop through it. At most `cap` lines wait to be
/// written; past that a line is counted and dropped, and the count is written
/// once the writer catches up.
package(mcp) final class BackgroundLog
{
	import core.sync.condition : Condition;
	import core.sync.mutex : Mutex;
	import core.thread : Thread;

	private void delegate(string) @safe nothrow write;
	private size_t cap;
	private Mutex mtx;
	private Condition wake;
	private string[] queue;
	private size_t dropped;
	private bool busy; // the writer thread holds lines it has not written yet
	private Thread thread;

	this(void delegate(string) @safe nothrow write, size_t cap) @trusted nothrow
	{
		this.write = write;
		this.cap = cap;
		mtx = new Mutex;
		wake = new Condition(mtx);
	}

	/// Queue `line` for writing, or count it as dropped when `cap` lines are
	/// already waiting. Never waits for a write.
	void put(string line) @trusted nothrow
	{
		mtx.lock_nothrow();
		scope (exit)
			mtx.unlock_nothrow();
		if (queue.length >= cap)
		{
			++dropped;
			return;
		}
		queue ~= line;
		try
		{
			if (thread is null)
			{
				thread = new Thread(&run);
				thread.isDaemon = true;
				thread.start();
			}
			wake.notifyAll();
		}
		catch (Exception)
		{
		}
	}

	/// Wait up to `timeout` for every queued line to be written. Returns whether
	/// they were.
	bool flush(Duration timeout) @trusted nothrow
	{
		import core.time : MonoTime;

		const deadline = MonoTime.currTime + timeout;
		mtx.lock_nothrow();
		scope (exit)
			mtx.unlock_nothrow();
		while (queue.length || dropped || busy)
		{
			const now = MonoTime.currTime;
			if (now >= deadline)
				return false;
			try
				wake.wait(deadline - now);
			catch (Exception)
				return false;
		}
		return true;
	}

	private void run() @trusted nothrow
	{
		for (;;)
		{
			string[] lines;
			size_t lost;
			{
				mtx.lock_nothrow();
				scope (exit)
					mtx.unlock_nothrow();
				busy = false;
				try
				{
					wake.notifyAll();
					while (queue.length == 0 && dropped == 0)
						wake.wait();
				}
				catch (Exception)
				{
					return;
				}
				lines = queue;
				queue = null;
				lost = dropped;
				dropped = 0;
				busy = true;
			}
			foreach (l; lines)
				write(l);
			if (lost)
				write("[mcp] " ~ intToString(lost) ~ " log lines dropped: stderr is not being read");
		}
	}
}

/// The process-wide stderr log behind the stdio transports' default error
/// reporting.
package(mcp) BackgroundLog stderrLog() @trusted nothrow
{
	__gshared BackgroundLog log;

	synchronized
	{
		if (log is null)
			log = new BackgroundLog((string line) @trusted nothrow{
				import std.stdio : stderr;

				try
					stderr.writeln(line);
				catch (Exception)
				{
				}
			}, 256);
	}
	return log;
}

unittest  // BackgroundLog never runs its writer on the reporting thread and drops past its cap
{
	import core.sync.semaphore : Semaphore;
	import core.thread : Thread;

	auto caller = () @trusted { return Thread.getThis(); }();
	auto gate = () @trusted { return new Semaphore(0); }();
	auto entered = () @trusted { return new Semaphore(0); }();
	shared bool onCaller;
	string[] got;
	auto log = new BackgroundLog((string line) @trusted nothrow{
		if (Thread.getThis() is caller)
		{
			onCaller = true;
			return;
		}
		try
		{
			entered.notify();
			gate.wait();
		}
		catch (Exception)
		{
		}
		got ~= line;
	}, 2);
	log.put("first");
	assert(!onCaller, "a report must not wait for its write");
	if (!onCaller)
		() @trusted { entered.wait(); }();
	foreach (_; 0 .. 5)
		log.put("queued");
	foreach (_; 0 .. 8)
		() @trusted { gate.notify(); }();
	assert(log.flush(5.seconds));
	assert(got.length == 4 && got[0] == "first" && got[1] == "queued"
			&& got[2] == "queued", "the first line is written, then the queued ones");
	assert(got[3] == "[mcp] 3 log lines dropped: stderr is not being read", got[3]);
}

private string intToString(size_t n) @safe nothrow
{
	import std.conv : to;

	try
		return n.to!string;
	catch (Exception)
		return "?";
}

/// Thrown by a `DuplexChannel` send when writing the line fails. The byte stream
/// is broken (typically the peer closed its end), so the peer is gone.
class ChannelWriteException : McpException
{
	this(string message) @safe pure nothrow
	{
		super(ErrorCode.internalError, message);
	}
}

/// A request line `DuplexChannel.deliver` handed to its writer task.
private final class PendingWrite
{
	// Set by `abort`: a line not yet being written is dropped.
	bool abandoned;
	// Set once the line's write begins.
	bool started;
	// What writing the line threw, rethrown to the awaiting caller.
	Exception failure;
}

version (unittest)
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, yield;
	import vibe.core.sync : LocalManualEvent, createManualEvent;
}

// A pair of in-memory line queues wiring two DuplexChannels back to back, so a
// test can drive a client channel against a responder without any subprocess.
version (unittest) private final class LineLink
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
			return null; // EOF
		auto s = queue[0];
		queue = queue[1 .. $];
		return s;
	}
}

unittest  // two concurrent deliver() calls get their correct, distinct results even when replied OUT OF ORDER
{
	// Drives the CLIENT-style concurrency acceptance: two requests in flight on
	// two tasks; a responder replies to id 2 before id 1. Each await must wake
	// with ITS own result.
	auto toResponder = new LineLink; // client -> responder
	auto toClient = new LineLink; // responder -> client

	long got1, got2;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				toResponder.put(s);
			}, (Message) @safe {});
			channel.start();

			// A responder task: read both requests, then reply id 2 first, id 1 second.
			runTask(() nothrow{
				try
				{
					auto a = toResponder.take();
					auto b = toResponder.take();
					import vibe.data.json : parseJsonString;

					auto ja = parseJsonString(a);
					auto jb = parseJsonString(b);
					// Reply out of order: second-received first.
					Json r2 = Json.emptyObject;
					r2["jsonrpc"] = "2.0";
					r2["id"] = jb["id"];
					r2["result"] = Json(["v": jb["id"]]);
					toClient.put(r2.toString());
					Json r1 = Json.emptyObject;
					r1["jsonrpc"] = "2.0";
					r1["id"] = ja["id"];
					r1["result"] = Json(["v": ja["id"]]);
					toClient.put(r1.toString());
				}
				catch (Exception)
				{
				}
			});

			// Fire two concurrent deliver() in their own tasks.
			auto done = createManualEvent();
			int remaining = 2;
			runTask(() nothrow{
				try
				{
					auto r = channel.deliver(makeRequest(Json(1L), "ping",
					Json.emptyObject), 1, 60.seconds);
					got1 = r["v"].get!long;
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
					auto r = channel.deliver(makeRequest(Json(2L), "ping",
					Json.emptyObject), 2, 60.seconds);
					got2 = r["v"].get!long;
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
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// Each deliver got its OWN id's result despite the out-of-order reply.
	assert(got1 == 1, "deliver(id=1) must return id 1's result");
	assert(got2 == 2, "deliver(id=2) must return id 2's result");
}

unittest  // inbound notifications run on at most maxNotificationTasks tasks, cancellations always
{
	import std.conv : to;

	auto inbound = new LineLink;
	auto release = createManualEvent();
	size_t running, peak, handled;
	bool cancelSeen;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.method == "notifications/cancelled")
				{
					cancelSeen = true;
					return;
				}
				++running;
				if (running > peak)
					peak = running;
				release.wait(release.emitCount);
				--running;
				++handled;
			});
			channel.maxNotificationTasks = 4;
			channel.onError = (string) @safe nothrow{};
			channel.start();
			foreach (i; 0 .. 6)
				inbound.put(`{"jsonrpc":"2.0","method":"notifications/n` ~ i.to!string ~ `"}`);
			inbound.put(
				`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`);
			foreach (_; 0 .. 16)
				yield();
			assert(peak == 4, "no more than maxNotificationTasks notifications run at once ");
			assert(cancelSeen, "a cancellation is handled while the notification slots are full");
			foreach (_; 0 .. 4)
			{
				release.emit();
				foreach (__; 0 .. 8)
					yield();
			}
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(handled == 6, "queued notifications run once a slot frees up");
}

unittest  // inbound requests run on at most maxRequestTasks tasks, queue as many more and refuse the rest
{
	import std.conv : to;

	auto inbound = new LineLink;
	auto release = createManualEvent();
	size_t running, peak;
	long[] handled;
	string[] written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written ~= s;
			}, (Message m) @safe {
				if (m.kind != MessageKind.request)
					return;
				++running;
				if (running > peak)
					peak = running;
				release.wait(release.emitCount);
				--running;
				handled ~= m.id.get!long;
			});
			channel.maxRequestTasks = 2;
			channel.onError = (string) @safe nothrow{};
			channel.start();
			foreach (i; 1 .. 7)
				inbound.put(
					`{"jsonrpc":"2.0","id":` ~ i.to!string ~ `,"method":"elicitation/create"}`);
			inbound.put(
				`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`);
			foreach (_; 0 .. 32)
				yield();
			assert(peak == 2, "no more than maxRequestTasks requests run at once");
			assert(written.length == 2, "only the requests beyond the queue are answered early");
			foreach (k, w; written)
			{
				auto j = parseJsonString(w);
				assert(j["id"] == Json(5 + cast(long) k) && j["error"]["code"].get!int == -32603);
			}
			foreach (_; 0 .. 4)
			{
				release.emit();
				foreach (__; 0 .. 8)
					yield();
			}
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(handled == [1, 2, 4], "queued requests run once a slot frees up; a cancelled one never");
}

unittest  // queued list_changed notifications of one kind are coalesced
{
	auto inbound = new LineLink;
	auto release = createManualEvent();
	string[] handled;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.method == "notifications/block")
					release.wait(release.emitCount);
				handled ~= m.method;
			});
			channel.maxNotificationTasks = 1;
			channel.start();
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/block"}`);
			foreach (_; 0 .. 5)
				inbound.put(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`);
			foreach (_; 0 .. 16)
				yield();
			release.emit();
			foreach (_; 0 .. 16)
				yield();
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(handled == [
		"notifications/block", "notifications/tools/list_changed"
	], "waiting list_changed notifications of one kind collapse into one");
}

unittest  // an inbound notification line is routed to onInbound (not the coordinator)
{
	auto inbound = new LineLink;
	string seenMethod;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.kind == MessageKind.notification)
					seenMethod = m.method;
			});
			channel.start();
			inbound.put(
				`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(seenMethod == "notifications/message");
}

unittest  // deliver() throws when the channel reaches EOF before the response (failPending)
{
	auto toClient = new LineLink;
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string) @safe {
			}, (Message) @safe {});
			channel.start();
			// Close the inbound end so the read loop hits EOF and fails pending.
			runTask(() nothrow{
				try
				{
					foreach (_; 0 .. 2)
						yield();
					toClient.closeEnd();
				}
				catch (Exception)
				{
				}
			});
			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 60.seconds);
			catch (McpException)
				threw = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "deliver must throw once the channel closes with no response");
}

unittest  // a malformed inbound line does not kill the read loop
{
	auto inbound = new LineLink;
	int seen;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.kind == MessageKind.notification)
					seen++;
			});
			channel.onError = (string) @safe nothrow{};
			channel.start();
			inbound.put("this is not json");
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/a"}`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	// The good notification after the garbage line was still dispatched.
	assert(seen == 1);
}

unittest  // an inbound request with by-position params is answered with -32602 carrying its id
{
	import vibe.data.json : parseJsonString;

	auto inbound = new LineLink;
	string[] written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written ~= s;
			}, (Message) @safe {});
			channel.start();
			inbound.put(`{"jsonrpc":"2.0","id":3,"method":"ping","params":[]}`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(written.length == 1);
	auto j = parseJsonString(written[0]);
	assert(j["error"]["code"].get!int == ErrorCode.invalidParams);
	assert(j["id"] == Json(3));
}

unittest  // an inbound batch array routes every contained request/notification to onInbound
{
	auto inbound = new LineLink;
	int requests;
	int notifications;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.kind == MessageKind.request)
					requests++;
				else if (m.kind == MessageKind.notification)
					notifications++;
			});
			channel.start();
			inbound.put(`[{"jsonrpc":"2.0","id":1,"method":"ping"},`
				~ `{"jsonrpc":"2.0","method":"notifications/initialized"},`
				~ `{"jsonrpc":"2.0","id":2,"method":"ping"}]`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	// Both batched requests and the batched notification were dispatched, not dropped.
	assert(requests == 2);
	assert(notifications == 1);
}

unittest  // when a batch handler is installed (server path) a batch line is routed WHOLE, not split
{
	// The server inbound path supplies onInboundBatch so the whole batch reaches
	// server.handleRaw (version gate + single-array framing) instead of being split
	// into per-member onInbound calls that would bypass both.
	auto inbound = new LineLink;
	int members;
	string wholeRaw;
	enum batch = `[{"jsonrpc":"2.0","id":1,"method":"ping"},`
		~ `{"jsonrpc":"2.0","id":2,"method":"ping"}]`;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message) @safe { members++; }, (string raw) @safe {
				wholeRaw = raw;
			});
			channel.start();
			inbound.put(batch);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	// The per-member dispatcher was never called; the raw batch was handed over whole.
	assert(members == 0, "a batch must not be split when a batch handler is installed");
	assert(wholeRaw == batch, "the batch handler must receive the whole raw line");
}

version (Posix) unittest  // an exception thrown by the onInbound notification handler is logged to stderr, not silently swallowed
{
	// Guarded to POSIX: the test captures stderr by redirecting its file descriptor
	// via pipe()/dup2(), which has no portable Windows equivalent. The behaviour
	// under test (a throwing notification handler logs to stderr and the read loop
	// continues) is itself platform-independent.
	// When the synchronous onInbound delegate throws for a notification (e.g.
	// a notifications/cancelled handler encountering an unexpected requestId type),
	// the exception must produce a diagnostic on stderr so the failure is visible;
	// silent swallowing makes notification-handler bugs completely invisible at runtime.
	// This test also verifies the read loop continues after the throwing notification
	// so a subsequent valid notification is still dispatched.
	import core.sys.posix.unistd : pipe, close, read;
	import core.sys.posix.fcntl : fcntl, F_SETFL, O_NONBLOCK;

	int[2] errPipe;
	assert(pipe(errPipe) == 0, "pipe() failed");
	scope (exit)
		close(errPipe[0]);

	// Save the real stderr fd and redirect stderr to the write end of the pipe.
	import std.stdio : stderr;

	const stderrFd = () @trusted { return stderr.fileno(); }();
	const savedStderrFd = () {
		import core.sys.posix.unistd : dup;

		return dup(stderrFd);
	}();
	scope (exit)
	{
		() @trusted {
			import core.sys.posix.unistd : dup2;

			stderr.flush();
			dup2(savedStderrFd, stderrFd);
			close(savedStderrFd);
		}();
	}
	{
		import core.sys.posix.unistd : dup2;

		dup2(errPipe[1], stderrFd);
		close(errPipe[1]);
	}

	auto inbound = new LineLink;
	int goodSeen;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe {
				if (m.method == "notifications/bad")
					throw new Exception("notification handler error: unexpected requestId type");
				if (m.kind == MessageKind.notification)
					goodSeen++;
			});
			channel.start();
			// A notification whose handler throws.
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/bad"}`);
			// A well-formed notification that must still be dispatched after the error.
			inbound.put(
				`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`);
			inbound.closeEnd();
			foreach (_; 0 .. 12)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// Flush stderr (now pointing at the pipe) and read what was written to the pipe.
	assert(stderrLog.flush(5.seconds));
	() @trusted { stderr.flush(); }();
	// Make the read end non-blocking so we don't hang if nothing was written.
	() @trusted { fcntl(errPipe[0], F_SETFL, O_NONBLOCK); }();
	char[4096] buf;
	const n = () @trusted { return read(errPipe[0], buf.ptr, buf.length); }();
	const stderrOut = n > 0 ? () @trusted { return cast(string) buf[0 .. n].dup; }() : "";

	// The good notification after the throwing one must still reach onInbound.
	assert(goodSeen == 1, "read loop must continue and dispatch subsequent notifications");
	// The thrown exception must produce a diagnostic on stderr, not be silently discarded.
	assert(stderrOut.length > 0, "a notification handler exception must be logged to stderr");
}

unittest  // a malformed inbound line is answered with a null-id JSON-RPC error instead of silence
{
	auto inbound = new LineLink;
	string written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written = s;
			}, (Message) @safe {});
			channel.answersMalformed = true;
			channel.start();
			inbound.put("this is not json");
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	import vibe.data.json : parseJsonString;

	assert(written.length, "a malformed line must produce an error reply");
	auto j = parseJsonString(written);
	assert(j["jsonrpc"].get!string == "2.0");
	assert(j["id"].type == Json.Type.null_);
	assert("error" in j);
}

unittest  // a whitespace-only inbound line is ignored like a blank one, not answered as malformed
{
	auto inbound = new LineLink;
	string written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written ~= s;
			}, (Message) @safe {});
			channel.answersMalformed = true;
			channel.start();
			inbound.put("   ");
			inbound.put("\t\r");
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(written.length == 0, written);
}

unittest  // answering a malformed line does not stall the read loop behind a peer that stopped reading
{
	auto inbound = new LineLink;
	auto never = createManualEvent();
	int seen;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
				never.wait(never.emitCount); // the peer never drains its input
			}, (Message m) @safe {
				if (m.kind == MessageKind.notification)
					seen++;
			});
			channel.answersMalformed = true;
			channel.start();
			inbound.put("this is not json");
			inbound.put(`{"jsonrpc":"2.0","id":4,"method":"ping","params":[]}`);
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/a"}`);
			foreach (_; 0 .. 16)
				yield();
			channel.close();
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(seen == 1, "lines after a malformed one are still read while its reply is unwritten");
}

unittest  // PostQueue holds at most cap writes outstanding and drops the rest
{
	auto never = createManualEvent();
	string[] dropped;
	size_t pendingAfter;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		auto q = new PostQueue((string) @safe { never.wait(never.emitCount); },
			3, (string l) @safe nothrow{ dropped ~= l; });
		foreach (i; 0 .. 5)
			q.post(i == 3 ? "d" : i == 4 ? "e" : "x");
		pendingAfter = q.pending;
		never.emit();
	});
	runEventLoop();
	assert(pendingAfter == 3);
	assert(dropped == ["d", "e"]);
}

unittest  // PostQueue frees a slot once a write finishes
{
	string[] written;
	string[] dropped;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		auto q = new PostQueue((string l) @safe { written ~= l; }, 1, (string l) @safe nothrow{
			dropped ~= l;
		});
		// runTask starts each writer at once, so a write that does not block
		// finishes before `post` returns.
		q.post("a");
		q.post("b");
		q.post("c");
	});
	runEventLoop();
	assert(written == ["a", "b", "c"]);
	assert(dropped.length == 0);
}

unittest  // replies to malformed lines waiting on a peer that stopped reading are bounded
{
	import std.algorithm : canFind, count;

	auto inbound = new LineLink;
	auto never = createManualEvent();
	string[] errors;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
				never.wait(never.emitCount); // the peer never drains its input
			}, (Message) @safe {});
			channel.answersMalformed = true;
			channel.onError = (string msg) @safe nothrow{ errors ~= msg; };
			channel.start();
			foreach (_; 0 .. 200)
				inbound.put("this is not json");
			foreach (_; 0 .. 16)
				yield();
			channel.close();
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(errors.count!(e => e.canFind("dropped")) == 200 - 64,
			"past the cap a reply is dropped and reported rather than parked");
}

unittest  // a channel not answering malformed lines reports an unparseable line without replying
{
	auto inbound = new LineLink;
	string[] written;
	string[] errors;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written ~= s;
			}, (Message) @safe {});
			channel.onError = (string msg) @safe nothrow{ errors ~= msg; };
			channel.start();
			inbound.put("server v1.2 starting up");
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(written.length == 0, "nothing is written back for an unparseable line");
	assert(errors.length == 1, "the unparseable line is reported");
}

unittest  // a failing writeLine propagates out of request() instead of being swallowed
{
	// Mirrors the stdio write path surfacing a broken pipe: when the writer throws
	// (the peer closed its read end), the originating server->client request must
	// observe the failure rather than block on a reply that can never arrive.
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			string delegate() @safe nullRead = () @safe {
				return cast(string) null;
			};
			auto channel = new DuplexChannel(nullRead, (string) @safe {
				throw new Exception("stdout write failed (peer closed its read end)");
			}, (Message) @safe {});
			try
				channel.request("ping", Json.emptyObject, 30.seconds);
			catch (Exception)
				threw = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "a failed write must surface to the request() caller");
}

unittest  // request() issued after the read loop closed fails fast instead of blocking for the timeout
{
	auto toClient = new LineLink;
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string) @safe {
			}, (Message) @safe {});
			channel.start();
			// Let the read loop reach EOF and mark the channel closed.
			toClient.closeEnd();
			foreach (_; 0 .. 4)
				yield();
			// A generous timeout would be paid in full if the guard were missing.
			try
				channel.request("ping", Json.emptyObject, 30.seconds);
			catch (McpException)
				threw = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "request() after close must fail fast, not wait out the timeout");
}

unittest  // close() wakes a pending deliver() and is idempotent
{
	auto toClient = new LineLink;
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string) @safe {
			}, (Message) @safe {});
			// No read loop is started; close() must wake the pending deliver itself.
			runTask(() nothrow{
				try
				{
					foreach (_; 0 .. 2)
						yield();
					channel.close();
					channel.close(); // idempotent: a second call is a no-op
				}
				catch (Exception)
				{
				}
			});
			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 30.seconds);
			catch (McpException)
				threw = true;
			assert(channel.closed(), "closed() must report true after close()");
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "close() must wake a pending deliver() with a channel-closed error");
}

unittest  // sendRaw() writes the already-serialized line verbatim, without a parse+reserialize round-trip
{
	// A line whose byte form is not canonical JSON (extra spaces, distinct key
	// order) must reach the writer EXACTLY as given; a parse->reserialize path would
	// normalize it and change the bytes.
	enum raw = `{"jsonrpc":"2.0",  "id":1,  "method":"ping"}`;
	string written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			string delegate() @safe nullRead = () @safe {
				return cast(string) null;
			};
			auto channel = new DuplexChannel(nullRead, (string s) @safe {
				written = s;
			}, (Message) @safe {});
			channel.sendRaw(raw);
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(written == raw, "sendRaw must write the line verbatim, not re-serialize it");
}

unittest  // a malformed batch member carrying a pending id wakes its deliver() with an error, not a timeout
{
	// Client read path (no batch handler): the peer replies with a batch whose
	// member for the pending id is malformed (both result and error present →
	// -32600). That member lands in input.errors; its id must still wake the
	// awaiting deliver() with the member's error rather than being dropped so the
	// caller blocks until its timeout.
	auto toResponder = new LineLink; // client -> responder
	auto toClient = new LineLink; // responder -> client

	bool threw;
	int errCode;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				toResponder.put(s);
			}, (Message) @safe {});
			channel.start();

			runTask(() nothrow{
				try
				{
					toResponder.take(); // the deliver() request frame
					enum batch = `[{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}},` ~ `{"jsonrpc":"2.0","id":2,"result":{}}]`;
					toClient.put(batch);
				}
				catch (Exception)
				{
				}
			});

			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 5.seconds);
			catch (McpException e)
			{
				threw = true;
				errCode = e.code;
			}
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "a malformed batch member for a pending id must wake its deliver()");
	assert(errCode == ErrorCode.invalidRequest,
			"the waiter must wake with the member's -32600 error, not a -32603 timeout");
}

unittest  // a malformed single-line reply carrying a pending id wakes its deliver() with an error, not a timeout
{
	auto toResponder = new LineLink;
	auto toClient = new LineLink;

	bool threw;
	int errCode;
	string[] extraWrites;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				toResponder.put(s);
			}, (Message) @safe {});
			channel.start();

			runTask(() nothrow{
				try
				{
					toResponder.take(); // the deliver() request frame
					toClient.put(`{"jsonrpc":"2.0","id":1,"error":"boom"}`);
				}
				catch (Exception)
				{
				}
			});

			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 5.seconds);
			catch (McpException e)
			{
				threw = true;
				errCode = e.code;
			}
			extraWrites = toResponder.queue;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "a malformed reply for a pending id must wake its deliver()");
	assert(errCode != ErrorCode.internalError,
			"the waiter must wake with the reply's parse error, not a -32603 timeout");
	assert(extraWrites.length == 0, "a reply resolved locally is not answered back to the peer");
}

unittest  // a malformed batch member with a non-integer (string) id sends a null-id error, not silence
{
	// coord.resolve() returns false for any non-integer id; the else branch must fall
	// back to the null-id error path so the peer is notified rather than dropped.
	auto inbound = new LineLink;
	string written;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				written = s;
			}, (Message) @safe {});
			channel.answersMalformed = true;
			channel.start();
			// A batch where member 0 has a string id and is malformed (both result and error).
			inbound.put(
				`[{"jsonrpc":"2.0","id":"req-abc","result":{},"error":{"code":-1,"message":"x"}}]`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	import vibe.data.json : parseJsonString;

	assert(written.length, "a string-id batch member error must produce a null-id error reply");
	auto j = parseJsonString(written);
	assert(j["id"].type == Json.Type.null_, "the fallback error reply must carry a null id");
	assert("error" in j, "the fallback reply must be an error response");
}

unittest  // deliver() that times out withdraws its line still queued behind another write
{
	import core.time : msecs;

	auto inbound = new LineLink;
	auto release = createManualEvent();
	string[] written;
	bool timedOut;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				if (s == `"block"`)
					release.wait(release.emitCount);
				written ~= s;
			}, (Message) @safe {});
			channel.start();
			runTask(() nothrow{
				try
					channel.sendRaw(`"block"`);
				catch (Exception)
				{
				}
			});
			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 20.msecs);
			catch (RequestTimeoutException)
				timedOut = true;
			release.emit();
			foreach (_; 0 .. 8)
				yield();
			channel.close();
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(timedOut);
	assert(written == [`"block"`], "a timed-out request's queued line is never written");
}

unittest  // deliver() that times out mid-write posts notifications/cancelled for its request
{
	import core.time : msecs;
	import std.algorithm : canFind;

	auto inbound = new LineLink;
	auto release = createManualEvent();
	string[] written;
	bool timedOut;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			bool first = true;
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string s) @safe {
				if (first)
				{
					first = false;
					release.wait(release.emitCount);
				}
				written ~= s;
			}, (Message) @safe {});
			channel.start();
			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 20.msecs);
			catch (RequestTimeoutException)
				timedOut = true;
			release.emit();
			foreach (_; 0 .. 8)
				yield();
			channel.close();
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(timedOut);
	assert(written.length == 2 && written[1].canFind(`"notifications/cancelled"`),
			"the peer is told the request it is receiving was abandoned");
}

unittest  // deliver() after close() fails fast
{
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			string delegate() @safe nullRead = () @safe {
				return cast(string) null;
			};
			auto channel = new DuplexChannel(nullRead, (string) @safe {}, (Message) @safe {
			});
			channel.close();
			try
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1, 30.seconds);
			catch (McpException)
				threw = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw, "deliver() after close() must throw immediately");
}

unittest  // an inbound request handler that calls back into the channel does not stall the read loop
{
	// The handler for an inbound request issues its own outbound request and
	// awaits the reply. That reply arrives on the same read loop, so the handler
	// must run off the read loop or the two wait on each other until the timeout.
	auto toResponder = new LineLink;
	auto toClient = new LineLink;
	bool handlerGotReply;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			DuplexChannel channel;
			channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				toResponder.put(s);
			}, (Message m) @safe {
				if (m.kind != MessageKind.request)
					return;
				auto r = channel.deliver(makeRequest(Json(7L), "ping",
				Json.emptyObject), 7, 2.seconds);
				handlerGotReply = r["ok"].get!bool;
			});
			channel.start();
			toClient.put(`{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage"}`);
			// The peer answers the handler's nested request.
			auto nested = toResponder.take();
			import vibe.data.json : parseJsonString;

			Json reply = Json.emptyObject;
			reply["jsonrpc"] = "2.0";
			reply["id"] = parseJsonString(nested)["id"];
			reply["result"] = Json(["ok": Json(true)]);
			toClient.put(reply.toString());
			foreach (_; 0 .. 16)
				yield();
			toClient.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(handlerGotReply, "a request handler must be able to await a reply read by the same loop");
}

unittest  // an inbound notification handler that blocks does not stall the read loop
{
	auto toResponder = new LineLink;
	auto toClient = new LineLink;
	bool handlerGotReply;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			DuplexChannel channel;
			channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				toResponder.put(s);
			}, (Message m) @safe {
				if (m.kind != MessageKind.notification)
					return;
				auto r = channel.request("roots/list", Json.emptyObject, 2.seconds);
				handlerGotReply = r["ok"].get!bool;
			});
			channel.start();
			toClient.put(`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`);
			auto nested = toResponder.take();
			import vibe.data.json : parseJsonString;

			Json reply = Json.emptyObject;
			reply["jsonrpc"] = "2.0";
			reply["id"] = parseJsonString(nested)["id"];
			reply["result"] = Json(["ok": Json(true)]);
			toClient.put(reply.toString());
			foreach (_; 0 .. 16)
				yield();
			toClient.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(handlerGotReply,
			"a notification handler must be able to await a reply read by the same loop");
}

unittest  // inbound messages whose handlers do not block are handled in arrival order
{
	auto inbound = new LineLink;
	string[] seen;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message m) @safe { seen ~= m.method; });
			channel.start();
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
			inbound.put(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`);
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/b"}`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(seen == [
		"notifications/initialized", "tools/list", "notifications/b"
	]);
}

unittest  // a failed read ends the loop and is reported rather than passed off as EOF
{
	import std.algorithm : canFind;

	auto ch = new DuplexChannel(() @safe {
		throw new Exception("input/output error");
		return "";
	}, (string) @safe {}, (Message) @safe {});
	string[] reported;
	ch.onError = (string msg) @safe nothrow{ reported ~= msg; };
	ch.runReadLoop();
	assert(ch.closed);
	assert(reported.length == 1 && reported[0].canFind("input/output error"));
}

unittest  // an inbound handler's exception is reported through onError
{
	import std.algorithm : canFind;

	auto inbound = new LineLink;
	string[] reported;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto ch = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message) @safe { throw new Exception("handler exploded"); });
			ch.onError = (string msg) @safe nothrow{ reported ~= msg; };
			ch.start();
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/x"}`);
			inbound.closeEnd();
			foreach (_; 0 .. 8)
				yield();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(reported.length == 1 && reported[0].canFind("handler exploded"));
}

unittest  // reaching end-of-input reports nothing
{
	auto ch = new DuplexChannel(() @safe => cast(string) null, (string) @safe {}, (Message) @safe {
	});
	string[] reported;
	ch.onError = (string msg) @safe nothrow{ reported ~= msg; };
	ch.runReadLoop();
	assert(reported.length == 0);
}

unittest  // a timed-out server->client request is followed by notifications/cancelled for its id
{
	import core.time : msecs;
	import vibe.data.json : parseJsonString;

	auto toClient = new LineLink;
	string[] sent;
	bool timedOut;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string s) @safe {
				sent ~= s;
			}, (Message) @safe {});
			channel.start();
			try
				channel.request("elicitation/create", Json.emptyObject, 20.msecs);
			catch (RequestTimeoutException)
				timedOut = true;
			toClient.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(timedOut);
	assert(sent.length == 2, "the timed-out request must be cancelled on the wire");
	const req = parseJsonString(sent[0]);
	const note = parseJsonString(sent[1]);
	assert(note["method"].get!string == "notifications/cancelled");
	assert(note["params"]["requestId"] == req["id"]);
}

unittest  // request() times out on schedule while its line is stalled on a peer that stopped reading
{
	import core.time : msecs, MonoTime;
	import vibe.core.core : sleep;

	auto toClient = new LineLink;
	bool timedOut;
	Duration took;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return toClient.take(); }, (string) @safe {
				sleep(2.seconds);
			}, (Message) @safe {});
			channel.start();
			const start = MonoTime.currTime;
			try
				channel.request("elicitation/create", Json.emptyObject, 100.msecs);
			catch (RequestTimeoutException)
				timedOut = true;
			took = MonoTime.currTime - start;
			sleep(2500.msecs);
			toClient.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(timedOut);
	assert(took < 1.seconds, "a stalled write must not hold request() past its timeout");
}

unittest  // close() ends the read loop: a line arriving afterwards is not dispatched
{
	auto inbound = new LineLink;
	int dispatched;
	bool loopRunning = true;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe { return inbound.take(); }, (string) @safe {
			}, (Message) @safe { dispatched++; });
			channel.start();
			yield();
			channel.close();
			inbound.put(`{"jsonrpc":"2.0","method":"notifications/x"}`);
			foreach (_; 0 .. 8)
				yield();
			loopRunning = channel.readLoopRunning;
			inbound.closeEnd();
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(dispatched == 0, "a closed channel must not dispatch inbound lines");
	assert(!loopRunning, "close() must end the read loop");
}

unittest  // send() and sendRaw() on a closed channel throw instead of writing
{
	string[] written;
	int threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto channel = new DuplexChannel(() @safe => cast(string) null, (string s) @safe {
				written ~= s;
			}, (Message) @safe {});
			channel.close();
			try
				channel.send(Json.emptyObject);
			catch (McpException)
				threw++;
			try
				channel.sendRaw("{}");
			catch (McpException)
				threw++;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(threw == 2, "sends on a closed channel must throw");
	assert(written.length == 0, "a closed channel must write nothing");
}
