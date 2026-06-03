module mcp.transport.duplex;

import core.time : Duration, seconds;

import vibe.core.core : runTask;
import vibe.core.sync : TaskMutex;
import vibe.data.json : Json;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.transport.coordinator : DuplexCoordinator;

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
///     or server's inbound dispatcher), which a peer typically runs in its own
///     task so multiple inbound requests are handled concurrently.
///
/// The read loop is a plain cooperative vibe task over an async `readLine`
/// delegate — there is NO dedicated OS reader thread, so there is no OS-thread ⇄
/// event-loop seam to race on. All writes go through one `TaskMutex` so two tasks
/// emitting at once cannot interleave bytes of different frames on the wire (the
/// stdio transport requires each message to be a single newline-delimited line).
///
/// Construct it with three async delegates supplied by the concrete transport:
/// `readLine` (returns the next line without its terminator, or `null` at
/// end-of-input), `writeLine` (emits one line; the delegate appends the
/// terminator), and `onInbound` (dispatches an inbound request/notification).
final class DuplexChannel
{
	private string delegate() @safe readLineDg;
	private void delegate(string) @safe writeLineDg;
	private void delegate(Message) @safe onInbound;
	private void delegate(string) @safe onInboundBatch;
	private DuplexCoordinator coord;
	private TaskMutex writeMutex;
	private bool closed_;

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
	}

	/// Start the cooperative read loop as a vibe task. Requires a running event
	/// loop (`runEventLoop`).
	void start() @safe
	{
		runTask(&readLoop);
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
		for (;;)
		{
			string line;
			bool eof;
			try
				line = readLineDg();
			catch (Exception)
				eof = true; // a read error is treated as end-of-input
			if (eof || line is null)
				break;
			if (line.length == 0)
				continue; // blank line, ignore
			try
				handleLine(line);
			catch (Exception)
			{
				// One malformed/erroring line must not kill the loop; skip it.
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

	private void handleLine(string line) @safe
	{
		// One inbound line is either a single JSON-RPC message or a 2024-11-05 /
		// 2025-03-26 batch array; `parseAny` classifies both.
		ParsedInput input;
		try
			input = parseAny(line);
		catch (McpException e)
		{
			// A malformed/invalid line has no recoverable id, so reply with a
			// null-id JSON-RPC error rather than dropping it silently.
			send(makeErrorResponse(Json(null), e));
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
			if (onInbound !is null)
				onInbound(m);
			break;
		}
	}

	/// Send a request whose id was already chosen by the caller (the CLIENT path:
	/// `McpClient` pre-allocates the id), and block the current task until the
	/// correlated reply arrives. Returns its result, or throws `McpException` on an
	/// error reply / timeout / channel close.
	Json deliver(Json message, long expectId, Duration timeout = 60.seconds) @safe
	{
		if (closed_)
			throw internalError("stdio channel closed");
		coord.register(expectId);
		try
			send(message);
		catch (Exception e)
		{
			coord.cancel(expectId);
			throw e;
		}
		return coord.await(expectId, timeout);
	}

	/// Originate a server->client request (the SERVER path: sampling / elicitation
	/// / roots / ping), allocating a fresh id, and block until the peer replies.
	/// Returns its result, or throws `McpException` on an error reply / timeout /
	/// channel close.
	Json request(string method, Json params, Duration timeout = 60.seconds) @safe
	{
		if (closed_)
			throw internalError("stdio channel closed");
		const id = coord.alloc();
		coord.register(id);
		Json req = makeRequest(Json(id), method, params);
		try
			send(req);
		catch (Exception e)
		{
			coord.cancel(id);
			throw e;
		}
		return coord.await(id, timeout);
	}

	/// Write one JSON-RPC `message` as a single newline-delimited line, serialized
	/// against concurrent writers. `Json.toString` never emits a raw newline, so the
	/// line framing holds and only a valid MCP message is written.
	void send(Json message) @safe
	{
		sendRaw(message.toString());
	}

	/// Write an already-serialized JSON-RPC line as a single newline-delimited line,
	/// serialized against concurrent writers. Used by callers that already hold the
	/// serialized text (the stdio server sink and reply path) so the line is not
	/// parsed back to `Json` only to be re-serialized. The caller is responsible for
	/// the text being one valid MCP message with no embedded newline.
	void sendRaw(string text) @safe
	{
		writeMutex.lock();
		scope (exit)
			writeMutex.unlock();
		writeLineDg(text);
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
	/// timeout; any request issued after this point also fails fast. The owning
	/// transport still closes the underlying byte stream to stop the read loop;
	/// `close` is idempotent and the read loop's own EOF path is equivalent.
	void close() @safe
	{
		if (closed_)
			return;
		closed_ = true;
		coord.failPending(internalError("stdio channel closed"));
	}
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
			() @trusted { evt.wait(ec); }();
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
					auto r = channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1);
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
					auto r = channel.deliver(makeRequest(Json(2L), "ping", Json.emptyObject), 2);
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
				() @trusted { done.wait(ec); }();
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
				channel.deliver(makeRequest(Json(1L), "ping", Json.emptyObject), 1);
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
				channel.request("ping", Json.emptyObject);
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
