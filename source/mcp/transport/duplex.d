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
		this.readLineDg = readLine;
		this.writeLineDg = writeLine;
		this.onInbound = onInbound;
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
		Message m = parseMessage(line);
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
		const text = message.toString();
		writeMutex.lock();
		scope (exit)
			writeMutex.unlock();
		writeLineDg(text);
	}

	/// Whether the read loop has ended (EOF or read error).
	bool closed() @safe
	{
		return closed_;
	}

	/// Release the channel. The owning transport closes the underlying byte stream
	/// (which makes the read loop observe EOF and exit); this is a hook for any
	/// channel-local cleanup and is currently a no-op.
	void close() @safe
	{
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
