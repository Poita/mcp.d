module mcp.transport.coordinator;

import core.time : Duration, seconds;

import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.data.json : Json;

import mcp.protocol.errors;

@safe:

/// Correlates outbound requests with the responses that arrive — possibly out of
/// order — on a *single, shared* duplex channel. This is the waiter-registry
/// pattern generalized out of `mcp.transport.sse_context.StreamCoordinator` (the
/// HTTP server->client correlator) into a transport-agnostic, reusable class: a
/// background reader/demultiplexer classifies each inbound line and routes every
/// response/errorResponse through `resolve(id, ...)`, while each in-flight caller
/// blocks its own task in `await(id)` until its matching reply lands.
///
/// One instance is shared by all concurrent callers on one channel. The stdio
/// **client** transport uses it so two simultaneous `deliver` calls correlate by
/// id (no longer discarding a non-matching response); the stdio **server** can
/// reuse it later for its own server->client request channel. Distinct and
/// deliberately separate from `StreamCoordinator` — that class also owns SSE
/// stream-ordinal allocation and HTTP-specific concerns and must not be disturbed.
///
/// Concurrency model: every method runs on a vibe task within ONE event loop
/// (single-fiber). `register`/`await`/`resolve`/`cancel` therefore execute
/// atomically with respect to each other between cooperative yield points; the
/// only blocking call is `LocalManualEvent.wait` inside `await`, where another
/// task's `resolve` runs and flips the waiter to done. Inbound lines produced by
/// a separate OS reader thread MUST be marshalled onto the event loop (e.g. via a
/// vibe channel consumed by a task) before being handed to `resolve` — the
/// `LocalManualEvent` is loop-local and is not itself cross-thread safe.
final class DuplexCoordinator
{
	private static final class Waiter
	{
		LocalManualEvent evt;
		Json result = Json.undefined;
		Json error = Json.undefined;
		bool done;
	}

	private long counter = 1;
	private Waiter[long] waiters;

	/// Allocate a fresh outbound request id (monotonic, starting at 1).
	long alloc() @safe
	{
		return counter++;
	}

	/// Begin tracking a pending outbound request. Call this BEFORE writing the
	/// request line, so a fast peer cannot resolve the id before the waiter exists.
	void register(long id) @safe
	{
		auto w = new Waiter;
		w.evt = createManualEvent();
		waiters[id] = w;
	}

	/// Block the current task until the peer's response to `id` arrives (or
	/// `timeout` elapses). Returns the result `Json`, or throws `McpException` on a
	/// JSON-RPC error response or on timeout. Removes the waiter on the way out
	/// (whether by reply, error, or timeout) so the table never leaks.
	Json await(long id, Duration timeout = 60.seconds) @safe
	{
		auto w = waiters[id];
		scope (exit)
			waiters.remove(id);

		auto ec = w.evt.emitCount;
		while (!w.done)
		{
			const newEc = () @trusted { return w.evt.wait(timeout, ec); }();
			if (newEc == ec && !w.done)
				throw internalError("Timed out awaiting response to request " ~ idStr(id));
			ec = newEc;
		}
		if (w.error.type != Json.Type.undefined)
		{
			const code = ("code" in w.error) ? w.error["code"].get!int : ErrorCode.internalError;
			const m = ("message" in w.error) ? w.error["message"].get!string : "peer error";
			throw new McpException(code, m, w.error);
		}
		return w.result;
	}

	/// Drop a registered-but-unawaited request id (e.g. when writing the request
	/// failed so the peer will never reply). Idempotent; unknown ids are ignored.
	/// Keeps the waiter table from leaking when `register` is not followed by a
	/// completed `await`.
	void cancel(long id) @safe
	{
		waiters.remove(id);
	}

	/// Deliver a peer response/errorResponse. `idJson` is the JSON-RPC id of the
	/// reply, `result` the success payload (or `Json.undefined`), `error` the
	/// JSON-RPC error object (or `Json.undefined`). Returns true if it matched a
	/// pending request (waking its `await`), false otherwise (an id we are not
	/// awaiting, or a non-integer id — neither is an error here; the caller decides
	/// what to do with an unmatched reply).
	bool resolve(Json idJson, Json result, Json error) @safe
	{
		if (idJson.type != Json.Type.int_)
			return false;
		const id = idJson.get!long;
		if (auto w = id in waiters)
		{
			w.result = result;
			w.error = error;
			w.done = true;
			w.evt.emit();
			return true;
		}
		return false;
	}

	private static string idStr(long id) @safe
	{
		import std.conv : to;

		return id.to!string;
	}
}

version (unittest)
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, yield;
	import vibe.data.json : parseJsonString;
}

unittest  // alloc hands out monotonic ids starting at 1
{
	auto c = new DuplexCoordinator;
	assert(c.alloc() == 1);
	assert(c.alloc() == 2);
	assert(c.alloc() == 3);
}

unittest  // resolve returns false for an id no one is awaiting
{
	auto c = new DuplexCoordinator;
	assert(!c.resolve(Json(7L), Json.emptyObject, Json.undefined));
}

unittest  // resolve returns false for a non-integer id (string/null ids are not tracked)
{
	auto c = new DuplexCoordinator;
	c.register(1);
	assert(!c.resolve(Json("abc"), Json.emptyObject, Json.undefined));
	assert(!c.resolve(Json(null), Json.emptyObject, Json.undefined));
}

unittest  // cancel drops a registered id so a later resolve finds nothing
{
	auto c = new DuplexCoordinator;
	c.register(5);
	c.cancel(5);
	assert(!c.resolve(Json(5L), Json.emptyObject, Json.undefined));
	// Idempotent: cancelling again is a no-op.
	c.cancel(5);
}

unittest  // await returns the result once resolve fires from another task
{
	auto c = new DuplexCoordinator;
	Json got = Json.undefined;
	bool done;

	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			c.register(1);
			// A sibling task resolves id 1 after we begin awaiting.
			runTask(() nothrow{
				try
				{
					yield(); // let the await below register its wait first
					c.resolve(Json(1L), parseJsonString(`{"ok":true}`), Json.undefined);
				}
				catch (Exception)
				{
				}
			});
			got = c.await(1);
			done = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	assert(done);
	assert(got["ok"].get!bool == true);
}

unittest  // await throws McpException carrying the code from an error response
{
	auto c = new DuplexCoordinator;
	int code;
	bool threw;

	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			c.register(2);
			runTask(() nothrow{
				try
				{
					yield();
					c.resolve(Json(2L), Json.undefined,
					parseJsonString(`{"code":-32601,"message":"Method not found"}`));
				}
				catch (Exception)
				{
				}
			});
			try
				c.await(2);
			catch (McpException e)
			{
				threw = true;
				code = e.code;
			}
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	assert(threw);
	assert(code == ErrorCode.methodNotFound);
}

unittest  // two concurrent awaits each receive their own correlated result (out of order)
{
	auto c = new DuplexCoordinator;
	Json r1 = Json.undefined, r2 = Json.undefined;
	int finished;

	runTask(() nothrow{
		try
		{
			c.register(1);
			c.register(2);

			auto t1 = runTask(() nothrow{
				try
					r1 = c.await(1);
				catch (Exception)
				{
				}
			});
			auto t2 = runTask(() nothrow{
				try
					r2 = c.await(2);
				catch (Exception)
				{
				}
			});

			yield(); // let both awaits arm their waits
			// Resolve OUT OF ORDER: id 2 first, then id 1.
			c.resolve(Json(2L), parseJsonString(`{"which":2}`), Json.undefined);
			c.resolve(Json(1L), parseJsonString(`{"which":1}`), Json.undefined);

			t1.join();
			t2.join();
			finished = 1;
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();

	assert(finished == 1);
	assert(r1["which"].get!int == 1);
	assert(r2["which"].get!int == 2);
}

unittest  // await times out with an McpException when no reply arrives
{
	import core.time : msecs;

	auto c = new DuplexCoordinator;
	bool threw;

	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			c.register(9);
			try
				c.await(9, 30.msecs);
			catch (McpException)
				threw = true;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();

	assert(threw);
}
