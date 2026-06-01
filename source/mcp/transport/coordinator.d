module mcp.transport.coordinator;

import core.time : Duration, seconds;

import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.data.json : Json;

import mcp.protocol.errors;

@safe:

/// Correlates outbound JSON-RPC requests with the peer's responses on a single
/// duplex byte channel (the MCP **stdio** transport, where both directions share
/// one stream). This generalizes `StreamCoordinator`'s waiter registry — which
/// the Streamable HTTP transport uses to match a server->client request with the
/// client's reply that arrives on a *separate* POST — to a symmetric, transport-
/// neutral primitive used by `DuplexChannel` for BOTH peers:
///
///   - the client awaits the response to a request it sent the server, and
///   - the server awaits the response to a server->client request it sent the
///     client (sampling / elicitation / roots / ping).
///
/// A waiting task blocks on a vibe `LocalManualEvent`, so the await is
/// cooperative: the channel's read loop keeps running and `resolve`s the waiter
/// when the matching reply line arrives. One instance is shared across the
/// channel; the read loop is the single `resolve`/`failPending` caller, and each
/// awaiting task is its own `register`/`await` caller, so on the default single-
/// threaded vibe event loop no additional locking is required.
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

	/// Allocate a fresh outbound request id. Used by the server peer, which
	/// originates its own server->client requests; the client peer supplies the id
	/// `McpClient` pre-allocated.
	long alloc() @safe
	{
		return counter++;
	}

	/// Begin tracking a pending outbound request `id`. Call before sending the
	/// request frame so a fast reply cannot race ahead of the registration.
	void register(long id) @safe
	{
		auto w = new Waiter;
		w.evt = createManualEvent();
		waiters[id] = w;
	}

	/// Block the current task until the peer responds to `id` (or `timeout`
	/// elapses). Returns the result, or throws `McpException` on error / timeout /
	/// channel close (`failPending`). Deregisters the waiter on the way out.
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
				throw internalError("Timed out awaiting peer response to request " ~ idStr(id));
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

	/// Drop a registered-but-unawaited request id (e.g. when sending the request
	/// frame failed so a response will never arrive). Idempotent; unknown ids are
	/// ignored. Keeps the waiter table from leaking when `register` is not followed
	/// by `await`.
	void cancel(long id) @safe
	{
		waiters.remove(id);
	}

	/// Deliver a peer response / errorResponse. Returns true if `idJson` matched a
	/// pending outbound request (waking its awaiting task), false otherwise (an id
	/// we are not awaiting — e.g. a stray response — is ignored).
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

	/// Fail every still-pending request with `error` and wake its awaiting task.
	/// Called by the read loop at end-of-input so a caller blocked in `await`
	/// is released with an exception instead of hanging until its timeout.
	void failPending(McpException error) @safe
	{
		// `await`'s scope(exit) removes each id, so snapshot the keys first.
		foreach (id; waiters.keys)
		{
			if (auto w = id in waiters)
			{
				Json err = Json.emptyObject;
				err["code"] = error.code;
				err["message"] = error.msg;
				w.error = err;
				w.done = true;
				w.evt.emit();
			}
		}
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
}

unittest  // alloc hands out distinct, increasing ids
{
	auto coord = new DuplexCoordinator;
	const a = coord.alloc();
	const b = coord.alloc();
	const c = coord.alloc();
	assert(a != b && b != c && a != c);
	assert(b == a + 1 && c == b + 1);
}

unittest  // resolve before await: a result registered then resolved is returned by await
{
	auto coord = new DuplexCoordinator;
	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			coord.register(7);
			// Simulate the read loop resolving on another turn.
			runTask(() nothrow{
				try
					coord.resolve(Json(7L), Json(["ok": Json(true)]), Json.undefined);
				catch (Exception)
				{
				}
			});
			auto r = coord.await(7);
			if (r["ok"].get!bool)
				rc = 1;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(rc == 1);
}

unittest  // resolve delivers an error response as an McpException to the awaiting task
{
	auto coord = new DuplexCoordinator;
	int code;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			coord.register(3);
			runTask(() nothrow{
				try
				{
					Json err = Json.emptyObject;
					err["code"] = -32601;
					err["message"] = "nope";
					coord.resolve(Json(3L), Json.undefined, err);
				}
				catch (Exception)
				{
				}
			});
			try
				coord.await(3);
			catch (McpException e)
				code = e.code;
		}
		catch (Exception)
		{
		}
	});
	runEventLoop();
	assert(code == -32601);
}

unittest  // failPending wakes an awaiting task with an error instead of hanging
{
	auto coord = new DuplexCoordinator;
	bool threw;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			coord.register(9);
			runTask(() nothrow{
				try
					coord.failPending(internalError("channel closed"));
				catch (Exception)
				{
				}
			});
			try
				coord.await(9);
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

unittest  // resolve returns false for an id no task is awaiting
{
	auto coord = new DuplexCoordinator;
	assert(!coord.resolve(Json(42L), Json.emptyObject, Json.undefined));
}

unittest  // resolve ignores a non-integer id
{
	auto coord = new DuplexCoordinator;
	coord.register(1);
	assert(!coord.resolve(Json("str-id"), Json.emptyObject, Json.undefined));
	coord.cancel(1);
}

unittest  // cancel drops an unawaited registration without leaking
{
	auto coord = new DuplexCoordinator;
	coord.register(5);
	coord.cancel(5);
	// A subsequent resolve for the cancelled id matches nothing.
	assert(!coord.resolve(Json(5L), Json.emptyObject, Json.undefined));
}
