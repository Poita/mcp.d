/**
 * examples/streaming — server.d (dual-transport: stdio AND Streamable HTTP)
 *
 * Demonstrates the SERVER side of MCP's three "in-flight" channels —
 * progress, logging and cancellation — written in the ergonomic
 * UDA style: tools are annotated typed methods on a class, registered in one
 * call with `registerHandlers`. Typed args are marshalled and the structured
 * result is inferred from the struct return — no hand-built `Json` schemas or
 * args.
 *
 * Transport selection is delegated to the shared `examples/common` scaffold:
 * `runServerFromArgs(server, args, 9357)` serves stdio by default and
 * Streamable HTTP on `--http` (+ `--port`/`--host`) — the SAME single binary,
 * EITHER transport — so the getopt + transport branch lives in the scaffold,
 * not here.
 *
 * Two tools:
 *
 *   `countdown` — a long-running task. On every step it:
 *       - emits a `notifications/progress` via the integer-step convenience
 *         `ctx.reportProgress(done, total, msg)` — delivered to the
 *         client only when the call carried a `_meta.progressToken`,
 *       - emits a `notifications/message` (logging) via the typed
 *         `ctx.log(LogLevel.info, message, logger)` convenience — a plain
 *         string payload, no hand-built `Json` data, and
 *       - polls `ctx.isCancelled` and stops promptly when the client cancels.
 *     Its structured result records `{completed, total, cancelled}` so the client
 *     can assert concrete values. When a run is cancelled it bumps a server-side
 *     counter so cancellation can be verified out of band.
 *
 *   `cancel_stats` — returns `{cancelled: <int>}`, the number of `countdown`
 *     runs that observed a cancellation. The cancellation client closes its
 *     stream mid-flight (the Streamable HTTP cancellation signal); a later,
 *     fresh client reads this tool to confirm the server honored it.
 *
 * This example is STATELESS (the default). Its HTTP path exercises the draft
 * transport's client-disconnect cancellation, which a stateful server cannot
 * serve (the draft is excluded from stateful negotiation). Server->client
 * features (elicit/sample/roots) require a stateful server and are demonstrated
 * by the dedicated `examples/elicitation` and `examples/sampling` examples.
 *
 * Run standalone:
 *   dub build -c server
 *   ./streaming-server                        # stdio (default)
 *   ./streaming-server --http --port 9357      # serves http://127.0.0.1:9357/mcp
 */
module streaming_server;

import core.time : msecs;
import std.conv : to;
import std.typecons : nullable;

import vibe.core.core : sleep;

import mcp;
import mcp.api.attributes : tool, describe;
import mcp.api.reflection : registerHandlers;
import mcp.protocol.types : LogLevel;

import examples_common : runServerFromArgs;

void main(string[] args) @safe
{
	auto server = new McpServer("streaming-example", "1.0.0",
			nullable("Progress / logging / cancellation demo over stdio AND Streamable HTTP."));
	// Advertise the `logging` capability so `ctx.log` notifications are emitted on
	// the released (2025-*) protocols.
	server.enableLogging();

	// Register every @tool method on the API object. The shared cancellation
	// tally lives on the instance, so `cancel_stats` reports what `countdown` saw.
	registerHandlers(server, new StreamingApi);

	// Transport selection (stdio default; --http + --port/--host) comes from the
	// shared examples/common scaffold, default port 9357.
	runServerFromArgs(server, args, 9357);
}

/// The `countdown` structured result: `{completed, total, cancelled}`. Returned
/// from the `@tool` method, so the SDK infers the output JSON Schema (integers
/// for `completed`/`total`, boolean for `cancelled`) and emits it as
/// `structuredContent`.
struct CountdownResult
{
	int completed;
	int total;
	bool cancelled;
}

/// The `cancel_stats` structured result: `{cancelled}`.
struct CancelStats
{
	int cancelled;
}

/// The annotated MCP tool surface for this example. The mutable cancellation
/// tally lives on the instance so `countdown` can record what it saw and
/// `cancel_stats` can report it.
final class StreamingApi
{
	private int cancelled_;

	/// `countdown`: a deliberately slow, observable task.
	///
	/// For each step `i` in `1..=steps` it sleeps `delayMs`, checks
	/// `ctx.isCancelled` (returning early with `cancelled:true` and bumping the
	/// server counter), then reports progress `i/steps` and logs an info line.
	@tool("countdown",
			"Run a multi-step task, reporting progress + logging each step and honoring cancellation.")
	CountdownResult countdown(@describe("number of steps to run") int steps,
			@describe("delay between steps, in milliseconds") int delayMs, RequestContext ctx)@safe
	{
		bool cancelled = false;
		int completed = 0;
		foreach (i; 1 .. steps + 1)
		{
			// Sleep simulates a slow unit of work, and yields so the transport can
			// interleave other connections while this handler is mid-flight.
			sleep(delayMs.msecs);

			// Cooperative cancellation: a handler SHOULD poll this and stop promptly
			// (basic/utilities/cancellation).
			if (ctx.isCancelled)
			{
				cancelled = true;
				break;
			}

			// Emit progress + a log line for this step. On Streamable HTTP the
			// cancellation signal is the client closing its response stream (draft
			// basic/utilities/cancellation §Transport-Specific Cancellation). A
			// closed stream surfaces here as a FAILED SSE write, which we treat as
			// cancellation: stop the work and record it.
			try
			{
				// Integer-step progress convenience: done/total as longs, no
				// cast(double) + Nullable wrapping at the call site.
				ctx.reportProgress(cast(long) i, cast(long) steps,
						"step " ~ i.to!string ~ "/" ~ steps.to!string);
				// Typed log convenience: a LogLevel + a plain string message,
				// no hand-built Json `data` payload.
				ctx.log(LogLevel.info,
						"processing step " ~ i.to!string ~ " of " ~ steps.to!string, "countdown");
			}
			catch (Exception)
			{
				cancelled = true;
				break;
			}
			completed = i;
		}
		if (cancelled)
			cancelled_++;

		return CountdownResult(completed, steps, cancelled);
	}

	/// `cancel_stats`: returns `{cancelled:<int>}`, how many countdown runs have
	/// observed a cancellation since the server started.
	@tool("cancel_stats", "Number of countdown runs that observed a cancellation.")
	CancelStats cancelStats() @safe
	{
		return CancelStats(cancelled_);
	}
}
