/**
 * examples/streaming — server.d
 *
 * Demonstrates the SERVER side of "Progress / logging / cancellation" over the
 * Streamable HTTP transport (issue #357).
 *
 * Two tools:
 *
 *   `countdown` — a long-running task. On every step it:
 *       - emits a `notifications/progress` via `ctx.reportProgress(done, total, msg)`
 *         (delivered to the client only when the call carried a `_meta.progressToken`),
 *       - emits a `notifications/message` (logging) via `ctx.log("info", ...)`, and
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
 * Run standalone:
 *   dub build -c server
 *   ./streaming-server --port 9357          # serves http://127.0.0.1:9357/mcp
 */
module streaming_server;

import core.time : msecs;
import std.conv : to;
import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable;

import vibe.core.core : sleep;
import vibe.data.json : Json;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

enum ushort defaultPort = 9357;

void main(string[] args)
{
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 9357)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("streaming-example", "1.0.0",
			nullable("Progress / logging / cancellation demo over Streamable HTTP."));
	// Advertise the `logging` capability so `ctx.log` notifications are emitted on
	// the released (2025-*) protocols.
	server.enableLogging();

	// A server-side counter of how many countdown runs observed a cancellation.
	// Captured by both handlers so `cancel_stats` can report what `countdown` saw.
	auto state = new CancelState;
	registerCountdown(server, state);
	registerCancelStats(server, state);

	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	() @trusted {
		stderr.writefln("streaming-server listening on http://%s:%d/mcp", host, port);
	}();
	runStreamableHttp(server, port, opts);
}

/// Shared, mutable cancellation tally for the running server instance.
final class CancelState
{
	private int cancelled_;
	void recordCancelled() @safe nothrow @nogc
	{
		cancelled_++;
	}

	int cancelled() const @safe nothrow @nogc
	{
		return cancelled_;
	}
}

/// Register `countdown`: a deliberately slow, observable task.
///
/// Arguments (object): `steps` (int, default 5) and `delayMs` (int, default 40).
/// For each step `i` in `1..=steps` it sleeps `delayMs`, checks `ctx.isCancelled`
/// (returning early with `cancelled:true` and bumping the server counter), then
/// reports progress `i/steps` and logs an info line. The final structured result
/// is `{ completed:<int>, total:<int>, cancelled:<bool> }`.
void registerCountdown(McpServer server, CancelState state) @safe
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["steps"] = Json(["type": Json("integer"), "minimum": Json(1)]);
	props["delayMs"] = Json(["type": Json("integer"), "minimum": Json(0)]);
	schema["properties"] = props;

	Json outSchema = Json.emptyObject;
	outSchema["type"] = "object";
	Json outProps = Json.emptyObject;
	outProps["completed"] = Json(["type": Json("integer")]);
	outProps["total"] = Json(["type": Json("integer")]);
	outProps["cancelled"] = Json(["type": Json("boolean")]);
	outSchema["properties"] = outProps;
	outSchema["required"] = Json([Json("completed"), Json("total"), Json("cancelled")]);

	Tool countdown = {
		name: "countdown",
		description: nullable(
			"Run a multi-step task, reporting progress + logging each step and honoring cancellation."),
		inputSchema: schema,
		outputSchema: outSchema
	};

	server.registerDynamicTool(countdown, (Json args, RequestContext ctx) @safe {
		const steps = ("steps" in args && args["steps"].type == Json.Type.int_)
			? cast(int) args["steps"].get!long : 5;
		const delayMs = ("delayMs" in args && args["delayMs"].type == Json.Type.int_)
			? cast(int) args["delayMs"].get!long : 40;

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
				ctx.reportProgress(cast(double) i, nullable(cast(double) steps),
						"step " ~ i.to!string ~ "/" ~ steps.to!string);
				Json logData = Json.emptyObject;
				logData["message"] = "processing step " ~ i.to!string ~ " of " ~ steps.to!string;
				logData["step"] = i;
				ctx.log("info", logData, "countdown");
			}
			catch (Exception)
			{
				cancelled = true;
				break;
			}
			completed = i;
		}
		if (cancelled)
			state.recordCancelled();

		Json structured = Json.emptyObject;
		structured["completed"] = completed;
		structured["total"] = steps;
		structured["cancelled"] = cancelled;

		CallToolResult r;
		r.content = [Content.makeText(cancelled
				? ("cancelled after " ~ completed.to!string ~ "/" ~ steps.to!string ~ " steps")
				: ("completed all " ~ steps.to!string ~ " steps"))];
		r.structuredContent = structured;
		return r;
	});
}

/// Register `cancel_stats`: returns `{cancelled:<int>}`, how many countdown runs
/// have observed a cancellation since the server started.
void registerCancelStats(McpServer server, CancelState state) @safe
{
	Json outSchema = Json.emptyObject;
	outSchema["type"] = "object";
	outSchema["properties"] = Json(["cancelled": Json(["type": Json("integer")])]);
	outSchema["required"] = Json([Json("cancelled")]);

	Tool stats = {
		name: "cancel_stats",
		description: nullable("Number of countdown runs that observed a cancellation."),
		outputSchema: outSchema
	};

	server.registerDynamicTool(stats, (Json args, RequestContext ctx) @safe {
		Json structured = Json.emptyObject;
		structured["cancelled"] = state.cancelled();
		CallToolResult r;
		r.content = [Content.makeText("cancelled=" ~ state.cancelled().to!string)];
		r.structuredContent = structured;
		return r;
	});
}

