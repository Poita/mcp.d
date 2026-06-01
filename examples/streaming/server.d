/**
 * examples/streaming — server.d (dual-transport: stdio AND Streamable HTTP)
 *
 * Demonstrates the SERVER side of MCP's three "in-flight" channels —
 * progress, logging and cancellation (issue #357) — written in the ergonomic
 * UDA style: tools are annotated typed methods on a class, registered in one
 * call with `registerHandlers`. Typed args are marshalled and the structured
 * result is inferred from the struct return — no hand-built `Json` schemas or
 * args.
 *
 * ONE binary, EITHER transport:
 *   - default (no flag): `runStdio(server)` — newline-delimited JSON-RPC on
 *     stdin/stdout, the transport the bundled client spawns for its stdio e2e.
 *   - `--http` (+ `--port`/`--host`): `runStreamableHttp(server, port, opts)`.
 *
 * Three tools:
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
 *   `summarize` — exercises the TYPED server->client round-trip APIs (#436/#437),
 *     which work over BOTH transports (the SDK pumps the same channel mid-handler):
 *       - `ctx.elicit!Confirm(message)` derives the elicitation `requestedSchema`
 *         from the flat struct `Confirm` via `jsonSchemaOf!T` and returns a typed
 *         `ElicitResult` (we branch on `.action` and decode with `.contentAs!T`),
 *       - `ctx.sample(CreateMessageRequest)` builds a typed sampling request from
 *         `SamplingMessage` + `Content.makeText` and parses the typed
 *         `CreateMessageResult` reply.
 *     It returns a typed `SummaryResult` so the SDK infers the output schema.
 *
 *   `cancel_stats` — returns `{cancelled: <int>}`, the number of `countdown`
 *     runs that observed a cancellation. The cancellation client closes its
 *     stream mid-flight (the Streamable HTTP cancellation signal); a later,
 *     fresh client reads this tool to confirm the server honored it.
 *
 * Run standalone:
 *   dub build -c server
 *   ./streaming-server                        # stdio (default)
 *   ./streaming-server --http --port 9357      # serves http://127.0.0.1:9357/mcp
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
import mcp.api.attributes : tool, describe;
import mcp.api.reflection : registerHandlers;
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult, SamplingMessage;
import mcp.protocol.types : Content, ElicitAction;
import mcp.transport : StreamableHttpOptions, runStreamableHttp, runStdio;

enum ushort defaultPort = 9357;

void main(string[] args)
{
	bool http = false;
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args,
			"http", "Serve over Streamable HTTP instead of stdio (default: stdio)", &http,
			"port|p", "HTTP port to listen on (default 9357)", &port,
			"host|h", "HTTP address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("streaming-example", "1.0.0",
			nullable("Progress / logging / cancellation demo over stdio AND Streamable HTTP."));
	// Advertise the `logging` capability so `ctx.log` notifications are emitted on
	// the released (2025-*) protocols.
	server.enableLogging();

	// Register every @tool method on the API object. The shared cancellation
	// tally lives on the instance, so `cancel_stats` reports what `countdown` saw.
	registerHandlers(server, new StreamingApi);

	if (http)
	{
		StreamableHttpOptions opts;
		opts.bindAddresses = [host];
		() @trusted {
			stderr.writefln("streaming-server listening on http://%s:%d/mcp", host, port);
		}();
		runStreamableHttp(server, port, opts);
	}
	else
	{
		// stdio: only valid MCP frames go to stdout; diagnostics go to stderr.
		() @trusted { stderr.writeln("streaming-server serving over stdio"); }();
		runStdio(server);
	}
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

/// The flat elicitation struct for `summarize`. `ctx.elicit!Confirm` derives the
/// `requestedSchema` from this struct via `jsonSchemaOf!T`, and the typed
/// `ElicitResult.contentAs!Confirm` decodes the accept content — no hand-built
/// schema Json, no hand-built field reads.
struct Confirm
{
	bool proceed; /// whether the user agrees to summarize
	string tone; /// requested tone, e.g. "concise"
}

/// The `summarize` structured result.
struct SummaryResult
{
	string status; /// "summarized" | "declined"
	string tone; /// the tone the user asked for (echoed)
	string model; /// the model the client's sampling reply reported
	string summary; /// the text the client's sampling reply produced
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
	CountdownResult countdown(
			@describe("number of steps to run") int steps,
			@describe("delay between steps, in milliseconds") int delayMs,
			RequestContext ctx) @safe
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
				ctx.reportProgress(cast(double) i, nullable(cast(double) steps),
						"step " ~ i.to!string ~ "/" ~ steps.to!string);
				// Logging `data` is a free-form payload (no typed surface): build it
				// as Json by design.
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
			cancelled_++;

		return CountdownResult(completed, steps, cancelled);
	}

	/// `summarize`: mid-handler it BLOCKS on the typed server->client round-trip
	/// APIs (both work over stdio AND Streamable HTTP because the SDK pumps the
	/// same channel while the handler is in flight):
	///
	///   - `ctx.elicit!Confirm(message)` derives the elicitation schema from the
	///     flat `Confirm` struct (no hand-built schema Json) and returns a typed
	///     `ElicitResult`; on accept we decode it with `.contentAs!Confirm`.
	///   - `ctx.sample(CreateMessageRequest)` sends a typed sampling request built
	///     from `SamplingMessage` + `Content.makeText`, and parses the typed
	///     `CreateMessageResult` reply (reading `.model` and `.content.text`).
	@tool("summarize",
			"Summarize text after confirming tone via a typed elicitation, using typed sampling.")
	SummaryResult summarize(
			@describe("the text to summarize") string text,
			RequestContext ctx) @safe
	{
		// Typed elicitation: requestedSchema is DERIVED from `Confirm` (#436).
		auto elicited = ctx.elicit!Confirm("Confirm summarization preferences");
		if (elicited.action != ElicitAction.accept)
			return SummaryResult("declined", "", "", "User declined to summarize.");

		const confirm = elicited.contentAs!Confirm;
		if (!confirm.proceed)
			return SummaryResult("declined", confirm.tone, "", "User chose not to proceed.");

		// Typed sampling: build CreateMessageRequest from typed SamplingMessage +
		// Content.makeText (#437) instead of hand-built content Json.
		CreateMessageRequest req;
		req.messages = [
			SamplingMessage("user",
					Content.makeText("Summarize the following in a " ~ confirm.tone
						~ " tone:\n" ~ text))
		];
		req.maxTokens = nullable(256L);
		req.systemPrompt = nullable("You are a careful summarizer.");

		CreateMessageResult reply = ctx.sample(req);
		return SummaryResult("summarized", confirm.tone, reply.model, reply.content.text);
	}

	/// `cancel_stats`: returns `{cancelled:<int>}`, how many countdown runs have
	/// observed a cancellation since the server started.
	@tool("cancel_stats", "Number of countdown runs that observed a cancellation.")
	CancelStats cancelStats() @safe
	{
		return CancelStats(cancelled_);
	}
}
