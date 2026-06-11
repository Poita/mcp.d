/**
 * examples/streaming — client.d (self-verifying e2e test, dual-transport)
 *
 * One self-verifying client that exercises the streaming server over EITHER
 * transport, selected at runtime by the shared `examples/common` scaffold:
 *
 *   - STDIO (default): `connectFromArgs` spawns the sibling `streaming-server`
 *     binary (no `--http`) via `McpClient.spawnSibling`, talking to it over its
 *     stdin/stdout.
 *   - HTTP (`--http <url>` / `--url <url>`): connect to an already-running server
 *     with `McpClient.http(url)`.
 *
 * The event-loop wiring (runTask / runEventLoop / catch->rc) and the assertion
 * helper `check` are provided by the scaffold's `runClient`.
 *
 * Every observation is asserted against the value the server promises; the
 * process exits NON-ZERO on any mismatch, so CI can run it as an e2e regression
 * test. The transport-agnostic phases (A/C) run over BOTH transports; the
 * mid-flight cancellation phase (D) runs over HTTP, where the cancel signal is
 * tearing down the per-request SSE response stream (a client disconnect). Over
 * stdio the cancel signal is instead a `notifications/cancelled` message, which
 * the SDK server honours mid-handler via its cooperative input drain (see the
 * `serveStdio` cancellation unittest); this client keeps phase D HTTP-only
 * because its simple synchronous stdio client cannot inject a notification while
 * a `callTool` is in flight.
 *
 * Typed/ergonomic SDK APIs used here:
 *   - per-call progress sink: `callTool(name, args, onProgress)` (the delegate
 *     overload) delivers THIS call's progress to a local callback.
 *   - `result.structuredContentAs!T` decodes structured output into a struct.
 *   - the call `arguments` are built as a JSON object (the untyped client
 *     request surface — see the repo-root DESIGN.md).
 *
 * What it verifies, in order:
 *   A. LIST + PROGRESS + LOGGING (transport-agnostic)
 *      - `listTools()` contains `countdown` and `cancel_stats`, and
 *        `countdown` declares its output schema.
 *      - A `countdown` call with a per-call progress sink streams EXACTLY N
 *        `notifications/progress` (monotonically increasing, last == total,
 *        carrying a progress token) AND N `notifications/message` (level=info,
 *        logger="countdown") BEFORE the final result `{completed:N, total:N,
 *        cancelled:false}`.
 *   C. ERROR CODE (transport-agnostic)
 *      - an unknown tool raises McpException with code invalidParams (-32602).
 *   D. CANCELLATION (HTTP only) — disconnect IS the cancel signal on Streamable
 *      HTTP. A long `countdown` is started on its own task; after the first
 *      progress proves it is in flight, the client closes its stream; the server
 *      observes the disconnect via `ctx.isCancelled`, stops early, and bumps its
 *      cancel counter, which a fresh `cancel_stats` read confirms.
 */
module streaming_client;

import core.time : msecs;
import std.algorithm : map, canFind;
import std.array : array;
import std.conv : to;
import std.getopt : getopt;

import vibe.core.core : runTask, sleep;
import vibe.data.json : Json;

import mcp;
import mcp.client.client : McpClient;
import mcp.protocol.errors : ErrorCode, McpException;

import examples_common : check, runClient, connectFromArgs;

// Typed mirrors of the server's structured RESULTS, used for structuredContentAs!T
// decoding. They match the server's field names exactly.

/// `countdown` arguments as a JSON object (`{ "steps": steps, "delayMs": delayMs }`).
/// The client request surface is untyped — see the repo-root `DESIGN.md`.
private Json countdownArgs(int steps, int delayMs) @safe
{
	Json j = Json.emptyObject;
	j["steps"] = steps;
	j["delayMs"] = delayMs;
	return j;
}

/// `countdown` final structured result.
struct CountdownResult
{
	int completed;
	int total;
	bool cancelled;
}

/// `cancel_stats` structured result.
struct CancelStats
{
	int cancelled;
}

int main(string[] args) @safe
{
	// Detect the HTTP URL (if any) up front: phase D (mid-flight cancellation) is
	// HTTP-only and needs to open its OWN draft-mode client to the same URL. The
	// transport for phases A/C is chosen by the scaffold's `connectFromArgs`.
	string httpUrl;
	(() @trusted {
		getopt(args, "http", "Connect over Streamable HTTP to this MCP endpoint.",
			&httpUrl, "url", "Alias for --http.", &httpUrl);
	})();
	const bool useHttp = httpUrl.length != 0;

	// `runClient` drives the vibe event loop so the same scenario body works over
	// both the synchronous stdio (spawnSibling) transport and the HTTP transport.
	return runClient(() @safe => run(args, useHttp, httpUrl));
}

private int run(string[] args, bool useHttp, string httpUrl) @safe
{
	enum int steps = 5;

	// One connection for the transport-agnostic phases. `connectFromArgs` picks
	// HTTP (when --http/--url is given) or spawns the sibling `streaming-server`
	// over stdio.
	auto client = connectFromArgs(args, "streaming-server");
	scope (exit)
		client.close();
	client.initialize();
	// The streaming server is stateless and refuses the `logging/setLevel` RPC
	// (-32601) on every transport. The server's default minimum log level is "info",
	// so the countdown's info-level logs flow on both transports without setLogLevel.
	// The Phase A assertion checks for level == "info", which holds at the default.

	const int progressSeen = phaseListProgressLogging(client, steps);
	phaseErrorCode(client);

	if (useHttp)
	{
		// Phase D — mid-flight cancellation, HTTP-only (disconnect is the signal).
		const int cancelledBefore = readCancelCount(httpUrl);
		// phaseCancellation drives the cancel and polls the server counter until it
		// observes the increment (or surfaces a diagnostic on timeout).
		const int cancelledAfter = phaseCancellation(httpUrl, cancelledBefore);
		check(cancelledAfter >= cancelledBefore + 1,
				"server's cancel_stats must increase after a mid-flight cancellation (before="
				~ cancelledBefore.to!string ~ ", after=" ~ cancelledAfter.to!string ~ ")");

		report("OK [http]: countdown streamed " ~ progressSeen.to!string ~ " progress + "
				~ progressSeen.to!string ~ " log msgs; unknown-tool error code; "
				~ "mid-flight cancel honored (cancel_stats "
				~ cancelledBefore.to!string ~ " -> " ~ cancelledAfter.to!string ~ ").");
		return 0;
	}

	report("OK [stdio]: countdown streamed " ~ progressSeen.to!string
			~ " progress + " ~ progressSeen.to!string ~ " log msgs; "
			~ "unknown-tool error code. (phase D not run here: this client cannot inject "
			~ "notifications/cancelled mid-callTool; the SDK server honours it over stdio "
			~ "— see serveStdio's unittest.)");
	return 0;
}

private void report(string msg) @trusted
{
	import std.stdio : writeln;

	writeln(msg);
}

// --- Phase A: list + progress + logging (transport-agnostic) -----------------

private int phaseListProgressLogging(McpClient client, int steps) @safe
{
	auto tools = client.listTools().tools;
	auto names = tools.map!(t => t.name).array;
	foreach (want; ["countdown", "cancel_stats"])
		check(names.canFind(want), "listTools() must contain '" ~ want ~ "'");

	long idx = -1;
	foreach (i, ref t; tools)
		if (t.name == "countdown")
			idx = i;
	check(idx >= 0, "listTools() must contain a 'countdown' tool");
	const countdown = tools[idx];
	check(countdown.outputSchema.type == Json.Type.object, "countdown must declare an outputSchema");
	check(countdown.outputSchema["properties"]["cancelled"]["type"].get!string == "boolean",
			"countdown output schema must declare cancelled:boolean");

	ProgressUpdate[] progress;
	LogEntry[] logs;
	client.onLogMessage = (LogMessageNotification n) @safe {
		logs ~= LogEntry(n.level, n.logger.isNull ? "" : n.logger.get);
	};

	// Per-call progress sink: the SDK mints a unique progressToken for THIS call
	// and routes only its progress notifications to this callback for the
	// duration of the call.
	auto result = client.callTool("countdown", countdownArgs(steps, 20),
			(ProgressNotification n) @safe {
		progress ~= ProgressUpdate(n.progress, n.total.isNull
			? -1 : n.total.get, n.progressTokenString);
	});

	// Final structured result, decoded into the typed CountdownResult.
	check(result.structuredContent.type == Json.Type.object, "result must carry structuredContent");
	const cr = result.structuredContentAs!CountdownResult;
	check(cr.completed == steps,
			"completed should be " ~ steps.to!string ~ ", got " ~ cr.completed.to!string);
	check(cr.total == steps, "total should be " ~ steps.to!string);
	check(cr.cancelled == false, "cancelled should be false on a full run");

	// Exactly `steps` progress notifications, increasing, last == total. The
	// per-call sink only ever sees THIS call's progress, so a non-empty token
	// string is enough to prove each notification carried the minted token.
	check(progress.length == steps,
			"expected " ~ steps.to!string ~ " progress notifications, got "
			~ progress.length.to!string);
	foreach (i, p; progress)
	{
		check(p.value == cast(double)(i + 1),
				"progress[" ~ i.to!string ~ "].value should be " ~ (i + 1)
					.to!string ~ ", got " ~ p.value.to!string);
		check(p.total == cast(double) steps, "progress total should be " ~ steps.to!string);
		check(p.token.length != 0, "progress must carry the call's progressToken");
		if (i > 0)
			check(p.value > progress[i - 1].value, "progress MUST strictly increase");
	}
	check(progress[$ - 1].value == cast(double) steps, "final progress must equal total");

	// Exactly `steps` info logs from the "countdown" logger.
	check(logs.length == steps,
			"expected " ~ steps.to!string ~ " log messages, got " ~ logs.length.to!string);
	foreach (l; logs)
	{
		check(l.level == "info", "log level should be info, got " ~ l.level);
		check(l.logger == "countdown", "log logger should be 'countdown', got " ~ l.logger);
	}
	return cast(int) progress.length;
}

// --- Phase C: error code (transport-agnostic) --------------------------------

private void phaseErrorCode(McpClient client) @safe
{
	int code;
	bool threw;
	try
		client.callTool("does_not_exist", Json.emptyObject);
	catch (McpException e)
	{
		threw = true;
		code = e.code;
	}
	check(threw, "calling an unknown tool should raise McpException");
	check(code == ErrorCode.invalidParams,
			"unknown tool error code should be invalidParams (-32602), got " ~ code.to!string);
}

// --- Phase D: cancellation via stream disconnect (HTTP only) -----------------

private int phaseCancellation(string url, int cancelledBefore) @trusted
{
	auto client = McpClient.http(url);
	// Draft mode: on Streamable HTTP the cancellation signal is the client
	// closing its response stream (draft basic/utilities/cancellation
	// §Transport-Specific Cancellation). connect() negotiates the draft revision.
	client.enableModern();
	client.connect();

	bool sawFirstProgress = false;
	bool callEnded = false;
	// Count progress notifications IN-BAND so we can prove the run was truncated,
	// not just that the server's counter moved.
	int progressCount = 0;

	// Run the long call on its own task; we will close the stream from here. The
	// per-call progress sink signals when the call is in flight.
	enum int longSteps = 50;
	auto callTask = runTask(() {
		// Catch Exception only: InterruptException IS an Exception, so the intended
		// cancel signal is absorbed, but Errors propagate and fail the run instead
		// of being silently swallowed.
		try
			client.callTool("countdown", countdownArgs(longSteps, 40),
				(ProgressNotification) @safe {
				sawFirstProgress = true;
				progressCount++;
			});
		catch (Exception)
		{
			// Interrupt/disconnect aborts the in-flight read: the call ends abnormally.
		}
		callEnded = true;
	});

	int spins = 0;
	while (!sawFirstProgress && spins < 600)
	{
		sleep(5.msecs);
		spins++;
	}
	check(sawFirstProgress, "cancellation phase: never observed progress; call did not start");
	// Interrupt the call task: this unwinds the blocking SSE read and tears down
	// the underlying TCP connection — the Streamable HTTP cancellation signal.
	callTask.interrupt();

	spins = 0;
	while (!callEnded && spins < 1200)
	{
		sleep(5.msecs);
		spins++;
	}
	check(callEnded, "cancellation phase: call task never ended after interrupt");
	callTask.join();
	client.close();

	// The run must have been cut short: fewer progress notifications than a full
	// countdown would emit. This is the in-band proof of truncation.
	check(progressCount < longSteps, "cancellation phase: run must be cut short — saw "
			~ progressCount.to!string ~ " of " ~ longSteps.to!string ~ " progress notifications");

	// Poll the server's cancel counter until it increments past the pre-cancel
	// baseline, rather than trusting a fixed wall-clock sleep. Generous deadline
	// so a slow handler is not a flake.
	enum int deadlineSpins = 200; // ~10s at 50ms
	int after = cancelledBefore;
	foreach (i; 0 .. deadlineSpins)
	{
		after = readCancelCount(url);
		if (after > cancelledBefore)
			break;
		sleep(50.msecs);
	}
	check(after > cancelledBefore,
			"cancellation phase: cancel issued but server cancel_stats never incremented "
			~ "within deadline (before=" ~ cancelledBefore.to!string
			~ ", last=" ~ after.to!string ~ ")");
	return after;
}

// --- Phase D helper: read the server-side cancel counter ---------------------

private int readCancelCount(string url) @safe
{
	auto client = McpClient.http(url);
	scope (exit)
		client.close();
	client.initialize();
	auto r = client.callTool("cancel_stats");
	check(r.structuredContent.type == Json.Type.object,
			"cancel_stats must return structuredContent");
	return r.structuredContentAs!CancelStats.cancelled;
}

// --- small value types --------------------------------------------------------

private struct ProgressUpdate
{
	double value;
	double total;
	string token;
}

private struct LogEntry
{
	string level;
	string logger;
}
