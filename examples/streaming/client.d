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
 * The event-loop wiring (runTask / runEventLoop / catch->rc) is provided by the
 * scaffold's `runClient`, and the assertion helper `check` is the scaffold's —
 * this file no longer hand-rolls either.
 *
 * Every observation is asserted against the value the server promises; the
 * process exits NON-ZERO on any mismatch, so CI can run it as an e2e regression
 * test. The transport-agnostic phases (A/B/C) run over BOTH transports; the
 * mid-flight cancellation phase (D) runs over HTTP, where the cancel signal is
 * tearing down the per-request SSE response stream (a client disconnect). Over
 * stdio the cancel signal is instead a `notifications/cancelled` message, which
 * the SDK server now honours mid-handler via its cooperative input drain (see
 * the `serveStdio` cancellation unittest); this client keeps phase D HTTP-only
 * only because its simple synchronous stdio client cannot inject a notification
 * while a `callTool` is in flight — not an SDK limitation.
 *
 * Typed/ergonomic SDK APIs adopted here:
 *   - per-call progress sink: `callTool(name, args, onProgress)` (#494) delivers
 *     THIS call's progress to a local callback, replacing a global
 *     `client.onProgress` + manual token correlation.
 *   - `result.structuredContentAs!T` decodes structured output into a struct
 *     instead of field-by-field raw-Json reads (#464).
 *   - typed `callTool(name, T args)` passes a struct for the static-shape calls
 *     (#468).
 *   - `ElicitResult.accept(T)` / `CreateMessageResult.text(model, text)` build
 *     the mocked client replies from typed values (#466/#467).
 *   - Installing `onElicitation` alone advertises elicitation; the inbound gate
 *     honours `effectiveCapabilities()` (#463), so no redundant raw flag-set.
 *
 * What it verifies, in order:
 *   A. LIST + PROGRESS + LOGGING (transport-agnostic)
 *      - `listTools()` contains `countdown`, `summarize`, `cancel_stats`, and
 *        `countdown` declares its output schema.
 *      - A `countdown` call with a per-call progress sink streams EXACTLY N
 *        `notifications/progress` (monotonically increasing, last == total,
 *        carrying a progress token) AND N `notifications/message` (level=info,
 *        logger="countdown") BEFORE the final result `{completed:N, total:N,
 *        cancelled:false}`.
 *   B. TYPED ELICITATION + SAMPLING round-trip (transport-agnostic)
 *      - `summarize` opens a blocking server->client elicitation; the client's
 *        mocked `onElicitation` accepts with concrete values, then its mocked
 *        `onSampling` returns a concrete model + text. The structured result
 *        echoes those mocked values exactly.
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
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
import mcp.protocol.types : ElicitParams, ElicitResult;

import examples_common : check, runClient, connectFromArgs;

// Mocked sampling reply the client returns to the server's `summarize` tool, and
// the elicited values it accepts. These are the contract: the structured result
// must echo them back exactly.
enum string MockedModel = "mock-model-1";
enum string MockedSummary = "A concise mock summary.";
enum string ElicitedTone = "concise";

// Typed mirrors of the server's structures, used for typed callTool args
// (#468), structuredContentAs!T decoding (#464), and the elicitation accept
// content (#466). They match the server's field names exactly.

/// `countdown` arguments.
struct CountdownArgs
{
	int steps;
	int delayMs;
}

/// `countdown` final structured result.
struct CountdownResult
{
	int completed;
	int total;
	bool cancelled;
}

/// `summarize` arguments.
struct SummarizeArgs
{
	string text;
}

/// `summarize` structured result.
struct SummaryResult
{
	string status;
	string tone;
	string model;
	string summary;
}

/// `cancel_stats` structured result.
struct CancelStats
{
	int cancelled;
}

/// The flat elicitation content the server's `summarize` tool collects.
struct Confirm
{
	bool proceed;
	string tone;
}

int main(string[] args) @safe
{
	// Detect the HTTP URL (if any) up front: phase D (mid-flight cancellation) is
	// HTTP-only and needs to open its OWN draft-mode client to the same URL. The
	// transport for phases A/B/C is chosen by the scaffold's `connectFromArgs`.
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
	// over stdio. Handlers are installed BEFORE initialize so the
	// `sampling`/`elicitation` capabilities are advertised at the handshake.
	auto client = connectFromArgs(args, "streaming-server");
	scope (exit)
		client.close();
	installMockHandlers(client);
	client.initialize();
	client.setLogLevel("debug");

	const int progressSeen = phaseListProgressLogging(client, steps);
	phaseTypedElicitSampling(client);
	phaseErrorCode(client);

	if (useHttp)
	{
		// Phase D — mid-flight cancellation, HTTP-only (disconnect is the signal).
		const int cancelledBefore = readCancelCount(httpUrl);
		phaseCancellation(httpUrl);
		const int cancelledAfter = readCancelCount(httpUrl);
		check(cancelledAfter >= cancelledBefore + 1,
				"server's cancel_stats must increase after a mid-flight cancellation (before="
				~ cancelledBefore.to!string ~ ", after=" ~ cancelledAfter.to!string ~ ")");

		report("OK [http]: countdown streamed " ~ progressSeen.to!string ~ " progress + "
				~ progressSeen.to!string ~ " log msgs; typed elicit+sample round-trip verified; "
				~ "unknown-tool error code; mid-flight cancel honored (cancel_stats "
				~ cancelledBefore.to!string ~ " -> " ~ cancelledAfter.to!string ~ ").");
		return 0;
	}

	report("OK [stdio]: countdown streamed " ~ progressSeen.to!string ~ " progress + "
			~ progressSeen.to!string ~ " log msgs; typed elicit+sample round-trip verified; "
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

// --- mocked client-side input handlers ---------------------------------------

/// Install the mocked client-side input handlers. Installing them is sufficient:
/// the handlers auto-advertise the `sampling` / `elicitation` capabilities at
/// initialize, and the inbound `elicitation/create` gate honours
/// `effectiveCapabilities()` (#463) — so no redundant raw flag-setting is needed.
private void installMockHandlers(McpClient client) @safe
{
	client.onElicitation = (ElicitParams params) @safe {
		// Accept with concrete values matching the server's flat `Confirm` struct.
		return ElicitResult.accept(Confirm(true, ElicitedTone));
	};
	client.onSampling = (CreateMessageRequest request) @safe {
		// Return a typed result with a concrete model + summary text.
		return CreateMessageResult.text(MockedModel, MockedSummary);
	};
}

// --- Phase A: list + progress + logging (transport-agnostic) -----------------

private int phaseListProgressLogging(McpClient client, int steps) @safe
{
	auto tools = client.listTools().tools;
	auto names = tools.map!(t => t.name).array;
	foreach (want; ["countdown", "summarize", "cancel_stats"])
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

	// Per-call progress sink (#494): the SDK mints a unique progressToken for THIS
	// call and routes only its progress notifications to this callback for the
	// duration of the call — no global client.onProgress + manual token matching.
	auto result = client.callTool("countdown", CountdownArgs(steps, 20),
			(ProgressNotification n) @safe {
		progress ~= ProgressUpdate(n.progress, n.total.isNull
			? -1 : n.total.get, n.progressTokenString);
	});

	// Final structured result, decoded into the typed CountdownResult (#464).
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

// --- Phase B: typed elicitation + sampling round-trip (transport-agnostic) ----

private void phaseTypedElicitSampling(McpClient client) @safe
{
	auto r = client.callTool("summarize",
			SummarizeArgs("The quick brown fox jumps over the lazy dog."));
	check(!r.isError, "summarize should not be an error");
	check(r.structuredContent.type == Json.Type.object, "summarize must return structuredContent");
	const sc = r.structuredContentAs!SummaryResult;
	check(sc.status == "summarized", "summarize status should be 'summarized', got " ~ sc.status);
	check(sc.tone == ElicitedTone,
			"summarize tone should echo the elicited '" ~ ElicitedTone ~ "', got " ~ sc.tone);
	check(sc.model == MockedModel,
			"summarize model should echo the mocked sampling model '"
			~ MockedModel ~ "', got " ~ sc.model);
	check(sc.summary == MockedSummary, "summarize summary should echo the mocked sampling text '"
			~ MockedSummary ~ "', got " ~ sc.summary);
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

private void phaseCancellation(string url) @trusted
{
	auto client = McpClient.http(url);
	// Draft mode: on Streamable HTTP the cancellation signal is the client
	// closing its response stream (draft basic/utilities/cancellation
	// §Transport-Specific Cancellation). connect() negotiates the draft revision.
	client.enableDraft();
	client.connect();

	bool sawFirstProgress = false;
	bool callEnded = false;

	// Run the long call on its own task; we will close the stream from here. The
	// per-call progress sink (#494) signals when the call is in flight.
	enum int longSteps = 50;
	auto callTask = runTask(() nothrow{
		try
			client.callTool("countdown", CountdownArgs(longSteps, 40),
				(ProgressNotification) @safe { sawFirstProgress = true; });
		catch (Throwable)
		{
			// Closing the stream aborts the in-flight read: the call ends abnormally.
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

	while (!callEnded && spins < 1200)
	{
		sleep(5.msecs);
		spins++;
	}
	sleep(300.msecs);
	callTask.join();
	client.close();
}

// --- Phase C/D helpers: read the server-side cancel counter -------------------

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
