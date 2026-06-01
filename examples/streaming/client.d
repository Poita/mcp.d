/**
 * examples/streaming — client.d (self-verifying e2e test, dual-transport)
 *
 * One self-verifying client that exercises the streaming server over EITHER
 * transport, selected at runtime:
 *
 *   - STDIO (default): spawn the built `streaming-server` binary (no `--http`)
 *     and talk to it over its stdin/stdout via `McpClient.stdio`, exactly like
 *     examples/tools/client.d.
 *   - HTTP (`--http <url>`): connect to an already-running server with
 *     `McpClient.http(url)`.
 *
 * Every observation is asserted against the value the server promises; the
 * process exits NON-ZERO on any mismatch, so CI can run it as an e2e regression
 * test. The transport-agnostic phases (A/B/C) run over BOTH transports; the
 * mid-flight cancellation phase (D) is HTTP-only because it relies on tearing
 * down the per-request SSE response stream — the Streamable HTTP cancellation
 * signal. (Over stdio the server processes one request to completion before
 * reading the next line, so there is no in-flight stream to drop.)
 *
 * What it verifies, in order:
 *   A. LIST + PROGRESS + LOGGING (transport-agnostic)
 *      - `listTools()` contains `countdown`, `summarize`, `cancel_stats`, and
 *        `countdown` declares its output schema.
 *      - A `countdown` call carrying a progressToken streams EXACTLY N
 *        `notifications/progress` (monotonically increasing, echoing the token,
 *        last == total) AND N `notifications/message` (level=info, logger=
 *        "countdown") BEFORE the final result `{completed:N, total:N,
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
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.stdio : stderr, writeln;
import std.string : stripRight;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.data.json : Json;

import mcp;
import mcp.client.client : McpClient;
import mcp.protocol.errors : ErrorCode, McpException;
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult, SamplingMessage;
import mcp.protocol.types : Content, ElicitAction, ElicitParams, ElicitResult;

// Mocked sampling reply the client returns to the server's `summarize` tool, and
// the elicited values it accepts. These are the contract: the structured result
// must echo them back exactly.
enum string MockedModel = "mock-model-1";
enum string MockedSummary = "A concise mock summary.";
enum string ElicitedTone = "concise";

int main(string[] args)
{
	string httpUrl;
	getopt(args, "http", "Connect over Streamable HTTP to this MCP endpoint "
			~ "(e.g. http://127.0.0.1:9357/mcp); omit to spawn the server over stdio", &httpUrl);
	const bool useHttp = httpUrl.length != 0;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = run(useHttp, httpUrl);
		catch (Throwable t) // AssertError and exceptions both fail the e2e
		{
			try
				stderr.writeln("FAIL: ", t.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

private int run(bool useHttp, string url) @safe
{
	enum int steps = 5;

	if (useHttp)
	{
		// HTTP: each phase opens a fresh client to the running server's URL.
		const int progressSeen = phaseListProgressLogging(() => httpClient(url), steps);
		phaseTypedElicitSampling(() => httpClient(url));
		phaseErrorCode(() => httpClient(url));

		// Phase D — mid-flight cancellation, HTTP-only.
		const int cancelledBefore = readCancelCount(() => httpClient(url));
		phaseCancellation(url);
		const int cancelledAfter = readCancelCount(() => httpClient(url));
		check(cancelledAfter >= cancelledBefore + 1,
				"server's cancel_stats must increase after a mid-flight cancellation (before="
				~ cancelledBefore.to!string ~ ", after=" ~ cancelledAfter.to!string ~ ")");

		() @trusted {
			writeln("OK [http]: countdown streamed ", progressSeen, " progress + ", progressSeen,
					" log msgs; typed elicit+sample round-trip verified; unknown-tool error code; ",
					"mid-flight cancel honored (cancel_stats ", cancelledBefore, " -> ",
					cancelledAfter, ").");
		}();
		return 0;
	}

	// STDIO: spawn ONE server process and reuse ONE initialized client across the
	// transport-agnostic phases (the stdio server serves a single connection).
	auto proc = new ServerProcess([serverBinaryPath()]);
	scope (exit)
		proc.shutdown();
	auto client = stdioClient(proc);
	client.initialize();
	client.setLogLevel("debug");

	const int progressSeen = phaseListProgressLogging(() => client, steps, /*alreadyInit=*/ true);
	phaseTypedElicitSampling(() => client, /*alreadyInit=*/ true);
	phaseErrorCode(() => client, /*alreadyInit=*/ true);

	() @trusted {
		writeln("OK [stdio]: countdown streamed ", progressSeen, " progress + ", progressSeen,
				" log msgs; typed elicit+sample round-trip verified; unknown-tool error code. ",
				"(mid-flight cancellation is HTTP-only and skipped over stdio.)");
	}();
	return 0;
}

// --- transport factories -----------------------------------------------------

/// An HTTP client pinned to the released protocol (progress + logging + blocking
/// elicitation are all available there), with the mocked input handlers wired
/// BEFORE initialize so `sampling`/`elicitation` are advertised at the handshake.
private McpClient httpClient(string url) @safe
{
	auto client = McpClient.http(url);
	installMockHandlers(client);
	client.initialize();
	client.setLogLevel("debug");
	return client;
}

/// A stdio client over the spawned server process. Handlers are installed before
/// the caller initializes.
private McpClient stdioClient(ServerProcess proc) @safe
{
	auto client = McpClient.stdio(&proc.readLine, &proc.writeLine);
	installMockHandlers(client);
	return client;
}

/// Install the mocked client-side input handlers. Installing them auto-advertises
/// the `sampling` / `elicitation` capabilities at initialize, so the server's
/// blocking `ctx.elicit` / `ctx.sample` can complete.
private void installMockHandlers(McpClient client) @safe
{
	// Declare form-mode elicitation explicitly: the inbound `elicitation/create`
	// check consults the raw declared capabilities, so we set `elicitation` here
	// (a bare `elicitation` declaration is form-capable) in addition to relying on
	// the handler-driven auto-advertise.
	client.capabilities.elicitation = true;

	client.onElicitation = (ElicitParams params) @safe {
		// Accept with concrete values matching the server's flat `Confirm` struct.
		Json content = Json.emptyObject;
		content["proceed"] = true;
		content["tone"] = ElicitedTone;
		return ElicitResult.accept(content);
	};
	client.onSampling = (CreateMessageRequest request) @safe {
		// Return a typed result with a concrete model + summary text.
		return CreateMessageResult("assistant",
				[Content.makeText(MockedSummary)], MockedModel, "endTurn");
	};
}

// --- Phase A: list + progress + logging (transport-agnostic) -----------------

private int phaseListProgressLogging(scope McpClient delegate() @safe open,
		int steps, bool alreadyInit = false) @safe
{
	auto client = open();
	scope (exit)
		if (!alreadyInit)
			client.close();

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
	client.onProgress = (ProgressNotification n) @safe {
		progress ~= ProgressUpdate(n.progress, n.total.isNull ? -1 : n.total.get,
				n.progressToken.type == Json.Type.string ? n.progressToken.get!string : "");
	};
	client.onLogMessage = (LogMessageNotification n) @safe {
		logs ~= LogEntry(n.level, n.logger.isNull ? "" : n.logger.get);
	};

	auto result = client.callTool("countdown", countdownArgs(steps, 20), ProgressToken("count-1"));

	// Final structured result.
	check(result.structuredContent.type == Json.Type.object, "result must carry structuredContent");
	check(result.structuredContent["completed"].get!long == steps,
			"completed should be " ~ steps.to!string ~ ", got "
			~ result.structuredContent["completed"].to!string);
	check(result.structuredContent["total"].get!long == steps, "total should be " ~ steps.to!string);
	check(result.structuredContent["cancelled"].get!bool == false,
			"cancelled should be false on a full run");

	// Exactly `steps` progress notifications, increasing, echoing the token, last == total.
	check(progress.length == steps,
			"expected " ~ steps.to!string ~ " progress notifications, got " ~ progress.length.to!string);
	foreach (i, p; progress)
	{
		check(p.value == cast(double)(i + 1),
				"progress[" ~ i.to!string ~ "].value should be " ~ (i + 1).to!string
				~ ", got " ~ p.value.to!string);
		check(p.total == cast(double) steps, "progress total should be " ~ steps.to!string);
		check(p.token == "count-1", "progress must echo the request's progressToken 'count-1'");
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

private void phaseTypedElicitSampling(scope McpClient delegate() @safe open,
		bool alreadyInit = false) @safe
{
	auto client = open();
	scope (exit)
		if (!alreadyInit)
			client.close();

	Json a = Json.emptyObject;
	a["text"] = "The quick brown fox jumps over the lazy dog.";
	auto r = client.callTool("summarize", a);
	check(!r.isError, "summarize should not be an error");
	auto sc = r.structuredContent;
	check(sc.type == Json.Type.object, "summarize must return structuredContent");
	check(sc["status"].get!string == "summarized",
			"summarize status should be 'summarized', got " ~ sc["status"].get!string);
	check(sc["tone"].get!string == ElicitedTone,
			"summarize tone should echo the elicited '" ~ ElicitedTone ~ "', got " ~ sc["tone"].get!string);
	check(sc["model"].get!string == MockedModel,
			"summarize model should echo the mocked sampling model '" ~ MockedModel
			~ "', got " ~ sc["model"].get!string);
	check(sc["summary"].get!string == MockedSummary,
			"summarize summary should echo the mocked sampling text '" ~ MockedSummary
			~ "', got " ~ sc["summary"].get!string);
}

// --- Phase C: error code (transport-agnostic) --------------------------------

private void phaseErrorCode(scope McpClient delegate() @safe open,
		bool alreadyInit = false) @safe
{
	auto client = open();
	scope (exit)
		if (!alreadyInit)
			client.close();

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
	client.onProgress = (ProgressNotification) @safe { sawFirstProgress = true; };

	// Run the long call on its own task; we will close the stream from here.
	enum int longSteps = 50;
	auto callTask = runTask(() nothrow{
		try
			client.callTool("countdown", countdownArgs(longSteps, 40), ProgressToken("cancel-1"));
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

private int readCancelCount(scope McpClient delegate() @safe open) @safe
{
	auto client = open();
	scope (exit)
		client.close();
	auto r = client.callTool("cancel_stats");
	check(r.structuredContent.type == Json.Type.object, "cancel_stats must return structuredContent");
	return cast(int) r.structuredContent["cancelled"].get!long;
}

// --- stdio process plumbing ---------------------------------------------------

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client.
final class ServerProcess
{
	private ProcessPipes pipes;

	this(string[] command) @trusted
	{
		pipes = pipeProcess(command, Redirect.stdin | Redirect.stdout);
	}

	/// Read one response line (terminator stripped), or null at EOF.
	string readLine() @trusted
	{
		auto f = pipes.stdout;
		if (f.eof)
			return null;
		auto ln = f.readln();
		if (ln.length == 0 && f.eof)
			return null;
		return ln.stripRight("\r\n");
	}

	/// Write one request line (the channel appends the terminator).
	void writeLine(string s) @trusted
	{
		pipes.stdin.writeln(s);
		pipes.stdin.flush();
	}

	/// Close stdin and reap the child.
	void shutdown() @trusted
	{
		pipes.stdin.close();
		wait(pipes.pid);
	}
}

/// Absolute path to the `streaming-server` binary, resolved next to this client
/// binary (dub writes both into the package root).
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "streaming-server");
}

// --- small value types + helpers ---------------------------------------------

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

private Json countdownArgs(int steps, int delayMs) @safe
{
	Json a = Json.emptyObject;
	a["steps"] = steps;
	a["delayMs"] = delayMs;
	return a;
}

/// Assertion helper: throws (failing the e2e with a clear message) when `cond`
/// is false.
private void check(bool cond, string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}
