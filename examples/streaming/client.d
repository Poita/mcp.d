/**
 * examples/streaming — client.d (self-verifying e2e test)
 *
 * Connects to `streaming-server` over Streamable HTTP and exercises the
 * "Progress / logging / cancellation" features from the consumer's eye view.
 * It is NOT just a demo: every observation is asserted against the value the
 * server promises, and the process exits NON-ZERO on any mismatch, so CI can
 * run it as an end-to-end regression test.
 *
 * Two-step run (see README):
 *   terminal 1:  dub run -c server
 *   terminal 2:  dub run -c client          # exits 0 on OK, non-zero on mismatch
 *
 * What it verifies, in order:
 *   A. PROGRESS + LOGGING (released protocol 2025-11-25)
 *      - `listTools()` contains `countdown` (with its declared output schema).
 *      - A `countdown` call carrying a progressToken streams EXACTLY N
 *        `notifications/progress` (monotonically increasing, echoing the token,
 *        last == total) AND N `notifications/message` (level=info, logger=
 *        "countdown") BEFORE the final result, whose structuredContent is
 *        `{completed:N, total:N, cancelled:false}`.
 *   B. CANCELLATION (draft protocol — disconnect IS the cancel signal on
 *      Streamable HTTP, per basic/utilities/cancellation §Transport-Specific
 *      Cancellation). A long `countdown` is started on its own task; after the
 *      first progress proves it is in flight, the client closes its stream. The
 *      server observes the disconnect via `ctx.isCancelled`, stops early, and
 *      bumps its cancel counter.
 *   C. VERIFY + HEALTH (fresh released client)
 *      - `cancel_stats` reports `cancelled >= 1` — concrete server-side proof
 *        the mid-flight cancellation was honored.
 *      - A fresh `countdown` still returns a full result (server healthy).
 */
module streaming_client;

import core.time : msecs;
import std.algorithm : startsWith;
import std.conv : to;
import std.stdio : stderr, writeln;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.data.json : Json;

import mcp;
import mcp.protocol.errors : McpException;

enum string defaultUrl = "http://127.0.0.1:9357/mcp";

int main(string[] args)
{
	string url = defaultUrl;
	foreach (a; args[1 .. $])
		if (a.startsWith("http://") || a.startsWith("https://"))
			url = a;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = run(url);
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

private int run(string url) @safe
{
	enum int steps = 5;
	const int progressSeen = phaseProgressAndLogging(url, steps);

	const int cancelledBefore = readCancelCount(url);
	phaseCancellation(url);
	const int cancelledAfter = readCancelCount(url);
	check(cancelledAfter >= cancelledBefore + 1,
			"server's cancel_stats must increase after a mid-flight cancellation (before="
			~ cancelledBefore.to!string ~ ", after=" ~ cancelledAfter.to!string ~ ")");

	phaseHealthCheck(url);

	() @trusted {
		writeln("OK: countdown streamed ", progressSeen, " progress + ", progressSeen,
				" log msgs (released); mid-flight cancel honored (cancel_stats ",
				cancelledBefore, " -> ", cancelledAfter, "); server healthy after cancel.");
	}();
	return 0;
}

// --- Phase A: progress + logging on a released-protocol client -------------

private int phaseProgressAndLogging(string url, int steps) @safe
{
	auto client = McpClient.http(url);
	scope (exit)
		client.close();
	// Pin a released version (2025-11-25): progress + logging notifications and
	// `logging/setLevel` are all available. (The draft revision drops setLevel
	// and gates logging on a per-request _meta field, so we initialize a stable
	// version here rather than letting connect() negotiate the newest.)
	client.initialize();
	client.setLogLevel("debug"); // accept every level so the info logs flow

	auto tools = client.listTools().tools;
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

	auto result = client.callTool("countdown", args(steps, 20), ProgressToken("count-1"));

	// Final structured result.
	check(result.structuredContent.type == Json.Type.object, "result must carry structuredContent");
	check(result.structuredContent["completed"].get!long == steps,
			"completed should be " ~ steps.to!string ~ ", got "
			~ result.structuredContent["completed"].to!string);
	check(result.structuredContent["total"].get!long == steps, "total should be " ~ steps.to!string);
	check(result.structuredContent["cancelled"].get!bool == false, "cancelled should be false on a full run");

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

// --- Phase B: cancellation via stream disconnect (draft protocol) ----------

private void phaseCancellation(string url) @trusted
{
	auto client = McpClient.http(url);
	// Draft mode: on Streamable HTTP the cancellation signal is the client
	// closing its response stream (draft basic/utilities/cancellation
	// §Transport-Specific Cancellation: "Closing the SSE response stream is the
	// cancellation signal. The server MUST treat a client disconnect as
	// cancellation of that request"). connect() negotiates the draft revision.
	client.enableDraft();
	client.connect();

	bool sawFirstProgress = false;
	bool callEnded = false;
	client.onProgress = (ProgressNotification) @safe { sawFirstProgress = true; };

	// Run the long call on its own task; we will close the stream from here.
	enum int longSteps = 50;
	auto callTask = runTask(() nothrow{
		try
		{
			// 50 steps * 40ms = 2s of work — ample time to disconnect mid-flight.
			client.callTool("countdown", args(longSteps, 40), ProgressToken("cancel-1"));
		}
		catch (Throwable)
		{
			// Closing the stream aborts the in-flight read: the call ends abnormally.
		}
		callEnded = true;
	});

	// Wait until the first progress proves the call is in flight, then close the
	// stream — the cancellation signal the server reacts to.
	int spins = 0;
	while (!sawFirstProgress && spins < 600)
	{
		sleep(5.msecs);
		spins++;
	}
	check(sawFirstProgress, "cancellation phase: never observed progress; call did not start");
	// Interrupt the call task: this unwinds the blocking SSE read and tears down
	// the underlying TCP connection. The dropped response stream is exactly the
	// Streamable HTTP cancellation signal the server reacts to via ctx.isCancelled.
	callTask.interrupt();

	// Let the task unwind and the server observe the disconnect on its next poll.
	while (!callEnded && spins < 1200)
	{
		sleep(5.msecs);
		spins++;
	}
	// Give the server a beat to run its post-disconnect isCancelled check, then
	// release the transport.
	sleep(300.msecs);
	callTask.join();
	client.close();
}

// --- Phase C helpers: read the server-side cancel counter / health ----------

private int readCancelCount(string url) @safe
{
	auto client = McpClient.http(url);
	scope (exit)
		client.close();
	client.initialize();
	auto r = client.callTool("cancel_stats");
	check(r.structuredContent.type == Json.Type.object, "cancel_stats must return structuredContent");
	return cast(int) r.structuredContent["cancelled"].get!long;
}

private void phaseHealthCheck(string url) @safe
{
	auto client = McpClient.http(url);
	scope (exit)
		client.close();
	client.initialize();
	auto after = client.callTool("countdown", args(3, 10));
	check(after.structuredContent["completed"].get!long == 3,
			"server must still serve calls after a cancellation");
	check(after.structuredContent["cancelled"].get!bool == false, "follow-up call must not be cancelled");
}

// --- small value types + helpers --------------------------------------------

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

private Json args(int steps, int delayMs) @safe
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
