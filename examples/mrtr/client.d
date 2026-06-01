/**
 * MRTR (Multi Round-Trip Requests, SEP-2322) example client — and self-verifying
 * end-to-end test, over BOTH transports.
 *
 * Exercises the `book_meeting` tool, which needs two pieces of input. The client
 * shows both the raw round-trip and the SDK's transparent completion:
 *
 *   1. First it calls `book_meeting` with NO input handlers installed, so the
 *      server's `InputRequiredResult` is surfaced verbatim. It asserts the
 *      `inputRequests` shape (ids, types, the elicitation message + the schema
 *      derived from the server's flat struct) and the opaque `requestState`.
 *   2. Then it installs mock `onElicitation` + `onSampling` handlers and calls
 *      again. The SDK's `callTool` MRTR loop satisfies each request, resubmits
 *      with `inputResponses` + the echoed `requestState`, and returns the FINAL
 *      `CallToolResult`. The client asserts the mocked values flowed through.
 *
 * Transport selection (the SAME assertions verify both):
 *   - default (no --http): STDIO. The client SPAWNS the built `mrtr-server`
 *     binary (with no --http) and speaks newline-delimited JSON-RPC over the pipe
 *     via `McpClient.stdio` (the pattern from examples/tools/client.d).
 *   - `--http <url>`: connect to a running HTTP server via `McpClient.http(url)`.
 *
 * On success it prints "OK: ..." and exits 0; any failed assertion prints what
 * differed and exits NON-ZERO.
 *
 *   dub build -c server && dub build -c client
 *   # stdio:
 *   ./mrtr-client
 *   # http:
 *   ./mrtr-server --http --port 8765 &
 *   ./mrtr-client --http http://127.0.0.1:8765/mcp
 */
module mrtr_client;

import std.getopt : getopt;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.stdio : stderr, writeln;
import std.string : stripRight;

import vibe.data.json : Json;

import mcp;

enum string defaultHttpUrl = "http://127.0.0.1:8765/mcp";

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client (a stack
/// value would be destructed when the spawning helper returns).
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

/// Absolute path to the `mrtr-server` binary, resolved next to this executable
/// (dub writes both binaries into the package root).
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "mrtr-server");
}

int main(string[] args)
{
	string url;
	getopt(args, "http", "Connect over Streamable HTTP at this URL instead of spawning the server over stdio", &url);

	if (url.length)
		return runHttp(url);
	return runStdio();
}

/// HTTP transport: connect to an already-running server, then run the shared
/// assertions inside vibe's event loop (the HTTP client requires it).
private int runHttp(string url)
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			auto client = McpClient.http(url);
			rc = runE2E(client);
		}
		catch (Throwable e)
		{
			try
				stderr.writeln("FAIL: ", e.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

/// STDIO transport: spawn the built server binary (no --http) and drive it over
/// the pipe. No event loop is needed for the stdio client.
private int runStdio()
{
	auto proc = new ServerProcess([serverBinaryPath()]);
	scope (exit)
		proc.shutdown();

	try
	{
		auto client = McpClient.stdio(&proc.readLine, &proc.writeLine);
		return runE2E(client);
	}
	catch (Throwable e)
	{
		try
			stderr.writeln("FAIL: ", e.msg);
		catch (Exception)
		{
		}
		return 1;
	}
}

/// A tiny assert helper that throws (caught by the transport driver -> exit 1)
/// with a clear message describing what differed.
private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}

/// The transport-agnostic e2e body: given a connected `McpClient`, exercise the
/// MRTR `book_meeting` tool end-to-end and assert every expected value. The same
/// function runs over stdio and HTTP.
private int runE2E(McpClient client) @safe
{
	// Stateless draft (2026-07-28): MRTR is the input mechanism. Every request
	// carries per-request `_meta`.
	client.enableDraft();

	// ---- discovery: the server advertises the draft version + its identity ----
	auto disc = client.discover();
	check(disc.serverInfo.name == "mrtr-example",
		"server name: expected 'mrtr-example', got '" ~ disc.serverInfo.name ~ "'");

	// ---- the tool is listed with the expected name + required arg ----
	auto tools = client.listTools().tools;
	bool found;
	foreach (t; tools)
		if (t.name == "book_meeting")
			found = true;
	check(found, "listTools did not contain 'book_meeting'");

	Json topicArg = Json.emptyObject;
	topicArg["topic"] = Json("Q3 roadmap");

	// ---- Round-trip view #1: no handlers -> the server's InputRequiredResult is
	// surfaced so we can assert the raw MRTR shape. ----
	auto raw = client.callTool("book_meeting", topicArg);
	check(raw.isInputRequired,
		"expected an inputRequired result on the first call with no handlers");
	check(raw.inputRequests.length == 2,
		"expected 2 input requests, got " ~ itoa(raw.inputRequests.length));

	bool sawDate, sawAgenda;
	foreach (req; raw.inputRequests)
	{
		if (req.id == "meeting_date")
		{
			sawDate = true;
			check(req.type == "elicitation",
				"meeting_date type: expected 'elicitation', got '" ~ req.type ~ "'");
			check(req.params["message"].get!string == "On what date should we meet?",
				"meeting_date message mismatch: '" ~ req.params["message"].get!string ~ "'");
			// The schema was DERIVED from the server's flat MeetingDate struct via
			// InputRequest.elicitation!T, so it must expose a `date` string property.
			auto schema = req.params["requestedSchema"];
			check(schema.type == Json.Type.object,
				"meeting_date requestedSchema should be an object");
			check(("date" in schema["properties"]) !is null,
				"meeting_date requestedSchema should expose a 'date' property");
		}
		else if (req.id == "meeting_agenda")
		{
			sawAgenda = true;
			check(req.type == "sampling",
				"meeting_agenda type: expected 'sampling', got '" ~ req.type ~ "'");
			// The sampling request was built from a typed CreateMessageRequest:
			// it must carry the maxTokens and the user message we set.
			check(req.params["maxTokens"].get!int == 64,
				"meeting_agenda maxTokens: expected 64, got " ~ itoa(req.params["maxTokens"].get!int));
		}
	}
	check(sawDate, "missing 'meeting_date' input request");
	check(sawAgenda, "missing 'meeting_agenda' input request");

	// SEP-2322: the opaque requestState the server stashed (it encoded the topic).
	check(raw.requestState == "topic=Q3 roadmap",
		"requestState mismatch: '" ~ raw.requestState ~ "'");

	// ---- Round-trip view #2: install mock handlers; the SDK completes the loop. ----
	// The elicitation handler returns the meeting date; the sampling handler
	// returns the agenda. These mocked values must flow through to the result.
	client.onElicitation = (ElicitParams p) @safe {
		Json content = Json.emptyObject;
		content["date"] = Json("2026-06-15");
		return ElicitResult.accept(content);
	};
	client.onSampling = (CreateMessageRequest req) @safe {
		CreateMessageResult r;
		r.role = "assistant";
		r.content = Content.makeText("Review Q3 milestones and assign owners.");
		r.model = "mock-llm";
		r.stopReason = "endTurn";
		return r;
	};

	auto done = client.callTool("book_meeting", topicArg);
	check(!done.isInputRequired,
		"second call should have completed, but still wants input");
	check(!done.isError, "completed result unexpectedly flagged isError");
	check(done.content.length == 1,
		"expected 1 content block, got " ~ itoa(done.content.length));

	const text = done.content[0].text();
	const expectedText =
		"Booked 'Q3 roadmap' on 2026-06-15. Agenda: Review Q3 milestones and assign owners.";
	check(text == expectedText,
		"final text mismatch.\n  expected: " ~ expectedText ~ "\n  got:      " ~ text);

	// Structured content carries the same values plus the round count (serialized
	// from the server's typed Booking struct).
	auto sc = done.structuredContent;
	check(sc.type == Json.Type.object, "expected structuredContent object");
	check(sc["topic"].get!string == "Q3 roadmap",
		"structured topic mismatch: '" ~ sc["topic"].get!string ~ "'");
	check(sc["date"].get!string == "2026-06-15",
		"structured date mismatch: '" ~ sc["date"].get!string ~ "'");
	check(sc["agenda"].get!string == "Review Q3 milestones and assign owners.",
		"structured agenda mismatch: '" ~ sc["agenda"].get!string ~ "'");
	check(sc["rounds"].get!int == 2,
		"structured rounds mismatch: " ~ itoa(sc["rounds"].get!int));

	client.close();
	() @trusted {
		writeln("OK: MRTR e2e — 2 input requests resolved (schema derived from struct), ",
			"requestState echoed, mocked elicitation+sampling flowed through, ",
			"server completed in 2 rounds.");
	}();
	return 0;
}

/// Minimal integer-to-string for assertion messages (avoids pulling std.conv
/// into @safe error paths).
private string itoa(long n) @safe
{
	import std.conv : to;

	return n.to!string;
}
