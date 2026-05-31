/**
 * MRTR (Multi Round-Trip Requests, SEP-2322) example client — and self-verifying
 * end-to-end test.
 *
 * Connects to the `mrtr-server` (Streamable HTTP) in stateless draft mode and
 * exercises the `book_meeting` tool, which needs two pieces of input. The client
 * shows both the raw round-trip and the SDK's transparent completion:
 *
 *   1. First it calls `book_meeting` with NO input handlers installed, so the
 *      server's `InputRequiredResult` is surfaced verbatim. It asserts the
 *      `inputRequests` shape (ids, types, the elicitation message) and the opaque
 *      `requestState`.
 *   2. Then it installs mock `onElicitation` + `onSampling` handlers and calls
 *      again. The SDK's `callTool` MRTR loop satisfies each request, resubmits
 *      with `inputResponses` + the echoed `requestState`, and returns the FINAL
 *      `CallToolResult`. The client asserts the mocked values flowed through.
 *
 * On success it prints "OK: ..." and exits 0; any failed assertion prints what
 * differed and exits NON-ZERO. CI starts server.d in the background, then runs
 * this against it and checks the exit code.
 *
 *   dub build -c client
 *   ./mrtr-server --port 8765 &        # (built from -c server)
 *   ./mrtr-client http://127.0.0.1:8765/mcp
 */
module mrtr_client;

import std.algorithm : startsWith;
import std.stdio : stderr, writeln;
import std.string : indexOf;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;

enum string defaultUrl = "http://127.0.0.1:8765/mcp";

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
			rc = runE2E(url);
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

/// A tiny assert helper that throws (caught in main -> exit 1) with a clear
/// message describing what differed.
private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}

private int runE2E(string url) @safe
{
	auto client = McpClient.http(url);
	// Stateless draft (2026-07-28): no initialize handshake; MRTR is the input
	// mechanism. Every request carries per-request `_meta`.
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
		}
		else if (req.id == "meeting_agenda")
		{
			sawAgenda = true;
			check(req.type == "sampling",
				"meeting_agenda type: expected 'sampling', got '" ~ req.type ~ "'");
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

	// Structured content carries the same values plus the round count.
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
		writeln("OK: MRTR e2e — 2 input requests resolved, requestState echoed, ",
			"mocked elicitation+sampling flowed through, server completed in 2 rounds.");
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
