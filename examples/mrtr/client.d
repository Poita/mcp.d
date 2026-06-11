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
 * Transport selection is delegated to the shared `examples_common` scaffold:
 *   - `connectFromArgs(args, "mrtr-server")` returns an HTTP client when
 *     `--http <url>` is given, else spawns the sibling `mrtr-server` binary over
 *     stdio (`McpClient.spawnSibling`). The SAME assertions verify both.
 *   - `runClient(scenario)` drives the vibe event loop uniformly so the identical
 *     scenario body works over stdio and HTTP, mapping any thrown assertion to a
 *     non-zero exit code.
 *
 * Typed/ergonomic SDK APIs used here (args, handlers, and result decode are all
 * typed; no hand-built Json on those paths):
 *   - the call `arguments` are built as a JSON object (`bookMeetingArgs(topic)`,
 *     the untyped client request surface);
 *   - the inbound `InputRequest`s are read with the typed readers
 *     `req.elicitationMessage()` / `req.requestedSchema()` / `req.asSampling()`;
 *   - `ElicitResult.accept!MeetingDate` and `CreateMessageResult.text` build the
 *     elicitation/sampling replies;
 *   - `CallToolResult.structuredContentAs!Booking` decodes the structured result.
 *
 * On success it prints "OK: ..." and exits 0; any failed assertion prints what
 * differed and exits NON-ZERO.
 *
 *   dub build -c server && dub build -c client
 *   # stdio:
 *   dub run -c client
 *   # http:
 *   dub run -c server -- --http --port 8765 &
 *   dub run -c client -- --http http://127.0.0.1:8765/mcp
 */
module mrtr_client;

import std.conv : to;
import std.stdio : writeln;

import vibe.data.json : Json;

import mcp;

import examples_common : check, runClient, connectFromArgs;

/// `book_meeting` arguments as a JSON object (`{ "topic": topic }`). The client
/// request surface is untyped — see the repo-root `DESIGN.md`.
private Json bookMeetingArgs(string topic) @safe
{
	Json j = Json.emptyObject;
	j["topic"] = topic;
	return j;
}

/// Typed view of the elicitation answer. `ElicitResult.accept!MeetingDate(...)`
/// serializes this into the elicitation content map, mirroring the server's
/// `MeetingDate` form struct.
struct MeetingDate
{
	string date;
}

/// Typed view of the server's structured `Booking` result, decoded in one shot
/// with `CallToolResult.structuredContentAs!Booking`.
struct Booking
{
	string topic;
	string date;
	string agenda;
	int rounds;
}

int main(string[] args) @safe
{
	// The scaffold drives the event loop and maps any thrown assertion to rc 1;
	// `connectFromArgs` picks HTTP (`--http <url>`) or a spawned sibling server.
	return runClient(() @safe {
		auto client = connectFromArgs(args, "mrtr-server");
		scope (exit)
			client.close();
		return runE2E(client);
	});
}

/// The transport-agnostic e2e body: given a connected `McpClient`, exercise the
/// MRTR `book_meeting` tool end-to-end and assert every expected value. The same
/// function runs over stdio and HTTP.
private int runE2E(McpClient client) @safe
{
	// Stateless draft (2026-07-28): MRTR is the input mechanism. Every request
	// carries per-request `_meta`.
	client.enableModern();

	// Advertise the input capabilities this client can satisfy. The server only
	// includes an InputRequest the client declared support for, so we must
	// advertise elicitation + sampling for the raw-inspection call below (which
	// deliberately installs NO handlers). The no-handler call still surfaces the
	// InputRequiredResult verbatim — advertising a capability is distinct from
	// installing a handler to auto-resolve it.
	client.capabilities.elicitation = true;
	client.capabilities.elicitationForm = true;
	client.capabilities.sampling = true;

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

	// Build the arguments as a JSON object (the untyped client request surface).
	auto topicArg = bookMeetingArgs("Q3 roadmap");

	// ---- First round-trip view: no handlers -> the server's InputRequiredResult
	// is surfaced so we can assert the raw MRTR shape. ----
	auto raw = client.callTool("book_meeting", topicArg);
	check(raw.isInputRequired,
			"expected an inputRequired result on the first call with no handlers");
	check(raw.inputRequests.length == 2,
			"expected 2 input requests, got " ~ to!string(raw.inputRequests.length));

	bool sawDate, sawAgenda;
	foreach (req; raw.inputRequests)
	{
		if (req.id == "meeting_date")
		{
			sawDate = true;
			check(req.type == "elicitation",
					"meeting_date type: expected 'elicitation', got '" ~ req.type ~ "'");
			// Typed reader: read the elicitation message + requestedSchema via
			// req.elicitationMessage() / req.requestedSchema().
			check(req.elicitationMessage() == "On what date should we meet?",
					"meeting_date message mismatch: '" ~ req.elicitationMessage() ~ "'");
			// The schema was DERIVED from the server's flat MeetingDate struct via
			// InputRequest.elicitation!T, so it must expose a `date` string property.
			auto schema = req.requestedSchema();
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
			// Typed reader: decode the sampling request back into a typed
			// CreateMessageRequest via req.asSampling(). It must carry the maxTokens
			// and user message the server set.
			auto sreq = req.asSampling();
			check(!sreq.maxTokens.isNull && sreq.maxTokens.get == 64,
					"meeting_agenda maxTokens: expected 64");
			check(sreq.messages.length == 1 && sreq.messages[0].role == "user",
					"meeting_agenda should carry one user sampling message");
		}
	}
	check(sawDate, "missing 'meeting_date' input request");
	check(sawAgenda, "missing 'meeting_agenda' input request");

	// SEP-2322: requestState is server-owned and opaque — the client MUST NOT
	// parse it, only echo it verbatim. This server also runs `secureRequestState`,
	// so the blob is a signed+expiring envelope the client could not read even if
	// it tried. We assert only that a blob is present to echo; that the server
	// correctly recovered the stashed topic from the verified blob is proven
	// end-to-end by the final result assertions below (`Booking.topic`).
	check(raw.requestState.length > 0, "expected an opaque requestState blob to echo back");

	// ---- Second round-trip view: install mock handlers; the SDK completes the loop. ----
	// Installing onElicitation/onSampling alone auto-advertises the matching
	// capabilities (effectiveCapabilities), so no raw flag-setting is needed.
	// The elicitation handler returns the meeting date via the typed accept!T
	// builder; the sampling handler returns the agenda via CreateMessageResult.text.
	// These mocked values must flow through to the result.
	client.onElicitation = (ElicitParams p) @safe {
		return ElicitResult.accept(MeetingDate("2026-06-15"));
	};
	client.onSampling = (CreateMessageRequest req) @safe {
		return CreateMessageResult.text("mock-llm", "Review Q3 milestones and assign owners.");
	};

	auto done = client.callTool("book_meeting", topicArg);
	check(!done.isInputRequired, "second call should have completed, but still wants input");
	check(!done.isError, "completed result unexpectedly flagged isError");
	check(done.content.length == 1,
			"expected 1 content block, got " ~ to!string(done.content.length));

	const text = done.content[0].text();
	const expectedText = "Booked 'Q3 roadmap' on 2026-06-15. Agenda: Review Q3 milestones and assign owners.";
	check(text == expectedText,
			"final text mismatch.\n  expected: " ~ expectedText ~ "\n  got:      " ~ text);

	// Structured content carries the same values plus the round count. Decode it
	// in one shot into the typed Booking struct and assert on the fields.
	auto booking = done.structuredContentAs!Booking;
	check(booking.topic == "Q3 roadmap", "structured topic mismatch: '" ~ booking.topic ~ "'");
	check(booking.date == "2026-06-15", "structured date mismatch: '" ~ booking.date ~ "'");
	check(booking.agenda == "Review Q3 milestones and assign owners.",
			"structured agenda mismatch: '" ~ booking.agenda ~ "'");
	check(booking.rounds == 2, "structured rounds mismatch: " ~ to!string(booking.rounds));

	() @trusted {
		writeln("OK: MRTR e2e — 2 input requests resolved (schema derived from struct), ",
				"requestState echoed, mocked elicitation+sampling flowed through, ",
				"server completed in 2 rounds.");
	}();
	return 0;
}
