/**
 * MCP Tasks example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `tasks-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `tasks-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Two complementary async input patterns are exercised:
 *
 *   1. SEP-2663 async tasks — `callToolAwait` calls the tool, detects the
 *      `CreateTaskResult`, polls `tasks/get` until completed, and returns the
 *      final `CallToolResult`. Tested via `word_count` and `slow_reverse`.
 *
 *   2. SEP-2322 MRTR stateless elicitation — `callTool` has the MRTR loop built
 *      in: when the server returns `InputRequiredResult`, the SDK gathers answers
 *      from the installed handlers and resubmits transparently. Tested via
 *      `labeled_word_count`:
 *        a. First called with no handler installed to inspect the raw
 *           `InputRequiredResult` shape (input requests + requestState blob).
 *        b. Then `onElicitation` is installed and the call is repeated; the SDK
 *           loop satisfies round 1 and returns the completed round-2 result.
 *
 * Assertions verified:
 *   - `server/discover` advertises the tasks extension under `capabilities`.
 *   - `callToolAwait("word_count", ...)` returns correct word/character counts.
 *   - `callToolAwait("slow_reverse", ...)` returns the fully reversed string.
 *   - `callTool("labeled_word_count", ...)` surfaces `isInputRequired` on the
 *     first call (no handler), with the correct request id and type.
 *   - With handler installed, `callTool("labeled_word_count", ...)` completes
 *     with the label supplied by the handler and the correct counts.
 *   - `isTaskResult` correctly identifies a `CreateTaskResult` JSON object.
 */
module tasks_client;

import std.conv : to;
import std.stdio : writeln;

import vibe.data.json : Json;

import mcp;
import examples_common : check, checkEq, runClient, connectFromArgs;

/// Typed view of the `word_count` structured result.
struct WordCountResult
{
	int words;
	int chars;
}

/// Typed view of the `slow_reverse` structured result.
struct ReverseResult
{
	string reversed;
	bool cancelled;
}

/// Elicitation answer for `labeled_word_count` — mirrors the server's
/// `LabelOptions` form struct so `ElicitResult.accept!LabelOptions` builds the
/// correct wire payload.
struct LabelOptions
{
	string label;
}

/// Typed view of the `labeled_word_count` structured result.
struct LabeledCount
{
	string label;
	int words;
	int chars;
}

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "tasks-server");
		scope (exit)
			client.close();

		// The tasks extension is draft-only: switch to the stateless draft
		// protocol and declare the tasks extension in client capabilities before
		// version negotiation.
		client.enableModern();
		client.enableTasks();

		// Advertise elicitation capability before discover() so the server
		// includes elicitation InputRequests for clients that support it.
		client.capabilities.elicitation = true;
		client.capabilities.elicitationForm = true;

		// --- 1. server/discover: tasks extension must be advertised ---------
		auto disc = client.discover();
		checkEq(disc.serverInfo.name, "tasks-example", "discover.serverInfo.name");

		import mcp.protocol.capabilities : tasksExtensionKey;

		auto caps = disc.capabilities.toJson();
		check("extensions" in caps && caps["extensions"].type == Json.Type.object,
			"discover should include extensions in capabilities");
		check((tasksExtensionKey in caps["extensions"]) !is null,
			"discover capabilities.extensions should contain the tasks extension key");

		// --- 2. connect(): negotiate draft ----------------------------------
		auto negotiated = client.connect();
		checkEq(negotiated, ProtocolVersion.modern, "connect() should negotiate draft");

		// --- 3. word_count (async task, no user input required) -------------
		// `callToolAwait` detects the `CreateTaskResult`, polls `tasks/get`
		// until the task moves to `completed`, and returns the final
		// `CallToolResult` decoded from the task's structured result.
		{
			Json a = Json.emptyObject;
			a["text"] = "the quick brown fox jumps over the lazy dog";
			auto r = client.callToolAwait("word_count", a);
			check(!r.isError, "word_count should not be an error");
			auto wc = r.structuredContentAs!WordCountResult;
			checkEq(wc.words, 9, "word_count.words");
			checkEq(wc.chars, 43, "word_count.chars");
		}

		// --- 4. slow_reverse (async task, runs to completion) ---------------
		// A short string so the e2e test finishes quickly (5 chars × 10 ms).
		{
			Json a = Json.emptyObject;
			a["text"] = "hello";
			auto r = client.callToolAwait("slow_reverse", a);
			check(!r.isError, "slow_reverse should not be an error");
			auto rv = r.structuredContentAs!ReverseResult;
			checkEq(rv.reversed, "olleh", "slow_reverse.reversed");
			check(!rv.cancelled, "slow_reverse completed normally (not cancelled)");
		}

		// --- 5. labeled_word_count (MRTR / stateless elicitation) -----------
		// Round a: no handler installed → `callTool` surfaces the raw
		// `InputRequiredResult` so we can inspect the request shape.
		{
			auto raw = client.callTool("labeled_word_count", Json([
					"text": Json("hello world")
			]));
			check(raw.isInputRequired,
				"labeled_word_count round 1 should return InputRequiredResult");
			check(raw.inputRequests.length == 1,
				"labeled_word_count should have 1 input request, got " ~ to!string(
				raw.inputRequests.length));
			check(raw.inputRequests[0].id == "label_req",
				"input request id should be 'label_req', got '" ~ raw.inputRequests[0].id ~ "'");
			check(raw.inputRequests[0].type == "elicitation",
				"input request type should be 'elicitation', got '" ~ raw.inputRequests[0].type
				~ "'");
			// The schema is derived from the server's `LabelOptions` struct; it
			// must expose a `label` string property.
			auto schema = raw.inputRequests[0].requestedSchema();
			check(schema.type == Json.Type.object,
				"labeled_word_count requestedSchema should be a JSON object");
			check(("label" in schema["properties"]) !is null,
				"labeled_word_count requestedSchema should expose a 'label' property");
			check(raw.requestState.length > 0,
				"labeled_word_count round 1 should carry a requestState blob");
		}

		// Round b: install handler → the SDK MRTR loop satisfies round 1 and
		// returns the completed round-2 result directly.
		client.onElicitation = (ElicitParams p) @safe {
			return ElicitResult.accept(LabelOptions("my-label"));
		};
		{
			auto done = client.callTool("labeled_word_count", Json([
					"text": Json("hello world")
			]));
			check(!done.isInputRequired,
				"labeled_word_count with handler should have completed, not returned InputRequired");
			check(!done.isError, "labeled_word_count should not be an error");
			auto lc = done.structuredContentAs!LabeledCount;
			checkEq(lc.label, "my-label", "labeled_word_count.label");
			checkEq(lc.words, 2, "labeled_word_count.words");
			checkEq(lc.chars, 11, "labeled_word_count.chars");
		}

		// --- 6. isTaskResult discriminator ----------------------------------
		{
			check(McpClient.isTaskResult(Json([
				"resultType": Json("task"),
				"taskId": Json("x"),
				"status": Json("working")
			])), "isTaskResult should be true for resultType:\"task\"");
			check(!McpClient.isTaskResult(Json(["content": Json.emptyArray])),
				"isTaskResult should be false for a regular CallToolResult");
			check(!McpClient.isTaskResult(Json(["resultType": Json("complete")])),
				"isTaskResult should be false for resultType:\"complete\"");
		}

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: tasks example e2e passed over ", http
			? "http" : "stdio",
			" — tasks extension advertised, word_count async task (9 words/43 chars),",
			" slow_reverse async task (\"hello\"->\"olleh\"),",
			" labeled_word_count MRTR (raw InputRequired shape + handler completion),",
			" isTaskResult discriminator all verified.");
		return 0;
	});
}
