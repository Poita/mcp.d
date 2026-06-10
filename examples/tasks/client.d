/**
 * MCP Tasks example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `tasks-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `tasks-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Exercises the SEP-2663 task flow against the server's three `@task` tools:
 *
 *   1. word_count — `callToolAwait` calls the tool, detects the CreateTaskResult,
 *      polls `tasks/get` to completion, and returns the final CallToolResult.
 *   2. slow_reverse — same await flow; verifies the reversed string. A second
 *      call then skips the await helper: plain `callTool` returns the task handle
 *      directly (`CallToolResult.isTask`/`task`), the `taskId` is persisted, and
 *      `awaitTask` resumes polling from that bare id — the post-restart path.
 *   3. labeled_count — a task that needs input MID-EXECUTION. `callToolAwait`
 *      surfaces the task's `inputRequests` (an elicitation) through its
 *      `onInputRequired` callback; the client answers via `respondTaskInput`
 *      (`tasks/update`) and keeps polling until the resumed task completes.
 *
 * The tasks extension is draft-only, so the client enables the draft protocol
 * (`enableModern`) and declares the extension (`enableTasks`) before negotiation.
 *
 * Assertions verified:
 *   - `server/discover` advertises the tasks extension under `capabilities`.
 *   - word_count returns the expected word/character counts.
 *   - slow_reverse returns the fully reversed string (not cancelled).
 *   - a `callTool` task handle exposes `task.taskId`, which `awaitTask` resumes
 *     from a bare id (the persist-then-restart path) to the same final result.
 *   - labeled_count surfaces an elicitation mid-task, and after the client
 *     answers it completes with the supplied label and correct counts.
 *   - `isTaskResult` correctly identifies a CreateTaskResult JSON object.
 */
module tasks_client;

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

/// Elicitation answer for `labeled_count` — mirrors the server's `LabelChoice`
/// form so `ElicitResult.accept!LabelChoice` builds the matching wire payload.
struct LabelChoice
{
	string label;
}

/// Typed view of the `labeled_count` structured result.
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

		// The tasks extension is draft-only: switch to the draft protocol and
		// declare the extension (plus elicitation, which labeled_count needs to
		// answer its mid-task input request) before version negotiation.
		client.enableModern();
		client.enableTasks();
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

		auto negotiated = client.connect();
		checkEq(negotiated, ProtocolVersion.modern, "connect() should negotiate draft");

		// --- 2. word_count (plain async task) -------------------------------
		{
			Json a = Json.emptyObject;
			a["text"] = "the quick brown fox jumps over the lazy dog";
			auto r = client.callToolAwait("word_count", a);
			check(!r.isError, "word_count should not be an error");
			auto wc = r.structuredContentAs!WordCountResult;
			checkEq(wc.words, 9, "word_count.words");
			checkEq(wc.chars, 43, "word_count.chars");
		}

		// --- 3. slow_reverse (async task, runs to completion) ---------------
		{
			Json a = Json.emptyObject;
			a["text"] = "hello";
			auto r = client.callToolAwait("slow_reverse", a);
			check(!r.isError, "slow_reverse should not be an error");
			auto rv = r.structuredContentAs!ReverseResult;
			checkEq(rv.reversed, "olleh", "slow_reverse.reversed");
			check(!rv.cancelled, "slow_reverse completed normally (not cancelled)");
		}

		// --- 3b. persist-and-resume: callTool exposes the task handle -------
		// Instead of awaiting inline, call the tool with plain `callTool`. When the
		// server creates a task the result IS the handle (`isTask`); persist
		// `task.taskId` somewhere durable, then drive it to completion with
		// `awaitTask` — the same call a client would make after a restart, rebuilt
		// from nothing but the stored id.
		{
			Json a = Json.emptyObject;
			a["text"] = "resume me";
			auto handle = client.callTool("slow_reverse", a);
			check(handle.isTask, "slow_reverse via callTool should return a task handle");
			check(handle.task.taskId.length > 0, "the task handle should carry a taskId");

			// Pretend the process restarted: all we keep is the id string.
			string persistedTaskId = handle.task.taskId;
			auto r = client.awaitTask(persistedTaskId);
			check(!r.isError, "resumed slow_reverse should not be an error");
			auto rv = r.structuredContentAs!ReverseResult;
			checkEq(rv.reversed, "em emuser", "resumed slow_reverse.reversed");
		}

		// --- 4. labeled_count (mid-task elicitation via tasks/update) -------
		// The task suspends into input_required with an elicitation. callToolAwait
		// surfaces it through onInputRequired; we answer with respondTaskInput
		// (tasks/update) and the resumed task completes. Answer once (the snapshot
		// may repeat across polls until the resume lands).
		{
			Json a = Json.emptyObject;
			a["text"] = "hello world";
			bool answered;
			auto r = client.callToolAwait("labeled_count", a, (string taskId,
				Json inputRequests) @safe {
				check((("label" in inputRequests) !is null),
				"labeled_count should surface a 'label' input request");
				check(inputRequests["label"]["method"].get!string == "elicitation/create",
				"the 'label' input request should be an elicitation");
				if (answered)
					return;
				answered = true;
				// The answer is keyed by the request id ("label"); its value is an
				// ElicitResult, accepting the LabelChoice form.
				auto er = ElicitResult.accept(LabelChoice("my-label"));
				client.respondTaskInput(taskId, Json(["label": er.toJson()]));
			});
			check(answered, "labeled_count should have requested input mid-task");
			check(!r.isError, "labeled_count should not be an error");
			auto lc = r.structuredContentAs!LabeledCount;
			checkEq(lc.label, "my-label", "labeled_count.label");
			checkEq(lc.words, 2, "labeled_count.words");
			checkEq(lc.chars, 11, "labeled_count.chars");
		}

		// --- 5. isTaskResult discriminator ----------------------------------
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
		writeln("OK: tasks example e2e passed over ", http ? "http" : "stdio",
			" — tasks extension advertised, word_count (9 words/43 chars),",
			" slow_reverse (\"hello\"->\"olleh\"),",
			" callTool task handle persisted + resumed via awaitTask,",
			" labeled_count mid-task elicitation answered via tasks/update (label=my-label),",
			" isTaskResult discriminator all verified.");
		return 0;
	});
}
