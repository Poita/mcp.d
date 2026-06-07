/**
 * MCP Tasks example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `tasks-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `tasks-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * The Tasks extension is draft-only (`io.modelcontextprotocol/tasks`, SEP-2663):
 * before calling any tool the client enables the draft protocol with
 * `enableModern()` and declares the tasks extension with `enableTasks()`, then
 * negotiates via `server/discover` + `connect()`. `callToolAwait` transparently
 * handles the poll loop for any `CreateTaskResult` the server returns.
 *
 * Assertions verified:
 *   - `server/discover` advertises the tasks extension under `capabilities`.
 *   - `callToolAwait("word_count", ...)` polls until completed and returns the
 *     expected word/character counts decoded from `structuredContent`.
 *   - `callToolAwait("slow_reverse", ...)` returns the fully reversed string.
 *   - `isTaskResult` correctly identifies a `CreateTaskResult` JSON object.
 */
module tasks_client;

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

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "tasks-server");
		scope (exit)
			client.close();

		// The tasks extension is draft-only: switch to the stateless draft
		// protocol and declare the extension in client capabilities before
		// version negotiation.
		client.enableModern();
		client.enableTasks();

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

		// --- 3. word_count (async, no user input required) ------------------
		// `callToolAwait` calls the tool, detects the `CreateTaskResult`, and
		// polls `tasks/get` until the task moves to `completed`, then returns
		// the final `CallToolResult` decoded from the task's structured result.
		{
			Json a = Json.emptyObject;
			a["text"] = "the quick brown fox jumps over the lazy dog";
			auto r = client.callToolAwait("word_count", a);
			check(!r.isError, "word_count should not be an error");
			auto wc = r.structuredContentAs!WordCountResult;
			checkEq(wc.words, 9, "word_count.words");
			checkEq(wc.chars, 43, "word_count.chars");
		}

		// --- 4. slow_reverse (async, runs to completion) -------------------
		// A short string so the e2e test finishes quickly (5 chars × 10ms).
		{
			Json a = Json.emptyObject;
			a["text"] = "hello";
			auto r = client.callToolAwait("slow_reverse", a);
			check(!r.isError, "slow_reverse should not be an error");
			auto rv = r.structuredContentAs!ReverseResult;
			checkEq(rv.reversed, "olleh", "slow_reverse.reversed");
			check(!rv.cancelled, "slow_reverse completed normally (not cancelled)");
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

		import std.stdio : writeln;

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: tasks example e2e passed over ",
			http ? "http" : "stdio",
			" — tasks extension advertised, word_count async completion (",
			"9 words/43 chars), slow_reverse completion (\"hello\"->\"olleh\"), ",
			"isTaskResult discriminator all verified.");
		return 0;
	});
}
