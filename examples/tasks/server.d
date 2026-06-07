/**
 * MCP Tasks example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates the server side of the SEP-2663 `io.modelcontextprotocol/tasks`
 * extension: long-running `tools/call` executions that return immediately with a
 * `CreateTaskResult` (resultType:"task") and drive the task lifecycle through a
 * background fiber. The matching client polls via `tasks/get` and awaits the
 * final result.
 *
 * Two tools are exposed:
 *
 *   word_count — asynchronous, completes on its own: counts words and
 *   characters in the supplied text inside a `runTask` fiber, emitting a
 *   progress update before returning the final structured result.
 *
 *   slow_reverse — asynchronous with cancellation support: reverses the input
 *   string character-by-character in a loop, pausing briefly per character and
 *   checking `cancelRequested` so the client can abort mid-run. Returns the
 *   partial result produced so far if cancelled.
 *
 * Both tools are registered via `registerDynamicTool` with the raw
 * `MrtrToolHandler` delegate type so they can return `ToolResponse.task(...)`.
 * `enableTasks()` advertises the extension and wires the `tasks/get` /
 * `tasks/update` / `tasks/cancel` dispatch.
 *
 * Transport selection is delegated to `runServerFromArgs`:
 *   stdio (default):  ./tasks-server
 *   http:             ./tasks-server --http --port 8643
 */
module tasks_server;

import core.time : msecs;
import std.typecons : Nullable, nullable;

import vibe.core.core : runTask, sleep;
import vibe.data.json : Json;

import mcp;
import examples_common : runServerFromArgs;

/// The fixed HTTP port for this example.
enum ushort defaultPort = 8643;

/// Typed result of the `word_count` tool.
struct WordCountResult
{
	int words;
	int chars;
}

/// Typed result of the `slow_reverse` tool.
struct ReverseResult
{
	string reversed;
	bool cancelled;
}

/// Shared task runtime — created by `enableTasks()` during server setup and
/// captured by the tool handlers via the module-level variable.
private TaskRuntime rt;

/// Build a `CallToolResult`-shaped JSON (with `content` + `structuredContent`)
/// from a plain-data object. The client's `awaitTask` passes the task `result`
/// directly to `CallToolResult.fromJson`, so the stored shape must match.
private Json toCallToolResultJson(T)(T value) @safe
{
	import vibe.data.json : serializeToJson;

	Json sc = serializeToJson(value);
	Json j = Json.emptyObject;
	j["structuredContent"] = sc;
	j["content"] = Json([
		Json(["type": Json("text"), "text": Json(sc.toString())])
	]);
	return j;
}

/// Fail a task safely from a nothrow context, swallowing any secondary error.
private void failTaskNothrow(string taskId, string msg) @safe nothrow
{
	try
	{
		rt.fail(taskId, Json(["code": Json(-32000), "message": Json(msg)]));
	}
	catch (Exception)
	{
	}
}

/// Build the `word_count` tool descriptor and handler. The handler:
///   1. Creates a task (200ms poll interval so the e2e test is quick).
///   2. Spawns a background `runTask` fiber that counts words, emits a progress
///      update, and completes the task.
///   3. Returns `ToolResponse.task(makeCreateTaskResult(task))` immediately.
private void registerWordCount(McpServer server) @safe
{
	import std.algorithm : splitter;
	import std.array : array;

	Tool desc;
	desc.name = "word_count";
	desc.description = "Count words and characters in text (runs asynchronously).";
	Json props = Json.emptyObject;
	props["text"] = Json([
		"type": Json("string"),
		"description": Json("the text to analyse")
	]);
	desc.inputSchema = Json([
		"type": Json("object"),
		"properties": props,
		"required": Json([Json("text")])
	]);

	server.registerDynamicTool(desc, (Json args, RequestContext) @safe {
		const text = args["text"].get!string;
		auto task = rt.create(Nullable!long(30_000L), Nullable!long(200L));
		const taskId = task.taskId;
		string capturedText = text;
		runTask(() @safe nothrow{
			try
			{
				rt.progress(taskId, "counting...");
				const words = cast(int) capturedText.splitter.array.length;
				const chars = cast(int) capturedText.length;
				rt.complete(taskId, toCallToolResultJson(WordCountResult(words, chars)));
			}
			catch (Exception e)
				failTaskNothrow(taskId, e.msg);
		});
		return ToolResponse.task(makeCreateTaskResult(task));
	});
}

/// Build the `slow_reverse` tool descriptor and handler. The handler:
///   1. Creates a task (200ms poll interval).
///   2. Spawns a fiber that reverses the string one character at a time,
///      sleeping briefly between characters and honoring `cancelRequested`.
///   3. Returns `ToolResponse.task(makeCreateTaskResult(task))` immediately.
private void registerSlowReverse(McpServer server) @safe
{
	Tool desc;
	desc.name = "slow_reverse";
	desc.description = "Reverse a string one character at a time (cancellable).";
	Json props = Json.emptyObject;
	props["text"] = Json([
		"type": Json("string"),
		"description": Json("the text to reverse")
	]);
	desc.inputSchema = Json([
		"type": Json("object"),
		"properties": props,
		"required": Json([Json("text")])
	]);

	server.registerDynamicTool(desc, (Json args, RequestContext) @safe {
		const text = args["text"].get!string;
		auto task = rt.create(Nullable!long(30_000L), Nullable!long(200L));
		const taskId = task.taskId;
		string capturedText = text;
		runTask(() @safe nothrow{
			try
			{
				import std.array : Appender;

				Appender!string buf;
				foreach_reverse (ch; capturedText)
				{
					if (rt.cancelRequested(taskId))
					{
						rt.complete(taskId, toCallToolResultJson(ReverseResult(buf.data, true)));
						return;
					}
					buf ~= ch;
					sleep(10.msecs);
				}
				rt.complete(taskId, toCallToolResultJson(ReverseResult(buf.data, false)));
			}
			catch (Exception e)
				failTaskNothrow(taskId, e.msg);
		});
		return ToolResponse.task(makeCreateTaskResult(task));
	});
}

void main(string[] args) @safe
{
	auto server = new McpServer("tasks-example", "1.0.0");
	rt = server.enableTasks();
	registerWordCount(server);
	registerSlowReverse(server);
	runServerFromArgs(server, args, defaultPort);
}
