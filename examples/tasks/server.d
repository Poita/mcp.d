/**
 * MCP Tasks example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates two complementary async input patterns on one server:
 *
 *   1. SEP-2663 async tasks (`io.modelcontextprotocol/tasks`): a `tools/call`
 *      returns immediately with a `CreateTaskResult` (resultType:"task") and
 *      drives the task lifecycle through a background vibe-d fiber. The client
 *      polls via `tasks/get` and collects the final `CallToolResult`.
 *
 *      word_count — counts words and characters asynchronously, emitting a
 *      progress update before completing.
 *
 *      slow_reverse — reverses a string one character at a time with per-step
 *      cancellation support via `cancelRequested`; returns the partial result
 *      if cancelled mid-run.
 *
 *   2. SEP-2322 MRTR stateless elicitation: a `tools/call` ends with
 *      `ToolResponse.inputRequired(...)` when it needs more information. The
 *      client satisfies each request and resubmits; the server recovers the
 *      echoed `requestState` and the answers on the retry.
 *
 *      labeled_word_count — asks the client for a label via elicitation (round
 *      1), then returns the word/character count under that label (round 2).
 *
 * All three tools are registered via `registerHandlers` in the SDK's ergonomic
 * UDA style: methods annotated with `@tool` on a `TasksApi` class, with typed
 * parameters whose input JSON Schema is inferred automatically. Returning
 * `ToolResponse` lets each method answer `task`, `inputRequired`, or `complete`.
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
import mcp.protocol.modern : InputRequest;
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

/// Elicitation form for `labeled_word_count` round 1: the client fills in the
/// `label` field; `InputRequest.elicitation!LabelOptions` derives its
/// `requestedSchema` from this flat struct automatically.
struct LabelOptions
{
	string label;
}

/// Opaque server-owned `requestState` for `labeled_word_count`: stashes the
/// input text so it survives the client round-trip without being re-sent as an
/// argument. The typed `ToolResponse.inputRequired(reqs, T)` overload serialises
/// it; `ctx.requestStateAs!LabeledCountState()` recovers it on the retry.
struct LabeledCountState
{
	string text;
}

/// Typed structured result of `labeled_word_count`.
struct LabeledCount
{
	string label;
	int words;
	int chars;
}

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
private void failTaskNothrow(TaskRuntime rt, string taskId, string msg) @safe nothrow
{
	try
	{
		rt.fail(taskId, Json(["code": Json(-32000), "message": Json(msg)]));
	}
	catch (Exception)
	{
	}
}

/// All three tools as UDA-annotated methods. `registerHandlers` wires them onto
/// the server, deriving the input JSON Schema from the typed parameters and
/// auto-injecting `RequestContext` (which is omitted from the schema). Returning
/// `ToolResponse` lets each method answer `task`, `inputRequired`, or `complete`.
final class TasksApi
{
	private TaskRuntime rt;

	this(TaskRuntime rt) @safe
	{
		this.rt = rt;
	}

	/// Asynchronous word and character counter. Returns a `CreateTaskResult`
	/// immediately and completes the task in a background fiber.
	@tool("word_count", "Count words and characters in text (runs asynchronously).")
	@readOnly ToolResponse wordCount(string text, RequestContext) @safe
	{
		auto task = rt.create(Nullable!long(30_000L), Nullable!long(200L));
		const taskId = task.taskId;
		string capturedText = text;
		TaskRuntime capturedRt = rt;
		runTask(() @safe nothrow{
			try
			{
				import std.algorithm : splitter;
				import std.array : array;

				capturedRt.progress(taskId, "counting...");
				const words = cast(int) capturedText.splitter.array.length;
				const chars = cast(int) capturedText.length;
				capturedRt.complete(taskId, toCallToolResultJson(WordCountResult(words, chars)));
			}
			catch (Exception e)
				failTaskNothrow(capturedRt, taskId, e.msg);
		});
		return ToolResponse.task(makeCreateTaskResult(task));
	}

	/// Asynchronous string reverser with per-step cancellation. Returns a
	/// `CreateTaskResult` immediately; the fiber checks `cancelRequested` between
	/// characters and stores the partial result if cancelled.
	@tool("slow_reverse", "Reverse a string one character at a time (cancellable).")
	ToolResponse slowReverse(string text, RequestContext) @safe
	{
		auto task = rt.create(Nullable!long(30_000L), Nullable!long(200L));
		const taskId = task.taskId;
		string capturedText = text;
		TaskRuntime capturedRt = rt;
		runTask(() @safe nothrow{
			try
			{
				import std.array : Appender;

				Appender!string buf;
				foreach_reverse (ch; capturedText)
				{
					if (capturedRt.cancelRequested(taskId))
					{
						capturedRt.complete(taskId,
							toCallToolResultJson(ReverseResult(buf.data, true)));
						return;
					}
					buf ~= ch;
					sleep(10.msecs);
				}
				capturedRt.complete(taskId, toCallToolResultJson(ReverseResult(buf.data, false)));
			}
			catch (Exception e)
				failTaskNothrow(capturedRt, taskId, e.msg);
		});
		return ToolResponse.task(makeCreateTaskResult(task));
	}

	/// MRTR word counter. Round 1: asks the client for a label via elicitation
	/// and stashes the input text in the opaque `requestState`. Round 2: reads the
	/// echoed state + the elicitation answer and returns the synchronous result.
	@tool("labeled_word_count", "Count words; first asks for a label via elicitation (MRTR).")
	@readOnly ToolResponse labeledWordCount(string text, RequestContext ctx) @safe
	{
		if (!ctx.isResubmit())
		{
			// Round 1: request a label from the client and echo the input text
			// back via the typed requestState so it survives the round-trip.
			auto req = InputRequest.elicitation!LabelOptions("label_req",
					"Choose a label for this word count");
			return ToolResponse.inputRequired([req], LabeledCountState(text));
		}

		// Round 2: recover the text from the echoed requestState and decode the
		// elicitation answer. Fall back to "count" if the client declined.
		const state = ctx.requestStateAs!LabeledCountState();
		auto answer = ctx.inputResponseAs!ElicitResult("label_req");
		string label = "count";
		if (answer.action == ElicitAction.accept)
			label = answer.contentAs!LabelOptions().label;

		import std.algorithm : splitter;
		import std.array : array;

		return ToolResponse.complete(LabeledCount(label,
				cast(int) state.text.splitter.array.length, cast(int) state.text.length));
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("tasks-example", "1.0.0");
	auto rt = server.enableTasks();
	// Register all three @tool methods via the UDA reflection path; input schemas
	// are inferred from typed parameters, RequestContext is auto-injected.
	registerHandlers(server, new TasksApi(rt));
	runServerFromArgs(server, args, defaultPort);
}
