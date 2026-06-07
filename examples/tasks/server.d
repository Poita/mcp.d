/**
 * MCP Tasks example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates the SDK's ergonomic `@task` UDA for the SEP-2663
 * `io.modelcontextprotocol/tasks` extension. A `@task` method becomes a tool
 * whose `tools/call` returns a task handle immediately; the body runs
 * asynchronously via the server's task dispatcher and its typed return value
 * becomes the task's final result. The matching client polls `tasks/get` and
 * awaits the result. There is no manual `rt.create` / `runTask` / result
 * wrapping — `registerHandlers` wires everything from the method signature.
 *
 * Three tasks, covering the whole surface:
 *
 *   word_count — a plain async task: counts words/characters, emitting a
 *   progress update via `TaskContext.progress` before returning a typed result.
 *
 *   slow_reverse — an async task with cooperative cancellation: reverses the
 *   input one character at a time, polling `TaskContext.cancelRequested` between
 *   characters so a `tasks/cancel` stops it promptly.
 *
 *   labeled_count — a human-in-the-loop task: it needs a label from the client
 *   MID-EXECUTION, so it calls `TaskContext.requireInput` with an elicitation.
 *   That suspends the task into `input_required`; the client answers via
 *   `tasks/update`, the executor is re-invoked (the re-entrant model) and reads
 *   the answer through `TaskContext.inputAs`, then returns the final result.
 *
 * The `TaskContext` parameter is injected (and omitted from the input schema);
 * the other parameters derive the schema and are reconstituted from the task's
 * durable input on every dispatch — so the same handler is correct whether it
 * runs in-process or is re-dispatched on another node from a shared store.
 *
 * Transport selection is delegated to `runServerFromArgs`:
 *   stdio (default):  ./tasks-server
 *   http:             ./tasks-server --http --port 8643
 */
module tasks_server;

import core.time : msecs, seconds;

import vibe.core.core : sleep;

import mcp;
import mcp.protocol.modern : InputRequest;
import examples_common : runServerFromArgs;

/// The fixed HTTP port for this example.
enum ushort defaultPort = 8643;

/// Typed result of `word_count`.
struct WordCountResult
{
	int words;
	int chars;
}

/// Typed result of `slow_reverse`.
struct ReverseResult
{
	string reversed;
	bool cancelled;
}

/// Elicitation form for `labeled_count`: the client fills in `label`. The
/// `requestedSchema` is derived from this flat struct by `InputRequest.elicitation!T`.
struct LabelChoice
{
	string label;
}

/// Typed result of `labeled_count`.
struct LabeledCount
{
	string label;
	int words;
	int chars;
}

/// All three tasks as `@task`-annotated methods. `registerHandlers` derives each
/// tool's input schema from the typed parameters, injects the `TaskContext`
/// (omitted from the schema), and runs the body asynchronously via the
/// dispatcher, wrapping the return value as the task result.
final class TasksApi
{
	import std.algorithm : splitter;
	import std.array : array, Appender;

	/// Plain async task: count words and characters, with a progress update.
	/// @taskTtl / @taskPollInterval set this task's timing (per-task, not global).
	@task("word_count", "Count words and characters in text (runs asynchronously).")
	@taskTtl(10.seconds) @taskPollInterval(200.msecs)
	@readOnly WordCountResult wordCount(string text, TaskContext tc) @safe
	{
		tc.progress("counting...");
		return WordCountResult(cast(int) text.splitter.array.length, cast(int) text.length);
	}

	/// Async task with cooperative cancellation: reverse the string one character
	/// at a time, checking `cancelRequested` between characters. Returns the
	/// partial result with `cancelled = true` if a cancel was observed.
	@task("slow_reverse", "Reverse a string one character at a time (cancellable).")
	@taskTtl(30.seconds) @taskPollInterval(100.msecs)
	ReverseResult slowReverse(string text, TaskContext tc) @safe
	{
		Appender!string buf;
		foreach_reverse (ch; text)
		{
			if (tc.cancelRequested)
				return ReverseResult(buf.data, true);
			buf ~= ch;
			sleep(10.msecs);
		}
		return ReverseResult(buf.data, false);
	}

	/// Human-in-the-loop task: ask the client for a label mid-execution via an
	/// elicitation, then count under that label. On the first dispatch there is no
	/// answer yet, so `requireInput` suspends the task into `input_required`; once
	/// the client answers via `tasks/update`, the executor is re-invoked and the
	/// answer is present.
	@task("labeled_count", "Count words under a label the client supplies mid-task.")
	@taskTtl(60.seconds) @taskPollInterval(200.msecs)
	@readOnly LabeledCount labeledCount(string text, TaskContext tc) @safe
	{
		if (!tc.hasInput("label"))
			return tc.requireInput([
			InputRequest.elicitation!LabelChoice("label", "Choose a label for this count")
		]);

		auto answer = tc.inputAs!ElicitResult("label");
		string label = (answer.action == ElicitAction.accept) ? answer.contentAs!LabelChoice()
			.label : "count";
		return LabeledCount(label, cast(int) text.splitter.array.length, cast(int) text.length);
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("tasks-example", "1.0.0");

	// Enable the tasks extension. A null store uses the in-memory default and a
	// null dispatcher uses the in-process (fiber) default — fine for a single-node
	// demo. Per-task timing comes from each @task's @taskTtl / @taskPollInterval.
	//
	// For a durable, horizontally-scaled deployment you supply your own store and
	// dispatcher; the @task handlers above do not change. Because all task state
	// lives in the store, any node can serve tasks/get|update|cancel and re-run an
	// executor purely from the task ID:
	//
	//   final class RedisTaskStore : TaskStore {
	//       void put(TaskRecord r)               { redis.set(r.meta.taskId, r.toJson.toString); }
	//       Nullable!TaskRecord get(string id)   { ... TaskRecord.fromJson(...) ... }
	//       void update(TaskRecord r)            { redis.set(r.meta.taskId, r.toJson.toString); }
	//       void remove(string id)               { redis.del(id); }
	//   }
	//   // A dispatcher that enqueues the task ID; a worker process running the same
	//   // server + @task registration picks it up and runs the executor.
	//   final class QueueTaskDispatcher : TaskDispatcher {
	//       void dispatch(string taskId, void delegate(string) @safe run) { queue.publish(taskId); }
	//   }
	//   server.enableTasks(new RedisTaskStore(...), TaskOptions.init, new QueueTaskDispatcher(...));
	//
	server.enableTasks();

	// Register all @task methods in one call — no per-tool wiring.
	registerHandlers(server, new TasksApi);

	runServerFromArgs(server, args, defaultPort);
}
