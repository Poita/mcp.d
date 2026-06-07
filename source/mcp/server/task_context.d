module mcp.server.task_context;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json, serializeToJson, deserializeJson;

import mcp.protocol.errors : McpException, ErrorCode;
import mcp.protocol.modern : InputRequest, inputRequestsToJson;
import mcp.server.task_runtime : TaskRuntime;

@safe:

/// Thrown by `TaskContext.requireInput` to unwind a task executor that needs
/// client input. The runtime has already persisted the `input_required` status
/// and outstanding `inputRequests` before this is thrown; the dispatcher catches
/// it and simply stops the current dispatch. The executor is re-invoked (from the
/// top) once the answers arrive via `tasks/update`. Do not catch this in executor
/// code.
final class TaskSuspended : Exception
{
	this(string taskId) @safe nothrow
	{
		super("task suspended for input: " ~ taskId);
	}
}

/// The handle a task executor uses to drive its task. It is store-backed (every
/// call reads/writes the durable `TaskRecord` via the runtime), so an executor is
/// a pure function of its persisted input plus this context — it can run in-process
/// or be re-dispatched on another node with identical behavior.
///
/// Mid-execution input follows the re-entrant model: when an executor needs the
/// client to answer something it calls `requireInput`, which persists the request
/// and suspends. The client answers via `tasks/update`; the executor is re-invoked
/// and observes the answer through `hasInput`/`inputAs`. Intermediate state that
/// must survive a suspension is saved with `checkpoint` and read with `restore`.
struct TaskContext
{
	private TaskRuntime rt_;
	private string taskId_;

	this(TaskRuntime rt, string taskId) @safe
	{
		rt_ = rt;
		taskId_ = taskId;
	}

	/// The task's stable identifier.
	string taskId() const @safe
	{
		return taskId_;
	}

	/// The durable input recorded when the task was created (the original tool
	/// `arguments`). Reconstituted from the store on every dispatch, so an executor
	/// reads identical input whether on its first run or a re-dispatch elsewhere.
	Json inputJson() @safe
	{
		return rt_.executorInput(taskId_);
	}

	/// Set the task's human-readable status message (visible via `tasks/get`).
	void progress(string statusMessage) @safe
	{
		rt_.progress(taskId_, statusMessage);
	}

	/// Whether the client has requested cancellation. Executors should poll this
	/// at safe points and stop promptly; the dispatcher marks the task `cancelled`
	/// when an executor returns with this set.
	bool cancelRequested() @safe
	{
		return rt_.cancelRequested(taskId_);
	}

	/// Whether an answer for `key` has been delivered via `tasks/update`.
	bool hasInput(string key) @safe
	{
		auto m = rt_.takenInput(taskId_);
		return (key in m) !is null;
	}

	/// The raw delivered answer for `key`, or `undefined` if not yet present.
	Json input(string key) @safe
	{
		auto m = rt_.takenInput(taskId_);
		if (auto p = key in m)
			return *p;
		return Json.undefined;
	}

	/// The delivered answer for `key`, decoded as `T`.
	T inputAs(T)(string key) @safe
	{
		return deserializeJson!T(input(key));
	}

	/// Persist a checkpoint value under `key` so it survives a suspension and is
	/// available when the executor is re-invoked.
	void checkpoint(T)(string key, T value) @safe
	{
		rt_.putCheckpoint(taskId_, key, serializeToJson(value));
	}

	/// Whether a checkpoint exists under `key`.
	bool hasCheckpoint(string key) @safe
	{
		return rt_.getCheckpoint(taskId_, key).type != Json.Type.undefined;
	}

	/// Read a previously stored checkpoint, decoded as `T`. Throws if absent.
	T restore(T)(string key) @safe
	{
		auto j = rt_.getCheckpoint(taskId_, key);
		if (j.type == Json.Type.undefined)
			throw new McpException(ErrorCode.internalError, "no checkpoint stored under key: " ~ key);
		return deserializeJson!T(j);
	}

	/// Suspend the executor pending client input. Persists `requests` as the
	/// task's outstanding `inputRequests` (status `input_required`) and throws
	/// `TaskSuspended`. Never returns — its `noreturn` result type lets an executor
	/// write `return tc.requireInput(...);` from a value-returning method.
	noreturn requireInput(const(InputRequest)[] requests) @safe
	{
		rt_.requireInput(taskId_, inputRequestsToJson(requests));
		throw new TaskSuspended(taskId_);
	}

	/// `requireInput` plus a typed `state` checkpoint (stored under the reserved
	/// key `_state`, read back with `restore!T("_state")`) for state that must
	/// survive the suspension.
	noreturn requireInput(T)(const(InputRequest)[] requests, T state) @safe
			if (!is(T : const(InputRequest)[]))
	{
		checkpoint("_state", state);
		return requireInput(requests);
	}
}

/// A registered task executor: given its `TaskContext`, it produces the final
/// `CallToolResult`-shaped result JSON, or calls `tc.requireInput(...)` to suspend.
/// The runtime stores the executor key (`toolName`) on the task so the dispatcher
/// can look the executor up on re-dispatch.
alias TaskExecutor = Json delegate(TaskContext tc) @safe;

/// Drives the task lifecycle for one dispatch: build the context, run `executor`,
/// and record the outcome on the durable task. A normal return completes the task
/// (or marks it `cancelled` if a cancel was requested during the run);
/// `TaskSuspended` leaves it `input_required`; any other exception fails it. Pure
/// over the store, so it is correct whether invoked in-process or by a remote
/// worker.
void runTaskExecutor(TaskRuntime rt, string taskId, TaskExecutor executor) @safe
{
	auto tc = TaskContext(rt, taskId);
	try
	{
		auto result = executor(tc);
		if (rt.cancelRequested(taskId))
			rt.markCancelled(taskId);
		else
			rt.complete(taskId, result);
	}
	catch (TaskSuspended)
	{
		// Already persisted as input_required; nothing further this dispatch.
	}
	catch (McpException e)
	{
		Json err = Json.emptyObject;
		err["code"] = cast(int) e.code;
		err["message"] = e.msg;
		rt.fail(taskId, err);
	}
	catch (Exception e)
	{
		rt.fail(taskId, Json([
			"code": Json(cast(int) ErrorCode.internalError),
			"message": Json(e.msg)
		]));
	}
}

/// Decides where a task executor actually runs. `dispatch` is invoked by the
/// runtime when a task is created and again whenever input arrives, with a
/// callback that runs the executor for the given task ID. The in-process default
/// runs it in a local fiber; a production implementation enqueues the ID to an
/// external worker pool (which calls the equivalent of `runTaskExecutor` itself).
interface TaskDispatcher
{
	void dispatch(string taskId, void delegate(string taskId) @safe run) @safe;
}

/// The default dispatcher: runs the executor in a local vibe-d fiber. Suitable
/// for single-node or sticky-routed deployments (where `Mcp-Name: <taskId>` keeps
/// a task's requests on the node holding its fiber). Not durable across restarts —
/// production deployments that need durability supply their own dispatcher backed
/// by a queue / durable execution engine.
final class InProcessTaskDispatcher : TaskDispatcher
{
	import vibe.core.core : runTask;

	void dispatch(string taskId, void delegate(string taskId) @safe run) @safe
	{
		auto id = taskId;
		auto r = run;
		runTask(() @safe nothrow{
			try
				r(id);
			catch (Exception)
			{
			}
		});
	}
}

/// A dispatcher that runs the executor inline, synchronously, on the dispatching
/// thread. Suitable for fast CPU-bound executors that need no concurrency, and
/// for deterministic tests (no event loop required). Note the executor runs
/// before `dispatch` returns, so a synchronous task may already be `completed`
/// (or `input_required`) by the time the `CreateTaskResult` reaches the client.
final class SyncTaskDispatcher : TaskDispatcher
{
	void dispatch(string taskId, void delegate(string taskId) @safe run) @safe
	{
		run(taskId);
	}
}

unittest  // runTaskExecutor completes a task with the executor's result
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("echo", Json(["v": Json(7)]));
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		return Json(["structuredContent": Json(["v": Json(7)])]);
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "completed");
	assert(d["result"]["structuredContent"]["v"].get!int == 7);
}

unittest  // requireInput suspends into input_required; re-run completes after answer
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);

	// The executor needs an "ok" answer before it can finish.
	TaskExecutor exec = (TaskContext tc) @safe {
		if (!tc.hasInput("ok"))
			return tc.requireInput([InputRequest.elicitation("ok", "Proceed?")]);
		return Json(["structuredContent": Json(["done": Json(true)])]);
	};

	// First dispatch suspends.
	runTaskExecutor(rt, t.taskId, exec);
	auto blocked = rt.getDetailed(t.taskId);
	assert(blocked["status"].get!string == "input_required");
	assert(blocked["inputRequests"]["ok"]["method"].get!string == "elicitation/create");

	// Client answers; re-dispatch completes.
	rt.deliverInput(t.taskId, Json(["ok": Json(["action": Json("accept")])]));
	runTaskExecutor(rt, t.taskId, exec);
	auto done = rt.getDetailed(t.taskId);
	assert(done["status"].get!string == "completed");
	assert(done["result"]["structuredContent"]["done"].get!bool);
}

unittest  // an executor that throws fails the task with a JSON-RPC error
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("boom", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		throw new Exception("kaboom");
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["message"].get!string == "kaboom");
}

unittest  // a cancel observed during the run marks the task cancelled, not completed
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	rt.cancel(t.taskId); // sets the cooperative flag (executor-backed: status stays working)
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		// Executor returns a result, but a cancel was requested.
		return Json(["structuredContent": Json.emptyObject]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // checkpoint state survives a suspension and is restored on re-run
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("multi", Json.undefined);

	TaskExecutor exec = (TaskContext tc) @safe {
		if (!tc.hasInput("go"))
			return tc.requireInput([InputRequest.elicitation("go", "go?")], "carried");
		return Json([
			"structuredContent": Json([
				"state": Json(tc.restore!string("_state"))
			])
		]);
	};
	runTaskExecutor(rt, t.taskId, exec);
	rt.deliverInput(t.taskId, Json(["go": Json(true)]));
	runTaskExecutor(rt, t.taskId, exec);
	auto d = rt.getDetailed(t.taskId);
	assert(d["result"]["structuredContent"]["state"].get!string == "carried");
}
