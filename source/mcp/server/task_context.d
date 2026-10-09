module mcp.server.task_context;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json, serializeToJson, deserializeJson;

import mcp.protocol.capabilities : tasksExtensionKey;
import mcp.protocol.errors : McpException, ErrorCode;
import mcp.protocol.mrtr : InputRequest, inputRequestsToJson;
import mcp.server.task_runtime : TaskRuntime;

@safe:

/// Thrown by `TaskContext.requireInput` to unwind a task executor that needs
/// client input. The runtime has already persisted the `input_required` status
/// and outstanding `inputRequests` before this is thrown; the dispatcher catches
/// it and simply stops the current dispatch. The executor is re-invoked (from the
/// top) once the answers arrive via `tasks/update`. Do not catch this in executor
/// code; an executor that does anyway (e.g. with a blanket `catch (Exception)`)
/// still ends the dispatch suspended, since the dispatcher also records the
/// suspension on the `TaskContext`. It derives from `Exception` rather than
/// `Throwable` so `finally` / `scope(exit)` cleanup in the executor always runs.
final class TaskSuspended : Exception
{
	this(string taskId) @safe nothrow
	{
		super("task suspended for input: " ~ taskId);
	}
}

/// Thrown by `TaskContext.detach` to unwind a task executor that has handed its
/// work off to be completed out of band. Unlike `TaskSuspended`, the task is left
/// `working` (no `inputRequests`): the dispatcher catches this and stops the
/// current dispatch, and an external signal later calls `rt.complete` / `rt.fail`.
/// Do not catch this in executor code; as with `TaskSuspended`, a swallowed
/// detach still ends the dispatch with the task left `working`.
final class TaskDetached : Exception
{
	this(string taskId) @safe nothrow
	{
		super("task detached: " ~ taskId);
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
	private DispatchOutcome outcome_;
	// Set when the executor runs inline on the calling request (a client
	// without the Tasks extension): that request's cancellation state.
	private bool delegate() @safe requestCancelled_;

	this(TaskRuntime rt, string taskId) @safe
	{
		rt_ = rt;
		taskId_ = taskId;
		outcome_ = new DispatchOutcome();
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
		return snapshot().executorInput;
	}

	/// Set the task's human-readable status message (visible via `tasks/get`).
	void progress(string statusMessage) @safe
	{
		rt_.progress(taskId_, statusMessage);
	}

	/// Whether the client has requested cancellation. Executors should poll this
	/// at safe points and stop promptly; the dispatcher marks the task `cancelled`
	/// when an executor returns with this set. For an executor running inline on
	/// a `tools/call`, cancelling that request cancels the task.
	bool cancelRequested() @safe
	{
		if (requestCancelled_ !is null && !outcome_.cancelForwarded && requestCancelled_())
		{
			rt_.cancel(taskId_);
			outcome_.cancelForwarded = true;
		}
		return rt_.cancelRequested(taskId_);
	}

	/// Whether an answer for `key` has been delivered via `tasks/update`.
	bool hasInput(string key) @safe
	{
		return (key in snapshot().inputs) !is null;
	}

	/// The raw delivered answer for `key`, or `undefined` if not yet present.
	Json input(string key) @safe
	{
		if (auto p = key in snapshot().inputs)
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
		auto j = serializeToJson(value);
		rt_.putCheckpoint(taskId_, key, j);
		snapshot().checkpoints[key] = j;
	}

	/// Whether a checkpoint exists under `key`.
	bool hasCheckpoint(string key) @safe
	{
		return (key in snapshot().checkpoints) !is null;
	}

	/// Read a previously stored checkpoint, decoded as `T`. Throws if absent.
	T restore(T)(string key) @safe
	{
		auto p = key in snapshot().checkpoints;
		if (p is null)
			throw new McpException(ErrorCode.internalError, "no checkpoint stored under key: " ~ key);
		return deserializeJson!T(*p);
	}

	/// Suspend the executor pending client input. Persists `requests` as the
	/// task's outstanding `inputRequests` (status `input_required`, or
	/// `cancelled` if a cancel was already requested) and throws `TaskSuspended`.
	/// `requests` must be non-empty; an empty set throws `internalError`, which
	/// fails the task. Never returns — its `noreturn` result type lets an executor
	/// write `return tc.requireInput(...);` from a value-returning method.
	noreturn requireInput(const(InputRequest)[] requests) @safe
	{
		rt_.requireInput(taskId_, inputRequestsToJson(requests));
		if (outcome_ !is null)
			outcome_.unwound = true;
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

	/// Stop this dispatch without completing the task: it stays `working` and is
	/// finished out of band via `rt.complete` / `rt.fail` (e.g. a deploy webhook or
	/// job callback that holds the task ID). Use this after kicking off external work
	/// so no fiber is held — any node can later complete the task from the store.
	/// Never returns — its `noreturn` result type lets an executor write
	/// `return tc.detach();` from a value-returning method.
	///
	/// An executor running inline (the client did not declare the Tasks
	/// extension) has no task the client could later observe, so `detach` throws
	/// a -32021 `McpException` naming the extension instead.
	noreturn detach() @safe
	{
		if (requestCancelled_ !is null)
			throw tasksExtensionRequired("The tool finishes out of band, which requires the "
					~ tasksExtensionKey ~ " extension");
		rt_.markDetached(taskId_);
		if (outcome_ !is null)
			outcome_.unwound = true;
		throw new TaskDetached(taskId_);
	}

	/// The task's durable input, delivered answers and checkpoints, read from the
	/// store once per dispatch. Answers cannot change while the executor runs (a
	/// running task has no outstanding input requests, so `tasks/update` is
	/// refused), and checkpoints change only through this context, which updates
	/// the snapshot as it writes.
	private DispatchOutcome snapshot() @safe
	{
		if (outcome_ is null)
			outcome_ = new DispatchOutcome();
		if (!outcome_.loaded)
		{
			auto r = rt_.recordOf(taskId_);
			if (!r.isNull)
			{
				outcome_.executorInput = r.get.executorInput;
				outcome_.inputs = r.get.inputResponses;
				outcome_.checkpoints = r.get.checkpoints;
			}
			outcome_.loaded = true;
		}
		return outcome_;
	}

	/// `detach` that also records a human-readable working status message (visible
	/// on the next `tasks/get`).
	noreturn detach(string statusMessage) @safe
	{
		rt_.progress(taskId_, statusMessage);
		return detach();
	}
}

/// Shared by every copy of a `TaskContext`, so the dispatcher sees that the
/// executor suspended or detached even if the executor swallowed the unwinding
/// exception, and every copy reads the same per-dispatch record snapshot.
private final class DispatchOutcome
{
	bool unwound;
	bool loaded;
	// The inline request's cancellation has been recorded on the task.
	bool cancelForwarded;
	Json executorInput;
	Json[string] inputs;
	Json[string] checkpoints;
}

/// A registered task executor: given its `TaskContext`, it produces the final
/// `CallToolResult`-shaped result JSON, or calls `tc.requireInput(...)` to suspend.
/// The runtime stores the executor key (`toolName`) on the task so the dispatcher
/// can look the executor up on re-dispatch.
alias TaskExecutor = Json delegate(TaskContext tc) @safe;

/// Drives the task lifecycle for one dispatch: build the context, run `executor`,
/// and record the outcome on the durable task. A normal return completes the
/// task and any other exception fails it, except that either marks it
/// `cancelled` when a cancel was requested during the run (an executor may abort
/// by throwing); `TaskSuspended` leaves it `input_required`. Once the executor
/// has suspended or detached, the dispatch ends there whatever it does
/// afterwards. A task whose record was removed during the run is left gone.
/// A task already cancelled or removed when the dispatch starts is settled
/// without invoking the executor.
/// Pure over the store, so it is correct whether invoked in-process or by a
/// remote worker. Throws only when the outcome cannot be recorded (e.g. the
/// store is unreachable).
void runTaskExecutor(TaskRuntime rt, string taskId, TaskExecutor executor) @safe
{
	auto tc = TaskContext(rt, taskId);
	drive(tc, executor);
}

/// `runTaskExecutor` for an executor running inline on the request that
/// created the task: `requestCancelled` reports that request's cancellation,
/// which cancels the task, and `TaskContext.detach` is refused.
package(mcp) void runTaskExecutorInline(TaskRuntime rt, string taskId,
		TaskExecutor executor, bool delegate() @safe requestCancelled) @safe
{
	auto tc = TaskContext(rt, taskId);
	tc.requestCancelled_ = requestCancelled;
	drive(tc, executor);
}

/// The -32021 error naming the Tasks extension as the missing client capability.
package(mcp) McpException tasksExtensionRequired(string message) @safe
{
	import mcp.protocol.capabilities : ClientCapabilities;
	import mcp.protocol.errors : missingRequiredClientCapability;

	ClientCapabilities c;
	Json ext = Json.emptyObject;
	ext[tasksExtensionKey] = Json.emptyObject;
	c.extensions = ext;
	return missingRequiredClientCapability(c, message);
}

private void drive(ref TaskContext tc, TaskExecutor executor) @safe
{
	auto rt = tc.rt_;
	const taskId = tc.taskId_;
	// A task removed while its executor ran has no record left to settle.
	void settleCancelled() @safe
	{
		if (!rt.statusOf(taskId).isNull)
			rt.markCancelled(taskId);
	}

	// A task cancelled (or removed) while its dispatch was queued must not run
	// its side effects; `cancelRequested` is also true once the record is gone.
	if (tc.cancelRequested())
	{
		settleCancelled();
		return;
	}

	try
	{
		auto result = executor(tc);
		if (tc.outcome_.unwound)
			return;
		if (tc.cancelRequested())
			settleCancelled();
		else
			rt.complete(taskId, result);
	}
	catch (TaskSuspended)
	{
		// Already persisted as input_required; nothing further this dispatch.
	}
	catch (TaskDetached)
	{
		// Left `working`; an external signal completes it via rt.complete/rt.fail.
	}
	catch (McpException e)
	{
		if (tc.outcome_.unwound)
			return;
		if (tc.cancelRequested())
			settleCancelled();
		else
			rt.fail(taskId, e);
	}
	catch (Exception e)
	{
		import vibe.core.log : logError;

		if (tc.outcome_.unwound)
			return;
		if (tc.cancelRequested())
			settleCancelled();
		else
		{
			// The task error is visible to clients via tasks/get and
			// notifications/tasks, so an unexpected exception's message (which can
			// carry paths, SQL or other internals) is logged and replaced with a
			// generic one unless the server exposes internal errors.
			logError("task %s: executor threw %s: %s", taskId, typeid(e).name, e.msg);
			rt.fail(taskId, Json([
				"code": Json(cast(int) ErrorCode.internalError),
				"message": Json(rt.exposeInternalErrors ? e.msg : "Internal error")
			]));
		}
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
/// by a queue / durable execution engine. A dispatch that could not record its
/// outcome is logged, since the fiber has no caller to report it to.
final class InProcessTaskDispatcher : TaskDispatcher
{
	import vibe.core.core : runTask;

	void dispatch(string taskId, void delegate(string taskId) @safe run) @safe
	{
		auto id = taskId;
		auto r = run;
		runTask(() @safe nothrow{
			import vibe.core.log : logError;

			try
				r(id);
			catch (Exception e)
				logError("task %s: dispatch failed to record its outcome: %s", id, e.msg);
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

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("echo", Json(["v": Json(7)]));
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		return Json(["structuredContent": Json(["v": Json(7)])]);
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "completed");
	assert(d["result"]["structuredContent"]["v"].get!int == 7);
}

unittest  // a throwing status-change sink leaves a suspended task input_required
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	rt.onStatusChange((Json d, string owner) @safe {
		throw new Exception("stdout closed");
	});
	auto t = rt.createFor("gate", Json.undefined);
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		tc.progress("asking");
		return tc.requireInput([InputRequest.elicitation("ok", "Proceed?")]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "input_required");
}

unittest  // an executor whose task record is removed mid-run stops without failing the dispatch
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(TaskOptions(store));
	auto t = rt.createFor("slow", Json.undefined);
	bool sawCancel;
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		store.remove(t.taskId);
		sawCancel = tc.cancelRequested();
		return Json.emptyObject;
	});
	assert(sawCancel);
	assert(rt.statusOf(t.taskId).isNull);
}

unittest  // an executor suspending with no input requests fails the task
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		return tc.requireInput([]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "failed");
}

unittest  // requireInput suspends into input_required; re-run completes after answer
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
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

unittest  // detach stops the dispatch without completing; the task stays working
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("deploy", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		return tc.detach();
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");

	// An external signal completes it later.
	rt.complete(t.taskId, Json(["structuredContent": Json(["ok": Json(true)])]));
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "completed");
	assert(d["result"]["structuredContent"]["ok"].get!bool);
}

unittest  // detach(statusMessage) records a working status message
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("deploy", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		return tc.detach("deploying");
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "working");
	assert(d["statusMessage"].get!string == "deploying");
}

version (unittest)
{
	import vibe.core.log : LogLevel, Logger, LogLine;

	// Records the text of every error-or-higher log line.
	private final class CaptureLogger : Logger
	{
		string[] lines;
		this() @safe
		{
			minLevel = LogLevel.error;
		}

		override void log(ref LogLine line) @safe
		{
			lines ~= line.text;
		}
	}
}

unittest  // an executor that throws fails the task with a generic internal error
{
	import std.algorithm : any, canFind;
	import vibe.core.log : deregisterLogger, registerLogger;
	import mcp.server.task_runtime : TaskOptions;

	auto logger = new CaptureLogger;
	auto shared_ = () @trusted { return cast(shared) logger; }();
	() @trusted { registerLogger(shared_); }();
	scope (exit)
		() @trusted { deregisterLogger(shared_); }();

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("boom", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		throw new Exception("kaboom");
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["code"].get!int == cast(int) ErrorCode.internalError);
	assert(d["error"]["message"].get!string == "Internal error");
	auto lines = () @trusted { return (cast() logger).lines; }();
	assert(lines.any!(l => l.canFind("kaboom")));
}

unittest  // exposeInternalErrors records a throwing executor's own message
{
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	rt.exposeInternalErrors = true;
	auto t = rt.createFor("boom", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		throw new Exception("kaboom");
	});
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["message"].get!string == "kaboom");
}

unittest  // an executor's McpException message is recorded verbatim
{
	import mcp.server.task_runtime : TaskOptions;
	import mcp.protocol.errors : invalidParams;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("boom", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		throw invalidParams("bad input");
	});
	assert(rt.getDetailed(t.taskId)["error"]["message"].get!string == "bad input");
}

unittest  // a cancel observed during the run marks the task cancelled, not completed
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	rt.cancel(t.taskId); // sets the cooperative flag (executor-backed: status stays working)
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		// Executor returns a result, but a cancel was requested.
		return Json(["structuredContent": Json.emptyObject]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // a task cancelled before its dispatch runs is cancelled without invoking the executor
{
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	rt.cancel(t.taskId);
	bool ran;
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		ran = true;
		return Json.emptyObject;
	});
	assert(!ran);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // a task whose record is gone before its dispatch runs never invokes the executor
{
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	bool ran;
	runTaskExecutor(rt, "no-such-task", (TaskContext tc) @safe {
		ran = true;
		return Json.emptyObject;
	});
	assert(!ran);
}

unittest  // an executor that throws after a cancel was requested ends the task cancelled
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		rt.cancel(tc.taskId);
		throw new Exception("aborted on cancel");
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // an executor that throws an McpException after a cancel ends the task cancelled
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;
	import mcp.protocol.errors : internalError;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		rt.cancel(tc.taskId);
		throw internalError("aborted on cancel");
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // cancelling a task suspended for input cancels it at once
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		return tc.requireInput([InputRequest.elicitation("ok", "Proceed?")]);
	});
	rt.cancel(t.taskId);
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "cancelled");
	assert("inputRequests" !in d);
}

unittest  // cancelling a detached task cancels it at once; a later completion is ignored
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("deploy", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		return tc.detach("deploying");
	});
	rt.cancel(t.taskId);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
	rt.complete(t.taskId, Json.emptyObject);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // requireInput after a cancel was requested cancels instead of suspending
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		rt.cancel(tc.taskId); // arrives while the executor is running
		return tc.requireInput([InputRequest.elicitation("ok", "Proceed?")]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // detach after a cancel was requested cancels instead of detaching
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("deploy", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		rt.cancel(tc.taskId);
		return tc.detach();
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // an executor that swallows its suspension still leaves the task input_required
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		try
			tc.requireInput([InputRequest.elicitation("ok", "Proceed?")]);
		catch (Exception)
		{
		}
		return Json(["structuredContent": Json.emptyObject]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "input_required");
}

unittest  // an executor that swallows its detach leaves the task working
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("deploy", Json.undefined);
	runTaskExecutor(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		try
			tc.detach();
		catch (Exception)
		{
		}
		throw new Exception("after detach");
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
}

unittest  // re-requesting an input key discards its earlier answer, so only a fresh one satisfies it
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("retry", Json.undefined);
	TaskExecutor exec = (TaskContext tc) @safe {
		if (!tc.hasInput("x"))
			return tc.requireInput([InputRequest.elicitation("x", "x?")]);
		if (tc.inputAs!int("x") < 0) // invalid: ask again
			return tc.requireInput([InputRequest.elicitation("x", "x again?")]);
		return Json([
			"structuredContent": Json(["x": Json(tc.inputAs!int("x"))])
		]);
	};
	runTaskExecutor(rt, t.taskId, exec);
	rt.deliverInput(t.taskId, Json(["x": Json(-1)]));
	rt.resumeWorking(t.taskId);
	runTaskExecutor(rt, t.taskId, exec);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "input_required");
	assert(("x" in rt.takenInput(t.taskId)) is null, "the stale answer was discarded");
	rt.deliverInput(t.taskId, Json(["x": Json(5)]));
	rt.resumeWorking(t.taskId);
	runTaskExecutor(rt, t.taskId, exec);
	assert(rt.getDetailed(t.taskId)["result"]["structuredContent"]["x"].get!int == 5);
}

unittest  // re-requesting one key keeps the answers to other keys from earlier rounds
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("two", Json.undefined);
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")])
	]));
	rt.deliverInput(t.taskId, Json(["a": Json(1)]));
	rt.resumeWorking(t.taskId);
	rt.requireInput(t.taskId, Json([
			"b": Json(["method": Json("elicitation/create")])
	]));
	assert(("a" in rt.takenInput(t.taskId)) !is null);
}

unittest  // checkpoint state survives a suspension and is restored on re-run
{
	import mcp.server.task_store : InMemoryTaskStore;
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
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

unittest  // an executor's input and checkpoint reads share one store read per dispatch
{
	import mcp.server.task_store : TaskStore, InMemoryTaskStore, TaskRecord;
	import mcp.server.task_runtime : TaskOptions;

	static final class CountingStore : TaskStore
	{
		InMemoryTaskStore inner;
		size_t gets;

		this() @safe
		{
			inner = new InMemoryTaskStore();
		}

		bool put(TaskRecord r) @safe
		{
			return inner.put(r);
		}

		Nullable!TaskRecord get(string id) @safe
		{
			gets++;
			return inner.get(id);
		}

		bool compareAndSwap(TaskRecord r, ulong expected) @safe
		{
			return inner.compareAndSwap(r, expected);
		}

		void remove(string id) @safe
		{
			inner.remove(id);
		}

		size_t removeIf(scope bool delegate(const TaskRecord) @safe pred) @safe
		{
			return inner.removeIf(pred);
		}
	}

	auto store = new CountingStore();
	TaskOptions o;
	o.store = store;
	auto rt = new TaskRuntime(o);
	auto t = rt.createFor("reader", Json(["n": Json(1)]));
	rt.putCheckpoint(t.taskId, "seen", Json(true));
	runTaskExecutor(rt, t.taskId, (TaskContext tc) @safe {
		const before = store.gets;
		foreach (_; 0 .. 5)
		{
			assert(tc.inputJson()["n"].get!int == 1);
			assert(!tc.hasInput("x"));
			assert(tc.input("x").type == Json.Type.undefined);
			assert(tc.hasCheckpoint("seen"));
			assert(tc.restore!bool("seen"));
		}
		assert(store.gets - before == 1, "reads after the first must come from the snapshot");
		tc.checkpoint("later", 2);
		assert(tc.restore!int("later") == 2);
		return Json(["content": Json.emptyArray]);
	});
	assert(rt.getDetailed(t.taskId)["status"].get!string == "completed");
}

unittest  // an inline executor forwards its request's cancellation to the task only once
{
	import mcp.server.task_runtime : TaskOptions;

	auto rt = new TaskRuntime(TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	bool started;
	int cancelledPolls;
	runTaskExecutorInline(rt, t.taskId, delegate Json(TaskContext tc) @safe {
		started = true;
		foreach (_; 0 .. 3)
			assert(tc.cancelRequested());
		return Json.emptyObject;
	}, () @safe {
		if (started)
			cancelledPolls++;
		return started;
	});
	assert(cancelledPolls == 1);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}
