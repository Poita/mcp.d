module mcp.server.task_runtime;

import core.time : Duration, seconds;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.tasks;
import mcp.protocol.errors : McpException, ErrorCode;
import mcp.server.task_store : TaskStore, InMemoryTaskStore, TaskIdGenerator,
	defaultTaskIdGenerator;

@safe:

/// Tuning for the task runtime. `idGenerator` mints task IDs (default
/// `defaultTaskIdGenerator`). `defaultTtlMs` / `defaultPollIntervalMs` seed a
/// task's `ttlMs` / `pollIntervalMs` when a creator does not specify them.
/// `sweepInterval` is how often the (fiber-layer) TTL sweep runs. `nowIso` is an
/// injectable clock returning an ISO-8601 timestamp; null uses the system clock.
struct TaskOptions
{
	TaskIdGenerator idGenerator;
	long defaultTtlMs = 60_000;
	long defaultPollIntervalMs = 5_000;
	Duration sweepInterval = 30.seconds;
	string delegate() @safe nowIso;
}

/// Live, non-persisted coordination state for an in-flight task: the cancel
/// request flag, input responses delivered via `tasks/update` awaiting the
/// handler, and the outstanding `inputRequests` surfaced on `tasks/get` while
/// the task is `input_required`.
final class TaskRuntimeEntry
{
	bool cancelRequested;
	Json[string] inputResponses;
	Json outstandingInputRequests = Json.emptyObject;
	Nullable!Json result; /// final result for a completed task
	Nullable!Json error; /// JSON-RPC error for a failed task
}

/// The system clock as an ISO-8601 UTC timestamp, used when `TaskOptions.nowIso`
/// is not supplied.
string systemNowIso() @safe
{
	import std.datetime.systime : Clock;

	return () @trusted { return Clock.currTime().toUTC().toISOExtString(); }();
}

/// Server-side task lifecycle over a `TaskStore` plus live coordination state.
///
/// `create` mints a `working` task; the transition helpers (`progress`,
/// `complete`, `fail`, `requireInput`, `cancel`) update the stored `Task` and
/// stamp `lastUpdatedAt`. `getDetailed` builds the `tasks/get` response, and
/// `deliverInput` records `tasks/update` responses. A status-change callback (set
/// via `onStatusChange`) lets the server emit `notifications/tasks`.
final class TaskRuntime
{
	private TaskStore store_;
	private TaskOptions opts_;
	private TaskRuntimeEntry[string] entries_;
	private void delegate(Json detailed) @safe onStatusChange_;

	this(TaskStore store, TaskOptions opts) @safe
	{
		store_ = (store is null) ? new InMemoryTaskStore() : store;
		opts_ = opts;
		if (opts_.idGenerator is null)
			opts_.idGenerator = () @safe => defaultTaskIdGenerator();
		if (opts_.nowIso is null)
			opts_.nowIso = () @safe => systemNowIso();
	}

	/// The backing durable store.
	TaskStore store() @safe
	{
		return store_;
	}

	/// Register a callback invoked with the full `DetailedTask` JSON whenever a
	/// task's status changes, so the server can push `notifications/tasks`.
	void onStatusChange(void delegate(Json detailed) @safe cb) @safe
	{
		onStatusChange_ = cb;
	}

	/// Create a fresh `working` task. `ttlMs`/`pollIntervalMs` default to the
	/// runtime options when null. The returned `Task` is the seed for a
	/// `CreateTaskResult`. The generated ID is guaranteed unique against the store.
	Task create(Nullable!long ttlMs = Nullable!long.init,
			Nullable!long pollIntervalMs = Nullable!long.init) @safe
	{
		string id;
		// Defend against a misbehaving custom generator returning a duplicate.
		foreach (_; 0 .. 8)
		{
			id = opts_.idGenerator();
			if (store_.get(id).isNull)
				break;
			id = "";
		}
		if (id.length == 0)
			throw new McpException(ErrorCode.internalError,
					"task id generator failed to produce a unique id");

		Task t;
		t.taskId = id;
		t.status = TaskStatus.working;
		const now = opts_.nowIso();
		t.createdAt = now;
		t.lastUpdatedAt = now;
		t.ttlMs = ttlMs.isNull ? nullable(opts_.defaultTtlMs) : ttlMs;
		t.pollIntervalMs = pollIntervalMs.isNull
			? nullable(opts_.defaultPollIntervalMs) : pollIntervalMs;
		store_.put(t);
		entries_[id] = new TaskRuntimeEntry();
		return t;
	}

	private Task require(string id) @safe
	{
		auto t = store_.get(id);
		if (t.isNull)
		{
			Json data = Json.emptyObject;
			data["taskId"] = id;
			throw new McpException(ErrorCode.invalidParams, "Task not found", data);
		}
		return t.get;
	}

	private void touchAndStore(ref Task t) @safe
	{
		t.lastUpdatedAt = opts_.nowIso();
		store_.update(t);
		if (onStatusChange_ !is null)
			onStatusChange_(getDetailed(t.taskId));
	}

	/// Update a `working`/`input_required` task's human-readable status message.
	void progress(string id, string statusMessage) @safe
	{
		auto t = require(id);
		t.statusMessage = nullable(statusMessage);
		touchAndStore(t);
	}

	/// Move a task to `completed`, storing the final result for `tasks/get`.
	void complete(string id, Json result) @safe
	{
		auto t = require(id);
		t.status = TaskStatus.completed;
		store_.put(t); // ensure present before result lookup
		if (auto e = id in entries_)
		{
			e.result = result;
			e.outstandingInputRequests = Json.emptyObject;
		}
		touchAndStore(t);
	}

	/// Move a task to `failed`, storing the JSON-RPC error for `tasks/get`.
	void fail(string id, Json error) @safe
	{
		auto t = require(id);
		t.status = TaskStatus.failed;
		if (auto e = id in entries_)
		{
			e.error = error;
			e.outstandingInputRequests = Json.emptyObject;
		}
		touchAndStore(t);
	}

	/// Move a task to `input_required`, surfacing `inputRequests` on the next
	/// `tasks/get`. `inputRequests` follows the MRTR shape (a map of unique keys
	/// to server-to-client requests).
	void requireInput(string id, Json inputRequests) @safe
	{
		auto t = require(id);
		t.status = TaskStatus.inputRequired;
		if (auto e = id in entries_)
			e.outstandingInputRequests = (inputRequests.type == Json.Type.object)
				? inputRequests : Json.emptyObject;
		touchAndStore(t);
	}

	/// Move a task back to `working` (e.g. after its required input arrived).
	void resumeWorking(string id) @safe
	{
		auto t = require(id);
		t.status = TaskStatus.working;
		if (auto e = id in entries_)
			e.outstandingInputRequests = Json.emptyObject;
		touchAndStore(t);
	}

	/// Mark a task `cancelled` and record the cancel request. Cancellation is
	/// cooperative; a fiber-backed task may still finish in another terminal
	/// state, but with no running fiber this transitions immediately.
	void cancel(string id) @safe
	{
		auto t = require(id);
		if (auto e = id in entries_)
			e.cancelRequested = true;
		if (t.status == TaskStatus.completed || t.status == TaskStatus.failed
				|| t.status == TaskStatus.cancelled)
			return; // already terminal
		t.status = TaskStatus.cancelled;
		touchAndStore(t);
	}

	/// Whether cancellation was requested for `id` (cooperative check for a
	/// running handler).
	bool cancelRequested(string id) @safe
	{
		if (auto e = id in entries_)
			return e.cancelRequested;
		return false;
	}

	/// Record `tasks/update` input responses for a task. Unknown/satisfied keys
	/// are accepted silently (the runtime keeps the latest value per key).
	void deliverInput(string id, Json inputResponses) @safe
	{
		require(id); // throws if unknown task
		auto e = id in entries_;
		if (e is null || inputResponses.type != Json.Type.object)
			return;
		() @trusted {
			foreach (string k, v; inputResponses)
				e.inputResponses[k] = v;
		}();
	}

	/// The responses delivered so far for a task (keyed by input-request key).
	Json[string] takenInput(string id) @safe
	{
		if (auto e = id in entries_)
			return e.inputResponses;
		return null;
	}

	/// Build the `tasks/get` (`DetailedTask`) response for `id`. Throws
	/// `-32602 Task not found` (with the taskId in `data`) for an unknown task.
	Json getDetailed(string id) @safe
	{
		auto t = require(id);
		auto e = id in entries_;
		final switch (t.status)
		{
		case TaskStatus.working:
		case TaskStatus.cancelled:
			return makeDetailedTask(t, DetailedTaskPayload.none());
		case TaskStatus.inputRequired:
			Json reqs = (e !is null) ? e.outstandingInputRequests : Json.emptyObject;
			return makeDetailedTask(t, DetailedTaskPayload.inputRequests(reqs));
		case TaskStatus.completed:
			Json r = (e !is null && !e.result.isNull) ? e.result.get : Json.emptyObject;
			return makeDetailedTask(t, DetailedTaskPayload.completed(r));
		case TaskStatus.failed:
			Json err = (e !is null && !e.error.isNull) ? e.error.get : Json.emptyObject;
			return makeDetailedTask(t, DetailedTaskPayload.failed(err));
		}
	}
}

unittest  // create yields a working task with seeded ttl/poll and timestamps
{
	TaskOptions o;
	o.nowIso = () @safe => "2026-06-07T10:30:00Z";
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	auto t = rt.create();
	assert(t.status == TaskStatus.working);
	assert(t.taskId.length > 0);
	assert(t.createdAt == "2026-06-07T10:30:00Z");
	assert(t.ttlMs.get == 60_000 && t.pollIntervalMs.get == 5_000);
	// stored and retrievable
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
}

unittest  // create honors explicit ttl/poll overrides
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create(nullable(1_000L), nullable(250L));
	assert(t.ttlMs.get == 1_000 && t.pollIntervalMs.get == 250);
}

unittest  // complete stores the result and getDetailed inlines it
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	Json result = Json(["content": Json([Json(["type": Json("text"), "text": Json("done")])])]);
	rt.complete(t.taskId, result);
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "completed");
	assert(d["result"]["content"][0]["text"].get!string == "done");
}

unittest  // fail stores the JSON-RPC error and getDetailed inlines it
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.fail(t.taskId, Json(["code": Json(-32000), "message": Json("boom")]));
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["code"].get!int == -32000);
}

unittest  // requireInput surfaces inputRequests and deliverInput records responses
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	Json reqs = Json(["k1": Json(["method": Json("elicitation/create")])]);
	rt.requireInput(t.taskId, reqs);
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "input_required");
	assert(d["inputRequests"]["k1"]["method"].get!string == "elicitation/create");

	rt.deliverInput(t.taskId, Json(["k1": Json(["answer": Json("yes")])]));
	assert(rt.takenInput(t.taskId)["k1"]["answer"].get!string == "yes");
}

unittest  // cancel transitions a non-terminal task to cancelled and records the request
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.cancel(t.taskId);
	assert(rt.cancelRequested(t.taskId));
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // cancel does not override an already-completed task
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.complete(t.taskId, Json.emptyObject);
	rt.cancel(t.taskId);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "completed");
}

unittest  // getDetailed throws -32602 with the taskId for an unknown task
{
	import std.exception : collectException;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto ex = cast(McpException) collectException(rt.getDetailed("nope"));
	assert(ex !is null);
	assert(ex.code == ErrorCode.invalidParams);
}

unittest  // onStatusChange fires with the DetailedTask on each transition
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	int calls;
	string lastStatus;
	rt.onStatusChange((Json d) @safe { calls++; lastStatus = d["status"].get!string; });
	auto t = rt.create();
	rt.complete(t.taskId, Json.emptyObject);
	assert(calls >= 1);
	assert(lastStatus == "completed");
}

unittest  // a unique-id collision from a bad generator is retried, then errors
{
	import std.exception : collectException;

	TaskOptions o;
	o.idGenerator = () @safe => "dup"; // always the same id
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	auto first = rt.create();
	assert(first.taskId == "dup");
	// Second create cannot find a free id and must error rather than overwrite.
	auto ex = cast(McpException) collectException(rt.create());
	assert(ex !is null && ex.code == ErrorCode.internalError);
}
