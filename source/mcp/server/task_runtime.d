module mcp.server.task_runtime;

import core.time : Duration, seconds;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.tasks;
import mcp.protocol.errors : McpException, ErrorCode;
import mcp.server.task_store : TaskStore, TaskRecord, InMemoryTaskStore,
	TaskIdGenerator, defaultTaskIdGenerator;

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

/// The system clock as an ISO-8601 UTC timestamp, used when `TaskOptions.nowIso`
/// is not supplied.
string systemNowIso() @safe
{
	import std.datetime.systime : Clock;

	return () @trusted { return Clock.currTime().toUTC().toISOExtString(); }();
}

/// Server-side task lifecycle over a `TaskStore`. Every piece of task state —
/// status, result, error, inputRequests, inputResponses, the cancel flag, and the
/// executor's durable input/checkpoints — lives in the store, so a runtime on any
/// node reconstructs a task purely from its ID. There is no in-process task state,
/// which is what makes a shared store yield a correct multi-node deployment.
///
/// `create`/`createFor` mint a `working` task; the transition helpers (`progress`,
/// `complete`, `fail`, `requireInput`, `resumeWorking`, `cancel`) read-modify-write
/// the stored `TaskRecord` and stamp `lastUpdatedAt`. `getDetailed` builds the
/// `tasks/get` response from the record, and `deliverInput` records `tasks/update`
/// responses. A status-change callback (set via `onStatusChange`) lets the server
/// emit `notifications/tasks`.
final class TaskRuntime
{
	private TaskStore store_;
	private TaskOptions opts_;
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

	/// Create a fresh `working` task with no associated executor (the manual path,
	/// where the caller drives the lifecycle itself). `ttlMs`/`pollIntervalMs`
	/// default to the runtime options when null.
	Task create(Nullable!long ttlMs = Nullable!long.init,
			Nullable!long pollIntervalMs = Nullable!long.init) @safe
	{
		return createFor("", Json.undefined, ttlMs, pollIntervalMs);
	}

	/// Create a fresh `working` task bound to a registered executor (`toolName`),
	/// persisting `executorInput` as the durable input the executor reconstitutes
	/// on each dispatch. The returned `Task` seeds a `CreateTaskResult`. The
	/// generated ID is guaranteed unique against the store.
	Task createFor(string toolName, Json executorInput,
			Nullable!long ttlMs = Nullable!long.init,
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

		TaskRecord r;
		r.meta.taskId = id;
		r.meta.status = TaskStatus.working;
		const now = opts_.nowIso();
		r.meta.createdAt = now;
		r.meta.lastUpdatedAt = now;
		r.meta.ttlMs = ttlMs.isNull ? nullable(opts_.defaultTtlMs) : ttlMs;
		r.meta.pollIntervalMs = pollIntervalMs.isNull
			? nullable(opts_.defaultPollIntervalMs) : pollIntervalMs;
		r.toolName = toolName;
		r.executorInput = executorInput;
		store_.put(r);
		return r.meta;
	}

	private TaskRecord require(string id) @safe
	{
		auto r = store_.get(id);
		if (r.isNull)
		{
			Json data = Json.emptyObject;
			data["taskId"] = id;
			throw new McpException(ErrorCode.invalidParams, "Task not found", data);
		}
		return r.get;
	}

	private void touchAndStore(ref TaskRecord r) @safe
	{
		r.meta.lastUpdatedAt = opts_.nowIso();
		store_.update(r);
		if (onStatusChange_ !is null)
			onStatusChange_(getDetailed(r.meta.taskId));
	}

	/// Whether a status is terminal (`completed`/`failed`/`cancelled`).
	private static bool isTerminal(TaskStatus s) @safe pure nothrow
	{
		return s == TaskStatus.completed || s == TaskStatus.failed
			|| s == TaskStatus.cancelled;
	}

	/// Update a `working`/`input_required` task's human-readable status message.
	void progress(string id, string statusMessage) @safe
	{
		auto r = require(id);
		r.meta.statusMessage = nullable(statusMessage);
		touchAndStore(r);
	}

	/// Move a task to `completed`, storing the final result for `tasks/get`. A
	/// no-op if the task is already terminal (e.g. a cancel landed first).
	void complete(string id, Json result) @safe
	{
		auto r = require(id);
		if (isTerminal(r.meta.status))
			return;
		r.meta.status = TaskStatus.completed;
		r.result = nullable(result);
		r.inputRequests = Json.emptyObject;
		touchAndStore(r);
	}

	/// Move a task to `failed`, storing the JSON-RPC error for `tasks/get`. A
	/// no-op if the task is already terminal.
	void fail(string id, Json error) @safe
	{
		auto r = require(id);
		if (isTerminal(r.meta.status))
			return;
		r.meta.status = TaskStatus.failed;
		r.error = nullable(error);
		r.inputRequests = Json.emptyObject;
		touchAndStore(r);
	}

	/// Move a task to `input_required`, surfacing `inputRequests` on the next
	/// `tasks/get`. `inputRequests` follows the MRTR shape (a map of unique keys
	/// to server-to-client requests).
	void requireInput(string id, Json inputRequests) @safe
	{
		auto r = require(id);
		r.meta.status = TaskStatus.inputRequired;
		r.inputRequests = (inputRequests.type == Json.Type.object)
			? inputRequests : Json.emptyObject;
		touchAndStore(r);
	}

	/// Move a task back to `working` (e.g. after its required input arrived).
	void resumeWorking(string id) @safe
	{
		auto r = require(id);
		r.meta.status = TaskStatus.working;
		r.inputRequests = Json.emptyObject;
		touchAndStore(r);
	}

	/// Request cancellation. Always records the cooperative `cancelRequested`
	/// flag. For a task with no executor to honor it (`toolName` empty), the
	/// runtime transitions to `cancelled` immediately; for an executor-backed
	/// task it leaves the status untouched so the running executor can observe the
	/// flag and decide its own terminal state (cancellation is cooperative).
	void cancel(string id) @safe
	{
		auto r = require(id);
		if (isTerminal(r.meta.status))
			return;
		r.cancelRequested = true;
		if (r.toolName.length == 0)
			r.meta.status = TaskStatus.cancelled;
		touchAndStore(r);
	}

	/// Mark a task `cancelled` (used by an executor that honored a cancel
	/// request). A no-op if already terminal.
	void markCancelled(string id) @safe
	{
		auto r = require(id);
		if (isTerminal(r.meta.status))
			return;
		r.meta.status = TaskStatus.cancelled;
		touchAndStore(r);
	}

	/// Whether cancellation was requested for `id` (cooperative check for a
	/// running handler).
	bool cancelRequested(string id) @safe
	{
		auto r = store_.get(id);
		return !r.isNull && r.get.cancelRequested;
	}

	/// Record `tasks/update` input responses for a task. Unknown/satisfied keys
	/// are accepted silently (the runtime keeps the latest value per key).
	void deliverInput(string id, Json inputResponses) @safe
	{
		auto r = require(id); // throws if unknown task
		if (inputResponses.type != Json.Type.object)
			return;
		() @trusted {
			foreach (string k, v; inputResponses)
				r.inputResponses[k] = v;
		}();
		store_.update(r);
	}

	/// The responses delivered so far for a task (keyed by input-request key).
	Json[string] takenInput(string id) @safe
	{
		auto r = store_.get(id);
		return r.isNull ? null : r.get.inputResponses;
	}

	/// The durable executor input recorded at creation, or `undefined`.
	Json executorInput(string id) @safe
	{
		auto r = store_.get(id);
		return r.isNull ? Json.undefined : r.get.executorInput;
	}

	/// The registered executor key (`toolName`) bound to a task, or empty.
	string toolName(string id) @safe
	{
		auto r = store_.get(id);
		return r.isNull ? "" : r.get.toolName;
	}

	/// Persist a re-entry checkpoint value under `key`.
	void putCheckpoint(string id, string key, Json value) @safe
	{
		auto r = require(id);
		r.checkpoints[key] = value;
		store_.update(r);
	}

	/// Read a previously stored checkpoint value, or `undefined` if absent.
	Json getCheckpoint(string id, string key) @safe
	{
		auto r = store_.get(id);
		if (r.isNull)
			return Json.undefined;
		if (auto p = key in r.get.checkpoints)
			return *p;
		return Json.undefined;
	}

	/// Build the `tasks/get` (`DetailedTask`) response for `id`. Throws
	/// `-32602 Task not found` (with the taskId in `data`) for an unknown task.
	Json getDetailed(string id) @safe
	{
		auto r = require(id);
		final switch (r.meta.status)
		{
		case TaskStatus.working:
		case TaskStatus.cancelled:
			return makeDetailedTask(r.meta, DetailedTaskPayload.none());
		case TaskStatus.inputRequired:
			return makeDetailedTask(r.meta, DetailedTaskPayload.inputRequests(r.inputRequests));
		case TaskStatus.completed:
			return makeDetailedTask(r.meta,
					DetailedTaskPayload.completed(r.result.isNull ? Json.emptyObject : r.result.get));
		case TaskStatus.failed:
			return makeDetailedTask(r.meta,
					DetailedTaskPayload.failed(r.error.isNull ? Json.emptyObject : r.error.get));
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
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
}

unittest  // create honors explicit ttl/poll overrides
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create(nullable(1_000L), nullable(250L));
	assert(t.ttlMs.get == 1_000 && t.pollIntervalMs.get == 250);
}

unittest  // createFor records the executor toolName and durable input
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("word_count", Json(["text": Json("hi there")]));
	assert(rt.toolName(t.taskId) == "word_count");
	assert(rt.executorInput(t.taskId)["text"].get!string == "hi there");
}

unittest  // complete stores the result and getDetailed inlines it
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	Json result = Json([
		"content": Json([Json(["type": Json("text"), "text": Json("done")])])
	]);
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

unittest  // a manual (executor-less) task cancels immediately
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.cancel(t.taskId);
	assert(rt.cancelRequested(t.taskId));
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // an executor-backed task cancels cooperatively (flag set, status unchanged)
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	rt.cancel(t.taskId);
	assert(rt.cancelRequested(t.taskId));
	// Status stays working until the executor honors the request.
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
	rt.markCancelled(t.taskId);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // complete does not override an already-cancelled task
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.cancel(t.taskId);
	rt.complete(t.taskId, Json.emptyObject);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // checkpoints persist and read back
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("multi", Json.undefined);
	rt.putCheckpoint(t.taskId, "stage", Json("approved"));
	assert(rt.getCheckpoint(t.taskId, "stage").get!string == "approved");
	assert(rt.getCheckpoint(t.taskId, "missing").type == Json.Type.undefined);
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
	rt.onStatusChange((Json d) @safe {
		calls++;
		lastStatus = d["status"].get!string;
	});
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
	auto ex = cast(McpException) collectException(rt.create());
	assert(ex !is null && ex.code == ErrorCode.internalError);
}

unittest  // STATELESSNESS: two runtimes sharing one store see each other's state
{
	// The core guarantee: task state lives entirely in the store, so a runtime on
	// a different node (here, a second TaskRuntime over the same store) resolves a
	// task created/advanced by the first — result, inputRequests, and responses.
	auto store = new InMemoryTaskStore();
	auto nodeA = new TaskRuntime(store, TaskOptions.init);
	auto nodeB = new TaskRuntime(store, TaskOptions.init);

	// A creates and an executor on A requires input; B must see input_required.
	auto t = nodeA.createFor("deploy", Json(["build": Json("v9")]));
	nodeA.requireInput(t.taskId, Json([
		"approval": Json(["method": Json("elicitation/create")])
	]));
	auto onB = nodeB.getDetailed(t.taskId);
	assert(onB["status"].get!string == "input_required");
	assert(onB["inputRequests"]["approval"]["method"].get!string == "elicitation/create");

	// B receives the tasks/update; A (a different node) must see the answer and
	// the durable executor input.
	nodeB.deliverInput(t.taskId, Json(["approval": Json(["answer": Json("ok")])]));
	assert(nodeA.takenInput(t.taskId)["approval"]["answer"].get!string == "ok");
	assert(nodeA.executorInput(t.taskId)["build"].get!string == "v9");

	// A completes; B sees the result.
	nodeA.complete(t.taskId, Json(["structuredContent": Json(["ok": Json(true)])]));
	auto done = nodeB.getDetailed(t.taskId);
	assert(done["status"].get!string == "completed");
	assert(done["result"]["structuredContent"]["ok"].get!bool);
}
