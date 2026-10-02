module mcp.server.task_runtime;

import core.time : Duration, hours, minutes, seconds, msecs;
import std.datetime.systime : SysTime;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json, serializeToJson;

import mcp.internal.background_loop : BackgroundLoop;
import mcp.internal.clock : systemNowIso;
import mcp.protocol.tasks;
import mcp.protocol.errors : McpException, ErrorCode, toErrorJson, internalError;
import mcp.server.task_store : TaskStore, TaskRecord, InMemoryTaskStore,
	TaskIdGenerator, defaultTaskIdGenerator;

@safe:

/// The TTL that keeps a settled task's record forever (wire `ttlMs: null`). Pass
/// it as a creator's `ttl` or as `TaskOptions.defaultTtl`; the record then lives
/// until the store removes it.
enum Duration unlimitedTaskTtl = Duration.max;

/// Tuning for the task runtime. `idGenerator` mints task IDs (default
/// `defaultTaskIdGenerator`). `defaultTtl` / `defaultPollInterval` seed a task's
/// TTL / suggested poll cadence when a creator does not specify them. A task's
/// TTL is how long its record is kept once it settles (`unlimitedTaskTtl` keeps
/// it forever); a task that is still working or awaiting input does not expire
/// by TTL. `maxUnsettledAge` bounds that instead: a task still unsettled that
/// long after `createdAt` (its executor hung or its node vanished) is failed —
/// or cancelled, when a cancel was requested — and then expires by its TTL like
/// any settled task; zero disables the bound.
/// `sweepInterval` is how often `enableTasks`'s background sweep removes expired
/// tasks (zero disables it; expired tasks are still hidden on access). `nowIso` is an
/// injectable clock returning an ISO-8601 timestamp; null uses the system clock.
struct TaskOptions
{
	TaskIdGenerator idGenerator;
	Duration defaultTtl = 10.minutes;
	Duration defaultPollInterval = 5.seconds;
	Duration sweepInterval = 30.seconds;
	Duration maxUnsettledAge = 24.hours;
	string delegate() @safe nowIso;
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
	private void delegate(Json detailed, string owner) @safe onStatusChange_;
	private BackgroundLoop sweeper_;
	// Tasks whose status changes are not pushed: ephemeral records whose id no
	// client ever learns.
	private bool[string] silenced_;

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

	/// Register a callback invoked with the full `DetailedTask` JSON and the task's
	/// owning principal whenever a task's status changes, so the server can push
	/// `notifications/tasks` to that principal only.
	void onStatusChange(void delegate(Json detailed, string owner) @safe cb) @safe
	{
		onStatusChange_ = cb;
	}

	/// Stop (`silent` true) or resume pushing status changes of task `id` to the
	/// `onStatusChange` sink. Used for a task record that backs a synchronous
	/// call, whose client never sees the task.
	package(mcp) void setSilent(string id, bool silent) @safe nothrow
	{
		if (silent)
			silenced_[id] = true;
		else
			silenced_.remove(id);
	}

	/// Create a fresh `working` task with no associated executor (the manual path,
	/// where the caller drives the lifecycle itself). `ttl`/`pollInterval` default
	/// to the runtime options when null.
	Task create(Nullable!Duration ttl = Nullable!Duration.init,
			Nullable!Duration pollInterval = Nullable!Duration.init) @safe
	{
		return createFor("", Json.undefined, ttl, pollInterval);
	}

	/// Create a fresh `working` task bound to a registered executor (`toolName`),
	/// persisting `executorInput` as the durable input the executor reconstitutes
	/// on each dispatch. The returned `Task` seeds a `CreateTaskResult`. The
	/// generated ID is guaranteed unique against the store. `ttl`/`pollInterval`
	/// default to the runtime options when null; both are serialized to integer
	/// milliseconds on the wire `Task`, except `unlimitedTaskTtl`, which is
	/// `ttlMs: null` and keeps the settled record forever. A non-empty `owner` (the creating
	/// request's authenticated principal) binds the task: `requireAccess` then
	/// admits only that principal.
	Task createFor(string toolName, Json executorInput,
			Nullable!Duration ttl = Nullable!Duration.init,
			Nullable!Duration pollInterval = Nullable!Duration.init, string owner = "") @safe
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

		const ttlDur = ttl.isNull ? opts_.defaultTtl : ttl.get;
		const pollDur = pollInterval.isNull ? opts_.defaultPollInterval : pollInterval.get;

		TaskRecord r;
		r.meta.taskId = id;
		r.meta.status = TaskStatus.working;
		const now = opts_.nowIso();
		r.meta.createdAt = now;
		r.meta.lastUpdatedAt = now;
		r.meta.ttlMs = ttlDur == unlimitedTaskTtl ? Nullable!long.init
			: nullable(ttlDur.total!"msecs");
		r.meta.pollIntervalMs = nullable(pollDur.total!"msecs");
		r.toolName = toolName;
		r.owner = owner;
		r.executorInput = executorInput;
		store_.put(r);
		return r.meta;
	}

	/// Enforce the task's principal binding for a tasks/* request made by
	/// `principal` ("" when unauthenticated). A task created by an authenticated
	/// principal is reachable only by that principal; one created without a
	/// principal is open to every request. A mismatch throws the same
	/// `-32602 Task not found` as an unknown id, so a foreign principal cannot
	/// learn that the task exists.
	void requireAccess(string id, string principal) @safe
	{
		auto r = require(id);
		if (r.owner.length && r.owner != principal)
			throw taskNotFound(id);
	}

	private TaskRecord require(string id) @safe
	{
		auto r = fetch(id);
		if (r.isNull)
			throw taskNotFound(id);
		return r.get;
	}

	/// The stored record for `id`, or null when unknown or expired. An expired
	/// record is removed on sight, and one unsettled past `maxUnsettledAge` is
	/// settled on sight, so both hold between sweeps.
	private Nullable!TaskRecord fetch(string id) @safe
	{
		auto r = store_.get(id);
		if (r.isNull)
			return r;
		const now = currentTime();
		if (isExpired(r.get, now))
		{
			store_.remove(id);
			return Nullable!TaskRecord.init;
		}
		if (isOverdue(r.get, now))
			return settleOverdue(r.get);
		return r;
	}

	/// Whether `r` is still unsettled `maxUnsettledAge` after it was created.
	private bool isOverdue(const TaskRecord r, SysTime now) @safe
	{
		if (opts_.maxUnsettledAge <= Duration.zero || isTerminal(r.meta.status))
			return false;
		try
			return now >= SysTime.fromISOExtString(r.meta.createdAt) + opts_.maxUnsettledAge;
		catch (Exception)
			return false;
	}

	/// Settle an overdue task: `cancelled` when a cancel was requested (its
	/// executor never honored it), `failed` otherwise. The cancel flag is set so
	/// an executor still running stops. Written by compare-and-swap, so a
	/// transition that lands first wins and the next access re-evaluates.
	/// Returns the record as it now stands.
	private Nullable!TaskRecord settleOverdue(TaskRecord r) @safe
	{
		const expected = r.revision;
		if (r.cancelRequested)
			transition(r, TaskStatus.cancelled);
		else
		{
			transition(r, TaskStatus.failed);
			r.error = nullable(toErrorJson(internalError(
					"Task did not settle within the server's maximum unsettled age")));
		}
		r.cancelRequested = true;
		r.inputRequests = Json.emptyObject;
		r.meta.lastUpdatedAt = opts_.nowIso();
		if (store_.compareAndSwap(r, expected))
			notifyStatusChange(r);
		return store_.get(r.meta.taskId);
	}

	/// The injected clock as a `SysTime`, falling back to the system clock when
	/// it does not yield an ISO-8601 extended timestamp.
	private SysTime currentTime() @safe
	{
		import std.datetime.systime : Clock;

		try
			return SysTime.fromISOExtString(opts_.nowIso());
		catch (Exception)
			return Clock.currTime();
	}

	/// Whether `r` has outlived its TTL at `now`. A task that has not settled
	/// never expires, so work running longer than its TTL is never discarded. A
	/// terminal task is retained for its TTL after it settled (`lastUpdatedAt`,
	/// frozen once terminal), giving the client that long to collect the result.
	/// A null TTL never expires.
	private static bool isExpired(const TaskRecord r, SysTime now) @safe
	{
		if (r.meta.ttlMs.isNull || !isTerminal(r.meta.status))
			return false;
		try
			return now >= SysTime.fromISOExtString(r.meta.lastUpdatedAt) + r.meta.ttlMs.get.msecs;
		catch (Exception)
			return false;
	}

	/// Remove every expired task from the store, returning how many were removed,
	/// and settle every task unsettled past `maxUnsettledAge`. `enableTasks` runs
	/// this every `TaskOptions.sweepInterval`.
	size_t sweepExpired() @safe
	{
		const now = currentTime();
		// The store offers no enumeration, so the removal pass also collects the
		// overdue tasks; they are settled afterwards, outside the store's scan.
		string[] overdue;
		const removed = store_.removeIf((const TaskRecord r) @safe {
			if (isOverdue(r, now))
				overdue ~= r.meta.taskId;
			return isExpired(r, now);
		});
		foreach (id; overdue)
			fetch(id);
		return removed;
	}

	/// Run `sweepExpired` every `interval` in a background fiber until
	/// `stopSweeper` is called or the event loop exits. Starting again replaces
	/// (and stops) a sweeper already running.
	void startSweeper(Duration interval) @safe
	{
		import vibe.core.core : runTask, sleep;
		import vibe.core.log : logError;

		stopSweeper();
		auto loop = new BackgroundLoop;
		sweeper_ = loop;
		loop.task = runTask(() nothrow @safe {
			while (!loop.stopped)
			{
				try
					sleep(interval);
				catch (Exception)
					return; // interrupted: stopped, or the event loop is shutting down
				if (loop.stopped)
					return;
				try
					sweepExpired();
				catch (Exception e)
					logError("task TTL sweep failed: %s", e.msg);
			}
		});
	}

	/// Stop the background sweeper started by `startSweeper`, if any.
	void stopSweeper() @safe nothrow
	{
		if (sweeper_ is null)
			return;
		sweeper_.stop();
		sweeper_ = null;
	}

	/// The `-32602 Task not found` error, with the offending `taskId` in `data`.
	private static McpException taskNotFound(string id) @safe
	{
		Json data = Json.emptyObject;
		data["taskId"] = id;
		return new McpException(ErrorCode.invalidParams, "Task not found", data);
	}

	/// What a `modify` mutation changed.
	private enum Change
	{
		none, /// nothing: leave the record as is
		state, /// internal state only: store it
		status /// wire-visible state: also stamp `lastUpdatedAt` and notify
	}

	/// Atomically apply `mutate` to the stored record for `id`: read it, let
	/// `mutate` change it, and write it back only if no other writer changed it
	/// in between, re-reading and retrying on a lost race. Returns whether a
	/// change was committed; throws `-32602 Task not found` for an unknown task.
	private bool modify(string id, scope Change delegate(ref TaskRecord) @safe mutate) @safe
	{
		enum maxAttempts = 64;
		foreach (_; 0 .. maxAttempts)
		{
			auto r = require(id);
			const expected = r.revision;
			const change = mutate(r);
			if (change == Change.none)
				return false;
			if (change == Change.status)
				r.meta.lastUpdatedAt = opts_.nowIso();
			if (!store_.compareAndSwap(r, expected))
				continue;
			if (change == Change.status)
				notifyStatusChange(r);
			return true;
		}
		throw internalError("task '" ~ id ~ "' is contended; the update was not applied");
	}

	/// Push a committed status change to the `onStatusChange` sink, built from the
	/// record as committed: a re-read could observe a later writer's state, so a
	/// state another transition superseded would never be reported. Best-effort:
	/// the transition is already stored and visible via `tasks/get`, so a failing
	/// sink (e.g. a closed output stream) is logged rather than propagated into
	/// the caller, which would otherwise fail or abort a healthy task.
	private void notifyStatusChange(const TaskRecord r) @safe
	{
		import vibe.core.log : logWarn;

		const id = r.meta.taskId;
		if (onStatusChange_ is null || id in silenced_)
			return;
		try
			onStatusChange_(detailedOf(r), r.owner);
		catch (Exception e)
			logWarn("task %s: status notification failed: %s", id, e.msg);
	}

	/// Move `r` to `status`. The status message describes the state being left,
	/// so it is cleared; a caller with a message for the new state sets it after.
	private static void transition(ref TaskRecord r, TaskStatus status) @safe
	{
		r.meta.status = status;
		r.meta.statusMessage = Nullable!string.init;
	}

	/// Update a `working`/`input_required` task's human-readable status message.
	/// A no-op if the task is already terminal. The next status transition
	/// clears it.
	void progress(string id, string statusMessage) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			r.meta.statusMessage = nullable(statusMessage);
			return Change.status;
		});
	}

	/// Move a task to `completed`, storing the final result for `tasks/get`. A
	/// no-op if the task is already terminal (e.g. a cancel landed first).
	void complete(string id, Json result) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			transition(r, TaskStatus.completed);
			r.result = nullable(result);
			r.inputRequests = Json.emptyObject;
			return Change.status;
		});
	}

	/// Move a task to `failed`, storing the JSON-RPC error for `tasks/get`. A
	/// no-op if the task is already terminal.
	void fail(string id, Json error) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			transition(r, TaskStatus.failed);
			r.error = nullable(error);
			r.inputRequests = Json.emptyObject;
			return Change.status;
		});
	}

	/// `fail` from an `McpException`, recording its JSON-RPC `code`/`message`/`data`.
	/// Pair with the error builders (`internalError`, `invalidParams`, …) instead of
	/// hand-rolling the error object.
	void fail(string id, const McpException e) @safe
	{
		fail(id, toErrorJson(e));
	}

	/// Move a task to `input_required`, surfacing `inputRequests` on the next
	/// `tasks/get`. `inputRequests` follows the MRTR shape (a map of unique keys
	/// to server-to-client requests); an earlier answer to a key requested again
	/// is discarded, so only a fresh answer satisfies it. A task whose cancellation was already
	/// requested is cancelled instead, since no dispatch would ever resume it. A
	/// no-op if the task is already terminal. Throws `internalError` when
	/// `inputRequests` is not a non-empty object: a task suspended with nothing to
	/// answer could never resume.
	void requireInput(string id, Json inputRequests) @safe
	{
		if (inputRequests.type != Json.Type.object || inputRequests.length == 0)
			throw internalError("task '" ~ id ~ "' requires input but supplied no input requests");
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			if (r.cancelRequested)
			{
				transition(r, TaskStatus.cancelled);
				r.inputRequests = Json.emptyObject;
			}
			else
			{
				transition(r, TaskStatus.inputRequired);
				r.inputRequests = inputRequests;
				// A key asked for again needs a fresh answer: drop the earlier one
				// so it cannot satisfy the new request. Other keys' answers stay,
				// since a re-run executor passes its earlier gates with them.
				foreach (k; r.inputRequests.get!(Json[string]).byKey)
					r.inputResponses.remove(k);
			}
			return Change.status;
		});
	}

	/// Record that the executor handed the task off to finish out of band
	/// (`TaskContext.detach`). The task stays `working`, but no dispatch is
	/// running any more, so a later cancel settles it at once; a cancel already
	/// requested cancels it now. A no-op if already terminal.
	void markDetached(string id) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			if (r.cancelRequested)
			{
				transition(r, TaskStatus.cancelled);
				return Change.status;
			}
			r.detached = true;
			return Change.state;
		});
	}

	/// Move an `input_required` task back to `working` (e.g. after its required
	/// input arrived). Returns whether this call made the transition, so when
	/// several resumers race exactly one of them re-dispatches the executor.
	bool resumeWorking(string id) @safe
	{
		return modify(id, (ref TaskRecord r) @safe {
			if (r.meta.status != TaskStatus.inputRequired)
				return Change.none;
			transition(r, TaskStatus.working);
			r.inputRequests = Json.emptyObject;
			r.detached = false;
			return Change.status;
		});
	}

	/// Request cancellation. Always records the cooperative `cancelRequested`
	/// flag. A task with no executor running to honor it — a manual task
	/// (`toolName` empty), one suspended in `input_required`, or one the executor
	/// detached — transitions to `cancelled` immediately; for a running executor
	/// the status is left untouched so it can observe the flag and decide its own
	/// terminal state (cancellation is cooperative).
	void cancel(string id) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			r.cancelRequested = true;
			if (r.toolName.length == 0 || r.detached || r.meta.status == TaskStatus.inputRequired)
			{
				transition(r, TaskStatus.cancelled);
				r.inputRequests = Json.emptyObject;
				return Change.status;
			}
			return Change.state;
		});
	}

	/// Mark a task `cancelled` (used by an executor that honored a cancel
	/// request). A no-op if already terminal.
	void markCancelled(string id) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			if (isTerminal(r.meta.status))
				return Change.none;
			transition(r, TaskStatus.cancelled);
			return Change.status;
		});
	}

	/// Whether cancellation was requested for `id` (cooperative check for a
	/// running handler). A task that no longer exists (expired past its TTL, or
	/// removed) also reports `true`: nothing can collect its result, so its
	/// executor should stop.
	bool cancelRequested(string id) @safe
	{
		auto r = fetch(id);
		return r.isNull || r.get.cancelRequested;
	}

	/// Record `tasks/update` input responses for a task, keeping the latest value
	/// per key. Throws `-32602` when `inputResponses` is not an object, when the
	/// task is unknown, when it is already terminal (no executor will ever read
	/// the answers), or when any key is not among the task's current
	/// `inputRequests` (nothing is recorded then; `data.keys` lists them).
	void deliverInput(string id, Json inputResponses) @safe
	{
		import mcp.protocol.errors : invalidParams;

		require(id);
		if (inputResponses.type != Json.Type.object)
			throw invalidParams("tasks/update 'inputResponses' must be an object");
		modify(id, (ref TaskRecord r) @trusted {
			if (isTerminal(r.meta.status))
			{
				Json data = Json.emptyObject;
				data["taskId"] = id;
				throw new McpException(ErrorCode.invalidParams,
					"Task is already " ~ taskStatusToWire(r.meta.status), data);
			}
			// Only answers to the current requests are kept, so a client cannot
			// grow the stored record with keys no executor will read.
			string[] unrequested;
			foreach (string k, v; inputResponses)
				if (r.inputRequests.type != Json.Type.object || k !in r.inputRequests)
					unrequested ~= k;
			if (unrequested.length)
			{
				import std.array : join;

				Json data = Json.emptyObject;
				data["taskId"] = id;
				data["keys"] = serializeToJson(unrequested);
				throw new McpException(ErrorCode.invalidParams,
					"Task has not requested input for: " ~ unrequested.join(", "), data);
			}
			foreach (string k, v; inputResponses)
				r.inputResponses[k] = v;
			return Change.state;
		});
	}

	/// The responses delivered so far for a task (keyed by input-request key).
	Json[string] takenInput(string id) @safe
	{
		auto r = fetch(id);
		return r.isNull ? null : r.get.inputResponses;
	}

	/// The durable executor input recorded at creation, or `undefined`.
	Json executorInput(string id) @safe
	{
		auto r = fetch(id);
		return r.isNull ? Json.undefined : r.get.executorInput;
	}

	/// The registered executor key (`toolName`) bound to a task, or empty.
	string toolName(string id) @safe
	{
		auto r = fetch(id);
		return r.isNull ? "" : r.get.toolName;
	}

	/// The current status of a task, or null if unknown.
	Nullable!TaskStatus statusOf(string id) @safe
	{
		auto r = fetch(id);
		return r.isNull ? Nullable!TaskStatus.init : nullable(r.get.meta.status);
	}

	/// Persist a re-entry checkpoint value under `key`.
	void putCheckpoint(string id, string key, Json value) @safe
	{
		modify(id, (ref TaskRecord r) @safe {
			r.checkpoints[key] = value;
			return Change.state;
		});
	}

	/// Read a previously stored checkpoint value, or `undefined` if absent.
	Json getCheckpoint(string id, string key) @safe
	{
		auto r = fetch(id);
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
		return detailedOf(require(id));
	}

	/// The `DetailedTask` JSON for record `r`.
	private static Json detailedOf(const TaskRecord r) @safe
	{
		final switch (r.meta.status)
		{
		case TaskStatus.working:
		case TaskStatus.cancelled:
		case TaskStatus.unknown:
			return makeDetailedTask(r.meta, DetailedTaskPayload.none());
		case TaskStatus.inputRequired:
			return makeDetailedTask(r.meta,
					DetailedTaskPayload.inputRequests(r.inputRequests));
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
	assert(t.ttlMs.get == 600_000 && t.pollIntervalMs.get == 5_000);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
}

unittest  // create honors explicit ttl/poll overrides
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create(nullable(1_000.msecs), nullable(250.msecs));
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

unittest  // fail from an McpException records its code, message, and data
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.fail(t.taskId, internalError("deploy failed", Json(["ref": Json("abc")])));
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["code"].get!int == cast(int) ErrorCode.internalError);
	assert(d["error"]["message"].get!string == "deploy failed");
	assert(d["error"]["data"]["ref"].get!string == "abc");
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
	rt.onStatusChange((Json d, string owner) @safe {
		calls++;
		lastStatus = d["status"].get!string;
	});
	auto t = rt.create();
	rt.complete(t.taskId, Json.emptyObject);
	assert(calls >= 1);
	assert(lastStatus == "completed");
}

unittest  // a throwing status-change sink neither fails the transition nor reaches the caller
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	rt.onStatusChange((Json d, string owner) @safe {
		throw new Exception("sink closed");
	});
	auto t = rt.createFor("gate", Json.undefined);
	rt.progress(t.taskId, "step 1");
	rt.requireInput(t.taskId, Json([
			"k": Json(["method": Json("elicitation/create")])
	]));
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "input_required");
}

unittest  // a status transition clears the previous status message
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto done = rt.createFor("t", Json.undefined);
	rt.progress(done.taskId, "halfway");
	rt.complete(done.taskId, Json.emptyObject);
	assert("statusMessage" !in rt.getDetailed(done.taskId));

	auto failed = rt.createFor("t", Json.undefined);
	rt.progress(failed.taskId, "halfway");
	rt.fail(failed.taskId, Json(["code": Json(-32000), "message": Json("boom")]));
	assert("statusMessage" !in rt.getDetailed(failed.taskId));

	auto cancelled = rt.createFor("t", Json.undefined);
	rt.progress(cancelled.taskId, "halfway");
	rt.cancel(cancelled.taskId);
	rt.markCancelled(cancelled.taskId);
	assert("statusMessage" !in rt.getDetailed(cancelled.taskId));

	auto resumed = rt.createFor("t", Json.undefined);
	rt.requireInput(resumed.taskId, Json([
			"k": Json(["method": Json("elicitation/create")])
	]));
	rt.progress(resumed.taskId, "waiting for approval");
	assert(rt.resumeWorking(resumed.taskId));
	assert("statusMessage" !in rt.getDetailed(resumed.taskId));
}

unittest  // requireInput rejects an empty request set and leaves the task working
{
	import std.exception : collectException;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	auto ex = cast(McpException) collectException(rt.requireInput(t.taskId, Json.emptyObject));
	assert(ex !is null && ex.code == ErrorCode.internalError);
	assert(collectException(rt.requireInput(t.taskId, Json.undefined)) !is null);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
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
	nodeA.complete(t.taskId, Json([
			"structuredContent": Json(["ok": Json(true)])
	]));
	auto done = nodeB.getDetailed(t.taskId);
	assert(done["status"].get!string == "completed");
	assert(done["result"]["structuredContent"]["ok"].get!bool);
}

unittest  // a terminal task expires ttl after it settled: tasks/get then reports not found
{
	import std.exception : collectException;

	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto t = rt.create(nullable(10_000.msecs));
	now = "2026-06-07T10:00:05Z";
	rt.complete(t.taskId, Json.emptyObject);
	now = "2026-06-07T10:00:14.5Z"; // past createdAt + ttl, within settledAt + ttl
	assert(rt.getDetailed(t.taskId)["status"].get!string == "completed");
	now = "2026-06-07T10:00:15Z";
	auto ex = cast(McpException) collectException(rt.getDetailed(t.taskId));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
	assert(store.get(t.taskId).isNull, "an expired record is removed from the store");
}

unittest  // a non-terminal task never expires; its ttl starts once it settles
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto t = rt.create(nullable(1_000.msecs));
	now = "2026-06-07T12:00:00Z";
	assert(rt.sweepExpired() == 0);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
	assert(!rt.cancelRequested(t.taskId));
	rt.complete(t.taskId, Json.emptyObject);
	now = "2026-06-07T12:00:01Z";
	assert(rt.sweepExpired() == 1);
	assert(store.get(t.taskId).isNull);
}

unittest  // cancelRequested reports true once the task record is gone, so its executor stops
{
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	assert(!rt.cancelRequested(t.taskId));
	store.remove(t.taskId);
	assert(rt.cancelRequested(t.taskId));
	assert(rt.cancelRequested("never-existed"));
}

unittest  // sweepExpired removes settled records past their ttl and keeps the rest
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto done = rt.create(nullable(1_000.msecs));
	auto fresh = rt.create(nullable(60_000.msecs));
	auto running = rt.create(nullable(1_000.msecs));
	rt.complete(done.taskId, Json.emptyObject);
	rt.complete(fresh.taskId, Json.emptyObject);
	now = "2026-06-07T10:00:02Z";
	assert(rt.sweepExpired() == 1);
	assert(store.get(done.taskId).isNull);
	assert(!store.get(fresh.taskId).isNull);
	assert(!store.get(running.taskId).isNull);
}

unittest  // cancelling a running executor's task records the request without a status notification
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	int notified;
	rt.onStatusChange((Json detailed, string owner) @safe { notified++; });
	auto t = rt.createFor("tool", Json.emptyObject);
	now = "2026-06-07T10:00:01Z";
	rt.cancel(t.taskId);
	assert(rt.cancelRequested(t.taskId));
	assert(notified == 0);
	assert(rt.getDetailed(t.taskId)["lastUpdatedAt"].get!string == "2026-06-07T10:00:00Z");
}

unittest  // stopSweeper ends the sweep loop, including one a restart replaced
{
	import vibe.core.core : runTask, exitEventLoop, runEventLoop, sleep;

	int clockReads;
	TaskOptions o;
	o.nowIso = () @safe { clockReads++; return "2026-06-07T10:00:00Z"; };
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	int beforeStop, afterStop;
	runTask(() nothrow @safe {
		try
		{
			rt.startSweeper(1.msecs);
			rt.startSweeper(1.msecs);
			sleep(30.msecs);
			rt.stopSweeper();
			sleep(1.msecs);
			beforeStop = clockReads;
			sleep(30.msecs);
			afterStop = clockReads;
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();
	assert(beforeStop > 0, "the sweeper ran");
	assert(afterStop == beforeStop, "no sweep runs after stopSweeper");
}

unittest  // a task with an unlimited ttl never expires
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto t = rt.create();
	TaskRecord r = store.get(t.taskId).get;
	r.meta.ttlMs = Nullable!long.init;
	r.meta.status = TaskStatus.completed;
	store.put(r);
	now = "2100-01-01T00:00:00Z";
	assert(rt.sweepExpired() == 0);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "completed");
}

unittest  // a task created with unlimitedTaskTtl has a null ttl and is kept forever once settled
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto t = rt.create(nullable(unlimitedTaskTtl));
	assert(t.ttlMs.isNull);
	rt.complete(t.taskId, Json.emptyObject);
	now = "2100-01-01T00:00:00Z";
	assert(rt.sweepExpired() == 0);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "completed");
}

unittest  // a defaultTtl of unlimitedTaskTtl makes tasks unlimited unless a ttl is given
{
	TaskOptions o;
	o.defaultTtl = unlimitedTaskTtl;
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	assert(rt.create().ttlMs.isNull);
	assert(rt.create(nullable(1_000.msecs)).ttlMs.get == 1_000);
}

unittest  // a task unsettled past maxUnsettledAge fails, stops its executor, then expires by ttl
{
	import std.exception : collectException;

	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	o.maxUnsettledAge = 1.hours;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	string[] seen;
	rt.onStatusChange((Json d, string owner) @safe {
		seen ~= d["status"].get!string;
	});
	auto t = rt.createFor("slow", Json.undefined, nullable(10_000.msecs));
	now = "2026-06-07T10:59:59Z";
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
	now = "2026-06-07T11:00:00Z";
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "failed");
	assert(d["error"]["code"].get!int == cast(int) ErrorCode.internalError);
	assert(rt.cancelRequested(t.taskId), "the executor is told to stop");
	assert(seen == ["failed"]);
	now = "2026-06-07T11:00:10Z";
	auto ex = cast(McpException) collectException(rt.getDetailed(t.taskId));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // the sweep fails a task unsettled past maxUnsettledAge
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	o.maxUnsettledAge = 1.hours;
	auto store = new InMemoryTaskStore();
	auto rt = new TaskRuntime(store, o);
	auto t = rt.createFor("slow", Json.undefined);
	rt.requireInput(t.taskId, Json([
			"k": Json(["method": Json("elicitation/create")])
	]));
	now = "2026-06-07T11:00:00Z";
	assert(rt.sweepExpired() == 0);
	assert(store.get(t.taskId).get.meta.status == TaskStatus.failed);
}

unittest  // a task whose cancel never settled is cancelled, not failed, at maxUnsettledAge
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	o.maxUnsettledAge = 1.hours;
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	auto t = rt.createFor("slow", Json.undefined);
	rt.cancel(t.taskId);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
	now = "2026-06-07T11:00:00Z";
	assert(rt.getDetailed(t.taskId)["status"].get!string == "cancelled");
}

unittest  // a zero maxUnsettledAge never fails an unsettled task
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	o.maxUnsettledAge = Duration.zero;
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	auto t = rt.createFor("slow", Json.undefined);
	now = "2027-06-07T10:00:00Z";
	assert(rt.sweepExpired() == 0);
	assert(rt.getDetailed(t.taskId)["status"].get!string == "working");
}

unittest  // the default maxUnsettledAge bounds an unsettled task to a day
{
	TaskOptions o;
	assert(o.maxUnsettledAge == 24.hours);
}

unittest  // deliverInput rejects a key the task has not requested and records nothing
{
	import std.exception : collectException;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	auto none = cast(McpException) collectException(rt.deliverInput(t.taskId, Json([
				"a": Json(1)
	])));
	assert(none !is null && none.code == ErrorCode.invalidParams);
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")])
	]));
	auto ex = cast(McpException) collectException(rt.deliverInput(t.taskId,
			Json(["a": Json(1), "junk": Json(2)])));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
	assert(ex.data["taskId"].get!string == t.taskId);
	assert(rt.takenInput(t.taskId).length == 0);
	rt.deliverInput(t.taskId, Json(["a": Json(1)]));
	assert(rt.takenInput(t.taskId)["a"].get!int == 1);
}

unittest  // progress, requireInput, and resumeWorking leave a terminal task untouched
{
	string now = "2026-06-07T10:00:00Z";
	TaskOptions o;
	o.nowIso = () @safe => now;
	auto rt = new TaskRuntime(new InMemoryTaskStore(), o);
	auto t = rt.create();
	rt.cancel(t.taskId);
	int notified;
	rt.onStatusChange((Json d, string owner) @safe { notified++; });
	now = "2026-06-07T10:00:01Z";

	rt.progress(t.taskId, "still going");
	rt.requireInput(t.taskId, Json([
			"k": Json(["method": Json("elicitation/create")])
	]));
	rt.resumeWorking(t.taskId);
	rt.complete(t.taskId, Json.emptyObject);

	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "cancelled");
	assert("statusMessage" !in d);
	assert(d["lastUpdatedAt"].get!string == "2026-06-07T10:00:00Z");
	assert(notified == 0);
}

version (unittest) private final class RacingTaskStore : TaskStore
{
	InMemoryTaskStore inner;
	/// Runs once, just before the next compareAndSwap, to simulate a concurrent
	/// writer on another fiber or node.
	void delegate() @safe beforeNextSwap;

	this() @safe
	{
		inner = new InMemoryTaskStore();
	}

	void put(TaskRecord r) @safe
	{
		inner.put(r);
	}

	Nullable!TaskRecord get(string id) @safe
	{
		return inner.get(id);
	}

	/// Runs once, just after the next successful compareAndSwap, to simulate a
	/// writer landing between a commit and anything that reads it back.
	void delegate() @safe afterNextSwap;

	bool compareAndSwap(TaskRecord r, ulong expected) @safe
	{
		if (auto hook = beforeNextSwap)
		{
			beforeNextSwap = null;
			hook();
		}
		const swapped = inner.compareAndSwap(r, expected);
		if (swapped)
			if (auto hook = afterNextSwap)
			{
				afterNextSwap = null;
				hook();
			}
		return swapped;
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

unittest  // a cancel racing a completion does not overwrite the stored result
{
	auto store = new RacingTaskStore();
	auto rt = new TaskRuntime(store, TaskOptions.init);
	auto t = rt.createFor("slow", Json.undefined);
	store.beforeNextSwap = () @safe {
		rt.complete(t.taskId, Json([
				"structuredContent": Json(["ok": Json(true)])
		]));
	};
	rt.cancel(t.taskId);
	auto d = rt.getDetailed(t.taskId);
	assert(d["status"].get!string == "completed");
	assert(d["result"]["structuredContent"]["ok"].get!bool);
}

unittest  // each status notification carries the state its own transition committed
{
	import std.algorithm : sort;

	auto store = new RacingTaskStore();
	auto rt = new TaskRuntime(store, TaskOptions.init);
	string[] seen;
	rt.onStatusChange((Json d, string owner) @safe {
		seen ~= d["status"].get!string;
	});
	auto t = rt.createFor("gate", Json.undefined);
	store.afterNextSwap = () @safe { rt.complete(t.taskId, Json.emptyObject); };
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")])
	]));
	seen.sort();
	assert(seen == ["completed", "input_required"]);
}

unittest  // concurrent tasks/update deliveries both keep their answers
{
	auto store = new RacingTaskStore();
	auto rt = new TaskRuntime(store, TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")]),
			"b": Json(["method": Json("elicitation/create")])
	]));
	store.beforeNextSwap = () @safe {
		rt.deliverInput(t.taskId, Json(["b": Json("second")]));
	};
	rt.deliverInput(t.taskId, Json(["a": Json("first")]));
	auto got = rt.takenInput(t.taskId);
	assert(got["a"].get!string == "first");
	assert(got["b"].get!string == "second");
}

unittest  // only one of two racing resumers moves the task back to working
{
	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")])
	]));
	assert(rt.resumeWorking(t.taskId));
	assert(!rt.resumeWorking(t.taskId));
}

unittest  // deliverInput rejects non-object inputResponses with -32602
{
	import std.exception : collectException;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.createFor("gate", Json.undefined);
	rt.requireInput(t.taskId, Json([
			"a": Json(["method": Json("elicitation/create")])
	]));
	auto ex = cast(McpException) collectException(rt.deliverInput(t.taskId, Json("x")));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // deliverInput rejects answers for a terminal task with -32602
{
	import std.exception : collectException;

	auto rt = new TaskRuntime(new InMemoryTaskStore(), TaskOptions.init);
	auto t = rt.create();
	rt.complete(t.taskId, Json.emptyObject);
	auto ex = cast(McpException) collectException(rt.deliverInput(t.taskId,
			Json(["a": Json("late")])));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
	assert(ex.data["taskId"].get!string == t.taskId);
	assert(rt.takenInput(t.taskId).length == 0);
}
