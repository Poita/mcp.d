module mcp.server.task_store;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.tasks : Task;

@safe:

/// A function that mints a fresh, unguessable task ID. Servers may supply their
/// own (e.g. to correlate IDs with an external job system); the runtime still
/// enforces uniqueness against the store. Defaults to `defaultTaskIdGenerator`.
alias TaskIdGenerator = string delegate() @safe;

/// The complete durable state of a task — the single source of truth.
///
/// `meta` is the SEP-2663 wire `Task` (status, timestamps, ttl). The remaining
/// fields are the execution state: `result`/`error` (terminal payloads),
/// `inputRequests` (outstanding server-to-client requests while `input_required`),
/// `inputResponses` (answers delivered via `tasks/update`), `cancelRequested`
/// (cooperative cancel flag), plus the executor's durable `executorInput` and
/// `checkpoints`. Because all of it is persisted, any node can serve `tasks/get`
/// and re-dispatch the executor purely from the store.
struct TaskRecord
{
	Task meta; /// wire metadata (taskId, status, timestamps, ttl, pollInterval)
	Nullable!Json result; /// final result for a completed task
	Nullable!Json error; /// JSON-RPC error for a failed task
	Json inputRequests = Json.emptyObject; /// outstanding requests when input_required
	Json[string] inputResponses; /// answers delivered via tasks/update, keyed by request id
	bool cancelRequested; /// cooperative cancel flag, honored by the executor
	/// The executor handed the task off via `TaskContext.detach`: no dispatch is
	/// running, so a cancel settles the task at once.
	bool detached;
	/// When the dispatch running the executor claimed the task (ISO-8601);
	/// empty when no dispatch holds it. A redelivered dispatch finding a live
	/// claim leaves the task to the running one.
	string dispatchClaimedAt;
	string toolName; /// executor key — which registered task executor drives this task
	/// The record backs a synchronous call from a client without the Tasks
	/// extension: it lives only as long as that request and is not counted by
	/// `TaskStore.countUnsettled` or `TaskStore.countSettled`.
	bool requestBacked;
	/// The authenticated principal (token subject) whose request created the
	/// task; every later tasks/* request must come from the same principal. Empty
	/// when the creating request was unauthenticated, which leaves the task open.
	string owner;
	/// Incremented by the store on every successful `compareAndSwap`; the
	/// optimistic-concurrency token that lets writers on different fibers or
	/// nodes detect a concurrent change instead of overwriting it.
	ulong revision;
	Json executorInput = Json.undefined; /// durable input, reconstituted on each dispatch
	Json[string] checkpoints; /// re-entry state persisted via TaskContext.checkpoint

	/// A deep copy sharing no mutable state (`Json` values or associative
	/// arrays) with this record.
	TaskRecord dup() const @safe
	{
		TaskRecord r;
		r.meta = meta;
		if (!result.isNull)
			r.result = nullable(cloneJson(result.get));
		if (!error.isNull)
			r.error = nullable(cloneJson(error.get));
		r.inputRequests = cloneJson(inputRequests);
		foreach (k, v; inputResponses)
			r.inputResponses[k] = cloneJson(v);
		r.cancelRequested = cancelRequested;
		r.detached = detached;
		r.dispatchClaimedAt = dispatchClaimedAt;
		r.toolName = toolName;
		r.requestBacked = requestBacked;
		r.owner = owner;
		r.revision = revision;
		r.executorInput = cloneJson(executorInput);
		foreach (k, v; checkpoints)
			r.checkpoints[k] = cloneJson(v);
		return r;
	}

	/// Serialize to a self-contained JSON object, the form a persistent store
	/// writes. `fromJson` is its inverse.
	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["meta"] = meta.toJson();
		if (!result.isNull)
			j["result"] = result.get;
		if (!error.isNull)
			j["error"] = error.get;
		j["inputRequests"] = inputRequests;
		Json ir = Json.emptyObject;
		foreach (k, v; inputResponses)
			ir[k] = v;
		j["inputResponses"] = ir;
		j["cancelRequested"] = cancelRequested;
		if (detached)
			j["detached"] = true;
		if (dispatchClaimedAt.length)
			j["dispatchClaimedAt"] = dispatchClaimedAt;
		j["toolName"] = toolName;
		if (requestBacked)
			j["requestBacked"] = true;
		j["revision"] = revision;
		if (owner.length)
			j["owner"] = owner;
		if (executorInput.type != Json.Type.undefined)
			j["executorInput"] = executorInput;
		Json cp = Json.emptyObject;
		foreach (k, v; checkpoints)
			cp[k] = v;
		j["checkpoints"] = cp;
		return j;
	}

	/// Reconstruct a record from `toJson` output, building fresh associative
	/// arrays so the result shares no mutable state with any other copy. Throws
	/// `internalError` (-32603) when the stored `meta` is not a valid `Task`: a
	/// corrupt record is a server fault, not a bad client request.
	static TaskRecord fromJson(Json j) @safe
	{
		import mcp.protocol.errors : McpException, internalError;

		TaskRecord r;
		if ("meta" in j)
		{
			try
				r.meta = Task.fromJson(j["meta"]);
			catch (McpException e)
				throw internalError("corrupt stored task record: " ~ e.msg);
		}
		if ("result" in j && j["result"].type != Json.Type.undefined)
			r.result = nullable(cloneJson(j["result"]));
		if ("error" in j && j["error"].type != Json.Type.undefined)
			r.error = nullable(cloneJson(j["error"]));
		r.inputRequests = ("inputRequests" in j && j["inputRequests"].type == Json.Type.object)
			? cloneJson(j["inputRequests"]) : Json.emptyObject;
		if ("inputResponses" in j && j["inputResponses"].type == Json.Type.object)
			foreach (k, v; j["inputResponses"].byKeyValue)
				r.inputResponses[k] = cloneJson(v);
		r.cancelRequested = ("cancelRequested" in j)
			&& j["cancelRequested"].type == Json.Type.bool_ && j["cancelRequested"].get!bool;
		r.detached = ("detached" in j) && j["detached"].type == Json.Type.bool_
			&& j["detached"].get!bool;
		if ("dispatchClaimedAt" in j && j["dispatchClaimedAt"].type == Json.Type.string)
			r.dispatchClaimedAt = j["dispatchClaimedAt"].get!string;
		if ("toolName" in j && j["toolName"].type == Json.Type.string)
			r.toolName = j["toolName"].get!string;
		r.requestBacked = ("requestBacked" in j)
			&& j["requestBacked"].type == Json.Type.bool_ && j["requestBacked"].get!bool;
		if ("revision" in j && j["revision"].type == Json.Type.int_)
			r.revision = j["revision"].get!ulong;
		if ("owner" in j && j["owner"].type == Json.Type.string)
			r.owner = j["owner"].get!string;
		r.executorInput = ("executorInput" in j) ? cloneJson(j["executorInput"]) : Json.undefined;
		if ("checkpoints" in j && j["checkpoints"].type == Json.Type.object)
			foreach (k, v; j["checkpoints"].byKeyValue)
				r.checkpoints[k] = cloneJson(v);
		return r;
	}
}

/// Deep-copy a `Json` value, so the copy shares no underlying storage with the
/// original. Used at the store boundary.
private Json cloneJson(const Json j) @safe
{
	return j.clone();
}

/// Durable storage for the complete `TaskRecord`, keyed by task ID. The SDK
/// persists all task state here — status, result, error, inputRequests,
/// inputResponses, cancel flag, and the executor's durable input/checkpoints — so
/// a `tasks/get` or executor re-dispatch on ANY node resolves against it. The
/// live execution fiber (if any) is tracked by the dispatcher and never persisted.
/// SEP-2663 defines no `tasks/list`, so enumeration is not part of this interface
/// — the task ID is the only handle.
interface TaskStore
{
	/// Store a newly created record unless a record with `record.meta.taskId`
	/// already exists. Returns false, changing nothing, when the id is taken; the
	/// runtime then retries with a fresh id. A shared store implements this as
	/// one atomic insert-if-absent (e.g. Redis `SET NX` or a SQL `INSERT` on a
	/// unique key), so two nodes minting the same id cannot clobber each other.
	bool put(TaskRecord record) @safe;

	/// The record with `taskId`, or null if unknown (or already removed/expired).
	Nullable!TaskRecord get(string taskId) @safe;

	/// Replace the stored record identified by `record.meta.taskId` only if its
	/// stored `revision` still equals `expectedRevision`, storing `record` with
	/// `revision = expectedRevision + 1`. Returns false, changing nothing, when
	/// the record is unknown or another writer changed it first; the runtime then
	/// re-reads and retries. A shared store implements this as one atomic
	/// conditional write (e.g. a Redis WATCH/MULTI or a SQL `UPDATE ... WHERE
	/// revision = ?`).
	bool compareAndSwap(TaskRecord record, ulong expectedRevision) @safe;

	/// Drop the record identified by `taskId`. A no-op if unknown.
	void remove(string taskId) @safe;

	/// Call `pred` once for every stored record and drop each one for which it
	/// returns true, returning how many were removed. The runtime's sweep uses it
	/// both to expire settled tasks and to find unsettled ones idle past
	/// `TaskOptions.maxUnsettledIdle`, which it then settles, so a store must
	/// evaluate `pred` on every record even when it also expires keys natively.
	size_t removeIf(scope bool delegate(const TaskRecord) @safe pred) @safe;

	/// How many records owned by `owner` ("" for unbound tasks) are not yet
	/// terminal, leaving out `requestBacked` ones. The runtime enforces its per-principal task caps with it on
	/// every task creation, so it must not scan the store: a shared store answers
	/// from an index on `(owner, status)` or a per-owner counter.
	size_t countUnsettled(string owner) @safe;

	/// How many records owned by `owner` ("" for unbound tasks) are terminal
	/// and awaiting expiry, leaving out `requestBacked` ones. Called on every
	/// task creation like `countUnsettled`, so it must not scan the store
	/// either.
	size_t countSettled(string owner) @safe;
}

/// In-memory `TaskStore` backed by an associative array. The default store; it
/// keeps task records until the runtime expires them. Records are deep-copied
/// on the way in and out (`TaskRecord.dup`), so a returned record never aliases
/// stored state — the same isolation a networked store provides for free, which
/// makes the in-memory store a faithful single-process stand-in for a shared one.
final class InMemoryTaskStore : TaskStore
{
	import mcp.protocol.tasks : isTerminal;

	private TaskRecord[string] records;
	// Unsettled and settled records per owner, kept in step with every write
	// so `countUnsettled` and `countSettled` never scan the store.
	private size_t[string] unsettled_;
	private size_t[string] settled_;

	private void track(const ref TaskRecord r, bool add) @safe
	{
		if (r.requestBacked)
			return;
		auto counts = isTerminal(r.meta.status) ? &settled_ : &unsettled_;
		if (add)
		{
			(*counts).require(r.owner, 0)++;
			return;
		}
		auto p = r.owner in *counts;
		if (p is null)
			return;
		if (--*p == 0)
			(*counts).remove(r.owner);
	}

	bool put(TaskRecord record) @safe
	{
		if (record.meta.taskId in records)
			return false;
		records[record.meta.taskId] = record.dup;
		track(record, true);
		return true;
	}

	Nullable!TaskRecord get(string taskId) @safe
	{
		if (auto p = taskId in records)
			return nullable(p.dup);
		return Nullable!TaskRecord.init;
	}

	bool compareAndSwap(TaskRecord record, ulong expectedRevision) @safe
	{
		auto p = record.meta.taskId in records;
		if (p is null || p.revision != expectedRevision)
			return false;
		track(*p, false);
		*p = record.dup;
		p.revision = expectedRevision + 1;
		track(*p, true);
		return true;
	}

	void remove(string taskId) @safe
	{
		if (auto p = taskId in records)
		{
			track(*p, false);
			records.remove(taskId);
		}
	}

	size_t removeIf(scope bool delegate(const TaskRecord) @safe pred) @safe
	{
		string[] doomed;
		foreach (id, ref r; records)
			if (pred(r))
				doomed ~= id;
		foreach (id; doomed)
			remove(id);
		return doomed.length;
	}

	size_t countUnsettled(string owner) @safe
	{
		if (auto p = owner in unsettled_)
			return *p;
		return 0;
	}

	size_t countSettled(string owner) @safe
	{
		if (auto p = owner in settled_)
			return *p;
		return 0;
	}
}

/// The default task-ID generator: 16 cryptographically-random bytes, hex-encoded
/// into a 32-character unguessable string. The task ID is the capability that
/// authorizes `tasks/get`/`tasks/update`/`tasks/cancel`, so it must be
/// unpredictable.
string defaultTaskIdGenerator() @safe
{
	import std.format : format;
	import mcp.auth.csprng : cryptoRandomBytes;

	return format("%(%02x%)", cryptoRandomBytes(16));
}

unittest  // TaskRecord.fromJson shares no Json with its source
{
	auto j = Json([
		"result": Json(["structuredContent": Json(["ok": Json(true)])]),
		"error": Json(["code": Json(-32603), "message": Json("m")])
	]);
	auto r = TaskRecord.fromJson(j);
	j["result"]["structuredContent"]["ok"] = false;
	j["error"]["message"] = "mutated";
	assert(r.result.get["structuredContent"]["ok"].get!bool);
	assert(r.error.get["message"].get!string == "m");
}

unittest  // TaskRecord.fromJson reports a corrupt stored record as an internal error
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	auto e = collectException!McpException(
			TaskRecord.fromJson(Json(["meta": Json(["status": Json(42)])])));
	assert(e !is null && e.code == ErrorCode.internalError);
}

unittest  // TaskRecord round-trips all execution state through JSON
{
	import mcp.protocol.tasks : TaskStatus;

	TaskRecord r;
	r.meta.taskId = "t1";
	r.meta.status = TaskStatus.inputRequired;
	r.meta.createdAt = r.meta.lastUpdatedAt = "2026-06-07T10:30:00Z";
	r.inputRequests = Json(["k1": Json(["method": Json("elicitation/create")])]);
	r.inputResponses["k1"] = Json(["answer": Json("yes")]);
	r.cancelRequested = true;
	r.toolName = "deploy";
	r.executorInput = Json(["build": Json("v2")]);
	r.checkpoints["stage"] = Json("approved");

	auto back = TaskRecord.fromJson(r.toJson());
	assert(back.meta.taskId == "t1");
	assert(back.meta.status == TaskStatus.inputRequired);
	assert(back.inputRequests["k1"]["method"].get!string == "elicitation/create");
	assert(back.inputResponses["k1"]["answer"].get!string == "yes");
	assert(back.cancelRequested);
	assert(back.toolName == "deploy");
	assert(back.executorInput["build"].get!string == "v2");
	assert(back.checkpoints["stage"].get!string == "approved");
}

unittest  // InMemoryTaskStore.put refuses an id that is already stored
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "id1";
	r.toolName = "first";
	assert(s.put(r));
	r.toolName = "second";
	assert(!s.put(r));
	assert(s.get("id1").get.toolName == "first");
}

unittest  // InMemoryTaskStore stores, fetches, updates, and removes a record
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "id1";
	r.meta.status = TaskStatus.working;
	r.meta.createdAt = r.meta.lastUpdatedAt = "2026-06-07T10:30:00Z";
	s.put(r);
	assert(s.get("id1").get.meta.status == TaskStatus.working);

	r.meta.status = TaskStatus.completed;
	r.result = nullable(Json(["content": Json.emptyArray]));
	assert(s.compareAndSwap(r, 0));
	auto got = s.get("id1").get;
	assert(got.meta.status == TaskStatus.completed);
	assert(!got.result.isNull);
	assert(got.revision == 1);

	assert(s.get("missing").isNull);
	s.remove("id1");
	assert(s.get("id1").isNull);
}

unittest  // compareAndSwap on an unknown taskId fails and does not insert
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "ghost";
	r.meta.status = TaskStatus.working;
	assert(!s.compareAndSwap(r, 0));
	assert(s.get("ghost").isNull);
}

unittest  // compareAndSwap rejects a write based on a stale revision
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "cas";
	r.meta.status = TaskStatus.working;
	s.put(r);
	auto a = s.get("cas").get;
	auto b = s.get("cas").get;
	a.meta.status = TaskStatus.completed;
	assert(s.compareAndSwap(a, a.revision));
	b.meta.status = TaskStatus.cancelled;
	assert(!s.compareAndSwap(b, b.revision));
	assert(s.get("cas").get.meta.status == TaskStatus.completed);
}

unittest  // a returned record does not alias stored state (store boundary isolation)
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "iso";
	r.meta.status = TaskStatus.working;
	r.inputResponses["k"] = Json("first");
	s.put(r);

	// Mutate a fetched copy; the store must be unaffected until it is written back.
	auto fetched = s.get("iso").get;
	fetched.inputResponses["k"] = Json("mutated");
	assert(s.get("iso").get.inputResponses["k"].get!string == "first");
}

unittest  // nested Json in a fetched or written record does not alias stored state
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "deep";
	r.meta.status = TaskStatus.working;
	r.inputRequests = Json(["k": Json(["method": Json("elicitation/create")])]);
	r.executorInput = Json(["list": Json([Json(1)])]);
	r.checkpoints["c"] = Json(["v": Json(1)]);
	r.result = nullable(Json(["ok": Json(true)]));
	s.put(r);

	// The caller's own copy stays independent after the write.
	r.inputRequests["k"]["method"] = "sampling/createMessage";
	r.executorInput["list"][0] = 2;
	// Checkpoints are written through `in` pointers: DMD 2.113 crashes compiling
	// a chained `aa[k][k2] = v` on a `Json[string]`.
	(*("c" in r.checkpoints))["v"] = 2;
	r.result.get["ok"] = false;

	auto fetched = s.get("deep").get;
	fetched.inputRequests["k"]["method"] = "roots/list";
	fetched.executorInput["list"][0] = 3;
	(*("c" in fetched.checkpoints))["v"] = 3;
	fetched.result.get["ok"] = false;

	auto again = s.get("deep").get;
	assert(again.inputRequests["k"]["method"].get!string == "elicitation/create");
	assert(again.executorInput["list"][0].get!int == 1);
	assert(again.checkpoints["c"]["v"].get!int == 1);
	assert(again.result.get["ok"].get!bool);

	// compareAndSwap stores its own copy too.
	assert(s.compareAndSwap(again, again.revision));
	(*("c" in again.checkpoints))["v"] = 4;
	assert(s.get("deep").get.checkpoints["c"]["v"].get!int == 1);
}

unittest  // defaultTaskIdGenerator yields distinct 32-char hex ids
{
	auto a = defaultTaskIdGenerator();
	auto b = defaultTaskIdGenerator();
	assert(a.length == 32);
	assert(b.length == 32);
	assert(a != b, "two generated task ids must differ");
	foreach (c; a)
		assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), "id must be lowercase hex");
}

unittest  // countUnsettled tracks each owner's unsettled records through every write
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord mk(string id, string owner, TaskStatus st) @safe
	{
		TaskRecord r;
		r.meta.taskId = id;
		r.meta.status = st;
		r.owner = owner;
		return r;
	}

	assert(s.put(mk("a1", "alice", TaskStatus.working)));
	assert(s.put(mk("a2", "alice", TaskStatus.inputRequired)));
	assert(s.put(mk("a3", "alice", TaskStatus.completed)));
	assert(s.put(mk("b1", "bob", TaskStatus.working)));
	assert(s.put(mk("n1", "", TaskStatus.working)));
	assert(!s.put(mk("a1", "alice", TaskStatus.working)));
	assert(s.countUnsettled("alice") == 2);
	assert(s.countUnsettled("bob") == 1);
	assert(s.countUnsettled("") == 1);
	assert(s.countUnsettled("carol") == 0);

	assert(s.compareAndSwap(mk("a1", "alice", TaskStatus.completed), 0));
	assert(s.countUnsettled("alice") == 1);
	assert(!s.compareAndSwap(mk("a2", "alice", TaskStatus.failed), 7));
	assert(s.countUnsettled("alice") == 1);
	assert(s.compareAndSwap(mk("a3", "alice", TaskStatus.working), 0));
	assert(s.countUnsettled("alice") == 2);

	s.remove("a2");
	s.remove("missing");
	assert(s.countUnsettled("alice") == 1);
	assert(s.removeIf((const TaskRecord r) @safe => r.owner == "bob") == 1);
	assert(s.countUnsettled("bob") == 0);
	assert(s.countUnsettled("alice") == 1);
}

unittest  // countSettled follows a record into and out of a terminal status, skipping request-backed ones
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "a";
	r.meta.status = TaskStatus.working;
	r.owner = "alice";
	assert(s.put(r));
	assert(s.countSettled("alice") == 0);
	r.meta.status = TaskStatus.completed;
	assert(s.compareAndSwap(r, 0));
	assert(s.countSettled("alice") == 1 && s.countUnsettled("alice") == 0);

	TaskRecord sync;
	sync.meta.taskId = "b";
	sync.meta.status = TaskStatus.completed;
	sync.owner = "alice";
	sync.requestBacked = true;
	assert(s.put(sync));
	assert(s.countSettled("alice") == 1);

	s.remove("a");
	assert(s.countSettled("alice") == 0);
}

unittest  // removeIf drops exactly the records matching the predicate
{
	auto s = new InMemoryTaskStore();
	foreach (id; ["a", "b", "c"])
	{
		TaskRecord r;
		r.meta.taskId = id;
		s.put(r);
	}
	assert(s.removeIf((const TaskRecord r) @safe => r.meta.taskId != "b") == 2);
	assert(s.get("a").isNull && s.get("c").isNull);
	assert(!s.get("b").isNull);
}
