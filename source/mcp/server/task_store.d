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
/// fields are the execution state that earlier lived only in process memory and
/// therefore broke multi-node deployments: `result`/`error` (terminal payloads),
/// `inputRequests` (outstanding server-to-client requests while `input_required`),
/// `inputResponses` (answers delivered via `tasks/update`), `cancelRequested`
/// (cooperative cancel flag), plus the executor's durable `executorInput` and
/// `checkpoints`. Persisting all of it means any node can serve `tasks/get` and
/// re-dispatch the executor purely from the store.
struct TaskRecord
{
	Task meta; /// wire metadata (taskId, status, timestamps, ttl, pollInterval)
	Nullable!Json result; /// final result for a completed task
	Nullable!Json error; /// JSON-RPC error for a failed task
	Json inputRequests = Json.emptyObject; /// outstanding requests when input_required
	Json[string] inputResponses; /// answers delivered via tasks/update, keyed by request id
	bool cancelRequested; /// cooperative cancel flag, honored by the executor
	string toolName; /// executor key — which registered task executor drives this task
	Json executorInput = Json.undefined; /// durable input, reconstituted on each dispatch
	Json[string] checkpoints; /// re-entry state persisted via TaskContext.checkpoint

	/// Serialize to a self-contained JSON object. A real store persists this; the
	/// in-memory store round-trips through it to guarantee stored records do not
	/// alias the caller's mutable state (mirroring a network/disk boundary).
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
		j["toolName"] = toolName;
		if (executorInput.type != Json.Type.undefined)
			j["executorInput"] = executorInput;
		Json cp = Json.emptyObject;
		foreach (k, v; checkpoints)
			cp[k] = v;
		j["checkpoints"] = cp;
		return j;
	}

	/// Reconstruct a record from `toJson` output, building fresh associative
	/// arrays so the result shares no mutable state with any other copy.
	static TaskRecord fromJson(Json j) @safe
	{
		TaskRecord r;
		if ("meta" in j)
			r.meta = Task.fromJson(j["meta"]);
		if ("result" in j && j["result"].type != Json.Type.undefined)
			r.result = nullable(j["result"]);
		if ("error" in j && j["error"].type != Json.Type.undefined)
			r.error = nullable(j["error"]);
		r.inputRequests = ("inputRequests" in j && j["inputRequests"].type == Json.Type.object)
			? cloneJson(j["inputRequests"]) : Json.emptyObject;
		if ("inputResponses" in j && j["inputResponses"].type == Json.Type.object)
			() @trusted {
			foreach (string k, v; j["inputResponses"])
				r.inputResponses[k] = cloneJson(v);
		}();
		r.cancelRequested = ("cancelRequested" in j) && j["cancelRequested"].type == Json.Type.bool_
			&& j["cancelRequested"].get!bool;
		if ("toolName" in j && j["toolName"].type == Json.Type.string)
			r.toolName = j["toolName"].get!string;
		r.executorInput = ("executorInput" in j) ? cloneJson(j["executorInput"]) : Json.undefined;
		if ("checkpoints" in j && j["checkpoints"].type == Json.Type.object)
			() @trusted {
			foreach (string k, v; j["checkpoints"])
				r.checkpoints[k] = cloneJson(v);
		}();
		return r;
	}
}

/// Deep-copy a `Json` value by serializing and re-parsing, so the copy shares no
/// underlying storage with the original. Used at the store boundary.
private Json cloneJson(Json j) @safe
{
	import vibe.data.json : parseJsonString;

	if (j.type == Json.Type.undefined)
		return Json.undefined;
	return parseJsonString(j.toString());
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
	/// Store a newly created record. The runtime guarantees `record.meta.taskId`
	/// is not already present.
	void put(TaskRecord record) @safe;

	/// The record with `taskId`, or null if unknown (or already removed/expired).
	Nullable!TaskRecord get(string taskId) @safe;

	/// Replace the stored record identified by `record.meta.taskId`. A no-op if
	/// unknown.
	void update(TaskRecord record) @safe;

	/// Drop the record identified by `taskId`. A no-op if unknown.
	void remove(string taskId) @safe;
}

/// In-memory `TaskStore` backed by an associative array. The default store; it
/// keeps task records for the lifetime of the server process. Records are stored
/// as serialized JSON and re-parsed on read, so a returned record never aliases
/// stored state — the same isolation a networked store provides for free, which
/// makes the in-memory store a faithful single-process stand-in for a shared one.
final class InMemoryTaskStore : TaskStore
{
	private Json[string] records;

	void put(TaskRecord record) @safe
	{
		records[record.meta.taskId] = record.toJson();
	}

	Nullable!TaskRecord get(string taskId) @safe
	{
		if (auto p = taskId in records)
			return nullable(TaskRecord.fromJson(*p));
		return Nullable!TaskRecord.init;
	}

	void update(TaskRecord record) @safe
	{
		if (record.meta.taskId in records)
			records[record.meta.taskId] = record.toJson();
	}

	void remove(string taskId) @safe
	{
		records.remove(taskId);
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
	s.update(r);
	auto got = s.get("id1").get;
	assert(got.meta.status == TaskStatus.completed);
	assert(!got.result.isNull);

	assert(s.get("missing").isNull);
	s.remove("id1");
	assert(s.get("id1").isNull);
}

unittest  // update on an unknown taskId is a no-op (does not insert)
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	TaskRecord r;
	r.meta.taskId = "ghost";
	r.meta.status = TaskStatus.working;
	s.update(r);
	assert(s.get("ghost").isNull);
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

	// Mutate a fetched copy; the store must be unaffected until update() is called.
	auto fetched = s.get("iso").get;
	fetched.inputResponses["k"] = Json("mutated");
	assert(s.get("iso").get.inputResponses["k"].get!string == "first");
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
