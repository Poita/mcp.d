module mcp.server.task_store;

import std.typecons : Nullable, nullable;

import mcp.protocol.tasks : Task;

@safe:

/// A function that mints a fresh, unguessable task ID. Servers may supply their
/// own (e.g. to correlate IDs with an external job system); the runtime still
/// enforces uniqueness against the store. Defaults to `defaultTaskIdGenerator`.
alias TaskIdGenerator = string delegate() @safe;

/// Durable storage for task metadata, keyed by task ID. The SDK persists task
/// status/result/error here so a `tasks/get` (possibly on a later connection)
/// resolves against it; the live execution fiber is tracked separately by the
/// runtime and is never persisted. Implementations may be backed by memory or an
/// external store. SEP-2663 defines no `tasks/list`, so enumeration is not part
/// of this interface — the task ID is the only handle.
interface TaskStore
{
	/// Store a newly created task. The runtime guarantees `task.taskId` is not
	/// already present.
	void put(Task task) @safe;

	/// The task with `taskId`, or null if unknown (or already removed/expired).
	Nullable!Task get(string taskId) @safe;

	/// Replace the stored task identified by `task.taskId`. A no-op if unknown.
	void update(Task task) @safe;

	/// Drop the task identified by `taskId`. A no-op if unknown.
	void remove(string taskId) @safe;
}

/// In-memory `TaskStore` backed by an associative array. The default store; it
/// keeps task metadata for the lifetime of the server process.
final class InMemoryTaskStore : TaskStore
{
	private Task[string] tasks;

	void put(Task task) @safe
	{
		tasks[task.taskId] = task;
	}

	Nullable!Task get(string taskId) @safe
	{
		if (auto p = taskId in tasks)
			return nullable(*p);
		return Nullable!Task.init;
	}

	void update(Task task) @safe
	{
		if (task.taskId in tasks)
			tasks[task.taskId] = task;
	}

	void remove(string taskId) @safe
	{
		tasks.remove(taskId);
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

unittest  // InMemoryTaskStore stores, fetches, updates, and removes a task
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	Task t;
	t.taskId = "id1";
	t.status = TaskStatus.working;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	s.put(t);
	assert(s.get("id1").get.status == TaskStatus.working);

	t.status = TaskStatus.completed;
	s.update(t);
	assert(s.get("id1").get.status == TaskStatus.completed);

	assert(s.get("missing").isNull);
	s.remove("id1");
	assert(s.get("id1").isNull);
}

unittest  // update on an unknown taskId is a no-op (does not insert)
{
	import mcp.protocol.tasks : TaskStatus;

	auto s = new InMemoryTaskStore();
	Task t;
	t.taskId = "ghost";
	t.status = TaskStatus.working;
	s.update(t);
	assert(s.get("ghost").isNull);
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
