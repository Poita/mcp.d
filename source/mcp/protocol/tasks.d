module mcp.protocol.tasks;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.jsonhelpers : getOr, tryGet;

@safe:

/// A task's lifecycle status (SEP-2663). `working` and `inputRequired` are
/// non-terminal; `completed`, `failed`, and `cancelled` are terminal.
enum TaskStatus
{
	working,
	inputRequired,
	completed,
	failed,
	cancelled
}

/// The wire string for a `TaskStatus` (e.g. `inputRequired` -> "input_required").
string taskStatusToWire(TaskStatus s) @safe pure nothrow
{
	final switch (s)
	{
	case TaskStatus.working:
		return "working";
	case TaskStatus.inputRequired:
		return "input_required";
	case TaskStatus.completed:
		return "completed";
	case TaskStatus.failed:
		return "failed";
	case TaskStatus.cancelled:
		return "cancelled";
	}
}

/// Parse a wire status string into a `TaskStatus`. Unknown strings map to
/// `working` (the seed status), keeping a forward-compatible default.
TaskStatus taskStatusFromWire(string s) @safe pure nothrow
{
	switch (s)
	{
	case "input_required":
		return TaskStatus.inputRequired;
	case "completed":
		return TaskStatus.completed;
	case "failed":
		return TaskStatus.failed;
	case "cancelled":
		return TaskStatus.cancelled;
	default:
		return TaskStatus.working;
	}
}

/// Operational metadata about an asynchronous task (SEP-2663 `Task`).
///
/// `ttlMs` is the time-to-live from creation in integer milliseconds; a null
/// `ttlMs` means unlimited, and the field is always emitted (as `null` when
/// unlimited). `pollIntervalMs` is the suggested polling interval and is omitted
/// when unset. `statusMessage` is an optional human-readable description of the
/// current state.
struct Task
{
	string taskId; /// server-generated, unguessable identifier
	TaskStatus status; /// current lifecycle status
	Nullable!string statusMessage; /// optional human-readable state description
	string createdAt; /// ISO-8601 creation timestamp
	string lastUpdatedAt; /// ISO-8601 last-update timestamp
	Nullable!long ttlMs; /// time-to-live in ms; null = unlimited (always emitted)
	Nullable!long pollIntervalMs; /// suggested poll interval in ms (omitted when unset)

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["taskId"] = taskId;
		j["status"] = taskStatusToWire(status);
		if (!statusMessage.isNull)
			j["statusMessage"] = statusMessage.get;
		j["createdAt"] = createdAt;
		j["lastUpdatedAt"] = lastUpdatedAt;
		j["ttlMs"] = ttlMs.isNull ? Json(null) : Json(ttlMs.get);
		if (!pollIntervalMs.isNull)
			j["pollIntervalMs"] = pollIntervalMs.get;
		return j;
	}

	static Task fromJson(Json j) @safe
	{
		Task t;
		t.taskId = j.getOr("taskId", "");
		t.status = taskStatusFromWire(j.getOr("status", "working"));
		tryGet(j, "statusMessage", t.statusMessage);
		t.createdAt = j.getOr("createdAt", "");
		t.lastUpdatedAt = j.getOr("lastUpdatedAt", "");
		// `ttlMs` is always present on the wire: a JSON null means unlimited
		// (leave `ttlMs` null), a number sets the duration.
		if ("ttlMs" in j && j["ttlMs"].type != Json.Type.null_)
			tryGet(j, "ttlMs", t.ttlMs);
		tryGet(j, "pollIntervalMs", t.pollIntervalMs);
		return t;
	}
}

/// Build the `CreateTaskResult` a server returns in lieu of the standard result
/// (e.g. `CallToolResult`) to indicate asynchronous processing. It is the seed
/// `Task` tagged with `resultType: "task"`, the discriminator a client uses to
/// tell a task handle apart from a synchronous result.
Json makeCreateTaskResult(const Task seed) @safe
{
	Json j = seed.toJson();
	j["resultType"] = "task";
	return j;
}

/// The status-specific payload a `tasks/get` response (`DetailedTask`) inlines:
/// `inputRequests` for `input_required`, `result` for `completed`, `error` for
/// `failed`; `none` for `working`/`cancelled`. Construct via the factory methods.
struct DetailedTaskPayload
{
	private enum Kind
	{
		none,
		inputRequests,
		result,
		error
	}

	private Kind kind = Kind.none;
	private Json value = Json.undefined;

	/// No status-specific payload (`working` / `cancelled`).
	static DetailedTaskPayload none() @safe
	{
		return DetailedTaskPayload.init;
	}

	/// Outstanding server-to-client requests for an `input_required` task. The
	/// `requests` object follows the MRTR `inputRequests` shape.
	static DetailedTaskPayload inputRequests(Json requests) @safe
	{
		return DetailedTaskPayload(Kind.inputRequests, requests);
	}

	/// The final result for a `completed` task (the original request's result
	/// shape, e.g. a `CallToolResult`).
	static DetailedTaskPayload completed(Json result) @safe
	{
		return DetailedTaskPayload(Kind.result, result);
	}

	/// The JSON-RPC error for a `failed` task.
	static DetailedTaskPayload failed(Json error) @safe
	{
		return DetailedTaskPayload(Kind.error, error);
	}

	private void emitInto(ref Json j) const @safe
	{
		final switch (kind)
		{
		case Kind.none:
			break;
		case Kind.inputRequests:
			j["inputRequests"] = value;
			break;
		case Kind.result:
			j["result"] = value;
			break;
		case Kind.error:
			j["error"] = value;
			break;
		}
	}
}

/// Build the `tasks/get` response (`DetailedTask`): the `Task` plus the
/// status-specific payload, tagged with `resultType: "complete"` (the standard
/// result shape for `tasks/get`).
Json makeDetailedTask(const Task task, const DetailedTaskPayload payload) @safe
{
	Json j = task.toJson();
	j["resultType"] = "complete";
	payload.emitInto(j);
	return j;
}

unittest  // Task serializes the SEP-2663 wire shape and round-trips
{
	Task t;
	t.taskId = "abc";
	t.status = TaskStatus.working;
	t.statusMessage = nullable("in progress");
	t.createdAt = "2026-06-07T10:30:00Z";
	t.lastUpdatedAt = "2026-06-07T10:40:00Z";
	t.ttlMs = nullable(60_000L);
	t.pollIntervalMs = nullable(5_000L);
	auto j = t.toJson();
	assert(j["taskId"].get!string == "abc");
	assert(j["status"].get!string == "working");
	assert(j["statusMessage"].get!string == "in progress");
	assert(j["ttlMs"].get!long == 60_000);
	assert(j["pollIntervalMs"].get!long == 5_000);

	auto back = Task.fromJson(j);
	assert(back.taskId == "abc" && back.status == TaskStatus.working);
	assert(back.statusMessage.get == "in progress");
	assert(back.ttlMs.get == 60_000 && back.pollIntervalMs.get == 5_000);
}

unittest  // Task emits ttlMs:null for an unlimited (unset) TTL and omits pollIntervalMs
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.completed;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	auto j = t.toJson();
	assert("ttlMs" in j && j["ttlMs"].type == Json.Type.null_);
	assert("pollIntervalMs" !in j);
	assert("statusMessage" !in j);

	auto back = Task.fromJson(j);
	assert(back.ttlMs.isNull && back.pollIntervalMs.isNull);
}

unittest  // every TaskStatus round-trips through its wire string
{
	foreach (s; [
		TaskStatus.working, TaskStatus.inputRequired, TaskStatus.completed,
		TaskStatus.failed, TaskStatus.cancelled
	])
		assert(taskStatusFromWire(taskStatusToWire(s)) == s);
	assert(taskStatusToWire(TaskStatus.inputRequired) == "input_required");
}

unittest  // makeCreateTaskResult tags the seed task with resultType "task"
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.working;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	auto j = makeCreateTaskResult(t);
	assert(j["resultType"].get!string == "task");
	assert(j["taskId"].get!string == "x");
	assert(j["status"].get!string == "working");
}

unittest  // makeDetailedTask(completed) inlines the result and tags resultType "complete"
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.completed;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	Json result = Json([
		"content": Json([Json(["type": Json("text"), "text": Json("hi")])])
	]);
	auto j = makeDetailedTask(t, DetailedTaskPayload.completed(result));
	assert(j["resultType"].get!string == "complete");
	assert(j["status"].get!string == "completed");
	assert(j["result"]["content"][0]["text"].get!string == "hi");
	assert("error" !in j && "inputRequests" !in j);
}

unittest  // makeDetailedTask(failed) inlines the JSON-RPC error
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.failed;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	Json err = Json(["code": Json(-32000), "message": Json("boom")]);
	auto j = makeDetailedTask(t, DetailedTaskPayload.failed(err));
	assert(j["error"]["code"].get!int == -32000);
	assert("result" !in j);
}

unittest  // makeDetailedTask(inputRequests) inlines outstanding requests for input_required
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.inputRequired;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	Json reqs = Json([
		"k1": Json(["method": Json("elicitation/create"), "params": Json.emptyObject])
	]);
	auto j = makeDetailedTask(t, DetailedTaskPayload.inputRequests(reqs));
	assert(j["status"].get!string == "input_required");
	assert(j["inputRequests"]["k1"]["method"].get!string == "elicitation/create");
}

unittest  // makeDetailedTask(none) carries no status-specific payload (working)
{
	Task t;
	t.taskId = "x";
	t.status = TaskStatus.working;
	t.createdAt = t.lastUpdatedAt = "2026-06-07T10:30:00Z";
	auto j = makeDetailedTask(t, DetailedTaskPayload.none());
	assert(j["resultType"].get!string == "complete");
	assert("result" !in j && "error" !in j && "inputRequests" !in j);
}
