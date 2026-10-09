/// The server core's transport-agnostic server->client push seam.
///
/// `McpServer` owns registration and JSON-RPC dispatch and has no I/O; when it
/// needs to push unsolicited traffic (list-changed notifications, resource
/// updates, pings) it goes through the `PushChannel` interface defined here.
/// A transport that can carry unsolicited server->client traffic (the
/// Streamable HTTP SSE channel) implements `PushChannel` and attaches itself
/// via `McpServer.attachPushChannel`, so the server core never depends on a
/// concrete transport type.
module mcp.server.push;

import core.time : Duration, seconds;

import vibe.data.json : Json;

@safe:

/// The per-stream opt-in a client expressed when it opened a modern
/// `subscriptions/listen` stream (2026-07-28 basic/utilities/subscriptions §Notification
/// Filter). It records exactly which notification types this one stream asked
/// for, so the server can honour the MUST NOT: "The server MUST NOT send notification
/// types the client has not explicitly requested." With Multiple Concurrent
/// Subscriptions each listen stream carries its own filter (keyed by its listen
/// request id), so a notification is delivered only to streams that opted into it —
/// never to a concurrent stream that requested a different type.
///
/// `active` distinguishes a real listen-stream filter (an opted-in modern stream) from
/// the zero value used for plain GET streams that did not go through `subscriptions/
/// listen`; an inactive filter accepts everything, so the plain GET stream still obeys
/// only the transport's Multiple Connections rule.
struct ListenFilter
{
	bool active; /// true once this is a real `subscriptions/listen` filter
	bool toolsListChanged;
	bool promptsListChanged;
	bool resourcesListChanged;
	bool resourceSubscriptions; /// opted into `notifications/resources/updated`
	string[] resourceUris; /// the exact URIs opted into for `notifications/resources/updated`
	/// The task ids opted into for `notifications/tasks` (the Tasks extension's
	/// `notifications.taskIds` listen filter key).
	string[] taskIds;

	/// Whether a notification with this JSON-RPC `method` and filter `key` (see
	/// `listenFilterKey`: the resource URI of `notifications/resources/updated`, the
	/// task id of `notifications/tasks`) is one this stream explicitly requested. An
	/// inactive filter (a plain GET stream) accepts every notification; an active
	/// filter accepts only its opted-in types and rejects everything else, since a
	/// listen stream carries only the notifications its filter names.
	bool accepts(string method, string key = "") const @safe
	{
		import std.algorithm : canFind;

		if (!active)
			return true;
		switch (method)
		{
		case "notifications/tools/list_changed":
			return toolsListChanged;
		case "notifications/prompts/list_changed":
			return promptsListChanged;
		case "notifications/resources/list_changed":
			return resourcesListChanged;
		case "notifications/resources/updated":
			return resourceSubscriptions && resourceUris.canFind(key);
		case "notifications/tasks":
			return key.length && taskIds.canFind(key);
		default:
			return false;
		}
	}
}

/// The per-notification key a `ListenFilter` matches on: the `uri` of a
/// `notifications/resources/updated`, the `taskId` of a `notifications/tasks`,
/// and "" for any other notification.
string listenFilterKey(string method, Json params) @safe
{
	string field;
	if (method == "notifications/resources/updated")
		field = "uri";
	else if (method == "notifications/tasks")
		field = "taskId";
	else
		return "";
	if (params.type != Json.Type.object)
		return "";
	auto v = field in params;
	return (v !is null && v.type == Json.Type.string) ? v.get!string : "";
}

unittest  // an inactive filter (plain GET stream) accepts every notification type
{
	ListenFilter f;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(f.accepts("notifications/resources/updated", "file:///x"));
	assert(f.accepts("notifications/message"));
}

unittest  // an active filter accepts only the change types it opted into
{
	ListenFilter f;
	f.active = true;
	f.toolsListChanged = true;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(!f.accepts("notifications/prompts/list_changed"));
	assert(!f.accepts("notifications/resources/list_changed"));
	assert(!f.accepts("notifications/resources/updated", "file:///x"));
}

unittest  // an active filter rejects every notification type it has no opt-in for
{
	ListenFilter f;
	f.active = true;
	f.toolsListChanged = true;
	f.promptsListChanged = true;
	f.resourcesListChanged = true;
	assert(!f.accepts("notifications/message"));
	assert(!f.accepts("notifications/progress"));
	assert(!f.accepts("notifications/events/list_changed"));
	assert(!f.accepts("notifications/tasks", "task-1"));
	assert(!f.accepts("notifications/elicitation/complete"));
}

unittest  // taskIds opts a listen stream into notifications/tasks for exactly those tasks
{
	ListenFilter f;
	f.active = true;
	f.taskIds = ["task-1"];
	assert(f.accepts("notifications/tasks", "task-1"));
	assert(!f.accepts("notifications/tasks", "task-2"));
	assert(!f.accepts("notifications/tasks", ""));
}

unittest  // listenFilterKey extracts the resource uri or the task id a notification is about
{
	assert(listenFilterKey("notifications/resources/updated",
			Json(["uri": Json("file:///a")])) == "file:///a");
	assert(listenFilterKey("notifications/tasks", Json(["taskId": Json("t-9")])) == "t-9");
	assert(listenFilterKey("notifications/tools/list_changed", Json.emptyObject) == "");
	assert(listenFilterKey("notifications/tasks", Json.undefined) == "");
}

unittest  // resourceSubscriptions matches only the opted-in URIs
{
	ListenFilter f;
	f.active = true;
	f.resourceSubscriptions = true;
	f.resourceUris = ["file:///project/config.json"];
	assert(f.accepts("notifications/resources/updated", "file:///project/config.json"));
	assert(!f.accepts("notifications/resources/updated", "file:///other"));

	// An opt-in naming no URI accepts none.
	ListenFilter noUris;
	noUris.active = true;
	noUris.resourceSubscriptions = true;
	assert(!noUris.accepts("notifications/resources/updated", "file:///x"));

	// Without resourceSubscriptions opt-in, resources/updated is rejected.
	ListenFilter none;
	none.active = true;
	assert(!none.accepts("notifications/resources/updated", "file:///x"));
}

unittest  // a per-URI filter must reject a notification that carries no URI
{
	// A server emitting notifications/resources/updated with an empty uri (e.g. a
	// bug upstream or a server that omits the field) must not bypass the per-URI
	// filter: an empty uri is not in the opted-in list and must not be delivered.
	ListenFilter f;
	f.active = true;
	f.resourceSubscriptions = true;
	f.resourceUris = ["file:///project/config.json"];
	assert(!f.accepts("notifications/resources/updated", ""));
}

/// A transport-owned server->client push channel as seen by the server core.
/// The Streamable HTTP transport's `ServerPushChannel` implements this and is
/// attached to the server when the mount is set up; the `notify*`/`ping`
/// server APIs deliver through it without knowing the transport. Delivery
/// counts return the number of streams reached.
interface PushChannel
{
	/// Fan a change notification out once per connected session and listen
	/// stream, honouring each stream's own opt-in filter; `plainEligible` gates
	/// delivery to plain (non-listen) streams.
	size_t broadcast(string method, Json params, string uri = "", bool plainEligible = true) @safe;

	/// Like `notify`, but only to streams opened by `principal` (the authenticated
	/// token subject). An empty `principal` reaches no stream.
	size_t notifyPrincipal(string principal, string method, Json params) @safe;

	/// Deliver a notification to a single stream of the session `sessionToken`,
	/// honouring each stream's own opt-in filter; `plainEligible` gates delivery
	/// to plain (non-listen) streams. An empty `sessionToken` makes every stream
	/// a candidate (the newest eligible one receives it), which is only
	/// meaningful on a server without sessions.
	size_t pushToSession(string sessionToken, string method, Json params,
			string uri = "", bool plainEligible = true) @safe;

	/// Issue a `ping` request on a stream of the session `sessionToken` and wait
	/// up to `timeout` for the client's response. An empty `sessionToken` selects
	/// only streams opened without a session (a server without sessions).
	void ping(Duration timeout = 60.seconds, string sessionToken = "") @safe;

	/// The distinct owner (session) tokens of all currently-connected streams.
	string[] connectedOwnerTokens() @safe;
}

unittest  // the push seam offers no ungated notify: delivery goes through the server's gated APIs
{
	static assert(!__traits(hasMember, PushChannel, "notify"));
}
