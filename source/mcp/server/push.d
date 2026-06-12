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

/// The per-stream opt-in a client expressed when it opened a draft
/// `subscriptions/listen` stream (draft basic/utilities/subscriptions §Notification
/// Filter). It records exactly which change-notification types this one stream asked
/// for, so the server can honour the MUST NOT: "The server MUST NOT send notification
/// types the client has not explicitly requested." With Multiple Concurrent
/// Subscriptions each listen stream carries its own filter (keyed by its listen
/// request id), so a notification is delivered only to streams that opted into it —
/// never to a concurrent stream that requested a different type.
///
/// `active` distinguishes a real listen-stream filter (an opted-in draft stream) from
/// the zero value used for plain GET streams that did not go through `subscriptions/
/// listen`; an inactive filter accepts everything, so the plain GET stream still obeys
/// only the transport's Multiple Connections rule.
struct SubscriptionFilter
{
	bool active; /// true once this is a real `subscriptions/listen` filter
	bool toolsListChanged;
	bool promptsListChanged;
	bool resourcesListChanged;
	bool resourceSubscriptions; /// opted into `notifications/resources/updated`
	string[] resourceUris; /// the exact URIs opted into for `notifications/resources/updated`

	/// Whether a notification with this JSON-RPC `method` (and, for
	/// `notifications/resources/updated`, this resource `uri`) is one this stream
	/// explicitly requested. An inactive filter (a plain GET stream) accepts every
	/// notification; an active filter accepts only its opted-in types. Notification
	/// methods that are not subscription-gated (progress, logging, elicitation
	/// completion, server->client requests, etc.) are always accepted — the draft
	/// filter governs only the four list/subscription change types.
	bool accepts(string method, string uri = "") const @safe
	{
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
			import std.algorithm : canFind;

			if (!resourceSubscriptions)
				return false;
			// A blanket boolean opt-in (no per-URI list) accepts any URI;
			// otherwise only the explicitly named URIs are accepted.
			return resourceUris.length == 0 || resourceUris.canFind(uri);
		default:
			// Not a subscription-gated change notification: always deliverable.
			return true;
		}
	}
}

unittest  // an inactive filter (plain GET stream) accepts every notification type
{
	SubscriptionFilter f;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(f.accepts("notifications/resources/updated", "file:///x"));
	assert(f.accepts("notifications/message"));
}

unittest  // an active filter accepts only the change types it opted into
{
	SubscriptionFilter f;
	f.active = true;
	f.toolsListChanged = true;
	assert(f.accepts("notifications/tools/list_changed"));
	assert(!f.accepts("notifications/prompts/list_changed"));
	assert(!f.accepts("notifications/resources/list_changed"));
	assert(!f.accepts("notifications/resources/updated", "file:///x"));
	// Non-gated notifications still flow regardless of opt-in.
	assert(f.accepts("notifications/message"));
	assert(f.accepts("notifications/progress"));
}

unittest  // resourceSubscriptions matches only the opted-in URIs
{
	SubscriptionFilter f;
	f.active = true;
	f.resourceSubscriptions = true;
	f.resourceUris = ["file:///project/config.json"];
	assert(f.accepts("notifications/resources/updated", "file:///project/config.json"));
	assert(!f.accepts("notifications/resources/updated", "file:///other"));

	// A blanket boolean opt-in (no per-URI list) accepts any resource URI.
	SubscriptionFilter blanket;
	blanket.active = true;
	blanket.resourceSubscriptions = true;
	assert(blanket.accepts("notifications/resources/updated", "file:///x"));

	// Without resourceSubscriptions opt-in, resources/updated is rejected.
	SubscriptionFilter none;
	none.active = true;
	assert(!none.accepts("notifications/resources/updated", "file:///x"));
}

unittest  // a per-URI filter must reject a notification that carries no URI
{
	// A server emitting notifications/resources/updated with an empty uri (e.g. a
	// bug upstream or a server that omits the field) must not bypass the per-URI
	// filter: an empty uri is not in the opted-in list and must not be delivered.
	SubscriptionFilter f;
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
	/// Deliver an unsolicited notification on one live stream (the transport's
	/// Multiple Connections rule: each message goes to exactly one stream).
	size_t notify(string method, Json params = Json.undefined) @safe;

	/// Fan a change notification out once per distinct connected session (the
	/// list-changed broadcasts), honouring each stream's own opt-in filter;
	/// `plainEligible` gates delivery to plain (non-listen) streams.
	size_t broadcast(string method, Json params, string uri = "", bool plainEligible = true) @safe;

	/// Deliver a change notification to a single stream of one session
	/// (`sessionToken` empty: any session), honouring each stream's own opt-in
	/// filter; `plainEligible` gates delivery to plain (non-listen) streams.
	size_t pushToSession(string sessionToken, string method, Json params,
			string uri = "", bool plainEligible = true) @safe;

	/// Issue a `ping` request on the channel and wait up to `timeout` for the
	/// client's response (`sessionToken` empty: any session's stream).
	void ping(Duration timeout = 60.seconds, string sessionToken = "") @safe;

	/// The distinct owner (session) tokens of all currently-connected streams.
	string[] connectedOwnerTokens() @safe;
}
