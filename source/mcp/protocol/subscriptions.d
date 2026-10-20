/// Wire helpers for the 2026-07-28 `subscriptions/listen` stream
/// (basic/utilities/subscriptions): stamping each delivered notification with
/// the listen request's id and building the stream's teardown result.
module mcp.protocol.subscriptions;

import vibe.data.json : Json;

import mcp.protocol.meta_keys : MetaKey;

@safe:

/// Stamp the modern `io.modelcontextprotocol/subscriptionId` (`MetaKey.subscriptionId`)
/// into `params._meta` of a JSON-RPC notification and return it, leaving the
/// original untouched. Per 2026-07-28 basic/utilities/subscriptions every notification
/// delivered on a `subscriptions/listen` stream MUST carry the listen request's id
/// as `subscriptionId` in `_meta`, so clients can correlate the notification with
/// the listen request that established the stream — this is the producer for that
/// key. `subscriptionId` is the originating `subscriptions/listen` request's
/// JSON-RPC id, carried verbatim so its wire type is preserved (the spec types it
/// as `RequestId = string | number`, so a numeric listen id stays numeric). An
/// absent (`undefined`) or `null` id is a no-op (the notification is returned
/// unchanged). Notifications carry their payload under `params`, so the key is
/// stamped into `params._meta` by `withSubscriptionId`.
Json withListenSubscriptionId(Json notification, Json subscriptionId) @safe
{
	import mcp.protocol.events : withSubscriptionId;

	if (subscriptionId.type == Json.Type.undefined || subscriptionId.type == Json.Type.null_)
		return notification;

	Json n = notification.clone();
	n["params"] = withSubscriptionId(("params" in n) ? n["params"] : Json.undefined, subscriptionId);
	return n;
}

/// Build the JSON-RPC response for a `subscriptions/listen` request the server is
/// gracefully tearing down (2026-07-28 basic/utilities/subscriptions
/// `SubscriptionsListenResult`). The long-lived listen stream emits this single
/// response only on graceful teardown — e.g. server shutdown or an accepted
/// cancellation; an abrupt transport close carries no response. The result body is
/// `{resultType:"complete", _meta:{subscriptionId}}`, and the response `id` equals
/// the listen request's id (carried verbatim, preserving its JSON type).
Json subscriptionsListenResult(Json subscriptionId) @safe
{
	Json meta = Json.emptyObject;
	meta[MetaKey.subscriptionId] = subscriptionId;
	Json result = Json.emptyObject;
	result["resultType"] = "complete";
	result["_meta"] = meta;
	Json resp = Json.emptyObject;
	resp["jsonrpc"] = "2.0";
	resp["id"] = subscriptionId;
	resp["result"] = result;
	return resp;
}

unittest  // subscriptionsListenResult is a complete result carrying the listen id as id and subscriptionId
{
	auto r = subscriptionsListenResult(Json("listen-1"));
	assert(r["jsonrpc"].get!string == "2.0");
	assert(r["id"].get!string == "listen-1");
	assert(r["result"]["resultType"].get!string == "complete");
	assert(r["result"]["_meta"][MetaKey.subscriptionId].get!string == "listen-1");
}

unittest  // subscriptionsListenResult preserves a numeric listen id in both id and subscriptionId
{
	auto r = subscriptionsListenResult(Json(7L));
	assert(r["id"].type == Json.Type.int_ && r["id"].get!long == 7);
	assert(r["result"]["_meta"][MetaKey.subscriptionId].get!long == 7);
}

unittest  // withListenSubscriptionId stamps the listen request id into params._meta
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/tools/list_changed")
	]);
	auto stamped = withListenSubscriptionId(n, Json("listen-7"));
	assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "listen-7");
	// The original is left untouched.
	assert("params" !in n);
}

unittest  // withListenSubscriptionId preserves a numeric JSON-RPC id verbatim (RequestId = string | number)
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/tools/list_changed")
	]);
	auto stamped = withListenSubscriptionId(n, Json(42L));
	auto id = stamped["params"]["_meta"][MetaKey.subscriptionId];
	assert(id.type == Json.Type.int_, "a numeric listen id must stay numeric, not be stringified");
	assert(id.get!long == 42);
}

unittest  // withListenSubscriptionId preserves an existing params payload and _meta entries
{
	Json params = Json.emptyObject;
	params["uri"] = "file:///x";
	Json meta = Json.emptyObject;
	meta["other.vendor/flag"] = true;
	params["_meta"] = meta;
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/resources/updated"),
		"params": params
	]);
	auto stamped = withListenSubscriptionId(n, Json("id-42"));
	assert(stamped["params"]["uri"].get!string == "file:///x");
	assert(stamped["params"]["_meta"]["other.vendor/flag"].get!bool);
	assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "id-42");
}

unittest  // withListenSubscriptionId with an absent or null id is a no-op
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/message")
	]);
	assert("params" !in withListenSubscriptionId(n, Json.undefined));
	assert("params" !in withListenSubscriptionId(n, Json(null)));
}

unittest  // withListenSubscriptionId stamps an empty-string id, which JSON-RPC allows
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/message")
	]);
	auto stamped = withListenSubscriptionId(n, Json(""));
	assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "");
}
