/// Wire types for the MCP Events extension (`io.modelcontextprotocol/events`):
/// `events/list`, `events/poll`, `events/stream`, and `events/subscribe`/
/// `events/unsubscribe`. A server declares event types; a client subscribes with
/// `(name, arguments)` and receives `EventOccurrence` records over one of three
/// delivery modes — poll, push, or webhook. These are the JSON shapes only;
/// server-side execution lives in `mcp.server.events_runtime` and the signing /
/// SSRF machinery in the runtime + `mcp.auth`.
module mcp.protocol.events;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.jsonhelpers : getOr, tryGet;

@safe:

/// The `_meta` key under which every `notifications/events/*` message carries the
/// JSON-RPC id of its parent `events/stream` request, so a client holding several
/// concurrent streams (notably on stdio, where they share one stdout) can route
/// each notification to the right subscription (SEP-2575 correlation convention).
enum string subscriptionIdMetaKey = "io.modelcontextprotocol/subscriptionId";

/// JSON-RPC method names introduced by the extension.
enum string eventsListMethod = "events/list";
enum string eventsPollMethod = "events/poll";
enum string eventsStreamMethod = "events/stream";
enum string eventsSubscribeMethod = "events/subscribe";
enum string eventsUnsubscribeMethod = "events/unsubscribe";

/// Notification method names carried on a push stream (and, where noted, used as
/// the shape of webhook control bodies).
enum string eventsActiveNotification = "notifications/events/active";
enum string eventsEventNotification = "notifications/events/event";
enum string eventsErrorNotification = "notifications/events/error";
enum string eventsHeartbeatNotification = "notifications/events/heartbeat";
enum string eventsTerminatedNotification = "notifications/events/terminated";
enum string eventsListChangedNotification = "notifications/events/list_changed";

/// A delivery mechanism an event type supports. Advertised per event type in
/// `events/list`; none is mandatory.
enum DeliveryMode
{
	poll,
	push,
	webhook
}

/// The wire string for a `DeliveryMode`.
string deliveryModeToWire(DeliveryMode m) @safe pure nothrow
{
	final switch (m)
	{
	case DeliveryMode.poll:
		return "poll";
	case DeliveryMode.push:
		return "push";
	case DeliveryMode.webhook:
		return "webhook";
	}
}

/// Parse a wire delivery-mode string; null for an unrecognized value.
Nullable!DeliveryMode deliveryModeFromWire(string s) @safe pure nothrow
{
	switch (s)
	{
	case "poll":
		return nullable(DeliveryMode.poll);
	case "push":
		return nullable(DeliveryMode.push);
	case "webhook":
		return nullable(DeliveryMode.webhook);
	default:
		return Nullable!DeliveryMode.init;
	}
}

/// A declared event type, as listed by `events/list`. `inputSchema` describes
/// valid subscription arguments (filters/transforms/config); `payloadSchema`
/// describes the shape of `data` in delivered events.
struct EventType
{
	string name;
	string description;
	string title; /// optional human-readable display name (empty = unset)
	DeliveryMode[] delivery; /// non-empty subset of poll/push/webhook
	Json inputSchema = Json.undefined; /// JSON Schema for subscription arguments
	Json payloadSchema = Json.undefined; /// JSON Schema for delivered `data`
	Json meta = Json.undefined; /// optional `_meta`, same semantics as on Tool/Resource

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		if (description.length)
			j["description"] = description;
		if (title.length)
			j["title"] = title;
		Json arr = Json.emptyArray;
		foreach (m; delivery)
			arr ~= deliveryModeToWire(m);
		j["delivery"] = arr;
		if (inputSchema.type == Json.Type.object)
			j["inputSchema"] = inputSchema;
		if (payloadSchema.type == Json.Type.object)
			j["payloadSchema"] = payloadSchema;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static EventType fromJson(Json j) @safe
	{
		EventType e;
		e.name = j.getOr("name", "");
		e.description = j.getOr("description", "");
		e.title = j.getOr("title", "");
		if ("delivery" in j && j["delivery"].type == Json.Type.array)
			foreach (i; 0 .. j["delivery"].length)
			{
				if (j["delivery"][i].type != Json.Type.string)
					continue;
				auto m = deliveryModeFromWire(j["delivery"][i].get!string);
				if (!m.isNull)
					e.delivery ~= m.get;
			}
		if ("inputSchema" in j && j["inputSchema"].type == Json.Type.object)
			e.inputSchema = j["inputSchema"];
		if ("payloadSchema" in j && j["payloadSchema"].type == Json.Type.object)
			e.payloadSchema = j["payloadSchema"];
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			e.meta = j["_meta"];
		return e;
	}
}

/// The `events/list` result: the declared event types plus an optional
/// pagination cursor (same semantics as `tools/list`).
struct EventListResult
{
	EventType[] events;
	Nullable!string nextCursor;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (const ref e; events)
			arr ~= e.toJson();
		j["events"] = arr;
		if (!nextCursor.isNull)
			j["nextCursor"] = nextCursor.get;
		return j;
	}

	static EventListResult fromJson(Json j) @safe
	{
		EventListResult r;
		if ("events" in j && j["events"].type == Json.Type.array)
			foreach (i; 0 .. j["events"].length)
				r.events ~= EventType.fromJson(j["events"][i]);
		tryGet(j, "nextCursor", r.nextCursor);
		return r;
	}
}

/// One delivered event occurrence. The same shape backs each entry in a poll
/// result, the params of `notifications/events/event`, and a webhook event POST
/// body. `cursor` is the subscription position after this event (push/webhook
/// only; poll carries the cursor at the result level). An absent `cursor` is
/// identical to an explicit `null` (no replay position).
struct EventOccurrence
{
	string eventId; /// stable identifier for deduplication
	string name; /// event type name
	string timestamp; /// ISO-8601 time the event occurred
	Json data = Json.emptyObject; /// payload conforming to the type's payloadSchema
	Nullable!string cursor; /// position after this event (push/webhook); absent == null
	Json meta = Json.undefined; /// optional `_meta`, not governed by payloadSchema

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["eventId"] = eventId;
		j["name"] = name;
		j["timestamp"] = timestamp;
		j["data"] = data.type == Json.Type.undefined ? Json.emptyObject : data;
		if (!cursor.isNull)
			j["cursor"] = cursor.get;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static EventOccurrence fromJson(Json j) @safe
	{
		EventOccurrence e;
		e.eventId = j.getOr("eventId", "");
		e.name = j.getOr("name", "");
		e.timestamp = j.getOr("timestamp", "");
		if ("data" in j)
			e.data = j["data"];
		// `cursor` is optional and nullable: a present string sets it; a present
		// JSON null (or absence) leaves it null per "absent means null".
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			e.cursor = j["cursor"].get!string;
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			e.meta = j["_meta"];
		return e;
	}
}

/// Parameters of an `events/poll` request. `cursor: null` means "from now".
struct PollParams
{
	string name;
	Json arguments = Json.emptyObject;
	Nullable!string cursor; /// null/absent = start from now
	Nullable!long maxAgeMs; /// optional replay floor: do not replay older than this
	Nullable!long maxEvents; /// optional cap on the returned batch

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		j["arguments"] = arguments.type == Json.Type.object ? arguments : Json.emptyObject;
		j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
		if (!maxAgeMs.isNull)
			j["maxAgeMs"] = maxAgeMs.get;
		if (!maxEvents.isNull)
			j["maxEvents"] = maxEvents.get;
		return j;
	}

	static PollParams fromJson(Json j) @safe
	{
		PollParams p;
		p.name = j.getOr("name", "");
		if ("arguments" in j && j["arguments"].type == Json.Type.object)
			p.arguments = j["arguments"];
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			p.cursor = j["cursor"].get!string;
		tryGet(j, "maxAgeMs", p.maxAgeMs);
		tryGet(j, "maxEvents", p.maxEvents);
		return p;
	}
}

/// The `events/poll` result. `cursor` is the position after this batch (the
/// client persists it and passes it back next poll). `truncated` signals a gap;
/// `hasMore` requests an immediate follow-up poll; `nextPollMs` paces the loop.
struct PollResult
{
	EventOccurrence[] events;
	Nullable!string cursor; /// null when the event type does not support replay
	bool truncated;
	bool hasMore;
	Nullable!long nextPollMs;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (const ref e; events)
			arr ~= e.toJson();
		j["events"] = arr;
		j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
		j["truncated"] = truncated;
		j["hasMore"] = hasMore;
		if (!nextPollMs.isNull)
			j["nextPollMs"] = nextPollMs.get;
		return j;
	}

	static PollResult fromJson(Json j) @safe
	{
		PollResult r;
		if ("events" in j && j["events"].type == Json.Type.array)
			foreach (i; 0 .. j["events"].length)
				r.events ~= EventOccurrence.fromJson(j["events"][i]);
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			r.cursor = j["cursor"].get!string;
		r.truncated = j.getOr("truncated", false);
		r.hasMore = j.getOr("hasMore", false);
		tryGet(j, "nextPollMs", r.nextPollMs);
		return r;
	}
}

/// Parameters of an `events/stream` (push) request — one subscription per stream.
struct StreamParams
{
	string name;
	Json arguments = Json.emptyObject;
	Nullable!string cursor;
	Nullable!long maxAgeMs;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		j["arguments"] = arguments.type == Json.Type.object ? arguments : Json.emptyObject;
		j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
		if (!maxAgeMs.isNull)
			j["maxAgeMs"] = maxAgeMs.get;
		return j;
	}

	static StreamParams fromJson(Json j) @safe
	{
		StreamParams p;
		p.name = j.getOr("name", "");
		if ("arguments" in j && j["arguments"].type == Json.Type.object)
			p.arguments = j["arguments"];
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			p.cursor = j["cursor"].get!string;
		tryGet(j, "maxAgeMs", p.maxAgeMs);
		return p;
	}
}

/// The webhook callback descriptor carried in `events/subscribe`. `url` MUST be
/// `https`; `secret` is the client-supplied Standard Webhooks `whsec_` value.
struct WebhookDelivery
{
	string url;
	string secret; /// `whsec_` + base64(24..64 random bytes); empty in unsubscribe

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["mode"] = "webhook";
		j["url"] = url;
		if (secret.length)
			j["secret"] = secret;
		return j;
	}

	static WebhookDelivery fromJson(Json j) @safe
	{
		WebhookDelivery d;
		d.url = j.getOr("url", "");
		d.secret = j.getOr("secret", "");
		return d;
	}
}

/// Parameters of an `events/subscribe` (webhook) request. Idempotent on the key
/// `(principal, delivery.url, name, arguments)`; re-calling refreshes the TTL.
///
/// `ttlMs` is tri-state: absent (`ttlMsPresent == false`) means "server default";
/// present-and-null (`ttlMsPresent && ttlMs.isNull`) requests no expiry; a present
/// value is the client's suggested lifetime.
struct SubscribeParams
{
	string name;
	Json arguments = Json.emptyObject;
	WebhookDelivery delivery;
	Nullable!string cursor;
	Nullable!long maxAgeMs;
	bool ttlMsPresent; /// whether the request carried a `ttlMs` field at all
	Nullable!long ttlMs; /// suggested lifetime; null (with present) = no expiry

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		j["arguments"] = arguments.type == Json.Type.object ? arguments : Json.emptyObject;
		j["delivery"] = delivery.toJson();
		j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
		if (!maxAgeMs.isNull)
			j["maxAgeMs"] = maxAgeMs.get;
		if (ttlMsPresent)
			j["ttlMs"] = ttlMs.isNull ? Json(null) : Json(ttlMs.get);
		return j;
	}

	static SubscribeParams fromJson(Json j) @safe
	{
		SubscribeParams p;
		p.name = j.getOr("name", "");
		if ("arguments" in j && j["arguments"].type == Json.Type.object)
			p.arguments = j["arguments"];
		if ("delivery" in j && j["delivery"].type == Json.Type.object)
			p.delivery = WebhookDelivery.fromJson(j["delivery"]);
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			p.cursor = j["cursor"].get!string;
		tryGet(j, "maxAgeMs", p.maxAgeMs);
		if ("ttlMs" in j)
		{
			p.ttlMsPresent = true;
			if (j["ttlMs"].type != Json.Type.null_)
				tryGet(j, "ttlMs", p.ttlMs);
		}
		return p;
	}
}

/// The `events/subscribe` response. `refreshBefore` is the authoritative grant
/// (ISO-8601, or null for no expiry). `cursor` is a safe-to-persist watermark.
struct SubscribeResult
{
	string id; /// server-derived routing handle (stable for the subscription key)
	Nullable!string refreshBefore; /// expiry grant; null = no expiry (always emitted)
	Nullable!string cursor; /// safe-to-persist watermark; null = no replay
	bool truncated;
	Nullable!DeliveryStatus deliveryStatus; /// optional; present on refresh

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["id"] = id;
		j["refreshBefore"] = refreshBefore.isNull ? Json(null) : Json(refreshBefore.get);
		j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
		j["truncated"] = truncated;
		if (!deliveryStatus.isNull)
			j["deliveryStatus"] = deliveryStatus.get.toJson();
		return j;
	}

	static SubscribeResult fromJson(Json j) @safe
	{
		SubscribeResult r;
		r.id = j.getOr("id", "");
		if ("refreshBefore" in j && j["refreshBefore"].type == Json.Type.string)
			r.refreshBefore = j["refreshBefore"].get!string;
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			r.cursor = j["cursor"].get!string;
		r.truncated = j.getOr("truncated", false);
		if ("deliveryStatus" in j && j["deliveryStatus"].type == Json.Type.object)
			r.deliveryStatus = DeliveryStatus.fromJson(j["deliveryStatus"]);
		return r;
	}
}

/// Parameters of `events/unsubscribe` (webhook only). Resolves the subscription
/// by the same key as subscribe; only `delivery.url` is needed (no secret).
struct UnsubscribeParams
{
	string name;
	Json arguments = Json.emptyObject;
	string url; /// the callback `delivery.url`

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		j["arguments"] = arguments.type == Json.Type.object ? arguments : Json.emptyObject;
		Json d = Json.emptyObject;
		d["url"] = url;
		j["delivery"] = d;
		return j;
	}

	static UnsubscribeParams fromJson(Json j) @safe
	{
		UnsubscribeParams p;
		p.name = j.getOr("name", "");
		if ("arguments" in j && j["arguments"].type == Json.Type.object)
			p.arguments = j["arguments"];
		if ("delivery" in j && j["delivery"].type == Json.Type.object)
			p.url = j["delivery"].getOr("url", "");
		return p;
	}
}

/// A fixed category describing why a webhook delivery (or verification) failed.
/// Surfaced both as `deliveryStatus.lastError` and as `data.reason` on a
/// `-32015 CallbackEndpointError`. Never carries raw endpoint bodies/headers, so
/// it cannot serve as a response oracle for attacker-chosen URLs.
enum DeliveryErrorCategory
{
	connectionRefused,
	timeout,
	tlsError,
	http4xx,
	http5xx,
	challengeFailed
}

/// The wire string for a `DeliveryErrorCategory`.
string deliveryErrorToWire(DeliveryErrorCategory c) @safe pure nothrow
{
	final switch (c)
	{
	case DeliveryErrorCategory.connectionRefused:
		return "connection_refused";
	case DeliveryErrorCategory.timeout:
		return "timeout";
	case DeliveryErrorCategory.tlsError:
		return "tls_error";
	case DeliveryErrorCategory.http4xx:
		return "http_4xx";
	case DeliveryErrorCategory.http5xx:
		return "http_5xx";
	case DeliveryErrorCategory.challengeFailed:
		return "challenge_failed";
	}
}

/// Parse a delivery-error category; null for an unrecognized value.
Nullable!DeliveryErrorCategory deliveryErrorFromWire(string s) @safe pure nothrow
{
	switch (s)
	{
	case "connection_refused":
		return nullable(DeliveryErrorCategory.connectionRefused);
	case "timeout":
		return nullable(DeliveryErrorCategory.timeout);
	case "tls_error":
		return nullable(DeliveryErrorCategory.tlsError);
	case "http_4xx":
		return nullable(DeliveryErrorCategory.http4xx);
	case "http_5xx":
		return nullable(DeliveryErrorCategory.http5xx);
	case "challenge_failed":
		return nullable(DeliveryErrorCategory.challengeFailed);
	default:
		return Nullable!DeliveryErrorCategory.init;
	}
}

/// Optional per-subscription delivery health, returned on an `events/subscribe`
/// refresh so a client can detect delivery problems without a side channel.
struct DeliveryStatus
{
	bool active; /// false => delivery suspended after repeated failures
	Nullable!string lastDeliveryAt;
	Nullable!DeliveryErrorCategory lastError; /// null when no recent failure
	Nullable!string failedSince;
	Nullable!bool throttled; /// true => deliveries delayed (rate-limited), not failing
	Nullable!long retryAfterMs; /// hint for how long throttling lasts

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["active"] = active;
		if (!lastDeliveryAt.isNull)
			j["lastDeliveryAt"] = lastDeliveryAt.get;
		j["lastError"] = lastError.isNull ? Json(null) : Json(deliveryErrorToWire(lastError.get));
		if (!failedSince.isNull)
			j["failedSince"] = failedSince.get;
		if (!throttled.isNull)
			j["throttled"] = throttled.get;
		if (!retryAfterMs.isNull)
			j["retryAfterMs"] = retryAfterMs.get;
		return j;
	}

	static DeliveryStatus fromJson(Json j) @safe
	{
		DeliveryStatus s;
		s.active = j.getOr("active", false);
		tryGet(j, "lastDeliveryAt", s.lastDeliveryAt);
		if ("lastError" in j && j["lastError"].type == Json.Type.string)
			s.lastError = deliveryErrorFromWire(j["lastError"].get!string);
		tryGet(j, "failedSince", s.failedSince);
		if ("throttled" in j && j["throttled"].type == Json.Type.bool_)
			s.throttled = j["throttled"].get!bool;
		tryGet(j, "retryAfterMs", s.retryAfterMs);
		return s;
	}
}

// ---------------------------------------------------------------------------
// Control envelopes (non-event webhook bodies) and push notification params.
// ---------------------------------------------------------------------------

/// A `gap` control envelope: a gap was detected between refreshes; the client
/// persists `cursor` and treats it as `truncated: true`.
Json gapEnvelope(string cursor) @safe
{
	Json j = Json.emptyObject;
	j["type"] = "gap";
	j["cursor"] = cursor;
	return j;
}

/// A `terminated` control envelope / `notifications/events/terminated` params:
/// the subscription has ended (e.g. authorization revoked).
Json terminatedEnvelope(Json error) @safe
{
	Json j = Json.emptyObject;
	j["type"] = "terminated";
	j["error"] = error;
	return j;
}

/// A `verification` control envelope: sent before activating delivery to an
/// unverified `(principal, url)`; the endpoint echoes `challenge` to prove intent.
Json verificationEnvelope(string challenge) @safe
{
	Json j = Json.emptyObject;
	j["type"] = "verification";
	j["challenge"] = challenge;
	return j;
}

/// Whether a webhook POST body is a control envelope (has a top-level `type`)
/// rather than an `EventOccurrence`.
bool isControlEnvelope(Json payload) @safe
{
	return payload.type == Json.Type.object && "type" in payload
		&& payload["type"].type == Json.Type.string;
}

/// Params for `notifications/events/active` (push confirmation, also resent
/// mid-stream when a gap occurs). The transport adds the subscription id `_meta`.
Json activeParams(Nullable!string cursor, bool truncated) @safe
{
	Json j = Json.emptyObject;
	j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
	j["truncated"] = truncated;
	return j;
}

/// Params for `notifications/events/heartbeat`: the position checked up to, so
/// the client's cursor advances during quiet periods. Null for no-replay types.
Json heartbeatParams(Nullable!string cursor) @safe
{
	Json j = Json.emptyObject;
	j["cursor"] = cursor.isNull ? Json(null) : Json(cursor.get);
	return j;
}

/// Params for a recoverable `notifications/events/error` (the stream stays open).
Json eventErrorParams(Json error) @safe
{
	Json j = Json.emptyObject;
	j["error"] = error;
	return j;
}

/// Attach the SEP-2575 subscription-id correlation `_meta` to a push
/// notification's params. `subscriptionId` is the parent `events/stream`
/// request's JSON-RPC id (an integer or string).
Json withSubscriptionId(Json params, Json subscriptionId) @safe
{
	Json p = params.type == Json.Type.object ? params.clone() : Json.emptyObject;
	Json meta = ("_meta" in p && p["_meta"].type == Json.Type.object) ? p["_meta"]
		: Json.emptyObject;
	meta[subscriptionIdMetaKey] = subscriptionId;
	p["_meta"] = meta;
	return p;
}

// ---------------------------------------------------------------------------
// Typed control signals (delivered to a subscription's onControl handler)
// ---------------------------------------------------------------------------

/// A JSON-RPC-style error carried by a recoverable `error` control signal or a
/// `terminated` one. `data` keeps any structured detail (e.g. a `reason`
/// delivery-error category) without enumerating every producer.
struct EventError
{
	long code; /// JSON-RPC error code; 0 when the producer sent none
	string message; /// human-readable detail, possibly empty
	Json data = Json.undefined; /// optional structured detail

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["code"] = code;
		if (message.length)
			j["message"] = message;
		if (data.type != Json.Type.undefined)
			j["data"] = data;
		return j;
	}

	static EventError fromJson(Json j) @safe
	{
		EventError e;
		if (j.type != Json.Type.object)
			return e;
		if ("code" in j && j["code"].type == Json.Type.int_)
			e.code = j["code"].get!long;
		e.message = j.getOr("message", "");
		if ("data" in j)
			e.data = j["data"];
		return e;
	}
}

/// The kind of a non-occurrence control signal on a subscription.
enum EventControlKind
{
	active, /// delivery confirmed (push)
	heartbeat, /// keepalive; the cursor advanced during a quiet period
	gap, /// a delivery gap was detected; occurrences may have been missed
	error, /// recoverable delivery error; the subscription stays open
	terminated /// the subscription has ended; no more occurrences will arrive
}

/// A typed control signal handed to a subscription's `onControl`. Unifies the
/// push `notifications/events/{active,heartbeat,error,terminated}` frames and the
/// webhook `{gap,terminated}` control envelopes, so a client never parses raw
/// control JSON. Fields are populated per kind: `cursor` for active/heartbeat/
/// gap, and `error` for error/terminated.
struct EventControl
{
	EventControlKind kind;
	Nullable!string cursor; /// position checked up to (active/heartbeat/gap)
	Nullable!EventError error; /// failure detail (error/terminated)

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["kind"] = controlKindToWire(kind);
		if (!cursor.isNull)
			j["cursor"] = cursor.get;
		if (!error.isNull)
			j["error"] = error.get.toJson();
		return j;
	}
}

/// The wire/log string for a control kind.
string controlKindToWire(EventControlKind k) @safe pure nothrow
{
	final switch (k)
	{
	case EventControlKind.active:
		return "active";
	case EventControlKind.heartbeat:
		return "heartbeat";
	case EventControlKind.gap:
		return "gap";
	case EventControlKind.error:
		return "error";
	case EventControlKind.terminated:
		return "terminated";
	}
}

private void readCursorInto(Json j, ref Nullable!string cursor) @safe
{
	if (j.type == Json.Type.object && "cursor" in j && j["cursor"].type == Json.Type.string)
		cursor = j["cursor"].get!string;
}

/// Parse a push `notifications/events/*` control frame into a typed control.
/// Returns false for methods that aren't control frames (the event notification
/// itself, or `list_changed`). An `active` re-sent with `truncated:true` is
/// normalized to `gap`, so a client treats a push gap and a webhook gap alike.
bool controlFromPushNotification(string method, Json params, out EventControl c) @safe
{
	switch (method)
	{
	case eventsActiveNotification:
		readCursorInto(params, c.cursor);
		const truncated = params.type == Json.Type.object && "truncated" in params
			&& params["truncated"].type == Json.Type.bool_ && params["truncated"].get!bool;
		c.kind = truncated ? EventControlKind.gap : EventControlKind.active;
		return true;
	case eventsHeartbeatNotification:
		c.kind = EventControlKind.heartbeat;
		readCursorInto(params, c.cursor);
		return true;
	case eventsErrorNotification:
		c.kind = EventControlKind.error;
		if (params.type == Json.Type.object && "error" in params)
			c.error = EventError.fromJson(params["error"]);
		return true;
	case eventsTerminatedNotification:
		c.kind = EventControlKind.terminated;
		if (params.type == Json.Type.object && "error" in params)
			c.error = EventError.fromJson(params["error"]);
		return true;
	default:
		return false;
	}
}

/// Parse a webhook control envelope (`{type: gap|terminated, ...}`) into a typed
/// control. Returns false for non-control bodies and for envelope types not
/// surfaced to the application (e.g. `verification`, handled internally).
bool controlFromWebhookEnvelope(Json env, out EventControl c) @safe
{
	if (env.type != Json.Type.object || "type" !in env
		|| env["type"].type != Json.Type.string)
		return false;
	switch (env["type"].get!string)
	{
	case "gap":
		c.kind = EventControlKind.gap;
		readCursorInto(env, c.cursor);
		return true;
	case "terminated":
		c.kind = EventControlKind.terminated;
		if ("error" in env)
			c.error = EventError.fromJson(env["error"]);
		return true;
	default:
		return false;
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

unittest  // DeliveryMode wire conversions round-trip and reject unknowns
{
	foreach (m; [DeliveryMode.poll, DeliveryMode.push, DeliveryMode.webhook])
		assert(deliveryModeFromWire(deliveryModeToWire(m)).get == m);
	assert(deliveryModeFromWire("sms").isNull);
}

unittest  // EventType serializes name/delivery/schemas and round-trips
{
	EventType e;
	e.name = "email.received";
	e.description = "New email arrives";
	e.delivery = [DeliveryMode.poll, DeliveryMode.webhook];
	e.inputSchema = Json(["type": Json("object")]);
	e.payloadSchema = Json(["type": Json("object")]);
	auto j = e.toJson();
	assert(j["name"].get!string == "email.received");
	assert(j["delivery"].length == 2);
	assert(j["delivery"][0].get!string == "poll");
	auto back = EventType.fromJson(j);
	assert(back.name == "email.received" && back.delivery.length == 2);
	assert(back.delivery[1] == DeliveryMode.webhook);
	assert(back.inputSchema.type == Json.Type.object);
}

unittest  // EventType carries an optional title and round-trips it
{
	EventType e;
	e.name = "email.received";
	e.title = "New Email";
	e.delivery = [DeliveryMode.poll];
	auto j = e.toJson();
	assert(j["title"].get!string == "New Email");
	auto back = EventType.fromJson(j);
	assert(back.title == "New Email");
}

unittest  // EventType omits description and schemas when unset
{
	EventType e;
	e.name = "x";
	e.delivery = [DeliveryMode.push];
	auto j = e.toJson();
	assert("description" !in j);
	assert("title" !in j);
	assert("inputSchema" !in j);
	assert("payloadSchema" !in j);
	assert("_meta" !in j);
}

unittest  // EventType.fromJson skips unknown delivery strings
{
	Json j = Json.emptyObject;
	j["name"] = "x";
	Json arr = Json.emptyArray;
	arr ~= Json("poll");
	arr ~= Json("carrier-pigeon");
	j["delivery"] = arr;
	auto e = EventType.fromJson(j);
	assert(e.delivery.length == 1 && e.delivery[0] == DeliveryMode.poll);
}

unittest  // EventListResult carries events and an optional nextCursor
{
	EventListResult r;
	r.events = [EventType("a", "", [DeliveryMode.poll])];
	auto j = r.toJson();
	assert(j["events"].length == 1);
	assert("nextCursor" !in j);
	r.nextCursor = "page2";
	assert(r.toJson()["nextCursor"].get!string == "page2");
	auto back = EventListResult.fromJson(r.toJson());
	assert(back.events.length == 1 && back.nextCursor.get == "page2");
}

unittest  // EventOccurrence round-trips with a cursor
{
	EventOccurrence e;
	e.eventId = "evt_001";
	e.name = "email.received";
	e.timestamp = "2026-02-19T15:30:00Z";
	e.data = Json(["from": Json("a@b.com")]);
	e.cursor = "historyId_99842";
	auto j = e.toJson();
	assert(j["eventId"].get!string == "evt_001");
	assert(j["cursor"].get!string == "historyId_99842");
	auto back = EventOccurrence.fromJson(j);
	assert(back.eventId == "evt_001" && back.cursor.get == "historyId_99842");
	assert(back.data["from"].get!string == "a@b.com");
}

unittest  // EventOccurrence omits cursor when null (poll-style occurrence)
{
	EventOccurrence e;
	e.eventId = "evt";
	e.name = "x";
	e.timestamp = "t";
	auto j = e.toJson();
	assert("cursor" !in j);
	// absent cursor parses back as null
	assert(EventOccurrence.fromJson(j).cursor.isNull);
}

unittest  // PollParams emits cursor:null for "from now" and round-trips a cursor
{
	PollParams p;
	p.name = "email.received";
	p.arguments = Json(["from": Json("*@x.com")]);
	auto j = p.toJson();
	assert(j["cursor"].type == Json.Type.null_);
	auto back = PollParams.fromJson(j);
	assert(back.name == "email.received" && back.cursor.isNull);

	p.cursor = "c1";
	p.maxAgeMs = 300_000;
	p.maxEvents = 50;
	auto j2 = p.toJson();
	assert(j2["cursor"].get!string == "c1");
	assert(j2["maxAgeMs"].get!long == 300_000 && j2["maxEvents"].get!long == 50);
	auto back2 = PollParams.fromJson(j2);
	assert(back2.cursor.get == "c1" && back2.maxAgeMs.get == 300_000 && back2.maxEvents.get == 50);
}

unittest  // PollResult round-trips events + flags
{
	PollResult r;
	r.events = [EventOccurrence("e1", "n", "t")];
	r.cursor = "c2";
	r.truncated = true;
	r.hasMore = true;
	r.nextPollMs = 30_000;
	auto j = r.toJson();
	assert(j["events"].length == 1);
	assert(j["cursor"].get!string == "c2");
	assert(j["truncated"].get!bool && j["hasMore"].get!bool);
	assert(j["nextPollMs"].get!long == 30_000);
	auto back = PollResult.fromJson(j);
	assert(back.events.length == 1 && back.cursor.get == "c2");
	assert(back.truncated && back.hasMore && back.nextPollMs.get == 30_000);
}

unittest  // PollResult emits cursor:null when the event type does not support replay
{
	PollResult r;
	auto j = r.toJson();
	assert(j["cursor"].type == Json.Type.null_);
	assert(PollResult.fromJson(j).cursor.isNull);
}

unittest  // WebhookDelivery serializes mode/url/secret and omits secret when empty
{
	WebhookDelivery d;
	d.url = "https://proxy.example.com/hooks/c1";
	d.secret = "whsec_abc";
	auto j = d.toJson();
	assert(j["mode"].get!string == "webhook");
	assert(j["url"].get!string == "https://proxy.example.com/hooks/c1");
	assert(j["secret"].get!string == "whsec_abc");
	auto bare = WebhookDelivery("https://x/y");
	assert("secret" !in bare.toJson());
}

unittest  // SubscribeParams: absent ttlMs leaves ttlMsPresent false (server default)
{
	Json j = Json.emptyObject;
	j["name"] = "incident.created";
	Json d = Json.emptyObject;
	d["url"] = "https://x/y";
	d["secret"] = "whsec_z";
	j["delivery"] = d;
	auto p = SubscribeParams.fromJson(j);
	assert(!p.ttlMsPresent && p.ttlMs.isNull);
	assert(p.delivery.url == "https://x/y" && p.delivery.secret == "whsec_z");
}

unittest  // SubscribeParams: explicit ttlMs:null requests no expiry
{
	Json j = Json.emptyObject;
	j["name"] = "x";
	j["ttlMs"] = Json(null);
	auto p = SubscribeParams.fromJson(j);
	assert(p.ttlMsPresent && p.ttlMs.isNull);
}

unittest  // SubscribeParams: a numeric ttlMs is a suggestion and round-trips
{
	SubscribeParams p;
	p.name = "x";
	p.delivery = WebhookDelivery("https://x/y", "whsec_z");
	p.ttlMsPresent = true;
	p.ttlMs = 3_600_000;
	auto j = p.toJson();
	assert(j["ttlMs"].get!long == 3_600_000);
	auto back = SubscribeParams.fromJson(j);
	assert(back.ttlMsPresent && back.ttlMs.get == 3_600_000);
}

unittest  // SubscribeResult emits refreshBefore/cursor (nullable) and round-trips
{
	SubscribeResult r;
	r.id = "sub_a3f1";
	r.refreshBefore = "2026-02-19T16:30:00Z";
	r.cursor = "cursor_start_001";
	auto j = r.toJson();
	assert(j["id"].get!string == "sub_a3f1");
	assert(j["refreshBefore"].get!string == "2026-02-19T16:30:00Z");
	assert(j["truncated"].get!bool == false);
	auto back = SubscribeResult.fromJson(j);
	assert(back.id == "sub_a3f1" && back.refreshBefore.get == "2026-02-19T16:30:00Z");
	assert(back.cursor.get == "cursor_start_001");
}

unittest  // SubscribeResult emits refreshBefore:null for a no-expiry grant
{
	SubscribeResult r;
	r.id = "s";
	auto j = r.toJson();
	assert(j["refreshBefore"].type == Json.Type.null_);
	assert(SubscribeResult.fromJson(j).refreshBefore.isNull);
}

unittest  // SubscribeResult carries an optional deliveryStatus when present
{
	SubscribeResult r;
	r.id = "s";
	DeliveryStatus st;
	st.active = false;
	st.lastError = DeliveryErrorCategory.http4xx;
	r.deliveryStatus = st;
	auto j = r.toJson();
	assert(j["deliveryStatus"]["active"].get!bool == false);
	assert(j["deliveryStatus"]["lastError"].get!string == "http_4xx");
	auto back = SubscribeResult.fromJson(j);
	assert(!back.deliveryStatus.isNull && !back.deliveryStatus.get.active);
	assert(back.deliveryStatus.get.lastError.get == DeliveryErrorCategory.http4xx);
}

unittest  // UnsubscribeParams carries name/arguments/url
{
	UnsubscribeParams p;
	p.name = "incident.created";
	p.arguments = Json(["severity": Json("P1")]);
	p.url = "https://proxy.example.com/hooks/c1";
	auto j = p.toJson();
	assert(j["delivery"]["url"].get!string == "https://proxy.example.com/hooks/c1");
	auto back = UnsubscribeParams.fromJson(j);
	assert(back.name == "incident.created" && back.url == "https://proxy.example.com/hooks/c1");
	assert(back.arguments["severity"].get!string == "P1");
}

unittest  // DeliveryErrorCategory wire conversions round-trip
{
	foreach (c; [
		DeliveryErrorCategory.connectionRefused, DeliveryErrorCategory.timeout,
		DeliveryErrorCategory.tlsError, DeliveryErrorCategory.http4xx,
		DeliveryErrorCategory.http5xx, DeliveryErrorCategory.challengeFailed
	])
		assert(deliveryErrorFromWire(deliveryErrorToWire(c)).get == c);
	assert(deliveryErrorFromWire("nope").isNull);
}

unittest  // DeliveryStatus emits lastError:null when no recent failure
{
	DeliveryStatus s;
	s.active = true;
	auto j = s.toJson();
	assert(j["active"].get!bool);
	assert(j["lastError"].type == Json.Type.null_);
	assert("throttled" !in j);
}

unittest  // DeliveryStatus carries throttling fields when set
{
	DeliveryStatus s;
	s.active = true;
	s.throttled = true;
	s.retryAfterMs = 60_000;
	auto j = s.toJson();
	assert(j["throttled"].get!bool && j["retryAfterMs"].get!long == 60_000);
	auto back = DeliveryStatus.fromJson(j);
	assert(back.throttled.get && back.retryAfterMs.get == 60_000);
}

unittest  // control envelopes carry the right discriminator
{
	assert(gapEnvelope("c")["type"].get!string == "gap");
	assert(gapEnvelope("c")["cursor"].get!string == "c");
	assert(terminatedEnvelope(Json(["code": Json(-32012)]))["type"].get!string == "terminated");
	assert(verificationEnvelope("nonce")["challenge"].get!string == "nonce");
}

unittest  // isControlEnvelope distinguishes control bodies from event occurrences
{
	assert(isControlEnvelope(gapEnvelope("c")));
	auto occ = EventOccurrence("e", "n", "t").toJson();
	assert(!isControlEnvelope(occ));
}

unittest  // activeParams / heartbeatParams emit cursor:null when null
{
	assert(activeParams(Nullable!string.init, true)["cursor"].type == Json.Type.null_);
	assert(activeParams(Nullable!string.init, true)["truncated"].get!bool);
	assert(activeParams(nullable("c"), false)["cursor"].get!string == "c");
	assert(heartbeatParams(nullable("h"))["cursor"].get!string == "h");
	assert(heartbeatParams(Nullable!string.init)["cursor"].type == Json.Type.null_);
}

unittest  // withSubscriptionId attaches the SEP-2575 correlation _meta (integer id)
{
	auto occ = EventOccurrence("e", "n", "t").toJson();
	auto tagged = withSubscriptionId(occ, Json(1));
	assert(tagged["_meta"][subscriptionIdMetaKey].get!int == 1);
	// original event fields preserved
	assert(tagged["eventId"].get!string == "e");
}

unittest  // withSubscriptionId merges into an existing _meta and supports string ids
{
	Json params = Json.emptyObject;
	params["_meta"] = Json(["existing": Json("keep")]);
	auto tagged = withSubscriptionId(params, Json("sub-7"));
	assert(tagged["_meta"]["existing"].get!string == "keep");
	assert(tagged["_meta"][subscriptionIdMetaKey].get!string == "sub-7");
}

unittest  // EventError round-trips code/message/data and tolerates a non-object
{
	auto err = EventError.fromJson(Json([
		"code": Json(-32012), "message": Json("revoked"),
		"data": Json(["reason": Json("challenge_failed")])
	]));
	assert(err.code == -32012);
	assert(err.message == "revoked");
	assert(err.data["reason"].get!string == "challenge_failed");
	assert(EventError.fromJson(Json("nope")).code == 0);
}

unittest  // a push `active` frame parses to active, carrying its cursor
{
	EventControl c;
	assert(controlFromPushNotification(eventsActiveNotification,
		activeParams(nullable("cur-1"), false), c));
	assert(c.kind == EventControlKind.active);
	assert(c.cursor.get == "cur-1");
}

unittest  // a push `active` with truncated:true is normalized to gap
{
	EventControl c;
	assert(controlFromPushNotification(eventsActiveNotification,
		activeParams(nullable("cur-2"), true), c));
	assert(c.kind == EventControlKind.gap);
	assert(c.cursor.get == "cur-2");
}

unittest  // a push `terminated` frame carries its typed error
{
	EventControl c;
	auto params = Json(["error": Json(["code": Json(-32012), "message": Json("gone")])]);
	assert(controlFromPushNotification(eventsTerminatedNotification, params, c));
	assert(c.kind == EventControlKind.terminated);
	assert(c.error.get.code == -32012);
	assert(c.error.get.message == "gone");
}

unittest  // a non-control push method (the event itself) is rejected
{
	EventControl c;
	assert(!controlFromPushNotification(eventsEventNotification, Json.emptyObject, c));
}

unittest  // a webhook gap envelope parses to a typed gap with its cursor
{
	EventControl c;
	assert(controlFromWebhookEnvelope(gapEnvelope("cur-3"), c));
	assert(c.kind == EventControlKind.gap);
	assert(c.cursor.get == "cur-3");
}

unittest  // a webhook terminated envelope carries its typed error
{
	EventControl c;
	assert(controlFromWebhookEnvelope(terminatedEnvelope(Json(["code": Json(-32012)])), c));
	assert(c.kind == EventControlKind.terminated);
	assert(c.error.get.code == -32012);
}

unittest  // a webhook verification envelope is not surfaced as control
{
	EventControl c;
	assert(!controlFromWebhookEnvelope(verificationEnvelope("nonce"), c));
}
