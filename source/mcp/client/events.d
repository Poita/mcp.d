/// Client-side helpers for the MCP Events extension's webhook delivery mode: a
/// `WebhookReceiver` that verifies inbound Standard Webhooks deliveries, answers
/// the verification handshake, deduplicates, and routes event occurrences to a
/// callback — usable directly as the forward proxy a `delivery.url` points at —
/// plus `generateWhsecSecret` for minting the client-supplied signing secret.
/// The subscribe/poll/stream RPCs themselves live on `McpClient`.
module mcp.client.events;

import std.base64 : Base64;
import vibe.data.json : Json, parseJsonString;

import standardwebhooks : Webhook;
import mcp.protocol.events : EventOccurrence, isControlEnvelope;

@safe:

/// Generate a Standard Webhooks symmetric secret: `whsec_` + base64 of 32
/// CSPRNG bytes. Client SDKs generate this rather than letting an application
/// hand-pick a value.
string generateWhsecSecret() @safe
{
	import mcp.auth.csprng : cryptoRandomBytes;

	return ("whsec_" ~ Base64.encode(cryptoRandomBytes(32))).idup;
}

/// The status and body a `WebhookReceiver` wants returned for one delivery.
struct ReceiverResponse
{
	int status;
	string body;
}

/// Receives signed webhook deliveries for one or more subscriptions, verifies
/// them, answers verification challenges, deduplicates per subscription, and
/// routes event occurrences (and control envelopes) to per-subscription
/// callbacks. Transport-agnostic: feed it the raw body + headers via
/// `processDelivery`; a thin HTTP adapter (e.g. a vibe route) calls that and
/// writes back `ReceiverResponse`.
final class WebhookReceiver
{
	private struct Reg
	{
		string secret;
		void delegate(EventOccurrence occ) @safe onEvent;
		void delegate(Json envelope) @safe onControl;
	}

	private Reg[string] regs_;
	// Dedup keyed per subscription (subId \0 webhook-id), value is the delivery's
	// webhook-timestamp (seconds). The same eventId fans out to multiple
	// subscriptions as deliveries sharing a webhook-id, so the key must include
	// the subscription id or one subscription's copy would swallow the others'.
	private long[string] seen_;

	/// Dedup entries older than this many seconds (relative to the newest
	/// webhook-timestamp seen) are evicted, and `seen_` is hard-capped at
	/// `seenCapacity` entries so it cannot grow without bound.
	long seenWindowSeconds = 24 * 3600;
	size_t seenCapacity = 100_000;

	/// When false, signatures are verified but the timestamp freshness window is
	/// ignored. Production receivers keep this true; tests with a synthetic clock
	/// set it false. (The server still regenerates the timestamp per attempt.)
	bool verifyTimestamp = true;

	/// Register (or replace) the secret and callbacks for a subscription id (the
	/// value carried in `X-MCP-Subscription-Id`). `onControl` is optional.
	void register(string subscriptionId, string secret,
			void delegate(EventOccurrence occ) @safe onEvent,
			void delegate(Json envelope) @safe onControl = null) @safe
	{
		regs_[subscriptionId] = Reg(secret, onEvent, onControl);
	}

	/// Stop routing deliveries for a subscription id.
	void unregister(string subscriptionId) @safe
	{
		regs_.remove(subscriptionId);
	}

	/// Verify and route one delivery. Returns the HTTP status (and body) the
	/// endpoint should reply with: `200` once the event is durably accepted (or a
	/// verification challenge is echoed), `400` on a signature/parse failure, and
	/// `503` for an unknown subscription id (a retryable subscribe/delivery race).
	ReceiverResponse processDelivery(string body, string[string] headers) @safe
	{
		const subId = headerGet(headers, "x-mcp-subscription-id");
		auto reg = subId in regs_;
		if (reg is null)
			return ReceiverResponse(503, ""); // not yet routable; the server retries

		auto wh = Webhook(reg.secret);
		auto vr = verifyTimestamp ? wh.tryVerify(body,
				headers) : wh.tryVerifyIgnoringTimestamp(body, headers);
		if (!vr.ok)
			return ReceiverResponse(400, "");

		// Deduplicate retries per subscription: the same eventId fans out to every
		// subscription as deliveries sharing one webhook-id, so a bare webhook-id
		// key would let the first subscription's copy swallow the rest. Only a true
		// retry (same subscription + same webhook-id) is a duplicate.
		const wid = headerGet(headers, "webhook-id");
		if (wid.length)
		{
			import std.conv : to;

			long ts;
			try
				ts = headerGet(headers, "webhook-timestamp").to!long;
			catch (Exception)
				ts = 0;
			const key = subId ~ "\0" ~ wid;
			if ((key in seen_) !is null)
				return ReceiverResponse(200, ""); // already processed
			seen_[key] = ts;
			evictSeen(ts);
		}

		Json j;
		try
			j = parseJsonString(body);
		catch (Exception)
			return ReceiverResponse(400, "");

		if (isControlEnvelope(j))
		{
			const type = j["type"].get!string;
			if (type == "verification") // Prove intent to receive: echo the challenge in a 2xx body.
				return ReceiverResponse(200, Json(["challenge": j["challenge"]]).toString());
			if (reg.onControl !is null)
				reg.onControl(j);
			return ReceiverResponse(200, "");
		}

		if (reg.onEvent !is null)
			reg.onEvent(EventOccurrence.fromJson(j));
		return ReceiverResponse(200, "");
	}

	// Bound the dedup set: drop entries older than `seenWindowSeconds` behind the
	// newest delivery, then, if still over `seenCapacity`, drop the oldest entries
	// until within cap. Webhook timestamps move forward, so anything far behind the
	// freshness window will never be retried.
	private void evictSeen(long newestTs) @safe
	{
		import std.algorithm : sort;
		import std.array : array;

		if (seenWindowSeconds > 0 && newestTs > 0)
		{
			const cutoff = newestTs - seenWindowSeconds;
			foreach (k; seen_.keys)
				if (seen_[k] < cutoff)
					seen_.remove(k);
		}

		if (seen_.length > seenCapacity)
		{
			auto byAge = seen_.byKeyValue.array;
			byAge.sort!((a, b) => a.value < b.value);
			const drop = seen_.length - seenCapacity;
			foreach (kv; byAge[0 .. drop])
				seen_.remove(kv.key);
		}
	}

	// Case-insensitive header lookup (a plain string[string] is case-sensitive,
	// but webhook senders and HTTP intermediaries vary header casing).
	private static string headerGet(string[string] headers, string name) @safe
	{
		import std.uni : toLower;

		foreach (k, v; headers)
			if (toLower(k) == name)
				return v;
		return "";
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

version (unittest)
{
	import mcp.server.webhook_delivery : signDeliveryHeaders;
	import mcp.protocol.events : verificationEnvelope;

	private enum testSecret = "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
}

unittest  // generateWhsecSecret produces a decodable whsec_ secret of 32 bytes
{
	import std.algorithm : startsWith;

	auto s = generateWhsecSecret();
	assert(s.startsWith("whsec_"));
	auto raw = Base64.decode(s["whsec_".length .. $]);
	assert(raw.length == 32);
	assert(generateWhsecSecret() != generateWhsecSecret()); // random
}

unittest  // the receiver verifies a signed event delivery and routes the occurrence
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false; // synthetic timestamp below
	EventOccurrence got;
	bool delivered;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe {
		got = occ;
		delivered = true;
	});

	const 
	body = EventOccurrence("evt_1", "incident.created", "t", Json([
		"severity": Json("P1")
	])).toJson().toString();
	auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, "evt_1",
			1700, body, "sub_1", null);
	auto resp = rx.processDelivery(body, headers);
	assert(resp.status == 200);
	assert(delivered && got.eventId == "evt_1");
	assert(got.data["severity"].get!string == "P1");
}

unittest  // the receiver answers a verification challenge by echoing the nonce
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe {});

	const 
	body = verificationEnvelope("nonce-123").toString();
	auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, "msg_verif",
			1700, body, "sub_1", null);
	auto resp = rx.processDelivery(body, headers);
	assert(resp.status == 200);
	assert(parseJsonString(resp.body)["challenge"].get!string == "nonce-123");
}

unittest  // an unknown subscription id yields a retryable 503
{
	auto rx = new WebhookReceiver();
	auto resp = rx.processDelivery(`{}`, ["X-MCP-Subscription-Id": "unknown"]);
	assert(resp.status == 503);
}

unittest  // a tampered body fails signature verification with 400
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe {});
	const 
	body = `{"eventId":"e","name":"n","timestamp":"t","data":{}}`;
	auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, "e", 1700, body, "sub_1", null);
	auto resp = rx.processDelivery(body ~ "tampered", headers);
	assert(resp.status == 400);
}

unittest  // a retried delivery (same webhook-id) is deduplicated, callback fires once
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	int count;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe { count++; });
	const 
	body = EventOccurrence("evt_dup", "n", "t").toJson().toString();
	auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, "evt_dup",
			1700, body, "sub_1", null);
	assert(rx.processDelivery(body, headers).status == 200);
	assert(rx.processDelivery(body, headers).status == 200); // retry
	assert(count == 1); // routed only once
}

unittest  // the same eventId fanned to two subscriptions reaches each subscription's callback
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	int a, b;
	rx.register("sub_a", testSecret, (EventOccurrence occ) @safe { a++; });
	rx.register("sub_b", testSecret, (EventOccurrence occ) @safe { b++; });

	// One occurrence => one webhook-id, fanned to both subscriptions as separate
	// deliveries that share the webhook-id but carry distinct subscription ids.
	const 
	body = EventOccurrence("evt_fan", "n", "t").toJson().toString();
	auto ha = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_shared",
			1700, body, "sub_a", null);
	auto hb = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_shared",
			1700, body, "sub_b", null);
	assert(rx.processDelivery(body, ha).status == 200);
	assert(rx.processDelivery(body, hb).status == 200);
	assert(a == 1 && b == 1); // each subscription got its own copy
}

unittest  // a true retry (same subscription + webhook-id) is still deduplicated across subscriptions
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	int a;
	rx.register("sub_a", testSecret, (EventOccurrence occ) @safe { a++; });
	rx.register("sub_b", testSecret, (EventOccurrence occ) @safe {});

	const 
	body = EventOccurrence("evt_fan", "n", "t").toJson().toString();
	auto ha = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_shared",
			1700, body, "sub_a", null);
	auto hb = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_shared",
			1700, body, "sub_b", null);
	assert(rx.processDelivery(body, ha).status == 200);
	assert(rx.processDelivery(body, hb).status == 200); // other subscription, not a dup
	assert(rx.processDelivery(body, ha).status == 200); // sub_a retry, deduped
	assert(a == 1);
}

unittest  // stale dedup entries are evicted once deliveries advance past the window
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	rx.seenWindowSeconds = 100;
	int count;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe { count++; });

	// An old delivery, then one far enough ahead to evict the old key.
	const oldBody = EventOccurrence("evt_old", "n", "t").toJson().toString();
	auto oldHeaders = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_old",
			1000, oldBody, "sub_1", null);
	assert(rx.processDelivery(oldBody, oldHeaders).status == 200);

	const newBody = EventOccurrence("evt_new", "n", "t").toJson().toString();
	auto newHeaders = signDeliveryHeaders(testSecret, "", 0, 1000, "wid_new",
			5000, newBody, "sub_1", null);
	assert(rx.processDelivery(newBody, newHeaders).status == 200);

	// The old key has aged out, so a redelivery of it routes again rather than
	// being silently swallowed, and the set has not retained it.
	assert(("sub_1\0wid_old" in rx.seen_) is null);
	assert(rx.processDelivery(oldBody, oldHeaders).status == 200);
	assert(count == 3);
}

unittest  // the dedup set is hard-capped so it cannot grow without bound
{
	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	rx.seenWindowSeconds = 0; // exercise the capacity bound alone
	rx.seenCapacity = 10;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe {});

	foreach (i; 0 .. 100)
	{
		import std.conv : to;

		const wid = "wid_" ~ i.to!string;
		const 
		body = EventOccurrence("evt_" ~ i.to!string, "n", "t").toJson().toString();
		auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, wid,
				1700 + i, body, "sub_1", null);
		assert(rx.processDelivery(body, headers).status == 200);
	}
	assert(rx.seen_.length <= 10);
}

unittest  // a terminated control envelope is routed to onControl
{
	import mcp.protocol.events : terminatedEnvelope;

	auto rx = new WebhookReceiver();
	rx.verifyTimestamp = false;
	Json gotControl;
	rx.register("sub_1", testSecret, (EventOccurrence occ) @safe {}, (Json env) @safe {
		gotControl = env;
	});
	const 
	body = terminatedEnvelope(Json(["code": Json(-32012)])).toString();
	auto headers = signDeliveryHeaders(testSecret, "", 0, 1000, "msg_term",
			1700, body, "sub_1", null);
	assert(rx.processDelivery(body, headers).status == 200);
	assert(gotControl["type"].get!string == "terminated");
}
