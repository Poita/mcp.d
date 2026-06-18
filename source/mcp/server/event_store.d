/// Storage backing the MCP Events extension: an in-memory `EmitBuffer` ring
/// buffer that serves `events/poll` for emit-only event types, and the
/// `WebhookSubscriptionStore` that holds webhook subscription identity/config
/// with per-subscription TTLs. The runtime (`mcp.server.events_runtime`) owns the
/// ephemeral delivery bookkeeping (retry queue, in-flight acks); what lives here
/// is the state a server MAY choose to persist when it grants long TTLs.
module mcp.server.event_store;

import std.typecons : Nullable, nullable;
import core.time : Duration, minutes;
import vibe.data.json : Json;

import mcp.protocol.events : EventOccurrence;
import mcp.protocol.jsonhelpers : getOr, tryGet;
import mcp.server.event_context : EventResult;

@safe:

/// Milliseconds since the Unix epoch, the time base shared by the emit buffer and
/// the webhook engine so their relative comparisons (age, expiry) stay coherent.
long nowUnixMs() @safe
{
	import std.datetime.systime : Clock;
	import std.datetime.timezone : UTC;

	auto t = Clock.currTime(UTC());
	return t.toUnixTime!long * 1000 + t.fracSecs.total!"msecs";
}

/// Parse a ring-buffer sequence cursor (the position stamped by `EmitBuffer`) into
/// its numeric value. Returns false for a null/unparseable cursor. Shared so the
/// webhook watermark can compare two cursors using the same encoding the buffer
/// assigns.
bool tryParseSeq(string s, out long seq) @safe nothrow
{
	import std.conv : to;

	try
	{
		seq = to!long(s);
		return true;
	}
	catch (Exception)
		return false;
}

/// Configuration for the emit ring buffer: how long and how many events to retain
/// per event type before eviction.
struct EmitBufferOptions
{
	Duration maxAge = 10.minutes; /// retain events younger than this
	size_t maxEvents = 10_000; /// cap retained events per event type
}

/// A bounded, in-memory ring buffer of emitted events per event type. Backs
/// `events/poll` for emit-only event types (those with no cursor-addressable
/// upstream). The cursor is a process-local sequence number: a server restart
/// invalidates all cursors, and a poll with a stale/unparseable cursor yields a
/// fresh cursor with `truncated: true`. Events emitted during downtime are not
/// recoverable — matching the upstream's own guarantees for push-only sources.
final class EmitBuffer
{
	private struct Entry
	{
		long seq;
		long atMs;
		EventOccurrence occ;
	}

	private Entry[][string] byName_;
	private long seqCounter_;
	private EmitBufferOptions opts_;

	/// Injectable clock (ms since epoch) so tests can drive eviction by age.
	long delegate() @safe nowMs;

	this(EmitBufferOptions opts = EmitBufferOptions.init) @safe
	{
		opts_ = opts;
		nowMs = () @safe => nowUnixMs();
	}

	/// Append an emitted event for `name`, assigning it the next sequence number
	/// as its cursor, then evict by age/count. Returns the assigned cursor.
	string append(string name, EventOccurrence occ) @safe
	{
		seqCounter_++;
		occ.cursor = seqString(seqCounter_);
		byName_[name] ~= Entry(seqCounter_, nowMs(), occ);
		evict(name);
		return occ.cursor.get;
	}

	/// The current head cursor — the position a bootstrap (`cursor: null`) poll
	/// resumes "from now" against.
	string headCursor() @safe
	{
		return seqString(seqCounter_);
	}

	/// Read events buffered after `cursor` for `name`, honouring the `maxAgeMs`
	/// replay floor and the `maxEvents` cap. Returns an `EventResult` whose
	/// `cursor` is the new position, with `truncated`/`hasMore` set as needed.
	EventResult readSince(string name, Nullable!string cursor,
			Nullable!long maxAgeMs, Nullable!long maxEvents) @safe
	{
		// Bootstrap: no replay, start from the current head.
		if (cursor.isNull)
			return EventResult.empty(headCursor());

		long fromSeq;
		if (!tryParseSeq(cursor.get, fromSeq)) // An unparseable cursor (e.g. from a prior process) resets to now.
			return EventResult.empty(headCursor(), true);

		// A cursor ahead of the current head (e.g. a client resuming after a restart
		// that reset the seq counter, or a forged future cursor) cannot be satisfied
		// from the buffer. Reset to head and signal a gap rather than reporting
		// up-to-date — the events between head and the stale cursor are unrecoverable.
		if (fromSeq > seqCounter_)
			return EventResult.empty(headCursor(), true);

		auto entries = byName_.get(name, null);
		bool truncated;

		// Gap from eviction: the cursor points before the earliest retained
		// event (and at least one event between them was dropped).
		if (entries.length && entries[0].seq > fromSeq + 1)
			truncated = true;

		const hasFloor = !maxAgeMs.isNull;
		const floorMs = hasFloor ? (nowMs() - maxAgeMs.get) : 0;

		EventOccurrence[] selected;
		foreach (const ref e; entries)
		{
			if (e.seq <= fromSeq)
				continue;
			if (hasFloor && e.atMs < floorMs)
			{
				// An event newer than the cursor but older than the floor is
				// skipped — that is a (bounded) gap.
				truncated = true;
				continue;
			}
			selected ~= e.occ;
		}

		// The cursor to return when the batch is empty: the last event the caller has
		// already seen (its supplied cursor), not the buffer head — advancing to head
		// would skip any retained-but-unselected events on the next poll.
		string emptyCursor = selected.length ? selected[$ - 1].cursor.get : cursor.get;

		bool hasMore;
		// A non-positive cap is treated as no cap: capping to zero would drop the whole
		// batch yet still advance the cursor, silently losing the window.
		if (!maxEvents.isNull && maxEvents.get >= 1 && selected.length > maxEvents.get)
		{
			selected = selected[0 .. cast(size_t) maxEvents.get];
			hasMore = true;
		}

		string newCursor = selected.length ? selected[$ - 1].cursor.get : emptyCursor;
		auto r = EventResult.of(selected, newCursor, truncated, hasMore);
		return r;
	}

	private void evict(string name) @safe
	{
		auto entries = byName_.get(name, null);
		if (entries is null)
			return;
		const cutoff = nowMs() - opts_.maxAge.total!"msecs";
		size_t start;
		while (start < entries.length && entries[start].atMs < cutoff)
			start++;
		if (entries.length - start > opts_.maxEvents)
			start = entries.length - opts_.maxEvents;
		byName_[name] = entries[start .. $];
	}

	private static string seqString(long seq) @safe
	{
		import std.conv : to;

		return to!string(seq);
	}
}

/// A webhook subscription's stored identity and config. The runtime upserts this
/// idempotently on the key `(principal, url, name, arguments)`; the `id` is a
/// deterministic hash of that key. Ephemeral delivery state (retry queue,
/// in-flight ack positions) is NOT here — it lives in the runtime.
struct WebhookSubscription
{
	string id; /// derived routing handle (hash of the subscription key)
	string principal; /// authenticated subject that owns the subscription
	string name; /// event type
	Json arguments = Json.emptyObject; /// subscription arguments (part of the key)
	string url; /// https callback URL (part of the key)
	string secret; /// current Standard Webhooks `whsec_` secret
	string previousSecret; /// prior secret during rotation grace ("" if none)
	long previousSecretGraceUntilMs; /// rotation grace deadline (0 if none)
	Nullable!string cursor; /// last safe-to-persist watermark the server computed
	bool noExpiry; /// true => never lapses (server-managed lifetime)
	long expiresAtMs; /// expiry (ms since epoch) when !noExpiry
	bool active = true; /// false => delivery suspended after repeated failures
	bool verified; /// endpoint verification satisfied for (principal, url)
	long lastDeliveryAtMs; /// last successful delivery (0 = never)
	int lastErrorCat = -1; /// last DeliveryErrorCategory (-1 = none)
	long failedSinceMs; /// when the current failure streak began (0 = healthy)
	int failedAttempts; /// consecutive failed deliveries since the last success (drives suspension)

	/// Whether the subscription has lapsed at `nowMs` (always false for no-expiry).
	bool isExpired(long nowMs) const @safe pure nothrow
	{
		return !noExpiry && nowMs >= expiresAtMs;
	}

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["id"] = id;
		j["principal"] = principal;
		j["name"] = name;
		j["arguments"] = arguments.type == Json.Type.object ? arguments : Json.emptyObject;
		j["url"] = url;
		j["secret"] = secret;
		if (previousSecret.length)
		{
			j["previousSecret"] = previousSecret;
			j["previousSecretGraceUntilMs"] = previousSecretGraceUntilMs;
		}
		if (!cursor.isNull)
			j["cursor"] = cursor.get;
		j["noExpiry"] = noExpiry;
		j["expiresAtMs"] = expiresAtMs;
		j["active"] = active;
		j["verified"] = verified;
		if (lastDeliveryAtMs)
			j["lastDeliveryAtMs"] = lastDeliveryAtMs;
		if (lastErrorCat >= 0)
			j["lastErrorCat"] = lastErrorCat;
		if (failedSinceMs)
			j["failedSinceMs"] = failedSinceMs;
		if (failedAttempts)
			j["failedAttempts"] = failedAttempts;
		return j;
	}

	static WebhookSubscription fromJson(Json j) @safe
	{
		WebhookSubscription s;
		s.id = j.getOr("id", "");
		s.principal = j.getOr("principal", "");
		s.name = j.getOr("name", "");
		if ("arguments" in j && j["arguments"].type == Json.Type.object)
			s.arguments = j["arguments"];
		s.url = j.getOr("url", "");
		s.secret = j.getOr("secret", "");
		s.previousSecret = j.getOr("previousSecret", "");
		s.previousSecretGraceUntilMs = j.getOr("previousSecretGraceUntilMs", 0L);
		if ("cursor" in j && j["cursor"].type == Json.Type.string)
			s.cursor = j["cursor"].get!string;
		s.noExpiry = j.getOr("noExpiry", false);
		s.expiresAtMs = j.getOr("expiresAtMs", 0L);
		s.active = j.getOr("active", true);
		s.verified = j.getOr("verified", false);
		s.lastDeliveryAtMs = j.getOr("lastDeliveryAtMs", 0L);
		s.lastErrorCat = j.getOr("lastErrorCat", -1);
		s.failedSinceMs = j.getOr("failedSinceMs", 0L);
		s.failedAttempts = j.getOr("failedAttempts", 0);
		return s;
	}
}

/// Storage for webhook subscriptions, keyed by derived `id`. A server granting
/// short TTLs can keep these purely in memory (the default); one granting long or
/// no-expiry TTLs supplies a durable implementation, since a no-expiry
/// subscription must survive restarts (its client never refreshes).
interface WebhookSubscriptionStore
{
	/// Insert or replace the subscription identified by `sub.id`.
	void put(WebhookSubscription sub) @safe;

	/// The subscription with `id`, or null if unknown.
	Nullable!WebhookSubscription get(string id) @safe;

	/// Drop the subscription identified by `id`. A no-op if unknown.
	void remove(string id) @safe;

	/// Every stored subscription. The runtime applies expiry and name filtering;
	/// the store need not.
	WebhookSubscription[] all() @safe;
}

/// In-memory `WebhookSubscriptionStore` backed by an associative array. The
/// default store; records are serialized to JSON and re-parsed on read so a
/// returned record never aliases stored state. Lost on restart — which is the
/// deliberate trade for short-TTL soft state (clients re-subscribe on refresh).
final class InMemoryWebhookSubscriptionStore : WebhookSubscriptionStore
{
	private Json[string] records_;

	void put(WebhookSubscription sub) @safe
	{
		records_[sub.id] = sub.toJson();
	}

	Nullable!WebhookSubscription get(string id) @safe
	{
		if (auto p = id in records_)
			return nullable(WebhookSubscription.fromJson(*p));
		return Nullable!WebhookSubscription.init;
	}

	void remove(string id) @safe
	{
		records_.remove(id);
	}

	WebhookSubscription[] all() @safe
	{
		WebhookSubscription[] result;
		foreach (_, v; records_)
			result ~= WebhookSubscription.fromJson(v);
		return result;
	}
}

/// One pending webhook delivery: the event to deliver to one subscription, plus
/// the attempt count. `publish` enqueues these; a worker leases, delivers, and
/// acks them. Decoupling publish from delivery is what lets webhook work across
/// nodes — a shared, durable `DeliveryQueue` lets any node deliver, and a crashed
/// node's leased-but-unacked jobs are re-leased by another.
struct Delivery
{
	string jobId; /// unique (subscription id + event id)
	string subscriptionId;
	EventOccurrence occ; /// the event to deliver (carries its watermark cursor)
	int attempt; /// attempts already made

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["jobId"] = jobId;
		j["subscriptionId"] = subscriptionId;
		j["occ"] = occ.toJson();
		j["attempt"] = attempt;
		return j;
	}

	static Delivery fromJson(Json j) @safe
	{
		Delivery d;
		d.jobId = j.getOr("jobId", "");
		d.subscriptionId = j.getOr("subscriptionId", "");
		if ("occ" in j)
			d.occ = EventOccurrence.fromJson(j["occ"]);
		d.attempt = j.getOr("attempt", 0);
		return d;
	}
}

/// The webhook delivery outbox: `publish` enqueues a `Delivery` per matching
/// subscription; a worker `lease`s ready jobs (claiming them for `leaseMs` so a
/// second worker won't double-deliver), delivers, then `ack`s. A job whose lease
/// expires (its worker died) becomes leasable again — the crash-recovery path.
/// The in-memory default is single-node; a shared/durable implementation
/// (Redis/SQS/DB) makes delivery node-agnostic. Mirrors the `TaskStore` seam.
interface DeliveryQueue
{
	/// Add a job to the queue (initially unleased).
	void enqueue(Delivery job) @safe;

	/// Claim and return the jobs that are ready at `nowMs` — unleased, or leased
	/// with an expired lease — marking each leased until `nowMs + leaseMs`.
	Delivery[] lease(long nowMs, long leaseMs) @safe;

	/// Persist a job's `attempt` count and extend its lease to `leasedUntilMs`, so
	/// the retry count survives a re-lease (crash recovery bounds total attempts)
	/// and a long retry loop keeps renewing its claim. A no-op for an acked job.
	void touch(string jobId, int attempt, long leasedUntilMs) @safe;

	/// Extend a leased job's claim to `leasedUntilMs` without changing its attempt
	/// count — called around each in-loop attempt so a slow job never lets its lease
	/// expire (which would let a concurrent drain re-lease and double-deliver it).
	void renew(string jobId, long leasedUntilMs) @safe;

	/// Remove a delivered (or abandoned) job.
	void ack(string jobId) @safe;
}

/// In-memory `DeliveryQueue`. The default; jobs are lost on restart, which is the
/// deliberate trade for short-TTL soft state (clients re-subscribe and replay
/// from their cursor). Records are serialized/re-parsed so a leased job never
/// aliases stored state.
final class InMemoryDeliveryQueue : DeliveryQueue
{
	private struct Entry
	{
		Json job;
		long leasedUntilMs;
	}

	private Entry[string] entries_;

	void enqueue(Delivery job) @safe
	{
		entries_[job.jobId] = Entry(job.toJson(), 0);
	}

	Delivery[] lease(long nowMs, long leaseMs) @safe
	{
		Delivery[] result;
		foreach (id, ref e; entries_)
			if (e.leasedUntilMs <= nowMs)
			{
				e.leasedUntilMs = nowMs + leaseMs;
				result ~= Delivery.fromJson(e.job);
			}
		return result;
	}

	void touch(string jobId, int attempt, long leasedUntilMs) @safe
	{
		if (auto e = jobId in entries_)
		{
			e.job["attempt"] = attempt;
			e.leasedUntilMs = leasedUntilMs;
		}
	}

	void renew(string jobId, long leasedUntilMs) @safe
	{
		if (auto e = jobId in entries_)
			e.leasedUntilMs = leasedUntilMs;
	}

	void ack(string jobId) @safe
	{
		entries_.remove(jobId);
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

unittest  // EmitBuffer bootstrap returns no events and the head cursor
{
	auto buf = new EmitBuffer();
	auto r = buf.readSince("x", Nullable!string.init, Nullable!long.init, Nullable!long.init);
	assert(r.events.length == 0 && !r.cursor.isNull);
}

unittest  // EmitBuffer delivers events appended after the cursor
{
	auto buf = new EmitBuffer();
	const start = buf.headCursor();
	buf.append("incident.created", EventOccurrence("a", "incident.created", "t1"));
	buf.append("incident.created", EventOccurrence("b", "incident.created", "t2"));
	auto r = buf.readSince("incident.created", nullable(start),
			Nullable!long.init, Nullable!long.init);
	assert(r.events.length == 2);
	assert(r.events[0].eventId == "a" && r.events[1].eventId == "b");
	// the new cursor is the last event's cursor
	assert(r.cursor.get == r.events[1].cursor.get);
}

unittest  // EmitBuffer assigns each event a monotonically increasing cursor
{
	auto buf = new EmitBuffer();
	auto c1 = buf.append("n", EventOccurrence("a", "n", "t"));
	auto c2 = buf.append("n", EventOccurrence("b", "n", "t"));
	import std.conv : to;

	assert(to!long(c2) > to!long(c1));
}

unittest  // EmitBuffer caps a batch with maxEvents and sets hasMore
{
	auto buf = new EmitBuffer();
	const start = buf.headCursor();
	foreach (i; 0 .. 5)
		buf.append("n", EventOccurrence("e", "n", "t"));
	auto r = buf.readSince("n", nullable(start), Nullable!long.init, nullable(2L));
	assert(r.events.length == 2 && r.hasMore);
}

unittest  // EmitBuffer treats maxEvents==0 as no cap, keeping the window intact
{
	auto buf = new EmitBuffer();
	const start = buf.headCursor();
	foreach (i; 0 .. 3)
		buf.append("n", EventOccurrence("e", "n", "t"));
	// A zero cap must not empty the batch while advancing the cursor past the
	// retained events (which would silently lose the window).
	auto r = buf.readSince("n", nullable(start), Nullable!long.init, nullable(0L));
	assert(r.events.length == 3 && !r.hasMore);
	assert(r.cursor.get == r.events[$ - 1].cursor.get);
}

unittest  // EmitBuffer maxEvents==0 followed by a re-poll loses no events
{
	auto buf = new EmitBuffer();
	const start = buf.headCursor();
	foreach (i; 0 .. 2)
		buf.append("n", EventOccurrence("e", "n", "t"));
	auto r = buf.readSince("n", nullable(start), Nullable!long.init, nullable(0L));
	// Re-polling from the returned cursor sees nothing new (all were delivered),
	// rather than the cursor having jumped to head and skipped the two events.
	auto again = buf.readSince("n", nullable(r.cursor.get), Nullable!long.init, nullable(0L));
	assert(again.events.length == 0);
}

unittest  // EmitBuffer flags truncation for an unparseable cursor and resets to head
{
	auto buf = new EmitBuffer();
	buf.append("n", EventOccurrence("a", "n", "t"));
	auto r = buf.readSince("n", nullable("not-a-seq"), Nullable!long.init, Nullable!long.init);
	assert(r.truncated && r.events.length == 0);
}

unittest  // EmitBuffer flags truncation for a cursor ahead of head (post-restart)
{
	auto buf = new EmitBuffer();
	buf.append("n", EventOccurrence("a", "n", "t")); // seq 1, head = "1"
	// A cursor beyond the current head — e.g. a client resuming a pre-restart
	// position the reset counter has not yet reached. It is unsatisfiable, so the
	// buffer resets to head and signals a gap rather than reporting up-to-date.
	auto r = buf.readSince("n", nullable("999"), Nullable!long.init, Nullable!long.init);
	assert(r.truncated && r.events.length == 0);
	assert(r.cursor.get == buf.headCursor());
}

unittest  // EmitBuffer maxAgeMs floor skips too-old events and flags truncation
{
	long fakeNow = 1_000_000;
	auto buf = new EmitBuffer();
	buf.nowMs = () @safe => fakeNow;
	const start = buf.headCursor();
	buf.append("n", EventOccurrence("old", "n", "t")); // at 1_000_000
	fakeNow = 1_500_000; // 500s later
	buf.append("n", EventOccurrence("new", "n", "t"));
	// floor of 300_000 ms (300s) excludes the first event
	auto r = buf.readSince("n", nullable(start), nullable(300_000L), Nullable!long.init);
	assert(r.truncated);
	assert(r.events.length == 1 && r.events[0].eventId == "new");
}

unittest  // EmitBuffer evicts by maxEvents so the buffer stays bounded
{
	auto buf = new EmitBuffer(EmitBufferOptions(10.minutes, 3));
	const start = buf.headCursor();
	foreach (i; 0 .. 6)
		buf.append("n", EventOccurrence("e", "n", "t"));
	auto r = buf.readSince("n", nullable(start), Nullable!long.init, Nullable!long.init);
	// only the last 3 are retained; the earlier ones were evicted -> truncated
	assert(r.events.length == 3 && r.truncated);
}

unittest  // WebhookSubscription round-trips through JSON
{
	WebhookSubscription s;
	s.id = "sub_a3f1";
	s.principal = "user-1";
	s.name = "incident.created";
	s.arguments = Json(["severity": Json("P1")]);
	s.url = "https://proxy/hooks";
	s.secret = "whsec_abc";
	s.cursor = "cursor_1";
	s.expiresAtMs = 5_000;
	s.verified = true;
	auto back = WebhookSubscription.fromJson(s.toJson());
	assert(back.id == "sub_a3f1" && back.principal == "user-1");
	assert(back.arguments["severity"].get!string == "P1");
	assert(back.secret == "whsec_abc" && back.cursor.get == "cursor_1");
	assert(back.expiresAtMs == 5_000 && back.verified);
}

unittest  // WebhookSubscription.isExpired honours noExpiry
{
	WebhookSubscription s;
	s.expiresAtMs = 1000;
	assert(!s.isExpired(999) && s.isExpired(1000) && s.isExpired(2000));
	s.noExpiry = true;
	assert(!s.isExpired(long.max));
}

unittest  // WebhookSubscription persists previousSecret only during rotation grace
{
	WebhookSubscription s;
	s.id = "s";
	s.secret = "whsec_new";
	auto j = s.toJson();
	assert("previousSecret" !in j);
	s.previousSecret = "whsec_old";
	s.previousSecretGraceUntilMs = 9999;
	auto j2 = s.toJson();
	assert(j2["previousSecret"].get!string == "whsec_old");
	auto back = WebhookSubscription.fromJson(j2);
	assert(back.previousSecret == "whsec_old" && back.previousSecretGraceUntilMs == 9999);
}

unittest  // InMemoryWebhookSubscriptionStore put/get/remove/all
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription s;
	s.id = "id1";
	s.name = "n";
	store.put(s);
	assert(!store.get("id1").isNull && store.get("id1").get.name == "n");
	assert(store.get("missing").isNull);
	assert(store.all().length == 1);
	store.remove("id1");
	assert(store.get("id1").isNull && store.all().length == 0);
}

unittest  // InMemoryWebhookSubscriptionStore returns isolated copies (no aliasing)
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription s;
	s.id = "id1";
	s.secret = "whsec_orig";
	store.put(s);
	auto got = store.get("id1").get;
	got.secret = "whsec_mutated";
	// the stored record is unaffected by mutating the returned copy
	assert(store.get("id1").get.secret == "whsec_orig");
}
