/// Storage backing the MCP Events extension: an in-memory `EmitBuffer` ring
/// buffer that serves `events/poll` for emit-only event types, the
/// `WebhookSubscriptionStore` that holds webhook subscription identity/config
/// with per-subscription TTLs, and the `DeliveryQueue` outbox that holds pending
/// webhook deliveries with their attempt counts and leases. The stores and queue
/// are the state a server MAY persist or share across nodes; the runtime
/// (`mcp.server.events_runtime`) keeps only node-local bookkeeping derived from
/// them (positions in flight for the watermark, owed gap signals).
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
/// its numeric value. Returns false for a null/unparseable cursor, and for one
/// stamped by another process: sequence numbers restart with each process, so
/// only a cursor carrying this process's epoch names a position in its buffer.
/// Shared so the webhook watermark can compare two cursors using the same
/// encoding the buffer assigns.
bool tryParseSeq(string s, out long seq) @safe nothrow
{
	import std.algorithm : startsWith;
	import std.conv : to;

	const prefix = seqEpoch() ~ ".";
	if (!s.startsWith(prefix))
		return false;
	try
	{
		seq = to!long(s[prefix.length .. $]);
		return true;
	}
	catch (Exception)
		return false;
}

/// The cursor naming sequence number `seq` in this process's emit buffers.
package string seqCursor(long seq) @safe nothrow
{
	import std.conv : to;

	try
		return seqEpoch() ~ "." ~ to!string(seq);
	catch (Exception)
		assert(0);
}

// A random identifier for this process, chosen once and prefixed to every
// sequence cursor so a cursor from before a restart is recognised as foreign.
private string seqEpoch() @trusted nothrow
{
	import std.concurrency : initOnce;

	__gshared string epoch;
	try
		return initOnce!epoch(newSeqEpoch());
	catch (Exception)
		assert(0);
}

private string newSeqEpoch() @safe nothrow
{
	import std.format : format;
	import std.random : unpredictableSeed;

	try
		return format("%016x", unpredictableSeed!ulong);
	catch (Exception)
		assert(0);
}

/// Configuration for the emit ring buffer: how long and how many events to retain
/// per event type before eviction. A zero bound disables that bound.
struct EmitBufferOptions
{
	Duration maxAge = 10.minutes; /// retain events younger than this (zero = no age limit)
	size_t maxEvents = 10_000; /// cap retained events per event type (0 = no count cap)
}

/// A bounded, in-memory ring buffer of emitted events per event type. Backs
/// `events/poll` for emit-only event types (those with no cursor-addressable
/// upstream). The cursor is a sequence number tagged with a per-process epoch:
/// a server restart invalidates all cursors, and a poll with a stale, foreign, or
/// unparseable cursor yields a fresh cursor with `truncated: true`. Events
/// emitted during downtime are not recoverable — matching the upstream's own
/// guarantees for push-only sources.
final class EmitBuffer
{
	private struct Entry
	{
		long seq;
		long atMs;
		EventOccurrence occ;
	}

	private Entry[][string] byName_;
	private long[string] evictedThrough_; // name -> highest sequence evicted for it
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

	/// Forget every event retained for `name` (its type was removed).
	void drop(string name) @safe
	{
		byName_.remove(name);
		evictedThrough_.remove(name);
	}

	/// Evict aged events for every type, including those no longer emitted
	/// (which `append` alone would never revisit).
	void evictExpired() @safe
	{
		foreach (name; byName_.keys)
			evict(name);
	}

	/// The number of events currently retained for `name`.
	size_t retained(string name) @safe
	{
		return byName_.get(name, null).length;
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
		// The furthest position the caller can no longer read: evicted, or
		// skipped by the replay floor.
		long lostThrough = fromSeq;

		// Gap from eviction: an event of this name after the cursor was dropped.
		// Sequence numbers are shared across names, so this is judged against the
		// name's own eviction point rather than the distance to its oldest entry.
		if (evictedThrough_.get(name, 0) > fromSeq)
		{
			truncated = true;
			lostThrough = evictedThrough_[name];
		}

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
				if (e.seq > lostThrough)
					lostThrough = e.seq;
				continue;
			}
			selected ~= e.occ;
		}

		// The cursor to return when the batch is empty: past whatever the caller
		// can no longer read, so the gap is reported once, but not the buffer head —
		// advancing to head would skip retained-but-unselected events next poll.
		string emptyCursor = selected.length ? selected[$ - 1].cursor.get
			: (lostThrough > fromSeq ? seqString(lostThrough) : cursor.get);

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
		size_t start;
		if (opts_.maxAge > Duration.zero)
		{
			const cutoff = nowMs() - opts_.maxAge.total!"msecs";
			while (start < entries.length && entries[start].atMs < cutoff)
				start++;
		}
		if (opts_.maxEvents > 0 && entries.length - start > opts_.maxEvents)
			start = entries.length - opts_.maxEvents;
		if (start > 0)
			evictedThrough_[name] = entries[start - 1].seq;
		byName_[name] = entries[start .. $];
	}

	private static string seqString(long seq) @safe
	{
		return seqCursor(seq);
	}
}

/// A webhook subscription's stored identity and config. The runtime upserts this
/// idempotently on the key `(principal, url, name, arguments)`; the `id` is a
/// deterministic hash of that key. Pending deliveries and their attempt counts
/// are NOT here — they live in the `DeliveryQueue`.
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
	Nullable!string fetchCursor; /// position the poll-driven loop has fetched up to (check-backed types)
	bool noExpiry; /// true => never lapses (server-managed lifetime)
	long expiresAtMs; /// expiry (ms since epoch) when !noExpiry
	bool active = true; /// false => delivery suspended after repeated failures
	bool verified; /// endpoint verification satisfied for (principal, url)
	long lastDeliveryAtMs; /// last successful delivery (0 = never)
	int lastErrorCat = -1; /// last DeliveryErrorCategory (-1 = none)
	long failedSinceMs; /// when the current failure streak began (0 = healthy)
	long windowStartMs; /// start of the current failure-rate sample window
	int windowAttempts; /// delivery attempts in the window
	int windowFailures; /// failed attempts in the window (drives suspension)
	/// Advanced by the store on every write; the optimistic-concurrency token that
	/// lets writers on different fibers or nodes detect a concurrent change
	/// (`WebhookSubscriptionStore.compareAndSwap`) instead of overwriting it.
	ulong revision;

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
		if (!fetchCursor.isNull)
			j["fetchCursor"] = fetchCursor.get;
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
		if (windowAttempts)
		{
			j["windowStartMs"] = windowStartMs;
			j["windowAttempts"] = windowAttempts;
			j["windowFailures"] = windowFailures;
		}
		j["revision"] = revision;
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
		if ("fetchCursor" in j && j["fetchCursor"].type == Json.Type.string)
			s.fetchCursor = j["fetchCursor"].get!string;
		s.noExpiry = j.getOr("noExpiry", false);
		s.expiresAtMs = j.getOr("expiresAtMs", 0L);
		s.active = j.getOr("active", true);
		s.verified = j.getOr("verified", false);
		s.lastDeliveryAtMs = j.getOr("lastDeliveryAtMs", 0L);
		s.lastErrorCat = j.getOr("lastErrorCat", -1);
		s.failedSinceMs = j.getOr("failedSinceMs", 0L);
		s.windowStartMs = j.getOr("windowStartMs", 0L);
		s.windowAttempts = j.getOr("windowAttempts", 0);
		s.windowFailures = j.getOr("windowFailures", 0);
		if ("revision" in j && j["revision"].type == Json.Type.int_)
			s.revision = j["revision"].get!ulong;
		return s;
	}
}

/// Storage for webhook subscriptions, keyed by derived `id`. A server granting
/// short TTLs can keep these purely in memory (the default); one granting long or
/// no-expiry TTLs supplies a durable implementation, since a no-expiry
/// subscription must survive restarts (its client never refreshes).
interface WebhookSubscriptionStore
{
	/// Whether stored subscriptions survive a restart. A no-expiry grant is
	/// permitted only over a durable store: its client never refreshes, so a
	/// subscription lost on restart would silently stop delivering.
	bool durable() @safe;

	/// Insert or replace the subscription identified by `sub.id` unconditionally.
	/// A replaced record's revision is advanced (the stored revision becomes the
	/// old one plus one), so a `compareAndSwap` based on the old record fails.
	/// The runtime uses this to create a subscription; every read-modify-write of
	/// an existing one goes through `compareAndSwap`.
	void put(WebhookSubscription sub) @safe;

	/// Replace the subscription identified by `sub.id` only if its stored
	/// `revision` still equals `expectedRevision`, storing `sub` with
	/// `revision = expectedRevision + 1`. Returns false, changing nothing, when
	/// the subscription is unknown or another writer changed it first; the
	/// runtime then re-reads and retries. A shared store implements this as one
	/// atomic conditional write (e.g. a Redis WATCH/MULTI or a SQL
	/// `UPDATE ... WHERE revision = ?`).
	bool compareAndSwap(WebhookSubscription sub, ulong expectedRevision) @safe;

	/// The subscription with `id`, or null if unknown.
	Nullable!WebhookSubscription get(string id) @safe;

	/// Drop the subscription identified by `id`. A no-op if unknown.
	void remove(string id) @safe;

	/// Every stored subscription. The runtime applies expiry filtering; the store
	/// need not. Used by the periodic sweep and by `terminatePrincipal` across all
	/// event types (revoking a principal's access); per-event paths use `byName`.
	WebhookSubscription[] all() @safe;

	/// Every stored subscription to event type `name`, lapsed or not. Called on
	/// every publish, so a store should answer it from an index on `name` rather
	/// than by scanning.
	WebhookSubscription[] byName(string name) @safe;

	/// How many of `principal`'s subscriptions are live (not lapsed) at `nowMs`,
	/// for the per-principal subscription cap.
	size_t countByPrincipal(string principal, long nowMs) @safe;
}

/// In-memory `WebhookSubscriptionStore` backed by an associative array, indexed
/// by event type name and by principal. The default store; records are
/// deep-copied to JSON on write and back on read, so neither a stored nor a
/// returned record shares `Json` with its caller. Lost on restart — which is the deliberate trade for short-TTL
/// soft state (clients re-subscribe on refresh).
final class InMemoryWebhookSubscriptionStore : WebhookSubscriptionStore
{
	private static struct Record
	{
		Json json;
		string name;
		string principal;
		bool noExpiry;
		long expiresAtMs;
		ulong revision;
	}

	private Record[string] records_;
	private bool[string][string] idsByName_; // name -> ids
	private bool[string][string] idsByPrincipal_; // principal -> ids

	bool durable() @safe
	{
		return false;
	}

	void put(WebhookSubscription sub) @safe
	{
		if (auto p = sub.id in records_)
			sub.revision = p.revision + 1;
		store(sub);
	}

	bool compareAndSwap(WebhookSubscription sub, ulong expectedRevision) @safe
	{
		auto p = sub.id in records_;
		if (p is null || p.revision != expectedRevision)
			return false;
		sub.revision = expectedRevision + 1;
		store(sub);
		return true;
	}

	private void store(WebhookSubscription sub) @safe
	{
		remove(sub.id);
		records_[sub.id] = Record(sub.toJson().clone(), sub.name,
				sub.principal, sub.noExpiry, sub.expiresAtMs, sub.revision);
		idsByName_[sub.name][sub.id] = true;
		idsByPrincipal_[sub.principal][sub.id] = true;
	}

	Nullable!WebhookSubscription get(string id) @safe
	{
		if (auto p = id in records_)
			return nullable(WebhookSubscription.fromJson(p.json.clone()));
		return Nullable!WebhookSubscription.init;
	}

	void remove(string id) @safe
	{
		auto p = id in records_;
		if (p is null)
			return;
		unindex(idsByName_, p.name, id);
		unindex(idsByPrincipal_, p.principal, id);
		records_.remove(id);
	}

	WebhookSubscription[] all() @safe
	{
		WebhookSubscription[] result;
		foreach (_, r; records_)
			result ~= WebhookSubscription.fromJson(r.json.clone());
		return result;
	}

	WebhookSubscription[] byName(string name) @safe
	{
		WebhookSubscription[] result;
		if (auto ids = name in idsByName_)
			foreach (id, _; *ids)
				result ~= WebhookSubscription.fromJson(records_[id].json.clone());
		return result;
	}

	size_t countByPrincipal(string principal, long nowMs) @safe
	{
		size_t n;
		if (auto ids = principal in idsByPrincipal_)
			foreach (id, _; *ids)
			{
				const r = records_[id];
				if (r.noExpiry || nowMs < r.expiresAtMs)
					n++;
			}
		return n;
	}

	private static void unindex(ref bool[string][string] index, string key, string id) @safe
	{
		if (auto ids = key in index)
		{
			(*ids).remove(id);
			if ((*ids).length == 0)
				index.remove(key);
		}
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
	/// A `gap` control envelope rather than an event: `occ.cursor` is the position
	/// the client should persist, `occ.eventId` the envelope's message id.
	bool gap;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["jobId"] = jobId;
		j["subscriptionId"] = subscriptionId;
		j["occ"] = occ.toJson();
		j["attempt"] = attempt;
		if (gap)
			j["gap"] = true;
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
		d.gap = j.getOr("gap", false);
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
	/// Add a job to the queue (initially unleased). A job whose `jobId` is
	/// already queued is left untouched — its payload, attempt count, and lease
	/// stand — and false is returned; true means the job was added.
	bool enqueue(Delivery job) @safe;

	/// Claim and return up to `maxJobs` (0 = no limit) of the jobs that are ready
	/// at `nowMs` — unleased, or leased with an expired lease — oldest first,
	/// marking each leased until `nowMs + leaseMs`. The limit keeps one node from
	/// claiming a whole backlog that other nodes could be delivering. A job is
	/// not ready while an earlier job for the same subscription is still leased:
	/// a subscription's deliveries go out in enqueue order, so one held back (in
	/// flight, or deferred to a retry) is never overtaken by a later one.
	Delivery[] lease(long nowMs, long leaseMs, size_t maxJobs) @safe;

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

	/// Whether `jobId` is still queued (leased or not). A node learns from this
	/// that a job it enqueued was settled by another node's worker.
	bool contains(string jobId) @safe;

	/// Whether any job for `subscriptionId` is still queued (leased or not),
	/// whichever node enqueued it. A node consults this before advancing a
	/// subscription's watermark on a quiet poll, so it never moves past a
	/// delivery another node still has in flight. It runs on every quiet fetch,
	/// so an implementation should answer it from an index on the subscription
	/// rather than by scanning the queue.
	bool hasPendingFor(string subscriptionId) @safe;
}

/// In-memory `DeliveryQueue`. The default; jobs are lost on restart, which is the
/// deliberate trade for short-TTL soft state (clients re-subscribe and replay
/// from their cursor). Jobs are deep-copied on enqueue and on lease, so neither
/// a queued nor a leased job shares `Json` with its caller.
final class InMemoryDeliveryQueue : DeliveryQueue
{
	private struct Entry
	{
		Json job;
		long leasedUntilMs;
		ulong seq; /// enqueue order, so a lease hands jobs out first-in first-out
		string subscriptionId;
	}

	private struct Slot
	{
		string jobId;
		ulong seq;
	}

	// One subscription's jobs in enqueue order. A slot whose job was acked (or
	// re-enqueued under a newer seq) is dead and skipped; dead slots ahead of
	// the first live one are dropped, and the rest compacted away once they
	// outnumber the live ones.
	private struct SubQueue
	{
		Slot[] slots;
		size_t head;
	}

	private Entry[string] entries_;
	private ulong nextSeq_;
	private SubQueue[string] subs_;
	// Queued jobs per subscription, so `hasPendingFor` needs no scan.
	private size_t[string] pendingBySub_;
	// A lease finds nothing ready until `nowMs` reaches `nextReadyMs_`, unless
	// `mayBeReady_` says a job was queued, acked, or left ready since the last
	// lease looked: an idle worker's lease then costs nothing.
	private bool mayBeReady_;
	private long nextReadyMs_ = long.max;
	version (unittest) private size_t scanned_; // queue slots a lease has visited

	bool enqueue(Delivery job) @safe
	{
		if ((job.jobId in entries_) !is null)
			return false;
		const seq = nextSeq_++;
		entries_[job.jobId] = Entry(job.toJson().clone(), 0, seq, job.subscriptionId);
		subs_.require(job.subscriptionId).slots ~= Slot(job.jobId, seq);
		pendingBySub_[job.subscriptionId]++;
		mayBeReady_ = true;
		return true;
	}

	Delivery[] lease(long nowMs, long leaseMs, size_t maxJobs) @safe
	{
		import std.algorithm : min, sort;

		if (!mayBeReady_ && nowMs < nextReadyMs_)
			return null;
		// Each subscription offers its ready prefix: the jobs ahead of its first
		// one still leased, which holds back everything behind it. The oldest
		// offers across subscriptions are taken.
		Slot[] offers;
		long nextReady = long.max;
		bool left;
		foreach (subId, ref q; subs_)
		{
			size_t taken;
			foreach (slot; q.slots[q.head .. $])
			{
				version (unittest)
					scanned_++;
				auto e = slot.jobId in entries_;
				if (e is null || e.seq != slot.seq)
					continue;
				if (e.leasedUntilMs > nowMs)
				{
					nextReady = min(nextReady, e.leasedUntilMs);
					break;
				}
				if (maxJobs > 0 && taken >= maxJobs)
				{
					left = true;
					break;
				}
				offers ~= slot;
				taken++;
			}
		}
		offers.sort!((a, b) => a.seq < b.seq);
		if (maxJobs > 0 && offers.length > maxJobs)
		{
			offers = offers[0 .. maxJobs];
			left = true;
		}
		Delivery[] result;
		result.reserve(offers.length);
		foreach (slot; offers)
		{
			auto e = slot.jobId in entries_;
			e.leasedUntilMs = nowMs + leaseMs;
			result ~= Delivery.fromJson(e.job.clone());
		}
		if (result.length)
			nextReady = min(nextReady, nowMs + leaseMs);
		mayBeReady_ = left;
		nextReadyMs_ = nextReady;
		return result;
	}

	// Drop `subId`'s dead slots ahead of its first live one, compact the rest
	// once dead slots outnumber live ones, and forget a subscription with none.
	private void trim(string subId) @safe
	{
		auto q = subId in subs_;
		if (q is null)
			return;
		const live = pendingBySub_.get(subId, 0);
		if (live == 0)
		{
			subs_.remove(subId);
			return;
		}
		while (q.head < q.slots.length && !isLive(q.slots[q.head]))
			q.head++;
		if (q.slots.length - q.head < 2 * live + 16)
			return;
		Slot[] kept;
		kept.reserve(live);
		foreach (slot; q.slots[q.head .. $])
			if (isLive(slot))
				kept ~= slot;
		q.slots = kept;
		q.head = 0;
	}

	private bool isLive(Slot slot) @safe
	{
		auto e = slot.jobId in entries_;
		return e !is null && e.seq == slot.seq;
	}

	// A claim moved to `leasedUntilMs` may make its job ready sooner.
	private void noteLease(long leasedUntilMs) @safe
	{
		if (leasedUntilMs < nextReadyMs_)
			nextReadyMs_ = leasedUntilMs;
	}

	void touch(string jobId, int attempt, long leasedUntilMs) @safe
	{
		if (auto e = jobId in entries_)
		{
			e.job["attempt"] = attempt;
			e.leasedUntilMs = leasedUntilMs;
			noteLease(leasedUntilMs);
		}
	}

	void renew(string jobId, long leasedUntilMs) @safe
	{
		if (auto e = jobId in entries_)
		{
			e.leasedUntilMs = leasedUntilMs;
			noteLease(leasedUntilMs);
		}
	}

	void ack(string jobId) @safe
	{
		auto e = jobId in entries_;
		if (e is null)
			return;
		const subId = e.subscriptionId;
		entries_.remove(jobId);
		if (auto n = subId in pendingBySub_)
			if (--*n == 0)
				pendingBySub_.remove(subId);
		trim(subId);
		mayBeReady_ = true;
	}

	bool contains(string jobId) @safe
	{
		return (jobId in entries_) !is null;
	}

	bool hasPendingFor(string subscriptionId) @safe
	{
		return (subscriptionId in pendingBySub_) !is null;
	}
}

unittest  // a lease with nothing ready does not walk the queued jobs
{
	import std.conv : to;

	auto q = new InMemoryDeliveryQueue();
	foreach (i; 0 .. 1000)
		q.enqueue(Delivery("s1/e" ~ i.to!string, "s1", EventOccurrence("e", "n", "t"), 0));
	assert(q.lease(0, 1000, 1).length == 1);
	q.scanned_ = 0;
	assert(q.lease(10, 1000, 1).length == 0);
	assert(q.scanned_ <= 1);
}

unittest  // a lease hands out jobs oldest first across subscriptions, holding back behind a leased one
{
	auto q = new InMemoryDeliveryQueue();
	q.enqueue(Delivery("a/1", "a", EventOccurrence("1", "n", "t"), 0));
	q.enqueue(Delivery("b/1", "b", EventOccurrence("1", "n", "t"), 0));
	q.enqueue(Delivery("a/2", "a", EventOccurrence("2", "n", "t"), 0));
	q.enqueue(Delivery("b/2", "b", EventOccurrence("2", "n", "t"), 0));
	auto first = q.lease(0, 1000, 3);
	assert(first.length == 3);
	assert(first[0].jobId == "a/1" && first[1].jobId == "b/1" && first[2].jobId == "a/2");
	q.ack("b/1");
	auto second = q.lease(10, 1000, 0);
	assert(second.length == 1 && second[0].jobId == "b/2");
	assert(q.lease(20, 1000, 0).length == 0);
	q.renew("a/1", 50); // a/1's claim lapses before a/2's
	auto third = q.lease(60, 1000, 0);
	assert(third.length == 1 && third[0].jobId == "a/1");
}

unittest  // the in-memory delivery queue reports whether a subscription has jobs queued
{
	auto q = new InMemoryDeliveryQueue();
	assert(!q.hasPendingFor("s1"));
	q.enqueue(Delivery("s1/e1", "s1", EventOccurrence("e1", "n", "t"), 0));
	assert(q.hasPendingFor("s1") && !q.hasPendingFor("s2"));
	q.lease(0, 1000, 0);
	assert(q.hasPendingFor("s1")); // a leased job is still pending
	q.ack("s1/e1");
	assert(!q.hasPendingFor("s1"));
}

unittest  // the in-memory delivery queue keeps a subscription pending until its last job is acked
{
	auto q = new InMemoryDeliveryQueue();
	q.enqueue(Delivery("s1/e1", "s1", EventOccurrence("e1", "n", "t"), 0));
	q.enqueue(Delivery("s1/e2", "s1", EventOccurrence("e2", "n", "t"), 0));
	assert(!q.enqueue(Delivery("s1/e2", "s1", EventOccurrence("e2", "n", "t"), 0)));
	q.ack("s1/e1");
	assert(q.hasPendingFor("s1"));
	q.ack("s1/e1"); // acking twice does not drop another job's count
	assert(q.hasPendingFor("s1"));
	q.ack("s1/e2");
	assert(!q.hasPendingFor("s1"));
}

unittest  // the in-memory subscription store's compareAndSwap applies only on the expected revision
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription sub;
	sub.id = "s";
	sub.name = "n";
	store.put(sub);
	auto read = store.get("s").get;
	read.verified = true;
	assert(store.compareAndSwap(read, read.revision));
	assert(store.get("s").get.verified);
	assert(store.get("s").get.revision == read.revision + 1);
	// A second writer holding the old revision loses.
	read.cursor = "stale";
	assert(!store.compareAndSwap(read, read.revision));
	assert(store.get("s").get.cursor.isNull);
}

unittest  // the in-memory subscription store's compareAndSwap fails for an unknown subscription
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription sub;
	sub.id = "missing";
	assert(!store.compareAndSwap(sub, 0));
	assert(store.get("missing").isNull);
}

unittest  // an unconditional put advances the revision, so an older compareAndSwap fails
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription sub;
	sub.id = "s";
	store.put(sub);
	auto read = store.get("s").get;
	store.put(read);
	assert(!store.compareAndSwap(read, read.revision));
}

unittest  // the in-memory subscription store shares no Json with its callers
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription sub;
	sub.id = "s";
	sub.name = "n";
	sub.arguments = Json(["channel": Json("general")]);
	store.put(sub);
	sub.arguments["channel"] = "mutated";
	auto got = store.get("s").get;
	assert(got.arguments["channel"].get!string == "general");
	got.arguments["channel"] = "mutated";
	assert(store.get("s").get.arguments["channel"].get!string == "general");
	store.byName("n")[0].arguments["channel"] = "mutated";
	store.all()[0].arguments["channel"] = "mutated";
	assert(store.get("s").get.arguments["channel"].get!string == "general");
}

unittest  // the in-memory delivery queue shares no Json with its callers
{
	auto q = new InMemoryDeliveryQueue();
	auto occ = EventOccurrence("a", "n", "t");
	occ.data = Json(["k": Json("v")]);
	q.enqueue(Delivery("j", "s", occ, 0));
	occ.data["k"] = "mutated";
	auto leased = q.lease(0, 1000, 0);
	assert(leased[0].occ.data["k"].get!string == "v");
	leased[0].occ.data["k"] = "mutated";
	assert(q.lease(2000, 1000, 0)[0].occ.data["k"].get!string == "v");
}

unittest  // the in-memory delivery queue reports a job queued until it is acked
{
	auto q = new InMemoryDeliveryQueue();
	q.enqueue(Delivery("j", "s", EventOccurrence("a", "n", "t"), 0));
	assert(q.contains("j") && !q.contains("other"));
	q.lease(0, 1000, 0);
	assert(q.contains("j"));
	q.ack("j");
	assert(!q.contains("j"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

unittest  // the in-memory delivery queue leases ready jobs in enqueue order
{
	auto q = new InMemoryDeliveryQueue();
	foreach (id; ["c", "a", "b"])
		q.enqueue(Delivery(id, "s", EventOccurrence(id, "n", "t"), 0));
	auto leased = q.lease(0, 1000, 0);
	assert(leased.length == 3);
	assert(leased[0].jobId == "c" && leased[1].jobId == "a" && leased[2].jobId == "b");
}

unittest  // the in-memory delivery queue holds a subscription's jobs behind an earlier leased one
{
	auto q = new InMemoryDeliveryQueue();
	foreach (id; ["a1", "a2", "a3"])
		q.enqueue(Delivery(id, "a", EventOccurrence(id, "n", "t"), 0));
	q.enqueue(Delivery("b1", "b", EventOccurrence("b1", "n", "t"), 0));
	auto first = q.lease(0, 1000, 1);
	assert(first.length == 1 && first[0].jobId == "a1");
	auto next = q.lease(0, 1000, 0);
	assert(next.length == 1 && next[0].jobId == "b1"); // a2, a3 wait behind a1
	q.ack("a1");
	auto rest = q.lease(0, 1000, 0);
	assert(rest.length == 2 && rest[0].jobId == "a2" && rest[1].jobId == "a3");
}

unittest  // the in-memory delivery queue leases at most maxJobs, oldest first
{
	auto q = new InMemoryDeliveryQueue();
	foreach (id; ["c", "a", "b", "d"])
		q.enqueue(Delivery(id, "s" ~ id, EventOccurrence(id, "n", "t"), 0));
	auto first = q.lease(0, 1000, 2);
	assert(first.length == 2 && first[0].jobId == "c" && first[1].jobId == "a");
	auto rest = q.lease(0, 1000, 2);
	assert(rest.length == 2 && rest[0].jobId == "b" && rest[1].jobId == "d");
	assert(q.lease(0, 1000, 2).length == 0);
}

unittest  // a job acked or re-leased keeps the remaining jobs in enqueue order
{
	auto q = new InMemoryDeliveryQueue();
	foreach (id; ["a", "b", "c"])
		q.enqueue(Delivery(id, "s", EventOccurrence(id, "n", "t"), 0));
	assert(q.lease(0, 1000, 1)[0].jobId == "a");
	q.ack("a");
	q.enqueue(Delivery("a", "s", EventOccurrence("a", "n", "t"), 0)); // re-enqueued: now newest
	auto all = q.lease(0, 1000, 0);
	assert(all.length == 3);
	assert(all[0].jobId == "b" && all[1].jobId == "c" && all[2].jobId == "a");
}

unittest  // enqueueing a job id already queued neither replaces it nor releases its lease
{
	auto q = new InMemoryDeliveryQueue();
	assert(q.enqueue(Delivery("j", "s", EventOccurrence("a", "n", "t"), 0)));
	assert(q.lease(0, 1000, 0).length == 1);
	assert(!q.enqueue(Delivery("j", "s", EventOccurrence("a", "n", "t"), 0)));
	assert(q.lease(10, 1000, 0).length == 0); // still leased by the first claim
}

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
	long s1, s2;
	assert(tryParseSeq(c1, s1) && tryParseSeq(c2, s2));
	assert(s2 > s1);
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

unittest  // EmitBuffer flags truncation for a cursor ahead of head
{
	auto buf = new EmitBuffer();
	buf.append("n", EventOccurrence("a", "n", "t"));
	// A cursor beyond the current head, e.g. a forged future position. It is
	// unsatisfiable, so the buffer resets to head and signals a gap rather than
	// reporting up-to-date.
	auto r = buf.readSince("n", nullable(seqCursor(999)),
			Nullable!long.init, Nullable!long.init);
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

unittest  // EmitBuffer maxEvents==0 retains events without a count cap
{
	auto buf = new EmitBuffer(EmitBufferOptions(10.minutes, 0));
	const start = buf.headCursor();
	foreach (i; 0 .. 3)
		buf.append("n", EventOccurrence("e", "n", "t"));
	assert(buf.retained("n") == 3);
	auto r = buf.readSince("n", nullable(start), Nullable!long.init, Nullable!long.init);
	assert(r.events.length == 3 && !r.truncated);
}

unittest  // EmitBuffer maxAge==0 retains events without an age limit
{
	long now = 1_000_000;
	auto buf = new EmitBuffer(EmitBufferOptions(Duration.zero, 100));
	buf.nowMs = () @safe => now;
	buf.append("n", EventOccurrence("e", "n", "t"));
	now += 24 * 60 * 60 * 1000;
	buf.evictExpired();
	assert(buf.retained("n") == 1);
}

unittest  // events of other names between two of one name are not reported as a gap
{
	auto buf = new EmitBuffer();
	const c1 = buf.append("a", EventOccurrence("a1", "a", "t"));
	buf.append("b", EventOccurrence("b1", "b", "t"));
	buf.append("b", EventOccurrence("b2", "b", "t"));
	buf.append("a", EventOccurrence("a2", "a", "t"));
	auto r = buf.readSince("a", nullable(c1), Nullable!long.init, Nullable!long.init);
	assert(r.events.length == 1 && r.events[0].eventId == "a2");
	assert(!r.truncated);
}

unittest  // eviction of one name's events is a gap only for cursors before the evicted ones
{
	auto buf = new EmitBuffer(EmitBufferOptions(10.minutes, 1));
	const start = buf.headCursor();
	const c1 = buf.append("a", EventOccurrence("a1", "a", "t"));
	buf.append("b", EventOccurrence("b1", "b", "t"));
	buf.append("a", EventOccurrence("a2", "a", "t")); // evicts a1
	auto fromStart = buf.readSince("a", nullable(start), Nullable!long.init, Nullable!long.init);
	assert(fromStart.truncated && fromStart.events.length == 1);
	auto fromC1 = buf.readSince("a", nullable(c1), Nullable!long.init, Nullable!long.init);
	assert(!fromC1.truncated && fromC1.events.length == 1);
	// the other name is unaffected by a's eviction
	auto b = buf.readSince("b", nullable(start), Nullable!long.init, Nullable!long.init);
	assert(!b.truncated && b.events.length == 1);
}

unittest  // age eviction followed by other names' events still reports a gap only when one exists
{
	long now = 1_000_000;
	auto buf = new EmitBuffer(EmitBufferOptions(1.minutes, 100));
	buf.nowMs = () @safe => now;
	const c1 = buf.append("a", EventOccurrence("a1", "a", "t"));
	now += 2 * 60 * 1000;
	buf.append("b", EventOccurrence("b1", "b", "t"));
	buf.append("a", EventOccurrence("a2", "a", "t")); // a1 aged out, but c1 already saw it
	auto r = buf.readSince("a", nullable(c1), Nullable!long.init, Nullable!long.init);
	assert(!r.truncated && r.events.length == 1);
}

unittest  // a cursor issued by another process is truncated, not read as a position in this one
{
	auto buf = new EmitBuffer();
	foreach (id; ["a", "b", "c"])
		buf.append("n", EventOccurrence(id, "n", "t"));
	// A position a previous process issued, which this process's sequence has
	// since passed: it must not silently skip "b" and "c".
	auto r = buf.readSince("n", nullable("1"), Nullable!long.init, Nullable!long.init);
	assert(r.truncated && r.events.length == 0);
	assert(r.cursor.get == buf.headCursor());
}

unittest  // a truncated read that selects nothing moves the cursor past the evicted events
{
	long now = 1_000_000;
	auto buf = new EmitBuffer(EmitBufferOptions(1.minutes, 100));
	buf.nowMs = () @safe => now;
	const start = buf.headCursor();
	buf.append("a", EventOccurrence("a1", "a", "t"));
	now += 2 * 60 * 1000;
	buf.evictExpired();
	auto r = buf.readSince("a", nullable(start), Nullable!long.init, Nullable!long.init);
	assert(r.truncated && r.events.length == 0);
	auto again = buf.readSince("a", r.cursor, Nullable!long.init, Nullable!long.init);
	assert(!again.truncated);
}

unittest  // a truncated read whose floor skips every event moves the cursor past them
{
	long now = 1_000_000;
	auto buf = new EmitBuffer();
	buf.nowMs = () @safe => now;
	const start = buf.headCursor();
	buf.append("a", EventOccurrence("a1", "a", "t"));
	now += 500_000;
	auto r = buf.readSince("a", nullable(start), nullable(300_000L), Nullable!long.init);
	assert(r.truncated && r.events.length == 0);
	auto again = buf.readSince("a", r.cursor, nullable(300_000L), Nullable!long.init);
	assert(!again.truncated);
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

unittest  // InMemoryWebhookSubscriptionStore.byName returns only that event type's subscriptions
{
	auto store = new InMemoryWebhookSubscriptionStore();
	foreach (id, name; ["a": "x", "b": "y", "c": "x"])
	{
		WebhookSubscription s;
		s.id = id;
		s.name = name;
		store.put(s);
	}
	assert(store.byName("x").length == 2 && store.byName("y").length == 1);
	assert(store.byName("z").length == 0);
	store.remove("a");
	assert(store.byName("x").length == 1 && store.byName("x")[0].id == "c");
}

unittest  // InMemoryWebhookSubscriptionStore.countByPrincipal counts only live subscriptions
{
	auto store = new InMemoryWebhookSubscriptionStore();
	WebhookSubscription live, lapsed, forever, other;
	live.id = "live";
	live.principal = "p";
	live.expiresAtMs = 2_000;
	lapsed.id = "lapsed";
	lapsed.principal = "p";
	lapsed.expiresAtMs = 500;
	forever.id = "forever";
	forever.principal = "p";
	forever.noExpiry = true;
	other.id = "other";
	other.principal = "q";
	other.expiresAtMs = 2_000;
	foreach (s; [live, lapsed, forever, other])
		store.put(s);
	assert(store.countByPrincipal("p", 1_000) == 2);
	assert(store.countByPrincipal("q", 1_000) == 1);
	assert(store.countByPrincipal("nobody", 1_000) == 0);
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
