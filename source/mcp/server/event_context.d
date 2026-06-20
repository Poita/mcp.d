/// The execution context handed to an event type's check function and lifecycle
/// hooks, plus the `EventResult` such a check returns. Mirrors the role
/// `TaskContext` plays for `@task`: the SDK injects it as a trailing parameter
/// (omitted from the input schema), carrying the incoming cursor, the raw
/// subscription arguments, the authenticated principal, and the replay floor.
module mcp.server.event_context;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.events : EventOccurrence;

@safe:

/// What an event check function returns: the matching events produced since the
/// supplied cursor, the new cursor position after them, and gap/backlog flags.
///
/// `cursor` is the position *after* the returned events — the value the client
/// persists and passes back next time. Leave it null for an event type that does
/// not support replay; the SDK then always polls with `null`. `truncated` signals
/// the server resumed from later than the supplied cursor (events were skipped).
/// `hasMore` indicates more events are immediately available beyond this batch.
struct EventResult
{
	EventOccurrence[] events;
	Nullable!string cursor;
	bool truncated;
	bool hasMore;

	/// A batch with a fresh cursor (the common replayable case).
	static EventResult of(EventOccurrence[] events, string cursor,
			bool truncated = false, bool hasMore = false) @safe
	{
		EventResult r;
		r.events = events;
		r.cursor = cursor;
		r.truncated = truncated;
		r.hasMore = hasMore;
		return r;
	}

	/// An empty batch carrying only the current cursor (a bootstrap or quiet
	/// poll). The server returns no events and advances the client's cursor.
	static EventResult empty(string cursor, bool truncated = false) @safe
	{
		EventResult r;
		r.cursor = cursor;
		r.truncated = truncated;
		return r;
	}

	/// A batch for an event type that does not support replay: events but no
	/// cursor. The client persists nothing and always polls with `null`.
	static EventResult noReplay(EventOccurrence[] events) @safe
	{
		EventResult r;
		r.events = events;
		return r;
	}
}

/// One typed event in a fetch batch: the strongly-typed `payload`, plus an
/// optional `cursor` (this event's position — falls back to the batch cursor),
/// `eventId` (for dedup; auto-generated when empty), and `timestamp` (ISO-8601;
/// stamped to now when empty).
struct Event(P)
{
	P payload;
	string cursor;
	string eventId;
	string timestamp;

	this(P payload, string cursor = null, string eventId = null, string timestamp = null) @safe
	{
		this.payload = payload;
		this.cursor = cursor;
		this.eventId = eventId;
		this.timestamp = timestamp;
	}
}

/// The strongly-typed result of a fetch handler: the events produced since the
/// requested cursor, the new cursor position after them, and gap/backlog flags.
/// Leave `cursor` null for an event type that does not support replay.
struct EventBatch(P)
{
	Event!P[] events;
	Nullable!string cursor;
	bool hasMore;
	bool truncated;

	/// A batch with a fresh cursor (the common replayable case).
	static EventBatch of(Event!P[] events, string cursor, bool hasMore = false,
			bool truncated = false) @safe
	{
		EventBatch b;
		b.events = events;
		b.cursor = cursor;
		b.hasMore = hasMore;
		b.truncated = truncated;
		return b;
	}

	/// An empty batch carrying only the current cursor (a bootstrap or quiet poll).
	static EventBatch empty(string cursor, bool truncated = false) @safe
	{
		EventBatch b;
		b.cursor = cursor;
		b.truncated = truncated;
		return b;
	}

	/// A batch for an event type that does not support replay: events, no cursor.
	static EventBatch noReplay(Event!P[] events) @safe
	{
		EventBatch b;
		b.events = events;
		return b;
	}
}

/// Read-only context passed to a typed fetch handler: the cursor to resume from,
/// the optional replay floor, the result cap, and the authenticated principal.
struct FetchContext
{
	Nullable!string cursor; /// resume position; null = from now
	Nullable!long maxAgeMs; /// replay floor; null = unbounded
	Nullable!long maxEvents; /// batch cap; null = server default
	string principal; /// authenticated subject ("" if unauthenticated)

	/// True when the client passed `cursor: null` (start from now).
	bool isBootstrap() const @safe nothrow
	{
		return cursor.isNull;
	}
}

/// Context passed to a typed subscription lifecycle hook (`onSubscribe`/
/// `onUnsubscribe`). Carries the authenticated principal and the derived
/// subscription id. The hooks fire once per distinct `(principal, name,
/// arguments)` — on the first subscription of any delivery mode, and again when
/// the last one goes away — so the author provisions/tears down an upstream source
/// exactly once: start a live source task in `onSubscribe` (it `publish`es) and
/// stop it in `onUnsubscribe`.
///
/// NODE-LOCAL: "once per distinct key" holds within a single `EventsRuntime`
/// instance — the lifecycle refcount is node-local. Webhook subscriptions are
/// shared across a cluster via the subscription store, so on a multi-node
/// deployment these hooks fire once per node, not once cluster-wide; write them to
/// be idempotent across nodes. A cluster-coherent shared-store refcount is future
/// work.
struct SubContext
{
	string principal;
	string subscriptionId;
}

/// Context injected into an event check function (and emit/lifecycle hooks). It
/// is read-only: it tells the author *what* the SDK is asking about (the cursor
/// to resume from, the subscription's arguments, who asked, and any replay
/// floor), leaving the author to return an `EventResult`.
final class EventContext
{
	private Nullable!string cursor_;
	private Json arguments_;
	private string principal_;
	private Nullable!long maxAgeMs_;

	this(Nullable!string cursor, Json arguments, string principal,
			Nullable!long maxAgeMs = Nullable!long.init) @safe
	{
		cursor_ = cursor;
		arguments_ = (arguments.type == Json.Type.object) ? arguments : Json.emptyObject;
		principal_ = principal;
		maxAgeMs_ = maxAgeMs;
	}

	/// The cursor the client supplied — the position to resume from. Null means
	/// "start from now": return no events and a fresh cursor.
	Nullable!string cursor() const @safe nothrow
	{
		return cursor_;
	}

	/// True when the client passed `cursor: null` (start from now).
	bool isBootstrap() const @safe nothrow
	{
		return cursor_.isNull;
	}

	/// The raw subscription arguments (validated against the type's inputSchema).
	Json arguments() @safe nothrow
	{
		return arguments_;
	}

	/// The authenticated principal that owns the subscription, or "" when the
	/// server is unauthenticated.
	string principal() const @safe nothrow
	{
		return principal_;
	}

	/// The optional replay floor (`maxAgeMs`): do not replay events older than
	/// this many milliseconds. Null when the client did not bound replay.
	Nullable!long maxAgeMs() const @safe nothrow
	{
		return maxAgeMs_;
	}
}

unittest  // EventResult.of carries events + cursor and clears flags by default
{
	auto r = EventResult.of([EventOccurrence("e1", "n", "t")], "c1");
	assert(r.events.length == 1 && r.cursor.get == "c1");
	assert(!r.truncated && !r.hasMore);
}

unittest  // EventResult.empty advances the cursor with no events
{
	auto r = EventResult.empty("c2", true);
	assert(r.events.length == 0 && r.cursor.get == "c2" && r.truncated);
}

unittest  // EventResult.noReplay leaves the cursor null
{
	auto r = EventResult.noReplay([EventOccurrence("e", "n", "t")]);
	assert(r.events.length == 1 && r.cursor.isNull);
}

unittest  // EventContext exposes cursor / bootstrap / arguments / principal
{
	auto ctx = new EventContext(nullable("c0"), Json(["from": Json("a@b.com")]), "user-1");
	assert(!ctx.isBootstrap() && ctx.cursor.get == "c0");
	assert(ctx.arguments["from"].get!string == "a@b.com");
	assert(ctx.principal == "user-1");
	assert(ctx.maxAgeMs.isNull);
}

unittest  // EventContext.isBootstrap is true for a null cursor
{
	auto ctx = new EventContext(Nullable!string.init, Json.emptyObject, "");
	assert(ctx.isBootstrap() && ctx.cursor.isNull);
	assert(ctx.principal.length == 0);
}

unittest  // EventContext normalizes non-object arguments to an empty object
{
	auto ctx = new EventContext(Nullable!string.init, Json("not-an-object"), "p");
	assert(ctx.arguments.type == Json.Type.object && ctx.arguments.length == 0);
}

unittest  // EventContext carries the maxAgeMs replay floor when supplied
{
	auto ctx = new EventContext(nullable("c"), Json.emptyObject, "p", nullable(300_000L));
	assert(ctx.maxAgeMs.get == 300_000);
}
