/**
 * Client-side response cache for the draft `CacheableResult` freshness hints.
 *
 * The six read-only MCP operations that carry a server TTL hint — `tools/list`,
 * `prompts/list`, `resources/list`, `resources/templates/list`,
 * `resources/read`, and `server/discover` — can have their results held in a
 * `CacheStore` so a repeat call within the hint's lifetime is served locally
 * instead of round-tripping to the server. `McpClient` owns the freshness
 * decision (it stamps an absolute `expiresAt` and checks it on read); a store is
 * therefore a plain key/value box. The default `InMemoryCacheStore` is per
 * client; a caller may supply its own (shared, persistent) `CacheStore` to
 * pre-seed entries and skip round-trips entirely.
 */
module mcp.client.cache;

import std.datetime : SysTime;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.modern : CacheScope;

/// Identifies one cacheable response. `method` is the JSON-RPC method
/// (`tools/list`, `resources/read`, `server/discover`, …); `key` is empty for
/// the singleton endpoints (the four lists and `server/discover`, which take no
/// distinguishing argument) and the resource URI for `resources/read`. The pair
/// is used directly as an associative-array key.
struct CacheKey
{
	string method;
	string key;
}

/// A stored response plus the freshness metadata needed to decide a hit.
/// `value` is the result's `toJson()` so any result type round-trips uniformly
/// through its `fromJson`. `expiresAt` is absolute, computed by the client when
/// it stores (now + the hint's ttl). `scope_` is advisory: the per-client
/// default store ignores it, but a shared backend must not serve a `private_`
/// entry to a different client identity.
struct CacheEntry
{
	Json value;
	SysTime expiresAt;
	CacheScope scope_ = CacheScope.public_;
}

/// Pluggable cache backend. Freshness is enforced by the client (it checks
/// `CacheEntry.expiresAt`), so an implementation is a dumb key/value box; it MAY
/// additionally evict on its own (size, native TTL) but is not required to.
interface CacheStore
{
	/// Return the entry stored under `key`, or null when absent. The client
	/// decides freshness, so a store returns whatever it holds.
	Nullable!CacheEntry get(CacheKey key) @safe;

	/// Store (or replace) the entry under `key`.
	void put(CacheKey key, CacheEntry entry) @safe;

	/// Drop the single entry under `key` (no-op if absent).
	void invalidate(CacheKey key) @safe;

	/// Drop every entry whose `CacheKey.method` equals `method` (e.g. all
	/// `resources/read` URIs at once).
	void invalidateMethod(string method) @safe;

	/// Drop every entry.
	void clear() @safe;
}

/// Default in-memory store: an associative array bounded by an
/// insertion-ordered size cap so an unbounded stream of distinct
/// `resources/read` URIs cannot grow it without limit. Single-fiber vibe.d
/// access means no locking is needed.
final class InMemoryCacheStore : CacheStore
{
	private CacheEntry[CacheKey] entries_;
	// Insertion order of live keys, used to evict the oldest when at capacity.
	// May name keys already removed by `invalidate`/`invalidateMethod`; those
	// are skipped during eviction.
	private CacheKey[] order_;
	private size_t cap_;

	/// `capacity` bounds the number of held entries (0 disables the bound). The
	/// default comfortably covers the handful of list/discover singletons plus a
	/// working set of resource URIs.
	this(size_t capacity = 256) @safe nothrow
	{
		cap_ = capacity;
	}

	override Nullable!CacheEntry get(CacheKey key) @safe
	{
		if (auto e = key in entries_)
			return nullable(*e);
		return Nullable!CacheEntry.init;
	}

	override void put(CacheKey key, CacheEntry entry) @safe
	{
		const isNew = (key in entries_) is null;
		if (isNew)
		{
			evictIfNeeded();
			order_ ~= key;
		}
		entries_[key] = entry;
	}

	override void invalidate(CacheKey key) @safe
	{
		entries_.remove(key);
	}

	override void invalidateMethod(string method) @safe
	{
		foreach (k; entries_.keys)
			if (k.method == method)
				entries_.remove(k);
	}

	override void clear() @safe
	{
		entries_ = null;
		order_ = null;
	}

	/// Evict the oldest still-present entry when adding a new key would exceed
	/// the cap. Stale names left in `order_` by prior removals are discarded
	/// until a live one is found and dropped.
	private void evictIfNeeded() @safe
	{
		if (cap_ == 0 || entries_.length < cap_)
			return;
		while (order_.length)
		{
			const oldest = order_[0];
			order_ = order_[1 .. $];
			if (oldest in entries_)
			{
				entries_.remove(oldest);
				break;
			}
		}
	}
}

/// Null-object store: holds nothing. Assigning it disables caching while keeping
/// a non-null `CacheStore` everywhere, so the client never branches on null.
/// Obtain the shared instance via `noCache`.
final class NullCacheStore : CacheStore
{
	override Nullable!CacheEntry get(CacheKey) @safe
	{
		return Nullable!CacheEntry.init;
	}

	override void put(CacheKey, CacheEntry) @safe
	{
	}

	override void invalidate(CacheKey) @safe
	{
	}

	override void invalidateMethod(string) @safe
	{
	}

	override void clear() @safe
	{
	}
}

/// The shared `NullCacheStore` singleton. Use as `settings.cache = noCache;` or
/// `client.setCache(noCache);` to turn caching off.
CacheStore noCache() @safe nothrow
{
	static CacheStore instance;
	if (instance is null)
		instance = new NullCacheStore();
	return instance;
}

@safe unittest  // put then get returns the stored entry
{
	auto s = new InMemoryCacheStore();
	auto entry = CacheEntry(Json(["a": Json(1)]), SysTime.init, CacheScope.public_);
	s.put(CacheKey("tools/list", ""), entry);
	auto got = s.get(CacheKey("tools/list", ""));
	assert(!got.isNull);
	assert(got.get.value == entry.value);
}

@safe unittest  // get on an absent key returns null
{
	auto s = new InMemoryCacheStore();
	assert(s.get(CacheKey("tools/list", "")).isNull);
}

@safe unittest  // invalidate drops only the named entry
{
	auto s = new InMemoryCacheStore();
	s.put(CacheKey("resources/read", "a"), CacheEntry(Json("a")));
	s.put(CacheKey("resources/read", "b"), CacheEntry(Json("b")));
	s.invalidate(CacheKey("resources/read", "a"));
	assert(s.get(CacheKey("resources/read", "a")).isNull);
	assert(!s.get(CacheKey("resources/read", "b")).isNull);
}

@safe unittest  // invalidateMethod drops every entry for that method, leaving siblings
{
	auto s = new InMemoryCacheStore();
	s.put(CacheKey("resources/read", "a"), CacheEntry(Json("a")));
	s.put(CacheKey("resources/read", "b"), CacheEntry(Json("b")));
	s.put(CacheKey("tools/list", ""), CacheEntry(Json("t")));
	s.invalidateMethod("resources/read");
	assert(s.get(CacheKey("resources/read", "a")).isNull);
	assert(s.get(CacheKey("resources/read", "b")).isNull);
	assert(!s.get(CacheKey("tools/list", "")).isNull);
}

@safe unittest  // clear empties the store
{
	auto s = new InMemoryCacheStore();
	s.put(CacheKey("tools/list", ""), CacheEntry(Json("t")));
	s.clear();
	assert(s.get(CacheKey("tools/list", "")).isNull);
}

@safe unittest  // re-putting an existing key updates in place without consuming capacity
{
	auto s = new InMemoryCacheStore(2);
	s.put(CacheKey("resources/read", "a"), CacheEntry(Json("a1")));
	s.put(CacheKey("resources/read", "a"), CacheEntry(Json("a2")));
	s.put(CacheKey("resources/read", "b"), CacheEntry(Json("b")));
	// 'a' was replaced, not duplicated, so 'b' fits without evicting 'a'.
	assert(s.get(CacheKey("resources/read", "a")).get.value == Json("a2"));
	assert(!s.get(CacheKey("resources/read", "b")).isNull);
}

@safe unittest  // the size cap evicts the oldest entry first (FIFO)
{
	auto s = new InMemoryCacheStore(2);
	s.put(CacheKey("resources/read", "a"), CacheEntry(Json("a")));
	s.put(CacheKey("resources/read", "b"), CacheEntry(Json("b")));
	s.put(CacheKey("resources/read", "c"), CacheEntry(Json("c")));
	assert(s.get(CacheKey("resources/read", "a")).isNull, "oldest entry evicted");
	assert(!s.get(CacheKey("resources/read", "b")).isNull);
	assert(!s.get(CacheKey("resources/read", "c")).isNull);
}

@safe unittest  // capacity 0 disables the bound
{
	auto s = new InMemoryCacheStore(0);
	foreach (i; 0 .. 1000)
		s.put(CacheKey("resources/read", () @trusted {
				import std.conv : to;

				return i.to!string;
			}()), CacheEntry(Json(i)));
	assert(!s.get(CacheKey("resources/read", "0")).isNull, "nothing evicted when unbounded");
	assert(!s.get(CacheKey("resources/read", "999")).isNull);
}

@safe unittest  // noCache stores nothing and returns the same singleton
{
	auto n = noCache();
	assert(n is noCache());
	n.put(CacheKey("tools/list", ""), CacheEntry(Json("t")));
	assert(n.get(CacheKey("tools/list", "")).isNull, "NullCacheStore never retains entries");
}
