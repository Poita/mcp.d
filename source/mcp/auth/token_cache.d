/// A result cache for token verifiers that make one upstream call per token
/// (RFC 7662 introspection, the GitHub and Google token APIs). It keeps bounded
/// positive and negative caches keyed by the SHA-256 of the token, so raw bearer
/// credentials are never held as map keys, and coalesces concurrent lookups of
/// the same token into a single upstream call.
module mcp.auth.token_cache;

import core.time : Duration, seconds;

import vibe.data.json : Json;

import mcp.auth.resource_server : TokenInfo;

@safe:

/// How a `TokenCache` reuses verification results.
struct TokenCacheOptions
{
	/// How long a valid result is reused before the verifier is asked again,
	/// clamped to the token's own expiry when the result carries one (`exp`, or
	/// GitHub's `expires_at`). Zero disables positive caching. A longer TTL
	/// trades revocation latency (a token revoked upstream keeps working until
	/// its entry expires) for fewer upstream calls.
	Duration ttl = 60.seconds;

	/// How long a rejection is reused, so a client retrying a dead token does
	/// not cost an upstream call each time. Zero disables negative caching. A
	/// temporarily-unavailable result is never cached.
	Duration negativeTtl = 10.seconds;

	/// Cap on live entries in each of the positive and negative caches. When a
	/// new token would exceed it, the soonest-expiring entry is evicted.
	size_t maxEntries = ExpiringCache.defaultMaxEntries;
}

/// Positive and negative result caches plus single-flight coalescing in front
/// of a token verifier. Bound to vibe.d's single-threaded event loop like the
/// verifiers that use it.
final class TokenCache
{
	import vibe.core.sync : TaskMutex;

	private static final class Flight
	{
		TaskMutex done;
		TokenInfo result;
	}

	private ExpiringCache positive; // null when positive caching is off
	private ExpiringCache negative; // null when negative caching is off
	private Flight[string] inFlight;

	/// The current Unix time in seconds. Null selects the wall clock; tests
	/// drive it by hand.
	package long delegate() @safe clock;

	this(TokenCacheOptions opts) @safe
	{
		if (opts.ttl > Duration.zero)
			positive = new ExpiringCache(opts.ttl, opts.maxEntries);
		if (opts.negativeTtl > Duration.zero)
			negative = new ExpiringCache(opts.negativeTtl, opts.maxEntries);
	}

	/// The result for `token`: a live cached one, else `verify`'s. Concurrent
	/// lookups of the same token share one `verify` call. Every caller gets its
	/// own deep copy, so mutating it affects neither the cache nor other callers.
	TokenInfo lookup(string token, scope TokenInfo delegate() @safe verify) @safe
	{
		const key = cacheKey(token);
		const t = now();
		if (positive !is null)
			if (auto hit = positive.get(key, t))
				return hit.dup;
		if (negative !is null && negative.get(key, t) !is null)
			return TokenInfo.invalid();

		if (auto pending = key in inFlight)
		{
			auto flight = *pending;
			flight.done.lock();
			flight.done.unlock();
			return flight.result.dup;
		}

		auto flight = new Flight;
		flight.done = new TaskMutex;
		flight.done.lock();
		inFlight[key] = flight;
		scope (exit)
		{
			inFlight.remove(key);
			flight.done.unlock();
		}
		flight.result = verify();
		store(key, flight.result);
		return flight.result.dup;
	}

	private void store(string key, TokenInfo result) @safe
	{
		if (result.valid)
		{
			if (positive !is null)
				positive.put(key, result.dup, now());
		}
		else if (!result.unavailable && negative !is null)
			negative.put(key, TokenInfo.invalid(), now());
	}

	private long now() @safe
	{
		import mcp.auth.jwt_verifier : currentUnixTime;

		return clock !is null ? clock() : currentUnixTime();
	}

	private static string cacheKey(string token) @safe
	{
		import std.digest : toHexString;
		import std.digest.sha : sha256Of;

		return toHexString(sha256Of(token)).idup;
	}
}

/// A TTL cache of `TokenInfo` results under string keys.
///
/// Every `put` sweeps entries whose `expiresAt` is in the past, and when a new
/// key would push `entries.length` past `maxEntries`, the entry with the earliest
/// `expiresAt` is evicted. This keeps memory bounded under sustained load with
/// many distinct short-lived tokens. Entries are also ordered by expiry, so a
/// sweep visits only the expired entries and an eviction takes the first one:
/// a `put` costs O(log n) plus the entries it removes.
final class ExpiringCache
{
	import std.container.rbtree : RedBlackTree;
	import std.typecons : Tuple;

	/// Default maximum number of live cache entries.
	enum size_t defaultMaxEntries = 10_000;

	private struct Entry
	{
		TokenInfo info;
		long expiresAt; // unix seconds
	}

	private alias Expiry = Tuple!(long, "at", string, "key");

	private Duration ttl;
	private size_t maxEntries;
	private Entry[string] entries;
	// One element per entry, ordered by (expiresAt, key).
	private RedBlackTree!Expiry byExpiry;

	this(Duration ttl, size_t maxEntries = defaultMaxEntries) @safe
	{
		this.ttl = ttl;
		this.maxEntries = maxEntries;
		this.byExpiry = new RedBlackTree!Expiry;
	}

	/// Number of live (not yet swept) entries.
	size_t length() @safe
	{
		return entries.length;
	}

	/// Return the cached `TokenInfo` under `key` if present and unexpired.
	TokenInfo* get(string key, long now) @safe
	{
		if (auto e = key in entries)
		{
			if (now < e.expiresAt)
				return &e.info;
			remove(key, e.expiresAt);
		}
		return null;
	}

	/// Cache `info` under `key`. The entry expiry is the TTL, clamped down to
	/// the token's own expiry (`tokenExpiry`) when known, so a cached result
	/// never outlives the token it represents. Expired entries are swept on
	/// every call; when the cap would be exceeded by a new key, the
	/// soonest-expiring entry is evicted first.
	void put(string key, TokenInfo info, long now) @safe
	{
		long expiresAt = now + cast(long) ttl.total!"seconds";
		const exp = tokenExpiry(info.claims);
		if (exp > 0 && exp < expiresAt)
			expiresAt = exp;
		if (expiresAt <= now)
			return; // token is already expired — nothing to cache
		sweep(now);
		if (auto old = key in entries)
			remove(key, old.expiresAt);
		else if (maxEntries != 0)
			while (entries.length >= maxEntries)
				remove(byExpiry.front.key, byExpiry.front.at);
		entries[key] = Entry(info, expiresAt);
		byExpiry.insert(Expiry(expiresAt, key));
	}

	// Remove all entries whose expiresAt is not in the future.
	private void sweep(long now) @safe
	{
		while (!byExpiry.empty && byExpiry.front.at <= now)
			remove(byExpiry.front.key, byExpiry.front.at);
	}

	private void remove(string key, long expiresAt) @safe
	{
		byExpiry.removeKey(Expiry(expiresAt, key));
		entries.remove(key);
	}
}

/// The token's expiry (unix seconds) from a verifier's claims: a numeric `exp`
/// (RFC 7662 2.2 / RFC 7519 4.1.1), an `exp` given as a decimal string (Google
/// tokeninfo), or an ISO 8601 `expires_at` (GitHub). Returns 0 when none is
/// present or parseable, signalling "no known expiry".
long tokenExpiry(Json claims) @safe
{
	import std.conv : to;

	if (claims.type != Json.Type.object)
		return 0;
	auto e = claims["exp"];
	if (e.type == Json.Type.int_)
		return e.get!long;
	if (e.type == Json.Type.float_)
		return cast(long) e.get!double;
	try
	{
		if (e.type == Json.Type.string)
			return e.get!string
				.to!long;
		auto at = claims["expires_at"];
		if (at.type == Json.Type.string)
		{
			import std.datetime.systime : SysTime;

			return SysTime.fromISOExtString(at.get!string).toUnixTime;
		}
	}
	catch (Exception)
	{
	}
	return 0;
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	import vibe.data.json : parseJsonString;

	/// A `TokenCache` over a hand-driven clock and a counting verifier.
	private final class CountingCache
	{
		long clock = 1_000;
		int calls;
		TokenInfo answer;
		TokenCache cache;

		this(TokenCacheOptions opts) @safe
		{
			cache = new TokenCache(opts);
			cache.clock = () @safe => clock;
		}

		TokenInfo lookup(string token) @safe
		{
			return cache.lookup(token, () @safe { ++calls; return answer; });
		}
	}

	private TokenInfo validInfo(string claimsJson = `{}`) @safe
	{
		TokenInfo ti;
		ti.valid = true;
		ti.subject = "u1";
		ti.scopes = ["read"];
		ti.claims = parseJsonString(claimsJson);
		return ti;
	}
}

unittest  // TokenCache reuses a valid result until its TTL lapses
{
	auto c = new CountingCache(TokenCacheOptions(30.seconds, Duration.zero));
	c.answer = validInfo();
	assert(c.lookup("tok").valid);
	assert(c.lookup("tok").subject == "u1");
	assert(c.calls == 1);
	c.clock += 30;
	assert(c.lookup("tok").valid);
	assert(c.calls == 2);
}

unittest  // TokenCache never serves a valid result past the token's own expiry
{
	auto c = new CountingCache(TokenCacheOptions(300.seconds, Duration.zero));
	c.answer = validInfo(`{"exp":"1010"}`);
	c.lookup("tok");
	c.clock += 10;
	c.lookup("tok");
	assert(c.calls == 2);
}

unittest  // TokenCache reuses a rejection for the negative TTL only
{
	auto c = new CountingCache(TokenCacheOptions(60.seconds, 10.seconds));
	c.answer = TokenInfo.invalid();
	assert(!c.lookup("bad").valid);
	assert(!c.lookup("bad").valid);
	assert(c.calls == 1);
	c.clock += 10;
	c.lookup("bad");
	assert(c.calls == 2);
}

unittest  // TokenCache never caches a temporarily-unavailable result
{
	auto c = new CountingCache(TokenCacheOptions(60.seconds, 10.seconds));
	c.answer = TokenInfo.temporarilyUnavailable();
	assert(c.lookup("tok").unavailable);
	assert(c.lookup("tok").unavailable);
	assert(c.calls == 2);
}

unittest  // TokenCache with both TTLs zero calls the verifier every time
{
	auto c = new CountingCache(TokenCacheOptions(Duration.zero, Duration.zero));
	c.answer = validInfo();
	c.lookup("tok");
	c.lookup("tok");
	assert(c.calls == 2);
}

unittest  // TokenCache keeps each token's result apart and bounds its entries
{
	auto c = new CountingCache(TokenCacheOptions(60.seconds, Duration.zero, 2));
	c.answer = validInfo();
	c.lookup("a");
	c.lookup("b");
	c.lookup("c");
	assert(c.cache.positive.length == 2);
	assert(c.calls == 3);
}

unittest  // TokenCache keys entries by a digest of the token, never the raw token
{
	auto c = new CountingCache(TokenCacheOptions.init);
	c.answer = validInfo();
	c.lookup("secret-bearer");
	assert(c.cache.positive.get("secret-bearer", c.clock) is null);
}

unittest  // a caller mutating a TokenCache result leaves the cached entry intact
{
	auto c = new CountingCache(TokenCacheOptions.init);
	c.answer = validInfo(`{"role":"user"}`);
	auto first = c.lookup("tok");
	first.claims["role"] = "admin";
	first.scopes[0] = "admin";
	auto second = c.lookup("tok");
	assert(second.claims["role"].get!string == "user");
	assert(second.scopes == ["read"]);
}

unittest  // TokenCache coalesces concurrent lookups of one token into a single verifier call
{
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	auto cache = new TokenCache(TokenCacheOptions(Duration.zero, Duration.zero));
	int calls;
	TokenInfo slowVerify() @safe
	{
		++calls;
		sleep(30.msecs);
		TokenInfo ti;
		ti.valid = true;
		ti.subject = "u1";
		return ti;
	}

	string[2] subjects;
	auto ta = runTask(() nothrow{
		try
			subjects[0] = cache.lookup("tok", &slowVerify).subject;
		catch (Exception)
		{
		}
	});
	auto tb = runTask(() nothrow{
		try
			subjects[1] = cache.lookup("tok", &slowVerify).subject;
		catch (Exception)
		{
		}
	});
	ta.join();
	tb.join();
	assert(calls == 1);
	assert(subjects[0] == "u1" && subjects[1] == "u1");
}

unittest  // ExpiringCache returns a hit before expiry and a miss after
{
	auto cache = new ExpiringCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.subject = "cached-user";
	cache.put("tok", ti, 1000);

	auto hit = cache.get("tok", 1010);
	assert(hit !is null);
	assert(hit.subject == "cached-user");

	assert(cache.get("tok", 1040) is null); // expired (1000 + 30 == 1030)
	assert(cache.get("other", 1010) is null); // never stored
}

unittest  // ExpiringCache clamps entry expiry to the token's exp claim
{
	auto cache = new ExpiringCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	// exp at 1005 is sooner than now(1000) + ttl(30) == 1030, so it must win.
	ti.claims = parseJsonString(`{"active":true,"exp":1005}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1004) !is null); // still valid before exp
	assert(cache.get("tok", 1005) is null); // expired at exp, not at 1030
}

unittest  // ExpiringCache keeps the TTL when exp is later than now + ttl
{
	auto cache = new ExpiringCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.claims = parseJsonString(`{"active":true,"exp":9999}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1029) !is null); // within TTL window
	assert(cache.get("tok", 1030) is null); // TTL (1030) bounds it, not exp
}

unittest  // ExpiringCache falls back to the TTL when no exp is present
{
	auto cache = new ExpiringCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.claims = parseJsonString(`{"active":true}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1029) !is null);
	assert(cache.get("tok", 1030) is null);
}

unittest  // tokenExpiry parses numeric, decimal-string and ISO 8601 expiries, 0 otherwise
{
	assert(tokenExpiry(parseJsonString(`{"exp":1700}`)) == 1700);
	assert(tokenExpiry(parseJsonString(`{"exp":1700.9}`)) == 1700);
	assert(tokenExpiry(parseJsonString(`{"exp":"1700"}`)) == 1700);
	assert(tokenExpiry(parseJsonString(`{"expires_at":"2023-11-14T22:13:20Z"}`)) == 1_700_000_000);
	assert(tokenExpiry(parseJsonString(`{"active":true}`)) == 0);
	assert(tokenExpiry(parseJsonString(`{"exp":"soon"}`)) == 0);
	assert(tokenExpiry(parseJsonString(`{"expires_at":null}`)) == 0);
	assert(tokenExpiry(parseJsonString(`"not-an-object"`)) == 0);
}

unittest  // ExpiringCache does not grow beyond the configured maxEntries cap
{
	// A cache with cap of 3 — inserting 5 distinct tokens must not keep all 5.
	auto cache = new ExpiringCache(60.seconds, 3);
	TokenInfo ti;
	ti.valid = true;
	foreach (i; 0 .. 5)
	{
		import std.conv : to;

		cache.put("tok-" ~ i.to!string, ti, 1000);
	}
	// The map must be capped; all 5 entries must NOT all be present.
	assert(cache.length <= 3);
}

unittest  // ExpiringCache sweeps expired entries on put, reclaiming space
{
	// All entries inserted at t=1000 with ttl=30s expire at t=1030.
	// After advancing past expiry, a new put must sweep the stale entries.
	auto cache = new ExpiringCache(30.seconds, 10);
	TokenInfo ti;
	ti.valid = true;
	cache.put("a", ti, 1000);
	cache.put("b", ti, 1000);
	// Advance past expiry and insert a new entry.
	cache.put("c", ti, 1031);
	// "a" and "b" should have been swept; only "c" should remain.
	assert(cache.get("a", 1031) is null);
	assert(cache.get("b", 1031) is null);
	assert(cache.get("c", 1031) !is null);
}

unittest  // ExpiringCache drops expired entries from its length once a later put runs
{
	auto cache = new ExpiringCache(30.seconds, 10);
	TokenInfo ti;
	ti.valid = true;
	cache.put("a", ti, 1000);
	cache.put("b", ti, 1000);
	cache.put("c", ti, 1031);
	assert(cache.length == 1);
}

unittest  // ExpiringCache evicts the soonest-expiring entry when full
{
	auto cache = new ExpiringCache(60.seconds, 2);
	TokenInfo late, soon;
	late.valid = soon.valid = true;
	soon.claims = parseJsonString(`{"active":true,"exp":1010}`);
	cache.put("late", late, 1000);
	cache.put("soon", soon, 1000);
	cache.put("new", late, 1001);
	assert(cache.get("soon", 1001) is null);
	assert(cache.get("late", 1001) !is null);
	assert(cache.get("new", 1001) !is null);
}

unittest  // ExpiringCache re-putting a key moves its expiry for eviction and sweeping
{
	auto cache = new ExpiringCache(60.seconds, 2);
	TokenInfo ti;
	ti.valid = true;
	cache.put("a", ti, 1000); // expires 1060
	cache.put("b", ti, 1010); // expires 1070
	cache.put("a", ti, 1020); // now expires 1080, so "b" expires first
	assert(cache.length == 2);
	cache.put("c", ti, 1030);
	assert(cache.get("b", 1030) is null);
	assert(cache.get("a", 1030) !is null);
	cache.put("d", ti, 1075); // "c" (1090) and "a" (1080) are both still live
	assert(cache.length == 2);
	assert(cache.get("a", 1075) is null, "the cap evicts the soonest-expiring entry");
	assert(cache.get("c", 1075) !is null);
}

unittest  // ExpiringCache skips storing a token whose exp claim is already in the past
{
	// TTL = 30s, now = 1000, but exp = 500 (500 s in the past).
	// The clamping sets expiresAt = 500, which is already expired relative to now.
	// put must not store the entry; the cache must remain empty.
	auto cache = new ExpiringCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.claims = parseJsonString(`{"active":true,"exp":500}`);
	cache.put("tok", ti, 1000);
	// The entry must not be stored — length stays 0 and a get returns null.
	assert(cache.length == 0);
	assert(cache.get("tok", 1000) is null);
}
