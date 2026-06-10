module mcp.auth.reference_token;

import core.time : Duration, MonoTime, dur;
import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.auth.resource_server : TokenInfo, TokenValidator;
import mcp.transport.session : BoundedExpiringMap;

@safe:

/// An access token the MCP server itself mints and validates by lookup (the
/// "reference"/opaque token pattern). The server keeps the principal it
/// authenticated server-side, keyed by the issued token string, and consults
/// it on every request. `expiresAt` is an absolute Unix time in seconds; a
/// token is live while `now < expiresAt`.
struct IssuedToken
{
	string subject; /// the authenticated principal (becomes `TokenInfo.subject`)
	string[] scopes; /// the scopes the token grants
	string[] audience; /// the resources the token was issued for (RFC 8707)
	Json claims = Json.undefined; /// arbitrary claims surfaced to handlers
	long expiresAt; /// absolute Unix-time expiry in seconds
}

/// Mints opaque bearer tokens and resolves them back to the `IssuedToken` they
/// represent. Backed by a bounded, lazily-expiring map so an insert-only token
/// table cannot grow without limit; the cap evicts the oldest entry and the
/// idle TTL sweeps stale ones. Bound to the single-threaded event loop, so it
/// does no locking. The map's TTL governs storage hygiene; per-token validity
/// is decided by each token's own `expiresAt` at lookup.
final class ReferenceTokenStore
{
	private BoundedExpiringMap!IssuedToken tokens;

	/// A store with no idle TTL sweep and no entry cap.
	this() @safe
	{
		this(Duration.zero, 0, null);
	}

	/// A store bounded by an idle `ttl` and a `maxEntries` cap. `clock`
	/// (`null` => `MonoTime.currTime`) drives the map's idle sweep and is
	/// injectable so tests can exercise eviction deterministically.
	this(Duration ttl, size_t maxEntries, MonoTime delegate() @safe clock) @safe
	{
		tokens = BoundedExpiringMap!IssuedToken(ttl, maxEntries, clock);
	}

	/// Mint a fresh opaque token (256 bits of CSPRNG entropy, base64url, no
	/// padding), store `t` under it, and return the token string.
	string issue(IssuedToken t) @safe
	{
		import mcp.auth.csprng : cryptoRandomBytes;
		import mcp.auth.oauth : base64UrlNoPad;

		const token = base64UrlNoPad(cryptoRandomBytes(32));
		tokens.put(token, t);
		return token;
	}

	/// Resolve `token` to its `IssuedToken` when it is known and still live at
	/// `now` (absolute Unix seconds). Returns null on an unknown or expired
	/// token; an expired entry is dropped from the store.
	Nullable!IssuedToken lookup(string token, long now) @safe
	{
		auto p = tokens.get(token, false);
		if (p is null)
			return Nullable!IssuedToken.init;
		if (now >= p.expiresAt)
		{
			tokens.remove(token);
			return Nullable!IssuedToken.init;
		}
		return nullable(*p);
	}
}

/// Adapt a `ReferenceTokenStore` into a `TokenValidator` for the resource
/// server. On a live-token hit it returns a valid `TokenInfo` carrying the
/// issued subject/scopes/claims, with `resource` added to the audience so
/// `hasAudience(resource)` holds (satisfying the RFC 8707 binding even when the
/// token was issued without an explicit audience). On a miss or expiry it
/// returns `TokenInfo.invalid()`.
TokenValidator referenceTokenValidator(ReferenceTokenStore store, string resource) @safe
in (store !is null)
{
	import std.algorithm : canFind;

	return (string token) @safe {
		auto found = store.lookup(token, nowUnixSeconds());
		if (found.isNull)
			return TokenInfo.invalid();
		auto t = found.get;
		TokenInfo info;
		info.valid = true;
		info.subject = t.subject;
		info.scopes = t.scopes;
		info.claims = t.claims;
		info.audience = t.audience.canFind(resource) ? t.audience : t.audience ~ resource;
		return info;
	};
}

private long nowUnixSeconds() @safe
{
	import std.datetime.systime : Clock;

	return Clock.currStdTime / 10_000_000L;
}

// ===========================================================================
// Tests
// ===========================================================================

unittest  // issue -> lookup round-trips the IssuedToken for a live token
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.scopes = ["read", "write"];
	t.audience = ["https://api.example.com"];
	t.expiresAt = 1000;
	const tok = store.issue(t);

	auto got = store.lookup(tok, 500);
	assert(!got.isNull);
	assert(got.get.subject == "alice");
	assert(got.get.scopes == ["read", "write"]);
	assert(got.get.audience == ["https://api.example.com"]);
	assert(got.get.expiresAt == 1000);
}

unittest  // lookup after expiry yields null
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "bob";
	t.expiresAt = 1000;
	const tok = store.issue(t);

	auto got = store.lookup(tok, 1000);
	assert(got.isNull);
}

unittest  // an unknown token is rejected
{
	auto store = new ReferenceTokenStore();
	auto got = store.lookup("not-a-real-token", 0);
	assert(got.isNull);
}

unittest  // minted tokens are unique
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.expiresAt = long.max;
	const a = store.issue(t);
	const b = store.issue(t);
	assert(a != b);
}

unittest  // minted tokens carry at least 256 bits of entropy
{
	import std.base64 : Base64URLNoPadding;

	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.expiresAt = long.max;
	const tok = store.issue(t);
	// base64url-no-pad of 32 bytes decodes back to 32 bytes (256 bits).
	auto decoded = () @trusted { return Base64URLNoPadding.decode(tok); }();
	assert(decoded.length >= 32);
}

unittest  // referenceTokenValidator returns a valid, audience-bound TokenInfo for a live token
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "carol";
	t.scopes = ["mcp:use"];
	t.expiresAt = nowUnixSeconds() + 3600;
	const tok = store.issue(t);

	auto validate = referenceTokenValidator(store, "https://api.example.com");
	auto info = validate(tok);
	assert(info.valid);
	assert(info.subject == "carol");
	assert(info.hasScope("mcp:use"));
	assert(info.hasAudience("https://api.example.com"));
}

unittest  // referenceTokenValidator rejects an unknown token
{
	auto store = new ReferenceTokenStore();
	auto validate = referenceTokenValidator(store, "https://api.example.com");
	auto info = validate("bogus");
	assert(!info.valid);
}

unittest  // referenceTokenValidator rejects an expired token
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "dave";
	t.expiresAt = nowUnixSeconds() - 1;
	const tok = store.issue(t);

	auto validate = referenceTokenValidator(store, "https://api.example.com");
	auto info = validate(tok);
	assert(!info.valid);
}

unittest  // the store evicts the oldest entry once the bound is exceeded
{
	MonoTime clk = MonoTime.currTime;
	auto store = new ReferenceTokenStore(Duration.zero, 2, () @safe => clk);

	IssuedToken t;
	t.expiresAt = long.max;
	const a = store.issue(t);
	clk += 1.dur!"seconds";
	const b = store.issue(t);
	clk += 1.dur!"seconds";
	const c = store.issue(t); // exceeds the cap of 2, evicting `a`

	assert(store.lookup(a, 0).isNull);
	assert(!store.lookup(b, 0).isNull);
	assert(!store.lookup(c, 0).isNull);
}
