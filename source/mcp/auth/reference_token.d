module mcp.auth.reference_token;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.auth.resource_server : TokenInfo, TokenValidator;

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
	/// Absolute Unix-time expiry in seconds. The zero-value default (0) is
	/// already in the past, so an `IssueTokenHook` that leaves this unset mints
	/// an instantly-dead token — always set it (use `long.max` for a
	/// non-expiring token).
	long expiresAt;
}

/// Settings for a `ReferenceTokenStore`.
struct ReferenceTokenStoreOptions
{
	/// The most tokens held at once; issuing past it evicts the oldest-issued
	/// token. 0 disables the cap.
	size_t maxEntries = 100_000;
	/// How often (in seconds) `issue` sweeps out tokens past their `expiresAt`.
	long sweepIntervalSeconds = 60;
	/// The current Unix time in seconds (`null` => the system clock); injectable
	/// so tests can drive expiry deterministically.
	long delegate() @safe clock;
}

/// Mints opaque bearer tokens and resolves them back to the `IssuedToken` they
/// represent. Each token lives until its own `expiresAt`: expired tokens are
/// dropped on lookup and swept periodically on `issue`, and the
/// `maxEntries` cap evicts the oldest-issued token so the table cannot grow
/// without limit. Bound to the single-threaded event loop, so it does no
/// locking.
final class ReferenceTokenStore
{
	private IssuedToken[string] tokens;
	// Issue order for cap eviction. Keys already removed are skipped when
	// evicting and dropped when the queue is compacted.
	private string[] order;
	private size_t orderHead;
	private long lastSweep;
	private ReferenceTokenStoreOptions opts;

	/// A store with the default `ReferenceTokenStoreOptions`.
	this() @safe
	{
		this(ReferenceTokenStoreOptions.init);
	}

	/// A store configured by `opts`.
	this(ReferenceTokenStoreOptions opts) @safe
	{
		this.opts = opts;
	}

	/// Mint a fresh opaque token (256 bits of CSPRNG entropy, base64url, no
	/// padding), store `t` under it, and return the token string.
	string issue(IssuedToken t) @safe
	{
		import mcp.auth.csprng : cryptoRandomBytes;
		import mcp.auth.oauth : base64UrlNoPad;

		sweepDue(now());
		if (opts.maxEntries != 0)
			while (tokens.length >= opts.maxEntries && evictOldest())
			{
			}
		const token = base64UrlNoPad(cryptoRandomBytes(32));
		tokens[token] = t;
		order ~= token;
		return token;
	}

	/// Resolve `token` to its `IssuedToken` when it is known and still live at
	/// `now` (absolute Unix seconds). Returns null on an unknown or expired
	/// token; an expired entry is dropped from the store.
	Nullable!IssuedToken lookup(string token, long now) @safe
	{
		auto p = token in tokens;
		if (p is null)
			return Nullable!IssuedToken.init;
		if (now >= p.expiresAt)
		{
			tokens.remove(token);
			return Nullable!IssuedToken.init;
		}
		return nullable(*p);
	}

	/// Resolve `token` as `lookup(token, now)` does, at the store's clock.
	Nullable!IssuedToken lookup(string token) @safe
	{
		return lookup(token, now());
	}

	/// Revoke `token` (e.g. at sign-out or on an RFC 7009 revocation request),
	/// so it no longer resolves. Returns whether the store held it.
	bool revoke(string token) @safe
	{
		if (!tokens.remove(token))
			return false;
		compactOrder();
		return true;
	}

	/// The number of tokens currently held, including any expired ones not yet
	/// swept.
	size_t length() const @safe
	{
		return tokens.length;
	}

	/// The store's current Unix time in seconds: its injected clock, else the
	/// system clock.
	long now() @safe
	{
		return opts.clock !is null ? opts.clock() : nowUnixSeconds();
	}

	private void sweepDue(long t) @safe
	{
		if (t - lastSweep < opts.sweepIntervalSeconds)
			return;
		lastSweep = t;
		string[] expired;
		foreach (k, ref v; tokens)
			if (t >= v.expiresAt)
				expired ~= k;
		foreach (k; expired)
			tokens.remove(k);
		compactOrder();
	}

	private bool evictOldest() @safe
	{
		while (orderHead < order.length)
		{
			const k = order[orderHead++];
			if (tokens.remove(k))
			{
				compactOrder();
				return true;
			}
		}
		return false;
	}

	// Rebuild the issue-order queue once removed keys dominate it, keeping its
	// size proportional to the live table.
	private void compactOrder() @safe
	{
		if (order.length - orderHead <= 2 * tokens.length + 16)
			return;
		string[] live;
		foreach (k; order[orderHead .. $])
			if ((k in tokens) !is null)
				live ~= k;
		order = live;
		orderHead = 0;
	}
}

/// Adapt a `ReferenceTokenStore` into a `TokenValidator` for the resource
/// server. On a live-token hit it returns a valid `TokenInfo` carrying the
/// issued subject/scopes/claims. A token issued without an audience is bound to
/// `resource` (its audience becomes `[resource]`, satisfying the RFC 8707
/// binding); a token issued with an explicit audience is accepted only when that
/// audience names `resource` (compared in RFC 8707 canonical form), so a store shared across resources never lets one
/// resource's token through at another. On a miss, expiry or audience mismatch it
/// returns `TokenInfo.invalid()`.
TokenValidator referenceTokenValidator(ReferenceTokenStore store, string resource) @safe
in (store !is null)
{
	import mcp.auth.jwt_verifier : includesAudience;

	return (string token) @safe {
		auto found = store.lookup(token);
		if (found.isNull)
			return TokenInfo.invalid();
		auto t = found.get;
		if (t.audience.length && !includesAudience(t.audience, resource))
			return TokenInfo.invalid();
		TokenInfo info;
		info.valid = true;
		info.subject = t.subject;
		info.scopes = t.scopes.dup;
		// Copies, so a handler editing its TokenInfo cannot rewrite the stored token.
		info.claims = t.claims.clone();
		info.audience = t.audience.length ? t.audience.dup : [resource];
		return info;
	};
}

private long nowUnixSeconds() @safe
{
	import std.datetime.systime : Clock;

	// Unix time (seconds since 1970), matching the documented unit of
	// `IssuedToken.expiresAt`. `Clock.currStdTime` is hnsecs since 1 AD, so
	// dividing it alone yields seconds since 1 AD — ~62 billion seconds too large,
	// which would make every realistically-dated token read as already expired.
	return Clock.currTime.toUnixTime;
}

// ===========================================================================
// Tests
// ===========================================================================

@safe unittest  // referenceTokenValidator rejects a token issued for a different audience
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.audience = ["https://other.example.com"];
	t.expiresAt = long.max;
	const tok = store.issue(t);

	auto validate = referenceTokenValidator(store, "https://api.example.com");
	assert(!validate(tok).valid);
}

@safe unittest  // referenceTokenValidator compares audiences in canonical resource form
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.audience = ["HTTPS://API.example.com:443/"];
	t.expiresAt = long.max;
	const tok = store.issue(t);

	assert(referenceTokenValidator(store, "https://api.example.com")(tok).valid);
}

@safe unittest  // a handler mutating the validated claims does not alter the stored token
{
	import vibe.data.json : parseJsonString;

	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.expiresAt = long.max;
	t.claims = parseJsonString(`{"role":"reader","nested":{"k":"v"}}`);
	const tok = store.issue(t);
	auto validate = referenceTokenValidator(store, "https://api.example.com");

	auto info = validate(tok);
	info.claims["role"] = "admin";
	info.claims["nested"]["k"] = "changed";
	auto again = validate(tok);
	assert(again.claims["role"].get!string == "reader");
	assert(again.claims["nested"]["k"].get!string == "v");
}

@safe unittest  // a revoked token no longer resolves or validates
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.expiresAt = long.max;
	const tok = store.issue(t);
	const other = store.issue(t);

	assert(store.revoke(tok));
	assert(store.lookup(tok).isNull);
	assert(!referenceTokenValidator(store, "https://api.example.com")(tok).valid);
	assert(!store.revoke(tok), "revoking an unknown token reports nothing removed");
	assert(!store.lookup(other).isNull);
}

@safe unittest  // referenceTokenValidator binds an audience-less token to the resource
{
	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.expiresAt = long.max;
	const tok = store.issue(t);

	auto info = referenceTokenValidator(store, "https://api.example.com")(tok);
	assert(info.valid);
	assert(info.audience == ["https://api.example.com"]);
}

@safe unittest  // the validator measures "now" in Unix seconds, matching IssuedToken.expiresAt
{
	// A token expiring an hour from now (real Unix seconds) must validate; a
	// clock in any other epoch (e.g. seconds since 1 AD) would read every
	// realistically-dated token as already expired.
	import std.datetime.systime : Clock;

	auto store = new ReferenceTokenStore();
	IssuedToken t;
	t.subject = "alice";
	t.audience = ["https://api.example.com"];
	t.expiresAt = Clock.currTime.toUnixTime + 3600;
	const tok = store.issue(t);

	auto validate = referenceTokenValidator(store, "https://api.example.com");
	assert(validate(tok).valid);
}

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
	auto decoded = Base64URLNoPadding.decode(tok);
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
	ReferenceTokenStoreOptions o;
	o.maxEntries = 2;
	auto store = new ReferenceTokenStore(o);

	IssuedToken t;
	t.expiresAt = long.max;
	const a = store.issue(t);
	const b = store.issue(t);
	const c = store.issue(t); // exceeds the cap of 2, evicting `a`

	assert(store.lookup(a, 0).isNull);
	assert(!store.lookup(b, 0).isNull);
	assert(!store.lookup(c, 0).isNull);
}

unittest  // a default-constructed store is bounded
{
	assert(ReferenceTokenStoreOptions.init.maxEntries > 0);
}

unittest  // issue sweeps out tokens past their own expiresAt
{
	long clk = 1000;
	ReferenceTokenStoreOptions o;
	o.clock = () @safe => clk;
	auto store = new ReferenceTokenStore(o);

	IssuedToken shortLived;
	shortLived.expiresAt = 1010;
	store.issue(shortLived);
	clk = 2000;
	IssuedToken t;
	t.expiresAt = long.max;
	store.issue(t);
	assert(store.length == 1);
}

unittest  // a token stays valid until its own expiresAt however long ago it was issued
{
	long clk = 1000;
	ReferenceTokenStoreOptions o;
	o.clock = () @safe => clk;
	auto store = new ReferenceTokenStore(o);

	IssuedToken t;
	t.expiresAt = 10_000_000;
	const tok = store.issue(t);
	clk = 9_000_000;
	store.issue(t); // triggers a sweep
	assert(!store.lookup(tok, clk).isNull);
}

unittest  // cap eviction skips tokens already removed by expiry
{
	ReferenceTokenStoreOptions o;
	o.maxEntries = 2;
	auto store = new ReferenceTokenStore(o);

	IssuedToken dead;
	dead.expiresAt = 1;
	const a = store.issue(dead);
	assert(store.lookup(a, 5).isNull); // dropped on lookup
	IssuedToken t;
	t.expiresAt = long.max;
	const b = store.issue(t);
	const c = store.issue(t);
	const d = store.issue(t); // evicts `b`, the oldest live token
	assert(store.lookup(b, 0).isNull);
	assert(!store.lookup(c, 0).isNull);
	assert(!store.lookup(d, 0).isNull);
}

@safe unittest  // the validator judges expiry by the store's injected clock
{
	long fakeNow = 1_000;
	ReferenceTokenStoreOptions o;
	o.clock = () @safe => fakeNow;
	auto store = new ReferenceTokenStore(o);
	IssuedToken t;
	t.subject = "alice";
	t.expiresAt = 2_000;
	const token = store.issue(t);

	auto validate = referenceTokenValidator(store, "https://mcp.example.com/mcp");
	assert(validate(token).valid);
	fakeNow = 2_000;
	assert(!validate(token).valid);
}
