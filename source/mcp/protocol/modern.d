module mcp.protocol.modern;

import std.typecons : Nullable, nullable;
import core.time : Duration, msecs, seconds;
import vibe.data.json : Json;

import mcp.protocol.capabilities;
import mcp.protocol.mrtr : MetaKey;
import mcp.protocol.jsonhelpers : tryGet;

@safe:

/// Per-request metadata that the draft carries in `params._meta` instead of a
/// once-per-connection `initialize` handshake.
struct RequestMeta
{
	string protocolVersion;
	Implementation clientInfo;
	ClientCapabilities clientCapabilities;
	Nullable!string logLevel;

	/// Extract request metadata from a request's `params` object.
	static RequestMeta fromParams(Json params) @safe
	{
		RequestMeta m;
		if (params.type != Json.Type.object || "_meta" !in params)
			return m;
		auto meta = params["_meta"];
		if (meta.type != Json.Type.object)
			return m;
		if (MetaKey.protocolVersion in meta && meta[MetaKey.protocolVersion].type
				== Json.Type.string)
			m.protocolVersion = meta[MetaKey.protocolVersion].get!string;
		if (MetaKey.clientInfo in meta && meta[MetaKey.clientInfo].type == Json.Type.object)
			m.clientInfo = Implementation.fromJson(meta[MetaKey.clientInfo]);
		if (MetaKey.clientCapabilities in meta
				&& meta[MetaKey.clientCapabilities].type == Json.Type.object)
			m.clientCapabilities = ClientCapabilities.fromJson(meta[MetaKey.clientCapabilities]);
		if (MetaKey.logLevel in meta && meta[MetaKey.logLevel].type == Json.Type.string)
			m.logLevel = meta[MetaKey.logLevel].get!string;
		return m;
	}
}

/// Result of `server/discover`: advertises supported versions, capabilities,
/// and identity so a client can select a version up front (stateless lifecycle).
struct DiscoverResult
{
	string[] protocolVersions;
	ServerCapabilities capabilities;
	Implementation serverInfo;
	Nullable!string instructions;
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`):
	/// `DiscoverResult extends CacheableResult` in the draft schema, so a client
	/// may cache the discovery response. Round-trips symmetrically; the server
	/// sets it (draft-gated), leaving pre-draft wire output unchanged.
	Nullable!CacheHint cache;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		// Base draft Result mandates a `resultType` discriminator on every
		// result; a complete discover response uses "complete".
		j["resultType"] = "complete";
		Json pv = Json.emptyArray;
		foreach (v; protocolVersions)
			pv ~= Json(v);
		// Spec wire field name is `supportedVersions` (draft server/discover
		// Response Fields table), even though the D member is `protocolVersions`.
		j["supportedVersions"] = pv;
		j["capabilities"] = capabilities.toJson();
		j["serverInfo"] = serverInfo.toJson();
		if (!instructions.isNull)
			j["instructions"] = instructions.get;
		if (!cache.isNull)
			j = withCache(j, cache.get);
		return j;
	}

	static DiscoverResult fromJson(Json j) @safe
	{
		DiscoverResult r;
		// Spec wire field is `supportedVersions`; accept the legacy
		// `protocolVersions` name as a fallback for older peers.
		auto verKey = ("supportedVersions" in j) ? "supportedVersions" : "protocolVersions";
		if (verKey in j && j[verKey].type == Json.Type.array)
		{
			auto arr = j[verKey];
			foreach (i; 0 .. arr.length)
				if (arr[i].type == Json.Type.string)
					r.protocolVersions ~= arr[i].get!string;
		}
		if ("capabilities" in j)
			r.capabilities = ServerCapabilities.fromJson(j["capabilities"]);
		if ("serverInfo" in j)
			r.serverInfo = Implementation.fromJson(j["serverInfo"]);
		tryGet(j, "instructions", r.instructions);
		r.cache = parseCacheHint(j);
		return r;
	}
}

@safe unittest  // DiscoverResult round-trips the CacheableResult freshness hint
{
	import core.time : msecs;

	DiscoverResult r;
	r.protocolVersions = ["2026-07-28"];
	r.cache = CacheHint(60_000.msecs, CacheScope.private_);
	auto j = r.toJson();
	assert(j["ttlMs"].get!long == 60_000);
	assert(j["cacheScope"].get!string == "private");
	auto back = DiscoverResult.fromJson(j);
	assert(!back.cache.isNull);
	assert(back.cache.get.ttl == 60_000.msecs);
	assert(back.cache.get.cacheScope == CacheScope.private_);
}

@safe unittest  // a DiscoverResult with no hint emits no cache fields and parses back null
{
	DiscoverResult r;
	r.protocolVersions = ["2026-07-28"];
	auto j = r.toJson();
	assert("ttlMs" !in j);
	assert("cacheScope" !in j);
	assert(DiscoverResult.fromJson(j).cache.isNull);
}

/// Whether a shared (public) or per-client (private) cache may hold a result.
enum CacheScope : string
{
	public_ = "public",
	private_ = "private",
}

/// A per-result freshness hint (draft `CacheableResult`): how long a result may
/// be cached (`ttl`) and by whom (`cacheScope`). Supplied per result by the
/// user and surfaced to client consumers. The wire field stays `ttlMs`
/// (milliseconds); `ttl` is the typed SDK-facing value.
struct CacheHint
{
	Duration ttl;
	CacheScope cacheScope = CacheScope.public_;
}

/// Attach the draft `CacheableResult` fields (`ttlMs`, `cacheScope`) to a result
/// object from a `CacheHint` and return it, leaving the original untouched (matching
/// the sibling `withSubscriptionId`). A freshness hint for clients/intermediaries
/// that complements `listChanged` notifications.
Json withCache(Json result, CacheHint hint) @safe
{
	if (result.type != Json.Type.object)
		return result;
	// `vibe.data.Json` is a reference type, so clone before writing to avoid
	// mutating the caller's object as a side effect.
	Json out_ = result.clone();
	// Spec (`CacheableResult`): servers MUST provide a `ttlMs` value that is
	// >= 0. The wire field is milliseconds; convert from the typed Duration and
	// clamp at this single emission chokepoint so a negative/zero Duration can
	// never reach the wire as a negative value, regardless of caller input.
	const ttlMs = hint.ttl.total!"msecs";
	out_["ttlMs"] = ttlMs < 0 ? 0L : ttlMs;
	out_["cacheScope"] = cast(string) hint.cacheScope;
	return out_;
}

/// Parse a draft `CacheableResult` freshness hint from a result object. Reads
/// `ttlMs` (accepting an integer or a float) and `cacheScope` (a string mapped to
/// the `CacheScope` enum, defaulting to `public`). Returns null when no `ttlMs`
/// field is present.
Nullable!CacheHint parseCacheHint(Json result) @safe
{
	if (result.type != Json.Type.object || "ttlMs" !in result)
		return Nullable!CacheHint.init;
	auto ttl = result["ttlMs"];
	CacheHint hint;
	long ttlMs;
	if (ttl.type == Json.Type.int_)
		ttlMs = ttl.get!long;
	else if (ttl.type == Json.Type.float_)
		ttlMs = cast(long) ttl.get!double;
	else
		return Nullable!CacheHint.init;
	// Spec (`CacheableResult`): `ttlMs` MUST be >= 0; clamp defensively on read
	// so values round-tripped through this SDK honour the constraint even if a
	// non-conforming peer emitted a negative value. The wire field is
	// milliseconds; store as a typed Duration.
	if (ttlMs < 0)
		ttlMs = 0;
	hint.ttl = ttlMs.msecs;
	if ("cacheScope" in result && result["cacheScope"].type == Json.Type.string)
	{
		const s = result["cacheScope"].get!string;
		hint.cacheScope = (s == "private") ? CacheScope.private_ : CacheScope.public_;
	}
	return nullable(hint);
}

unittest  // RequestMeta parses per-request _meta
{
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.logLevel] = "debug";
	Json caps = Json.emptyObject;
	caps["sampling"] = Json.emptyObject;
	meta[MetaKey.clientCapabilities] = caps;
	Json params = Json.emptyObject;
	params["_meta"] = meta;

	auto m = RequestMeta.fromParams(params);
	assert(m.protocolVersion == "2026-07-28");
	assert(m.clientInfo.name == "c");
	assert(m.clientCapabilities.sampling);
	assert(m.logLevel.get == "debug");
}

unittest  // RequestMeta.fromParams ignores non-object clientInfo and clientCapabilities without throwing
{
	// A malicious or buggy peer may send a non-object value for clientInfo or
	// clientCapabilities; the parser must treat them as absent rather than
	// propagating a JSONException from the fromJson helpers.
	import vibe.data.json : parseJsonString;

	auto params = parseJsonString(`{"_meta":{"` ~ MetaKey.clientInfo ~ `":42,"`
			~ MetaKey.clientCapabilities ~ `":"not-an-object"}}`);
	RequestMeta m;
	// Must not throw even though both values are not JSON objects.
	m = RequestMeta.fromParams(params);
	// Non-object values are treated as absent; scalar fields stay at their defaults.
	assert(m.clientInfo.name == "");
	assert(m.clientInfo.version_ == "");
	assert(!m.clientCapabilities.sampling);
	assert(!m.clientCapabilities.roots);
}

unittest  // DiscoverResult round-trips
{
	DiscoverResult d;
	d.protocolVersions = ["2026-07-28", "2025-11-25"];
	d.serverInfo = Implementation("srv", "1.0");
	d.capabilities.logging = true;
	auto back = DiscoverResult.fromJson(d.toJson());
	assert(back.protocolVersions.length == 2);
	assert(back.serverInfo.name == "srv");
	assert(back.capabilities.logging);
}

unittest  // DiscoverResult.toJson emits the spec wire field `supportedVersions`
{
	DiscoverResult d;
	d.protocolVersions = ["2026-07-28", "2025-11-25"];
	d.serverInfo = Implementation("srv", "1.0");
	auto j = d.toJson();
	// draft server/discover Response Fields table requires `supportedVersions`,
	// not the internal name `protocolVersions`.
	assert("supportedVersions" in j);
	assert("protocolVersions" !in j);
	assert(j["supportedVersions"].length == 2);
	assert(j["supportedVersions"][0].get!string == "2026-07-28");
}

unittest  // DiscoverResult.fromJson skips non-string entries in supportedVersions
{
	// A malformed server response with non-string elements must not throw;
	// only the valid string entries are collected.
	import vibe.data.json : parseJsonString;

	auto j = parseJsonString(`{"supportedVersions": ["2026-07-28", 42, null, true, "2025-11-25"]}`);
	auto r = DiscoverResult.fromJson(j);
	assert(r.protocolVersions.length == 2);
	assert(r.protocolVersions[0] == "2026-07-28");
	assert(r.protocolVersions[1] == "2025-11-25");
}

unittest  // DiscoverResult.toJson carries the required resultType discriminator
{
	DiscoverResult d;
	d.protocolVersions = ["2026-07-28"];
	auto j = d.toJson();
	// Base draft Result mandates a resultType discriminator on every result;
	// a complete discover response uses "complete".
	assert("resultType" in j);
	assert(j["resultType"].get!string == "complete");
}

unittest  // DiscoverResult.fromJson reads the spec wire field `supportedVersions`
{
	Json j = Json.emptyObject;
	Json sv = Json.emptyArray;
	sv ~= Json("2026-07-28");
	sv ~= Json("2025-11-25");
	j["resultType"] = Json("complete");
	j["supportedVersions"] = sv;
	auto r = DiscoverResult.fromJson(j);
	assert(r.protocolVersions.length == 2);
	assert(r.protocolVersions[0] == "2026-07-28");
}

unittest  // withCache attaches ttlMs (ms) and cacheScope from a CacheHint Duration
{
	Json r = Json.emptyObject;
	r["tools"] = Json.emptyArray;
	auto c = withCache(r, CacheHint(5.seconds, CacheScope.private_));
	assert(c["ttlMs"].get!long == 5000);
	assert(c["cacheScope"].get!string == "private");
}

unittest  // withCache clamps a negative Duration to ttlMs:0 (spec: ttlMs MUST be >= 0)
{
	Json r = Json.emptyObject;
	r["tools"] = Json.emptyArray;
	auto c = withCache(r, CacheHint((-5).seconds, CacheScope.public_));
	assert(c["ttlMs"].get!long == 0);
}

unittest  // withCache emits ttlMs:0 for a zero Duration
{
	Json r = Json.emptyObject;
	r["tools"] = Json.emptyArray;
	auto c = withCache(r, CacheHint(Duration.zero, CacheScope.public_));
	assert(c["ttlMs"].get!long == 0);
}

unittest  // withCache leaves the original result untouched (clones, like withSubscriptionId)
{
	Json r = Json.emptyObject;
	r["tools"] = Json.emptyArray;
	auto c = withCache(r, CacheHint(5.seconds, CacheScope.private_));
	assert("ttlMs" !in r);
	assert("cacheScope" !in r);
	assert(c["ttlMs"].get!long == 5000);
}

unittest  // parseCacheHint clamps a negative ttlMs to a zero Duration on read
{
	Json r = Json.emptyObject;
	r["ttlMs"] = -42;
	auto h = parseCacheHint(r);
	assert(!h.isNull);
	assert(h.get.ttl == Duration.zero);
}

unittest  // parseCacheHint clamps a negative float ttlMs to a zero Duration on read
{
	Json r = Json.emptyObject;
	r["ttlMs"] = -1500.0;
	auto h = parseCacheHint(r);
	assert(!h.isNull);
	assert(h.get.ttl == Duration.zero);
}

unittest  // parseCacheHint reads an integer ttlMs (ms) into a Duration and a cacheScope string
{
	Json r = Json.emptyObject;
	r["ttlMs"] = 5000;
	r["cacheScope"] = "private";
	auto h = parseCacheHint(r);
	assert(!h.isNull);
	assert(h.get.ttl == 5.seconds);
	assert(h.get.cacheScope == CacheScope.private_);
}

unittest  // parseCacheHint accepts a float ttlMs (ms) and defaults cacheScope to public
{
	Json r = Json.emptyObject;
	r["ttlMs"] = 1500.0;
	auto h = parseCacheHint(r);
	assert(!h.isNull);
	assert(h.get.ttl == 1500.msecs);
	assert(h.get.cacheScope == CacheScope.public_);
}

unittest  // round-trip: CacheHint(5.seconds) -> wire ttlMs:5000 -> 5.seconds
{
	Json r = Json.emptyObject;
	auto c = withCache(r, CacheHint(5.seconds, CacheScope.public_));
	assert(c["ttlMs"].get!long == 5000);
	auto h = parseCacheHint(c);
	assert(!h.isNull);
	assert(h.get.ttl == 5.seconds);
}

unittest  // parseCacheHint returns null when ttlMs is absent
{
	Json r = Json.emptyObject;
	r["tools"] = Json.emptyArray;
	assert(parseCacheHint(r).isNull);
}
