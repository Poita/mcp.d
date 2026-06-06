module mcp.protocol.versions;

@safe:

/// A supported MCP protocol version, ordered oldest to newest.
enum ProtocolVersion
{
	v2024_11_05,
	v2025_03_26,
	v2025_06_18,
	v2025_11_25,
	modern
}

/// The newest stable (legacy) version this SDK speaks. Versions before
/// `modern` (2026-07-28) are "legacy"; `modern` and later are "modern".
enum ProtocolVersion latestStable = ProtocolVersion.v2025_11_25;

/// All versions this SDK can speak, oldest to newest (modern last).
immutable ProtocolVersion[] supportedVersions = [
	ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
	ProtocolVersion.v2025_06_18, ProtocolVersion.v2025_11_25,
	ProtocolVersion.modern
];

/// Convert a version to its on-the-wire date string.
string toWire(ProtocolVersion v) pure nothrow
{
	final switch (v)
	{
	case ProtocolVersion.v2024_11_05:
		return "2024-11-05";
	case ProtocolVersion.v2025_03_26:
		return "2025-03-26";
	case ProtocolVersion.v2025_06_18:
		return "2025-06-18";
	case ProtocolVersion.v2025_11_25:
		return "2025-11-25";
	case ProtocolVersion.modern:
		return "2026-07-28"; // wire token for the modern revision (spec labels it "draft")
	}
}

/// Parse a wire string into a ProtocolVersion, or throw if unknown.
ProtocolVersion parseVersion(string s) pure
{
	ProtocolVersion v;
	if (!tryParseVersion(s, v))
		throw new Exception("Unknown MCP protocol version: " ~ s);
	return v;
}

/// Parse a wire string; returns false (without throwing) if unknown.
bool tryParseVersion(string s, out ProtocolVersion v) pure nothrow
{
	// The spec labels the modern revision's wire token "draft"; accept it as
	// an alias for the dated "2026-07-28" token.
	if (s == "draft")
	{
		v = ProtocolVersion.modern;
		return true;
	}
	foreach (candidate; supportedVersions)
	{
		if (candidate.toWire == s)
		{
			v = candidate;
			return true;
		}
	}
	return false;
}

/// Server-side negotiation: accept the client's version if supported,
/// otherwise offer our latest stable version.
ProtocolVersion negotiate(string clientRequested) pure nothrow
{
	ProtocolVersion v;
	return tryParseVersion(clientRequested, v) ? v : latestStable;
}

/// Whether elicitation (client feature) is available at this version.
bool supportsElicitation(ProtocolVersion v) pure nothrow
{
	return v >= ProtocolVersion.v2025_06_18;
}

/// Whether `notifications/progress` may carry the optional `message` field.
/// The 2024-11-05 ProgressNotification params are {progressToken, progress,
/// total?} with NO `message`; `message` was introduced in 2025-03-26 and is
/// retained in every later version. Emitting it to a 2024-11-05 peer would
/// inject an out-of-schema key, so the server gates it on this predicate.
bool supportsProgressMessage(ProtocolVersion v) pure nothrow
{
	return v >= ProtocolVersion.v2025_03_26;
}

/// The modern (>= 2026-07-28) redesign: stateless HTTP, per-request `_meta`,
/// `server/discover`, MRTR, `subscriptions/listen`, cacheable results, and the
/// standard request headers. Gated behind this single predicate so older
/// versions keep their session/handshake-based behavior.
bool isModern(ProtocolVersion v) pure nothrow
{
	return v >= ProtocolVersion.modern;
}

/// Whether a version predates the modern redesign (< 2026-07-28).
bool isLegacy(ProtocolVersion v) pure nothrow
{
	return v < ProtocolVersion.modern;
}

/// Modern uses per-request `_meta` (protocolVersion/clientInfo/clientCapabilities)
/// instead of an `initialize` handshake.
alias usesPerRequestMeta = isModern;

/// Modern implements `server/discover`.
alias supportsDiscover = isModern;

/// Modern uses Multi Round-Trip Requests instead of server-initiated requests.
alias usesMRTR = isModern;

/// Modern uses `subscriptions/listen` instead of GET stream + resources/subscribe.
alias usesSubscriptionsListen = isModern;

/// Modern returns `ttlMs`/`cacheScope` on cacheable results.
alias cacheableResults = isModern;

/// The JSON-RPC error code for "resource not found": modern aligns it to
/// invalidParams (-32602); earlier versions used the MCP-specific -32002.
int resourceNotFoundCode(ProtocolVersion v) pure nothrow
{
	return v.isModern ? -32602 : -32002;
}

unittest  // wire string round-trips for every version
{
	import std.exception : assertThrown;

	assert(ProtocolVersion.v2024_11_05.toWire == "2024-11-05");
	assert(ProtocolVersion.modern.toWire == "2026-07-28");
	assert("2025-06-18".parseVersion == ProtocolVersion.v2025_06_18);
	assert("draft".parseVersion == ProtocolVersion.modern);
	assert("2026-07-28".parseVersion == ProtocolVersion.modern);
	assertThrown("1999-01-01".parseVersion);
}

unittest  // tryParseVersion does not throw on unknown
{
	ProtocolVersion v;
	assert("2025-03-26".tryParseVersion(v));
	assert(v == ProtocolVersion.v2025_03_26);
	assert(!"nope".tryParseVersion(v));
}

unittest  // negotiation: client version supported -> echo it back
{
	assert(negotiate("2025-06-18") == ProtocolVersion.v2025_06_18);
	// both wire tokens for the modern revision must echo back modern, not fall through to latestStable
	assert(negotiate("draft") == ProtocolVersion.modern);
	assert(negotiate("2026-07-28") == ProtocolVersion.modern);
}

unittest  // negotiation: client version unknown/newer -> fall back to latest stable
{
	assert(negotiate("2099-01-01") == latestStable);
	assert(negotiate("garbage") == latestStable);
}

unittest  // feature gating: elicitation introduced in 2025-06-18
{
	assert(!ProtocolVersion.v2025_03_26.supportsElicitation);
	assert(ProtocolVersion.v2025_06_18.supportsElicitation);
	assert(ProtocolVersion.modern.supportsElicitation);
}

unittest  // modern feature gates and resource-not-found code
{
	assert(ProtocolVersion.modern.isModern);
	assert(!ProtocolVersion.v2025_11_25.isModern);
	assert(ProtocolVersion.modern.supportsDiscover);
	assert(ProtocolVersion.modern.usesMRTR);
	assert(ProtocolVersion.modern.usesSubscriptionsListen);
	assert(ProtocolVersion.modern.cacheableResults);
	assert(ProtocolVersion.modern.resourceNotFoundCode == -32602);
	assert(ProtocolVersion.v2025_11_25.resourceNotFoundCode == -32002);
}

unittest  // isLegacy: every pre-modern version is legacy, modern is not
{
	assert(ProtocolVersion.v2024_11_05.isLegacy);
	assert(ProtocolVersion.v2025_03_26.isLegacy);
	assert(ProtocolVersion.v2025_06_18.isLegacy);
	assert(ProtocolVersion.v2025_11_25.isLegacy);
	assert(!ProtocolVersion.modern.isLegacy);
}

unittest  // both wire tokens for the modern revision still parse
{
	assert("draft".parseVersion == ProtocolVersion.modern);
	assert("2026-07-28".parseVersion == ProtocolVersion.modern);
}
