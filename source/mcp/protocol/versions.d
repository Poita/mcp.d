module mcp.protocol.versions;

@safe:

/// A supported MCP protocol version, ordered oldest to newest.
enum ProtocolVersion
{
	v2024_11_05,
	v2025_03_26,
	v2025_06_18,
	v2025_11_25,
	v2026_07_28
}

/// The newest protocol version this SDK speaks: 2026-07-28, the first "modern"
/// revision (stateless per-request `_meta`, `server/discover`, MRTR,
/// `subscriptions/listen`, cacheable results).
enum ProtocolVersion latestStable = ProtocolVersion.v2026_07_28;

/// The newest "legacy" version: the last revision negotiated through the
/// `initialize` handshake. Every code path that exists only for that
/// handshake (the `initialize` fallback, a stateful connection's default, a
/// session with no per-request `_meta`) defaults to this, never to a modern
/// version, because a modern revision has no `InitializeResult` to answer with.
enum ProtocolVersion latestLegacy = ProtocolVersion.v2025_11_25;

/// All versions this SDK can speak, oldest to newest.
immutable ProtocolVersion[] supportedVersions = [
	ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
	ProtocolVersion.v2025_06_18, ProtocolVersion.v2025_11_25,
	ProtocolVersion.v2026_07_28
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
	case ProtocolVersion.v2026_07_28:
		return "2026-07-28";
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

/// Parse a wire string; returns false (without throwing) if unknown. Only
/// dated tokens are versions: the spec's "draft" label names whatever the next
/// unreleased revision currently is, never a version a peer can negotiate.
bool tryParseVersion(string s, out ProtocolVersion v) pure nothrow
{
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

/// `initialize`-handshake negotiation: accept the client's version if
/// supported, otherwise offer the latest legacy version (the handshake itself
/// only exists on legacy revisions, so a modern fallback could not be answered).
ProtocolVersion negotiate(string clientRequested) pure nothrow
{
	ProtocolVersion v;
	return tryParseVersion(clientRequested, v) ? v : latestLegacy;
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
	return v >= ProtocolVersion.v2026_07_28;
}

/// Whether a version predates the modern redesign (< 2026-07-28).
bool isLegacy(ProtocolVersion v) pure nothrow
{
	return v < ProtocolVersion.v2026_07_28;
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
	assert(ProtocolVersion.v2026_07_28.toWire == "2026-07-28");
	assert("2025-06-18".parseVersion == ProtocolVersion.v2025_06_18);
	assert("2026-07-28".parseVersion == ProtocolVersion.v2026_07_28);
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
	// The modern revision echoes back too; the handshake path clamps it afterwards.
	assert(negotiate("2026-07-28") == ProtocolVersion.v2026_07_28);
}

unittest  // negotiation: client version unknown/newer -> fall back to the latest legacy version
{
	assert(negotiate("2099-01-01") == latestLegacy);
	assert(negotiate("garbage") == latestLegacy);
}

unittest  // feature gating: elicitation introduced in 2025-06-18
{
	assert(!ProtocolVersion.v2025_03_26.supportsElicitation);
	assert(ProtocolVersion.v2025_06_18.supportsElicitation);
	assert(ProtocolVersion.v2026_07_28.supportsElicitation);
}

unittest  // modern feature gates and resource-not-found code
{
	assert(ProtocolVersion.v2026_07_28.isModern);
	assert(!ProtocolVersion.v2025_11_25.isModern);
	assert(ProtocolVersion.v2026_07_28.supportsDiscover);
	assert(ProtocolVersion.v2026_07_28.usesMRTR);
	assert(ProtocolVersion.v2026_07_28.usesSubscriptionsListen);
	assert(ProtocolVersion.v2026_07_28.cacheableResults);
	assert(ProtocolVersion.v2026_07_28.resourceNotFoundCode == -32602);
	assert(ProtocolVersion.v2025_11_25.resourceNotFoundCode == -32002);
}

unittest  // isLegacy: every pre-modern version is legacy, modern is not
{
	assert(ProtocolVersion.v2024_11_05.isLegacy);
	assert(ProtocolVersion.v2025_03_26.isLegacy);
	assert(ProtocolVersion.v2025_06_18.isLegacy);
	assert(ProtocolVersion.v2025_11_25.isLegacy);
	assert(!ProtocolVersion.v2026_07_28.isLegacy);
}

unittest  // 2026-07-28 is the latest stable version; 2025-11-25 the latest legacy one
{
	assert(latestStable == ProtocolVersion.v2026_07_28);
	assert(latestStable.toWire == "2026-07-28");
	assert(latestLegacy == ProtocolVersion.v2025_11_25);
	assert(latestLegacy.isLegacy && latestStable.isModern);
	assert(supportedVersions[$ - 1] == latestStable);
}

unittest  // "draft" is not a wire token: the released revision is addressed by its date only
{
	import std.exception : assertThrown;

	ProtocolVersion v;
	assert(!"draft".tryParseVersion(v));
	assertThrown("draft".parseVersion);
	// An initialize handshake naming "draft" is an unknown version and falls back
	// to the latest legacy revision, like any other unknown token.
	assert(negotiate("draft") == latestLegacy);
}
