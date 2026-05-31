module mcp.protocol.versions;

@safe:

/// A supported MCP protocol version, ordered oldest to newest.
enum ProtocolVersion
{
	v2024_11_05,
	v2025_03_26,
	v2025_06_18,
	v2025_11_25,
	draft
}

/// The newest stable (non-draft) version this SDK speaks.
enum ProtocolVersion latestStable = ProtocolVersion.v2025_11_25;

/// All versions this SDK can speak, oldest to newest (draft last).
immutable ProtocolVersion[] supportedVersions = [
	ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
	ProtocolVersion.v2025_06_18, ProtocolVersion.v2025_11_25,
	ProtocolVersion.draft
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
	case ProtocolVersion.draft:
		return "2026-07-28"; // the current draft revision
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
	// Accept the literal "draft" as an alias for the current draft revision.
	if (s == "draft")
	{
		v = ProtocolVersion.draft;
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

/// The draft (2026-07-28) redesign: stateless HTTP, per-request `_meta`,
/// `server/discover`, MRTR, `subscriptions/listen`, cacheable results, and the
/// standard request headers. Gated behind this single predicate so older
/// versions keep their session/handshake-based behavior.
bool isDraft(ProtocolVersion v) pure nothrow
{
	return v >= ProtocolVersion.draft;
}

/// Draft+ uses per-request `_meta` (protocolVersion/clientInfo/clientCapabilities)
/// instead of an `initialize` handshake.
alias usesPerRequestMeta = isDraft;

/// Draft+ implements `server/discover`.
alias supportsDiscover = isDraft;

/// Draft+ uses Multi Round-Trip Requests instead of server-initiated requests.
alias usesMRTR = isDraft;

/// Draft+ uses `subscriptions/listen` instead of GET stream + resources/subscribe.
alias usesSubscriptionsListen = isDraft;

/// Draft+ returns `ttlMs`/`cacheScope` on cacheable results.
alias cacheableResults = isDraft;

/// The JSON-RPC error code for "resource not found": draft aligns it to
/// invalidParams (-32602); earlier versions used the MCP-specific -32002.
int resourceNotFoundCode(ProtocolVersion v) pure nothrow
{
	return v.isDraft ? -32602 : -32002;
}

unittest  // wire string round-trips for every version
{
	import std.exception : assertThrown;

	assert(ProtocolVersion.v2024_11_05.toWire == "2024-11-05");
	assert(ProtocolVersion.draft.toWire == "2026-07-28");
	assert("2025-06-18".parseVersion == ProtocolVersion.v2025_06_18);
	assert("draft".parseVersion == ProtocolVersion.draft);
	assert("2026-07-28".parseVersion == ProtocolVersion.draft);
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
	assert(ProtocolVersion.draft.supportsElicitation);
}

unittest  // draft feature gates and resource-not-found code
{
	assert(ProtocolVersion.draft.isDraft);
	assert(!ProtocolVersion.v2025_11_25.isDraft);
	assert(ProtocolVersion.draft.supportsDiscover);
	assert(ProtocolVersion.draft.usesMRTR);
	assert(ProtocolVersion.draft.usesSubscriptionsListen);
	assert(ProtocolVersion.draft.cacheableResults);
	assert(ProtocolVersion.draft.resourceNotFoundCode == -32602);
	assert(ProtocolVersion.v2025_11_25.resourceNotFoundCode == -32002);
}
