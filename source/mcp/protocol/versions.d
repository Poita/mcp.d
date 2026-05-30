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
        return "draft";
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

unittest  // wire string round-trips for every version
{
    import std.exception : assertThrown;

    assert(ProtocolVersion.v2024_11_05.toWire == "2024-11-05");
    assert(ProtocolVersion.draft.toWire == "draft");
    assert("2025-06-18".parseVersion == ProtocolVersion.v2025_06_18);
    assert("draft".parseVersion == ProtocolVersion.draft);
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
