/// The `_meta` keys MCP reserves, and validation of `_meta` key names against
/// the spec's key-name format and reserved prefixes (basic/index).
module mcp.protocol.meta_keys;

import std.ascii : isAlpha, isAlphaNum;

import mcp.protocol.versions : ProtocolVersion;

@safe:

/// Reserved `_meta` keys defined by the 2026-07-28 revision.
enum MetaKey : string
{
	protocolVersion = "io.modelcontextprotocol/protocolVersion",
	clientInfo = "io.modelcontextprotocol/clientInfo",
	clientCapabilities = "io.modelcontextprotocol/clientCapabilities",
	/// Identifies the server software producing a response. A `ResultMetaObject`
	/// field, so it rides on every result rather than one handshake reply.
	serverInfo = "io.modelcontextprotocol/serverInfo",
	logLevel = "io.modelcontextprotocol/logLevel",
	subscriptionId = "io.modelcontextprotocol/subscriptionId",
}

/// A `_meta` key is `[<prefix>]<name>`. The optional `<prefix>` is a series of
/// dot-separated labels followed by a `/`. Each label MUST start with a letter
/// and end with a letter or digit (interior may contain hyphens). Unless empty,
/// the `<name>` MUST start and end with an alphanumeric character; the interior
/// may also contain `-`, `_`, and `.`.
///
/// Prefixes whose second label is `modelcontextprotocol` or `mcp` are reserved
/// for MCP use (see `isReservedMetaPrefix`).
bool isValidMetaKey(string key) @safe pure nothrow
{
	if (key.length == 0)
		return false;

	string prefix;
	string name;
	bool hasPrefix;
	splitMetaKey(key, prefix, name, hasPrefix);

	if (hasPrefix && !isValidMetaPrefixLabels(prefix))
		return false;
	return isValidMetaName(name);
}

/// Split a `_meta` key into its optional `<prefix>` and `<name>` at the final
/// `/`. A `_meta` key is `[<prefix>/]<name>`; the prefix (the dot-separated
/// labels, WITHOUT the trailing slash) is present only when a `/` occurs.
/// `hasPrefix` reports whether a `/` was found; when false `prefix` is empty and
/// `name` is the whole key. Centralises the last-`/` scan shared by the meta-key
/// validators.
private void splitMetaKey(string key, out string prefix, out string name, out bool hasPrefix) @safe pure nothrow
{
	ptrdiff_t slash = -1;
	foreach (i, char c; key)
		if (c == '/')
			slash = i;
	if (slash >= 0)
	{
		hasPrefix = true;
		prefix = key[0 .. slash]; // labels without the trailing slash
		name = key[slash + 1 .. $];
	}
	else
	{
		name = key;
	}
}

/// Split a prefix's dot-separated label portion into its individual labels,
/// preserving empty labels (so `"a..b"` yields `["a", "", "b"]` and `""` yields
/// `[""]`). Centralises the label-walk skeleton shared by the prefix validators
/// and the reserved-prefix scanners.
private string[] metaLabels(string labels) @safe pure nothrow
{
	string[] result;
	size_t start = 0;
	for (size_t i = 0; i <= labels.length; i++)
		if (i == labels.length || labels[i] == '.')
		{
			result ~= labels[start .. i];
			start = i + 1;
		}
	return result;
}

/// Validate the label portion of a prefix (everything before the trailing `/`).
/// Labels are dot-separated; each MUST start with a letter and end with a letter
/// or digit, and may contain hyphens in the interior.
private bool isValidMetaPrefixLabels(string labels) @safe pure nothrow
{
	if (labels.length == 0)
		return false; // a bare "/name" has an empty prefix, which is invalid
	foreach (label; metaLabels(labels))
		if (!isValidMetaLabel(label))
			return false;
	return true;
}

private bool isValidMetaLabel(string label) @safe pure nothrow
{
	if (label.length == 0)
		return false;
	if (!isAlpha(label[0]))
		return false;
	if (!isAlphaNum(label[$ - 1]))
		return false;
	foreach (char c; label)
		if (!isAlphaNum(c) && c != '-')
			return false;
	return true;
}

private bool isValidMetaName(string name) @safe pure nothrow
{
	// Per the spec's Name rule ("Unless empty, MUST begin and end with an
	// alphanumeric character"), an empty name segment is valid.
	if (name.length == 0)
		return true;
	if (!isAlphaNum(name[0]) || !isAlphaNum(name[$ - 1]))
		return false;
	foreach (char c; name)
		if (!isAlphaNum(c) && c != '-' && c != '_' && c != '.')
			return false;
	return true;
}

/// Whether a `_meta` key's prefix is reserved for MCP use, applying the rule for
/// the 2025-11-25 / modern revisions: the SECOND dot-separated label of the prefix
/// is `modelcontextprotocol` or `mcp` (e.g. `io.modelcontextprotocol/`, `com.mcp/`).
/// `com.example.mcp/` is NOT reserved. Such prefixes MUST NOT be used by
/// non-protocol code.
///
/// This version-agnostic overload preserves the 2025-11-25 / modern semantics. Use
/// the `(string, ProtocolVersion)` overload when an effective protocol version is
/// known, since 2025-06-18 uses a broader rule (see below).
bool isReservedMetaPrefix(string key) @safe pure nothrow
{
	string labels, name;
	bool hasPrefix;
	splitMetaKey(key, labels, name, hasPrefix);
	if (!hasPrefix)
		return false;

	// The second dot-separated label, if any, decides reservation.
	auto parts = metaLabels(labels);
	if (parts.length < 2)
		return false;
	return parts[1] == "modelcontextprotocol" || parts[1] == "mcp";
}

/// Whether a `_meta` key's prefix is reserved for MCP use under the effective
/// protocol version `v`. The two revisions differ:
///
/// - 2025-06-18 (basic/index): "Any prefix beginning with zero or more valid
///   labels, followed by `modelcontextprotocol` or `mcp`, followed by any valid
///   label, is reserved." So the mcp-token may appear in ANY position as long as
///   at least one more label follows it — e.g. `modelcontextprotocol.io/`,
///   `mcp.dev/`, `api.modelcontextprotocol.org/`, and `tools.mcp.com/` are all
///   reserved. Earlier versions (2024-11-05, 2025-03-26) had no formal `_meta`
///   reserved-prefix rule; this same any-position rule is applied to them as a
///   safe superset.
/// - 2025-11-25 / modern: the narrower "second label" rule (see the
///   single-argument overload), where `com.example.mcp/` is NOT reserved.
bool isReservedMetaPrefix(string key, ProtocolVersion v) @safe pure nothrow
{
	// 2025-11-25 and the modern use the narrower "second label" rule.
	if (v >= ProtocolVersion.v2025_11_25)
		return isReservedMetaPrefix(key);

	// 2025-06-18 (and earlier, as a safe superset): an mcp-token in any label
	// position that is followed by at least one further label reserves the prefix.
	string labels, name;
	bool hasPrefix;
	splitMetaKey(key, labels, name, hasPrefix);
	if (!hasPrefix)
		return false;

	auto parts = metaLabels(labels);
	foreach (i, label; parts)
	{
		// Reserved only if this mcp-token is followed by at least one more label.
		if ((label == "modelcontextprotocol" || label == "mcp") && i + 1 < parts.length)
			return true;
	}
	return false;
}

/// Validate a user-supplied `_meta` key for attachment: it MUST be a
/// well-formed key (`isValidMetaKey`) and MUST NOT use an MCP-reserved prefix
/// (`isReservedMetaPrefix`). Returns `true` if the key is safe to use. Uses the
/// 2025-11-25 / modern "second label" reserved-prefix rule; pass a
/// `ProtocolVersion` to apply the rule for a specific connection.
bool isUserMetaKeyAllowed(string key) @safe pure nothrow
{
	return isValidMetaKey(key) && !isReservedMetaPrefix(key);
}

/// Validate a user-supplied `_meta` key for attachment under the effective
/// protocol version `v`: it MUST be well-formed and MUST NOT use a prefix that is
/// MCP-reserved for that version.
bool isUserMetaKeyAllowed(string key, ProtocolVersion v) @safe pure nothrow
{
	return isValidMetaKey(key) && !isReservedMetaPrefix(key, v);
}

unittest  // isValidMetaKey: plain names without prefix
{
	assert(isValidMetaKey("progress"));
	assert(isValidMetaKey("a"));
	assert(isValidMetaKey("a-b_c.d"));
	assert(isValidMetaKey("trace2"));

	assert(!isValidMetaKey(""));
	assert(!isValidMetaKey("-bad")); // must start alphanumeric
	assert(!isValidMetaKey("bad-")); // must end alphanumeric
	assert(!isValidMetaKey("_bad")); // must start alphanumeric
	assert(!isValidMetaKey("has space"));
}

unittest  // isValidMetaKey: prefixed keys
{
	assert(isValidMetaKey("io.modelcontextprotocol/protocolVersion"));
	assert(isValidMetaKey("com.example/myKey"));
	assert(isValidMetaKey("a/b"));
	assert(isValidMetaKey("my-org.tools-v2/data.point"));

	assert(!isValidMetaKey("/name")); // empty prefix
	assert(!isValidMetaKey("1bad.example/name")); // label must start with letter
	assert(!isValidMetaKey("bad-.example/name")); // label must end alphanumeric
	assert(!isValidMetaKey("io..example/name")); // empty interior label
	assert(!isValidMetaKey("io.example/-x")); // name must start alphanumeric
}

unittest  // isValidMetaKey: prefix-only keys (empty name segment is valid)
{
	// The spec's Name rule is "Unless empty, MUST begin and end with an
	// alphanumeric character", so a valid prefix followed by an empty name
	// segment is a valid `_meta` key.
	assert(isValidMetaKey("io.example/"));
	assert(isValidMetaKey("com.example/"));
	assert(isValidMetaKey("io.modelcontextprotocol/"));
	assert(isValidMetaKey("a/"));

	// An empty prefix with an empty name is still invalid.
	assert(!isValidMetaKey("/"));
}

unittest  // isReservedMetaPrefix: second label modelcontextprotocol or mcp
{
	assert(isReservedMetaPrefix("io.modelcontextprotocol/protocolVersion"));
	assert(isReservedMetaPrefix("com.mcp/whatever"));

	assert(!isReservedMetaPrefix("io.example/key"));
	assert(!isReservedMetaPrefix("modelcontextprotocol/key")); // only one label, no second
	assert(!isReservedMetaPrefix("plainkey")); // no prefix at all
	assert(!isReservedMetaPrefix("a.b.mcp/key")); // mcp is third label, not second
}

unittest  // isReservedMetaPrefix(2025-06-18): mcp-token in first position + trailing label
{
	import mcp.protocol.versions : ProtocolVersion;

	// Per 2025-06-18 basic/index, a prefix beginning with `modelcontextprotocol`
	// or `mcp` followed by ANY valid label is reserved.
	assert(isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_06_18));
	assert(isReservedMetaPrefix("mcp.dev/key", ProtocolVersion.v2025_06_18));
	assert(isReservedMetaPrefix("tools.mcp.com/key", ProtocolVersion.v2025_06_18));
	assert(isReservedMetaPrefix("api.modelcontextprotocol.org/key", ProtocolVersion.v2025_06_18));
	// Reserved when the token is the second label AND a trailing label follows.
	assert(isReservedMetaPrefix("io.modelcontextprotocol.v2/key", ProtocolVersion.v2025_06_18));
}

unittest  // isReservedMetaPrefix(2025-06-18): not reserved without a trailing label or token
{
	import mcp.protocol.versions : ProtocolVersion;

	// No following label after the mcp-token -> not reserved.
	assert(!isReservedMetaPrefix("modelcontextprotocol/key", ProtocolVersion.v2025_06_18));
	assert(!isReservedMetaPrefix("mcp/key", ProtocolVersion.v2025_06_18));
	// No mcp-token at all.
	assert(!isReservedMetaPrefix("io.example/key", ProtocolVersion.v2025_06_18));
	// No prefix at all.
	assert(!isReservedMetaPrefix("plainkey", ProtocolVersion.v2025_06_18));
}

unittest  // isReservedMetaPrefix(2025-11-25/modern): keeps the narrower second-label rule
{
	import mcp.protocol.versions : ProtocolVersion;

	// First-position token is NOT reserved under 2025-11-25/modern (only the
	// second label counts), so the modern/2025-11-25 wire behaviour is unchanged.
	assert(!isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	assert(!isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2026_07_28));
	// `com.example.mcp/` has `mcp` as its THIRD label, so it is NOT reserved under
	// the second-label rule (the 2025-11-25 spec's own counter-example).
	assert(!isReservedMetaPrefix("com.example.mcp/key", ProtocolVersion.v2025_11_25));
	assert(!isReservedMetaPrefix("com.example.mcp/key", ProtocolVersion.v2026_07_28));
	// Second-label token IS reserved under both.
	assert(isReservedMetaPrefix("io.modelcontextprotocol/key", ProtocolVersion.v2025_11_25));
	assert(isReservedMetaPrefix("com.mcp/key", ProtocolVersion.v2026_07_28));
	// The clean divergence: `modelcontextprotocol.io/` is reserved under 2025-06-18
	// (first-position token + trailing label) but NOT under 2025-11-25 (second
	// label is `io`).
	assert(isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_06_18)
			&& !isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	// The version-agnostic overload must match the 2025-11-25/modern rule exactly.
	assert(isReservedMetaPrefix("io.modelcontextprotocol/key",
			ProtocolVersion.v2025_11_25) == isReservedMetaPrefix("io.modelcontextprotocol/key"));
	assert(isReservedMetaPrefix("modelcontextprotocol.io/key",
			ProtocolVersion.v2026_07_28) == isReservedMetaPrefix("modelcontextprotocol.io/key"));
}

unittest  // isUserMetaKeyAllowed(2025-06-18) rejects first-position mcp-token prefixes
{
	import mcp.protocol.versions : ProtocolVersion;

	// Reserved under 2025-06-18 (first-position token + trailing label, second
	// label not an mcp-token) -> disallowed on a 2025-06-18 connection.
	assert(!isUserMetaKeyAllowed("modelcontextprotocol.io/key", ProtocolVersion.v2025_06_18));
	assert(!isUserMetaKeyAllowed("mcp.dev/key", ProtocolVersion.v2025_06_18));
	// But allowed under 2025-11-25/modern, where those prefixes are not reserved
	// (their second label is `io` / `dev`, not an mcp-token).
	assert(isUserMetaKeyAllowed("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	assert(isUserMetaKeyAllowed("mcp.dev/key", ProtocolVersion.v2026_07_28));
	// A genuine vendor key is allowed on every version.
	assert(isUserMetaKeyAllowed("com.example/myKey", ProtocolVersion.v2025_06_18));
	assert(isUserMetaKeyAllowed("com.example/myKey", ProtocolVersion.v2025_11_25));
}

unittest  // isUserMetaKeyAllowed: valid and not reserved
{
	assert(isUserMetaKeyAllowed("com.example/myKey"));
	assert(isUserMetaKeyAllowed("progress"));

	assert(!isUserMetaKeyAllowed("io.modelcontextprotocol/x")); // reserved
	assert(!isUserMetaKeyAllowed("com.mcp/x")); // reserved
	assert(!isUserMetaKeyAllowed("bad space")); // invalid format
	assert(!isUserMetaKeyAllowed("/x")); // invalid format
}

unittest  // MetaKey enum values are all valid keys (spec-compliant by construction)
{
	import std.traits : EnumMembers;

	static foreach (k; EnumMembers!MetaKey)
		assert(isValidMetaKey(cast(string) k));
}

unittest  // splitMetaKey splits at the final slash into prefix + name
{
	string prefix, name;
	bool hasPrefix;
	splitMetaKey("io.example/data.point", prefix, name, hasPrefix);
	assert(hasPrefix);
	assert(prefix == "io.example");
	assert(name == "data.point");
}

unittest  // splitMetaKey treats a key without a slash as a bare name
{
	string prefix, name;
	bool hasPrefix;
	splitMetaKey("progress", prefix, name, hasPrefix);
	assert(!hasPrefix);
	assert(prefix == "");
	assert(name == "progress");
}

unittest  // splitMetaKey splits at the LAST slash (names may not contain '/', but be defensive)
{
	string prefix, name;
	bool hasPrefix;
	splitMetaKey("a/b/c", prefix, name, hasPrefix);
	assert(hasPrefix);
	assert(prefix == "a/b");
	assert(name == "c");
}

unittest  // metaLabels splits dot-separated labels, preserving empties
{
	assert(metaLabels("io.example") == ["io", "example"]);
	assert(metaLabels("a..b") == ["a", "", "b"]);
	assert(metaLabels("") == [""]);
	assert(metaLabels("solo") == ["solo"]);
}
