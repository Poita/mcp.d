module mcp.protocol.mrtr;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.versions : ProtocolVersion;
import mcp.protocol.sampling : CreateMessageRequest;
import mcp.protocol.errors : isValidElicitationUrl, invalidParams;
import mcp.protocol.jsonhelpers : tryGet;

@safe:

/// Reserved `_meta` keys defined by the draft (2026-07-28) revision.
enum MetaKey : string
{
	protocolVersion = "io.modelcontextprotocol/protocolVersion",
	clientInfo = "io.modelcontextprotocol/clientInfo",
	clientCapabilities = "io.modelcontextprotocol/clientCapabilities",
	logLevel = "io.modelcontextprotocol/logLevel",
	subscriptionId = "io.modelcontextprotocol/subscriptionId",
}

// ===========================================================================
// _meta key-name validation (basic/index, `_meta` Key name format)
// ===========================================================================

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

private bool isAlpha(char c) @safe pure nothrow
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

private bool isAlphaNum(char c) @safe pure nothrow
{
	return isAlpha(c) || (c >= '0' && c <= '9');
}

/// Whether a `_meta` key's prefix is reserved for MCP use, applying the rule for
/// the 2025-11-25 / draft revisions: the SECOND dot-separated label of the prefix
/// is `modelcontextprotocol` or `mcp` (e.g. `io.modelcontextprotocol/`, `com.mcp/`).
/// `com.example.mcp/` is NOT reserved. Such prefixes MUST NOT be used by
/// non-protocol code.
///
/// This version-agnostic overload preserves the 2025-11-25 / draft semantics. Use
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
/// - 2025-11-25 / draft: the narrower "second label" rule (see the
///   single-argument overload), where `com.example.mcp/` is NOT reserved.
bool isReservedMetaPrefix(string key, ProtocolVersion v) @safe pure nothrow
{
	// 2025-11-25 and the draft use the narrower "second label" rule.
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
/// 2025-11-25 / draft "second label" reserved-prefix rule; pass a
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

/// Stamp the draft `io.modelcontextprotocol/subscriptionId` (`MetaKey.subscriptionId`)
/// into `params._meta` of a JSON-RPC notification and return it, leaving the
/// original untouched. Per draft basic/utilities/subscriptions every notification
/// delivered on a `subscriptions/listen` stream MUST carry the listen request's id
/// as `subscriptionId` in `_meta`, so clients can correlate the notification with
/// the listen request that established the stream — this is the producer for that
/// key. `subscriptionId` is the originating `subscriptions/listen` request's
/// JSON-RPC id, carried verbatim so its wire type is preserved (the spec types it
/// as `RequestId = string | number`, so a numeric listen id stays numeric). An
/// absent id — `undefined`, `null`, or an empty string — is a no-op (the
/// notification is returned unchanged). Notifications carry their payload under
/// `params`, so the key is nested as `params._meta.<subscriptionId>`.
Json withSubscriptionId(Json notification, Json subscriptionId) @safe
{
	if (subscriptionId.type == Json.Type.undefined
			|| subscriptionId.type == Json.Type.null_
			|| (subscriptionId.type == Json.Type.string && subscriptionId.get!string.length == 0))
		return notification;

	Json n = notification.clone();
	Json params = ("params" in n && n["params"].type == Json.Type.object) ? n["params"]
		: Json.emptyObject;
	Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
		: Json.emptyObject;
	meta[MetaKey.subscriptionId] = subscriptionId;
	params["_meta"] = meta;
	n["params"] = params;
	return n;
}

unittest  // withSubscriptionId stamps the listen request id into params._meta
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/tools/list_changed")
	]);
	auto stamped = withSubscriptionId(n, Json("listen-7"));
	assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "listen-7");
	// The original is left untouched.
	assert("params" !in n);
}

unittest  // withSubscriptionId preserves a numeric JSON-RPC id verbatim (RequestId = string | number)
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/tools/list_changed")
	]);
	auto stamped = withSubscriptionId(n, Json(42L));
	auto id = stamped["params"]["_meta"][MetaKey.subscriptionId];
	assert(id.type == Json.Type.int_, "a numeric listen id must stay numeric, not be stringified");
	assert(id.get!long == 42);
}

unittest  // withSubscriptionId preserves an existing params payload and _meta entries
{
	Json params = Json.emptyObject;
	params["uri"] = "file:///x";
	Json meta = Json.emptyObject;
	meta["other.vendor/flag"] = true;
	params["_meta"] = meta;
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/resources/updated"),
		"params": params
	]);
	auto stamped = withSubscriptionId(n, Json("id-42"));
	assert(stamped["params"]["uri"].get!string == "file:///x");
	assert(stamped["params"]["_meta"]["other.vendor/flag"].get!bool);
	assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "id-42");
}

unittest  // withSubscriptionId with an empty id is a no-op
{
	auto n = Json([
		"jsonrpc": Json("2.0"),
		"method": Json("notifications/message")
	]);
	auto same = withSubscriptionId(n, Json(""));
	assert("params" !in same);
}

/// Standard Streamable HTTP request headers introduced by the draft.
enum HttpHeader : string
{
	protocolVersion = "MCP-Protocol-Version",
	method = "Mcp-Method",
	name = "Mcp-Name",
	paramPrefix = "Mcp-Param-",
}

// ===========================================================================
// x-mcp-header: mirroring tool parameters into HTTP headers
// ===========================================================================

/// Encode a tool-parameter value for transmission in an `Mcp-Param-*` header.
/// Plain-ASCII values pass through; anything else (non-ASCII, control chars,
/// surrounding whitespace, or a value that looks like the sentinel) is wrapped
/// as `=?base64?<base64-of-utf8>?=`.
string encodeHeaderValue(string value) @safe
{
	import std.base64 : Base64;

	if (value.length == 0)
		return value;
	bool needsEncoding = false;
	if (value[0] == ' ' || value[$ - 1] == ' ')
		needsEncoding = true;
	foreach (char c; value)
		if (c < 0x20 || c > 0x7E)
			needsEncoding = true;
	if (value.length >= 9 && value[0 .. 9] == "=?base64?")
		needsEncoding = true;

	if (!needsEncoding)
		return value;
	return "=?base64?" ~ () @trusted {
		return cast(string) Base64.encode(cast(const(ubyte)[]) value);
	}() ~ "?=";
}

/// Decode an `Mcp-Param-*` header value produced by `encodeHeaderValue`.
string decodeHeaderValue(string headerValue) @safe
{
	import std.base64 : Base64, Base64Exception;

	if (headerValue.length >= 11 && headerValue[0 .. 9] == "=?base64?"
			&& headerValue[$ - 2 .. $] == "?=")
	{
		const inner = headerValue[9 .. $ - 2];
		try
			return () @trusted { return cast(string) Base64.decode(inner); }();
		catch (Base64Exception)
			return headerValue;
	}
	return headerValue;
}

/// Whether a header value would corrupt the request line if written verbatim:
/// an embedded CR or LF lets the value terminate the current header and inject
/// further headers (or smuggle a request) into the outbound HTTP stream. The raw
/// socket request paths call this as a last line of defence before concatenating
/// a value onto the wire, so even a value that bypassed `encodeHeaderValue`
/// cannot break framing.
bool isHeaderValueUnsafe(string value) @safe nothrow @nogc
{
	foreach (char c; value)
		if (c == '\r' || c == '\n')
			return true;
	return false;
}

/// Whether a JSON Schema `type` value is one the draft permits an `x-mcp-header`
/// annotation to be applied to. Per `server/tools` #x-mcp-header, only the
/// primitive types `integer`, `string`, and `boolean` are allowed; `number` is
/// explicitly NOT permitted (its value may not round-trip through a header).
bool isPrimitiveHeaderType(string jsonSchemaType) @safe pure nothrow
{
	return jsonSchemaType == "integer" || jsonSchemaType == "string" || jsonSchemaType == "boolean";
}

/// Validate a single `x-mcp-header` value (the name portion of the resulting
/// `Mcp-Param-{name}` header) against the draft constraints, returning a
/// human-readable reason on violation or `null` when valid.
///
/// Per `server/tools` #x-mcp-header an `x-mcp-header` value:
/// * MUST NOT be empty;
/// * MUST match HTTP field-name token syntax (`1*tchar`, RFC 9110 §5.1);
/// * MUST NOT contain control characters, including CR (`\r`) or LF (`\n`).
///
/// Case-insensitive uniqueness across the whole schema is enforced separately by
/// `validateInputSchemaHeaders` (it is not a property of a value in isolation).
string validateHeaderName(string value) @safe pure nothrow
{
	if (value.length == 0)
		return "x-mcp-header value MUST NOT be empty";
	foreach (char c; value)
	{
		// RFC 9110 §5.1 tchar: "!#$%&'*+-.^_`|~" / DIGIT / ALPHA.
		// This excludes control characters (incl. CR/LF), spaces, and ':'.
		const bool isTchar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			|| (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%'
			|| c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.'
			|| c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
		if (!isTchar)
			return "x-mcp-header value '" ~ value
				~ "' is not a valid HTTP field-name token (1*tchar)";
	}
	return null;
}

/// ASCII-lowercase a string for case-insensitive comparison of header names.
private string asciiLowerName(string s) @safe pure nothrow
{
	char[] buf = new char[s.length];
	foreach (i, char c; s)
		buf[i] = (c >= 'A' && c <= 'Z') ? cast(char)(c + 32) : c;
	return () @trusted { return cast(string) buf; }();
}

/// A single `x-mcp-header` annotation discovered in a tool `inputSchema`,
/// together with the path of property keys to reach the annotated value.
struct ParamHeader
{
	string[] path; /// property keys from the root `inputSchema` to the annotated value
	string header; /// the resolved header name, e.g. `Mcp-Param-Region`
	string name; /// the raw `x-mcp-header` value (header suffix), e.g. `Region`
}

/// Collect every valid `x-mcp-header` annotation in a tool `inputSchema`,
/// recursing into nested `object` properties and `array` `items` schemas — the
/// draft permits the annotation "at any nesting depth within the inputSchema,
/// not only top-level properties". Annotations on non-primitive
/// (`number`/object/array) properties, or with an invalid value, are skipped
/// here; use `validateInputSchemaHeaders` to reject such schemas up front.
ParamHeader[] paramHeaders(Json inputSchema) @safe
{
	ParamHeader[] result;
	void walk(Json node, string[] path) @safe
	{
		if (node.type != Json.Type.object)
			return;
		if ("properties" in node && node["properties"].type == Json.Type.object)
		{
			() @trusted {
				foreach (string name, Json prop; node["properties"])
				{
					if (prop.type != Json.Type.object)
						continue;
					auto childPath = path ~ name;
					if ("x-mcp-header" in prop && prop["x-mcp-header"].type == Json.Type.string)
					{
						const hv = prop["x-mcp-header"].get!string;
						const ptype = ("type" in prop && prop["type"].type == Json.Type.string) ? prop["type"]
							.get!string : "";
						if (validateHeaderName(hv) is null && isPrimitiveHeaderType(ptype))
							result ~= ParamHeader(childPath, HttpHeader.paramPrefix ~ hv, hv);
					}
					walk(prop, childPath);
				}
			}();
		}
		// Object-form `items` (single schema) and array-form `items`/`prefixItems`
		// (tuple schemas, 2020-12). Path is passed through unchanged — array
		// element indices are not appended, matching the object-`items` case.
		foreach (key; ["items", "prefixItems"])
		{
			if (key !in node)
				continue;
			auto sub = node[key];
			if (sub.type == Json.Type.object)
				walk(sub, path);
			else if (sub.type == Json.Type.array)
			{
				() @trusted {
					foreach (Json elem; sub)
						if (elem.type == Json.Type.object)
							walk(elem, path);
				}();
			}
		}
	}

	walk(inputSchema, []);
	return result;
}

/// Validate every `x-mcp-header` annotation in a tool `inputSchema` against the
/// draft constraints (`server/tools` #x-mcp-header): non-empty, HTTP token
/// syntax, no CR/LF, primitive-only (`number` forbidden), and case-insensitive
/// uniqueness across the whole schema. Returns a human-readable reason on the
/// first violation, or `null` when every annotation is valid. Recurses to any
/// nesting depth.
string validateInputSchemaHeaders(Json inputSchema) @safe
{
	string err;
	bool[string] seen; // ASCII-lowercased header values already encountered
	void walk(Json node) @safe
	{
		if (err !is null || node.type != Json.Type.object)
			return;
		if ("properties" in node && node["properties"].type == Json.Type.object)
		{
			() @trusted {
				foreach (string name, Json prop; node["properties"])
				{
					if (err !is null)
						return;
					if (prop.type != Json.Type.object)
						continue;
					if ("x-mcp-header" in prop)
					{
						if (prop["x-mcp-header"].type != Json.Type.string)
						{
							err = "x-mcp-header value on '" ~ name ~ "' MUST be a string";
							return;
						}
						const hv = prop["x-mcp-header"].get!string;
						auto nameErr = validateHeaderName(hv);
						if (nameErr !is null)
						{
							err = nameErr;
							return;
						}
						const ptype = ("type" in prop && prop["type"].type == Json.Type.string) ? prop["type"]
							.get!string : "";
						if (!isPrimitiveHeaderType(ptype))
						{
							err = "x-mcp-header '" ~ hv ~ "' on '" ~ name
								~ "' may only be applied to primitive types"
								~ " (integer/string/boolean); type '" ~ ptype ~ "' is not permitted";
							return;
						}
						const lc = asciiLowerName(hv);
						if (lc in seen)
						{
							err = "x-mcp-header value '" ~ hv
								~ "' is not case-insensitively unique within the inputSchema";
							return;
						}
						seen[lc] = true;
					}
					walk(prop);
				}
			}();
		}
		// Object-form `items` and array-form `items`/`prefixItems` (tuple schemas).
		foreach (key; ["items", "prefixItems"])
		{
			if (err !is null || key !in node)
				continue;
			auto sub = node[key];
			if (sub.type == Json.Type.object)
				walk(sub);
			else if (sub.type == Json.Type.array)
			{
				() @trusted {
					foreach (Json elem; sub)
					{
						if (err !is null)
							return;
						if (elem.type == Json.Type.object)
							walk(elem);
					}
				}();
			}
		}
	}

	walk(inputSchema);
	return err;
}

/// Extract the `x-mcp-header` annotations from a tool `inputSchema`, returning a
/// map of (top-level) parameter name -> header name (`Mcp-Param-{name}`).
///
/// Retained for backward compatibility; only top-level, primitive-typed, valid
/// annotations appear. Nested annotations (which `validateInputSchemaHeaders`
/// accepts and `paramHeaders` surfaces) are silently omitted, so a schema whose
/// only annotations are nested validates yet yields an empty map. Prefer
/// `paramHeaders` (path-aware, any nesting depth) for new code.
deprecated("nested x-mcp-header annotations are dropped; use paramHeaders") string[string] paramHeaderMap(
		Json inputSchema) @safe
{
	string[string] map;
	foreach (ph; paramHeaders(inputSchema))
		if (ph.path.length == 1)
			map[ph.path[0]] = ph.header;
	return map;
}

// ===========================================================================
// Multi Round-Trip Requests (MRTR) — SEP-2322
// ===========================================================================

/// One unit of input the server needs from the client to continue (replacing a
/// server-initiated `sampling/createMessage`, `elicitation/create`, or
/// `roots/list` request).
/// The kind of server->client request an MRTR `InputRequest` stands in for.
/// Maps to the wire `type` discriminator (`"sampling"`/`"elicitation"`/`"roots"`).
enum InputKind
{
	sampling,
	elicitation,
	roots,
}

struct InputRequest
{
	string id; /// correlation id chosen by the server (the `InputRequests` map key)
	string type; /// "sampling" | "elicitation" | "roots"
	Json params = Json.emptyObject; /// the would-be request params

	/// The typed `InputKind` for this request's wire `type`, or null when the
	/// `type` is not one of the three recognised kinds.
	Nullable!InputKind kind() const @safe
	{
		switch (type)
		{
		case "sampling":
			return Nullable!InputKind(InputKind.sampling);
		case "elicitation":
			return Nullable!InputKind(InputKind.elicitation);
		case "roots":
			return Nullable!InputKind(InputKind.roots);
		default:
			return Nullable!InputKind.init;
		}
	}

	/// Build a `sampling` input-request from a typed `CreateMessageRequest` — no
	/// hand-built params `Json`.
	static InputRequest sampling(string id, CreateMessageRequest req) @safe
	{
		return InputRequest(id, "sampling", req.toJson());
	}

	/// Build a form-`elicitation` input-request from a message and an optional
	/// JSON Schema (`requestedSchema`). For a `requestedSchema` derived from a flat
	/// struct `T`, use `mcp.protocol.schema.elicitationRequest!T` (where
	/// reflection-driven schema generation lives, so this module stays free of any
	/// schema/reflection dependency).
	static InputRequest elicitation(string id, string message, Json requestedSchema = Json
			.undefined) @safe
	{
		Json p = Json.emptyObject;
		p["message"] = message;
		if (requestedSchema.type == Json.Type.object)
			p["requestedSchema"] = requestedSchema;
		return InputRequest(id, "elicitation", p);
	}

	/// Build a url-mode `elicitation` input-request: instead of a `requestedSchema`
	/// form, the client is directed to a `url` to gather input out-of-band and
	/// correlate the result via `elicitationId`. Mirrors
	/// `RequestContext.elicitUrl`'s invariants: `url` MUST be a non-empty valid
	/// absolute URI and `elicitationId` MUST be non-empty (throws otherwise).
	static InputRequest elicitationUrl(string id, string message, string url, string elicitationId) @safe
	{
		if (url.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty url");
		if (!isValidElicitationUrl(url))
			throw invalidParams("URL-mode elicitation requires a valid url (absolute URI): " ~ url);
		if (elicitationId.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty elicitationId");
		Json p = Json.emptyObject;
		p["mode"] = "url";
		p["message"] = message;
		p["url"] = url;
		p["elicitationId"] = elicitationId;
		return InputRequest(id, "elicitation", p);
	}

	/// Build a `roots` input-request (no params).
	static InputRequest roots(string id) @safe
	{
		return InputRequest(id, "roots", Json.emptyObject);
	}

	/// Parse this request's `params` as a typed `CreateMessageRequest` — the typed
	/// reader counterpart to the `sampling` builder. Only meaningful when
	/// `kind == InputKind.sampling`.
	CreateMessageRequest asSampling() @safe
	{
		return CreateMessageRequest.fromJson(params);
	}

	/// Read `params["message"]` as a string (`""` when absent) — the reader
	/// counterpart to the `elicitation` builder, for `kind == InputKind.elicitation`.
	string elicitationMessage() @safe
	{
		if (params.type == Json.Type.object && "message" in params
				&& params["message"].type == Json.Type.string)
			return params["message"].get!string;
		return "";
	}

	/// Read `params["requestedSchema"]` (`Json.undefined` when absent) — the
	/// reader counterpart to the `elicitation` builder, for
	/// `kind == InputKind.elicitation`.
	Json requestedSchema() @safe
	{
		if (params.type == Json.Type.object && "requestedSchema" in params)
			return params["requestedSchema"];
		return Json.undefined;
	}

	/// Read `params["url"]` as a string (`""` when absent) — the reader
	/// counterpart to the `elicitationUrl` builder. Non-empty only for url-mode
	/// elicitation requests (`params["mode"] == "url"`).
	string elicitationUrl() @safe
	{
		if (params.type == Json.Type.object && "url" in params
				&& params["url"].type == Json.Type.string)
			return params["url"].get!string;
		return "";
	}

	/// Read `params["elicitationId"]` as a string (`""` when absent) — the reader
	/// counterpart to the `elicitationUrl` builder.
	string elicitationIdField() @safe
	{
		if (params.type == Json.Type.object && "elicitationId" in params
				&& params["elicitationId"].type == Json.Type.string)
			return params["elicitationId"].get!string;
		return "";
	}

	/// The spec wire `method` for this request's `type`: an `InputRequests` value
	/// is a request object whose `method` is the full JSON-RPC method name
	/// (`elicitation/create`, `sampling/createMessage`, `roots/list`) — not the
	/// short internal discriminator.
	static string methodForType(string type) @safe pure nothrow
	{
		switch (type)
		{
		case "elicitation":
			return "elicitation/create";
		case "sampling":
			return "sampling/createMessage";
		case "roots":
			return "roots/list";
		default:
			return type;
		}
	}

	/// Inverse of `methodForType`: recover the short internal discriminator from
	/// the spec wire `method`.
	static string typeForMethod(string method) @safe pure nothrow
	{
		switch (method)
		{
		case "elicitation/create":
			return "elicitation";
		case "sampling/createMessage":
			return "sampling";
		case "roots/list":
			return "roots";
		default:
			return method;
		}
	}

	/// Serialize this request as an `InputRequests` *value* (the request object):
	/// a `{ method, params }` object. The `id` is the surrounding map key and is
	/// therefore not part of the value (see `InputRequiredResult.toJson`).
	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["method"] = methodForType(type);
		j["params"] = params;
		return j;
	}

	/// Parse an `InputRequests` value (request object) given its map `key` (the
	/// server-assigned id).
	static InputRequest fromJson(string key, Json j) @safe
	{
		InputRequest r;
		r.id = key;
		r.type = ("method" in j && j["method"].type == Json.Type.string)
			? typeForMethod(j["method"].get!string) : "";
		if ("params" in j)
			r.params = j["params"];
		return r;
	}
}

/// A result that asks the client to gather input and retry the original request
/// with matching `inputResponses`.
struct InputRequiredResult
{
	InputRequest[] inputRequests;
	/// SEP-2322 `requestState`: an opaque, server-owned string that lets a
	/// stateless server reconstruct its in-progress work on the retry. When
	/// non-empty it is emitted as a top-level `requestState` field; the client
	/// MUST echo it back verbatim (and MUST NOT inspect or modify it).
	string requestState;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		// Base draft Result mandates a `resultType` discriminator on every
		// result; an InputRequiredResult declares "input_required" so the
		// client knows to gather input and retry rather than treat this as a
		// completed response.
		j["resultType"] = "input_required";
		emitInputRequired(j, inputRequests, requestState);
		return j;
	}

	static InputRequiredResult fromJson(Json j) @safe
	{
		InputRequiredResult r;
		parseInputRequired(j, r.inputRequests, r.requestState);
		return r;
	}
}

/// Emit the shared MRTR (SEP-2322) `InputRequiredResult` payload onto `j`: the
/// `inputRequests` map plus the optional top-level `requestState`. This is the
/// glue common to `InputRequiredResult.toJson` and `CallToolResult.toJson`; it
/// deliberately does NOT write the `resultType` discriminator (a `CallToolResult`
/// stamps that elsewhere), so callers add it themselves when required.
void emitInputRequired(ref Json j, const(InputRequest)[] requests, string requestState) @safe
{
	// SEP-2322: `inputRequests` is an `InputRequests` object — a map whose
	// keys are the server-assigned ids and whose values are request objects
	// (`{ method, params }`), not an array.
	j["inputRequests"] = inputRequestsToJson(requests);
	// SEP-2322: `requestState` is an optional top-level field; omit it when
	// empty so the client knows not to echo one back.
	if (requestState.length)
		j["requestState"] = requestState;
}

/// Parse the shared MRTR (SEP-2322) `InputRequiredResult` payload from `j` into
/// `requests` and `requestState`. Inverse of `emitInputRequired`; shared by
/// `InputRequiredResult.fromJson` and `CallToolResult.fromJson`. Both reads are
/// guarded, so a `j` carrying neither field leaves the outputs untouched.
void parseInputRequired(Json j, ref InputRequest[] requests, ref string requestState) @safe
{
	if ("inputRequests" in j && j["inputRequests"].type == Json.Type.object)
		requests = inputRequestsFromJson(j["inputRequests"]);
	tryGet(j, "requestState", requestState);
}

/// Serialize a list of `InputRequest`s as a spec `InputRequests` object: a map
/// keyed by each request's server-assigned `id`, with `{ method, params }`
/// request objects as values (SEP-2322, draft basic/utilities/mrtr).
Json inputRequestsToJson(const(InputRequest)[] requests) @safe
{
	Json obj = Json.emptyObject;
	foreach (r; requests)
		obj[r.id] = r.toJson();
	return obj;
}

/// Parse a spec `InputRequests` object (map keyed by id) back into the internal
/// `InputRequest` list. A non-object value yields no requests.
InputRequest[] inputRequestsFromJson(Json j) @safe
{
	InputRequest[] requests;
	if (j.type == Json.Type.object)
	{
		// `Json.opApply` is `@system`; iterating a plain object is safe here.
		() @trusted {
			foreach (string key, Json value; j)
				requests ~= InputRequest.fromJson(key, value);
		}();
	}
	return requests;
}

/// A client's answer to one `InputRequest`, supplied on the retried request as
/// a value of the top-level `params.inputResponses` map (SEP-2322).
struct InputResponse
{
	string id; /// the originating `InputRequest.id` (the `InputResponses` map key)
	Json result = Json.emptyObject; /// the bare client result (the map value)
}

/// Serialize a list of `InputResponse`s as a spec `InputResponses` object: a map
/// whose keys are the originating `InputRequest.id`s and whose values are the
/// *bare* client results (e.g. `{action, content}` or
/// `{role, content, model, stopReason}`) — not `{id, result}` wrappers and not a
/// JSON array (SEP-2322, draft basic/utilities/mrtr).
Json inputResponsesToJson(const(InputResponse)[] responses) @safe
{
	Json obj = Json.emptyObject;
	foreach (resp; responses)
		obj[resp.id] = resp.result;
	return obj;
}

/// Read the input responses a client attached to a retried request, keyed by
/// the originating `InputRequest.id`. Per SEP-2322 the wire location is the
/// top-level `params.inputResponses` field (an `InputResponses` map, id -> bare
/// client result) — NOT `_meta`.
Json[string] readInputResponses(Json params) @safe
{
	Json[string] out_;
	if (params.type != Json.Type.object || "inputResponses" !in params)
		return out_;
	auto map = params["inputResponses"];
	if (map.type != Json.Type.object)
		return out_;
	// `Json.opApply` is `@system`; iterating a plain object is safe here.
	() @trusted {
		foreach (string key, Json value; map)
			out_[key] = value;
	}();
	return out_;
}

/// Read the opaque SEP-2322 `requestState` the client echoed back on a retried
/// request. It lives in the top-level `params.requestState` field. Returns an
/// empty string when absent. The server owns this value (the client treats it
/// as opaque), so servers MUST validate it as untrusted input.
string readRequestState(Json params) @safe
{
	if (params.type != Json.Type.object || "requestState" !in params)
		return "";
	auto rs = params["requestState"];
	if (rs.type != Json.Type.string)
		return "";
	return rs.get!string;
}

unittest  // InputRequiredResult.toJson carries resultType:"input_required"
{
	InputRequiredResult r;
	r.inputRequests = [InputRequest("date", "elicitation", Json.emptyObject)];
	auto j = r.toJson();
	// Base draft Result mandates a resultType discriminator on every result;
	// an InputRequiredResult uses "input_required".
	assert("resultType" in j);
	assert(j["resultType"].get!string == "input_required");
	assert("inputRequests" in j);
}

unittest  // SEP-2322: inputRequests serializes as a map keyed by id, value {method, params}
{
	InputRequiredResult r;
	r.inputRequests = [
		InputRequest("github_login", "elicitation", Json(["message": Json("hi")]))
	];
	auto j = r.toJson();
	// The `InputRequests` field MUST be a JSON object (map), not an array.
	assert(j["inputRequests"].type == Json.Type.object);
	// Keyed by the server-assigned id.
	assert("github_login" in j["inputRequests"]);
	auto value = j["inputRequests"]["github_login"];
	// Value is a request object with the full JSON-RPC `method`, no `id`/`type`.
	assert(value["method"].get!string == "elicitation/create");
	assert("id" !in value);
	assert("type" !in value);
	assert(value["params"]["message"].get!string == "hi");
}

unittest  // emitInputRequired/parseInputRequired round-trip the shared MRTR glue
{
	Json j = Json.emptyObject;
	auto reqs = [InputRequest("date", "elicitation", Json.emptyObject)];
	emitInputRequired(j, reqs, "opaque-state");
	// resultType is NOT written by the shared helper (callers stamp it).
	assert("resultType" !in j);
	assert(j["inputRequests"].type == Json.Type.object);
	assert(j["requestState"].get!string == "opaque-state");

	InputRequest[] outReqs;
	string outState;
	parseInputRequired(j, outReqs, outState);
	assert(outReqs.length == 1);
	assert(outReqs[0].id == "date");
	assert(outState == "opaque-state");
}

unittest  // emitInputRequired omits an empty requestState
{
	Json j = Json.emptyObject;
	emitInputRequired(j, [InputRequest("x", "roots", Json.emptyObject)], "");
	assert("requestState" !in j);
}

unittest  // SEP-2322: sampling/roots methods map to their full JSON-RPC names
{
	InputRequiredResult r;
	r.inputRequests = [
		InputRequest("s1", "sampling", Json.emptyObject),
		InputRequest("r1", "roots", Json.emptyObject)
	];
	auto j = r.toJson();
	assert(j["inputRequests"]["s1"]["method"].get!string == "sampling/createMessage");
	assert(j["inputRequests"]["r1"]["method"].get!string == "roots/list");
}

unittest  // InputRequest.sampling builder sets the sampling type + request params
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage;
	import mcp.protocol.types : Content;

	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 32;
	auto ir = InputRequest.sampling("s1", req);
	assert(ir.id == "s1");
	assert(ir.type == "sampling");
	assert(ir.params == req.toJson());
	assert(ir.kind.get == InputKind.sampling);
}

unittest  // InputRequest.elicitation builder sets message + requestedSchema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.type == "elicitation");
	assert(ir.params["message"].get!string == "Your name?");
	assert(ir.params["requestedSchema"] == schema);
	assert(ir.kind.get == InputKind.elicitation);
}

unittest  // InputRequest.roots builder sets the roots type with empty params
{
	auto ir = InputRequest.roots("r1");
	assert(ir.type == "roots");
	assert(ir.kind.get == InputKind.roots);
}

unittest  // InputRequest.kind returns null for an unrecognised type
{
	auto ir = InputRequest("x", "bogus", Json.emptyObject);
	assert(ir.kind.isNull);
}

unittest  // InputRequest.asSampling reads back the CreateMessageRequest builder input
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage;
	import mcp.protocol.types : Content;

	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 64;
	req.systemPrompt = "be terse";
	auto ir = InputRequest.sampling("s1", req);

	auto back = ir.asSampling();
	assert(back.messages.length == 1);
	assert(back.messages[0].content.text == "hi");
	assert(back.maxTokens.get == 64);
	assert(back.systemPrompt.get == "be terse");
}

unittest  // InputRequest.elicitationMessage reads back the elicitation builder message
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.elicitationMessage() == "Your name?");
}

unittest  // InputRequest.elicitationMessage is empty when no message is present
{
	auto ir = InputRequest.roots("r1");
	assert(ir.elicitationMessage() == "");
}

unittest  // InputRequest.requestedSchema reads back the elicitation builder schema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.requestedSchema() == schema);
}

unittest  // InputRequest.requestedSchema is undefined when no schema is present
{
	auto ir = InputRequest.elicitation("e1", "Just a message");
	assert(ir.requestedSchema().type == Json.Type.undefined);
}

unittest  // MRTR InputRequiredResult round-trips and input responses parse
{
	InputRequiredResult ir;
	ir.inputRequests = [
		InputRequest("r1", "elicitation", Json(["message": Json("hi")]))
	];
	auto back = InputRequiredResult.fromJson(ir.toJson());
	assert(back.inputRequests.length == 1);
	assert(back.inputRequests[0].id == "r1");
	assert(back.inputRequests[0].type == "elicitation");
	assert(back.inputRequests[0].params["message"].get!string == "hi");

	Json params = Json.emptyObject;
	params["inputResponses"] = inputResponsesToJson([
		InputResponse("r1", Json(["action": Json("accept")]))
	]);
	auto resps = readInputResponses(params);
	assert("r1" in resps);
	assert(resps["r1"]["action"].get!string == "accept");
}

unittest  // SEP-2322: inputResponses is a map keyed by id with bare result values
{
	// The spec `InputResponses` field is a JSON object whose keys are the
	// server-assigned `InputRequest` ids and whose values are the *bare* client
	// results (e.g. `{action, content}`) — not `{id, result}` wrapper objects,
	// and not a JSON array.
	auto obj = inputResponsesToJson([
		InputResponse("github_login", Json([
			"action": Json("accept"),
			"content": Json(["name": Json("octocat")])
		]))
	]);
	assert(obj.type == Json.Type.object);
	assert("github_login" in obj);
	auto value = obj["github_login"];
	// The value is the bare result, with no `id`/`result` wrapper.
	assert("id" !in value);
	assert("result" !in value);
	assert(value["action"].get!string == "accept");
	assert(value["content"]["name"].get!string == "octocat");
}

unittest  // SEP-2322: readInputResponses parses the spec map shape keyed by id
{
	Json responses = Json.emptyObject;
	responses["date"] = Json(["action": Json("accept")]);
	Json params = Json.emptyObject;
	// SEP-2322: inputResponses is a top-level params field, not under _meta.
	params["inputResponses"] = responses;

	auto parsed = readInputResponses(params);
	assert("date" in parsed);
	// The parsed value is the bare result the client supplied.
	assert(parsed["date"]["action"].get!string == "accept");
	// Nothing under _meta is consulted.
	assert("_meta" !in params);
}

unittest  // SEP-2322: inputResponses lives in params, NOT under params._meta
{
	// Regression guard for the wire location. A spec server reads
	// `params.inputResponses`; the invented reserved `_meta` key must not exist.
	Json responses = Json.emptyObject;
	responses["github_login"] = Json([
		"action": Json("accept"),
		"content": Json(["name": Json("octocat")])
	]);

	// Placed at top level: parsed.
	Json good = Json.emptyObject;
	good["name"] = "get_weather";
	good["inputResponses"] = responses;
	auto parsed = readInputResponses(good);
	assert("github_login" in parsed);
	assert(parsed["github_login"]["content"]["name"].get!string == "octocat");

	// Placed under _meta (the old, invented shape): ignored.
	Json bad = Json.emptyObject;
	Json meta = Json.emptyObject;
	meta["io.modelcontextprotocol/inputResponses"] = responses;
	bad["_meta"] = meta;
	assert(readInputResponses(bad).length == 0);
}

unittest  // SEP-2322: InputRequiredResult carries the opaque requestState round-trip
{
	InputRequiredResult ir;
	ir.inputRequests = [
		InputRequest("github_login", "elicitation", Json.emptyObject)
	];
	ir.requestState = "foo";
	auto j = ir.toJson();
	// requestState is a top-level field on the result, alongside inputRequests.
	assert(j["requestState"].get!string == "foo");
	auto back = InputRequiredResult.fromJson(j);
	assert(back.requestState == "foo");
}

unittest  // SEP-2322: an empty requestState is omitted from the wire result
{
	InputRequiredResult ir;
	ir.inputRequests = [InputRequest("r1", "elicitation", Json.emptyObject)];
	auto j = ir.toJson();
	// The client MUST NOT echo a requestState the server never sent.
	assert("requestState" !in j);
}

unittest  // SEP-2322: readRequestState reads the opaque top-level params.requestState
{
	Json params = Json.emptyObject;
	params["name"] = "get_weather";
	params["requestState"] = "eyJyZXNvbHV0aW9uIjoiRHVwbGljYXRlIn0";
	assert(readRequestState(params) == "eyJyZXNvbHV0aW9uIjoiRHVwbGljYXRlIn0");

	// Absent / wrong type -> empty.
	assert(readRequestState(Json.emptyObject) == "");
	Json wrong = Json.emptyObject;
	wrong["requestState"] = 7;
	assert(readRequestState(wrong) == "");
}

unittest  // header value codec: plain ASCII passes through; others base64
{
	assert(encodeHeaderValue("us-west1") == "us-west1");
	assert(decodeHeaderValue("us-west1") == "us-west1");

	// non-ASCII -> base64 sentinel, round-trips
	auto enc = encodeHeaderValue("Hello, 世界");
	assert(enc.length > 9 && enc[0 .. 9] == "=?base64?");
	assert(decodeHeaderValue(enc) == "Hello, 世界");

	// leading/trailing space and sentinel-looking values are encoded
	assert(encodeHeaderValue(" padded ")[0 .. 9] == "=?base64?");
	assert(decodeHeaderValue(encodeHeaderValue(" padded ")) == " padded ");
	assert(decodeHeaderValue(encodeHeaderValue("=?base64?x?=")) == "=?base64?x?=");
}

unittest  // decodeHeaderValue tolerates sentinel-framed but invalid base64
{
	// Valid sentinel framing with an undecodable body must not throw; the raw
	// value is returned so downstream comparison yields a clean mismatch.
	const malformed = "=?base64?@@@@?=";
	assert(decodeHeaderValue(malformed) == malformed);
}

unittest  // encodeHeaderValue neutralises CR/LF, so an encoded value is wire-safe
{
	// A URI carrying CR/LF must not survive as raw control bytes in the output;
	// it is base64-wrapped and the result carries no CR/LF.
	const evil = "file:///x\r\nMcp-Injected: 1";
	const enc = encodeHeaderValue(evil);
	assert(enc[0 .. 9] == "=?base64?");
	assert(!isHeaderValueUnsafe(enc));
	assert(decodeHeaderValue(enc) == evil);
}

unittest  // isHeaderValueUnsafe flags only embedded CR/LF
{
	assert(isHeaderValueUnsafe("a\rb"));
	assert(isHeaderValueUnsafe("a\nb"));
	assert(isHeaderValueUnsafe("trailing\r\n"));
	assert(!isHeaderValueUnsafe("file:///a b"));
	assert(!isHeaderValueUnsafe("us-west1"));
	assert(!isHeaderValueUnsafe(""));
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

unittest  // isReservedMetaPrefix(2025-11-25/draft): keeps the narrower second-label rule
{
	import mcp.protocol.versions : ProtocolVersion;

	// First-position token is NOT reserved under 2025-11-25/draft (only the
	// second label counts), so the draft/2025-11-25 wire behaviour is unchanged.
	assert(!isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	assert(!isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.modern));
	// `com.example.mcp/` has `mcp` as its THIRD label, so it is NOT reserved under
	// the second-label rule (the 2025-11-25 spec's own counter-example).
	assert(!isReservedMetaPrefix("com.example.mcp/key", ProtocolVersion.v2025_11_25));
	assert(!isReservedMetaPrefix("com.example.mcp/key", ProtocolVersion.modern));
	// Second-label token IS reserved under both.
	assert(isReservedMetaPrefix("io.modelcontextprotocol/key", ProtocolVersion.v2025_11_25));
	assert(isReservedMetaPrefix("com.mcp/key", ProtocolVersion.modern));
	// The clean divergence: `modelcontextprotocol.io/` is reserved under 2025-06-18
	// (first-position token + trailing label) but NOT under 2025-11-25 (second
	// label is `io`).
	assert(isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_06_18)
			&& !isReservedMetaPrefix("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	// The version-agnostic overload must match the 2025-11-25/draft rule exactly.
	assert(isReservedMetaPrefix("io.modelcontextprotocol/key",
			ProtocolVersion.v2025_11_25) == isReservedMetaPrefix("io.modelcontextprotocol/key"));
	assert(isReservedMetaPrefix("modelcontextprotocol.io/key",
			ProtocolVersion.modern) == isReservedMetaPrefix("modelcontextprotocol.io/key"));
}

unittest  // isUserMetaKeyAllowed(2025-06-18) rejects first-position mcp-token prefixes
{
	import mcp.protocol.versions : ProtocolVersion;

	// Reserved under 2025-06-18 (first-position token + trailing label, second
	// label not an mcp-token) -> disallowed on a 2025-06-18 connection.
	assert(!isUserMetaKeyAllowed("modelcontextprotocol.io/key", ProtocolVersion.v2025_06_18));
	assert(!isUserMetaKeyAllowed("mcp.dev/key", ProtocolVersion.v2025_06_18));
	// But allowed under 2025-11-25/draft, where those prefixes are not reserved
	// (their second label is `io` / `dev`, not an mcp-token).
	assert(isUserMetaKeyAllowed("modelcontextprotocol.io/key", ProtocolVersion.v2025_11_25));
	assert(isUserMetaKeyAllowed("mcp.dev/key", ProtocolVersion.modern));
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

deprecated unittest  // paramHeaderMap reads x-mcp-header annotations
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	props["query"] = Json(["type": Json("string")]);
	schema["properties"] = props;

	auto m = paramHeaderMap(schema);
	assert("region" in m);
	assert(m["region"] == "Mcp-Param-Region");
	assert("query" !in m);
}

deprecated unittest  // paramHeaderMap silently drops nested annotations (use paramHeaders)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = Json([
		"region": Json(["type": Json("string"), "x-mcp-header": Json("Region")])
	]);
	schema["properties"] = Json(["filter": nested]);

	// The schema is valid and the annotation is path-aware-visible, ...
	assert(validateInputSchemaHeaders(schema) is null);
	assert(paramHeaders(schema).length == 1);
	// ... but the legacy map form drops the nested annotation entirely.
	assert(paramHeaderMap(schema).length == 0);
}

unittest  // validateHeaderName: empty value rejected (draft x-mcp-header MUST NOT be empty)
{
	assert(validateHeaderName("") !is null);
}

unittest  // validateHeaderName: valid token passes
{
	assert(validateHeaderName("Region") is null);
	assert(validateHeaderName("X-Trace-Id_v2.1") is null);
}

unittest  // validateHeaderName: CR/LF and control chars rejected (no header injection)
{
	assert(validateHeaderName("Re\rgion") !is null);
	assert(validateHeaderName("Re\ngion") !is null);
	assert(validateHeaderName("Re\x01gion") !is null);
}

unittest  // validateHeaderName: space and colon are not tchar
{
	assert(validateHeaderName("My Region") !is null);
	assert(validateHeaderName("Region:") !is null);
}

unittest  // isPrimitiveHeaderType: integer/string/boolean allowed, number/object/array not
{
	assert(isPrimitiveHeaderType("integer"));
	assert(isPrimitiveHeaderType("string"));
	assert(isPrimitiveHeaderType("boolean"));
	assert(!isPrimitiveHeaderType("number"));
	assert(!isPrimitiveHeaderType("object"));
	assert(!isPrimitiveHeaderType("array"));
}

unittest  // validateInputSchemaHeaders: a valid primitive annotation passes
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	props["limit"] = Json([
		"type": Json("integer"),
		"x-mcp-header": Json("Limit")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) is null);
}

unittest  // validateInputSchemaHeaders: number-typed annotation is rejected (number NOT permitted)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: empty x-mcp-header value rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json(["type": Json("string"), "x-mcp-header": Json("")]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: CR/LF in value rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Re\r\ngion")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: case-insensitively duplicate values rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["a"] = Json(["type": Json("string"), "x-mcp-header": Json("Region")]);
	props["b"] = Json(["type": Json("string"), "x-mcp-header": Json("region")]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: detects duplicate across nesting depths
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nestedProps = Json.emptyObject;
	nestedProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = nestedProps;
	Json props = Json.emptyObject;
	props["top"] = Json(["type": Json("string"), "x-mcp-header": Json("REGION")]);
	props["obj"] = nested;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // paramHeaders: recurses into nested object properties (any nesting depth)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nestedProps = Json.emptyObject;
	nestedProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = nestedProps;
	Json props = Json.emptyObject;
	props["filters"] = nested;
	schema["properties"] = props;

	auto phs = paramHeaders(schema);
	assert(phs.length == 1);
	assert(phs[0].path == ["filters", "region"]);
	assert(phs[0].header == "Mcp-Param-Region");
}

unittest  // paramHeaders: recurses into array items schemas
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json itemProps = Json.emptyObject;
	itemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Tag")
	]);
	Json items = Json.emptyObject;
	items["type"] = "object";
	items["properties"] = itemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = items;
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;

	auto phs = paramHeaders(schema);
	assert(phs.length == 1);
	assert(phs[0].path == ["entries", "tag"]);
	assert(phs[0].header == "Mcp-Param-Tag");
}

unittest  // paramHeaders: number-typed annotations are skipped (not collected)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	schema["properties"] = props;
	assert(paramHeaders(schema).length == 0);
}

unittest  // paramHeaders: collects annotations under array-form (tuple) items
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Tag")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = Json([elem]); // array-form (tuple) items
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;

	auto phs = paramHeaders(schema);
	assert(phs.length == 1);
	assert(phs[0].path == ["entries", "tag"]);
	assert(phs[0].header == "Mcp-Param-Tag");
}

unittest  // paramHeaders: collects annotations under prefixItems element schemas
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["prefixItems"] = Json([elem]);
	Json props = Json.emptyObject;
	props["coords"] = arr;
	schema["properties"] = props;

	auto phs = paramHeaders(schema);
	assert(phs.length == 1);
	assert(phs[0].path == ["coords", "region"]);
	assert(phs[0].header == "Mcp-Param-Region");
}

unittest  // validateInputSchemaHeaders: rejects CR/LF header on array-form items element
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Ta\r\ng")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = Json([elem]);
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: rejects number-typed header on prefixItems element
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["prefixItems"] = Json([elem]);
	Json props = Json.emptyObject;
	props["coords"] = arr;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // InputRequest.elicitationUrl builds url-mode params with the four fields
{
	auto ir = InputRequest.elicitationUrl("e1", "Authorize access",
			"https://example.com/consent", "elic-123");
	assert(ir.type == "elicitation");
	assert(ir.kind.get == InputKind.elicitation);
	assert(ir.params["mode"].get!string == "url");
	assert(ir.params["message"].get!string == "Authorize access");
	assert(ir.params["url"].get!string == "https://example.com/consent");
	assert(ir.params["elicitationId"].get!string == "elic-123");
}

unittest  // InputRequest.elicitationUrl readers round-trip url and elicitationId
{
	auto ir = InputRequest.elicitationUrl("e1", "msg", "https://example.com/consent", "elic-123");
	assert(ir.elicitationUrl() == "https://example.com/consent");
	assert(ir.elicitationIdField() == "elic-123");
	assert(ir.elicitationMessage() == "msg");
}

unittest  // InputRequest.elicitationUrl rejects empty url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(InputRequest.elicitationUrl("e", "m", "", "elic-1"));
}

unittest  // InputRequest.elicitationUrl rejects a malformed (non-absolute) url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(InputRequest.elicitationUrl("e", "m", "not a url", "elic-1"));
}

unittest  // InputRequest.elicitationUrl rejects empty elicitationId
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(InputRequest.elicitationUrl("e", "m", "https://example.com", ""));
}

unittest  // InputRequest.fromJson: non-string "method" field is treated as unknown type
{
	// A peer may emit a non-string value for "method" (e.g. a number); the parser
	// must not throw a JSONException — it should degrade gracefully to an empty type.
	Json j = Json.emptyObject;
	j["method"] = Json(99); // integer, not a string
	j["params"] = Json.emptyObject;
	auto r = InputRequest.fromJson("req-1", j);
	assert(r.id == "req-1");
	assert(r.type == ""); // unknown type, not a crash
}
