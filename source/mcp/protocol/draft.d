module mcp.protocol.draft;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.capabilities;

@safe:

/// Reserved `_meta` keys defined by the draft (2026-07-28) revision.
enum MetaKey : string
{
    protocolVersion = "io.modelcontextprotocol/protocolVersion",
    clientInfo = "io.modelcontextprotocol/clientInfo",
    clientCapabilities = "io.modelcontextprotocol/clientCapabilities",
    logLevel = "io.modelcontextprotocol/logLevel",
    subscriptionId = "io.modelcontextprotocol/subscriptionId",
    inputResponses = "io.modelcontextprotocol/inputResponses",
}

// ===========================================================================
// _meta key-name validation (basic/index, `_meta` Key name format)
// ===========================================================================

/// A `_meta` key is `[<prefix>]<name>`. The optional `<prefix>` is a series of
/// dot-separated labels followed by a `/`. Each label MUST start with a letter
/// and end with a letter or digit (interior may contain hyphens). The `<name>`
/// MUST start and end with an alphanumeric character; the interior may also
/// contain `-`, `_`, and `.`.
///
/// Prefixes whose second label is `modelcontextprotocol` or `mcp` are reserved
/// for MCP use (see `isReservedMetaPrefix`).
bool isValidMetaKey(string key) @safe pure nothrow
{
    if (key.length == 0)
        return false;

    string prefix;
    string name;
    // The prefix, if present, is everything up to and including the final '/'.
    ptrdiff_t slash = -1;
    foreach (i, char c; key)
        if (c == '/')
            slash = i;
    if (slash >= 0)
    {
        prefix = key[0 .. slash]; // labels without the trailing slash
        name = key[slash + 1 .. $];
    }
    else
    {
        name = key;
    }

    if (slash >= 0 && !isValidMetaPrefixLabels(prefix))
        return false;
    return isValidMetaName(name);
}

/// Validate the label portion of a prefix (everything before the trailing `/`).
/// Labels are dot-separated; each MUST start with a letter and end with a letter
/// or digit, and may contain hyphens in the interior.
private bool isValidMetaPrefixLabels(string labels) @safe pure nothrow
{
    if (labels.length == 0)
        return false; // a bare "/name" has an empty prefix, which is invalid
    size_t start = 0;
    bool any = false;
    for (size_t i = 0; i <= labels.length; i++)
    {
        if (i == labels.length || labels[i] == '.')
        {
            if (!isValidMetaLabel(labels[start .. i]))
                return false;
            any = true;
            start = i + 1;
        }
    }
    return any;
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
    if (name.length == 0)
        return false;
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

/// Whether a `_meta` key's prefix is reserved for MCP use: the second label of
/// the prefix is `modelcontextprotocol` or `mcp` (e.g. `io.modelcontextprotocol/`,
/// `com.mcp/`). Such prefixes MUST NOT be used by non-protocol code.
bool isReservedMetaPrefix(string key) @safe pure nothrow
{
    ptrdiff_t slash = -1;
    foreach (i, char c; key)
        if (c == '/')
            slash = i;
    if (slash < 0)
        return false;
    auto labels = key[0 .. slash];

    // Collect the second dot-separated label, if any.
    size_t start = 0;
    size_t idx = 0;
    string second;
    bool haveSecond = false;
    for (size_t i = 0; i <= labels.length; i++)
    {
        if (i == labels.length || labels[i] == '.')
        {
            if (idx == 1)
            {
                second = labels[start .. i];
                haveSecond = true;
                break;
            }
            idx++;
            start = i + 1;
        }
    }
    if (!haveSecond)
        return false;
    return second == "modelcontextprotocol" || second == "mcp";
}

/// Validate a user-supplied `_meta` key for attachment: it MUST be a
/// well-formed key (`isValidMetaKey`) and MUST NOT use an MCP-reserved prefix
/// (`isReservedMetaPrefix`). Returns `true` if the key is safe to use.
bool isUserMetaKeyAllowed(string key) @safe pure nothrow
{
    return isValidMetaKey(key) && !isReservedMetaPrefix(key);
}

/// Stamp the draft `io.modelcontextprotocol/subscriptionId` (`MetaKey.subscriptionId`)
/// into `params._meta` of a JSON-RPC notification and return it, leaving the
/// original untouched. Per draft basic/utilities/subscriptions every notification
/// delivered on a `subscriptions/listen` stream MUST carry the listen request's id
/// as `subscriptionId` in `_meta`, so clients can correlate the notification with
/// the listen request that established the stream — this is the producer for that
/// key. `subscriptionId` is the (string-rendered) JSON-RPC id of the originating
/// `subscriptions/listen` request. An empty `subscriptionId` is a no-op (the
/// notification is returned unchanged). Notifications carry their payload under
/// `params`, so the key is nested as `params._meta.<subscriptionId>`.
Json withSubscriptionId(Json notification, string subscriptionId) @safe
{
    if (subscriptionId.length == 0)
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
    auto stamped = withSubscriptionId(n, "listen-7");
    assert(stamped["params"]["_meta"][MetaKey.subscriptionId].get!string == "listen-7");
    // The original is left untouched.
    assert("params" !in n);
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
    auto stamped = withSubscriptionId(n, "id-42");
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
    auto same = withSubscriptionId(n, "");
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
        if (MetaKey.clientInfo in meta)
            m.clientInfo = Implementation.fromJson(meta[MetaKey.clientInfo]);
        if (MetaKey.clientCapabilities in meta)
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
                r.protocolVersions ~= arr[i].get!string;
        }
        if ("capabilities" in j)
            r.capabilities = ServerCapabilities.fromJson(j["capabilities"]);
        if ("serverInfo" in j)
            r.serverInfo = Implementation.fromJson(j["serverInfo"]);
        if ("instructions" in j && j["instructions"].type == Json.Type.string)
            r.instructions = j["instructions"].get!string;
        return r;
    }
}

/// Whether a shared (public) or per-client (private) cache may hold a result.
enum CacheScope : string
{
    public_ = "public",
    private_ = "private",
}

/// Attach the draft `CacheableResult` fields (`ttlMs`, `cacheScope`) to a result
/// object. A freshness hint for clients/intermediaries that complements
/// `listChanged` notifications.
Json withCache(Json result, long ttlMs, CacheScope scope_ = CacheScope.public_) @safe
{
    if (result.type != Json.Type.object)
        return result;
    result["ttlMs"] = ttlMs;
    result["cacheScope"] = cast(string) scope_;
    return result;
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
    import std.base64 : Base64;

    if (headerValue.length >= 11 && headerValue[0 .. 9] == "=?base64?"
            && headerValue[$ - 2 .. $] == "?=")
    {
        const inner = headerValue[9 .. $ - 2];
        return () @trusted { return cast(string) Base64.decode(inner); }();
    }
    return headerValue;
}

/// Extract the `x-mcp-header` annotations from a tool `inputSchema`, returning a
/// map of parameter name -> header name (`Mcp-Param-{value}`). Only top-level
/// properties are inspected here.
string[string] paramHeaderMap(Json inputSchema) @safe
{
    string[string] map;
    if (inputSchema.type != Json.Type.object || "properties" !in inputSchema)
        return map;
    auto props = inputSchema["properties"];
    if (props.type != Json.Type.object)
        return map;
    () @trusted {
        foreach (string name, Json prop; props)
            if (prop.type == Json.Type.object && "x-mcp-header" in prop
                    && prop["x-mcp-header"].type == Json.Type.string)
                map[name] = HttpHeader.paramPrefix ~ prop["x-mcp-header"].get!string;
    }();
    return map;
}

// ===========================================================================
// Multi Round-Trip Requests (MRTR) — SEP-2322
// ===========================================================================

/// One unit of input the server needs from the client to continue (replacing a
/// server-initiated `sampling/createMessage`, `elicitation/create`, or
/// `roots/list` request).
struct InputRequest
{
    string id; /// correlation id chosen by the server
    string type; /// "sampling" | "elicitation" | "roots"
    Json params = Json.emptyObject; /// the would-be request params

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["id"] = id;
        j["type"] = type;
        j["params"] = params;
        return j;
    }

    static InputRequest fromJson(Json j) @safe
    {
        InputRequest r;
        r.id = ("id" in j) ? j["id"].get!string : "";
        r.type = ("type" in j) ? j["type"].get!string : "";
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

    Json toJson() const @safe
    {
        Json arr = Json.emptyArray;
        foreach (r; inputRequests)
            arr ~= r.toJson();
        Json j = Json.emptyObject;
        j["inputRequests"] = arr;
        return j;
    }

    static InputRequiredResult fromJson(Json j) @safe
    {
        InputRequiredResult r;
        if ("inputRequests" in j && j["inputRequests"].type == Json.Type.array)
        {
            auto arr = j["inputRequests"];
            foreach (i; 0 .. arr.length)
                r.inputRequests ~= InputRequest.fromJson(arr[i]);
        }
        return r;
    }
}

/// A client's answer to one `InputRequest`, supplied on the retried request via
/// `params._meta["io.modelcontextprotocol/inputResponses"]`.
struct InputResponse
{
    string id;
    Json result = Json.emptyObject;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["id"] = id;
        j["result"] = result;
        return j;
    }
}

/// Read the input responses a client attached to a retried request, keyed by
/// the originating `InputRequest.id`.
Json[string] readInputResponses(Json params) @safe
{
    Json[string] out_;
    if (params.type != Json.Type.object || "_meta" !in params)
        return out_;
    auto meta = params["_meta"];
    if (meta.type != Json.Type.object || MetaKey.inputResponses !in meta)
        return out_;
    auto arr = meta[MetaKey.inputResponses];
    if (arr.type != Json.Type.array)
        return out_;
    foreach (i; 0 .. arr.length)
    {
        auto resp = fromJson2(arr[i]);
        out_[resp.id] = resp.result;
    }
    return out_;
}

private InputResponse fromJson2(Json j) @safe
{
    InputResponse r;
    r.id = ("id" in j) ? j["id"].get!string : "";
    if ("result" in j)
        r.result = j["result"];
    return r;
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

unittest  // withCache attaches ttlMs and cacheScope
{
    Json r = Json.emptyObject;
    r["tools"] = Json.emptyArray;
    auto c = withCache(r, 5000, CacheScope.private_);
    assert(c["ttlMs"].get!long == 5000);
    assert(c["cacheScope"].get!string == "private");
}

unittest  // MRTR InputRequiredResult round-trips and input responses parse
{
    InputRequiredResult ir;
    ir.inputRequests = [
        InputRequest("r1", "elicitation", Json(["message": Json("hi")]))
    ];
    auto back = InputRequiredResult.fromJson(ir.toJson());
    assert(back.inputRequests.length == 1);
    assert(back.inputRequests[0].type == "elicitation");

    Json meta = Json.emptyObject;
    Json arr = Json.emptyArray;
    arr ~= InputResponse("r1", Json(["action": Json("accept")])).toJson();
    meta[MetaKey.inputResponses] = arr;
    Json params = Json.emptyObject;
    params["_meta"] = meta;
    auto resps = readInputResponses(params);
    assert("r1" in resps);
    assert(resps["r1"]["action"].get!string == "accept");
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
    assert(!isValidMetaKey("io.example/")); // empty name
    assert(!isValidMetaKey("io.example/-x")); // name must start alphanumeric
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

unittest  // paramHeaderMap reads x-mcp-header annotations
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
