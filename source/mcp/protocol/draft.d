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
        Json pv = Json.emptyArray;
        foreach (v; protocolVersions)
            pv ~= Json(v);
        j["protocolVersions"] = pv;
        j["capabilities"] = capabilities.toJson();
        j["serverInfo"] = serverInfo.toJson();
        if (!instructions.isNull)
            j["instructions"] = instructions.get;
        return j;
    }

    static DiscoverResult fromJson(Json j) @safe
    {
        DiscoverResult r;
        if ("protocolVersions" in j && j["protocolVersions"].type == Json.Type.array)
        {
            auto arr = j["protocolVersions"];
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
