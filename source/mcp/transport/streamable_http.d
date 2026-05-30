module mcp.transport.streamable_http;

import vibe.http.server;
import vibe.http.router : URLRouter;
import vibe.stream.operations : readAllUTF8;
import vibe.data.json : Json;

import mcp.server.server;
import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.draft;
import mcp.transport.sse_context;

/// Configuration for the Streamable HTTP server transport.
struct StreamableHttpOptions
{
    string path = "/mcp"; /// the single MCP endpoint path
    string[] bindAddresses = ["127.0.0.1"]; /// addresses to bind

    /// DNS-rebinding protection: reject requests whose Host/Origin is not a
    /// recognized localhost value (or in the explicit allow-lists below). On by
    /// default per the MCP transport security guidance; disable when fronting
    /// the server with a trusted reverse proxy.
    bool validateOrigin = true;
    string[] allowedHosts = []; /// extra Host header values to accept
    string[] allowedOrigins = []; /// extra Origin header values to accept
}

/// Mount an `MCPServer` onto a vibe.d `URLRouter` at the configured path,
/// implementing the modern Streamable HTTP transport (single endpoint):
///   - POST: a JSON-RPC message/batch; returns `application/json` for requests,
///     or `202 Accepted` with no body when the payload needs no reply.
///   - GET:  the draft drops the standalone server->client SSE stream -> 405.
///   - DELETE: the draft has no protocol-level sessions to tear down -> 405.
void mountMcp(URLRouter router, MCPServer server,
        StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
    auto coord = new StreamCoordinator;

    router.post(opts.path, (HTTPServerRequest req, HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        handlePost(server, coord, req, res);
    });
    router.get(opts.path, (HTTPServerRequest req, HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        // The draft transport drops the standalone GET SSE stream entirely;
        // server->client traffic flows on the SSE response to the relevant POST.
        // Per draft backward-compatibility, GET to the endpoint -> 405.
        res.statusCode = HTTPStatus.methodNotAllowed;
        res.headers["Allow"] = "POST";
        res.writeBody("", "text/plain");
    });
    router.match(HTTPMethod.DELETE, opts.path, (HTTPServerRequest req,
            HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        // The draft has no protocol-level sessions, so there is nothing to tear
        // down: per the backward-compatibility rules, DELETE -> 405. (Also
        // conformant for 2025-11-25, where the server simply does not allow
        // client-driven session termination.)
        res.statusCode = HTTPStatus.methodNotAllowed;
        res.headers["Allow"] = "POST";
        res.writeBody("", "text/plain");
    });
}

/// Enforce DNS-rebinding protection. Returns true if the request may proceed;
/// otherwise writes a `403 Forbidden` and returns false.
private bool guardOrigin(scope HTTPServerRequest req, scope HTTPServerResponse res,
        StreamableHttpOptions opts) @safe
{
    if (!opts.validateOrigin)
        return true;

    const host = req.headers.get("Host", "");
    const origin = req.headers.get("Origin", "");

    if (host.length && !hostAllowed(host, opts.allowedHosts))
    {
        res.statusCode = HTTPStatus.forbidden;
        res.writeBody("Forbidden: Host not allowed", "text/plain");
        return false;
    }
    if (origin.length && !originAllowed(origin, opts.allowedOrigins))
    {
        res.statusCode = HTTPStatus.forbidden;
        res.writeBody("Forbidden: Origin not allowed", "text/plain");
        return false;
    }
    return true;
}

private void handlePost(MCPServer server, StreamCoordinator coord,
        HTTPServerRequest req, HTTPServerResponse res) @safe
{
    const payload = req.bodyReader.readAllUTF8();

    ParsedInput input;
    try
        input = parseAny(payload);
    catch (McpException e)
    {
        res.writeBody(makeErrorResponse(Json(null), e).toString(), "application/json");
        return;
    }
    catch (Exception e)
    {
        res.writeBody(makeErrorResponse(Json(null), parseError(e.msg))
                .toString(), "application/json");
        return;
    }

    // Batches take the non-streaming path (no in-flight server->client traffic).
    if (input.isBatch)
    {
        const txt = server.handleRaw(payload);
        if (txt.length == 0)
        {
            res.statusCode = HTTPStatus.accepted;
            res.writeBody("", "text/plain");
        }
        else
            res.writeBody(txt, "application/json");
        return;
    }

    auto msg = input.messages[0];
    final switch (msg.kind)
    {
    case MessageKind.response:
    case MessageKind.errorResponse:
        // A client's reply to a server->client request: route it to the waiter.
        coord.resolve(msg.id, msg.result, msg.error);
        res.statusCode = HTTPStatus.accepted;
        res.writeBody("", "text/plain");
        return;
    case MessageKind.notification:
        server.handle(msg);
        res.statusCode = HTTPStatus.accepted;
        res.writeBody("", "text/plain");
        return;
    case MessageKind.request:
        // Draft: validate the standard request headers against the body.
        auto hdrErr = validateDraftHeaders(req.headers.get(
                HttpHeader.protocolVersion, ""), req.headers.get(HttpHeader.method,
                ""), req.headers.get(HttpHeader.name, ""), msg);
        if (hdrErr !is null)
        {
            res.statusCode = HTTPStatus.badRequest;
            res.writeBody(makeErrorResponse(msg.id, hdrErr).toString(), "application/json");
            return;
        }
        // Draft x-mcp-header: validate Mcp-Param-* headers against the tool's
        // declared header parameters and the body arguments.
        if (msg.method == "tools/call" && tryDraft(req.headers.get(HttpHeader.protocolVersion, "")))
        {
            const tname = ("name" in msg.params && msg.params["name"].type == Json.Type.string) ? msg
                .params["name"].get!string : "";
            auto schema = server.toolInputSchema(tname);
            auto args = ("arguments" in msg.params) ? msg.params["arguments"] : Json.emptyObject;
            auto perr = validateParamHeaders(schema, args, (string h) => req.headers.get(h, ""));
            if (perr !is null)
            {
                res.statusCode = HTTPStatus.badRequest;
                res.writeBody(makeErrorResponse(msg.id, perr).toString(), "application/json");
                return;
            }
        }
        auto ctx = new HttpStreamContext(res, coord, server.clientCapabilities,
                extractProgressToken(msg.params));
        auto resp = server.handle(msg, ctx);
        if (ctx.streaming)
            ctx.finishWith(resp.get);
        else
        {
            // Map reserved JSON-RPC errors onto their required HTTP statuses
            // (400 for unsupported-version/header-mismatch, draft 404 for
            // method-not-found); everything else rides on 200.
            auto j = resp.get;
            const isDraft = tryDraft(req.headers.get(HttpHeader.protocolVersion, ""))
                || tryDraft(RequestMeta.fromParams(msg.params).protocolVersion);
            res.statusCode = httpStatusForResponse(j, isDraft);
            res.writeBody(j.toString(), "application/json");
        }
        return;
    }
}

/// Map a JSON-RPC response to the HTTP status the Streamable HTTP transport must
/// surface. Successful results and ordinary application errors ride on `200`.
/// The draft reserves specific statuses so intermediaries — and clients probing
/// modern-vs-legacy servers — can act without parsing the body:
///   - `UnsupportedProtocolVersionError` (-32004) -> `400` (all modern versions),
///   - `HeaderMismatch` (-32001) -> `400`,
///   - `Method not found` (-32601) -> `404` on draft requests, which lets a client
///     tell a modern MCP endpoint apart from a legacy HTTP+SSE `404`. Pre-draft
///     versions keep the legacy JSON-RPC-error-over-`200` shape.
int httpStatusForResponse(Json resp, bool isDraft) @safe
{
    if ("error" !in resp || resp["error"].type != Json.Type.object)
        return 200;
    auto err = resp["error"];
    if ("code" !in err || err["code"].type != Json.Type.int_)
        return 200;
    const code = err["code"].get!int;
    if (code == ErrorCode.unsupportedProtocolVersion || code == ErrorCode.headerMismatch)
        return 400;
    if (isDraft && code == ErrorCode.methodNotFound)
        return 404;
    return 200;
}

/// Validate the draft Streamable HTTP request headers against the JSON-RPC body.
/// Returns a `HeaderMismatch` (-32001) exception on failure, or null when the
/// request is valid — or when the protocol version is pre-draft (older versions
/// did not define these headers, so they are not enforced).
McpException validateDraftHeaders(string protoHeader, string methodHeader,
        string nameHeader, Message msg) @safe
{
    ProtocolVersion pv;
    if (!tryParseVersion(protoHeader, pv) || !pv.isDraft)
        return null; // not a draft request: do not enforce draft headers

    if (methodHeader.length == 0)
        return new McpException(ErrorCode.headerMismatch, "Missing Mcp-Method header");
    if (methodHeader != msg.method)
        return new McpException(ErrorCode.headerMismatch,
                "Mcp-Method header '" ~ methodHeader
                ~ "' does not match body method '" ~ msg.method ~ "'");

    // Header protocol version must match the body's _meta protocol version.
    auto bodyMeta = RequestMeta.fromParams(msg.params);
    if (bodyMeta.protocolVersion.length && bodyMeta.protocolVersion != protoHeader)
        return new McpException(ErrorCode.headerMismatch,
                "MCP-Protocol-Version header does not match body _meta");

    // Mcp-Name mirrors params.name (tools/call, prompts/get) or params.uri
    // (resources/read).
    string bodyName;
    switch (msg.method)
    {
    case "tools/call":
    case "prompts/get":
        if ("name" in msg.params && msg.params["name"].type == Json.Type.string)
            bodyName = msg.params["name"].get!string;
        break;
    case "resources/read":
        if ("uri" in msg.params && msg.params["uri"].type == Json.Type.string)
            bodyName = msg.params["uri"].get!string;
        break;
    default:
        return null; // no Mcp-Name requirement for other methods
    }
    if (nameHeader.length == 0)
        return new McpException(ErrorCode.headerMismatch, "Missing Mcp-Name header");
    if (nameHeader != bodyName)
        return new McpException(ErrorCode.headerMismatch,
                "Mcp-Name header '" ~ nameHeader ~ "' does not match body value '" ~ bodyName ~ "'");
    return null;
}

/// Whether a `Host` header value (e.g. "127.0.0.1:3000") is localhost or listed.
package bool hostAllowed(string host, const string[] extra) @safe
{
    import std.algorithm : canFind;

    if (extra.canFind(host))
        return true;
    return isLoopbackHostname(stripPort(host));
}

/// Whether an `Origin` header value (e.g. "http://localhost:3000") is localhost
/// or listed.
package bool originAllowed(string origin, const string[] extra) @safe
{
    import std.algorithm : canFind;
    import std.string : indexOf;

    if (extra.canFind(origin))
        return true;

    // Strip the scheme, then the path, then the port to isolate the hostname.
    auto rest = origin;
    const sep = rest.indexOf("://");
    if (sep >= 0)
        rest = rest[sep + 3 .. $];
    const slash = rest.indexOf('/');
    if (slash >= 0)
        rest = rest[0 .. slash];
    return isLoopbackHostname(stripPort(rest));
}

private string stripPort(string hostport) @safe
{
    import std.string : lastIndexOf;

    // IPv6 literal in brackets: [::1]:port
    if (hostport.length && hostport[0] == '[')
    {
        import std.string : indexOf;

        const close = hostport.indexOf(']');
        if (close >= 0)
            return hostport[1 .. close];
    }
    const colon = hostport.lastIndexOf(':');
    if (colon >= 0)
        return hostport[0 .. colon];
    return hostport;
}

private bool isLoopbackHostname(string h) @safe
{
    return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

/// Start a standalone Streamable HTTP server for `server` on `port` and run the
/// vibe.d event loop. Blocks until the application exits.
void runStreamableHttp(MCPServer server, ushort port,
        StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
    import vibe.core.core : runEventLoop, lowerPrivileges;

    auto router = new URLRouter;
    mountMcp(router, server, opts);

    auto settings = new HTTPServerSettings;
    settings.port = port;
    settings.bindAddresses = opts.bindAddresses;
    auto listener = listenHTTP(settings, router);
    scope (exit)
        listener.stopListening();

    lowerPrivileges();
    runEventLoop();
}

unittest  // localhost hosts are accepted, foreign hosts rejected
{
    assert(hostAllowed("127.0.0.1:3000", []));
    assert(hostAllowed("localhost", []));
    assert(hostAllowed("[::1]:8080", []));
    assert(!hostAllowed("evil.example.com", []));
    assert(hostAllowed("myhost", ["myhost"]));
}

unittest  // localhost origins are accepted, foreign origins rejected
{
    assert(originAllowed("http://localhost:3000", []));
    assert(originAllowed("https://127.0.0.1", []));
    assert(!originAllowed("http://evil.example.com", []));
    assert(originAllowed("http://app.example.com", ["http://app.example.com"]));
}

version (unittest)
{
    private Message draftMsg(string method, Json params) @safe
    {
        Json meta = Json.emptyObject;
        meta[MetaKey.protocolVersion] = "2026-07-28";
        params["_meta"] = meta;
        return Message(makeRequest(Json(1), method, params));
    }
}

unittest  // pre-draft requests skip draft header enforcement
{
    auto m = Message(makeRequest(Json(1), "tools/list", Json.emptyObject));
    // protocol header empty / older -> no enforcement
    assert(validateDraftHeaders("", "", "", m) is null);
    assert(validateDraftHeaders("2025-11-25", "", "", m) is null);
}

unittest  // draft request missing Mcp-Method is a header mismatch
{
    auto m = draftMsg("tools/list", Json.emptyObject);
    auto e = validateDraftHeaders("2026-07-28", "", "", m);
    assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft request with mismatched Mcp-Method fails
{
    auto m = draftMsg("tools/list", Json.emptyObject);
    auto e = validateDraftHeaders("2026-07-28", "tools/call", "", m);
    assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // draft tools/list with correct headers passes
{
    auto m = draftMsg("tools/list", Json.emptyObject);
    assert(validateDraftHeaders("2026-07-28", "tools/list", "", m) is null);
}

unittest  // draft tools/call requires matching Mcp-Name
{
    Json p = Json.emptyObject;
    p["name"] = "add";
    auto m = draftMsg("tools/call", p);
    assert(validateDraftHeaders("2026-07-28", "tools/call", "add", m) is null);
    auto e = validateDraftHeaders("2026-07-28", "tools/call", "wrong", m);
    assert(e !is null && e.code == ErrorCode.headerMismatch);
    auto e2 = validateDraftHeaders("2026-07-28", "tools/call", "", m);
    assert(e2 !is null); // missing name
}

unittest  // draft resources/read mirrors uri into Mcp-Name
{
    Json p = Json.emptyObject;
    p["uri"] = "test://x";
    auto m = draftMsg("resources/read", p);
    assert(validateDraftHeaders("2026-07-28", "resources/read", "test://x", m) is null);
    assert(validateDraftHeaders("2026-07-28", "resources/read", "test://y", m) !is null);
}

/// True if the protocol-version header denotes a draft+ request.
private bool tryDraft(string protoHeader) @safe
{
    ProtocolVersion pv;
    return tryParseVersion(protoHeader, pv) && pv.isDraft;
}

/// Render a JSON scalar the way the draft requires for `Mcp-Param-*` header
/// comparison: strings as-is, integers as decimal, booleans as "true"/"false".
private string jsonScalarToString(Json v) @safe
{
    import std.conv : to;

    switch (v.type)
    {
    case Json.Type.string:
        return v.get!string;
    case Json.Type.int_:
        return v.get!long
            .to!string;
    case Json.Type.bool_:
        return v.get!bool ? "true" : "false";
    default:
        return v.toString();
    }
}

/// Validate draft `x-mcp-header` mirroring: every parameter annotated with
/// `x-mcp-header` whose value is present in `args` MUST have a matching
/// (decoded) `Mcp-Param-*` header; absent parameters MUST NOT carry the header.
/// Returns a `HeaderMismatch` exception on violation, else null.
McpException validateParamHeaders(Json inputSchema, Json args,
        scope string delegate(string) @safe headerGet) @safe
{
    auto map = paramHeaderMap(inputSchema);
    foreach (param, headerName; map)
    {
        const hv = headerGet(headerName);
        const present = args.type == Json.Type.object && param in args
            && args[param].type != Json.Type.null_ && args[param].type != Json.Type.undefined;
        if (!present)
        {
            if (hv.length)
                return new McpException(ErrorCode.headerMismatch,
                        "Header " ~ headerName ~ " present but parameter '" ~ param ~ "' absent");
            continue;
        }
        if (hv.length == 0)
            return new McpException(ErrorCode.headerMismatch,
                    "Missing required header " ~ headerName ~ " for parameter '" ~ param ~ "'");
        if (decodeHeaderValue(hv) != jsonScalarToString(args[param]))
            return new McpException(ErrorCode.headerMismatch,
                    "Header " ~ headerName ~ " does not match parameter '" ~ param ~ "'");
    }
    return null;
}

version (unittest)
{
    private Json schemaWithHeaderParam() @safe
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
        return schema;
    }
}

unittest  // x-mcp-header: matching header passes
{
    auto schema = schemaWithHeaderParam();
    Json args = Json(["region": Json("us-west1"), "query": Json("SELECT 1")]);
    auto e = validateParamHeaders(schema, args,
            (string h) => h == "Mcp-Param-Region" ? "us-west1" : "");
    assert(e is null);
}

unittest  // x-mcp-header: mismatched header is a HeaderMismatch
{
    auto schema = schemaWithHeaderParam();
    Json args = Json(["region": Json("us-west1")]);
    auto e = validateParamHeaders(schema, args, (string h) => "us-east1");
    assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: present param but missing header fails
{
    auto schema = schemaWithHeaderParam();
    Json args = Json(["region": Json("us-west1")]);
    auto e = validateParamHeaders(schema, args, (string h) => "");
    assert(e !is null && e.code == ErrorCode.headerMismatch);
}

unittest  // x-mcp-header: non-ASCII value matched via base64-encoded header
{
    import mcp.protocol.draft : encodeHeaderValue;

    auto schema = schemaWithHeaderParam();
    Json args = Json(["region": Json("Zürich")]);
    const enc = encodeHeaderValue("Zürich");
    auto e = validateParamHeaders(schema, args, (string h) => h == "Mcp-Param-Region" ? enc : "");
    assert(e is null);
}

version (unittest)
{
    private Json errResponse(int code) @safe
    {
        Json r = Json.emptyObject;
        r["jsonrpc"] = "2.0";
        r["id"] = 1;
        Json err = Json.emptyObject;
        err["code"] = code;
        err["message"] = "x";
        r["error"] = err;
        return r;
    }
}

unittest  // a successful (non-error) response always rides on HTTP 200
{
    Json ok = Json.emptyObject;
    ok["jsonrpc"] = "2.0";
    ok["id"] = 1;
    ok["result"] = Json.emptyObject;
    assert(httpStatusForResponse(ok, true) == 200);
    assert(httpStatusForResponse(ok, false) == 200);
}

unittest  // UnsupportedProtocolVersionError maps to HTTP 400 on any modern version
{
    auto r = errResponse(ErrorCode.unsupportedProtocolVersion);
    assert(httpStatusForResponse(r, true) == 400);
    assert(httpStatusForResponse(r, false) == 400);
}

unittest  // HeaderMismatch maps to HTTP 400
{
    auto r = errResponse(ErrorCode.headerMismatch);
    assert(httpStatusForResponse(r, true) == 400);
}

unittest  // draft Method-not-found maps to HTTP 404 (distinguishes modern endpoint from legacy)
{
    auto r = errResponse(ErrorCode.methodNotFound);
    assert(httpStatusForResponse(r, true) == 404);
}

unittest  // pre-draft Method-not-found stays on HTTP 200 (legacy JSON-RPC-over-200 shape)
{
    auto r = errResponse(ErrorCode.methodNotFound);
    assert(httpStatusForResponse(r, false) == 200);
}

unittest  // ordinary application errors (e.g. invalidParams) ride on HTTP 200
{
    auto r = errResponse(ErrorCode.invalidParams);
    assert(httpStatusForResponse(r, true) == 200);
    assert(httpStatusForResponse(r, false) == 200);
}
