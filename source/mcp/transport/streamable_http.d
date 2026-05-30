module mcp.transport.streamable_http;

import vibe.http.server;
import vibe.http.router : URLRouter;
import vibe.stream.operations : readAllUTF8;

import mcp.server.server;

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
///   - GET:  reserved for the server->client SSE stream (not yet offered -> 405).
///   - DELETE: session teardown (accepted as a no-op for the stateless core).
void mountMcp(URLRouter router, MCPServer server,
        StreamableHttpOptions opts = StreamableHttpOptions.init) @safe
{
    router.post(opts.path, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        handlePost(server, req, res);
    });
    router.get(opts.path, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        // No server-initiated SSE stream offered by the core yet.
        res.statusCode = HTTPStatus.methodNotAllowed;
        res.headers["Allow"] = "POST, DELETE";
        res.writeBody("", "text/plain");
    });
    router.match(HTTPMethod.DELETE, opts.path, (scope HTTPServerRequest req,
            scope HTTPServerResponse res) @safe {
        if (!guardOrigin(req, res, opts))
            return;
        res.statusCode = HTTPStatus.noContent;
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

private void handlePost(MCPServer server, scope HTTPServerRequest req, scope HTTPServerResponse res) @safe
{
    const payload = req.bodyReader.readAllUTF8();
    const responseText = server.handleRaw(payload);
    if (responseText.length == 0)
    {
        // Notifications/responses only: nothing to return.
        res.statusCode = HTTPStatus.accepted;
        res.writeBody("", "text/plain");
        return;
    }
    res.writeBody(responseText, "application/json");
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
