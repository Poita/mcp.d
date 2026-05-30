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
        handlePost(server, req, res);
    });
    router.get(opts.path, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
        // No server-initiated SSE stream offered by the core yet.
        res.statusCode = HTTPStatus.methodNotAllowed;
        res.headers["Allow"] = "POST, DELETE";
        res.writeBody("", "text/plain");
    });
    router.match(HTTPMethod.DELETE, opts.path, (scope HTTPServerRequest req,
            scope HTTPServerResponse res) @safe {
        res.statusCode = HTTPStatus.noContent;
        res.writeBody("", "text/plain");
    });
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
