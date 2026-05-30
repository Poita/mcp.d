module mcp.transport.sse_context;

import core.time : Duration, seconds;
import std.typecons : Nullable;

import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.data.json : Json;
import vibe.http.server : HTTPServerResponse;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.capabilities;
import mcp.server.context;

/// Correlates outbound server->client requests with the client's responses,
/// which arrive on a *separate* POST. One instance is shared across all
/// handlers of a single server mount.
final class StreamCoordinator
{
    private static final class Waiter
    {
        LocalManualEvent evt;
        Json result = Json.undefined;
        Json error = Json.undefined;
        bool done;
    }

    private long counter = 1;
    private Waiter[long] waiters;

    /// Allocate a fresh outbound request id.
    long alloc() @safe
    {
        return counter++;
    }

    /// Begin tracking a pending outbound request.
    void register(long id) @safe
    {
        auto w = new Waiter;
        w.evt = createManualEvent();
        waiters[id] = w;
    }

    /// Block the current task until the client responds to `id` (or `timeout`
    /// elapses). Returns the result, or throws `McpException` on error/timeout.
    Json await(long id, Duration timeout = 60.seconds) @safe
    {
        auto w = waiters[id];
        scope (exit)
            waiters.remove(id);

        auto ec = w.evt.emitCount;
        while (!w.done)
        {
            const newEc = () @trusted { return w.evt.wait(timeout, ec); }();
            if (newEc == ec && !w.done)
                throw internalError("Timed out awaiting client response");
            ec = newEc;
        }
        if (w.error.type != Json.Type.undefined)
        {
            const code = ("code" in w.error) ? w.error["code"].get!int : ErrorCode.internalError;
            const m = ("message" in w.error) ? w.error["message"].get!string : "client error";
            throw new McpException(code, m, w.error);
        }
        return w.result;
    }

    /// Deliver a client response/errorResponse. Returns true if it matched a
    /// pending outbound request.
    bool resolve(Json idJson, Json result, Json error) @safe
    {
        if (idJson.type != Json.Type.int_)
            return false;
        const id = idJson.get!long;
        if (auto w = id in waiters)
        {
            w.result = result;
            w.error = error;
            w.done = true;
            w.evt.emit();
            return true;
        }
        return false;
    }
}

/// A `RequestContext` backed by an HTTP response that is (lazily) upgraded to a
/// Server-Sent Events stream the first time the handler emits server->client
/// traffic. Progress/logging become SSE notification events; sampling/
/// elicitation send an SSE request event then block (via the coordinator) for
/// the client's response on a later POST. The final JSON-RPC response is the
/// terminating SSE event.
final class HttpStreamContext : RequestContext
{
    private HTTPServerResponse res;
    private StreamCoordinator coord;
    private ClientCapabilities clientCaps;
    private Json progressTok;
    private bool streaming_;

    this(HTTPServerResponse res, StreamCoordinator coord,
            ClientCapabilities caps, Json progressToken) @safe
    {
        this.res = res;
        this.coord = coord;
        this.clientCaps = caps;
        this.progressTok = progressToken;
    }

    /// Whether the response has been upgraded to an SSE stream.
    bool streaming() const @safe
    {
        return streaming_;
    }

    private void beginStream() @safe
    {
        if (streaming_)
            return;
        res.contentType = "text/event-stream";
        res.headers["Cache-Control"] = "no-cache";
        streaming_ = true;
    }

    private void writeEvent(Json msg) @safe
    {
        beginStream();
        () @trusted {
            auto data = "data: " ~ msg.toString() ~ "\n\n";
            res.bodyWriter.write(cast(const(ubyte)[]) data);
            res.bodyWriter.flush();
        }();
    }

    void reportProgress(double progress,
            Nullable!double total = Nullable!double.init, string message = null) @safe
    {
        if (progressTok.type == Json.Type.undefined)
            return;
        Json p = Json.emptyObject;
        p["progressToken"] = progressTok;
        p["progress"] = progress;
        if (!total.isNull)
            p["total"] = total.get;
        if (message.length)
            p["message"] = message;
        writeEvent(makeNotification("notifications/progress", p));
    }

    void log(string level, Json data, string logger = null) @safe
    {
        Json p = Json.emptyObject;
        p["level"] = level;
        if (logger.length)
            p["logger"] = logger;
        p["data"] = data;
        writeEvent(makeNotification("notifications/message", p));
    }

    Json sendRequest(string method, Json params) @safe
    {
        const id = coord.alloc();
        coord.register(id);
        writeEvent(makeRequest(Json(id), method, params));
        return coord.await(id);
    }

    bool clientSupports(string capability) @safe
    {
        switch (capability)
        {
        case "sampling":
            return clientCaps.sampling;
        case "elicitation":
            return clientCaps.elicitation;
        case "roots":
            return clientCaps.roots;
        default:
            return false;
        }
    }

    /// Write the final JSON-RPC response as the terminating SSE event.
    void finishWith(Json response) @safe
    {
        writeEvent(response);
    }
}

/// Extract `_meta.progressToken` from a request's params, or `Json.undefined`.
Json extractProgressToken(Json params) @safe
{
    if (params.type == Json.Type.object && "_meta" in params)
    {
        auto meta = params["_meta"];
        if (meta.type == Json.Type.object && "progressToken" in meta)
            return meta["progressToken"];
    }
    return Json.undefined;
}

unittest  // extractProgressToken finds the token or returns undefined
{
    Json p = Json.emptyObject;
    assert(extractProgressToken(p).type == Json.Type.undefined);
    Json meta = Json.emptyObject;
    meta["progressToken"] = "abc";
    p["_meta"] = meta;
    assert(extractProgressToken(p).get!string == "abc");
}

unittest  // coordinator resolves a pending request across "connections"
{
    auto c = new StreamCoordinator;
    const id = c.alloc();
    assert(id == 1);
    c.register(id);
    // Simulate the client's response arriving and being delivered.
    assert(c.resolve(Json(id), Json(["ok": Json(true)]), Json.undefined));
    // An unknown id does not match any pending request.
    assert(!c.resolve(Json(9999), Json.emptyObject, Json.undefined));
}
