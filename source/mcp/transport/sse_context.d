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
import mcp.auth.resource_server : TokenInfo;

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
    private long streamCounter = 0;

    /// Allocate a fresh outbound request id.
    long alloc() @safe
    {
        return counter++;
    }

    /// Allocate a fresh stream ordinal. Combined with a per-stream monotonic
    /// event sequence, this yields globally-unique SSE event ids across every
    /// stream served by this mount, as the Resumability/Redelivery requirement
    /// demands ("If present, the ID MUST be globally unique ... within ... the
    /// session").
    long allocStream() @safe
    {
        return streamCounter++;
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

/// A long-lived server->client SSE channel for *unsolicited* traffic — the
/// stream a client opens with an HTTP GET to the MCP endpoint (basic/transports
/// §Listening for Messages from the Server). Unlike `HttpStreamContext`, which
/// is bound to one in-flight POST, this channel fans a single notification (or
/// server->client request) out to every currently-connected GET listener.
///
/// A handler is registered per accepted GET; `emit` frames the JSON-RPC message
/// as an SSE event with a globally-unique id (via the shared `StreamCoordinator`
/// ordinal scheme) and writes it to every live listener. Listeners that fail to
/// write (a disconnected client) are dropped so the channel self-heals.
///
/// One instance is shared across a server mount. Thread-safety is the caller's
/// responsibility on multi-threaded vibe.d setups; the default single-fiber
/// dispatch needs none.
final class ServerPushChannel
{
    /// A connected GET listener: an opaque id plus the writer that delivers a
    /// pre-framed SSE block to it.
    private struct Listener
    {
        long id;
        void delegate(string frame) @safe write;
    }

    private StreamCoordinator coord;
    private Listener[] listeners;
    private long[long] streamOf; /// listener id -> its allocated stream ordinal
    private long[long] seqOf; /// listener id -> its monotonic event sequence
    private long nextListenerId = 1;

    this(StreamCoordinator coord) @safe
    {
        this.coord = coord;
    }

    /// Register a connected GET listener and return its id. Each listener gets a
    /// distinct stream ordinal so its event ids stay globally unique within the
    /// mount/session.
    long addListener(void delegate(string frame) @safe write) @safe
    {
        const id = nextListenerId++;
        listeners ~= Listener(id, write);
        streamOf[id] = coord.allocStream();
        seqOf[id] = 0;
        return id;
    }

    /// Drop a listener (e.g. when its GET stream is closed).
    void removeListener(long id) @safe
    {
        import std.algorithm : remove;

        listeners = listeners.remove!(l => l.id == id);
        streamOf.remove(id);
        seqOf.remove(id);
    }

    /// Number of currently-connected listeners.
    size_t listenerCount() const @safe
    {
        return listeners.length;
    }

    /// Frame `msg` as an SSE event (with a per-listener globally-unique id) and
    /// write it to every connected listener. A listener whose write throws (a
    /// disconnected client) is removed. Returns the number of listeners the
    /// message was delivered to.
    size_t emit(Json msg) @safe
    {
        long[] dead;
        size_t delivered;
        foreach (ref l; listeners)
        {
            import std.conv : to;

            const eid = streamOf[l.id].to!string ~ "-" ~ seqOf[l.id].to!string;
            const frame = formatSseEvent(eid, msg);
            try
            {
                l.write(frame);
                seqOf[l.id]++;
                delivered++;
            }
            catch (Exception)
            {
                dead ~= l.id;
            }
        }
        foreach (id; dead)
            removeListener(id);
        return delivered;
    }

    /// Convenience: broadcast a JSON-RPC notification to every listener.
    size_t notify(string method, Json params = Json.undefined) @safe
    {
        return emit(makeNotification(method, params));
    }
}

unittest  // a listener receives framed events, with monotonic per-listener ids
{
    auto coord = new StreamCoordinator;
    auto ch = new ServerPushChannel(coord);
    string[] received;
    const id = ch.addListener((string f) @safe { received ~= f; });
    assert(ch.listenerCount == 1);

    const n = ch.notify("notifications/resources/updated", Json([
        "uri": Json("test://x")
    ]));
    assert(n == 1);
    assert(received.length == 1);
    import std.string : startsWith;
    import std.algorithm : canFind;

    assert(received[0].startsWith("id: "));
    assert(received[0].canFind("notifications/resources/updated"));

    ch.notify("notifications/message");
    assert(received.length == 2);
    // event ids advance monotonically for the same listener.
    assert(received[0] != received[1]);
    ch.removeListener(id);
    assert(ch.listenerCount == 0);
}

unittest  // emit fans out to every listener and self-heals broken ones
{
    auto coord = new StreamCoordinator;
    auto ch = new ServerPushChannel(coord);
    int aCount;
    ch.addListener((string) @safe { aCount++; });
    // A listener that always throws simulates a disconnected client.
    ch.addListener((string) @safe { throw new Exception("closed"); });
    assert(ch.listenerCount == 2);

    const delivered = ch.notify("notifications/message");
    assert(delivered == 1); // only the healthy listener received it
    assert(aCount == 1);
    assert(ch.listenerCount == 1); // the broken listener was dropped
}

unittest  // distinct listeners get distinct stream ordinals, so ids stay unique
{
    auto coord = new StreamCoordinator;
    auto ch = new ServerPushChannel(coord);
    string aFrame, bFrame;
    ch.addListener((string f) @safe { aFrame = f; });
    ch.addListener((string f) @safe { bFrame = f; });
    ch.notify("notifications/message");
    assert(aFrame.length && bFrame.length);
    // The first line ("id: <stream>-<seq>") differs because the stream ordinal
    // differs between the two listeners.
    import std.string : splitLines;

    assert(aFrame.splitLines()[0] != bFrame.splitLines()[0]);
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
    private long streamId;
    private long eventSeq;
    private TokenInfo authInfo;

    this(HTTPServerResponse res, StreamCoordinator coord, ClientCapabilities caps,
            Json progressToken, TokenInfo auth = TokenInfo.invalid()) @safe
    {
        this.res = res;
        this.coord = coord;
        this.clientCaps = caps;
        this.progressTok = progressToken;
        this.streamId = coord.allocStream();
        this.authInfo = auth;
    }

    /// The globally-unique id this stream will assign to its next SSE event.
    /// Exposed for resumability tooling and tests; the format is opaque but
    /// stable and unique across all streams of the owning mount.
    string nextEventId() @safe
    {
        import std.conv : to;

        return streamId.to!string ~ "-" ~ eventSeq.to!string;
    }

    /// Whether the response has been upgraded to an SSE stream.
    bool streaming() const @safe
    {
        return streaming_;
    }

    /// Cancellation for this request is tracked by the server's `RequestScope`
    /// (which holds the shared token flipped by `notifications/cancelled`), so the
    /// transport context itself reports never-cancelled. The wrapping
    /// `RequestScope.isCancelled` consults its token before delegating here.
    bool isCancelled() @safe
    {
        return false;
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
        const frame = formatSseEvent(nextEventId(), msg);
        eventSeq++;
        () @trusted {
            res.bodyWriter.write(cast(const(ubyte)[]) frame);
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
        case "sampling.tools":
            return clientCaps.samplingTools;
        case "sampling.context":
            return clientCaps.samplingContext;
        case "elicitation":
            return clientCaps.elicitation;
        case "elicitation.form":
            return clientCaps.elicitationForm;
        case "elicitation.url":
            return clientCaps.elicitationUrl;
        case "roots":
            return clientCaps.roots;
        default:
            return false;
        }
    }

    // Per-request protocol state (statelessness, input responses) is supplied by
    // the server's RequestScope wrapper, not the transport; default here.
    bool isStateless() @safe
    {
        return false;
    }

    Json[string] inputResponses() @safe
    {
        Json[string] empty;
        return empty;
    }

    TokenInfo auth() @safe
    {
        return authInfo;
    }

    /// Write the final JSON-RPC response as the terminating SSE event.
    void finishWith(Json response) @safe
    {
        writeEvent(response);
    }
}

/// Frame a JSON-RPC message as a Server-Sent Events block. Per the transport
/// Resumability/Redelivery section, the server attaches an `id:` line so a
/// client can reconnect with `Last-Event-ID`; the id MUST be globally unique
/// within the session, which the caller guarantees via a per-stream ordinal
/// plus a monotonic event sequence. An empty `id` omits the line.
string formatSseEvent(string id, Json msg) @safe
{
    auto block = id.length ? ("id: " ~ id ~ "\n") : "";
    return block ~ "data: " ~ msg.toString() ~ "\n\n";
}

unittest  // formatSseEvent emits an id: line followed by the data: line
{
    auto j = makeNotification("notifications/message", Json.emptyObject);
    const frame = formatSseEvent("0-3", j);
    import std.string : startsWith, endsWith, indexOf;

    assert(frame.startsWith("id: 0-3\n"));
    assert(frame.indexOf("\ndata: ") >= 0);
    assert(frame.endsWith("\n\n"));
}

unittest  // formatSseEvent omits the id: line when id is empty
{
    auto j = makeNotification("notifications/message", Json.emptyObject);
    const frame = formatSseEvent("", j);
    import std.string : startsWith;

    assert(frame.startsWith("data: "));
}

unittest  // each stream gets a distinct ordinal, so event ids are globally unique
{
    auto c = new StreamCoordinator;
    const a = c.allocStream();
    const b = c.allocStream();
    assert(a != b);
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
