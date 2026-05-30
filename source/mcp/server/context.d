module mcp.server.context;

import std.typecons : Nullable;
import vibe.data.json : Json;

import mcp.protocol.errors;
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
import mcp.protocol.types : ListRootsResult;
import mcp.auth.resource_server : TokenInfo;

@safe:

/// The RFC 5424 severity ordering used by `notifications/message` logging
/// (server/utilities/logging). Lower index == less severe; a message is emitted
/// only when its severity is at or above the client's configured minimum (set
/// via `logging/setLevel`). Returns `-1` for an unrecognised level name.
int logLevelRank(string level) @safe pure nothrow @nogc
{
    switch (level)
    {
    case "debug":
        return 0;
    case "info":
        return 1;
    case "notice":
        return 2;
    case "warning":
        return 3;
    case "error":
        return 4;
    case "critical":
        return 5;
    case "alert":
        return 6;
    case "emergency":
        return 7;
    default:
        return -1;
    }
}

/// Whether a log message at `level` should be emitted when the client's
/// configured minimum is `minLevel` (RFC 5424 ordering). After
/// `logging/setLevel(error)` only `error` and above pass. An unrecognised
/// `level` is treated as always emitted (fail-open, so custom levels are not
/// silently dropped); an unrecognised `minLevel` admits everything.
bool shouldLog(string level, string minLevel) @safe pure nothrow @nogc
{
    const lvl = logLevelRank(level);
    const min = logLevelRank(minLevel);
    if (lvl < 0 || min < 0)
        return true;
    return lvl >= min;
}

unittest  // RFC 5424 ordering: debug < info < ... < emergency
{
    assert(logLevelRank("debug") < logLevelRank("info"));
    assert(logLevelRank("info") < logLevelRank("notice"));
    assert(logLevelRank("notice") < logLevelRank("warning"));
    assert(logLevelRank("warning") < logLevelRank("error"));
    assert(logLevelRank("error") < logLevelRank("critical"));
    assert(logLevelRank("critical") < logLevelRank("alert"));
    assert(logLevelRank("alert") < logLevelRank("emergency"));
    assert(logLevelRank("bogus") == -1);
}

unittest  // shouldLog gates by the configured minimum level
{
    // minLevel "error": only error and above pass.
    assert(!shouldLog("debug", "error"));
    assert(!shouldLog("warning", "error"));
    assert(shouldLog("error", "error"));
    assert(shouldLog("critical", "error"));
    assert(shouldLog("emergency", "error"));
}

unittest  // shouldLog with the default minimum "info" drops only debug
{
    assert(!shouldLog("debug", "info"));
    assert(shouldLog("info", "info"));
    assert(shouldLog("warning", "info"));
}

unittest  // shouldLog fails open on unrecognised level names
{
    assert(shouldLog("custom", "error"));
    assert(shouldLog("debug", "bogus"));
}

/// A shared, mutable cancellation flag for one in-flight request. The server
/// hands the same token to the request's `RequestContext` (so the handler can
/// poll `ctx.isCancelled`) and to its in-flight registry (so an inbound
/// `notifications/cancelled` for the matching request id can flip it). It is a
/// class so the flag is observed across the two tasks that a Streamable HTTP
/// transport runs the request and its cancellation on. See
/// basic/utilities/cancellation: a receiver "SHOULD: Stop processing the
/// cancelled request, Free associated resources, Not send a response".
final class CancellationToken
{
    private bool cancelled_;

    /// Whether a cancellation has been requested for this token's request.
    bool cancelled() const @safe nothrow @nogc
    {
        return cancelled_;
    }

    /// Mark the request cancelled. Idempotent.
    void cancel() @safe nothrow @nogc
    {
        cancelled_ = true;
    }
}

/// Per-request context handed to tool handlers. It is the channel through which
/// a handler emits server->client traffic while a request is in flight:
/// progress + logging notifications, and (blocking) sampling / elicitation
/// requests. Transports supply a concrete implementation; the in-process and
/// stdio paths use `NullContext` (notifications are dropped, server->client
/// requests are unsupported).
interface RequestContext
{
    /// Whether the client has sent a `notifications/cancelled` for this request
    /// (basic/utilities/cancellation). A long-running handler SHOULD poll this
    /// and, when true, stop work and free resources promptly; the server
    /// suppresses the late response for a cancelled request regardless. Always
    /// false on transports that cannot deliver an out-of-band cancellation while
    /// a request is in flight (e.g. the in-process / stdio `NullContext`).
    bool isCancelled() @safe;

    /// Emit a `notifications/progress`. No-op if the originating request carried
    /// no `_meta.progressToken`.
    void reportProgress(double progress,
            Nullable!double total = Nullable!double.init, string message = null) @safe;

    /// Emit a `notifications/message` (logging) at the given level. `data` may be
    /// any JSON value (commonly a string or object); `logger` is optional.
    void log(string level, Json data, string logger = null) @safe;

    /// Send a server->client request and block until the client responds.
    /// Returns the result, or throws `McpException` if the client returned an
    /// error or does not support the feature.
    Json sendRequest(string method, Json params) @safe;

    /// Whether the connected client advertised the named capability
    /// ("sampling", "elicitation", "roots").
    bool clientSupports(string capability) @safe;

    /// True when this request is on a stateless (MRTR) protocol — the draft
    /// revision, where there is no server->client channel. On such requests a
    /// tool handler must NOT call `elicit`/`sample` (they throw); instead it
    /// returns `ToolResponse.inputRequired(...)` and reads the client's answers
    /// from `inputResponses` on the retried request. False on 2025-era requests.
    bool isStateless() @safe;

    /// The input responses the client attached when resubmitting an MRTR
    /// request, keyed by the `InputRequest.id` the server issued on the prior
    /// round. Empty on the first call and on non-stateless requests.
    Json[string] inputResponses() @safe;

    /// The validated OAuth 2.1 access-token info for this request, when the
    /// transport enforces authorization (Streamable HTTP with a configured
    /// `ResourceServerConfig`). `TokenInfo.valid` is false on transports without
    /// auth (stdio, in-process) or when no token was required; handlers that need
    /// the authenticated subject or token scopes read it here.
    TokenInfo auth() @safe;

    /// Request an LLM completion from the client (`sampling/createMessage`).
    /// Throws on a stateless (MRTR) request — use `ToolResponse.inputRequired`
    /// instead — or if the client does not support sampling.
    final Json sample(Json params) @safe
    {
        if (isStateless)
            throw invalidRequest(
                    "sample() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
        if (!clientSupports("sampling"))
            throw invalidRequest("Client does not support sampling");
        // Per spec, servers MUST NOT send tool-enabled sampling requests to
        // clients that have not declared the `sampling.tools` sub-capability.
        if (params.type == Json.Type.object && "tools" in params
                && !clientSupports("sampling.tools"))
            throw invalidRequest("Client does not support tool use in sampling (sampling.tools)");
        // The soft-deprecated `sampling.context` sub-capability gates the
        // `includeContext` values `thisServer`/`allServers`.
        if (params.type == Json.Type.object && "includeContext" in params
                && params["includeContext"].type == Json.Type.string)
        {
            const inc = params["includeContext"].get!string;
            if ((inc == "thisServer" || inc == "allServers") && !clientSupports("sampling.context"))
                throw invalidRequest(
                        "Client does not support context-enabled sampling (sampling.context)");
        }
        return sendRequest("sampling/createMessage", params);
    }

    /// Typed convenience over `sample(Json)`: build a `CreateMessageRequest`,
    /// send it, and parse the client's reply into a `CreateMessageResult`. Same
    /// preconditions and exceptions as the JSON overload.
    final CreateMessageResult sample(CreateMessageRequest request) @safe
    {
        return CreateMessageResult.fromJson(sample(request.toJson()));
    }

    /// Request structured user input from the client (`elicitation/create`).
    /// `requestedSchema` must be a JSON Schema object. Throws on a stateless
    /// (MRTR) request — use `ToolResponse.inputRequired` instead — or if the
    /// client does not support elicitation.
    ///
    /// This is form-mode elicitation; per spec the `mode` field is omitted and
    /// defaults to `"form"`. For URL-mode elicitation use `elicitUrl`.
    final Json elicit(string message, Json requestedSchema) @safe
    {
        if (isStateless)
            throw invalidRequest(
                    "elicit() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
        if (!clientSupports("elicitation"))
            throw invalidRequest("Client does not support elicitation");
        Json params = Json.emptyObject;
        params["message"] = message;
        params["requestedSchema"] = requestedSchema;
        return sendRequest("elicitation/create", params);
    }

    /// Request URL-mode elicitation from the client (`elicitation/create` with
    /// `mode: "url"`, introduced in 2025-11-25). Directs the user to complete an
    /// out-of-band interaction (e.g. an OAuth consent or a web form) at `url`;
    /// `elicitationId` correlates the request with the outcome the client reports
    /// back. Per spec a URL-mode request MUST specify `mode: "url"`, a `message`,
    /// `url`, and `elicitationId`.
    ///
    /// Returns the client's `{action}` response (typically `accept`/`decline`/
    /// `cancel`). Throws on a stateless (MRTR) request — use
    /// `ToolResponse.inputRequired` instead — or if the client does not support
    /// elicitation, or if `url`/`elicitationId` are empty.
    final Json elicitUrl(string message, string url, string elicitationId) @safe
    {
        if (isStateless)
            throw invalidRequest(
                    "elicitUrl() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
        if (!clientSupports("elicitation"))
            throw invalidRequest("Client does not support elicitation");
        if (url.length == 0)
            throw invalidParams("URL-mode elicitation requires a non-empty url");
        if (elicitationId.length == 0)
            throw invalidParams("URL-mode elicitation requires a non-empty elicitationId");
        Json params = Json.emptyObject;
        params["mode"] = "url";
        params["message"] = message;
        params["url"] = url;
        params["elicitationId"] = elicitationId;
        return sendRequest("elicitation/create", params);
    }

    /// List the client's filesystem roots (`roots/list`). Per client/roots
    /// §Implementation Guidelines, checks the client's `roots` capability before
    /// usage and throws `McpException` if the client does not support it; parses
    /// the client's reply into a typed `ListRootsResult`.
    final ListRootsResult listRoots() @safe
    {
        if (!clientSupports("roots"))
            throw invalidRequest("Client does not support roots");
        return ListRootsResult.fromJson(sendRequest("roots/list", Json.emptyObject));
    }
}

/// A context with no client channel: notifications are dropped and
/// server->client requests are rejected. Used by transports that do not (yet)
/// support streaming, and as the default when none is supplied.
final class NullContext : RequestContext
{
    bool isCancelled() @safe
    {
        return false;
    }

    void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
    {
    }

    void log(string, Json, string = null) @safe
    {
    }

    Json sendRequest(string, Json) @safe
    {
        throw invalidRequest("This transport has no server-to-client channel");
    }

    bool clientSupports(string) @safe
    {
        return false;
    }

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
        return TokenInfo.invalid();
    }
}

/// Wraps a transport-supplied `RequestContext` with the per-request protocol
/// state the server determines only after parsing the message: whether the
/// request is stateless (MRTR), and the input responses the client attached.
/// The server installs this around the transport context before dispatching, so
/// handlers observe correct `isStateless`/`inputResponses` and `elicit`/`sample`
/// fail fast on stateless requests. Notifications and server->client requests
/// delegate to the wrapped context unchanged.
final class RequestScope : RequestContext
{
    private RequestContext inner;
    private bool stateless;
    private Json[string] responses;
    private string minLevel;
    private bool loggingRequested;
    private CancellationToken cancellation;

    this(RequestContext inner, bool stateless, Json[string] responses, string minLevel = "info",
            bool loggingRequested = true, CancellationToken cancellation = null) @safe
    {
        this.inner = inner;
        this.stateless = stateless;
        this.responses = responses;
        this.minLevel = minLevel;
        this.loggingRequested = loggingRequested;
        this.cancellation = cancellation;
    }

    /// True once the client has cancelled this request via
    /// `notifications/cancelled`. Reads the shared token the server installed for
    /// this request; if none was installed it delegates to the wrapped context.
    bool isCancelled() @safe
    {
        if (cancellation !is null && cancellation.cancelled)
            return true;
        return inner.isCancelled();
    }

    void reportProgress(double progress,
            Nullable!double total = Nullable!double.init, string message = null) @safe
    {
        inner.reportProgress(progress, total, message);
    }

    /// Emit a logging notification, but drop it when its severity is below the
    /// client-configured minimum (`logging/setLevel`) per the RFC 5424 ordering.
    /// This is where the server honours "Only sends error level and above".
    ///
    /// On the draft (stateless) protocol the server MUST NOT emit
    /// `notifications/message` for a request that did not carry
    /// `_meta["io.modelcontextprotocol/logLevel"]`; the server signals that by
    /// constructing this scope with `loggingRequested = false`, in which case
    /// every log is dropped regardless of severity.
    void log(string level, Json data, string logger = null) @safe
    {
        if (!loggingRequested)
            return;
        if (!shouldLog(level, minLevel))
            return;
        inner.log(level, data, logger);
    }

    Json sendRequest(string method, Json params) @safe
    {
        return inner.sendRequest(method, params);
    }

    bool clientSupports(string capability) @safe
    {
        return inner.clientSupports(capability);
    }

    bool isStateless() @safe
    {
        return stateless;
    }

    Json[string] inputResponses() @safe
    {
        return responses;
    }

    TokenInfo auth() @safe
    {
        return inner.auth();
    }
}

version (unittest) private final class SamplingProbe : RequestContext
{
    Json lastParams;

    bool isCancelled() @safe
    {
        return false;
    }

    void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
    {
    }

    void log(string, Json, string = null) @safe
    {
    }

    Json sendRequest(string method, Json params) @safe
    {
        lastParams = params;
        // Echo back a typed-looking sampling result.
        Json r = Json.emptyObject;
        r["role"] = "assistant";
        Json content = Json.emptyObject;
        content["type"] = "text";
        content["text"] = "echoed";
        r["content"] = content;
        r["model"] = "test-model";
        r["stopReason"] = "endTurn";
        return r;
    }

    bool clientSupports(string capability) @safe
    {
        return capability == "sampling";
    }

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
        return TokenInfo.invalid();
    }
}

version (unittest) private final class RootsProbe : RequestContext
{
    string lastMethod;
    Json lastParams;
    bool supportsRoots = true;

    bool isCancelled() @safe
    {
        return false;
    }

    void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
    {
    }

    void log(string, Json, string = null) @safe
    {
    }

    Json sendRequest(string method, Json params) @safe
    {
        lastMethod = method;
        lastParams = params;
        Json r = Json.emptyObject;
        Json arr = Json.emptyArray;
        Json root = Json.emptyObject;
        root["uri"] = "file:///home/user/project";
        root["name"] = "My Project";
        arr ~= root;
        r["roots"] = arr;
        return r;
    }

    bool clientSupports(string capability) @safe
    {
        return capability == "roots" && supportsRoots;
    }

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
        return TokenInfo.invalid();
    }
}

version (unittest) private final class ElicitProbe : RequestContext
{
    string lastMethod;
    Json lastParams;
    bool supportsElicitation = true;
    bool stateless = false;

    bool isCancelled() @safe
    {
        return false;
    }

    void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
    {
    }

    void log(string, Json, string = null) @safe
    {
    }

    Json sendRequest(string method, Json params) @safe
    {
        lastMethod = method;
        lastParams = params;
        Json r = Json.emptyObject;
        r["action"] = "accept";
        return r;
    }

    bool clientSupports(string capability) @safe
    {
        return capability == "elicitation" && supportsElicitation;
    }

    bool isStateless() @safe
    {
        return stateless;
    }

    Json[string] inputResponses() @safe
    {
        Json[string] empty;
        return empty;
    }

    TokenInfo auth() @safe
    {
        return TokenInfo.invalid();
    }
}

unittest  // elicitUrl() emits mode:"url" with message, url, and elicitationId
{
    auto probe = new ElicitProbe;
    auto result = probe.elicitUrl("Authorize access", "https://example.com/consent", "elic-123");

    assert(probe.lastMethod == "elicitation/create");
    assert(probe.lastParams["mode"].get!string == "url");
    assert(probe.lastParams["message"].get!string == "Authorize access");
    assert(probe.lastParams["url"].get!string == "https://example.com/consent");
    assert(probe.lastParams["elicitationId"].get!string == "elic-123");
    assert(result["action"].get!string == "accept");
}

unittest  // form-mode elicit() does not set a mode field
{
    auto probe = new ElicitProbe;
    probe.elicit("Pick one", Json.emptyObject);

    assert(probe.lastParams["mode"].type == Json.Type.undefined);
    assert(probe.lastParams["message"].get!string == "Pick one");
}

unittest  // elicitUrl() rejects an empty url
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto probe = new ElicitProbe;
    assertThrown!McpException(probe.elicitUrl("msg", "", "elic-1"));
}

unittest  // elicitUrl() rejects an empty elicitationId
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto probe = new ElicitProbe;
    assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", ""));
}

unittest  // elicitUrl() throws when the client does not support elicitation
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto probe = new ElicitProbe;
    probe.supportsElicitation = false;
    assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // elicitUrl() is rejected on a stateless (MRTR) request
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto probe = new ElicitProbe;
    probe.stateless = true;
    assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // listRoots() sends roots/list and parses the typed result
{
    auto probe = new RootsProbe;
    auto result = probe.listRoots();

    assert(probe.lastMethod == "roots/list");
    assert(result.roots.length == 1);
    assert(result.roots[0].uri == "file:///home/user/project");
    assert(result.roots[0].name.get == "My Project");
}

unittest  // listRoots() throws when client does not support roots
{
    import std.exception : assertThrown;
    import mcp.protocol.errors : McpException;

    auto probe = new RootsProbe;
    probe.supportsRoots = false;
    assertThrown!McpException(probe.listRoots());
}

unittest  // typed sample() builds params and parses the typed result
{
    import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage, StopReason;
    import mcp.protocol.types : Content;

    auto probe = new SamplingProbe;
    CreateMessageRequest req;
    req.messages = [SamplingMessage("user", Content.makeText("hi"))];
    req.maxTokens = 50;
    auto result = probe.sample(req);

    // Request was serialized to the wire shape.
    assert(probe.lastParams["messages"][0]["content"]["text"].get!string == "hi");
    assert(probe.lastParams["maxTokens"].get!long == 50);

    // Result parsed into a typed struct.
    assert(result.role == "assistant");
    assert(result.content.text == "echoed");
    assert(result.model == "test-model");
    assert(result.stopReasonEnum.get == StopReason.endTurn);
}

version (unittest) private final class LogProbe : RequestContext
{
    string[] emittedLevels;

    bool isCancelled() @safe
    {
        return false;
    }

    void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
    {
    }

    void log(string level, Json, string = null) @safe
    {
        emittedLevels ~= level;
    }

    Json sendRequest(string, Json) @safe
    {
        return Json.undefined;
    }

    bool clientSupports(string) @safe
    {
        return false;
    }

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
        return TokenInfo.invalid();
    }
}

unittest  // RequestScope drops log messages below the configured minimum level
{
    Json[string] empty;
    auto probe = new LogProbe;
    auto scope_ = new RequestScope(probe, false, empty, "error");

    scope_.log("debug", Json("d"));
    scope_.log("warning", Json("w"));
    scope_.log("error", Json("e"));
    scope_.log("critical", Json("c"));

    // Only error and above passed through to the inner transport context.
    assert(probe.emittedLevels == ["error", "critical"]);
}

unittest  // RequestScope with the default "info" minimum drops only debug
{
    Json[string] empty;
    auto probe = new LogProbe;
    auto scope_ = new RequestScope(probe, false, empty);

    scope_.log("debug", Json("d"));
    scope_.log("info", Json("i"));
    scope_.log("warning", Json("w"));

    assert(probe.emittedLevels == ["info", "warning"]);
}

unittest  // RequestScope exposes the shared cancellation token via isCancelled
{
    Json[string] empty;
    auto probe = new LogProbe;
    auto token = new CancellationToken;
    auto scope_ = new RequestScope(probe, false, empty, "info", true, token);

    assert(!scope_.isCancelled);
    token.cancel();
    assert(scope_.isCancelled);
}

unittest  // a CancellationToken starts uncancelled and cancel() is idempotent
{
    auto token = new CancellationToken;
    assert(!token.cancelled);
    token.cancel();
    assert(token.cancelled);
    token.cancel();
    assert(token.cancelled);
}

unittest  // NullContext reports never-cancelled (no out-of-band channel)
{
    auto ctx = new NullContext;
    assert(!ctx.isCancelled);
}
