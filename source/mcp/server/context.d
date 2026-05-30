module mcp.server.context;

import std.typecons : Nullable;
import vibe.data.json : Json;

import mcp.protocol.errors;
import mcp.auth.resource_server : TokenInfo;

@safe:

/// Per-request context handed to tool handlers. It is the channel through which
/// a handler emits server->client traffic while a request is in flight:
/// progress + logging notifications, and (blocking) sampling / elicitation
/// requests. Transports supply a concrete implementation; the in-process and
/// stdio paths use `NullContext` (notifications are dropped, server->client
/// requests are unsupported).
interface RequestContext
{
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

    /// Request structured user input from the client (`elicitation/create`).
    /// `requestedSchema` must be a JSON Schema object. Throws on a stateless
    /// (MRTR) request — use `ToolResponse.inputRequired` instead — or if the
    /// client does not support elicitation.
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
}

/// A context with no client channel: notifications are dropped and
/// server->client requests are rejected. Used by transports that do not (yet)
/// support streaming, and as the default when none is supplied.
final class NullContext : RequestContext
{
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

    this(RequestContext inner, bool stateless, Json[string] responses) @safe
    {
        this.inner = inner;
        this.stateless = stateless;
        this.responses = responses;
    }

    void reportProgress(double progress,
            Nullable!double total = Nullable!double.init, string message = null) @safe
    {
        inner.reportProgress(progress, total, message);
    }

    void log(string level, Json data, string logger = null) @safe
    {
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
