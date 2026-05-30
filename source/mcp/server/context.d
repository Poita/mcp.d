module mcp.server.context;

import std.typecons : Nullable;
import vibe.data.json : Json;

import mcp.protocol.errors;

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

    /// Request an LLM completion from the client (`sampling/createMessage`).
    /// Throws if the client does not support sampling.
    final Json sample(Json params) @safe
    {
        if (!clientSupports("sampling"))
            throw invalidRequest("Client does not support sampling");
        return sendRequest("sampling/createMessage", params);
    }

    /// Request structured user input from the client (`elicitation/create`).
    /// `requestedSchema` must be a JSON Schema object. Throws if the client does
    /// not support elicitation.
    final Json elicit(string message, Json requestedSchema) @safe
    {
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
}
