module mcp.protocol.jsonrpc;

import vibe.data.json : Json, parseJsonString;
import mcp.protocol.errors;

@safe:

/// What a JSON-RPC message represents.
enum MessageKind
{
    request,
    notification,
    response,
    errorResponse
}

/// A classified JSON-RPC message wrapping its raw Json.
struct Message
{
    Json raw;

    MessageKind kind() const @safe
    {
        const hasId = "id" in raw && raw["id"].type != Json.Type.undefined
            && raw["id"].type != Json.Type.null_;
        const hasMethod = "method" in raw;
        if (hasMethod)
            return hasId ? MessageKind.request : MessageKind.notification;
        if ("error" in raw)
            return MessageKind.errorResponse;
        return MessageKind.response;
    }

    string method() const @safe
    {
        return ("method" in raw) ? raw["method"].get!string : null;
    }

    Json id() const @safe
    {
        return ("id" in raw) ? raw["id"] : Json(null);
    }

    Json params() const @safe
    {
        return ("params" in raw) ? raw["params"] : Json.emptyObject;
    }

    Json result() const @safe
    {
        return ("result" in raw) ? raw["result"] : Json.undefined;
    }

    Json error() const @safe
    {
        return ("error" in raw) ? raw["error"] : Json.undefined;
    }
}

private void validateEnvelope(Json j) @safe
{
    if (j.type != Json.Type.object)
        throw invalidRequest("JSON-RPC message must be an object");
    if (("jsonrpc" !in j) || j["jsonrpc"].get!string != "2.0")
        throw invalidRequest("Missing or invalid jsonrpc version (expected \"2.0\")");
}

/// Parse and classify a single JSON-RPC message from text.
Message parseMessage(string text) @safe
{
    Json j;
    try
        j = parseJsonString(text);
    catch (Exception e)
        throw parseError("Invalid JSON: " ~ e.msg);
    validateEnvelope(j);
    return Message(j);
}

/// Parse a JSON-RPC batch (array) from text.
Message[] parseBatch(string text) @safe
{
    Json arr;
    try
        arr = parseJsonString(text);
    catch (Exception e)
        throw parseError("Invalid JSON: " ~ e.msg);
    if (arr.type != Json.Type.array)
        throw invalidRequest("Batch must be a JSON array");
    if (arr.length == 0)
        throw invalidRequest("Batch must not be empty");
    Message[] msgs;
    foreach (i; 0 .. arr.length)
    {
        auto item = arr[i];
        validateEnvelope(item);
        msgs ~= Message(item);
    }
    return msgs;
}

/// Result of `parseAny`: a single message or a batch, normalized to a list.
struct ParsedInput
{
    bool isBatch;
    Message[] messages;
}

/// Parse text that may be either a single message or a batch array.
ParsedInput parseAny(string text) @safe
{
    import std.string : strip, startsWith;

    if (text.strip.startsWith("["))
        return ParsedInput(true, parseBatch(text));
    return ParsedInput(false, [parseMessage(text)]);
}

/// Build a request object.
Json makeRequest(Json id, string method, Json params = Json.undefined) @safe
{
    Json j = Json.emptyObject;
    j["jsonrpc"] = "2.0";
    j["id"] = id;
    j["method"] = method;
    if (params.type != Json.Type.undefined)
        j["params"] = params;
    return j;
}

/// Build a notification object (no id).
Json makeNotification(string method, Json params = Json.undefined) @safe
{
    Json j = Json.emptyObject;
    j["jsonrpc"] = "2.0";
    j["method"] = method;
    if (params.type != Json.Type.undefined)
        j["params"] = params;
    return j;
}

/// Build a success response object.
Json makeResponse(Json id, Json result) @safe
{
    Json j = Json.emptyObject;
    j["jsonrpc"] = "2.0";
    j["id"] = id;
    j["result"] = result;
    return j;
}

/// Build an error response object from an McpException.
Json makeErrorResponse(Json id, const McpException e) @safe
{
    Json j = Json.emptyObject;
    j["jsonrpc"] = "2.0";
    j["id"] = id;
    j["error"] = toErrorJson(e);
    return j;
}

unittest  // classify a request
{
    auto m = parseMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
    assert(m.kind == MessageKind.request);
    assert(m.method == "ping");
    assert(m.id == Json(1));
}

unittest  // classify a notification (no id)
{
    auto m = parseMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
    assert(m.kind == MessageKind.notification);
    assert(m.method == "notifications/initialized");
}

unittest  // classify a success response
{
    auto m = parseMessage(`{"jsonrpc":"2.0","id":"abc","result":{"ok":true}}`);
    assert(m.kind == MessageKind.response);
    assert(m.id == Json("abc"));
    assert(m.result["ok"].get!bool);
}

unittest  // classify an error response
{
    auto m = parseMessage(`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"x"}}`);
    assert(m.kind == MessageKind.errorResponse);
    assert(m.error["code"].get!int == -32601);
}

unittest  // reject wrong jsonrpc version
{
    import std.exception : assertThrown;

    assertThrown!McpException(parseMessage(`{"jsonrpc":"1.0","id":1,"method":"x"}`));
}

unittest  // reject malformed json with a parse error
{
    import std.exception : assertThrown;

    assertThrown!McpException(parseMessage(`{not json`));
}

unittest  // builders produce spec-shaped objects
{
    auto req = makeRequest(Json(7), "tools/list", Json(["cursor": Json("c1")]));
    assert(req["jsonrpc"].get!string == "2.0");
    assert(req["id"].get!int == 7);
    assert(req["method"].get!string == "tools/list");
    assert(req["params"]["cursor"].get!string == "c1");

    auto note = makeNotification("notifications/cancelled", Json([
            "requestId": Json(7)
    ]));
    assert("id" !in note);
    assert(note["method"].get!string == "notifications/cancelled");

    auto ok = makeResponse(Json(7), Json(["tools": Json.emptyArray]));
    assert(ok["result"]["tools"].length == 0);

    auto err = makeErrorResponse(Json(7), new McpException(ErrorCode.methodNotFound, "no"));
    assert(err["error"]["code"].get!int == -32601);
    assert("result" !in err);
}

unittest  // batch parsing: array of messages
{
    auto batch = parseBatch(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}]`);
    assert(batch.length == 2);
    assert(batch[0].kind == MessageKind.request);
    assert(batch[1].kind == MessageKind.notification);
}

unittest  // parseAny distinguishes single vs batch
{
    auto single = parseAny(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
    assert(!single.isBatch && single.messages.length == 1);

    auto many = parseAny(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`);
    assert(many.isBatch && many.messages.length == 1);
}
