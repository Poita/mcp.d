module mcp.protocol.errors;

import vibe.data.json : Json;

@safe:

/// Standard JSON-RPC 2.0 + MCP error codes.
enum ErrorCode : int
{
    parseError = -32700,
    invalidRequest = -32600,
    methodNotFound = -32601,
    invalidParams = -32602,
    internalError = -32603,
    // MCP-specific
    resourceNotFound = -32002,
    requestCancelled = -32800
}

/// An error that maps onto a JSON-RPC error object.
class McpException : Exception
{
    int code;
    Json data; /// optional structured payload; `Json.undefined` if none

    this(int code, string message, Json data = Json.undefined,
            string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
    {
        super(message, file, line);
        this.code = code;
        this.data = data;
    }
}

/// Build the JSON-RPC error object `{code, message, data?}`.
Json toErrorJson(const McpException e) @safe
{
    Json j = Json.emptyObject;
    j["code"] = e.code;
    j["message"] = e.msg;
    if (e.data.type != Json.Type.undefined)
        j["data"] = e.data;
    return j;
}

McpException parseError(string message, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.parseError, message, data);
}

McpException invalidRequest(string message, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.invalidRequest, message, data);
}

McpException methodNotFound(string method, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.methodNotFound, "Method not found: " ~ method, data);
}

McpException invalidParams(string message, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.invalidParams, message, data);
}

McpException internalError(string message, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.internalError, message, data);
}

McpException resourceNotFound(string uri, Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.resourceNotFound, "Resource not found: " ~ uri, data);
}

unittest  // McpException carries code and message
{
    auto e = new McpException(ErrorCode.invalidParams, "bad arg");
    assert(e.code == -32602);
    assert(e.msg == "bad arg");
}

unittest  // convenience constructors set the right code
{
    assert(methodNotFound("nope").code == ErrorCode.methodNotFound);
    assert(invalidParams("x").code == ErrorCode.invalidParams);
    assert(resourceNotFound("file:///x").code == ErrorCode.resourceNotFound);
}

unittest  // toErrorJson produces a JSON-RPC error object
{
    auto e = new McpException(ErrorCode.internalError, "boom");
    auto j = e.toErrorJson();
    assert(j["code"].get!int == -32603);
    assert(j["message"].get!string == "boom");
    assert("data" !in j); // undefined data omitted
}

unittest  // toErrorJson includes data when present
{
    auto e = new McpException(ErrorCode.invalidParams, "bad", Json([
            "field": Json("name")
    ]));
    auto j = e.toErrorJson();
    assert(j["data"]["field"].get!string == "name");
}
