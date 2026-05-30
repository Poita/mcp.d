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
    requestCancelled = -32800,
    // draft Streamable HTTP: header/body validation failure
    headerMismatch = -32001,
    // draft: requested protocol version not supported (data: {supported, requested})
    unsupportedProtocolVersion = -32004,
    // 2025-11-25 (elicitation §"URL Elicitation Required Error"): a request
    // cannot be processed until a URL-mode elicitation is completed. The error
    // MUST carry a `data.elicitations` list of URL-mode elicitations.
    urlElicitationRequired = -32042,
    // sampling (client/sampling §Error Handling): the user declined the
    // server's `sampling/createMessage` request. Not a JSON-RPC reserved code;
    // the spec assigns this conventional value.
    userRejected = -1
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

/// A single URL-mode elicitation entry carried by a `-32042`
/// `URLElicitationRequiredError` (2025-11-25 elicitation §"URL Elicitation
/// Required Error"). Each entry directs the user to complete an out-of-band
/// interaction at `url`; `elicitationId` correlates the request with the
/// outcome the client later reports back.
struct UrlElicitation
{
    string elicitationId; /// correlation id for the elicitation outcome
    string url; /// where the user completes the interaction
    string message; /// human-readable description shown to the user

    /// Serialize to the wire shape `{mode:"url", elicitationId, url, message}`.
    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["mode"] = "url";
        j["elicitationId"] = elicitationId;
        j["url"] = url;
        j["message"] = message;
        return j;
    }
}

/// Build the `-32042` `URLElicitationRequiredError` a server returns when a
/// request cannot be processed until one or more URL-mode elicitations are
/// completed (2025-11-25 elicitation §"URL Elicitation Required Error"). The
/// error's `data.elicitations` array carries the URL-mode elicitations the
/// client must complete first; each entry is emitted as
/// `{mode:"url", elicitationId, url, message}`.
///
/// At least one elicitation is required, and every entry MUST have a non-empty
/// `elicitationId` and `url`; otherwise this throws.
McpException urlElicitationRequired(const UrlElicitation[] elicitations,
        string message = "URL elicitation required") @safe
{
    import std.exception : enforce;

    enforce(elicitations.length > 0,
            "URLElicitationRequiredError requires at least one elicitation");
    Json arr = Json.emptyArray;
    foreach (const ref e; elicitations)
    {
        enforce(e.elicitationId.length > 0, "URL elicitation requires a non-empty elicitationId");
        enforce(e.url.length > 0, "URL elicitation requires a non-empty url");
        arr ~= e.toJson();
    }
    Json data = Json.emptyObject;
    data["elicitations"] = arr;
    return new McpException(ErrorCode.urlElicitationRequired, message, data);
}

/// Build the conventional `-1` "User rejected sampling request" error a client
/// `onSampling` delegate SHOULD return when the user declines the request
/// (client/sampling §Error Handling).
McpException userRejected(string message = "User rejected sampling request",
        Json data = Json.undefined) @safe pure nothrow
{
    return new McpException(ErrorCode.userRejected, message, data);
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

unittest  // userRejected uses the conventional -1 sampling code
{
    auto e = userRejected();
    assert(e.code == -1);
    assert(e.code == ErrorCode.userRejected);
    assert(e.msg == "User rejected sampling request");
}

unittest  // userRejected accepts a custom message
{
    auto e = userRejected("nope, not this time");
    assert(e.code == ErrorCode.userRejected);
    assert(e.msg == "nope, not this time");
}

unittest  // toErrorJson includes data when present
{
    auto e = new McpException(ErrorCode.invalidParams, "bad", Json([
        "field": Json("name")
    ]));
    auto j = e.toErrorJson();
    assert(j["data"]["field"].get!string == "name");
}

unittest  // urlElicitationRequired uses the -32042 code
{
    auto e = urlElicitationRequired([
        UrlElicitation("elic-1", "https://example.com/consent", "Authorize access")
    ]);
    assert(e.code == -32042);
    assert(e.code == ErrorCode.urlElicitationRequired);
}

unittest  // urlElicitationRequired attaches the data.elicitations array
{
    auto e = urlElicitationRequired([
        UrlElicitation("elic-1", "https://example.com/consent", "Authorize access")
    ]);
    auto j = e.toErrorJson();
    auto elics = j["data"]["elicitations"];
    assert(elics.type == Json.Type.array);
    assert(elics.length == 1);
    assert(elics[0]["mode"].get!string == "url");
    assert(elics[0]["elicitationId"].get!string == "elic-1");
    assert(elics[0]["url"].get!string == "https://example.com/consent");
    assert(elics[0]["message"].get!string == "Authorize access");
}

unittest  // urlElicitationRequired carries multiple elicitations
{
    auto e = urlElicitationRequired([
        UrlElicitation("a", "https://example.com/a", "first"),
        UrlElicitation("b", "https://example.com/b", "second")
    ]);
    auto j = e.toErrorJson();
    assert(j["data"]["elicitations"].length == 2);
    assert(j["data"]["elicitations"][1]["elicitationId"].get!string == "b");
}

unittest  // urlElicitationRequired requires at least one elicitation
{
    import std.exception : assertThrown;

    assertThrown!Exception(urlElicitationRequired([]));
}

unittest  // urlElicitationRequired rejects an entry missing elicitationId
{
    import std.exception : assertThrown;

    assertThrown!Exception(urlElicitationRequired([
        UrlElicitation("", "https://example.com", "msg")
    ]));
}

unittest  // urlElicitationRequired rejects an entry missing url
{
    import std.exception : assertThrown;

    assertThrown!Exception(urlElicitationRequired([
        UrlElicitation("id", "", "msg")
    ]));
}
