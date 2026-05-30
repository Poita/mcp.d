module mcp.protocol.types;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;
import mcp.protocol.capabilities;

@safe:

/// The kind of a content block.
enum ContentKind
{
    text,
    image,
    audio,
    resourceLink,
    embeddedResource
}

/// A content block as used in tool results, prompt messages, and sampling.
///
/// Only the fields relevant to `kind` are meaningful; `toJson` emits the
/// spec-correct shape for each kind.
struct Content
{
    ContentKind kind;
    string text; /// text
    string data; /// image/audio: base64 payload
    string mimeType; /// image/audio/resource
    string uri; /// resourceLink/embeddedResource
    string name; /// resourceLink
    Json resource = Json.undefined; /// embeddedResource: the resource contents object

    static Content makeText(string t) @safe
    {
        Content c;
        c.kind = ContentKind.text;
        c.text = t;
        return c;
    }

    static Content makeImage(string base64, string mime) @safe
    {
        Content c;
        c.kind = ContentKind.image;
        c.data = base64;
        c.mimeType = mime;
        return c;
    }

    static Content makeAudio(string base64, string mime) @safe
    {
        Content c;
        c.kind = ContentKind.audio;
        c.data = base64;
        c.mimeType = mime;
        return c;
    }

    static Content makeResourceLink(string uri, string name, string mime = "") @safe
    {
        Content c;
        c.kind = ContentKind.resourceLink;
        c.uri = uri;
        c.name = name;
        c.mimeType = mime;
        return c;
    }

    static Content makeEmbeddedText(string uri, string mime, string text) @safe
    {
        Content c;
        c.kind = ContentKind.embeddedResource;
        Json r = Json.emptyObject;
        r["uri"] = uri;
        if (mime.length)
            r["mimeType"] = mime;
        r["text"] = text;
        c.resource = r;
        return c;
    }

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        final switch (kind)
        {
        case ContentKind.text:
            j["type"] = "text";
            j["text"] = text;
            break;
        case ContentKind.image:
            j["type"] = "image";
            j["data"] = data;
            j["mimeType"] = mimeType;
            break;
        case ContentKind.audio:
            j["type"] = "audio";
            j["data"] = data;
            j["mimeType"] = mimeType;
            break;
        case ContentKind.resourceLink:
            j["type"] = "resource_link";
            j["uri"] = uri;
            if (name.length)
                j["name"] = name;
            if (mimeType.length)
                j["mimeType"] = mimeType;
            break;
        case ContentKind.embeddedResource:
            j["type"] = "resource";
            j["resource"] = resource;
            break;
        }
        return j;
    }

    static Content fromJson(Json j) @safe
    {
        Content c;
        const t = ("type" in j) ? j["type"].get!string : "text";
        switch (t)
        {
        case "text":
            c.kind = ContentKind.text;
            c.text = ("text" in j) ? j["text"].get!string : "";
            break;
        case "image":
            c.kind = ContentKind.image;
            c.data = ("data" in j) ? j["data"].get!string : "";
            c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
            break;
        case "audio":
            c.kind = ContentKind.audio;
            c.data = ("data" in j) ? j["data"].get!string : "";
            c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
            break;
        case "resource_link":
            c.kind = ContentKind.resourceLink;
            c.uri = ("uri" in j) ? j["uri"].get!string : "";
            c.name = ("name" in j) ? j["name"].get!string : "";
            c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
            break;
        case "resource":
            c.kind = ContentKind.embeddedResource;
            c.resource = ("resource" in j) ? j["resource"] : Json.emptyObject;
            break;
        default:
            c.kind = ContentKind.text;
            break;
        }
        return c;
    }
}

/// A tool the server exposes for the model to call.
struct Tool
{
    string name;
    Nullable!string title;
    Nullable!string description;
    Json inputSchema = Json.undefined; /// JSON Schema (object); defaults to empty object schema
    Json outputSchema = Json.undefined; /// optional JSON Schema for structured results
    Json annotations = Json.undefined; /// optional ToolAnnotations

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["name"] = name;
        if (!title.isNull)
            j["title"] = title.get;
        if (!description.isNull)
            j["description"] = description.get;
        j["inputSchema"] = (inputSchema.type == Json.Type.object) ? inputSchema : emptyObjectSchema();
        if (outputSchema.type == Json.Type.object)
            j["outputSchema"] = outputSchema;
        if (annotations.type == Json.Type.object)
            j["annotations"] = annotations;
        return j;
    }

    static Tool fromJson(Json j) @safe
    {
        Tool t;
        t.name = ("name" in j) ? j["name"].get!string : "";
        if ("title" in j && j["title"].type == Json.Type.string)
            t.title = j["title"].get!string;
        if ("description" in j && j["description"].type == Json.Type.string)
            t.description = j["description"].get!string;
        if ("inputSchema" in j)
            t.inputSchema = j["inputSchema"];
        if ("outputSchema" in j)
            t.outputSchema = j["outputSchema"];
        if ("annotations" in j)
            t.annotations = j["annotations"];
        return t;
    }
}

/// An empty JSON Schema object: `{"type":"object"}`.
Json emptyObjectSchema() @safe
{
    Json s = Json.emptyObject;
    s["type"] = "object";
    return s;
}

/// Result of `tools/call`.
struct CallToolResult
{
    Content[] content;
    bool isError;
    Json structuredContent = Json.undefined;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (c; content)
            arr ~= c.toJson();
        j["content"] = arr;
        if (isError)
            j["isError"] = true;
        if (structuredContent.type != Json.Type.undefined)
            j["structuredContent"] = structuredContent;
        return j;
    }

    static CallToolResult fromJson(Json j) @safe
    {
        CallToolResult r;
        if ("content" in j && j["content"].type == Json.Type.array)
        {
            auto arr = j["content"];
            foreach (i; 0 .. arr.length)
                r.content ~= Content.fromJson(arr[i]);
        }
        if ("isError" in j && j["isError"].type == Json.Type.bool_)
            r.isError = j["isError"].get!bool;
        if ("structuredContent" in j)
            r.structuredContent = j["structuredContent"];
        return r;
    }
}

/// Result of `tools/list` (paginated).
struct ListToolsResult
{
    Tool[] tools;
    Nullable!string nextCursor;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (t; tools)
            arr ~= t.toJson();
        j["tools"] = arr;
        if (!nextCursor.isNull)
            j["nextCursor"] = nextCursor.get;
        return j;
    }

    static ListToolsResult fromJson(Json j) @safe
    {
        ListToolsResult r;
        if ("tools" in j && j["tools"].type == Json.Type.array)
        {
            auto arr = j["tools"];
            foreach (i; 0 .. arr.length)
                r.tools ~= Tool.fromJson(arr[i]);
        }
        if ("nextCursor" in j && j["nextCursor"].type == Json.Type.string)
            r.nextCursor = j["nextCursor"].get!string;
        return r;
    }
}

/// Parameters of the `initialize` request.
struct InitializeParams
{
    string protocolVersion;
    ClientCapabilities capabilities;
    Implementation clientInfo;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["protocolVersion"] = protocolVersion;
        j["capabilities"] = capabilities.toJson();
        j["clientInfo"] = clientInfo.toJson();
        return j;
    }

    static InitializeParams fromJson(Json j) @safe
    {
        InitializeParams p;
        p.protocolVersion = ("protocolVersion" in j) ? j["protocolVersion"].get!string : "";
        if ("capabilities" in j)
            p.capabilities = ClientCapabilities.fromJson(j["capabilities"]);
        if ("clientInfo" in j)
            p.clientInfo = Implementation.fromJson(j["clientInfo"]);
        return p;
    }
}

/// Result of the `initialize` request.
struct InitializeResult
{
    string protocolVersion;
    ServerCapabilities capabilities;
    Implementation serverInfo;
    Nullable!string instructions;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["protocolVersion"] = protocolVersion;
        j["capabilities"] = capabilities.toJson();
        j["serverInfo"] = serverInfo.toJson();
        if (!instructions.isNull)
            j["instructions"] = instructions.get;
        return j;
    }

    static InitializeResult fromJson(Json j) @safe
    {
        InitializeResult r;
        r.protocolVersion = ("protocolVersion" in j) ? j["protocolVersion"].get!string : "";
        if ("capabilities" in j)
            r.capabilities = ServerCapabilities.fromJson(j["capabilities"]);
        if ("serverInfo" in j)
            r.serverInfo = Implementation.fromJson(j["serverInfo"]);
        if ("instructions" in j && j["instructions"].type == Json.Type.string)
            r.instructions = j["instructions"].get!string;
        return r;
    }
}

unittest  // text content round-trips
{
    auto c = Content.makeText("hello");
    auto j = c.toJson();
    assert(j["type"].get!string == "text");
    assert(j["text"].get!string == "hello");
    assert(Content.fromJson(j).text == "hello");
}

unittest  // embedded text resource carries uri/mimeType/text
{
    auto c = Content.makeEmbeddedText("test://x", "text/plain", "hi");
    auto j = c.toJson();
    assert(j["type"].get!string == "resource");
    assert(j["resource"]["uri"].get!string == "test://x");
    assert(j["resource"]["mimeType"].get!string == "text/plain");
    assert(j["resource"]["text"].get!string == "hi");
    assert(Content.fromJson(j).kind == ContentKind.embeddedResource);
}

unittest  // resource link carries uri and name
{
    auto c = Content.makeResourceLink("file:///a", "a", "text/plain");
    auto j = c.toJson();
    assert(j["type"].get!string == "resource_link");
    assert(j["uri"].get!string == "file:///a");
    assert(j["name"].get!string == "a");
}

unittest  // image content uses data + mimeType
{
    auto c = Content.makeImage("YWJj", "image/png");
    auto j = c.toJson();
    assert(j["type"].get!string == "image");
    assert(j["data"].get!string == "YWJj");
    assert(j["mimeType"].get!string == "image/png");
    auto back = Content.fromJson(j);
    assert(back.kind == ContentKind.image && back.data == "YWJj");
}

unittest  // Tool defaults to an empty object input schema
{
    Tool t = {name: "noop"};
    auto j = t.toJson();
    assert(j["name"].get!string == "noop");
    assert(j["inputSchema"]["type"].get!string == "object");
    assert("description" !in j);
}

unittest  // Tool preserves provided schema and description
{
    Json schema = Json.emptyObject;
    schema["type"] = "object";
    Json props = Json.emptyObject;
    props["a"] = Json(["type": Json("integer")]);
    schema["properties"] = props;
    Tool t = {name: "add", description: nullable("adds"), inputSchema: schema};
    auto back = Tool.fromJson(t.toJson());
    assert(back.name == "add");
    assert(back.description.get == "adds");
    assert(back.inputSchema["properties"]["a"]["type"].get!string == "integer");
}

unittest  // CallToolResult serializes content array and isError
{
    CallToolResult r;
    r.content = [Content.makeText("oops")];
    r.isError = true;
    auto j = r.toJson();
    assert(j["content"][0]["text"].get!string == "oops");
    assert(j["isError"].get!bool);
    auto back = CallToolResult.fromJson(j);
    assert(back.isError && back.content.length == 1);
}

unittest  // CallToolResult omits isError when false
{
    CallToolResult r;
    r.content = [Content.makeText("ok")];
    assert("isError" !in r.toJson());
}

unittest  // ListToolsResult carries tools and optional cursor
{
    ListToolsResult r;
    r.tools = [Tool(name: "a"), Tool(name: "b")];
    r.nextCursor = "next";
    auto j = r.toJson();
    assert(j["tools"].length == 2);
    assert(j["nextCursor"].get!string == "next");
    auto back = ListToolsResult.fromJson(j);
    assert(back.tools.length == 2 && back.nextCursor.get == "next");
}

unittest  // InitializeParams round-trips protocol version and client info
{
    InitializeParams p;
    p.protocolVersion = "2025-11-25";
    p.clientInfo = Implementation("cli", "0.1");
    p.capabilities.sampling = true;
    auto back = InitializeParams.fromJson(p.toJson());
    assert(back.protocolVersion == "2025-11-25");
    assert(back.clientInfo.name == "cli");
    assert(back.capabilities.sampling);
}

unittest  // InitializeResult round-trips capabilities and server info
{
    InitializeResult r;
    r.protocolVersion = "2025-11-25";
    r.serverInfo = Implementation("srv", "1.0");
    r.capabilities.tools = ListChangedCapability(false);
    r.instructions = "be nice";
    auto back = InitializeResult.fromJson(r.toJson());
    assert(back.protocolVersion == "2025-11-25");
    assert(back.serverInfo.name == "srv");
    assert(!back.capabilities.tools.isNull);
    assert(back.instructions.get == "be nice");
}
