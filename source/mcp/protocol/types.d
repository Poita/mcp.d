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
    Json annotations = Json.undefined; /// optional annotations (audience/priority/lastModified)

    /// Attach optional annotations (audience/priority/lastModified) to this
    /// content block. Returns a copy so calls can be chained, e.g.
    /// `Content.makeText("hi").withAnnotations(a)`.
    Content withAnnotations(Json a) const @safe
    {
        Content c = this;
        c.annotations = a;
        return c;
    }

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
        if (annotations.type != Json.Type.undefined)
            j["annotations"] = annotations;
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
        if ("annotations" in j)
            c.annotations = j["annotations"];
        return c;
    }
}

/// An icon for display in user interfaces. Used by `Tool` (and other
/// definitions) per the MCP spec's icon shape: a required `src` and optional
/// `mimeType` and `sizes`.
struct Icon
{
    string src; /// URI or data: URL of the icon
    Nullable!string mimeType; /// optional MIME type, e.g. "image/png"
    string[] sizes; /// optional size strings, e.g. ["48x48", "96x96"]

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["src"] = src;
        if (!mimeType.isNull)
            j["mimeType"] = mimeType.get;
        if (sizes.length)
        {
            Json arr = Json.emptyArray;
            foreach (s; sizes)
                arr ~= Json(s);
            j["sizes"] = arr;
        }
        return j;
    }

    static Icon fromJson(Json j) @safe
    {
        Icon icon;
        icon.src = ("src" in j) ? j["src"].get!string : "";
        if ("mimeType" in j && j["mimeType"].type == Json.Type.string)
            icon.mimeType = j["mimeType"].get!string;
        if ("sizes" in j && j["sizes"].type == Json.Type.array)
            foreach (i; 0 .. j["sizes"].length)
                icon.sizes ~= j["sizes"][i].get!string;
        return icon;
    }
}

/// Optional properties describing a tool's behavior, per the MCP spec's
/// `ToolAnnotations`. All hints are advisory and optional; a hint that is left
/// `null` is omitted from the serialized form (and clients SHOULD treat its
/// absence as "unspecified" rather than a particular default).
struct ToolAnnotations
{
    Nullable!string title; /// human-readable title for display
    Nullable!bool readOnlyHint; /// if true, the tool does not modify its environment
    Nullable!bool destructiveHint; /// if true, the tool may perform destructive updates
    Nullable!bool idempotentHint; /// if true, repeated calls with the same args have no additional effect
    Nullable!bool openWorldHint; /// if true, the tool interacts with an "open world" of external entities

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (!title.isNull)
            j["title"] = title.get;
        if (!readOnlyHint.isNull)
            j["readOnlyHint"] = readOnlyHint.get;
        if (!destructiveHint.isNull)
            j["destructiveHint"] = destructiveHint.get;
        if (!idempotentHint.isNull)
            j["idempotentHint"] = idempotentHint.get;
        if (!openWorldHint.isNull)
            j["openWorldHint"] = openWorldHint.get;
        return j;
    }

    static ToolAnnotations fromJson(Json j) @safe
    {
        ToolAnnotations a;
        if ("title" in j && j["title"].type == Json.Type.string)
            a.title = j["title"].get!string;
        if ("readOnlyHint" in j && j["readOnlyHint"].type == Json.Type.bool_)
            a.readOnlyHint = j["readOnlyHint"].get!bool;
        if ("destructiveHint" in j && j["destructiveHint"].type == Json.Type.bool_)
            a.destructiveHint = j["destructiveHint"].get!bool;
        if ("idempotentHint" in j && j["idempotentHint"].type == Json.Type.bool_)
            a.idempotentHint = j["idempotentHint"].get!bool;
        if ("openWorldHint" in j && j["openWorldHint"].type == Json.Type.bool_)
            a.openWorldHint = j["openWorldHint"].get!bool;
        return a;
    }

    /// True if no hint is set (serializes to an empty object).
    bool empty() const @safe
    {
        return title.isNull && readOnlyHint.isNull && destructiveHint.isNull
            && idempotentHint.isNull && openWorldHint.isNull;
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
    Icon[] icons; /// optional icons for display in user interfaces

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
        if (icons.length)
        {
            Json arr = Json.emptyArray;
            foreach (icon; icons)
                arr ~= icon.toJson();
            j["icons"] = arr;
        }
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
        if ("icons" in j && j["icons"].type == Json.Type.array)
            foreach (i; 0 .. j["icons"].length)
                t.icons ~= Icon.fromJson(j["icons"][i]);
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

unittest  // content omits annotations key when none are set
{
    auto c = Content.makeText("hello");
    auto j = c.toJson();
    assert("annotations" !in j);
}

unittest  // content emits annotations when present
{
    Json a = Json.emptyObject;
    a["audience"] = Json([Json("user")]);
    a["priority"] = Json(0.9);
    auto c = Content.makeImage("YWJj", "image/png").withAnnotations(a);
    auto j = c.toJson();
    assert(j["annotations"]["audience"][0].get!string == "user");
    assert(j["annotations"]["priority"].get!double == 0.9);
}

unittest  // inbound content annotations are preserved on fromJson
{
    Json a = Json.emptyObject;
    a["audience"] = Json([Json("assistant")]);
    a["lastModified"] = Json("2025-01-01T00:00:00Z");
    auto orig = Content.makeText("hi").withAnnotations(a);
    auto back = Content.fromJson(orig.toJson());
    assert(back.annotations.type == Json.Type.object);
    assert(back.annotations["audience"][0].get!string == "assistant");
    assert(back.annotations["lastModified"].get!string == "2025-01-01T00:00:00Z");
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

unittest  // Tool emits icons array when present
{
    Tool t = {name: "draw"};
    t.icons = [
        Icon("https://example.com/draw.png", nullable("image/png"), ["48x48"])
    ];
    auto j = t.toJson();
    assert(j["icons"].type == Json.Type.array);
    assert(j["icons"].length == 1);
    assert(j["icons"][0]["src"].get!string == "https://example.com/draw.png");
    assert(j["icons"][0]["mimeType"].get!string == "image/png");
    assert(j["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // Tool omits icons when empty
{
    Tool t = {name: "noicons"};
    auto j = t.toJson();
    assert("icons" !in j);
}

unittest  // Tool icons round-trip through fromJson, including optional fields
{
    Tool t = {name: "img"};
    t.icons = [
        Icon("https://example.com/a.svg"),
        Icon("https://example.com/b.png", nullable("image/png"), [
            "16x16", "32x32"
        ])
    ];
    auto back = Tool.fromJson(t.toJson());
    assert(back.icons.length == 2);
    assert(back.icons[0].src == "https://example.com/a.svg");
    assert(back.icons[0].mimeType.isNull);
    assert(back.icons[0].sizes.length == 0);
    assert(back.icons[1].src == "https://example.com/b.png");
    assert(back.icons[1].mimeType.get == "image/png");
    assert(back.icons[1].sizes == ["16x16", "32x32"]);
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

// ===========================================================================
// Resources
// ===========================================================================

/// A direct resource the server exposes.
struct Resource
{
    string uri;
    string name;
    Nullable!string description;
    Nullable!string mimeType;
    Nullable!string title;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["uri"] = uri;
        j["name"] = name;
        if (!title.isNull)
            j["title"] = title.get;
        if (!description.isNull)
            j["description"] = description.get;
        if (!mimeType.isNull)
            j["mimeType"] = mimeType.get;
        return j;
    }

    static Resource fromJson(Json j) @safe
    {
        Resource r;
        r.uri = ("uri" in j) ? j["uri"].get!string : "";
        r.name = ("name" in j) ? j["name"].get!string : "";
        if ("title" in j && j["title"].type == Json.Type.string)
            r.title = j["title"].get!string;
        if ("description" in j && j["description"].type == Json.Type.string)
            r.description = j["description"].get!string;
        if ("mimeType" in j && j["mimeType"].type == Json.Type.string)
            r.mimeType = j["mimeType"].get!string;
        return r;
    }
}

/// A parameterized resource template (RFC 6570-style `{var}` placeholders).
struct ResourceTemplate
{
    string uriTemplate;
    string name;
    Nullable!string description;
    Nullable!string mimeType;
    Nullable!string title;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["uriTemplate"] = uriTemplate;
        j["name"] = name;
        if (!title.isNull)
            j["title"] = title.get;
        if (!description.isNull)
            j["description"] = description.get;
        if (!mimeType.isNull)
            j["mimeType"] = mimeType.get;
        return j;
    }
}

/// The contents of a resource read: either UTF-8 text or base64 blob.
struct ResourceContents
{
    string uri;
    string mimeType;
    bool isBlob;
    string text;
    string blob;

    static ResourceContents makeText(string uri, string mime, string text) @safe
    {
        ResourceContents c;
        c.uri = uri;
        c.mimeType = mime;
        c.text = text;
        return c;
    }

    static ResourceContents makeBlob(string uri, string mime, string base64) @safe
    {
        ResourceContents c;
        c.uri = uri;
        c.mimeType = mime;
        c.isBlob = true;
        c.blob = base64;
        return c;
    }

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["uri"] = uri;
        if (mimeType.length)
            j["mimeType"] = mimeType;
        if (isBlob)
            j["blob"] = blob;
        else
            j["text"] = text;
        return j;
    }

    static ResourceContents fromJson(Json j) @safe
    {
        ResourceContents c;
        c.uri = ("uri" in j) ? j["uri"].get!string : "";
        if ("mimeType" in j && j["mimeType"].type == Json.Type.string)
            c.mimeType = j["mimeType"].get!string;
        if ("blob" in j && j["blob"].type == Json.Type.string)
        {
            c.isBlob = true;
            c.blob = j["blob"].get!string;
        }
        else if ("text" in j && j["text"].type == Json.Type.string)
            c.text = j["text"].get!string;
        return c;
    }
}

/// Result of `resources/list`.
struct ListResourcesResult
{
    Resource[] resources;
    Nullable!string nextCursor;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (r; resources)
            arr ~= r.toJson();
        j["resources"] = arr;
        if (!nextCursor.isNull)
            j["nextCursor"] = nextCursor.get;
        return j;
    }

    static ListResourcesResult fromJson(Json j) @safe
    {
        ListResourcesResult r;
        if ("resources" in j && j["resources"].type == Json.Type.array)
        {
            auto arr = j["resources"];
            foreach (i; 0 .. arr.length)
                r.resources ~= Resource.fromJson(arr[i]);
        }
        if ("nextCursor" in j && j["nextCursor"].type == Json.Type.string)
            r.nextCursor = j["nextCursor"].get!string;
        return r;
    }
}

/// Result of `resources/templates/list`.
struct ListResourceTemplatesResult
{
    ResourceTemplate[] resourceTemplates;
    Nullable!string nextCursor;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (t; resourceTemplates)
            arr ~= t.toJson();
        j["resourceTemplates"] = arr;
        if (!nextCursor.isNull)
            j["nextCursor"] = nextCursor.get;
        return j;
    }
}

/// Result of `resources/read`.
struct ReadResourceResult
{
    ResourceContents[] contents;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (c; contents)
            arr ~= c.toJson();
        j["contents"] = arr;
        return j;
    }

    static ReadResourceResult fromJson(Json j) @safe
    {
        ReadResourceResult r;
        if ("contents" in j && j["contents"].type == Json.Type.array)
        {
            auto arr = j["contents"];
            foreach (i; 0 .. arr.length)
                r.contents ~= ResourceContents.fromJson(arr[i]);
        }
        return r;
    }
}

// ===========================================================================
// Prompts
// ===========================================================================

/// A declared prompt argument.
struct PromptArgument
{
    string name;
    Nullable!string description;
    bool required;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["name"] = name;
        if (!description.isNull)
            j["description"] = description.get;
        if (required)
            j["required"] = true;
        return j;
    }

    static PromptArgument fromJson(Json j) @safe
    {
        PromptArgument a;
        a.name = ("name" in j) ? j["name"].get!string : "";
        if ("description" in j && j["description"].type == Json.Type.string)
            a.description = j["description"].get!string;
        if ("required" in j && j["required"].type == Json.Type.bool_)
            a.required = j["required"].get!bool;
        return a;
    }
}

/// A prompt the server exposes.
struct Prompt
{
    string name;
    Nullable!string description;
    PromptArgument[] arguments;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["name"] = name;
        if (!description.isNull)
            j["description"] = description.get;
        if (arguments.length)
        {
            Json arr = Json.emptyArray;
            foreach (a; arguments)
                arr ~= a.toJson();
            j["arguments"] = arr;
        }
        return j;
    }

    static Prompt fromJson(Json j) @safe
    {
        Prompt p;
        p.name = ("name" in j) ? j["name"].get!string : "";
        if ("description" in j && j["description"].type == Json.Type.string)
            p.description = j["description"].get!string;
        if ("arguments" in j && j["arguments"].type == Json.Type.array)
        {
            auto arr = j["arguments"];
            foreach (i; 0 .. arr.length)
                p.arguments ~= PromptArgument.fromJson(arr[i]);
        }
        return p;
    }
}

/// A single message in a prompt result.
struct PromptMessage
{
    string role; /// "user" or "assistant"
    Content content;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["role"] = role;
        j["content"] = content.toJson();
        return j;
    }

    static PromptMessage fromJson(Json j) @safe
    {
        PromptMessage m;
        m.role = ("role" in j) ? j["role"].get!string : "";
        if ("content" in j)
            m.content = Content.fromJson(j["content"]);
        return m;
    }
}

/// Result of `prompts/list`.
struct ListPromptsResult
{
    Prompt[] prompts;
    Nullable!string nextCursor;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (p; prompts)
            arr ~= p.toJson();
        j["prompts"] = arr;
        if (!nextCursor.isNull)
            j["nextCursor"] = nextCursor.get;
        return j;
    }

    static ListPromptsResult fromJson(Json j) @safe
    {
        ListPromptsResult r;
        if ("prompts" in j && j["prompts"].type == Json.Type.array)
        {
            auto arr = j["prompts"];
            foreach (i; 0 .. arr.length)
                r.prompts ~= Prompt.fromJson(arr[i]);
        }
        if ("nextCursor" in j && j["nextCursor"].type == Json.Type.string)
            r.nextCursor = j["nextCursor"].get!string;
        return r;
    }
}

/// Result of `prompts/get`.
struct GetPromptResult
{
    Nullable!string description;
    PromptMessage[] messages;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (!description.isNull)
            j["description"] = description.get;
        Json arr = Json.emptyArray;
        foreach (m; messages)
            arr ~= m.toJson();
        j["messages"] = arr;
        return j;
    }

    static GetPromptResult fromJson(Json j) @safe
    {
        GetPromptResult r;
        if ("description" in j && j["description"].type == Json.Type.string)
            r.description = j["description"].get!string;
        if ("messages" in j && j["messages"].type == Json.Type.array)
        {
            auto arr = j["messages"];
            foreach (i; 0 .. arr.length)
                r.messages ~= PromptMessage.fromJson(arr[i]);
        }
        return r;
    }
}

// ===========================================================================
// Completion
// ===========================================================================

/// Result of `completion/complete`.
struct CompleteResult
{
    string[] values;
    Nullable!size_t total;
    bool hasMore;

    Json toJson() const @safe
    {
        Json completion = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (v; values)
            arr ~= Json(v);
        completion["values"] = arr;
        if (!total.isNull)
            completion["total"] = total.get;
        completion["hasMore"] = hasMore;
        Json j = Json.emptyObject;
        j["completion"] = completion;
        return j;
    }
}

unittest  // Resource serializes required + optional fields
{
    Resource r = {uri: "test://x", name: "x", description: nullable("d")};
    auto j = r.toJson();
    assert(j["uri"].get!string == "test://x");
    assert(j["name"].get!string == "x");
    assert(j["description"].get!string == "d");
    assert("mimeType" !in j);
}

unittest  // ResourceContents text vs blob are mutually exclusive
{
    auto t = ResourceContents.makeText("u", "text/plain", "hi");
    assert("text" in t.toJson() && "blob" !in t.toJson());
    auto b = ResourceContents.makeBlob("u", "image/png", "QUJD");
    assert("blob" in b.toJson() && "text" !in b.toJson());
}

unittest  // ReadResourceResult wraps contents array
{
    ReadResourceResult r;
    r.contents = [ResourceContents.makeText("u", "text/plain", "hi")];
    assert(r.toJson()["contents"][0]["text"].get!string == "hi");
}

unittest  // Prompt with arguments serializes the argument list
{
    Prompt p = {name: "greet", description: nullable("greets")};
    p.arguments = [PromptArgument("who", nullable("name"), true)];
    auto j = p.toJson();
    assert(j["name"].get!string == "greet");
    assert(j["arguments"][0]["name"].get!string == "who");
    assert(j["arguments"][0]["required"].get!bool);
}

unittest  // GetPromptResult serializes messages with object content
{
    GetPromptResult r;
    r.messages = [PromptMessage("user", Content.makeText("hi"))];
    auto j = r.toJson();
    assert(j["messages"][0]["role"].get!string == "user");
    assert(j["messages"][0]["content"]["type"].get!string == "text");
}

unittest  // CompleteResult nests values under completion with hasMore
{
    CompleteResult r;
    r.values = ["paris", "park"];
    r.total = 150;
    auto j = r.toJson();
    assert(j["completion"]["values"].length == 2);
    assert(j["completion"]["total"].get!int == 150);
    assert(j["completion"]["hasMore"].get!bool == false);
}

unittest  // Resource/ResourceContents/Prompt/GetPrompt fromJson round-trips
{
    Resource r = {
        uri: "u", name: "n", description: nullable("d"), mimeType: nullable("text/plain")
    };
    auto rb = Resource.fromJson(r.toJson());
    assert(rb.uri == "u" && rb.name == "n" && rb.mimeType.get == "text/plain");

    auto cb = ResourceContents.fromJson(ResourceContents.makeBlob("u",
            "image/png", "QQ==").toJson());
    assert(cb.isBlob && cb.blob == "QQ==");

    ListResourcesResult lr;
    lr.resources = [r];
    lr.nextCursor = "c";
    auto lrb = ListResourcesResult.fromJson(lr.toJson());
    assert(lrb.resources.length == 1 && lrb.nextCursor.get == "c");

    ReadResourceResult rr;
    rr.contents = [ResourceContents.makeText("u", "text/plain", "hi")];
    assert(ReadResourceResult.fromJson(rr.toJson()).contents[0].text == "hi");
}

unittest  // Prompt + GetPromptResult fromJson round-trips
{
    Prompt p = {name: "greet", description: nullable("g")};
    p.arguments = [PromptArgument("who", nullable("name"), true)];
    auto pb = Prompt.fromJson(p.toJson());
    assert(pb.name == "greet" && pb.arguments.length == 1 && pb.arguments[0].required);

    ListPromptsResult lp;
    lp.prompts = [p];
    assert(ListPromptsResult.fromJson(lp.toJson()).prompts[0].name == "greet");

    GetPromptResult gp;
    gp.messages = [PromptMessage("user", Content.makeText("hi"))];
    auto gpb = GetPromptResult.fromJson(gp.toJson());
    assert(gpb.messages.length == 1 && gpb.messages[0].content.text == "hi");
}
