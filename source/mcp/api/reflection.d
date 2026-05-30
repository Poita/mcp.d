module mcp.api.reflection;

import std.traits;
import std.typecons : Tuple, Nullable, nullable;
import std.meta : AliasSeq;

import vibe.data.json : Json, serializeToJson, deserializeJson;

import mcp.protocol.types;
import mcp.server.server;
import mcp.server.context;
import mcp.api.attributes;
import mcp.api.schema;

@safe:

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated method of `obj` on `server`, deriving JSON schemas and argument
/// marshalling from the method signatures (FastMCP-style ergonomics).
void registerHandlers(T)(MCPServer server, T obj) @safe
{
    static foreach (memberName; __traits(allMembers, T))
    {
        static if (__traits(compiles, __traits(getOverloads, T, memberName)))
        {
            static foreach (overload; __traits(getOverloads, T, memberName))
            {
                static foreach (attr; __traits(getAttributes, overload))
                {
                    static if (is(typeof(attr) == tool))
                        registerToolMethod!(T, memberName, overload)(server, obj, attr);
                    else static if (is(typeof(attr) == prompt))
                        registerPromptMethod!(T, memberName, overload)(server, obj, attr);
                    else static if (is(typeof(attr) == resource))
                        registerResourceMethod!(T, memberName, overload)(server, obj, attr);
                    else static if (is(typeof(attr) == resourceTemplate))
                        registerTemplateMethod!(T, memberName, overload)(server, obj, attr);
                }
            }
        }
    }
}

/// Build the `{type:object, properties, required}` schema for a method's
/// parameters, skipping any `RequestContext` parameter.
private Json parametersSchema(alias func)() @safe
{
    alias names = ParameterIdentifierTuple!func;
    alias types = Parameters!func;

    Json props = Json.emptyObject;
    Json required = Json.emptyArray;
    static foreach (i, P; types)
    {
        static if (!is(P : RequestContext))
        {
            props[names[i]] = jsonSchemaOf!P;
            static if (!isInstanceOf!(Nullable, P))
                required ~= Json(names[i]);
        }
    }
    Json s = Json.emptyObject;
    s["type"] = "object";
    s["properties"] = props;
    if (required.length > 0)
        s["required"] = required;
    return s;
}

/// Convert one JSON argument value into the parameter type `P`.
private P marshalArg(P)(Json args, string name) @safe
{
    static if (is(P : RequestContext))
    {
        assert(false, "context parameters are injected, not marshalled");
    }
    else static if (isInstanceOf!(Nullable, P))
    {
        alias Inner = TemplateArgsOf!P[0];
        if (name in args && args[name].type != Json.Type.null_
                && args[name].type != Json.Type.undefined)
            return P(marshalScalar!Inner(args[name]));
        return P.init;
    }
    else
    {
        if (name in args)
            return marshalScalar!P(args[name]);
        return P.init;
    }
}

private P marshalScalar(P)(Json v) @safe
{
    static if (is(P == enum))
    {
        import std.conv : to;

        return to!P(v.get!string);
    }
    else
        return () @trusted { return deserializeJson!P(v); }();
}

/// The JSON Schema describing a tool's structured output, derived from its
/// return type — or `Json.undefined` when the tool produces unstructured text
/// (a `string`) or supplies its own `CallToolResult`. Aggregate (`struct`)
/// returns map to their object schema directly; scalar/array/enum returns are
/// wrapped under a `result` property so `structuredContent` is always an object.
private Json outputSchemaOf(R)() @safe
{
    static if (is(R == CallToolResult) || isSomeString!R || is(R == void))
        return Json.undefined;
    else static if (is(R == struct))
        return jsonSchemaOf!R;
    else
    {
        Json s = Json.emptyObject;
        s["type"] = "object";
        Json props = Json.emptyObject;
        props["result"] = jsonSchemaOf!R;
        s["properties"] = props;
        s["required"] = Json([Json("result")]);
        return s;
    }
}

/// Wrap a tool method's return value into a `CallToolResult`. The structured
/// result mirrors `outputSchemaOf!R`: structs serialize to an object; scalars,
/// arrays, and enums are wrapped under a `result` key; strings become text
/// content with no structured output.
private CallToolResult toToolResult(R)(R ret) @safe
{
    static if (is(R == CallToolResult))
        return ret;
    else static if (isSomeString!R)
    {
        CallToolResult r;
        r.content = [Content.makeText(ret)];
        return r;
    }
    else
    {
        CallToolResult r;
        static if (is(R == struct))
            auto structured = () @trusted { return serializeToJson(ret); }();
        else
        {
            Json structured = Json.emptyObject;
            structured["result"] = () @trusted { return serializeToJson(ret); }();
        }
        r.structuredContent = structured;
        r.content = [Content.makeText(structured.toString())];
        return r;
    }
}

private void registerToolMethod(T, string memberName, alias overload)(
        MCPServer server, T obj, tool attr) @safe
{
    import std.traits : ReturnType;

    Tool descriptor;
    descriptor.name = attr.name;
    if (attr.description.length)
        descriptor.description = nullable(attr.description);
    if (attr.title.length)
        descriptor.title = nullable(attr.title);
    descriptor.inputSchema = parametersSchema!overload();
    auto outSchema = outputSchemaOf!(ReturnType!overload)();
    if (outSchema.type == Json.Type.object)
        descriptor.outputSchema = outSchema;

    // Fold any @toolAnnotations UDA on the same method into typed
    // ToolAnnotations, then serialize into the descriptor's annotations field.
    ToolAnnotations anns;
    static foreach (a; __traits(getAttributes, overload))
    {
        static if (is(typeof(a) == toolAnnotations))
        {
            anns.readOnlyHint = a.readOnlyHint;
            anns.destructiveHint = a.destructiveHint;
            anns.idempotentHint = a.idempotentHint;
            anns.openWorldHint = a.openWorldHint;
        }
    }
    if (!anns.empty)
        descriptor.annotations = anns.toJson();

    server.registerTool(descriptor, (Json args, RequestContext ctx) @safe {
        alias names = ParameterIdentifierTuple!overload;
        Tuple!(Parameters!overload) argv;
        static foreach (i, P; Parameters!overload)
        {
            static if (is(P : RequestContext))
                argv[i] = ctx;
            else
                argv[i] = marshalArg!P(args, names[i]);
        }
        return toToolResult(__traits(getMember, obj, memberName)(argv.expand));
    });
}

/// Wrap a prompt method's return value into a `GetPromptResult`.
private GetPromptResult toPromptResult(R)(R ret) @safe
{
    static if (is(R == GetPromptResult))
        return ret;
    else static if (is(R == PromptMessage[]))
    {
        GetPromptResult r;
        r.messages = ret;
        return r;
    }
    else static if (isSomeString!R)
    {
        GetPromptResult r;
        r.messages = [PromptMessage("user", Content.makeText(ret))];
        return r;
    }
    else
        static assert(false,
                "@prompt method must return GetPromptResult, PromptMessage[], or string");
}

private void registerPromptMethod(T, string memberName, alias overload)(
        MCPServer server, T obj, prompt attr) @safe
{
    Prompt descriptor;
    descriptor.name = attr.name;
    if (attr.description.length)
        descriptor.description = nullable(attr.description);
    alias names = ParameterIdentifierTuple!overload;
    static foreach (i, P; Parameters!overload)
    {
        static if (!is(P : RequestContext))
            descriptor.arguments ~= PromptArgument(names[i],
                    Nullable!string.init, !isInstanceOf!(Nullable, P));
    }

    server.registerPrompt(descriptor, (Json args) @safe {
        Tuple!(Parameters!overload) argv;
        static foreach (i, P; Parameters!overload)
        {
            static if (is(P : RequestContext))
                argv[i] = new NullContext;
            else
                argv[i] = marshalArg!P(args, names[i]);
        }
        return toPromptResult(__traits(getMember, obj, memberName)(argv.expand));
    });
}

private ResourceContents toResourceContents(R)(R ret, string uri, string mimeType) @safe
{
    static if (is(R == ResourceContents))
        return ret;
    else static if (isSomeString!R)
        return ResourceContents.makeText(uri, mimeType, ret);
    else
        static assert(false, "@resource method must return ResourceContents or string");
}

private void registerResourceMethod(T, string memberName, alias overload)(
        MCPServer server, T obj, resource attr) @safe
{
    Resource descriptor;
    descriptor.uri = attr.uri;
    descriptor.name = attr.name;
    if (attr.mimeType.length)
        descriptor.mimeType = nullable(attr.mimeType);

    // Fold any @resourceAnnotations UDA on the same method into the descriptor.
    static foreach (a; __traits(getAttributes, overload))
    {
        static if (is(typeof(a) == resourceAnnotations))
        {
            descriptor.annotations.audience = a.audience;
            descriptor.annotations.priority = a.priority;
            descriptor.annotations.lastModified = a.lastModified;
        }
    }

    server.registerResource(descriptor, () @safe {
        return toResourceContents(__traits(getMember, obj, memberName)(), attr.uri, attr.mimeType);
    });
}

private void registerTemplateMethod(T, string memberName, alias overload)(
        MCPServer server, T obj, resourceTemplate attr) @safe
{
    ResourceTemplate descriptor;
    descriptor.uriTemplate = attr.uriTemplate;
    descriptor.name = attr.name;
    if (attr.mimeType.length)
        descriptor.mimeType = nullable(attr.mimeType);

    // Fold any @resourceAnnotations UDA on the same method into the descriptor.
    static foreach (a; __traits(getAttributes, overload))
    {
        static if (is(typeof(a) == resourceAnnotations))
        {
            descriptor.annotations.audience = a.audience;
            descriptor.annotations.priority = a.priority;
            descriptor.annotations.lastModified = a.lastModified;
        }
    }

    server.registerResourceTemplate(descriptor, (string uri, string[string] params) @safe {
        alias names = ParameterIdentifierTuple!overload;
        Tuple!(Parameters!overload) argv;
        static foreach (i, P; Parameters!overload)
        {
            static if (is(P == string))
                argv[i] = (names[i] in params) ? params[names[i]] : "";
            else
                argv[i] = P.init;
        }
        auto ret = __traits(getMember, obj, memberName)(argv.expand);
        return toResourceContents(ret, uri, attr.mimeType);
    });
}

version (unittest)
{
    private enum Priority
    {
        low,
        high
    }

    private struct Stats
    {
        int count;
        double total;
    }

    private final class DemoApi
    {
        @tool("add", "Add two integers")
        int add(int a, int b) @safe
        {
            return a + b;
        }

        @tool("stats", "Summarize a list of integers")
        Stats stats(int[] values) @safe
        {
            Stats s;
            foreach (v; values)
            {
                s.count++;
                s.total += v;
            }
            return s;
        }

        @tool("greet", "Greet someone")
        string greet(string name) @safe
        {
            return "Hello, " ~ name ~ "!";
        }

        @tool("classify", "Classify with an enum + optional note")
        string classify(Priority p, Nullable!string note) @safe
        {
            return note.isNull ? "p" : "n";
        }

        @tool("erase", "Erase a record", "Erase Record")
        @toolAnnotations(destructiveHint : true.nullable, idempotentHint:
                true.nullable) string erase(string id) @safe
        {
            return "erased " ~ id;
        }

        @resource("test://doc", "Doc", "text/plain")
        string doc() @safe
        {
            return "document body";
        }

        @resource("test://readme", "Readme", "text/markdown") @resourceAnnotations(audience
                : ["user"], priority:
                0.9.nullable) string readme() @safe
        {
            return "readme body";
        }

        @prompt("intro", "Intro prompt")
        string intro(string topic) @safe
        {
            return "Tell me about " ~ topic;
        }
    }
}

unittest  // @tool reflection: schema derivation + typed dispatch
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);

    Json lp = Json.emptyObject;
    auto list = s.handle(Message(makeRequest(Json(1), "tools/list", lp))).get;
    assert(list["result"]["tools"].length == 5);

    // add -> scalar return wrapped under `result`, with an inferred outputSchema.
    Json p = Json.emptyObject;
    p["name"] = "add";
    p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
    auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
    assert(r["result"]["structuredContent"]["result"].get!int == 9);
}

unittest  // @tool reflection: outputSchema is inferred from the return type
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
            Json.emptyObject))).get["result"]["tools"];

    Json addSchema, statsSchema, greetTool;
    foreach (i; 0 .. tools.length)
    {
        const name = tools[i]["name"].get!string;
        if (name == "add")
            addSchema = tools[i]["outputSchema"];
        else if (name == "stats")
            statsSchema = tools[i]["outputSchema"];
        else if (name == "greet")
            greetTool = tools[i];
    }

    // Scalar return -> object schema wrapping the value under `result`.
    assert(addSchema["type"].get!string == "object");
    assert(addSchema["properties"]["result"]["type"].get!string == "integer");

    // Struct return -> the struct's object schema directly.
    assert(statsSchema["type"].get!string == "object");
    assert(statsSchema["properties"]["count"]["type"].get!string == "integer");
    assert(statsSchema["properties"]["total"]["type"].get!string == "number");

    // String return -> unstructured text, no outputSchema.
    assert("outputSchema" !in greetTool);
}

unittest  // @tool reflection: struct return produces matching structuredContent
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    Json p = Json.emptyObject;
    p["name"] = "stats";
    p["arguments"] = Json(["values": Json([Json(2), Json(3), Json(5)])]);
    auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
    assert(r["result"]["structuredContent"]["count"].get!int == 3);
    // `total` (a double) serializes as a JSON number; just confirm it's present
    // and numeric (int/float representation is vibe's choice for whole values).
    auto total = r["result"]["structuredContent"]["total"];
    assert(total.type == Json.Type.float_ || total.type == Json.Type.int_);
}

unittest  // @tool reflection: string return becomes text content
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    Json p = Json.emptyObject;
    p["name"] = "greet";
    p["arguments"] = Json(["name": Json("Sam")]);
    auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
    assert(r["result"]["content"][0]["text"].get!string == "Hello, Sam!");
}

unittest  // @tool reflection: enum param schema + optional Nullable param
{
    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
    // find classify
    bool found;
    foreach (i; 0 .. tools.length)
    {
        if (tools[i]["name"].get!string == "classify")
        {
            found = true;
            auto schema = tools[i]["inputSchema"];
            assert(schema["properties"]["p"]["type"].get!string == "string");
            assert(schema["properties"]["p"]["enum"].length == 2);
            // only p is required (note is Nullable)
            assert(schema["required"].length == 1);
        }
    }
    assert(found);
}

unittest  // @resource and @prompt reflection register and dispatch
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);

    Json rp = Json.emptyObject;
    rp["uri"] = "test://doc";
    auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
    assert(rr["result"]["contents"][0]["text"].get!string == "document body");

    Json pp = Json.emptyObject;
    pp["name"] = "intro";
    pp["arguments"] = Json(["topic": Json("MCP")]);
    auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
    assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Tell me about MCP");
}

unittest  // @resourceAnnotations reflection: annotations appear in resources/list
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);

    auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
            Json.emptyObject))).get["result"]["resources"];

    bool foundReadme, foundDoc;
    foreach (i; 0 .. res.length)
    {
        auto uri = res[i]["uri"].get!string;
        if (uri == "test://readme")
        {
            foundReadme = true;
            assert(res[i]["annotations"]["audience"][0].get!string == "user");
            assert(res[i]["annotations"]["priority"].get!double == 0.9);
        }
        else if (uri == "test://doc")
        {
            foundDoc = true;
            // A resource without @resourceAnnotations carries no annotations.
            assert("annotations" !in res[i]);
        }
    }
    assert(foundReadme && foundDoc);
}

unittest  // @tool reflection: optional title is emitted in tools/list
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
            Json.emptyObject))).get["result"]["tools"];

    Json eraseTool;
    foreach (i; 0 .. tools.length)
        if (tools[i]["name"].get!string == "erase")
            eraseTool = tools[i];
    assert(eraseTool.type == Json.Type.object);
    assert(eraseTool["title"].get!string == "Erase Record");
}

unittest  // @toolAnnotations reflection: hints are serialized into annotations
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    auto s = new MCPServer("t", "1");
    registerHandlers(s, new DemoApi);
    auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
            Json.emptyObject))).get["result"]["tools"];

    Json eraseTool, addTool;
    foreach (i; 0 .. tools.length)
    {
        const name = tools[i]["name"].get!string;
        if (name == "erase")
            eraseTool = tools[i];
        else if (name == "add")
            addTool = tools[i];
    }

    auto anns = eraseTool["annotations"];
    assert(anns["destructiveHint"].get!bool == true);
    assert(anns["idempotentHint"].get!bool == true);
    // Unset hints are omitted entirely.
    assert("readOnlyHint" !in anns);
    assert("openWorldHint" !in anns);

    // A tool without @toolAnnotations carries no annotations object.
    assert("annotations" !in addTool);
}

unittest  // ToolAnnotations: typed struct round-trips through JSON
{
    ToolAnnotations a;
    a.title = "Display";
    a.readOnlyHint = true;
    a.openWorldHint = false;
    auto j = a.toJson();
    auto b = ToolAnnotations.fromJson(j);
    assert(b.title.get == "Display");
    assert(b.readOnlyHint.get == true);
    assert(b.openWorldHint.get == false);
    assert(b.destructiveHint.isNull);
}

unittest  // ToolAnnotations: empty struct produces an empty object
{
    ToolAnnotations a;
    assert(a.empty);
    assert(a.toJson().length == 0);
}

version (unittest) private auto MakeListMessage()
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    return Message(makeRequest(Json(99), "tools/list", Json.emptyObject));
}
