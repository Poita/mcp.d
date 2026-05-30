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

/// Wrap a tool method's return value into a `CallToolResult`.
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
        import std.conv : to;

        CallToolResult r;
        auto structured = () @trusted { return serializeToJson(ret); }();
        r.structuredContent = structured;
        r.content = [Content.makeText(structured.toString())];
        return r;
    }
}

private void registerToolMethod(T, string memberName, alias overload)(
        MCPServer server, T obj, tool attr) @safe
{
    Tool descriptor;
    descriptor.name = attr.name;
    if (attr.description.length)
        descriptor.description = nullable(attr.description);
    descriptor.inputSchema = parametersSchema!overload();

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

    private final class DemoApi
    {
        @tool("add", "Add two integers")
        int add(int a, int b) @safe
        {
            return a + b;
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

        @resource("test://doc", "Doc", "text/plain")
        string doc() @safe
        {
            return "document body";
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
    assert(list["result"]["tools"].length == 3);

    // add -> structured integer result
    Json p = Json.emptyObject;
    p["name"] = "add";
    p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
    auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
    assert(r["result"]["structuredContent"].get!int == 9);
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

version (unittest) private auto MakeListMessage()
{
    import mcp.protocol.jsonrpc : Message, makeRequest;

    return Message(makeRequest(Json(99), "tools/list", Json.emptyObject));
}
