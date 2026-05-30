module mcp.protocol.capabilities;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

@safe:

/// Identifies an MCP implementation (client or server).
struct Implementation
{
    string name;
    string version_; /// serialized as "version"
    Nullable!string title; /// human-friendly display name (>= 2025-06-18)

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["name"] = name;
        j["version"] = version_;
        if (!title.isNull)
            j["title"] = title.get;
        return j;
    }

    static Implementation fromJson(Json j) @safe
    {
        Implementation impl;
        impl.name = ("name" in j) ? j["name"].get!string : "";
        impl.version_ = ("version" in j) ? j["version"].get!string : "";
        if ("title" in j && j["title"].type == Json.Type.string)
            impl.title = j["title"].get!string;
        return impl;
    }
}

/// A capability that carries an optional `listChanged` flag.
struct ListChangedCapability
{
    bool listChanged;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (listChanged)
            j["listChanged"] = true;
        return j;
    }

    static ListChangedCapability fromJson(Json j) @safe
    {
        ListChangedCapability c;
        if ("listChanged" in j && j["listChanged"].type == Json.Type.bool_)
            c.listChanged = j["listChanged"].get!bool;
        return c;
    }
}

/// Resources capability: supports `subscribe` and `listChanged`.
struct ResourcesCapability
{
    bool subscribe;
    bool listChanged;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (subscribe)
            j["subscribe"] = true;
        if (listChanged)
            j["listChanged"] = true;
        return j;
    }

    static ResourcesCapability fromJson(Json j) @safe
    {
        ResourcesCapability c;
        if ("subscribe" in j && j["subscribe"].type == Json.Type.bool_)
            c.subscribe = j["subscribe"].get!bool;
        if ("listChanged" in j && j["listChanged"].type == Json.Type.bool_)
            c.listChanged = j["listChanged"].get!bool;
        return c;
    }
}

/// Capabilities a server advertises during initialization.
struct ServerCapabilities
{
    Nullable!ListChangedCapability tools;
    Nullable!ResourcesCapability resources;
    Nullable!ListChangedCapability prompts;
    bool logging; /// presence-only ({} when set)
    bool completions; /// presence-only ({} when set)
    Json experimental = Json.undefined;
    /// draft Extension Negotiation: map of extension identifiers (e.g.
    /// "io.modelcontextprotocol/tasks") to per-extension settings objects.
    /// Distinct from `experimental`.
    Json extensions = Json.undefined;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (!tools.isNull)
            j["tools"] = tools.get.toJson();
        if (!resources.isNull)
            j["resources"] = resources.get.toJson();
        if (!prompts.isNull)
            j["prompts"] = prompts.get.toJson();
        if (logging)
            j["logging"] = Json.emptyObject;
        if (completions)
            j["completions"] = Json.emptyObject;
        if (experimental.type == Json.Type.object)
            j["experimental"] = experimental;
        if (extensions.type == Json.Type.object)
            j["extensions"] = extensions;
        return j;
    }

    static ServerCapabilities fromJson(Json j) @safe
    {
        ServerCapabilities c;
        if ("tools" in j && j["tools"].type == Json.Type.object)
            c.tools = ListChangedCapability.fromJson(j["tools"]);
        if ("resources" in j && j["resources"].type == Json.Type.object)
            c.resources = ResourcesCapability.fromJson(j["resources"]);
        if ("prompts" in j && j["prompts"].type == Json.Type.object)
            c.prompts = ListChangedCapability.fromJson(j["prompts"]);
        if ("logging" in j)
            c.logging = true;
        if ("completions" in j)
            c.completions = true;
        if ("experimental" in j)
            c.experimental = j["experimental"];
        if ("extensions" in j)
            c.extensions = j["extensions"];
        return c;
    }
}

/// Capabilities a client advertises during initialization.
struct ClientCapabilities
{
    bool roots; /// presence (with optional listChanged below)
    bool rootsListChanged;
    bool sampling; /// presence-only
    bool elicitation; /// presence-only (>= 2025-06-18)
    Json experimental = Json.undefined;
    /// draft Extension Negotiation: map of extension identifiers (e.g.
    /// "io.modelcontextprotocol/ui") to per-extension settings objects.
    /// Distinct from `experimental`.
    Json extensions = Json.undefined;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (roots)
        {
            Json r = Json.emptyObject;
            if (rootsListChanged)
                r["listChanged"] = true;
            j["roots"] = r;
        }
        if (sampling)
            j["sampling"] = Json.emptyObject;
        if (elicitation)
            j["elicitation"] = Json.emptyObject;
        if (experimental.type == Json.Type.object)
            j["experimental"] = experimental;
        if (extensions.type == Json.Type.object)
            j["extensions"] = extensions;
        return j;
    }

    static ClientCapabilities fromJson(Json j) @safe
    {
        ClientCapabilities c;
        if ("roots" in j && j["roots"].type == Json.Type.object)
        {
            c.roots = true;
            auto r = j["roots"];
            if ("listChanged" in r && r["listChanged"].type == Json.Type.bool_)
                c.rootsListChanged = r["listChanged"].get!bool;
        }
        if ("sampling" in j)
            c.sampling = true;
        if ("elicitation" in j)
            c.elicitation = true;
        if ("experimental" in j)
            c.experimental = j["experimental"];
        if ("extensions" in j)
            c.extensions = j["extensions"];
        return c;
    }
}

unittest  // Implementation round-trips with optional title omitted
{
    Implementation impl = {name: "srv", version_: "1.2.3"};
    auto j = impl.toJson();
    assert(j["name"].get!string == "srv");
    assert(j["version"].get!string == "1.2.3");
    assert("title" !in j);
    auto back = Implementation.fromJson(j);
    assert(back.name == "srv" && back.version_ == "1.2.3" && back.title.isNull);
}

unittest  // Implementation includes title when present
{
    Implementation impl = {
        name: "srv", version_: "1", title: nullable("My Server")
    };
    auto j = impl.toJson();
    assert(j["title"].get!string == "My Server");
    assert(Implementation.fromJson(j).title.get == "My Server");
}

unittest  // ServerCapabilities emits only set capabilities, presence-aware
{
    ServerCapabilities caps;
    caps.tools = ListChangedCapability(true);
    caps.logging = true;
    auto j = caps.toJson();
    assert(j["tools"]["listChanged"].get!bool);
    assert(j["logging"].type == Json.Type.object && j["logging"].length == 0);
    assert("resources" !in j);
    assert("prompts" !in j);
    assert("completions" !in j);
}

unittest  // ServerCapabilities round-trips presence semantics
{
    ServerCapabilities caps;
    caps.resources = ResourcesCapability(true, false);
    caps.completions = true;
    auto back = ServerCapabilities.fromJson(caps.toJson());
    assert(!back.resources.isNull);
    assert(back.resources.get.subscribe && !back.resources.get.listChanged);
    assert(back.completions);
    assert(back.tools.isNull);
}

unittest  // ClientCapabilities nests roots.listChanged and presence flags
{
    ClientCapabilities caps;
    caps.roots = true;
    caps.rootsListChanged = true;
    caps.sampling = true;
    auto j = caps.toJson();
    assert(j["roots"]["listChanged"].get!bool);
    assert(j["sampling"].type == Json.Type.object);
    assert("elicitation" !in j);
    auto back = ClientCapabilities.fromJson(j);
    assert(back.roots && back.rootsListChanged && back.sampling && !back.elicitation);
}

unittest  // ServerCapabilities advertises and round-trips the draft `extensions` map
{
    ServerCapabilities caps;
    Json ext = Json.emptyObject;
    ext["io.modelcontextprotocol/tasks"] = Json.emptyObject;
    caps.extensions = ext;
    auto j = caps.toJson();
    assert(j["extensions"].type == Json.Type.object);
    assert("io.modelcontextprotocol/tasks" in j["extensions"]);
    // `extensions` is distinct from `experimental`.
    assert("experimental" !in j);
    auto back = ServerCapabilities.fromJson(j);
    assert(back.extensions.type == Json.Type.object);
    assert("io.modelcontextprotocol/tasks" in back.extensions);
}

unittest  // ServerCapabilities omits `extensions` when unset
{
    ServerCapabilities caps;
    assert("extensions" !in caps.toJson());
}

unittest  // ClientCapabilities advertises and round-trips the draft `extensions` map
{
    ClientCapabilities caps;
    Json ext = Json.emptyObject;
    Json settings = Json.emptyObject;
    settings["maxConcurrent"] = 4;
    ext["io.modelcontextprotocol/ui"] = settings;
    caps.extensions = ext;
    auto j = caps.toJson();
    assert(j["extensions"]["io.modelcontextprotocol/ui"]["maxConcurrent"].get!int == 4);
    assert("experimental" !in j);
    auto back = ClientCapabilities.fromJson(j);
    assert(back.extensions["io.modelcontextprotocol/ui"]["maxConcurrent"].get!int == 4);
}

unittest  // ClientCapabilities omits `extensions` when unset
{
    ClientCapabilities caps;
    assert("extensions" !in caps.toJson());
}
