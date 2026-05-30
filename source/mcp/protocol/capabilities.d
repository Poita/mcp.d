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

/// Tasks capability (2025-11-25): support for task-augmented requests.
///
/// Server form may carry presence-only `list`/`cancel` sub-capabilities and a
/// `requests` map of request method names to per-request settings objects.
/// Client form carries only the `requests` map. Each struct preserves the
/// distinction by only emitting the fields relevant to its role.
struct TasksCapability
{
    bool list; /// server: presence-only ({} when set); supports tasks/list
    bool cancel; /// server: presence-only ({} when set); supports tasks/cancel
    /// Map of request method names (e.g. "tools/call") to per-request settings
    /// objects describing which requests may be task-augmented.
    Json requests = Json.undefined;

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        if (list)
            j["list"] = Json.emptyObject;
        if (cancel)
            j["cancel"] = Json.emptyObject;
        if (requests.type == Json.Type.object)
            j["requests"] = requests;
        return j;
    }

    static TasksCapability fromJson(Json j) @safe
    {
        TasksCapability c;
        if ("list" in j)
            c.list = true;
        if ("cancel" in j)
            c.cancel = true;
        if ("requests" in j && j["requests"].type == Json.Type.object)
            c.requests = j["requests"];
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
    Nullable!TasksCapability tasks; /// task-augmented requests (>= 2025-11-25)
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
        if (!tasks.isNull)
            j["tasks"] = tasks.get.toJson();
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
        if ("tasks" in j && j["tasks"].type == Json.Type.object)
            c.tasks = TasksCapability.fromJson(j["tasks"]);
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
    bool sampling; /// presence (with optional tools/context sub-caps below)
    /// sampling.tools sub-capability (>= 2025-11-25): declares support for
    /// tool use in sampling requests. Servers MUST NOT send tool-enabled
    /// sampling requests unless this is advertised. Implies `sampling`.
    bool samplingTools;
    /// sampling.context sub-capability (soft-deprecated): gates the
    /// `includeContext` values `thisServer`/`allServers`. Implies `sampling`.
    bool samplingContext;
    bool elicitation; /// presence-only (>= 2025-06-18)
    /// task-augmented requests (>= 2025-11-25); client form carries only the
    /// `requests` map (its `list`/`cancel` fields are server-only).
    Nullable!TasksCapability tasks;
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
        if (sampling || samplingTools || samplingContext)
        {
            Json s = Json.emptyObject;
            if (samplingTools)
                s["tools"] = Json.emptyObject;
            if (samplingContext)
                s["context"] = Json.emptyObject;
            j["sampling"] = s;
        }
        if (elicitation)
            j["elicitation"] = Json.emptyObject;
        if (!tasks.isNull)
            j["tasks"] = tasks.get.toJson();
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
        {
            c.sampling = true;
            if (j["sampling"].type == Json.Type.object)
            {
                if ("tools" in j["sampling"])
                    c.samplingTools = true;
                if ("context" in j["sampling"])
                    c.samplingContext = true;
            }
        }
        if ("elicitation" in j)
            c.elicitation = true;
        if ("tasks" in j && j["tasks"].type == Json.Type.object)
            c.tasks = TasksCapability.fromJson(j["tasks"]);
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

unittest  // ServerCapabilities advertises the 2025-11-25 `tasks` capability
{
    ServerCapabilities caps;
    TasksCapability t;
    t.list = true;
    t.cancel = true;
    Json reqs = Json.emptyObject;
    reqs["tools/call"] = Json.emptyObject;
    t.requests = reqs;
    caps.tasks = t;
    auto j = caps.toJson();
    assert(j["tasks"]["list"].type == Json.Type.object && j["tasks"]["list"].length == 0);
    assert(j["tasks"]["cancel"].type == Json.Type.object);
    assert("tools/call" in j["tasks"]["requests"]);
}

unittest  // ServerCapabilities round-trips the `tasks` capability
{
    ServerCapabilities caps;
    TasksCapability t;
    t.list = true;
    Json reqs = Json.emptyObject;
    reqs["tools/call"] = Json.emptyObject;
    t.requests = reqs;
    caps.tasks = t;
    auto back = ServerCapabilities.fromJson(caps.toJson());
    assert(!back.tasks.isNull);
    assert(back.tasks.get.list);
    assert(!back.tasks.get.cancel);
    assert("tools/call" in back.tasks.get.requests);
}

unittest  // ServerCapabilities omits `tasks` when unset
{
    ServerCapabilities caps;
    assert("tasks" !in caps.toJson());
}

unittest  // ClientCapabilities advertises the 2025-11-25 `tasks` capability
{
    ClientCapabilities caps;
    TasksCapability t;
    Json reqs = Json.emptyObject;
    reqs["sampling/createMessage"] = Json.emptyObject;
    t.requests = reqs;
    caps.tasks = t;
    auto j = caps.toJson();
    assert("sampling/createMessage" in j["tasks"]["requests"]);
    // Client form carries only `requests` (no server-only list/cancel keys).
    assert("list" !in j["tasks"]);
    assert("cancel" !in j["tasks"]);
}

unittest  // ClientCapabilities round-trips the `tasks` capability
{
    ClientCapabilities caps;
    TasksCapability t;
    Json reqs = Json.emptyObject;
    reqs["sampling/createMessage"] = Json.emptyObject;
    t.requests = reqs;
    caps.tasks = t;
    auto back = ClientCapabilities.fromJson(caps.toJson());
    assert(!back.tasks.isNull);
    assert("sampling/createMessage" in back.tasks.get.requests);
}

unittest  // ClientCapabilities omits `tasks` when unset
{
    ClientCapabilities caps;
    assert("tasks" !in caps.toJson());
}

unittest  // ClientCapabilities advertises sampling.tools sub-capability (2025-11-25)
{
    ClientCapabilities caps;
    caps.sampling = true;
    caps.samplingTools = true;
    auto j = caps.toJson();
    assert(j["sampling"].type == Json.Type.object);
    assert(j["sampling"]["tools"].type == Json.Type.object && j["sampling"]["tools"].length == 0);
    assert("context" !in j["sampling"]);
}

unittest  // ClientCapabilities advertises sampling.context sub-capability (2025-11-25)
{
    ClientCapabilities caps;
    caps.sampling = true;
    caps.samplingContext = true;
    auto j = caps.toJson();
    assert(j["sampling"]["context"].type == Json.Type.object && j["sampling"]["context"].length == 0);
    assert("tools" !in j["sampling"]);
}

unittest  // ClientCapabilities round-trips both sampling sub-capabilities
{
    ClientCapabilities caps;
    caps.sampling = true;
    caps.samplingTools = true;
    caps.samplingContext = true;
    auto back = ClientCapabilities.fromJson(caps.toJson());
    assert(back.sampling && back.samplingTools && back.samplingContext);
}

unittest  // ClientCapabilities emits bare empty sampling object when no sub-caps set
{
    ClientCapabilities caps;
    caps.sampling = true;
    auto j = caps.toJson();
    assert(j["sampling"].type == Json.Type.object && j["sampling"].length == 0);
    auto back = ClientCapabilities.fromJson(j);
    assert(back.sampling && !back.samplingTools && !back.samplingContext);
}

unittest  // ClientCapabilities parses sampling sub-caps from a server-style payload
{
    Json j = Json.emptyObject;
    Json s = Json.emptyObject;
    s["tools"] = Json.emptyObject;
    s["context"] = Json.emptyObject;
    j["sampling"] = s;
    auto back = ClientCapabilities.fromJson(j);
    assert(back.sampling && back.samplingTools && back.samplingContext);
}

unittest  // ClientCapabilities sub-caps imply sampling presence on serialization
{
    ClientCapabilities caps;
    caps.samplingTools = true;
    auto j = caps.toJson();
    assert("sampling" in j);
    assert(j["sampling"]["tools"].type == Json.Type.object);
}

unittest  // TasksCapability with empty `requests` map still round-trips presence
{
    TasksCapability t;
    t.list = true;
    auto j = t.toJson();
    assert("requests" !in j);
    auto back = TasksCapability.fromJson(j);
    assert(back.list && !back.cancel);
    assert(back.requests.type != Json.Type.object);
}
