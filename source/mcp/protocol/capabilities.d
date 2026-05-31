module mcp.protocol.capabilities;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;
import mcp.protocol.versions : ProtocolVersion;

@safe:

/// An icon for display in user interfaces. Used by `Implementation`,
/// `Tool` (and other definitions) per the MCP spec's icon shape: a required
/// `src` and optional `mimeType` and `sizes`.
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

/// Identifies an MCP implementation (client or server).
///
/// Per the schema `Implementation` extends `BaseMetadata` (`name`/`title`) and
/// the `Icons` mixin, adding `version` plus the optional `description`,
/// `websiteUrl`, and `icons` fields (`description`/`icons`/`websiteUrl` were
/// added by 2025-11-25). All optional fields are omitted from `toJson` when
/// unset, so wire output for older protocol versions is unchanged.
struct Implementation
{
	string name;
	string version_; /// serialized as "version"
	Nullable!string title; /// human-friendly display name (>= 2025-06-18)
	Nullable!string description; /// optional human-readable description (>= 2025-11-25)
	Nullable!string websiteUrl; /// optional website URL (>= 2025-11-25)
	Icon[] icons; /// optional icons for display in user interfaces (>= 2025-11-25)

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		j["version"] = version_;
		if (!title.isNull)
			j["title"] = title.get;
		if (!description.isNull)
			j["description"] = description.get;
		if (!websiteUrl.isNull)
			j["websiteUrl"] = websiteUrl.get;
		if (icons.length)
		{
			Json arr = Json.emptyArray;
			foreach (icon; icons)
				arr ~= icon.toJson();
			j["icons"] = arr;
		}
		return j;
	}

	static Implementation fromJson(Json j) @safe
	{
		Implementation impl;
		impl.name = ("name" in j) ? j["name"].get!string : "";
		impl.version_ = ("version" in j) ? j["version"].get!string : "";
		if ("title" in j && j["title"].type == Json.Type.string)
			impl.title = j["title"].get!string;
		if ("description" in j && j["description"].type == Json.Type.string)
			impl.description = j["description"].get!string;
		if ("websiteUrl" in j && j["websiteUrl"].type == Json.Type.string)
			impl.websiteUrl = j["websiteUrl"].get!string;
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				impl.icons ~= Icon.fromJson(j["icons"][i]);
		return impl;
	}

	/// Return a copy of this `Implementation` with any fields newer than the
	/// negotiated protocol version stripped, so the wire output stays valid for
	/// the peer's version. `title` was introduced by 2025-06-18 (`BaseMetadata`);
	/// `description`, `websiteUrl`, and `icons` were introduced by 2025-11-25.
	/// `name`/`version` are always present. This lets a server (or client) hold a
	/// fully-populated identity while emitting only the fields its peer understands.
	Implementation forVersion(ProtocolVersion v) const @safe
	{
		Implementation projected;
		projected.name = name;
		projected.version_ = version_;
		if (v >= ProtocolVersion.v2025_06_18)
			projected.title = title;
		if (v >= ProtocolVersion.v2025_11_25)
		{
			projected.description = description;
			projected.websiteUrl = websiteUrl;
			foreach (icon; icons)
			{
				Icon copy;
				copy.src = icon.src;
				copy.mimeType = icon.mimeType;
				copy.sizes = icon.sizes.dup;
				projected.icons ~= copy;
			}
		}
		return projected;
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
/// `requests` object structured by request category (e.g. `tools.call`).
/// Client form carries only the `requests` object. Each struct preserves the
/// distinction by only emitting the fields relevant to its role. Build the
/// nested `requests` shape with `TaskRequests`.
struct TasksCapability
{
	bool list; /// server: presence-only ({} when set); supports tasks/list
	bool cancel; /// server: presence-only ({} when set); supports tasks/cancel
	/// Which request types may be task-augmented, structured by request
	/// category with presence-only sub-objects (spec 2025-11-25). Server form:
	/// `{"tools": {"call": {}}}`; client form:
	/// `{"sampling": {"createMessage": {}}, "elicitation": {"create": {}}}`.
	/// Use `TaskRequests` to build this shape rather than flat slash-delimited
	/// method names like `"tools/call"`.
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

/// Builder for the nested `tasks.requests` capability object (spec 2025-11-25).
///
/// The spec structures `tasks.requests` by request category with presence-only
/// sub-objects rather than flat slash-delimited method names. For example, a
/// server advertises task-augmented `tools/call` as
/// `{"tools": {"call": {}}}` (capability key `tasks.requests.tools.call`), and
/// a client advertises task-augmented `sampling/createMessage` and
/// `elicitation/create` as
/// `{"sampling": {"createMessage": {}}, "elicitation": {"create": {}}}`.
///
/// Chain the convenience methods (or `add`) and call `toJson` to obtain the
/// object to assign to `TasksCapability.requests`:
/// ---
/// TasksCapability t;
/// t.requests = TaskRequests().tool().toJson();        // server
/// t.requests = TaskRequests()
///     .samplingCreateMessage()
///     .elicitationCreate()
///     .toJson();                                       // client
/// ---
struct TaskRequests
{
	private Json obj = Json.emptyObject;

	/// Mark `category.operation` (e.g. `tools.call`) as task-augmentable.
	ref TaskRequests add(string category, string operation) return @safe
	{
		if (obj.type != Json.Type.object)
			obj = Json.emptyObject;
		if (category !in obj || obj[category].type != Json.Type.object)
			obj[category] = Json.emptyObject;
		obj[category][operation] = Json.emptyObject;
		return this;
	}

	/// Server: task-augmented `tools/call` (`tasks.requests.tools.call`).
	ref TaskRequests tool() return @safe
	{
		return add("tools", "call");
	}

	/// Client: task-augmented `sampling/createMessage`
	/// (`tasks.requests.sampling.createMessage`).
	ref TaskRequests samplingCreateMessage() return @safe
	{
		return add("sampling", "createMessage");
	}

	/// Client: task-augmented `elicitation/create`
	/// (`tasks.requests.elicitation.create`).
	ref TaskRequests elicitationCreate() return @safe
	{
		return add("elicitation", "create");
	}

	/// The accumulated nested `requests` object. Returns an empty object when
	/// nothing was added.
	Json toJson() const @safe
	{
		return obj;
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
	bool elicitation; /// presence (>= 2025-06-18); empty object => form mode only
	/// elicitation.form submode (2025-11-25): declares support for schema-driven
	/// form elicitation. Implies `elicitation`. An empty `elicitation` object is
	/// equivalent to declaring form mode only, so this is treated as set when a
	/// peer advertises a bare `{}`.
	bool elicitationForm;
	/// elicitation.url submode (2025-11-25): declares support for URL-mode
	/// elicitation (`elicitUrl`). Implies `elicitation`. Servers MUST NOT send
	/// URL-mode elicitation requests unless this is advertised.
	bool elicitationUrl;
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
		if (elicitation || elicitationForm || elicitationUrl)
		{
			Json e = Json.emptyObject;
			// Emit explicit submodes only when set; a bare `{}` is equivalent to
			// declaring form mode only (backwards compatible with 2025-06-18).
			if (elicitationForm)
				e["form"] = Json.emptyObject;
			if (elicitationUrl)
				e["url"] = Json.emptyObject;
			j["elicitation"] = e;
		}
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
		{
			c.elicitation = true;
			if (j["elicitation"].type == Json.Type.object && j["elicitation"].length > 0)
			{
				if ("form" in j["elicitation"])
					c.elicitationForm = true;
				if ("url" in j["elicitation"])
					c.elicitationUrl = true;
			}
			else
			{
				// An empty (or non-object) elicitation declaration is equivalent
				// to declaring form mode only.
				c.elicitationForm = true;
			}
		}
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

unittest  // forVersion strips title for versions older than 2025-06-18
{
	Implementation impl = {
		name: "srv", version_: "1", title: nullable("My Server")
	};
	auto p1 = impl.forVersion(ProtocolVersion.v2025_03_26);
	assert(p1.title.isNull);
	assert("title" !in p1.toJson());
	assert(p1.name == "srv" && p1.version_ == "1");
}

unittest  // forVersion keeps title from 2025-06-18 but strips 2025-11-25 fields
{
	Implementation impl = {
		name: "srv", version_: "1", title: nullable("My Server"), description: nullable("does things"), websiteUrl: nullable(
				"https://example.com"), icons: [
			Icon("https://example.com/i.png")
		]
	};
	auto p1 = impl.forVersion(ProtocolVersion.v2025_06_18);
	auto j = p1.toJson();
	assert(j["title"].get!string == "My Server");
	assert("description" !in j);
	assert("websiteUrl" !in j);
	assert("icons" !in j);
}

unittest  // forVersion keeps every field for 2025-11-25 and draft
{
	Implementation impl = {
		name: "srv", version_: "1", title: nullable("My Server"), description: nullable("does things"), websiteUrl: nullable(
				"https://example.com"), icons: [
			Icon("https://example.com/i.png")
		]
	};
	foreach (v; [ProtocolVersion.v2025_11_25, ProtocolVersion.draft])
	{
		auto j = impl.forVersion(v).toJson();
		assert(j["title"].get!string == "My Server");
		assert(j["description"].get!string == "does things");
		assert(j["websiteUrl"].get!string == "https://example.com");
		assert(j["icons"].length == 1);
	}
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
	// Spec 2025-11-25: `requests` is structured by request category with boolean
	// (presence) properties, e.g. {"tools": {"call": {}}} -- NOT a flat
	// "tools/call" key.
	t.requests = TaskRequests().tool().toJson();
	caps.tasks = t;
	auto j = caps.toJson();
	assert(j["tasks"]["list"].type == Json.Type.object && j["tasks"]["list"].length == 0);
	assert(j["tasks"]["cancel"].type == Json.Type.object);
	assert(j["tasks"]["requests"]["tools"]["call"].type == Json.Type.object);
	assert("tools/call" !in j["tasks"]["requests"]);
}

unittest  // ServerCapabilities round-trips the `tasks` capability
{
	ServerCapabilities caps;
	TasksCapability t;
	t.list = true;
	t.requests = TaskRequests().tool().toJson();
	caps.tasks = t;
	auto back = ServerCapabilities.fromJson(caps.toJson());
	assert(!back.tasks.isNull);
	assert(back.tasks.get.list);
	assert(!back.tasks.get.cancel);
	assert(back.tasks.get.requests["tools"]["call"].type == Json.Type.object);
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
	// Spec 2025-11-25 client form: {"sampling": {"createMessage": {}},
	// "elicitation": {"create": {}}} -- nested by category, not flat
	// "sampling/createMessage".
	t.requests = TaskRequests().samplingCreateMessage().elicitationCreate().toJson();
	caps.tasks = t;
	auto j = caps.toJson();
	assert(j["tasks"]["requests"]["sampling"]["createMessage"].type == Json.Type.object);
	assert(j["tasks"]["requests"]["elicitation"]["create"].type == Json.Type.object);
	assert("sampling/createMessage" !in j["tasks"]["requests"]);
	// Client form carries only `requests` (no server-only list/cancel keys).
	assert("list" !in j["tasks"]);
	assert("cancel" !in j["tasks"]);
}

unittest  // ClientCapabilities round-trips the `tasks` capability
{
	ClientCapabilities caps;
	TasksCapability t;
	t.requests = TaskRequests().samplingCreateMessage().toJson();
	caps.tasks = t;
	auto back = ClientCapabilities.fromJson(caps.toJson());
	assert(!back.tasks.isNull);
	assert(back.tasks.get.requests["sampling"]["createMessage"].type == Json.Type.object);
}

unittest  // ClientCapabilities omits `tasks` when unset
{
	ClientCapabilities caps;
	assert("tasks" !in caps.toJson());
}

unittest  // TaskRequests builds the spec server shape {"tools": {"call": {}}}
{
	auto j = TaskRequests().tool().toJson();
	assert(j.type == Json.Type.object);
	assert(j["tools"].type == Json.Type.object);
	assert(j["tools"]["call"].type == Json.Type.object && j["tools"]["call"].length == 0);
	assert("tools/call" !in j);
}

unittest  // TaskRequests builds the spec client shape with nested categories
{
	auto j = TaskRequests().samplingCreateMessage().elicitationCreate().toJson();
	assert(j["sampling"]["createMessage"].type == Json.Type.object);
	assert(j["elicitation"]["create"].type == Json.Type.object);
	assert("sampling/createMessage" !in j);
	assert("elicitation/create" !in j);
}

unittest  // TaskRequests.add nests arbitrary category/operation pairs
{
	auto j = TaskRequests().add("tools", "call").add("sampling", "createMessage").toJson();
	assert(j["tools"]["call"].type == Json.Type.object);
	assert(j["sampling"]["createMessage"].type == Json.Type.object);
}

unittest  // TaskRequests.add groups multiple operations under one category
{
	auto j = TaskRequests().add("tools", "call").add("tools", "list").toJson();
	assert(j["tools"]["call"].type == Json.Type.object);
	assert(j["tools"]["list"].type == Json.Type.object);
}

unittest  // TaskRequests with nothing added yields an empty object
{
	auto j = TaskRequests().toJson();
	assert(j.type == Json.Type.object && j.length == 0);
}

unittest  // TaskRequests output assigned to TasksCapability round-trips nested keys
{
	TasksCapability t;
	t.list = true;
	t.requests = TaskRequests().tool().toJson();
	auto back = TasksCapability.fromJson(t.toJson());
	assert(back.requests["tools"]["call"].type == Json.Type.object);
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

unittest  // ClientCapabilities advertises elicitation form/url submodes (2025-11-25)
{
	ClientCapabilities caps;
	caps.elicitation = true;
	caps.elicitationForm = true;
	caps.elicitationUrl = true;
	auto j = caps.toJson();
	assert(j["elicitation"].type == Json.Type.object);
	assert(j["elicitation"]["form"].type == Json.Type.object && j["elicitation"]["form"].length == 0);
	assert(j["elicitation"]["url"].type == Json.Type.object && j["elicitation"]["url"].length == 0);
}

unittest  // ClientCapabilities advertises URL-only elicitation mode
{
	ClientCapabilities caps;
	caps.elicitation = true;
	caps.elicitationUrl = true;
	auto j = caps.toJson();
	assert(j["elicitation"]["url"].type == Json.Type.object);
	assert("form" !in j["elicitation"]);
}

unittest  // ClientCapabilities round-trips elicitation submodes
{
	ClientCapabilities caps;
	caps.elicitation = true;
	caps.elicitationForm = true;
	caps.elicitationUrl = true;
	auto back = ClientCapabilities.fromJson(caps.toJson());
	assert(back.elicitation && back.elicitationForm && back.elicitationUrl);
}

unittest  // ClientCapabilities elicitation empty object => form-only (backwards compat)
{
	ClientCapabilities caps;
	caps.elicitation = true;
	auto j = caps.toJson();
	// Backwards-compatible empty-object emission.
	assert(j["elicitation"].type == Json.Type.object && j["elicitation"].length == 0);
	auto back = ClientCapabilities.fromJson(j);
	// Empty object is equivalent to declaring form mode only.
	assert(back.elicitation && back.elicitationForm && !back.elicitationUrl);
}

unittest  // ClientCapabilities parses explicit elicitation submodes from peer payload
{
	Json j = Json.emptyObject;
	Json e = Json.emptyObject;
	e["form"] = Json.emptyObject;
	e["url"] = Json.emptyObject;
	j["elicitation"] = e;
	auto back = ClientCapabilities.fromJson(j);
	assert(back.elicitation && back.elicitationForm && back.elicitationUrl);
}

unittest  // ClientCapabilities parses url-only elicitation from peer payload
{
	Json j = Json.emptyObject;
	Json e = Json.emptyObject;
	e["url"] = Json.emptyObject;
	j["elicitation"] = e;
	auto back = ClientCapabilities.fromJson(j);
	assert(back.elicitation && !back.elicitationForm && back.elicitationUrl);
}

unittest  // ClientCapabilities elicitation submodes imply elicitation presence
{
	ClientCapabilities caps;
	caps.elicitationUrl = true;
	auto j = caps.toJson();
	assert("elicitation" in j);
	assert(j["elicitation"]["url"].type == Json.Type.object);
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

unittest  // Implementation emits 2025-11-25 description/websiteUrl/icons when set
{
	Implementation impl;
	impl.name = "srv";
	impl.version_ = "1.0";
	impl.description = "A demo server";
	impl.websiteUrl = "https://example.com";
	impl.icons = [
		Icon("https://example.com/i.png", nullable("image/png"), ["48x48"])
	];
	auto j = impl.toJson();
	assert(j["description"].get!string == "A demo server");
	assert(j["websiteUrl"].get!string == "https://example.com");
	assert(j["icons"].type == Json.Type.array);
	assert(j["icons"].length == 1);
	assert(j["icons"][0]["src"].get!string == "https://example.com/i.png");
	assert(j["icons"][0]["mimeType"].get!string == "image/png");
	assert(j["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // Implementation omits the optional BaseMetadata fields when unset
{
	Implementation impl;
	impl.name = "srv";
	impl.version_ = "1.0";
	auto j = impl.toJson();
	assert("description" !in j);
	assert("websiteUrl" !in j);
	assert("icons" !in j);
}

unittest  // Implementation round-trips description/websiteUrl/icons from a peer payload
{
	Json j = Json.emptyObject;
	j["name"] = "cli";
	j["version"] = "0.1";
	j["description"] = "client";
	j["websiteUrl"] = "https://client.example";
	Json arr = Json.emptyArray;
	Json ic = Json.emptyObject;
	ic["src"] = "https://client.example/logo.svg";
	arr ~= ic;
	j["icons"] = arr;
	auto impl = Implementation.fromJson(j);
	assert(impl.description.get == "client");
	assert(impl.websiteUrl.get == "https://client.example");
	assert(impl.icons.length == 1);
	assert(impl.icons[0].src == "https://client.example/logo.svg");
}
