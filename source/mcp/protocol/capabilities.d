module mcp.protocol.capabilities;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;
import mcp.protocol.versions : ProtocolVersion, isDraft;
import mcp.protocol.jsonhelpers : getOr, tryGet;

@safe:

/// The draft Extension Negotiation identifier under which task support is
/// declared. In the draft schema, `ServerCapabilities`/`ClientCapabilities`
/// have NO top-level `tasks` field; task support is carried in the `extensions`
/// map keyed by this identifier. (2025-11-25 keeps `tasks` as a first-class
/// capability instead.)
enum string tasksExtensionKey = "io.modelcontextprotocol/tasks";

/// Fold a (possibly null) first-class `tasks` capability into a copy of the
/// draft `extensions` map under `tasksExtensionKey`. Used by `forVersion` to
/// project task support to the draft wire shape, where `tasks` is not a
/// top-level field. An explicit `extensions[tasksExtensionKey]` entry already
/// present in `ext` is preserved (the caller's explicit advertisement wins).
private Json foldTasksIntoExtensions(Json ext, const Nullable!TasksCapability tasks) @safe
{
	Json merged = (ext.type == Json.Type.object) ? ext.clone() : Json.emptyObject;
	if (!tasks.isNull && tasksExtensionKey !in merged)
		merged[tasksExtensionKey] = tasks.get.toJson();
	return (merged.length > 0) ? merged : Json.undefined;
}

/// An icon for display in user interfaces. Used by `Implementation`,
/// `Tool` (and other definitions) per the MCP spec's icon shape: a required
/// `src` and optional `mimeType`, `sizes`, and `theme` ("light"|"dark").
struct Icon
{
	string src; /// URI or data: URL of the icon
	Nullable!string mimeType; /// optional MIME type, e.g. "image/png"
	string[] sizes; /// optional size strings, e.g. ["48x48", "96x96"]
	Nullable!string theme; /// optional theme preference, "light" or "dark"

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
		if (!theme.isNull)
			j["theme"] = theme.get;
		return j;
	}

	static Icon fromJson(Json j) @safe
	{
		Icon icon;
		icon.src = j.getOr("src", "");
		tryGet(j, "mimeType", icon.mimeType);
		if ("sizes" in j && j["sizes"].type == Json.Type.array)
			foreach (i; 0 .. j["sizes"].length)
				icon.sizes ~= j["sizes"][i].get!string;
		tryGet(j, "theme", icon.theme);
		return icon;
	}

	/// Deep-copy this icon. Scalar and `Nullable` fields copy by value; the
	/// `sizes` slice is duplicated so the copy does not alias the original.
	Icon dup() const @safe
	{
		Icon c;
		c.src = src;
		c.mimeType = mimeType;
		c.sizes = sizes.dup;
		c.theme = theme;
		return c;
	}
}

@safe unittest  // Icon.dup deep-copies sizes so the copy does not alias the original
{
	Icon icon;
	icon.src = "https://example/icon.png";
	icon.sizes = ["48x48", "96x96"];
	Icon copy = icon.dup();
	copy.sizes[0] = "16x16";
	assert(icon.sizes[0] == "48x48");
}

/// Identifies an MCP implementation (client or server).
///
/// Per the schema `Implementation` extends `BaseMetadata` (`name`/`title`) and
/// the `Icons` mixin, adding `version` plus the optional `description`,
/// `websiteUrl`, and `icons` fields (`description`/`icons`/`websiteUrl` apply
/// from 2025-11-25). All optional fields are omitted from `toJson` when unset,
/// so wire output stays valid for older protocol versions.
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
		impl.name = j.getOr("name", "");
		impl.version_ = j.getOr("version", "");
		tryGet(j, "title", impl.title);
		tryGet(j, "description", impl.description);
		tryGet(j, "websiteUrl", impl.websiteUrl);
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				impl.icons ~= Icon.fromJson(j["icons"][i]);
		return impl;
	}

	/// Return a copy of this `Implementation` with any fields newer than the
	/// negotiated protocol version stripped, so the wire output stays valid for
	/// the peer's version. `title` applies from 2025-06-18 (`BaseMetadata`);
	/// `description`, `websiteUrl`, and `icons` apply from 2025-11-25.
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
				projected.icons ~= icon.dup();
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

	/// Return a copy of these capabilities with any field newer than the
	/// negotiated protocol version stripped, so the wire output only advertises
	/// capabilities that existed in (and were negotiated for) the peer's
	/// version. Mirrors `Implementation.forVersion`. The basic/lifecycle rule
	/// "Only use capabilities that were successfully negotiated" requires this:
	/// `completions` applies from 2025-03-26, `tasks` from 2025-11-25, and
	/// the `extensions` negotiation map is draft-only. `tools`/`resources`/
	/// `prompts`/`logging`/`experimental` exist in every supported version.
	ServerCapabilities forVersion(ProtocolVersion v) const @safe
	{
		ServerCapabilities projected;
		projected.tools = tools;
		projected.resources = resources;
		projected.prompts = prompts;
		projected.logging = logging;
		projected.experimental = experimental;
		if (v >= ProtocolVersion.v2025_03_26)
			projected.completions = completions;
		// `tasks` is a first-class capability in the stable 2025-11-25 era and any
		// future stable (non-draft) revision >= 2025-11-25. The draft schema has no
		// top-level `tasks`; task support there is negotiated via the `extensions`
		// map keyed by `tasksExtensionKey`. The range + `!isDraft` predicate keeps a
		// future stable version inserted before `draft` emitting top-level `tasks`.
		if (v >= ProtocolVersion.v2025_11_25 && !v.isDraft)
			projected.tasks = tasks;
		else if (v.isDraft)
			projected.extensions = foldTasksIntoExtensions(extensions, tasks);
		return projected;
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

	/// Project these capabilities to the wire shape for protocol version `v`,
	/// stripping any field newer than `v` and migrating `tasks` to the draft
	/// `extensions` map. `roots`/`rootsListChanged`, a bare `sampling`, and
	/// `experimental` exist in every supported version and pass through unchanged.
	/// `elicitation` applies from 2025-06-18, so it is gated to
	/// `>= 2025-06-18` (a client that set only an elicitation submode still
	/// projects a bare `elicitation` there). The sampling/elicitation sub-objects
	/// (`sampling.tools`/`sampling.context`, `elicitation.form`/`elicitation.url`)
	/// apply from 2025-11-25 and are stripped below that. `tasks` is a
	/// first-class client capability in the stable 2025-11-25 era (and any future
	/// stable revision >= 2025-11-25); the draft schema has no top-level client
	/// `tasks`, so for draft it is folded into `extensions[tasksExtensionKey]`. The
	/// `extensions` negotiation map itself is draft-only.
	ClientCapabilities forVersion(ProtocolVersion v) const @safe
	{
		ClientCapabilities projected;
		projected.roots = roots;
		projected.rootsListChanged = rootsListChanged;
		projected.sampling = sampling;
		projected.experimental = experimental;
		// elicitation applies from 2025-06-18. `toJson` treats a set
		// `elicitationForm`/`elicitationUrl` as implying elicitation presence, so a
		// client that set only a submode must still project a bare `elicitation`
		// here; the sub-flags themselves are gated to 2025-11-25 below.
		if (v >= ProtocolVersion.v2025_06_18)
			projected.elicitation = elicitation || elicitationForm || elicitationUrl;
		// sampling/elicitation sub-objects apply from 2025-11-25.
		if (v >= ProtocolVersion.v2025_11_25)
		{
			projected.samplingTools = samplingTools;
			projected.samplingContext = samplingContext;
			projected.elicitationForm = elicitationForm;
			projected.elicitationUrl = elicitationUrl;
		}
		// `tasks` is first-class in the stable 2025-11-25 era and any future stable
		// (non-draft) revision; the draft era folds it into `extensions`. Mirror the
		// range + `!isDraft` predicate used by `ServerCapabilities.forVersion`.
		if (v >= ProtocolVersion.v2025_11_25 && !v.isDraft)
			projected.tasks = tasks;
		else if (v.isDraft)
			projected.extensions = foldTasksIntoExtensions(extensions, tasks);
		return projected;
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

	/// Compute the capabilities this object requires that are NOT present in
	/// `declared`. Used by a server to build the `data.requiredCapabilities`
	/// payload of a `-32003 MissingRequiredClientCapabilityError`: `this` is the
	/// set a request needs, `declared` is what the client actually advertised,
	/// and the result is a `ClientCapabilities` containing exactly the missing
	/// ones. A capability is satisfied when the client declared at least the same
	/// presence flag (sub-capability flags imply their parent presence here, in
	/// line with `toJson`). The boolean `anyMissing` out-param is `true` iff the
	/// returned object carries at least one unmet requirement. The `experimental`
	/// and `extensions` Json maps are compared by required-key presence: any
	/// required key absent from `declared` is reported.
	ClientCapabilities missingFrom(const ClientCapabilities declared, out bool anyMissing) const @safe
	{
		ClientCapabilities missing;
		const declSampling = declared.sampling || declared.samplingTools || declared
			.samplingContext;
		const declElicit = declared.elicitation || declared.elicitationForm
			|| declared.elicitationUrl;

		if (roots && !declared.roots)
		{
			missing.roots = true;
			anyMissing = true;
		}
		if (rootsListChanged && !declared.rootsListChanged)
		{
			missing.roots = true;
			missing.rootsListChanged = true;
			anyMissing = true;
		}
		if (sampling && !declSampling)
		{
			missing.sampling = true;
			anyMissing = true;
		}
		if (samplingTools && !declared.samplingTools)
		{
			missing.samplingTools = true;
			anyMissing = true;
		}
		if (samplingContext && !declared.samplingContext)
		{
			missing.samplingContext = true;
			anyMissing = true;
		}
		if (elicitation && !declElicit)
		{
			missing.elicitation = true;
			anyMissing = true;
		}
		if (elicitationForm && !(declared.elicitationForm || declElicit))
		{
			missing.elicitationForm = true;
			anyMissing = true;
		}
		if (elicitationUrl && !declared.elicitationUrl)
		{
			missing.elicitationUrl = true;
			anyMissing = true;
		}
		if (!tasks.isNull && declared.tasks.isNull)
		{
			missing.tasks = tasks;
			anyMissing = true;
		}
		if (experimental.type == Json.Type.object)
		{
			Json missingExp = Json.emptyObject;
			bool anyExp;
			// `Json.opApply` is `@system` and non-`const`; we only read, so cast
			// away `const` inside the trusted block to iterate the object.
			() @trusted {
				foreach (string k, Json v; cast() experimental)
					if (declared.experimental.type != Json.Type.object || k !in declared
							.experimental)
					{
						missingExp[k] = v;
						anyExp = true;
					}
			}();
			if (anyExp)
			{
				missing.experimental = missingExp;
				anyMissing = true;
			}
		}
		if (extensions.type == Json.Type.object)
		{
			Json missingExt = Json.emptyObject;
			bool anyExt;
			// `Json.opApply` is `@system` and non-`const`; we only read, so cast
			// away `const` inside the trusted block to iterate the object.
			() @trusted {
				foreach (string k, Json v; cast() extensions)
					if (declared.extensions.type != Json.Type.object || k !in declared.extensions)
					{
						missingExt[k] = v;
						anyExt = true;
					}
			}();
			if (anyExt)
			{
				missing.extensions = missingExt;
				anyMissing = true;
			}
		}
		return missing;
	}
}

unittest  // missingFrom: an unmet sampling requirement is reported
{
	ClientCapabilities required = {sampling: true};
	ClientCapabilities declared; // nothing advertised
	bool any;
	auto missing = required.missingFrom(declared, any);
	assert(any);
	assert(missing.sampling);
	assert("sampling" in missing.toJson());
}

unittest  // missingFrom: a satisfied requirement reports nothing
{
	ClientCapabilities required = {sampling: true};
	ClientCapabilities declared = {sampling: true};
	bool any;
	auto missing = required.missingFrom(declared, any);
	assert(!any);
	assert(!missing.sampling);
	assert(missing.toJson().length == 0);
}

unittest  // missingFrom: elicitation url submode unmet by a form-only client
{
	ClientCapabilities required = {elicitationUrl: true};
	ClientCapabilities declared = {elicitationForm: true};
	bool any;
	auto missing = required.missingFrom(declared, any);
	assert(any);
	assert(missing.elicitationUrl);
}

unittest  // missingFrom: a required experimental key absent from the client
{
	ClientCapabilities required;
	required.experimental = Json(["io.example/x": Json.emptyObject]);
	ClientCapabilities declared;
	bool any;
	auto missing = required.missingFrom(declared, any);
	assert(any);
	assert("io.example/x" in missing.experimental);
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

unittest  // Icon emits theme when set and omits it when unset
{
	Icon i = {src: "https://example.com/i.png", theme: nullable("dark")};
	auto j = i.toJson();
	assert(j["src"].get!string == "https://example.com/i.png");
	assert(j["theme"].get!string == "dark");

	Icon bare = {src: "https://example.com/i.png"};
	assert("theme" !in bare.toJson());
}

unittest  // Icon round-trips theme through fromJson (light)
{
	Icon i = {src: "s", theme: nullable("light")};
	auto back = Icon.fromJson(i.toJson());
	assert(back.theme.get == "light");
}

unittest  // Icon.fromJson leaves theme null when absent
{
	auto j = Icon("s").toJson();
	auto back = Icon.fromJson(j);
	assert(back.theme.isNull);
	assert("theme" !in back.toJson());
}

unittest  // Implementation.forVersion carries icon theme for 2025-11-25 and draft
{
	Implementation impl = {
		name: "srv", version_: "1", icons: [
			Icon("https://example.com/i.png", Nullable!string.init, [], nullable("dark"))
		]
	};
	foreach (v; [ProtocolVersion.v2025_11_25, ProtocolVersion.draft])
	{
		auto projected = impl.forVersion(v);
		assert(projected.icons.length == 1);
		assert(projected.icons[0].theme.get == "dark");
		assert(projected.toJson()["icons"][0]["theme"].get!string == "dark");
	}
}

unittest  // ServerCapabilities.forVersion strips completions before 2025-03-26
{
	ServerCapabilities caps;
	caps.completions = true;
	auto j = caps.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("completions" !in j);
}

unittest  // ServerCapabilities.forVersion keeps completions from 2025-03-26
{
	ServerCapabilities caps;
	caps.completions = true;
	foreach (v; [
		ProtocolVersion.v2025_03_26, ProtocolVersion.v2025_06_18,
		ProtocolVersion.v2025_11_25, ProtocolVersion.draft
	])
		assert("completions" in caps.forVersion(v).toJson());
}

unittest  // ServerCapabilities.forVersion strips tasks before 2025-11-25
{
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	foreach (v; [
		ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
		ProtocolVersion.v2025_06_18
	])
		assert("tasks" !in caps.forVersion(v).toJson());
}

unittest  // ServerCapabilities.forVersion keeps top-level tasks only for 2025-11-25
{
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	assert("tasks" in caps.forVersion(ProtocolVersion.v2025_11_25).toJson());
}

unittest  // ServerCapabilities.forVersion: draft has no top-level tasks capability
{
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	auto j = caps.forVersion(ProtocolVersion.draft).toJson();
	assert("tasks" !in j);
}

unittest  // ServerCapabilities.forVersion folds tasks into extensions for draft
{
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	auto j = caps.forVersion(ProtocolVersion.draft).toJson();
	assert("extensions" in j);
	assert("io.modelcontextprotocol/tasks" in j["extensions"]);
	// The per-extension settings object carries the negotiated tasks shape.
	assert("list" in j["extensions"]["io.modelcontextprotocol/tasks"]);
	assert("cancel" in j["extensions"]["io.modelcontextprotocol/tasks"]);
}

unittest  // ServerCapabilities.forVersion: explicit tasks extension wins over folded tasks
{
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	Json ext = Json.emptyObject;
	Json settings = Json.emptyObject;
	settings["maxConcurrent"] = 4;
	ext["io.modelcontextprotocol/tasks"] = settings;
	caps.extensions = ext;
	auto j = caps.forVersion(ProtocolVersion.draft).toJson();
	// The caller's explicit advertisement is preserved, not overwritten by fold.
	assert(j["extensions"]["io.modelcontextprotocol/tasks"]["maxConcurrent"].get!int == 4);
}

unittest  // ClientCapabilities.forVersion keeps top-level tasks only for 2025-11-25
{
	ClientCapabilities caps;
	caps.tasks = TasksCapability(false, false);
	assert("tasks" in caps.forVersion(ProtocolVersion.v2025_11_25).toJson());
}

unittest  // ClientCapabilities.forVersion: draft has no top-level tasks capability
{
	ClientCapabilities caps;
	caps.tasks = TasksCapability(false, false);
	auto j = caps.forVersion(ProtocolVersion.draft).toJson();
	assert("tasks" !in j);
}

unittest  // ClientCapabilities.forVersion folds tasks into extensions for draft
{
	ClientCapabilities caps;
	caps.tasks = TasksCapability(false, false);
	auto j = caps.forVersion(ProtocolVersion.draft).toJson();
	assert("extensions" in j);
	assert("io.modelcontextprotocol/tasks" in j["extensions"]);
}

unittest  // ClientCapabilities.forVersion strips top-level tasks before 2025-11-25
{
	ClientCapabilities caps;
	caps.tasks = TasksCapability(false, false);
	foreach (v; [
		ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
		ProtocolVersion.v2025_06_18
	])
	{
		auto j = caps.forVersion(v).toJson();
		assert("tasks" !in j);
		assert("extensions" !in j);
	}
}

unittest  // ServerCapabilities.forVersion strips extensions for non-draft
{
	ServerCapabilities caps;
	Json ext = Json.emptyObject;
	ext["io.modelcontextprotocol/tasks"] = Json.emptyObject;
	caps.extensions = ext;
	foreach (v; [
		ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
		ProtocolVersion.v2025_06_18, ProtocolVersion.v2025_11_25
	])
		assert("extensions" !in caps.forVersion(v).toJson());
}

unittest  // ServerCapabilities.forVersion keeps extensions for draft
{
	ServerCapabilities caps;
	Json ext = Json.emptyObject;
	ext["io.modelcontextprotocol/tasks"] = Json.emptyObject;
	caps.extensions = ext;
	assert("extensions" in caps.forVersion(ProtocolVersion.draft).toJson());
}

unittest  // ServerCapabilities.forVersion always keeps base capabilities
{
	ServerCapabilities caps;
	caps.tools = ListChangedCapability(true);
	caps.resources = ResourcesCapability(true, true);
	caps.prompts = ListChangedCapability(false);
	caps.logging = true;
	auto j = caps.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("tools" in j);
	assert("resources" in j);
	assert("prompts" in j);
	assert("logging" in j);
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

unittest  // ClientCapabilities.forVersion: 2025-03-26 emits a bare sampling and no elicitation
{
	// elicitation applies from 2025-06-18; sampling sub-objects from 2025-11-25. A
	// client holding the full 2025-11-25 capability set must project to the older
	// wire shape: a bare `sampling: {}` with no tools/context, and no
	// `elicitation` at all.
	ClientCapabilities caps;
	caps.sampling = true;
	caps.samplingTools = true;
	caps.samplingContext = true;
	caps.elicitation = true;
	caps.elicitationForm = true;
	caps.elicitationUrl = true;
	auto j = caps.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert(j["sampling"].type == Json.Type.object && j["sampling"].length == 0);
	assert("tools" !in j["sampling"]);
	assert("context" !in j["sampling"]);
	assert("elicitation" !in j);
}

unittest  // ClientCapabilities.forVersion: 2025-06-18 emits bare sampling and bare elicitation, no sub-objects
{
	ClientCapabilities caps;
	caps.sampling = true;
	caps.samplingTools = true;
	caps.samplingContext = true;
	caps.elicitation = true;
	caps.elicitationForm = true;
	caps.elicitationUrl = true;
	auto j = caps.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert(j["sampling"].type == Json.Type.object && j["sampling"].length == 0);
	assert(j["elicitation"].type == Json.Type.object && j["elicitation"].length == 0);
	assert("tools" !in j["sampling"]);
	assert("context" !in j["sampling"]);
	assert("form" !in j["elicitation"]);
	assert("url" !in j["elicitation"]);
}

unittest  // ClientCapabilities.forVersion: 2025-06-18 projects bare elicitation when only a submode was set
{
	// toJson treats elicitationForm/elicitationUrl as implying elicitation
	// presence. A client that set only a submode must still project a bare
	// `elicitation: {}` for 2025-06-18 (the era with elicitation but no submodes).
	ClientCapabilities caps;
	caps.elicitationUrl = true; // submode only, no explicit `elicitation`
	auto j = caps.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("elicitation" in j);
	assert(j["elicitation"].type == Json.Type.object && j["elicitation"].length == 0);
}

unittest  // ClientCapabilities.forVersion: 2025-11-25 preserves all sampling/elicitation sub-objects
{
	ClientCapabilities caps;
	caps.sampling = true;
	caps.samplingTools = true;
	caps.samplingContext = true;
	caps.elicitation = true;
	caps.elicitationForm = true;
	caps.elicitationUrl = true;
	auto j = caps.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("tools" in j["sampling"]);
	assert("context" in j["sampling"]);
	assert("form" in j["elicitation"]);
	assert("url" in j["elicitation"]);
}

unittest  // ClientCapabilities.forVersion keeps roots/rootsListChanged unconditionally
{
	ClientCapabilities caps;
	caps.roots = true;
	caps.rootsListChanged = true;
	foreach (v; [
		ProtocolVersion.v2024_11_05, ProtocolVersion.v2025_03_26,
		ProtocolVersion.v2025_06_18, ProtocolVersion.v2025_11_25,
		ProtocolVersion.draft
	])
		assert(caps.forVersion(v).toJson()["roots"]["listChanged"].get!bool);
}

unittest  // ServerCapabilities.forVersion keeps top-level tasks for any stable version >= 2025-11-25
{
	// Any stable (non-draft) version >= 2025-11-25 must keep top-level tasks; the
	// draft era folds tasks into `extensions` instead. Today 2025-11-25 is the
	// only such stable version, but the predicate must be range + draft based so a
	// future stable version inserted before `draft` still emits top-level tasks.
	ServerCapabilities caps;
	caps.tasks = TasksCapability(true, true);
	foreach (v; supportedVersionsAtLeast(ProtocolVersion.v2025_11_25))
	{
		auto j = caps.forVersion(v).toJson();
		if (v.isDraft)
		{
			assert("tasks" !in j);
			assert("extensions" in j);
		}
		else
			assert("tasks" in j);
	}
}

unittest  // ClientCapabilities.forVersion keeps top-level tasks for any stable version >= 2025-11-25
{
	ClientCapabilities caps;
	caps.tasks = TasksCapability(false, false);
	foreach (v; supportedVersionsAtLeast(ProtocolVersion.v2025_11_25))
	{
		auto j = caps.forVersion(v).toJson();
		if (v.isDraft)
		{
			assert("tasks" !in j);
			assert("extensions" in j);
		}
		else
			assert("tasks" in j);
	}
}

version (unittest) private ProtocolVersion[] supportedVersionsAtLeast(ProtocolVersion min) @safe
{
	import mcp.protocol.versions : supportedVersions;

	ProtocolVersion[] result;
	foreach (v; supportedVersions)
		if (v >= min)
			result ~= v;
	return result;
}
