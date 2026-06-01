module mcp.protocol.types;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json, parseJsonString;
import mcp.protocol.capabilities;
import mcp.protocol.versions : ProtocolVersion;
import mcp.protocol.draft : InputRequest, inputRequestsToJson,
	inputRequestsFromJson, CacheHint, parseCacheHint, withCache;

@safe:

/// The kind of a content block.
///
/// `toolUse`/`toolResult` are the sampling content blocks added by the
/// 2025-11-25 / draft tool-enabled sampling revisions (`ToolUseContent` /
/// `ToolResultContent` in the schema); they appear inside
/// `sampling/createMessage` messages and results, not in tool/prompt content.
enum ContentKind
{
	text,
	image,
	audio,
	resourceLink,
	embeddedResource,
	toolUse,
	toolResult
}

/// Shared optional fields carried by every content kind in the MCP schema:
/// an `_meta` object and `annotations` (audience/priority/lastModified). Mixed
/// into each per-kind content struct so the fields live exactly once, with no
/// per-kind duplication or "meaningless on this kind" footgun.
mixin template ContentMetaFields()
{
	Json annotations = Json.undefined; /// optional annotations (audience/priority/lastModified)
	Json meta = Json.undefined; /// optional `_meta` object

	private void emitMeta(ref Json j) const @safe
	{
		if (annotations.type != Json.Type.undefined)
			j["annotations"] = annotations;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
	}

	private void parseMeta(Json j) @safe
	{
		if ("annotations" in j)
			annotations = j["annotations"];
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			meta = j["_meta"];
	}
}

/// `text` content block (`TextContent`).
struct TextContent
{
	string text;
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "text";
		j["text"] = text;
		emitMeta(j);
		return j;
	}
}

/// `image` content block (`ImageContent`): base64 `data` + `mimeType`.
struct ImageContent
{
	string data;
	string mimeType;
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "image";
		j["data"] = data;
		j["mimeType"] = mimeType;
		emitMeta(j);
		return j;
	}
}

/// `audio` content block (`AudioContent`): base64 `data` + `mimeType`.
struct AudioContent
{
	string data;
	string mimeType;
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "audio";
		j["data"] = data;
		j["mimeType"] = mimeType;
		emitMeta(j);
		return j;
	}
}

/// `resource_link` content block (`ResourceLink`, extends `Resource`).
struct ResourceLink
{
	string uri;
	string name;
	string mimeType;
	Nullable!string description; /// optional human-readable description
	Nullable!string title; /// optional human-readable display name
	Nullable!long size; /// optional size in bytes of the linked resource
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "resource_link";
		j["uri"] = uri;
		if (name.length)
			j["name"] = name;
		if (!title.isNull)
			j["title"] = title.get;
		if (!description.isNull)
			j["description"] = description.get;
		if (mimeType.length)
			j["mimeType"] = mimeType;
		if (!size.isNull)
			j["size"] = size.get;
		emitMeta(j);
		return j;
	}
}

/// `resource` content block (`EmbeddedResource`): wraps a resource contents
/// object under `resource`.
struct EmbeddedResource
{
	Json resource = Json.undefined;
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "resource";
		j["resource"] = resource;
		emitMeta(j);
		return j;
	}
}

/// `tool_use` content block (`ToolUseContent`, sampling only): the model's
/// request to call a tool.
struct ToolUseContent
{
	string id; /// the tool-call id the model assigned
	string name; /// the tool name
	Json input = Json.undefined; /// the tool-call arguments object
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "tool_use";
		j["id"] = id;
		j["name"] = name;
		j["input"] = (input.type == Json.Type.object) ? input : Json.emptyObject;
		emitMeta(j);
		return j;
	}
}

/// `tool_result` content block (`ToolResultContent`, sampling only): the result
/// of a tool call, answering the `tool_use` whose id is `toolUseId`.
struct ToolResultContent
{
	string toolUseId; /// the `id` of the tool_use this answers
	Content[] content; /// nested content blocks of the result
	Json structuredContent = Json.undefined; /// optional structured result
	Nullable!bool isError; /// optional error flag
	mixin ContentMetaFields;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = "tool_result";
		j["toolUseId"] = toolUseId;
		Json tc = Json.emptyArray;
		foreach (b; content)
			tc ~= b.toJson();
		j["content"] = tc;
		if (structuredContent.type != Json.Type.undefined)
			j["structuredContent"] = structuredContent;
		if (!isError.isNull)
			j["isError"] = isError.get;
		emitMeta(j);
		return j;
	}
}

/// A content block as used in tool results, prompt messages, and sampling.
///
/// Modeled as a tagged union over the per-kind content structs above
/// (`TextContent`, `ImageContent`, `AudioContent`, `ResourceLink`,
/// `EmbeddedResource`, `ToolUseContent`, `ToolResultContent`). Each kind stores
/// only the fields that are meaningful for it, so there are no
/// meaningless-per-kind fields. Construct via the `make*` factories; the
/// chainable `with*` setters apply only on the kinds where the field is valid.
struct Content
{
	import std.sumtype : SumType, match;

	/// The underlying tagged union. Public so callers that prefer
	/// `std.sumtype.match` can pattern-match directly over the per-kind structs.
	alias Payload = SumType!(TextContent, ImageContent, AudioContent,
			ResourceLink, EmbeddedResource, ToolUseContent, ToolResultContent);

	Payload payload = Payload(TextContent.init);

	this(P)(P p) @safe
			if (is(P : TextContent) || is(P : ImageContent) || is(P
				: AudioContent) || is(P : ResourceLink) || is(P : EmbeddedResource)
				|| is(P : ToolUseContent) || is(P : ToolResultContent))
	{
		payload = Payload(p);
	}

	// SumType's generated `opAssign` is inferred `@system` (vibe-d `Json` fields
	// make the compiler-injected safety check `@system`), which would poison
	// every `@safe` `c = other;` site. The payload assignment is genuinely
	// memory-safe, so route assignment through an explicit `@trusted` shim.
	ref Content opAssign(return scope Content other) @trusted
	{
		this.payload = other.payload;
		return this;
	}

	/// Which content kind this block holds.
	ContentKind kind() const @safe
	{
		return payload.match!((const ref TextContent _) => ContentKind.text,
				(const ref ImageContent _) => ContentKind.image,
				(const ref AudioContent _) => ContentKind.audio,
				(const ref ResourceLink _) => ContentKind.resourceLink,
				(const ref EmbeddedResource _) => ContentKind.embeddedResource,
				(const ref ToolUseContent _) => ContentKind.toolUse,
				(const ref ToolResultContent _) => ContentKind.toolResult);
	}

	// --- Convenience accessors: read the field if this kind has it, else a
	// neutral default. They let callers read common fields without an explicit
	// match and never expose a field on a kind that lacks it.

	string text() const @safe
	{
		return payload.match!((const ref TextContent c) => c.text, _ => "");
	}

	string data() const @safe
	{
		return payload.match!((const ref ImageContent c) => c.data,
				(const ref AudioContent c) => c.data, _ => "");
	}

	string mimeType() const @safe
	{
		return payload.match!((const ref ImageContent c) => c.mimeType,
				(const ref AudioContent c) => c.mimeType,
				(const ref ResourceLink c) => c.mimeType, _ => "");
	}

	string uri() const @safe
	{
		return payload.match!((const ref ResourceLink c) => c.uri, _ => "");
	}

	string name() const @safe
	{
		return payload.match!((const ref ResourceLink c) => c.name,
				(const ref ToolUseContent c) => c.name, _ => "");
	}

	Json resource() const @safe
	{
		return payload.match!((const ref EmbeddedResource c) => c.resource, _ => Json.undefined);
	}

	Nullable!string description() const @safe
	{
		return payload.match!((const ref ResourceLink c) => c.description,
				_ => Nullable!string.init);
	}

	Nullable!string title() const @safe
	{
		return payload.match!((const ref ResourceLink c) => c.title, _ => Nullable!string.init);
	}

	Nullable!long size() const @safe
	{
		return payload.match!((const ref ResourceLink c) => c.size, _ => Nullable!long.init);
	}

	string id() const @safe
	{
		return payload.match!((const ref ToolUseContent c) => c.id, _ => "");
	}

	Json input() const @safe
	{
		return payload.match!((const ref ToolUseContent c) => c.input, _ => Json.undefined);
	}

	string toolUseId() const @safe
	{
		return payload.match!((const ref ToolResultContent c) => c.toolUseId, _ => "");
	}

	Content[] toolContent() const @safe
	{
		return payload.match!((const ref ToolResultContent c) {
			Content[] dup;
			foreach (b; c.content)
				dup ~= b.dupSelf();
			return dup;
		}, _ => Content[].init);
	}

	Json structuredContent() const @safe
	{
		return payload.match!((const ref ToolResultContent c) => c.structuredContent,
				_ => Json.undefined);
	}

	Nullable!bool isError() const @safe
	{
		return payload.match!((const ref ToolResultContent c) => c.isError, _ => Nullable!bool.init);
	}

	/// The shared `annotations` value (any kind may carry it).
	Json annotations() const @safe
	{
		return payload.match!(c => c.annotations);
	}

	/// The shared `_meta` value (any kind may carry it).
	Json meta() const @safe
	{
		return payload.match!(c => c.meta);
	}

	/// A deep copy of this content block.
	Content dupSelf() const @safe
	{
		return payload.match!((const ref ToolResultContent c) {
			ToolResultContent t;
			t.toolUseId = c.toolUseId;
			foreach (b; c.content)
				t.content ~= b.dupSelf();
			t.structuredContent = c.structuredContent;
			t.isError = c.isError;
			t.annotations = c.annotations;
			t.meta = c.meta;
			return Content(t);
		}, (const ref c) => Content(c));
	}

	/// Attach optional annotations (audience/priority/lastModified) to this
	/// content block. Returns a copy so calls can be chained, e.g.
	/// `Content.makeText("hi").withAnnotations(a)`. Valid on every kind.
	Content withAnnotations(Json a) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref x) { x.annotations = a; });
		return c;
	}

	/// Attach an optional `description` to a `resource_link` content block, per
	/// the MCP `ResourceLink` shape (it extends `Resource`). Returns a copy so
	/// calls can be chained. Only valid for the `resourceLink` kind.
	Content withDescription(string d) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref ResourceLink x) { x.description = d; }, (ref _) {
			assert(false, "withDescription is only valid on resource_link content");
		});
		return c;
	}

	/// Attach an optional human-readable `title` to a `resource_link` content
	/// block (`ResourceLink` extends `Resource`/`BaseMetadata`). Returns a copy.
	/// Only valid for the `resourceLink` kind.
	Content withTitle(string t) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref ResourceLink x) { x.title = t; }, (ref _) {
			assert(false, "withTitle is only valid on resource_link content");
		});
		return c;
	}

	/// Attach an optional `size` (bytes) to a `resource_link` content block, per
	/// the MCP `ResourceLink` shape. Returns a copy. Only valid for the
	/// `resourceLink` kind.
	Content withSize(long s) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref ResourceLink x) { x.size = s; }, (ref _) {
			assert(false, "withSize is only valid on resource_link content");
		});
		return c;
	}

	/// Attach an optional `_meta` object to this content block. Per the MCP
	/// schema every content kind may carry `_meta`. Returns a copy.
	Content withContentMeta(Json m) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref x) { x.meta = m; });
		return c;
	}

	/// Mark a `tool_result` content block as an error (sampling). Returns a
	/// copy. Only valid for the `toolResult` kind.
	Content withIsError(bool e) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref ToolResultContent x) { x.isError = e; }, (ref _) {
			assert(false, "withIsError is only valid on tool_result content");
		});
		return c;
	}

	/// Attach an optional `structuredContent` object to a `tool_result` content
	/// block (sampling). Returns a copy. Only valid for the `toolResult` kind.
	Content withStructuredContent(Json sc) const @safe
	{
		Content c = dupSelf();
		c.payload.match!((ref ToolResultContent x) { x.structuredContent = sc; }, (ref _) {
			assert(false, "withStructuredContent is only valid on tool_result content");
		});
		return c;
	}

	static Content makeText(string t) @safe
	{
		return Content(TextContent(t));
	}

	static Content makeImage(string base64, string mime) @safe
	{
		return Content(ImageContent(base64, mime));
	}

	static Content makeAudio(string base64, string mime) @safe
	{
		return Content(AudioContent(base64, mime));
	}

	static Content makeResourceLink(string uri, string name, string mime = "") @safe
	{
		ResourceLink r;
		r.uri = uri;
		r.name = name;
		r.mimeType = mime;
		return Content(r);
	}

	static Content makeEmbeddedText(string uri, string mime, string text) @safe
	{
		Json r = Json.emptyObject;
		r["uri"] = uri;
		if (mime.length)
			r["mimeType"] = mime;
		r["text"] = text;
		return Content(EmbeddedResource(r));
	}

	/// A `tool_use` content block (sampling): the model's request to call a
	/// tool. `id` is the model-assigned call id, `name` the tool name, and
	/// `input` the arguments object. Per `ToolUseContent` in the 2025-11-25 /
	/// draft schema.
	static Content makeToolUse(string id, string name, Json input = Json.emptyObject) @safe
	{
		return Content(ToolUseContent(id, name, input));
	}

	/// A `tool_result` content block (sampling): the result of a tool call,
	/// answering the `tool_use` whose id is `toolUseId`. `content` is the nested
	/// result content blocks. Per `ToolResultContent` in the 2025-11-25 / draft
	/// schema.
	static Content makeToolResult(string toolUseId, Content[] content = null) @safe
	{
		ToolResultContent t;
		t.toolUseId = toolUseId;
		t.content = content;
		return Content(t);
	}

	Json toJson() const @safe
	{
		return payload.match!(c => c.toJson());
	}

	static Content fromJson(Json j) @safe
	{
		const t = ("type" in j) ? j["type"].get!string : "text";
		switch (t)
		{
		case "text":
			TextContent c;
			c.text = ("text" in j) ? j["text"].get!string : "";
			c.parseMeta(j);
			return Content(c);
		case "image":
			ImageContent c;
			c.data = ("data" in j) ? j["data"].get!string : "";
			c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
			c.parseMeta(j);
			return Content(c);
		case "audio":
			AudioContent c;
			c.data = ("data" in j) ? j["data"].get!string : "";
			c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
			c.parseMeta(j);
			return Content(c);
		case "resource_link":
			ResourceLink c;
			c.uri = ("uri" in j) ? j["uri"].get!string : "";
			c.name = ("name" in j) ? j["name"].get!string : "";
			c.mimeType = ("mimeType" in j) ? j["mimeType"].get!string : "";
			if ("title" in j && j["title"].type == Json.Type.string)
				c.title = j["title"].get!string;
			if ("description" in j && j["description"].type == Json.Type.string)
				c.description = j["description"].get!string;
			if ("size" in j && j["size"].type == Json.Type.int_)
				c.size = j["size"].get!long;
			c.parseMeta(j);
			return Content(c);
		case "resource":
			EmbeddedResource c;
			c.resource = ("resource" in j) ? j["resource"] : Json.emptyObject;
			c.parseMeta(j);
			return Content(c);
		case "tool_use":
			ToolUseContent c;
			c.id = ("id" in j && j["id"].type == Json.Type.string) ? j["id"].get!string : "";
			c.name = ("name" in j && j["name"].type == Json.Type.string) ? j["name"].get!string
				: "";
			c.input = ("input" in j) ? j["input"] : Json.emptyObject;
			c.parseMeta(j);
			return Content(c);
		case "tool_result":
			ToolResultContent c;
			c.toolUseId = ("toolUseId" in j && j["toolUseId"].type == Json.Type.string)
				? j["toolUseId"].get!string : "";
			if ("content" in j && j["content"].type == Json.Type.array)
				foreach (i; 0 .. j["content"].length)
					c.content ~= Content.fromJson(j["content"][i]);
			if ("structuredContent" in j)
				c.structuredContent = j["structuredContent"];
			if ("isError" in j && j["isError"].type == Json.Type.bool_)
				c.isError = j["isError"].get!bool;
			c.parseMeta(j);
			return Content(c);
		default:
			TextContent c;
			c.parseMeta(j);
			return Content(c);
		}
	}
}

// `Icon` is defined in mcp.protocol.capabilities (a shared BaseMetadata building
// block used by `Implementation` there and by `Tool`/`Resource`/etc. here) and
// re-exported below so existing `Icon` references in this module resolve.
public import mcp.protocol.capabilities : Icon;

/// Optional annotations attached to resources, resource templates, and content
/// blocks, per the MCP spec's `Annotations` shape. All fields are optional and
/// advisory; a field left unset is omitted from the serialized form.
///
/// - `audience`: who the object is intended for (e.g. `["user"]`,
///   `["assistant"]`).
/// - `priority`: importance from 0.0 (least) to 1.0 (most).
/// - `lastModified`: ISO 8601 timestamp of last modification.
struct Annotations
{
	string[] audience; /// intended audience, e.g. ["user", "assistant"]
	Nullable!double priority; /// importance 0.0..1.0
	Nullable!string lastModified; /// ISO 8601 last-modified timestamp

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (audience.length)
		{
			Json arr = Json.emptyArray;
			foreach (a; audience)
				arr ~= Json(a);
			j["audience"] = arr;
		}
		if (!priority.isNull)
			j["priority"] = priority.get;
		if (!lastModified.isNull)
			j["lastModified"] = lastModified.get;
		return j;
	}

	static Annotations fromJson(Json j) @safe
	{
		Annotations a;
		if ("audience" in j && j["audience"].type == Json.Type.array)
			foreach (i; 0 .. j["audience"].length)
				a.audience ~= j["audience"][i].get!string;
		if ("priority" in j && j["priority"].type == Json.Type.float_)
			a.priority = j["priority"].get!double;
		else if ("priority" in j && j["priority"].type == Json.Type.int_)
			a.priority = cast(double) j["priority"].get!long;
		if ("lastModified" in j && j["lastModified"].type == Json.Type.string)
			a.lastModified = j["lastModified"].get!string;
		return a;
	}

	/// True if no annotation is set (serializes to an empty object).
	bool empty() const @safe
	{
		return audience.length == 0 && priority.isNull && lastModified.isNull;
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

/// Per-tool task-augmented execution descriptor (`Tool.execution`), introduced
/// in MCP 2025-11-25. Lets a tool declare whether it supports the `tasks`
/// augmentation when invoked via `tools/call`.
///
/// `taskSupport` is one of `"forbidden"` (default when absent — the tool does
/// not support task-augmented execution), `"optional"` (the client may request
/// it), or `"required"` (the tool must be invoked as a task). The field is
/// omitted from the serialized form when unset, which the spec treats as
/// `"forbidden"`.
struct ToolExecution
{
	Nullable!string taskSupport; /// "forbidden" (default) | "optional" | "required"

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (!taskSupport.isNull)
			j["taskSupport"] = taskSupport.get;
		return j;
	}

	static ToolExecution fromJson(Json j) @safe
	{
		ToolExecution e;
		if ("taskSupport" in j && j["taskSupport"].type == Json.Type.string)
			e.taskSupport = j["taskSupport"].get!string;
		return e;
	}

	/// True when no field is set (serializes to an empty object).
	bool empty() const @safe
	{
		return taskSupport.isNull;
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
	Nullable!ToolExecution execution; /// optional per-tool task-augmented execution descriptor (2025-11-25)
	Json annotations = Json.undefined; /// optional ToolAnnotations
	Icon[] icons; /// optional icons for display in user interfaces
	Json meta; /// optional descriptor-level `_meta` object

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
		if (!execution.isNull && !execution.get.empty)
			j["execution"] = execution.get.toJson();
		if (annotations.type == Json.Type.object)
			j["annotations"] = annotations;
		if (icons.length)
		{
			Json arr = Json.emptyArray;
			foreach (icon; icons)
				arr ~= icon.toJson();
			j["icons"] = arr;
		}
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		if ("execution" in j && j["execution"].type == Json.Type.object)
			t.execution = ToolExecution.fromJson(j["execution"]);
		if ("annotations" in j)
			t.annotations = j["annotations"];
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				t.icons ~= Icon.fromJson(j["icons"][i]);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			t.meta = j["_meta"];
		return t;
	}

	/// Return a copy of this `Tool` with any fields newer than (or absent from)
	/// the negotiated protocol version stripped, so the wire output stays valid
	/// for the peer's version. `Tool.execution` (`ToolExecution.taskSupport`)
	/// exists ONLY in the 2025-11-25 schema: it was never present before
	/// 2025-11-25 and was dropped again in the draft schema. It is therefore
	/// emitted only when the negotiated version is exactly 2025-11-25, and
	/// omitted for every other version (including `draft`). Mirrors
	/// `Implementation.forVersion`.
	Tool forVersion(ProtocolVersion v) const @safe
	{
		Tool projected;
		projected.name = name;
		projected.description = description;
		projected.inputSchema = inputSchema;
		projected.meta = meta;
		// `Tool.annotations` (ToolAnnotations) was introduced by 2025-03-26; it
		// is absent from the 2024-11-05 'Tool' type (name/description/inputSchema
		// only). Strip it for any version older than 2025-03-26.
		if (v >= ProtocolVersion.v2025_03_26)
			projected.annotations = annotations;
		// `BaseMetadata.title` and `Tool.outputSchema` were introduced by
		// 2025-06-18; they are absent from 2025-03-26 and 2024-11-05.
		if (v >= ProtocolVersion.v2025_06_18)
		{
			projected.title = title;
			projected.outputSchema = outputSchema;
		}
		// `Tool.icons` was introduced by 2025-11-25; absent from every earlier
		// version (and present in draft, which is >= 2025-11-25).
		if (v >= ProtocolVersion.v2025_11_25)
		{
			foreach (icon; icons)
			{
				Icon copy;
				copy.src = icon.src;
				copy.mimeType = icon.mimeType;
				copy.sizes = icon.sizes.dup;
				copy.theme = icon.theme;
				projected.icons ~= copy;
			}
		}
		// `Tool.execution` is a 2025-11-25-only field: emit it solely when the
		// negotiated version is exactly 2025-11-25 (absent pre-2025-11-25,
		// dropped from draft).
		if (v == ProtocolVersion.v2025_11_25)
			projected.execution = execution;
		return projected;
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
	Json meta; /// optional result-level `_meta` object
	/// Multi Round-Trip Requests (MRTR / SEP-2322): when the draft server needs
	/// more input to complete the call, it answers `tools/call` with an
	/// `InputRequiredResult` instead of a `CallToolResult` — a set of
	/// `InputRequest`s the client must satisfy (via its sampling / elicitation /
	/// roots handlers) and resubmit. When non-empty, `content` is meaningless and
	/// the caller should gather input and retry the request with matching
	/// `inputResponses`. See `isInputRequired`.
	InputRequest[] inputRequests;
	/// MRTR (SEP-2322): the opaque, server-owned `requestState` carried on an
	/// `InputRequiredResult`. The client MUST echo it back verbatim (and MUST
	/// NOT inspect it) when retrying. Empty when the server sent none.
	string requestState;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		// An `InputRequiredResult` is a distinct result shape (only `inputRequests`),
		// not a `CallToolResult` with content — serialise it as such.
		if (inputRequests.length)
		{
			// SEP-2322: `inputRequests` is an `InputRequests` object (map keyed
			// by the server-assigned id with `{ method, params }` values), not
			// an array.
			j["inputRequests"] = inputRequestsToJson(inputRequests);
			// SEP-2322: `requestState` is an optional top-level field on the
			// result; omit it when empty.
			if (requestState.length)
				j["requestState"] = requestState;
			return j;
		}
		Json arr = Json.emptyArray;
		foreach (c; content)
			arr ~= c.toJson();
		j["content"] = arr;
		if (isError)
			j["isError"] = true;
		if (structuredContent.type != Json.Type.undefined)
			j["structuredContent"] = structuredContent;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		// MRTR: detect an `InputRequiredResult` (the server asks for more input).
		// `inputRequests` is a map keyed by the server-assigned id.
		if ("inputRequests" in j && j["inputRequests"].type == Json.Type.object)
			r.inputRequests = inputRequestsFromJson(j["inputRequests"]);
		// SEP-2322: capture the opaque requestState so the client can echo it
		// back verbatim on the retry.
		if ("requestState" in j && j["requestState"].type == Json.Type.string)
			r.requestState = j["requestState"].get!string;
		return r;
	}

	/// Whether this result is an MRTR `InputRequiredResult`: the server needs the
	/// client to gather input (`inputRequests`) and retry the original `tools/call`
	/// with matching `inputResponses`, rather than a completed tool result.
	bool isInputRequired() const @safe nothrow
	{
		return inputRequests.length > 0;
	}

	/// Fluent setter for the result-level `_meta` object, e.g.
	/// `CallToolResult([Content.makeText("ok")]).withMeta(m)`.
	CallToolResult withMeta(Json m) @safe
	{
		meta = m;
		return this;
	}

	/// Return a copy of this `CallToolResult` with any fields newer than the
	/// negotiated protocol version stripped, so the wire output stays valid for
	/// the peer's version. `structuredContent` was introduced by 2025-06-18: the
	/// 2025-03-26 and 2024-11-05 tool-result shapes are `content[]` + `isError`
	/// only, with no `structuredContent`. It is therefore emitted only when the
	/// negotiated version is >= 2025-06-18 and dropped for every earlier version.
	/// The `content` text mirror (which the reflection layer populates alongside
	/// `structuredContent`) is valid in all versions and is preserved. Mirrors
	/// `Tool.forVersion`.
	CallToolResult forVersion(ProtocolVersion v) const @safe
	{
		CallToolResult projected;
		projected.content = content.dup;
		projected.isError = isError;
		projected.meta = meta;
		projected.inputRequests = inputRequests.dup;
		projected.requestState = requestState;
		// `structuredContent` is a 2025-06-18+ field: absent from 2025-03-26 and
		// 2024-11-05, so omit it for those versions.
		if (v >= ProtocolVersion.v2025_06_18)
			projected.structuredContent = structuredContent;
		return projected;
	}
}

/// Result of `tools/list` (paginated).
struct ListToolsResult
{
	Tool[] tools;
	Nullable!string nextCursor;
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`). Round-trips
	/// symmetrically: `toJson` emits it when set and `fromJson` parses it. The
	/// server sets this (draft-gated) so pre-draft wire output is unchanged.
	Nullable!CacheHint cache;
	/// Optional result-level `_meta` object. Reserved by MCP on every `Result`
	/// (the base interface all paginated list results extend), so it round-trips
	/// on every protocol version: `toJson` emits it only when set and `fromJson`
	/// parses it. Unset by default, so pre-existing wire output is unchanged.
	Json meta;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (t; tools)
			arr ~= t.toJson();
		j["tools"] = arr;
		if (!nextCursor.isNull)
			j["nextCursor"] = nextCursor.get;
		if (!cache.isNull)
			j = withCache(j, cache.get);
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		r.cache = parseCacheHint(j);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

unittest  // ListToolsResult: a set cache hint round-trips through toJson/fromJson
{
	import mcp.protocol.draft : CacheScope;

	ListToolsResult r;
	r.cache = CacheHint(5000, CacheScope.private_);
	auto back = ListToolsResult.fromJson(r.toJson());
	assert(!back.cache.isNull);
	assert(back.cache.get.ttlMs == 5000);
	assert(back.cache.get.cacheScope == CacheScope.private_);
}

unittest  // ListToolsResult: an unset cache hint emits no ttlMs/cacheScope
{
	ListToolsResult r;
	auto j = r.toJson();
	assert("ttlMs" !in j);
	assert("cacheScope" !in j);
	assert(ListToolsResult.fromJson(j).cache.isNull);
}

unittest  // ListToolsResult: result-level `_meta` round-trips through toJson/fromJson
{
	ListToolsResult r;
	Json m = Json.emptyObject;
	m["progressToken"] = "abc";
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["progressToken"].get!string == "abc");
	auto back = ListToolsResult.fromJson(j);
	assert(back.meta.type == Json.Type.object);
	assert(back.meta["progressToken"].get!string == "abc");
}

unittest  // ListToolsResult: an unset `_meta` emits no `_meta` key
{
	ListToolsResult r;
	auto j = r.toJson();
	assert("_meta" !in j);
}

unittest  // ListResourcesResult: result-level `_meta` round-trips through toJson/fromJson
{
	ListResourcesResult r;
	Json m = Json.emptyObject;
	m["k"] = "v";
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["k"].get!string == "v");
	auto back = ListResourcesResult.fromJson(j);
	assert(back.meta.type == Json.Type.object);
	assert(back.meta["k"].get!string == "v");
}

unittest  // ListResourcesResult: an unset `_meta` emits no `_meta` key
{
	ListResourcesResult r;
	assert("_meta" !in r.toJson());
}

unittest  // ListResourceTemplatesResult: result-level `_meta` round-trips through toJson/fromJson
{
	ListResourceTemplatesResult r;
	Json m = Json.emptyObject;
	m["k"] = "v";
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["k"].get!string == "v");
	auto back = ListResourceTemplatesResult.fromJson(j);
	assert(back.meta.type == Json.Type.object);
	assert(back.meta["k"].get!string == "v");
}

unittest  // ListResourceTemplatesResult: an unset `_meta` emits no `_meta` key
{
	ListResourceTemplatesResult r;
	assert("_meta" !in r.toJson());
}

unittest  // ListPromptsResult: result-level `_meta` round-trips through toJson/fromJson
{
	ListPromptsResult r;
	Json m = Json.emptyObject;
	m["k"] = "v";
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["k"].get!string == "v");
	auto back = ListPromptsResult.fromJson(j);
	assert(back.meta.type == Json.Type.object);
	assert(back.meta["k"].get!string == "v");
}

unittest  // ListPromptsResult: an unset `_meta` emits no `_meta` key
{
	ListPromptsResult r;
	assert("_meta" !in r.toJson());
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

unittest  // resource link omits description/title/size when unset
{
	auto c = Content.makeResourceLink("file:///a", "a");
	auto j = c.toJson();
	assert("description" !in j);
	assert("title" !in j);
	assert("size" !in j);
}

unittest  // resource link emits description (matches spec tools example)
{
	auto c = Content.makeResourceLink("file:///project/src/main.rs", "main.rs",
			"text/x-rust").withDescription("Primary application entry point");
	auto j = c.toJson();
	assert(j["type"].get!string == "resource_link");
	assert(j["uri"].get!string == "file:///project/src/main.rs");
	assert(j["name"].get!string == "main.rs");
	assert(j["mimeType"].get!string == "text/x-rust");
	assert(j["description"].get!string == "Primary application entry point");
}

unittest  // resource link emits title and size
{
	auto c = Content.makeResourceLink("file:///a", "a").withTitle("Display A").withSize(4096L);
	auto j = c.toJson();
	assert(j["title"].get!string == "Display A");
	assert(j["size"].get!long == 4096);
}

unittest  // resource link round-trips description/title/size through fromJson
{
	auto c = Content.makeResourceLink("file:///a", "a", "text/plain")
		.withDescription("d").withTitle("t").withSize(7L);
	auto back = Content.fromJson(c.toJson());
	assert(back.kind == ContentKind.resourceLink);
	assert(back.uri == "file:///a");
	assert(back.name == "a");
	assert(back.mimeType == "text/plain");
	assert(!back.description.isNull && back.description.get == "d");
	assert(!back.title.isNull && back.title.get == "t");
	assert(!back.size.isNull && back.size.get == 7);
}

unittest  // resource link emits and parses _meta
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto c = Content.makeResourceLink("file:///a", "a").withContentMeta(m);
	auto j = c.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = Content.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // text content emits and parses _meta (spec: TextContent._meta)
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto c = Content.makeText("hello").withContentMeta(m);
	auto j = c.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = Content.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // image content emits and parses _meta (spec: ImageContent._meta)
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto c = Content.makeImage("YWJj", "image/png").withContentMeta(m);
	auto j = c.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = Content.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // audio content emits and parses _meta (spec: AudioContent._meta)
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto c = Content.makeAudio("YWJj", "audio/wav").withContentMeta(m);
	auto j = c.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = Content.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // embedded resource emits and parses _meta (spec: EmbeddedResource._meta)
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto c = Content.makeEmbeddedText("test://x", "text/plain", "hi").withContentMeta(m);
	auto j = c.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = Content.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // content omits _meta when none is set
{
	auto j = Content.makeText("hello").toJson();
	assert("_meta" !in j);
}

unittest  // withDescription/withTitle/withSize reject non-resourceLink kinds
{
	// They are valid only on resource_link content. Applying them to another
	// kind is a programming error (no silent no-op), so it must fail loudly.
	import core.exception : AssertError;

	static bool throwsAssert(scope void delegate() @safe dg) @trusted
	{
		try
			dg();
		catch (AssertError)
			return true;
		return false;
	}

	assert(throwsAssert(() {
			cast(void) Content.makeText("hi").withDescription("x");
		}));
	assert(throwsAssert(() {
			cast(void) Content.makeImage("d", "image/png").withTitle("t");
		}));
	assert(throwsAssert(() {
			cast(void) Content.makeAudio("d", "audio/wav").withSize(5L);
		}));
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

unittest  // tool_use content carries id/name/input (ToolUseContent shape)
{
	Json input = Json.emptyObject;
	input["location"] = "Paris";
	auto c = Content.makeToolUse("call_1", "get_weather", input);
	auto j = c.toJson();
	assert(j["type"].get!string == "tool_use");
	assert(j["id"].get!string == "call_1");
	assert(j["name"].get!string == "get_weather");
	assert(j["input"]["location"].get!string == "Paris");
}

unittest  // tool_use content round-trips id/name/input through fromJson
{
	Json input = Json.emptyObject;
	input["q"] = 42;
	auto back = Content.fromJson(Content.makeToolUse("c1", "calc", input).toJson());
	assert(back.kind == ContentKind.toolUse);
	assert(back.id == "c1");
	assert(back.name == "calc");
	assert(back.input["q"].get!long == 42);
}

unittest  // tool_use input defaults to an empty object when omitted
{
	auto c = Content.makeToolUse("c", "noargs");
	auto j = c.toJson();
	assert(j["input"].type == Json.Type.object);
	assert(j["input"].length == 0);
}

unittest  // tool_result content carries toolUseId and nested content array
{
	auto c = Content.makeToolResult("call_1", [
		Content.makeText("18C and sunny")
	]);
	auto j = c.toJson();
	assert(j["type"].get!string == "tool_result");
	assert(j["toolUseId"].get!string == "call_1");
	assert(j["content"].type == Json.Type.array);
	assert(j["content"][0]["type"].get!string == "text");
	assert(j["content"][0]["text"].get!string == "18C and sunny");
	assert("isError" !in j);
	assert("structuredContent" !in j);
}

unittest  // tool_result content round-trips nested content/isError/structured
{
	Json sc = Json.emptyObject;
	sc["code"] = 500;
	auto c = Content.makeToolResult("call_2", [Content.makeText("boom")])
		.withIsError(true).withStructuredContent(sc);
	auto back = Content.fromJson(c.toJson());
	assert(back.kind == ContentKind.toolResult);
	assert(back.toolUseId == "call_2");
	assert(back.toolContent.length == 1 && back.toolContent[0].text == "boom");
	assert(!back.isError.isNull && back.isError.get == true);
	assert(back.structuredContent["code"].get!long == 500);
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

unittest  // Content is a SumType over per-kind structs (issue #305)
{
	import std.sumtype : SumType;

	static assert(is(Content.Payload == SumType!(TextContent, ImageContent,
			AudioContent, ResourceLink, EmbeddedResource, ToolUseContent, ToolResultContent)));
}

unittest  // per-kind structs serialize the spec-correct wire shape directly
{
	assert(TextContent("hi").toJson()["type"].get!string == "text");
	assert(ImageContent("d", "image/png").toJson()["type"].get!string == "image");
	assert(AudioContent("d", "audio/wav").toJson()["type"].get!string == "audio");
}

unittest  // a Content can be constructed directly from a per-kind struct
{
	auto c = Content(ResourceLink("file:///a", "a"));
	assert(c.kind == ContentKind.resourceLink);
	assert(c.uri == "file:///a" && c.name == "a");
}

unittest  // withDescription/withTitle/withSize succeed on resource_link content
{
	auto c = Content.makeResourceLink("file:///a", "a").withDescription("d")
		.withTitle("t").withSize(9L);
	auto j = c.toJson();
	assert(j["description"].get!string == "d");
	assert(j["title"].get!string == "t");
	assert(j["size"].get!long == 9);
}

unittest  // tool_result nested content deep-copies through dupSelf (no aliasing)
{
	auto inner = Content.makeText("inner");
	auto tr = Content.makeToolResult("call_1", [inner]);
	auto copy = tr.dupSelf();
	assert(copy.kind == ContentKind.toolResult);
	assert(copy.toolContent.length == 1);
	assert(copy.toolContent[0].text == "inner");
}

unittest  // text content round-trips through the SumType-backed Content
{
	auto back = Content.fromJson(Content.makeText("hello").toJson());
	assert(back.kind == ContentKind.text && back.text == "hello");
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

unittest  // Tool emits execution.taskSupport when set (2025-11-25 ToolExecution)
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("optional"));
	auto j = t.toJson();
	assert(j["execution"].type == Json.Type.object);
	assert(j["execution"]["taskSupport"].get!string == "optional");
}

unittest  // Tool omits execution when taskSupport unset (forbidden default)
{
	Tool t = {name: "plain"};
	auto j = t.toJson();
	assert("execution" !in j);
}

unittest  // Tool execution round-trips taskSupport through fromJson
{
	Tool t = {name: "task", execution: ToolExecution(nullable("required"))};
	auto back = Tool.fromJson(t.toJson());
	assert(!back.execution.isNull);
	assert(back.execution.get.taskSupport.get == "required");
}

unittest  // Tool.fromJson leaves execution null when absent
{
	Json j = Json.emptyObject;
	j["name"] = "noexec";
	auto t = Tool.fromJson(j);
	assert(t.execution.isNull);
}

unittest  // ToolExecution serializes only when taskSupport present
{
	ToolExecution e;
	assert("taskSupport" !in e.toJson());
	e.taskSupport = "forbidden";
	assert(e.toJson()["taskSupport"].get!string == "forbidden");
}

unittest  // Tool.forVersion keeps execution on 2025-11-25 (the only version with it)
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("optional"));
	auto j = t.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("execution" in j);
	assert(j["execution"]["taskSupport"].get!string == "optional");
}

unittest  // Tool.forVersion strips execution on draft (field was dropped from draft schema)
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("optional"));
	auto j = t.forVersion(ProtocolVersion.draft).toJson();
	assert("execution" !in j);
}

unittest  // Tool.forVersion strips execution on 2025-06-18 (field never existed pre-2025-11-25)
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("required"));
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("execution" !in j);
}

unittest  // Tool.forVersion strips execution on 2024-11-05
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("required"));
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("execution" !in j);
}

unittest  // Tool.forVersion leaves the original Tool unmodified (returns a projected copy)
{
	Tool t = {name: "longjob"};
	t.execution = ToolExecution(nullable("optional"));
	cast(void) t.forVersion(ProtocolVersion.draft);
	assert(!t.execution.isNull);
	assert(t.execution.get.taskSupport.get == "optional");
}

unittest  // Tool.forVersion preserves non-version-gated fields (name/description) intact
{
	Tool t = {name: "longjob", description: nullable("does a long job")};
	t.execution = ToolExecution(nullable("optional"));
	auto pj = t.forVersion(ProtocolVersion.v2025_06_18);
	assert(pj.name == "longjob");
	assert(pj.description.get == "does a long job");
	assert(pj.execution.isNull);
}

unittest  // Tool.forVersion strips title for 2024-11-05 (BaseMetadata.title introduced 2025-06-18)
{
	Tool t = {name: "t", title: nullable("Nice Title")};
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("title" !in j);
}

unittest  // Tool.forVersion strips title for 2025-03-26 (BaseMetadata.title introduced 2025-06-18)
{
	Tool t = {name: "t", title: nullable("Nice Title")};
	auto j = t.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("title" !in j);
}

unittest  // Tool.forVersion keeps title for 2025-06-18 (title introduced here)
{
	Tool t = {name: "t", title: nullable("Nice Title")};
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert(j["title"].get!string == "Nice Title");
}

unittest  // Tool.forVersion strips outputSchema for 2024-11-05 (introduced 2025-06-18)
{
	Tool t = {name: "t"};
	t.outputSchema = emptyObjectSchema();
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("outputSchema" !in j);
}

unittest  // Tool.forVersion strips outputSchema for 2025-03-26 (introduced 2025-06-18)
{
	Tool t = {name: "t"};
	t.outputSchema = emptyObjectSchema();
	auto j = t.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("outputSchema" !in j);
}

unittest  // Tool.forVersion keeps outputSchema for 2025-06-18 (introduced here)
{
	Tool t = {name: "t"};
	t.outputSchema = emptyObjectSchema();
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("outputSchema" in j);
}

unittest  // Tool.forVersion strips icons for 2025-06-18 (Tool.icons introduced 2025-11-25)
{
	Tool t = {name: "t"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("icons" !in j);
}

unittest  // Tool.forVersion strips icons for 2025-03-26 (Tool.icons introduced 2025-11-25)
{
	Tool t = {name: "t"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("icons" !in j);
}

unittest  // Tool.forVersion keeps icons for 2025-11-25 (Tool.icons introduced here)
{
	Tool t = {name: "t"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("icons" in j);
	assert(j["icons"].length == 1);
}

unittest  // Tool.forVersion strips annotations for 2024-11-05 (ToolAnnotations introduced 2025-03-26)
{
	Tool t = {name: "t"};
	t.annotations = Json.emptyObject;
	t.annotations["readOnlyHint"] = true;
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("annotations" !in j);
}

unittest  // Tool.forVersion keeps annotations for 2025-03-26 (ToolAnnotations introduced here)
{
	Tool t = {name: "t"};
	t.annotations = Json.emptyObject;
	t.annotations["readOnlyHint"] = true;
	auto j = t.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("annotations" in j);
	assert(j["annotations"]["readOnlyHint"].get!bool);
}

unittest  // Tool.forVersion keeps annotations for 2025-11-25 (still present in later versions)
{
	Tool t = {name: "t"};
	t.annotations = Json.emptyObject;
	t.annotations["destructiveHint"] = true;
	auto j = t.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("annotations" in j);
	assert(j["annotations"]["destructiveHint"].get!bool);
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

unittest  // CallToolResult emits result-level _meta when set, omits when unset
{
	CallToolResult r;
	r.content = [Content.makeText("ok")];
	assert("_meta" !in r.toJson());

	Json m = Json.emptyObject;
	m["io.modelcontextprotocol/cacheHit"] = true;
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["io.modelcontextprotocol/cacheHit"].get!bool);
	auto back = CallToolResult.fromJson(j);
	assert(back.meta["io.modelcontextprotocol/cacheHit"].get!bool);
}

unittest  // Tool emits descriptor-level _meta when set
{
	Tool t = {name: "withmeta"};
	Json m = Json.emptyObject;
	m["x.example/hint"] = "v";
	t.meta = m;
	auto j = t.toJson();
	assert(j["_meta"]["x.example/hint"].get!string == "v");
	auto back = Tool.fromJson(j);
	assert(back.meta["x.example/hint"].get!string == "v");
}

unittest  // Tool omits _meta when unset
{
	Tool t = {name: "nometa"};
	assert("_meta" !in t.toJson());
}

unittest  // Resource round-trips _meta
{
	Resource r = {uri: "test://x", name: "x"};
	Json m = Json.emptyObject;
	m["x.example/tag"] = 7;
	r.meta = m;
	auto back = Resource.fromJson(r.toJson());
	assert(back.meta["x.example/tag"].get!long == 7);
}

unittest  // Resource.forVersion strips icons for 2025-06-18 (Resource.icons introduced 2025-11-25)
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons ~= Icon("https://example.com/i.png");
	auto j = r.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("icons" !in j);
}

unittest  // Resource.forVersion strips icons for 2025-03-26
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons ~= Icon("https://example.com/i.png");
	auto j = r.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("icons" !in j);
}

unittest  // Resource.forVersion strips icons for 2024-11-05
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons ~= Icon("https://example.com/i.png");
	auto j = r.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("icons" !in j);
}

unittest  // Resource.forVersion keeps icons for 2025-11-25 (introduced here)
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons ~= Icon("https://example.com/i.png");
	auto j = r.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("icons" in j && j["icons"].length == 1);
}

unittest  // Resource.forVersion keeps icons for draft (>= 2025-11-25)
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons ~= Icon("https://example.com/i.png");
	auto j = r.forVersion(ProtocolVersion.draft).toJson();
	assert("icons" in j && j["icons"].length == 1);
}

unittest  // Resource.forVersion strips title for 2025-03-26 (BaseMetadata.title introduced 2025-06-18)
{
	Resource r = {uri: "test://x", name: "x"};
	r.title = "Display X";
	auto j = r.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("title" !in j);
}

unittest  // Resource.forVersion strips title for 2024-11-05
{
	Resource r = {uri: "test://x", name: "x"};
	r.title = "Display X";
	auto j = r.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("title" !in j);
}

unittest  // Resource.forVersion keeps title for 2025-06-18 (introduced here)
{
	Resource r = {uri: "test://x", name: "x"};
	r.title = "Display X";
	auto j = r.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert(j["title"].get!string == "Display X");
}

unittest  // Resource.forVersion preserves non-gated fields (uri/name/description/mimeType/size)
{
	Resource r = {uri: "test://x", name: "x"};
	r.description = "desc";
	r.mimeType = "text/plain";
	r.size = 42;
	auto j = r.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert(j["uri"].get!string == "test://x");
	assert(j["name"].get!string == "x");
	assert(j["description"].get!string == "desc");
	assert(j["mimeType"].get!string == "text/plain");
	assert(j["size"].get!long == 42);
}

unittest  // Resource.forVersion leaves the original Resource unmodified (returns a projected copy)
{
	Resource r = {uri: "test://x", name: "x"};
	r.title = "Display X";
	r.icons ~= Icon("https://example.com/i.png");
	cast(void) r.forVersion(ProtocolVersion.v2024_11_05);
	assert(!r.title.isNull && r.icons.length == 1);
}

unittest  // ResourceTemplate.forVersion strips icons for 2025-06-18 (introduced 2025-11-25)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("icons" !in j);
}

unittest  // ResourceTemplate.forVersion strips icons for 2024-11-05
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("icons" !in j);
}

unittest  // ResourceTemplate.forVersion keeps icons for 2025-11-25 (introduced here)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("icons" in j && j["icons"].length == 1);
}

unittest  // ResourceTemplate.forVersion keeps icons for draft (>= 2025-11-25)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.icons ~= Icon("https://example.com/i.png");
	auto j = t.forVersion(ProtocolVersion.draft).toJson();
	assert("icons" in j && j["icons"].length == 1);
}

unittest  // ResourceTemplate.forVersion strips title for 2025-03-26 (title introduced 2025-06-18)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.title = "Display X";
	auto j = t.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("title" !in j);
}

unittest  // ResourceTemplate.forVersion strips title for 2024-11-05
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.title = "Display X";
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("title" !in j);
}

unittest  // ResourceTemplate.forVersion keeps title for 2025-06-18 (introduced here)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.title = "Display X";
	auto j = t.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert(j["title"].get!string == "Display X");
}

unittest  // ResourceTemplate.forVersion preserves non-gated fields (uriTemplate/name/description/mimeType)
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "x"};
	t.description = "desc";
	t.mimeType = "text/plain";
	auto j = t.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert(j["uriTemplate"].get!string == "test://{id}");
	assert(j["name"].get!string == "x");
	assert(j["description"].get!string == "desc");
	assert(j["mimeType"].get!string == "text/plain");
}

unittest  // Prompt round-trips _meta
{
	Prompt p = {name: "p"};
	Json m = Json.emptyObject;
	m["x.example/group"] = "demo";
	p.meta = m;
	auto back = Prompt.fromJson(p.toJson());
	assert(back.meta["x.example/group"].get!string == "demo");
}

unittest  // ReadResourceResult round-trips _meta
{
	ReadResourceResult r;
	r.contents = [ResourceContents.makeText("file://x", "text/plain", "hi")];
	assert("_meta" !in r.toJson());
	Json m = Json.emptyObject;
	m["x.example/etag"] = "abc";
	r.meta = m;
	auto back = ReadResourceResult.fromJson(r.toJson());
	assert(back.meta["x.example/etag"].get!string == "abc");
}

unittest  // GetPromptResult round-trips _meta
{
	GetPromptResult r;
	r.messages = [PromptMessage("user", Content.makeText("hi"))];
	Json m = Json.emptyObject;
	m["x.example/v"] = 1;
	r.meta = m;
	auto back = GetPromptResult.fromJson(r.toJson());
	assert(back.meta["x.example/v"].get!long == 1);
}

unittest  // CompleteResult round-trips _meta
{
	CompleteResult r;
	r.values = ["a", "b"];
	Json m = Json.emptyObject;
	m["x.example/src"] = "cache";
	r.meta = m;
	auto j = r.toJson();
	assert(j["_meta"]["x.example/src"].get!string == "cache");
	auto back = CompleteResult.fromJson(j);
	assert(back.meta["x.example/src"].get!string == "cache");
}

unittest  // CallToolResult.withMeta is a fluent setter
{
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	auto r = CallToolResult([Content.makeText("ok")]).withMeta(m);
	assert(r.meta["x.example/k"].get!string == "v");
}

unittest  // CallToolResult.forVersion drops structuredContent on 2024-11-05 (introduced 2025-06-18)
{
	CallToolResult r;
	r.content = [Content.makeText("ok")];
	Json sc = Json.emptyObject;
	sc["result"] = 42;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("structuredContent" !in j);
	assert(j["content"].length == 1);
}

unittest  // CallToolResult.forVersion drops structuredContent on 2025-03-26 (introduced 2025-06-18)
{
	CallToolResult r;
	r.content = [Content.makeText("ok")];
	Json sc = Json.emptyObject;
	sc["result"] = 42;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("structuredContent" !in j);
}

unittest  // CallToolResult.forVersion keeps structuredContent on 2025-06-18 (introduced here)
{
	CallToolResult r;
	r.content = [Content.makeText("ok")];
	Json sc = Json.emptyObject;
	sc["result"] = 42;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("structuredContent" in j);
	assert(j["structuredContent"]["result"].get!int == 42);
}

unittest  // CallToolResult.forVersion keeps structuredContent on 2025-11-25
{
	CallToolResult r;
	Json sc = Json.emptyObject;
	sc["result"] = 7;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert("structuredContent" in j);
}

unittest  // CallToolResult.forVersion keeps structuredContent on draft
{
	CallToolResult r;
	Json sc = Json.emptyObject;
	sc["result"] = 7;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.draft).toJson();
	assert("structuredContent" in j);
}

unittest  // CallToolResult.forVersion preserves content/isError/_meta on the old version
{
	CallToolResult r;
	r.content = [Content.makeText("boom")];
	r.isError = true;
	Json m = Json.emptyObject;
	m["x.example/k"] = "v";
	r.meta = m;
	Json sc = Json.emptyObject;
	sc["result"] = 1;
	r.structuredContent = sc;
	auto j = r.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert(j["content"].length == 1);
	assert(j["isError"].get!bool == true);
	assert(j["_meta"]["x.example/k"].get!string == "v");
	assert("structuredContent" !in j);
}

unittest  // CallToolResult.forVersion leaves the original unmodified (returns a projected copy)
{
	CallToolResult r;
	Json sc = Json.emptyObject;
	sc["result"] = 1;
	r.structuredContent = sc;
	r.forVersion(ProtocolVersion.v2024_11_05);
	assert(r.structuredContent.type == Json.Type.object);
}

unittest  // CallToolResult.fromJson detects an MRTR InputRequiredResult
{
	// SEP-2322: a real draft server emits `inputRequests` as a map keyed by the
	// server-assigned id, with `{ method, params }` request-object values.
	Json reqObj = Json.emptyObject;
	reqObj["method"] = "elicitation/create";
	reqObj["params"] = Json(["message": Json("When?")]);
	Json reqs = Json.emptyObject;
	reqs["date"] = reqObj;
	Json j = Json.emptyObject;
	j["inputRequests"] = reqs;

	auto r = CallToolResult.fromJson(j);
	assert(r.isInputRequired());
	assert(r.inputRequests.length == 1);
	assert(r.inputRequests[0].id == "date");
	assert(r.inputRequests[0].type == "elicitation");
	assert(r.inputRequests[0].params["message"].get!string == "When?");
}

unittest  // CallToolResult.toJson serializes inputRequests as a map keyed by id
{
	CallToolResult r;
	r.inputRequests = [
		InputRequest("date", "elicitation", Json(["message": Json("When?")]))
	];
	auto j = r.toJson();
	assert(j["inputRequests"].type == Json.Type.object);
	assert("date" in j["inputRequests"]);
	assert(j["inputRequests"]["date"]["method"].get!string == "elicitation/create");
	assert("content" !in j);
	// Round-trips back to the same internal request.
	auto back = CallToolResult.fromJson(j);
	assert(back.isInputRequired());
	assert(back.inputRequests[0].id == "date");
	assert(back.inputRequests[0].type == "elicitation");
}

unittest  // a completed CallToolResult is not an InputRequiredResult
{
	CallToolResult r;
	r.content = [Content.makeText("done")];
	auto back = CallToolResult.fromJson(r.toJson());
	assert(!back.isInputRequired());
	assert(back.inputRequests.length == 0);
	assert(back.content[0].text == "done");
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
	Annotations annotations; /// optional audience/priority/lastModified annotations
	Nullable!long size; /// optional size in bytes
	Icon[] icons; /// optional icons for display in user interfaces
	Json meta; /// optional descriptor-level `_meta` object

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
		if (!annotations.empty)
			j["annotations"] = annotations.toJson();
		if (!size.isNull)
			j["size"] = size.get;
		if (icons.length)
		{
			Json arr = Json.emptyArray;
			foreach (icon; icons)
				arr ~= icon.toJson();
			j["icons"] = arr;
		}
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		if ("annotations" in j && j["annotations"].type == Json.Type.object)
			r.annotations = Annotations.fromJson(j["annotations"]);
		if ("size" in j && j["size"].type == Json.Type.int_)
			r.size = j["size"].get!long;
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				r.icons ~= Icon.fromJson(j["icons"][i]);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}

	/// Return a copy of this `Resource` with any fields newer than the
	/// negotiated protocol version stripped, so the wire output stays valid
	/// for the peer's version. `BaseMetadata.title` was introduced by
	/// 2025-06-18 (absent from 2025-03-26 and 2024-11-05); `Resource.icons`
	/// was introduced by 2025-11-25 (absent from every earlier version,
	/// present in draft which is >= 2025-11-25). `uri`/`name`/`description`/
	/// `mimeType`/`annotations`/`size`/`_meta` all existed in 2024-11-05 and
	/// are preserved unchanged. Mirrors `Tool.forVersion` / `Prompt.forVersion`.
	Resource forVersion(ProtocolVersion v) const @safe
	{
		Resource projected;
		projected.uri = uri;
		projected.name = name;
		projected.description = description;
		projected.mimeType = mimeType;
		projected.annotations.audience = annotations.audience.dup;
		projected.annotations.priority = annotations.priority;
		projected.annotations.lastModified = annotations.lastModified;
		projected.size = size;
		projected.meta = meta;
		// `BaseMetadata.title` was introduced by 2025-06-18.
		if (v >= ProtocolVersion.v2025_06_18)
			projected.title = title;
		// `Resource.icons` was introduced by 2025-11-25.
		if (v >= ProtocolVersion.v2025_11_25)
		{
			foreach (icon; icons)
			{
				Icon copy;
				copy.src = icon.src;
				copy.mimeType = icon.mimeType;
				copy.sizes = icon.sizes.dup;
				copy.theme = icon.theme;
				projected.icons ~= copy;
			}
		}
		return projected;
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
	Annotations annotations; /// optional audience/priority/lastModified annotations
	Icon[] icons; /// optional icons for display in user interfaces
	Json meta; /// optional descriptor-level `_meta` object

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
		if (!annotations.empty)
			j["annotations"] = annotations.toJson();
		if (icons.length)
		{
			Json arr = Json.emptyArray;
			foreach (icon; icons)
				arr ~= icon.toJson();
			j["icons"] = arr;
		}
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static ResourceTemplate fromJson(Json j) @safe
	{
		ResourceTemplate t;
		t.uriTemplate = ("uriTemplate" in j) ? j["uriTemplate"].get!string : "";
		t.name = ("name" in j) ? j["name"].get!string : "";
		if ("title" in j && j["title"].type == Json.Type.string)
			t.title = j["title"].get!string;
		if ("description" in j && j["description"].type == Json.Type.string)
			t.description = j["description"].get!string;
		if ("mimeType" in j && j["mimeType"].type == Json.Type.string)
			t.mimeType = j["mimeType"].get!string;
		if ("annotations" in j && j["annotations"].type == Json.Type.object)
			t.annotations = Annotations.fromJson(j["annotations"]);
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				t.icons ~= Icon.fromJson(j["icons"][i]);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			t.meta = j["_meta"];
		return t;
	}

	/// Return a copy of this `ResourceTemplate` with any fields newer than the
	/// negotiated protocol version stripped. `BaseMetadata.title` was
	/// introduced by 2025-06-18; `ResourceTemplate.icons` was introduced by
	/// 2025-11-25 (present in draft which is >= 2025-11-25).
	/// `uriTemplate`/`name`/`description`/`mimeType`/`annotations`/`_meta` all
	/// existed in 2024-11-05 and are preserved unchanged. Mirrors
	/// `Tool.forVersion` / `Prompt.forVersion`.
	ResourceTemplate forVersion(ProtocolVersion v) const @safe
	{
		ResourceTemplate projected;
		projected.uriTemplate = uriTemplate;
		projected.name = name;
		projected.description = description;
		projected.mimeType = mimeType;
		projected.annotations.audience = annotations.audience.dup;
		projected.annotations.priority = annotations.priority;
		projected.annotations.lastModified = annotations.lastModified;
		projected.meta = meta;
		// `BaseMetadata.title` was introduced by 2025-06-18.
		if (v >= ProtocolVersion.v2025_06_18)
			projected.title = title;
		// `ResourceTemplate.icons` was introduced by 2025-11-25.
		if (v >= ProtocolVersion.v2025_11_25)
		{
			foreach (icon; icons)
			{
				Icon copy;
				copy.src = icon.src;
				copy.mimeType = icon.mimeType;
				copy.sizes = icon.sizes.dup;
				copy.theme = icon.theme;
				projected.icons ~= copy;
			}
		}
		return projected;
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
	Json meta; /// optional per-content `_meta` object

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
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			c.meta = j["_meta"];
		return c;
	}
}

unittest  // ResourceContents emits per-content _meta when set
{
	auto c = ResourceContents.makeText("file://x", "text/plain", "hi");
	assert("_meta" !in c.toJson());

	Json m = Json.emptyObject;
	m["io.modelcontextprotocol/audience"] = "user";
	c.meta = m;
	auto j = c.toJson();
	assert(j["_meta"]["io.modelcontextprotocol/audience"].get!string == "user");
	assert(j["uri"].get!string == "file://x");
	assert(j["text"].get!string == "hi");
}

unittest  // ResourceContents omits _meta when unset (no wire change)
{
	auto c = ResourceContents.makeBlob("file://b", "application/octet-stream", "AAAA");
	auto j = c.toJson();
	assert("_meta" !in j);
	assert(j["blob"].get!string == "AAAA");
}

unittest  // ResourceContents parses inbound per-content _meta
{
	Json j = Json.emptyObject;
	j["uri"] = "file://y";
	j["text"] = "data";
	Json m = Json.emptyObject;
	m["k"] = 7;
	j["_meta"] = m;
	auto c = ResourceContents.fromJson(j);
	assert(c.uri == "file://y");
	assert(c.text == "data");
	assert(c.meta.type == Json.Type.object);
	assert(c.meta["k"].get!long == 7);
}

unittest  // ResourceContents per-content _meta round-trips through JSON
{
	auto c = ResourceContents.makeText("file://z", "text/plain", "round");
	Json m = Json.emptyObject;
	m["nested"] = Json.emptyObject;
	m["nested"]["a"] = true;
	c.meta = m;
	auto back = ResourceContents.fromJson(c.toJson());
	assert(back.meta["nested"]["a"].get!bool);
	assert(back.text == "round");
}

unittest  // ResourceContents drops non-object _meta on parse
{
	Json j = Json.emptyObject;
	j["uri"] = "file://w";
	j["text"] = "x";
	j["_meta"] = "not-an-object";
	auto c = ResourceContents.fromJson(j);
	assert(c.meta.type != Json.Type.object);
}

/// Result of `resources/list`.
struct ListResourcesResult
{
	Resource[] resources;
	Nullable!string nextCursor;
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`). Round-trips
	/// symmetrically: `toJson` emits it when set and `fromJson` parses it. The
	/// server sets this (draft-gated) so pre-draft wire output is unchanged.
	Nullable!CacheHint cache;
	/// Optional result-level `_meta` object. Reserved by MCP on every `Result`
	/// (the base interface all paginated list results extend), so it round-trips
	/// on every protocol version: `toJson` emits it only when set and `fromJson`
	/// parses it. Unset by default, so pre-existing wire output is unchanged.
	Json meta;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (r; resources)
			arr ~= r.toJson();
		j["resources"] = arr;
		if (!nextCursor.isNull)
			j["nextCursor"] = nextCursor.get;
		if (!cache.isNull)
			j = withCache(j, cache.get);
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		r.cache = parseCacheHint(j);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// Result of `resources/templates/list`.
struct ListResourceTemplatesResult
{
	ResourceTemplate[] resourceTemplates;
	Nullable!string nextCursor;
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`). Round-trips
	/// symmetrically: `toJson` emits it when set and `fromJson` parses it. The
	/// server sets this (draft-gated) so pre-draft wire output is unchanged.
	Nullable!CacheHint cache;
	/// Optional result-level `_meta` object. Reserved by MCP on every `Result`
	/// (the base interface all paginated list results extend), so it round-trips
	/// on every protocol version: `toJson` emits it only when set and `fromJson`
	/// parses it. Unset by default, so pre-existing wire output is unchanged.
	Json meta;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (t; resourceTemplates)
			arr ~= t.toJson();
		j["resourceTemplates"] = arr;
		if (!nextCursor.isNull)
			j["nextCursor"] = nextCursor.get;
		if (!cache.isNull)
			j = withCache(j, cache.get);
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static ListResourceTemplatesResult fromJson(Json j) @safe
	{
		ListResourceTemplatesResult r;
		if ("resourceTemplates" in j && j["resourceTemplates"].type == Json.Type.array)
		{
			auto arr = j["resourceTemplates"];
			foreach (i; 0 .. arr.length)
				r.resourceTemplates ~= ResourceTemplate.fromJson(arr[i]);
		}
		if ("nextCursor" in j && j["nextCursor"].type == Json.Type.string)
			r.nextCursor = j["nextCursor"].get!string;
		r.cache = parseCacheHint(j);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// A filesystem root exposed by the client (client/roots §Data Types).
///
/// `uri` MUST be a `file://` URI identifying the root directory; `name` is an
/// optional human-readable label. `_meta` carries optional implementation
/// metadata per the draft schema.
struct Root
{
	string uri; /// MUST be a `file://` URI
	Nullable!string name; /// optional human-readable name
	Json meta; /// optional `_meta` object

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["uri"] = uri;
		if (!name.isNull)
			j["name"] = name.get;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static Root fromJson(Json j) @safe
	{
		Root r;
		r.uri = ("uri" in j) ? j["uri"].get!string : "";
		if ("name" in j && j["name"].type == Json.Type.string)
			r.name = j["name"].get!string;
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// Params of the `elicitation/create` request (client/elicitation).
///
/// The schema models the params as a union of a form variant and a URL variant
/// (`ElicitRequestParams = ElicitRequestFormParams | ElicitRequestURLParams`).
/// This struct holds the union of both shapes: `mode` is `"form"` (the default,
/// when absent) or `"url"`. Form-mode requests carry `message` and a
/// `requestedSchema` (a restricted JSON Schema object the handler fills in);
/// URL-mode requests (2025-11-25+) carry `message`, `url`, and `elicitationId`
/// for an out-of-band interaction and leave `requestedSchema` undefined. The
/// raw request `Json` is preserved in `raw` so a handler can inspect any field
/// the typed view does not surface.
struct ElicitParams
{
	string mode = "form"; /// "form" (default) or "url"
	string message; /// human-readable prompt shown to the user
	Json requestedSchema = Json.undefined; /// form mode: the restricted JSON Schema
	string url; /// url mode: the URL the user completes out-of-band
	string elicitationId; /// url mode: correlates the request with its outcome
	Json raw = Json.undefined; /// the full request params as received

	/// True for a URL-mode request (`mode == "url"`).
	bool isUrl() const @safe nothrow
	{
		return mode == "url";
	}

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		// `mode` is omitted for the form default, exactly as the wire form
		// expects; emitted only for the url variant (or a non-default mode).
		if (mode.length && mode != "form")
			j["mode"] = mode;
		j["message"] = message;
		if (requestedSchema.type == Json.Type.object)
			j["requestedSchema"] = requestedSchema;
		if (url.length)
			j["url"] = url;
		if (elicitationId.length)
			j["elicitationId"] = elicitationId;
		return j;
	}

	static ElicitParams fromJson(Json j) @safe
	{
		ElicitParams p;
		p.raw = j;
		if (j.type != Json.Type.object)
			return p;
		if ("mode" in j && j["mode"].type == Json.Type.string)
			p.mode = j["mode"].get!string;
		if ("message" in j && j["message"].type == Json.Type.string)
			p.message = j["message"].get!string;
		if ("requestedSchema" in j && j["requestedSchema"].type == Json.Type.object)
			p.requestedSchema = j["requestedSchema"];
		if ("url" in j && j["url"].type == Json.Type.string)
			p.url = j["url"].get!string;
		if ("elicitationId" in j && j["elicitationId"].type == Json.Type.string)
			p.elicitationId = j["elicitationId"].get!string;
		return p;
	}
}

/// The user's decision on an elicitation request.
enum ElicitAction
{
	accept, /// the user submitted the requested input
	decline, /// the user explicitly declined
	cancel, /// the user dismissed without choosing
}

/// Result of the `elicitation/create` request (client/elicitation).
///
/// `action` is the user's decision (`accept` / `decline` / `cancel`). For an
/// `accept`, `content` carries the collected values keyed by schema property
/// name (each a string, number, boolean, or string array per the schema); it is
/// omitted for `decline`/`cancel`.
struct ElicitResult
{
	ElicitAction action; /// the user's decision
	Json content = Json.undefined; /// accept: the collected `{name: value}` map
	Json meta = Json.undefined; /// optional `_meta` object

	/// Convenience constructor for an `accept` carrying collected `content`.
	static ElicitResult accept(Json content) @safe
	{
		ElicitResult r;
		r.action = ElicitAction.accept;
		r.content = content;
		return r;
	}

	/// Convenience constructor for a `decline` (no content).
	static ElicitResult decline() @safe
	{
		ElicitResult r;
		r.action = ElicitAction.decline;
		return r;
	}

	/// Convenience constructor for a `cancel` (no content).
	static ElicitResult cancel() @safe
	{
		ElicitResult r;
		r.action = ElicitAction.cancel;
		return r;
	}

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		final switch (action)
		{
		case ElicitAction.accept:
			j["action"] = "accept";
			break;
		case ElicitAction.decline:
			j["action"] = "decline";
			break;
		case ElicitAction.cancel:
			j["action"] = "cancel";
			break;
		}
		// Per the schema `content` is only meaningful for `accept`; emit it only
		// when present so decline/cancel stay `{action}`-only on the wire.
		if (action == ElicitAction.accept && content.type == Json.Type.object)
			j["content"] = content;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static ElicitResult fromJson(Json j) @safe
	{
		ElicitResult r;
		if (j.type != Json.Type.object)
			return r;
		if ("action" in j && j["action"].type == Json.Type.string)
		{
			switch (j["action"].get!string)
			{
			case "accept":
				r.action = ElicitAction.accept;
				break;
			case "decline":
				r.action = ElicitAction.decline;
				break;
			case "cancel":
				r.action = ElicitAction.cancel;
				break;
			default:
				break;
			}
		}
		if ("content" in j && j["content"].type == Json.Type.object)
			r.content = j["content"];
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// Result of the `roots/list` request (client/roots).
struct ListRootsResult
{
	Root[] roots;
	Json meta; /// optional `_meta` object

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (r; roots)
			arr ~= r.toJson();
		j["roots"] = arr;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static ListRootsResult fromJson(Json j) @safe
	{
		ListRootsResult r;
		if ("roots" in j && j["roots"].type == Json.Type.array)
		{
			auto arr = j["roots"];
			foreach (i; 0 .. arr.length)
				r.roots ~= Root.fromJson(arr[i]);
		}
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

unittest  // Resource omits annotations/size/icons when unset
{
	Resource r = {uri: "test://x", name: "x"};
	auto j = r.toJson();
	assert("annotations" !in j);
	assert("size" !in j);
	assert("icons" !in j);
}

unittest  // Root serializes uri and optional name
{
	Root r = {uri: "file:///home/user/project", name: nullable("My Project")};
	auto j = r.toJson();
	assert(j["uri"].get!string == "file:///home/user/project");
	assert(j["name"].get!string == "My Project");
}

unittest  // Root omits name when unset
{
	Root r = {uri: "file:///tmp"};
	auto j = r.toJson();
	assert("name" !in j);
}

unittest  // Root round-trips through fromJson including name
{
	Root r = {uri: "file:///a", name: nullable("a")};
	auto back = Root.fromJson(r.toJson());
	assert(back.uri == "file:///a");
	assert(!back.name.isNull && back.name.get == "a");
}

unittest  // Root preserves _meta
{
	Root r = {uri: "file:///a"};
	r.meta = Json.emptyObject;
	r.meta["k"] = "v";
	auto back = Root.fromJson(r.toJson());
	assert(back.meta["k"].get!string == "v");
}

unittest  // ListRootsResult serializes roots envelope
{
	ListRootsResult res;
	res.roots = [Root("file:///a", nullable("a")), Root("file:///b")];
	auto j = res.toJson();
	assert(j["roots"].type == Json.Type.array);
	assert(j["roots"].length == 2);
	assert(j["roots"][0]["uri"].get!string == "file:///a");
	assert(j["roots"][0]["name"].get!string == "a");
	assert("name" !in j["roots"][1]);
}

unittest  // ListRootsResult round-trips through fromJson
{
	ListRootsResult res;
	res.roots = [Root("file:///x", nullable("x"))];
	auto back = ListRootsResult.fromJson(res.toJson());
	assert(back.roots.length == 1);
	assert(back.roots[0].uri == "file:///x");
	assert(back.roots[0].name.get == "x");
}

unittest  // ElicitParams parses a form-mode request (mode defaults to form)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json p = Json.emptyObject;
	p["message"] = "Your name?";
	p["requestedSchema"] = schema;
	auto parsed = ElicitParams.fromJson(p);
	assert(parsed.mode == "form");
	assert(!parsed.isUrl);
	assert(parsed.message == "Your name?");
	assert(parsed.requestedSchema.type == Json.Type.object);
	assert(parsed.url.length == 0);
}

unittest  // ElicitParams parses a url-mode request and preserves raw
{
	Json p = Json.emptyObject;
	p["mode"] = "url";
	p["message"] = "Approve";
	p["url"] = "https://example.com/consent";
	p["elicitationId"] = "e1";
	auto parsed = ElicitParams.fromJson(p);
	assert(parsed.isUrl);
	assert(parsed.url == "https://example.com/consent");
	assert(parsed.elicitationId == "e1");
	assert("requestedSchema" !in parsed.raw); // raw is the original params
}

unittest  // ElicitParams.toJson omits mode for the form default
{
	ElicitParams p;
	p.message = "Pick one";
	auto j = p.toJson();
	assert("mode" !in j);
	assert(j["message"].get!string == "Pick one");
}

unittest  // ElicitParams.toJson emits mode for url variant
{
	ElicitParams p;
	p.mode = "url";
	p.message = "Approve";
	p.url = "https://example.com";
	p.elicitationId = "e1";
	auto j = p.toJson();
	assert(j["mode"].get!string == "url");
	assert(j["url"].get!string == "https://example.com");
	assert(j["elicitationId"].get!string == "e1");
}

unittest  // ElicitResult.accept emits {action, content}
{
	auto r = ElicitResult.accept(Json(["name": Json("Ada")]));
	auto j = r.toJson();
	assert(j["action"].get!string == "accept");
	assert(j["content"]["name"].get!string == "Ada");
}

unittest  // ElicitResult.decline emits only the action (no content)
{
	auto j = ElicitResult.decline().toJson();
	assert(j["action"].get!string == "decline");
	assert("content" !in j);
}

unittest  // ElicitResult.cancel emits only the action (no content)
{
	auto j = ElicitResult.cancel().toJson();
	assert(j["action"].get!string == "cancel");
	assert("content" !in j);
}

unittest  // ElicitResult round-trips an accept through fromJson
{
	auto r = ElicitResult.accept(Json(["age": Json(30)]));
	auto back = ElicitResult.fromJson(r.toJson());
	assert(back.action == ElicitAction.accept);
	assert(back.content["age"].get!int == 30);
}

unittest  // ElicitResult.fromJson parses decline
{
	Json j = Json.emptyObject;
	j["action"] = "decline";
	auto r = ElicitResult.fromJson(j);
	assert(r.action == ElicitAction.decline);
}

unittest  // Resource emits annotations (audience/priority/lastModified)
{
	Resource r = {uri: "test://x", name: "x"};
	r.annotations.audience = ["user", "assistant"];
	r.annotations.priority = 0.8;
	r.annotations.lastModified = nullable("2025-01-01T00:00:00Z");
	auto j = r.toJson();
	assert(j["annotations"]["audience"][0].get!string == "user");
	assert(j["annotations"]["audience"][1].get!string == "assistant");
	assert(j["annotations"]["priority"].get!double == 0.8);
	assert(j["annotations"]["lastModified"].get!string == "2025-01-01T00:00:00Z");
}

unittest  // Resource emits size in bytes
{
	Resource r = {uri: "test://x", name: "x"};
	r.size = 1234L;
	auto j = r.toJson();
	assert(j["size"].get!long == 1234);
}

unittest  // Resource emits icons array
{
	Resource r = {uri: "test://x", name: "x"};
	r.icons = [
		Icon("https://example.com/x.png", nullable("image/png"), ["48x48"])
	];
	auto j = r.toJson();
	assert(j["icons"].type == Json.Type.array);
	assert(j["icons"][0]["src"].get!string == "https://example.com/x.png");
	assert(j["icons"][0]["mimeType"].get!string == "image/png");
	assert(j["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // Resource round-trips annotations/size/icons through fromJson
{
	Resource r = {uri: "test://x", name: "x"};
	r.annotations.audience = ["user"];
	r.annotations.priority = 0.5;
	r.size = 99L;
	r.icons = [Icon("https://e/x.png", nullable("image/png"), ["16x16"])];
	auto back = Resource.fromJson(r.toJson());
	assert(back.annotations.audience == ["user"]);
	assert(back.annotations.priority.get == 0.5);
	assert(back.size.get == 99);
	assert(back.icons.length == 1);
	assert(back.icons[0].src == "https://e/x.png");
}

unittest  // ResourceTemplate emits annotations and icons
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "t"};
	t.annotations.audience = ["assistant"];
	t.icons = [Icon("https://e/t.png", nullable("image/png"), [])];
	auto j = t.toJson();
	assert(j["annotations"]["audience"][0].get!string == "assistant");
	assert(j["icons"][0]["src"].get!string == "https://e/t.png");
}

unittest  // ResourceTemplate round-trips annotations/icons through fromJson
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "t"};
	t.annotations.lastModified = nullable("2025-06-01T00:00:00Z");
	t.icons = [Icon("https://e/t.png", Nullable!string.init, [])];
	auto back = ResourceTemplate.fromJson(t.toJson());
	assert(back.uriTemplate == "test://{id}");
	assert(back.annotations.lastModified.get == "2025-06-01T00:00:00Z");
	assert(back.icons.length == 1);
	assert(back.icons[0].src == "https://e/t.png");
}

unittest  // ResourceTemplate emits and round-trips the optional _meta field
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "t"};
	t.meta = Json.emptyObject;
	t.meta["foo"] = "bar";
	auto j = t.toJson();
	assert(j["_meta"]["foo"].get!string == "bar");
	auto back = ResourceTemplate.fromJson(j);
	assert(back.meta.type == Json.Type.object);
	assert(back.meta["foo"].get!string == "bar");
}

unittest  // ResourceTemplate omits _meta when unset
{
	ResourceTemplate t = {uriTemplate: "test://{id}", name: "t"};
	auto j = t.toJson();
	assert("_meta" !in j);
}

unittest  // Annotations.empty reflects whether any field is set
{
	Annotations a;
	assert(a.empty);
	a.priority = 0.1;
	assert(!a.empty);
}

/// Result of `resources/read`.
struct ReadResourceResult
{
	ResourceContents[] contents;
	Json meta; /// optional result-level `_meta` object
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`). Round-trips
	/// symmetrically: `toJson` emits it when set and `fromJson` parses it. The
	/// server sets this (draft-gated) so pre-draft wire output is unchanged.
	Nullable!CacheHint cache;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (c; contents)
			arr ~= c.toJson();
		j["contents"] = arr;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		if (!cache.isNull)
			j = withCache(j, cache.get);
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
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		r.cache = parseCacheHint(j);
		return r;
	}

	/// Fluent setter for the result-level `_meta` object.
	ReadResourceResult withMeta(Json m) @safe
	{
		meta = m;
		return this;
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
	Nullable!string title; /// optional human-readable display name (BaseMetadata)

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		if (!title.isNull)
			j["title"] = title.get;
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
		if ("title" in j && j["title"].type == Json.Type.string)
			a.title = j["title"].get!string;
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
	Nullable!string title; /// optional human-readable display name
	Nullable!string description;
	PromptArgument[] arguments;
	Icon[] icons; /// optional icons for display in user interfaces
	Json meta; /// optional descriptor-level `_meta` object

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		if (!title.isNull)
			j["title"] = title.get;
		if (!description.isNull)
			j["description"] = description.get;
		if (arguments.length)
		{
			Json arr = Json.emptyArray;
			foreach (a; arguments)
				arr ~= a.toJson();
			j["arguments"] = arr;
		}
		if (icons.length)
		{
			Json arr = Json.emptyArray;
			foreach (icon; icons)
				arr ~= icon.toJson();
			j["icons"] = arr;
		}
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static Prompt fromJson(Json j) @safe
	{
		Prompt p;
		p.name = ("name" in j) ? j["name"].get!string : "";
		if ("title" in j && j["title"].type == Json.Type.string)
			p.title = j["title"].get!string;
		if ("description" in j && j["description"].type == Json.Type.string)
			p.description = j["description"].get!string;
		if ("arguments" in j && j["arguments"].type == Json.Type.array)
		{
			auto arr = j["arguments"];
			foreach (i; 0 .. arr.length)
				p.arguments ~= PromptArgument.fromJson(arr[i]);
		}
		if ("icons" in j && j["icons"].type == Json.Type.array)
			foreach (i; 0 .. j["icons"].length)
				p.icons ~= Icon.fromJson(j["icons"][i]);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			p.meta = j["_meta"];
		return p;
	}

	/// Return a copy of this `Prompt` with any fields newer than the negotiated
	/// protocol version stripped, so the wire output stays valid for the peer's
	/// version. `BaseMetadata.title` was introduced by 2025-06-18 (absent from
	/// 2025-03-26 and 2024-11-05); `Prompt.icons` was introduced by 2025-11-25
	/// (absent from every earlier version, present in draft which is
	/// >= 2025-11-25). Mirrors `Tool.forVersion`.
	Prompt forVersion(ProtocolVersion v) const @safe
	{
		Prompt projected;
		projected.name = name;
		projected.description = description;
		foreach (a; arguments)
			projected.arguments ~= a;
		projected.meta = meta;
		if (v >= ProtocolVersion.v2025_06_18)
			projected.title = title;
		if (v >= ProtocolVersion.v2025_11_25)
		{
			foreach (icon; icons)
			{
				Icon copy;
				copy.src = icon.src;
				copy.mimeType = icon.mimeType;
				copy.sizes = icon.sizes.dup;
				copy.theme = icon.theme;
				projected.icons ~= copy;
			}
		}
		return projected;
	}
}

unittest  // Prompt.forVersion strips title for 2024-11-05 (BaseMetadata.title introduced 2025-06-18)
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	auto j = p.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("title" !in j);
}

unittest  // Prompt.forVersion strips title for 2025-03-26 (BaseMetadata.title introduced 2025-06-18)
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	auto j = p.forVersion(ProtocolVersion.v2025_03_26).toJson();
	assert("title" !in j);
}

unittest  // Prompt.forVersion keeps title for 2025-06-18 (title introduced here)
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	auto j = p.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert(j["title"].get!string == "Greeting");
}

unittest  // Prompt.forVersion keeps title for 2025-11-25
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	auto j = p.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert(j["title"].get!string == "Greeting");
}

unittest  // Prompt.forVersion keeps title for draft
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	auto j = p.forVersion(ProtocolVersion.draft).toJson();
	assert(j["title"].get!string == "Greeting");
}

unittest  // Prompt.forVersion strips icons for 2024-11-05 (Prompt.icons introduced 2025-11-25)
{
	Prompt p = {name: "greet"};
	p.icons = [Icon("https://e/p.png", nullable("image/png"), ["16x16"])];
	auto j = p.forVersion(ProtocolVersion.v2024_11_05).toJson();
	assert("icons" !in j);
}

unittest  // Prompt.forVersion strips icons for 2025-06-18 (Prompt.icons introduced 2025-11-25)
{
	Prompt p = {name: "greet"};
	p.icons = [Icon("https://e/p.png", nullable("image/png"), ["16x16"])];
	auto j = p.forVersion(ProtocolVersion.v2025_06_18).toJson();
	assert("icons" !in j);
}

unittest  // Prompt.forVersion keeps icons for 2025-11-25 (Prompt.icons introduced here)
{
	Prompt p = {name: "greet"};
	p.icons = [Icon("https://e/p.png", nullable("image/png"), ["16x16"])];
	auto j = p.forVersion(ProtocolVersion.v2025_11_25).toJson();
	assert(j["icons"].type == Json.Type.array);
	assert(j["icons"][0]["src"].get!string == "https://e/p.png");
}

unittest  // Prompt.forVersion keeps icons for draft (draft >= 2025-11-25)
{
	Prompt p = {name: "greet"};
	p.icons = [Icon("https://e/p.png", nullable("image/png"), ["16x16"])];
	auto j = p.forVersion(ProtocolVersion.draft).toJson();
	assert(j["icons"].type == Json.Type.array);
}

unittest  // Prompt.forVersion preserves non-version-gated fields (name/description/arguments) intact
{
	Prompt p = {name: "greet", description: nullable("desc")};
	p.arguments ~= PromptArgument("arg1");
	auto pj = p.forVersion(ProtocolVersion.v2024_11_05);
	assert(pj.name == "greet");
	assert(pj.description.get == "desc");
	assert(pj.arguments.length == 1);
	assert(pj.arguments[0].name == "arg1");
}

unittest  // Prompt.forVersion leaves the original unmodified (returns a projected copy)
{
	Prompt p = {name: "greet"};
	p.title = "Greeting";
	p.icons = [Icon("https://e/p.png", nullable("image/png"), [])];
	cast(void) p.forVersion(ProtocolVersion.v2024_11_05);
	assert(!p.title.isNull);
	assert(p.icons.length == 1);
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
	/// Draft `CacheableResult` freshness hint (`ttlMs`/`cacheScope`). Round-trips
	/// symmetrically: `toJson` emits it when set and `fromJson` parses it. The
	/// server sets this (draft-gated) so pre-draft wire output is unchanged.
	Nullable!CacheHint cache;
	/// Optional result-level `_meta` object. Reserved by MCP on every `Result`
	/// (the base interface all paginated list results extend), so it round-trips
	/// on every protocol version: `toJson` emits it only when set and `fromJson`
	/// parses it. Unset by default, so pre-existing wire output is unchanged.
	Json meta;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (p; prompts)
			arr ~= p.toJson();
		j["prompts"] = arr;
		if (!nextCursor.isNull)
			j["nextCursor"] = nextCursor.get;
		if (!cache.isNull)
			j = withCache(j, cache.get);
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		r.cache = parseCacheHint(j);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// Result of `prompts/get`.
struct GetPromptResult
{
	Nullable!string description;
	PromptMessage[] messages;
	Json meta; /// optional result-level `_meta` object

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (!description.isNull)
			j["description"] = description.get;
		Json arr = Json.emptyArray;
		foreach (m; messages)
			arr ~= m.toJson();
		j["messages"] = arr;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
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
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}

	/// Fluent setter for the result-level `_meta` object.
	GetPromptResult withMeta(Json m) @safe
	{
		meta = m;
		return this;
	}
}

// ===========================================================================
// Completion
// ===========================================================================

/// A `completion/complete` reference: the thing being completed. Per
/// server/utilities/completion §"Requesting Completions", a client specifies
/// either a prompt (`ref/prompt`, identified by `name`) or a resource template
/// (`ref/resource`, identified by `uri`). Use `forPrompt` / `forResource` to
/// construct one.
struct CompletionReference
{
	/// Either `"ref/prompt"` or `"ref/resource"`.
	string type;
	/// Prompt name (for `ref/prompt`).
	string name;
	/// Resource (template) URI (for `ref/resource`).
	string uri;
	/// Optional human-readable display title for the prompt (`ref/prompt`
	/// only). `PromptReference extends BaseMetadata`, so a prompt reference may
	/// carry BaseMetadata's optional `title`. Has no meaning for `ref/resource`
	/// (`ResourceTemplateReference` does not extend BaseMetadata) and is never
	/// serialized in that case.
	Nullable!string title;

	/// Build a reference to a prompt argument.
	static CompletionReference forPrompt(string name) @safe
	{
		return CompletionReference("ref/prompt", name, null);
	}

	/// Build a reference to a resource template URI.
	static CompletionReference forResource(string uri) @safe
	{
		return CompletionReference("ref/resource", null, uri);
	}

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["type"] = type;
		if (type == "ref/resource")
		{
			j["uri"] = uri;
		}
		else
		{
			j["name"] = name;
			// PromptReference extends BaseMetadata, so emit the optional
			// display title when present (prompt references only).
			if (!title.isNull)
				j["title"] = title.get;
		}
		return j;
	}
}

/// A parsed `completion/complete` request, as received by a server. Per
/// server/utilities/completion §"Data Types > CompleteRequest" a client sends a
/// `ref` (a `ref/prompt` or `ref/resource` reference), an `argument`
/// (`{name, value}`) naming the argument being completed and its partial value,
/// and an optional `context.arguments` map of previously-resolved argument
/// values. Use `fromJson` to parse the raw params handed to a completion handler.
struct CompleteRequest
{
	/// What is being completed (a prompt or a resource template).
	CompletionReference reference;
	/// Name of the argument being completed.
	string argumentName;
	/// Partial value typed so far for that argument.
	string argumentValue;
	/// Previously-resolved argument values (`context.arguments`), if supplied.
	string[string] context;

	/// `true` if this request targets a prompt argument (`ref/prompt`).
	bool isPrompt() const @safe
	{
		return reference.type == "ref/prompt";
	}

	/// `true` if this request targets a resource template (`ref/resource`).
	bool isResource() const @safe
	{
		return reference.type == "ref/resource";
	}

	/// Parse the raw `completion/complete` params object.
	static CompleteRequest fromJson(Json params) @safe
	{
		CompleteRequest r;
		if (params.type != Json.Type.object)
			return r;
		if ("ref" in params && params["ref"].type == Json.Type.object)
		{
			auto refJson = params["ref"];
			if ("type" in refJson && refJson["type"].type == Json.Type.string)
				r.reference.type = refJson["type"].get!string;
			if ("name" in refJson && refJson["name"].type == Json.Type.string)
				r.reference.name = refJson["name"].get!string;
			if ("title" in refJson && refJson["title"].type == Json.Type.string)
				r.reference.title = nullable(refJson["title"].get!string);
			if ("uri" in refJson && refJson["uri"].type == Json.Type.string)
				r.reference.uri = refJson["uri"].get!string;
		}
		if ("argument" in params && params["argument"].type == Json.Type.object)
		{
			auto arg = params["argument"];
			if ("name" in arg && arg["name"].type == Json.Type.string)
				r.argumentName = arg["name"].get!string;
			if ("value" in arg && arg["value"].type == Json.Type.string)
				r.argumentValue = arg["value"].get!string;
		}
		if ("context" in params && params["context"].type == Json.Type.object)
		{
			auto ctx = params["context"];
			if ("arguments" in ctx && ctx["arguments"].type == Json.Type.object)
			{
				auto args = ctx["arguments"];
				foreach (string k, v; args.byKeyValue)
					if (v.type == Json.Type.string)
						r.context[k] = v.get!string;
			}
		}
		return r;
	}
}

/// Result of `completion/complete`.
struct CompleteResult
{
	string[] values;
	Nullable!size_t total;
	bool hasMore;
	Json meta; /// optional result-level `_meta` object

	/// The spec hard-caps `completion.values` at 100 items
	/// (schema `@maxItems 100`: "Must not exceed 100 items.").
	enum size_t maxValues = 100;

	Json toJson() const @safe
	{
		Json completion = Json.emptyObject;
		Json arr = Json.emptyArray;
		// Cap at the spec's max of 100 so the SDK can never emit a
		// schema-violating completion result.
		immutable truncated = values.length > maxValues;
		foreach (v; values[0 .. truncated ? maxValues : values.length])
			arr ~= Json(v);
		completion["values"] = arr;
		if (!total.isNull)
			completion["total"] = total.get;
		// When values are truncated there are necessarily more options
		// available, so report hasMore even if the caller did not.
		completion["hasMore"] = hasMore || truncated;
		Json j = Json.emptyObject;
		j["completion"] = completion;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	/// Parse a `completion/complete` result envelope (`{completion: {values,
	/// total?, hasMore?}}`) as returned by a server.
	static CompleteResult fromJson(Json j) @safe
	{
		CompleteResult r;
		if (j.type != Json.Type.object || "completion" !in j
				|| j["completion"].type != Json.Type.object)
			return r;
		auto c = j["completion"];
		if ("values" in c && c["values"].type == Json.Type.array)
		{
			auto arr = c["values"];
			foreach (i; 0 .. arr.length)
				if (arr[i].type == Json.Type.string)
					r.values ~= arr[i].get!string;
		}
		// The spec types completion.total as `number`, which covers both
		// integral and fractional JSON encodings (e.g. `10` or `10.0`).
		// Accept either so a float-encoded total is preserved rather than
		// dropped (mirrors ProgressNotification.fromJson).
		if ("total" in c && c["total"].type == Json.Type.int_)
			r.total = cast(size_t) c["total"].get!long;
		else if ("total" in c && c["total"].type == Json.Type.float_)
			r.total = cast(size_t)(c["total"].get!double + 0.5);
		if ("hasMore" in c && c["hasMore"].type == Json.Type.bool_)
			r.hasMore = c["hasMore"].get!bool;
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}
}

/// A typed `notifications/progress` payload, per basic/utilities/progress: the
/// notification carries `params: {progressToken, progress, total?, message?}`.
/// `progressToken` correlates the update to the request that supplied it (a
/// string or integer; see `ProgressToken`), `progress` is the current amount
/// (which "MUST increase with each notification"), `total` the optional final
/// amount, and `message` an optional human-readable description. Parsed from an
/// inbound notification's `params` so clients receive a structured value rather
/// than hand-parsing raw JSON.
struct ProgressNotification
{
	/// The progress token from the originating request (string or integer);
	/// `Json.undefined` if absent. Compare against the `ProgressToken` you sent.
	Json progressToken = Json.undefined;
	/// The current progress amount.
	double progress = 0;
	/// The optional total amount of work (`null` when the server omits it).
	Nullable!double total;
	/// An optional human-readable progress message.
	Nullable!string message;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["progressToken"] = progressToken;
		j["progress"] = progress;
		if (!total.isNull)
			j["total"] = total.get;
		if (!message.isNull)
			j["message"] = message.get;
		return j;
	}

	/// Parse the `params` object of a `notifications/progress` message. Tolerant
	/// of a missing/ill-typed payload (returns a default-valued struct), and
	/// accepts `progress`/`total` as either integer or floating-point JSON.
	static ProgressNotification fromJson(Json params) @safe
	{
		ProgressNotification n;
		if (params.type != Json.Type.object)
			return n;
		if ("progressToken" in params)
			n.progressToken = params["progressToken"];
		if ("progress" in params)
			n.progress = toDouble(params["progress"]);
		if ("total" in params && (params["total"].type == Json.Type.int_
				|| params["total"].type == Json.Type.float_))
			n.total = toDouble(params["total"]);
		if ("message" in params && params["message"].type == Json.Type.string)
			n.message = params["message"].get!string;
		return n;
	}

	private static double toDouble(Json v) @safe
	{
		if (v.type == Json.Type.float_)
			return v.get!double;
		if (v.type == Json.Type.int_)
			return cast(double) v.get!long;
		return 0;
	}
}

unittest  // ProgressNotification parses token, progress, total and message
{
	Json p = Json.emptyObject;
	p["progressToken"] = "tok-1";
	p["progress"] = 5;
	p["total"] = 10;
	p["message"] = "halfway";
	auto n = ProgressNotification.fromJson(p);
	assert(n.progressToken.get!string == "tok-1");
	assert(n.progress == 5);
	assert(!n.total.isNull && n.total.get == 10);
	assert(!n.message.isNull && n.message.get == "halfway");
}

unittest  // ProgressNotification accepts a floating-point progress and integer token
{
	Json p = Json.emptyObject;
	p["progressToken"] = 7;
	p["progress"] = 0.25;
	auto n = ProgressNotification.fromJson(p);
	assert(n.progressToken.get!long == 7);
	assert(n.progress == 0.25);
	assert(n.total.isNull);
	assert(n.message.isNull);
}

unittest  // ProgressNotification tolerates a non-object payload
{
	auto n = ProgressNotification.fromJson(Json("not an object"));
	assert(n.progress == 0);
	assert(n.progressToken.type == Json.Type.undefined);
}

/// The severity of a `notifications/message`, per server/utilities/logging. The
/// eight levels follow the syslog severities (RFC 5424); ordered most verbose
/// (`debug`) to most severe (`emergency`).
enum LogLevel : string
{
	debug_ = "debug",
	info = "info",
	notice = "notice",
	warning = "warning",
	error = "error",
	critical = "critical",
	alert = "alert",
	emergency = "emergency"
}

/// A typed `notifications/message` payload, per server/utilities/logging: the
/// notification carries `params: {level, logger?, data}`. `level` is one of the
/// eight `LogLevel` severities, `logger` an optional name of the emitting
/// component, and `data` an arbitrary JSON value (commonly a string or object).
/// Parsed from an inbound notification's `params` so clients receive a
/// structured value rather than hand-parsing raw JSON.
struct LogMessageNotification
{
	/// The severity level (raw string, as on the wire). Compare against
	/// `LogLevel` values; an unrecognised level is preserved verbatim.
	string level;
	/// The optional name of the logger/component that emitted the message
	/// (`null` when the server omits it).
	Nullable!string logger;
	/// The log payload — any JSON value; `Json.undefined` if absent.
	Json data = Json.undefined;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["level"] = level;
		if (!logger.isNull)
			j["logger"] = logger.get;
		// `data` is REQUIRED by server/utilities/logging. vibe.data.json drops
		// a key whose value is Json.undefined, so substitute an explicit JSON
		// null to guarantee the wire frame always carries the `data` field.
		j["data"] = data.type == Json.Type.undefined ? Json(null) : data;
		return j;
	}

	/// Parse the `params` object of a `notifications/message`. Tolerant of a
	/// missing/ill-typed payload (returns a default-valued struct).
	static LogMessageNotification fromJson(Json params) @safe
	{
		LogMessageNotification n;
		if (params.type != Json.Type.object)
			return n;
		if ("level" in params && params["level"].type == Json.Type.string)
			n.level = params["level"].get!string;
		if ("logger" in params && params["logger"].type == Json.Type.string)
			n.logger = params["logger"].get!string;
		if ("data" in params)
			n.data = params["data"];
		return n;
	}
}

unittest  // LogMessageNotification parses level, logger and data
{
	Json p = Json.emptyObject;
	p["level"] = "warning";
	p["logger"] = "db";
	p["data"] = "disk almost full";
	auto n = LogMessageNotification.fromJson(p);
	assert(n.level == "warning");
	assert(n.level == LogLevel.warning);
	assert(!n.logger.isNull && n.logger.get == "db");
	assert(n.data.get!string == "disk almost full");
}

unittest  // LogMessageNotification keeps logger null when absent and accepts structured data
{
	Json p = Json.emptyObject;
	p["level"] = "info";
	Json d = Json.emptyObject;
	d["count"] = 3;
	p["data"] = d;
	auto n = LogMessageNotification.fromJson(p);
	assert(n.level == "info");
	assert(n.logger.isNull);
	assert(n.data["count"].get!long == 3);
}

unittest  // LogMessageNotification tolerates a non-object payload
{
	auto n = LogMessageNotification.fromJson(Json("not an object"));
	assert(n.level == "");
	assert(n.logger.isNull);
	assert(n.data.type == Json.Type.undefined);
}

unittest  // LogMessageNotification.toJson round-trips through fromJson
{
	LogMessageNotification n;
	n.level = LogLevel.error;
	n.logger = "net";
	n.data = Json("timeout");
	auto j = n.toJson();
	assert(j["level"].get!string == "error");
	assert(j["logger"].get!string == "net");
	auto back = LogMessageNotification.fromJson(j);
	assert(back.level == "error");
	assert(back.logger.get == "net");
	assert(back.data.get!string == "timeout");
}

unittest  // LogMessageNotification.toJson always emits the REQUIRED data field
{
	// server/utilities/logging types `data` as required (`data: unknown`, no
	// `?`). A level-only struct whose `data` was never assigned must still
	// serialise the `data` key (as explicit JSON null), not drop it — vibe
	// omits keys whose value is Json.undefined.
	LogMessageNotification n;
	n.level = LogLevel.info;
	auto j = n.toJson();
	assert("data" in j);
	assert(j["data"].type == Json.Type.null_);
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

unittest  // PromptArgument emits an optional title when set
{
	PromptArgument a;
	a.name = "who";
	a.title = nullable("Recipient");
	auto j = a.toJson();
	assert(j["name"].get!string == "who");
	assert(j["title"].get!string == "Recipient");
}

unittest  // PromptArgument omits title when unset
{
	PromptArgument a;
	a.name = "who";
	auto j = a.toJson();
	assert("title" !in j);
}

unittest  // PromptArgument parses the optional title from JSON
{
	Json j = Json.emptyObject;
	j["name"] = "who";
	j["title"] = "Recipient";
	auto a = PromptArgument.fromJson(j);
	assert(a.name == "who");
	assert(!a.title.isNull);
	assert(a.title.get == "Recipient");
}

unittest  // Prompt emits an optional title and round-trips it
{
	Prompt p = {
		name: "greet", title: nullable("Greeting"), description: nullable("greets")
	};
	auto j = p.toJson();
	assert(j["title"].get!string == "Greeting");
	auto back = Prompt.fromJson(j);
	assert(back.title.get == "Greeting");
}

unittest  // Prompt omits title when unset
{
	Prompt p = {name: "greet"};
	auto j = p.toJson();
	assert("title" !in j);
	assert(Prompt.fromJson(j).title.isNull);
}

unittest  // Prompt emits icons array when present
{
	Prompt p = {name: "greet"};
	p.icons = [
		Icon("https://example.com/greet.png", nullable("image/png"), ["48x48"])
	];
	auto j = p.toJson();
	assert(j["icons"].type == Json.Type.array);
	assert(j["icons"].length == 1);
	assert(j["icons"][0]["src"].get!string == "https://example.com/greet.png");
	assert(j["icons"][0]["mimeType"].get!string == "image/png");
	assert(j["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // Prompt omits icons when empty
{
	Prompt p = {name: "noicons"};
	auto j = p.toJson();
	assert("icons" !in j);
}

unittest  // Prompt icons round-trip through fromJson
{
	Prompt p = {name: "greet"};
	p.icons = [
		Icon("https://example.com/a.svg"),
		Icon("https://example.com/b.png", nullable("image/png"), [
			"16x16", "32x32"
		])
	];
	auto back = Prompt.fromJson(p.toJson());
	assert(back.icons.length == 2);
	assert(back.icons[0].src == "https://example.com/a.svg");
	assert(back.icons[0].mimeType.isNull);
	assert(back.icons[0].sizes.length == 0);
	assert(back.icons[1].src == "https://example.com/b.png");
	assert(back.icons[1].mimeType.get == "image/png");
	assert(back.icons[1].sizes == ["16x16", "32x32"]);
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

unittest  // CompleteResult.fromJson parses the completion envelope
{
	auto j = `{"completion":{"values":["paris","park"],"total":150,"hasMore":true}}`
		.parseJsonString;
	auto r = CompleteResult.fromJson(j);
	assert(r.values == ["paris", "park"]);
	assert(!r.total.isNull && r.total.get == 150);
	assert(r.hasMore);
}

unittest  // CompleteResult.fromJson preserves a total encoded as a JSON float
{
	// The spec types completion.total as `number`, which covers float
	// encodings (e.g. `10.0`). A conformant server may emit it as a float;
	// the field must be preserved, not dropped.
	auto j = `{"completion":{"values":["paris"],"total":10.0,"hasMore":false}}`.parseJsonString;
	auto r = CompleteResult.fromJson(j);
	assert(r.values == ["paris"]);
	assert(!r.total.isNull && r.total.get == 10);
	assert(!r.hasMore);
}

unittest  // CompleteResult.fromJson tolerates a missing completion envelope
{
	auto r = CompleteResult.fromJson(Json.emptyObject);
	assert(r.values.length == 0);
	assert(r.total.isNull);
	assert(!r.hasMore);
}

unittest  // CompleteResult caps serialized values at the spec's max of 100
{
	CompleteResult r;
	foreach (i; 0 .. 150)
		r.values ~= "v";
	auto j = r.toJson();
	assert(j["completion"]["values"].length == 100);
}

unittest  // CompleteResult sets hasMore when values are truncated to 100
{
	CompleteResult r;
	foreach (i; 0 .. 101)
		r.values ~= "v";
	auto j = r.toJson();
	assert(j["completion"]["hasMore"].get!bool == true);
}

unittest  // CompleteResult preserves a caller-supplied total when truncating
{
	CompleteResult r;
	foreach (i; 0 .. 150)
		r.values ~= "v";
	r.total = 150;
	auto j = r.toJson();
	assert(j["completion"]["total"].get!int == 150);
	assert(j["completion"]["values"].length == 100);
}

unittest  // CompleteResult leaves <=100 values untouched and hasMore unchanged
{
	CompleteResult r;
	r.values = ["a", "b", "c"];
	auto j = r.toJson();
	assert(j["completion"]["values"].length == 3);
	assert(j["completion"]["hasMore"].get!bool == false);
}

unittest  // CompletionReference.forPrompt builds a ref/prompt with a name
{
	auto j = CompletionReference.forPrompt("greet").toJson();
	assert(j["type"].get!string == "ref/prompt");
	assert(j["name"].get!string == "greet");
	assert("uri" !in j);
}

unittest  // CompletionReference.forResource builds a ref/resource with a uri
{
	auto j = CompletionReference.forResource("file:///{path}").toJson();
	assert(j["type"].get!string == "ref/resource");
	assert(j["uri"].get!string == "file:///{path}");
	assert("name" !in j);
}

unittest  // CompletionReference omits title for ref/prompt when unset
{
	// PromptReference extends BaseMetadata: `title` is optional and MUST be
	// absent on the wire when not provided.
	auto j = CompletionReference.forPrompt("greet").toJson();
	assert("title" !in j);
}

unittest  // CompletionReference emits title for ref/prompt when set
{
	// PromptReference extends BaseMetadata, so a `ref/prompt` reference may
	// carry the optional human-readable `title` alongside `name`.
	auto refr = CompletionReference.forPrompt("greet");
	refr.title = nullable("Greeting");
	auto j = refr.toJson();
	assert(j["type"].get!string == "ref/prompt");
	assert(j["name"].get!string == "greet");
	assert(j["title"].get!string == "Greeting");
}

unittest  // CompletionReference never emits title for ref/resource
{
	// ResourceTemplateReference does NOT extend BaseMetadata; it has only
	// `type` and `uri`, so `title` must never appear even if set.
	auto refr = CompletionReference.forResource("file:///{path}");
	refr.title = nullable("ignored");
	auto j = refr.toJson();
	assert("title" !in j);
	assert("name" !in j);
	assert(j["uri"].get!string == "file:///{path}");
}

unittest  // CompleteRequest.fromJson parses the optional ref/prompt title
{
	auto refr = CompletionReference.forPrompt("greet");
	refr.title = nullable("Greeting");
	Json p = Json.emptyObject;
	p["ref"] = refr.toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "who";
	arg["value"] = "al";
	p["argument"] = arg;
	auto r = CompleteRequest.fromJson(p);
	assert(r.reference.name == "greet");
	assert(!r.reference.title.isNull);
	assert(r.reference.title.get == "Greeting");
}

unittest  // CompleteRequest.fromJson parses a prompt reference
{
	Json p = Json.emptyObject;
	p["ref"] = CompletionReference.forPrompt("greet").toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "who";
	arg["value"] = "al";
	p["argument"] = arg;
	auto r = CompleteRequest.fromJson(p);
	assert(r.isPrompt);
	assert(!r.isResource);
	assert(r.reference.name == "greet");
	assert(r.argumentName == "who");
	assert(r.argumentValue == "al");
	assert(r.context.length == 0);
}

unittest  // CompleteRequest.fromJson parses a resource reference
{
	Json p = Json.emptyObject;
	p["ref"] = CompletionReference.forResource("file:///{path}").toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "path";
	arg["value"] = "/ho";
	p["argument"] = arg;
	auto r = CompleteRequest.fromJson(p);
	assert(r.isResource);
	assert(!r.isPrompt);
	assert(r.reference.uri == "file:///{path}");
	assert(r.argumentName == "path");
	assert(r.argumentValue == "/ho");
}

unittest  // CompleteRequest.fromJson parses context.arguments
{
	Json p = Json.emptyObject;
	p["ref"] = CompletionReference.forPrompt("pr").toJson();
	Json arg = Json.emptyObject;
	arg["name"] = "branch";
	arg["value"] = "m";
	p["argument"] = arg;
	Json args = Json.emptyObject;
	args["repo"] = "mcp.d";
	Json ctx = Json.emptyObject;
	ctx["arguments"] = args;
	p["context"] = ctx;
	auto r = CompleteRequest.fromJson(p);
	assert(r.context["repo"] == "mcp.d");
}

unittest  // CompleteRequest.fromJson tolerates an empty/garbage params object
{
	auto r = CompleteRequest.fromJson(Json.emptyObject);
	assert(r.reference.type.length == 0);
	assert(r.argumentName.length == 0);
	assert(!r.isPrompt);
	assert(!r.isResource);
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

unittest  // ListResourceTemplatesResult.fromJson round-trips templates + cursor
{
	ResourceTemplate t;
	t.uriTemplate = "file:///logs/{name}";
	t.name = "log";
	t.title = nullable("Log file");
	t.mimeType = nullable("text/plain");

	ListResourceTemplatesResult res;
	res.resourceTemplates = [t];
	res.nextCursor = "page2";

	auto back = ListResourceTemplatesResult.fromJson(res.toJson());
	assert(back.resourceTemplates.length == 1);
	assert(back.resourceTemplates[0].uriTemplate == "file:///logs/{name}");
	assert(back.resourceTemplates[0].name == "log");
	assert(back.resourceTemplates[0].title.get == "Log file");
	assert(!back.nextCursor.isNull && back.nextCursor.get == "page2");
}

unittest  // ListResourceTemplatesResult.fromJson tolerates a missing array
{
	ListResourceTemplatesResult back = ListResourceTemplatesResult.fromJson(Json.emptyObject);
	assert(back.resourceTemplates.length == 0);
	assert(back.nextCursor.isNull);
}
