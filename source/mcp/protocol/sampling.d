/**
 * Typed request/result structs for the MCP sampling feature
 * (`sampling/createMessage`).
 *
 * The wire path through `RequestContext.sample` and the client `onSampling`
 * handler is plain JSON, but assembling that JSON by hand is error-prone. These
 * builders/parsers give sampling the same ergonomic typing the SDK already
 * provides for tools and prompts: build a `CreateMessageRequest`, call
 * `toJson`, and pass it to `sample`; parse the reply with
 * `CreateMessageResult.fromJson`. They reuse the existing `Content` block from
 * `mcp.protocol.types`.
 */
module mcp.protocol.sampling;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;
import mcp.protocol.types : Content, ContentKind, Tool;
import mcp.protocol.errors : McpException, invalidParams;

@safe:

/// A single message in a sampling conversation. `role` is "user" or
/// "assistant"; `content` reuses the SDK's `Content` block (text/image/audio).
struct SamplingMessage
{
	string role; /// "user" or "assistant"
	Content content;
	Json meta = Json.undefined; /// optional message-level `_meta` object (schema.ts: SamplingMessage._meta)

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["role"] = role;
		j["content"] = content.toJson();
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static SamplingMessage fromJson(Json j) @safe
	{
		SamplingMessage m;
		m.role = ("role" in j) ? j["role"].get!string : "";
		if ("content" in j)
			m.content = Content.fromJson(j["content"]);
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			m.meta = j["_meta"];
		return m;
	}
}

/// A hint for which model the client should select. `name` is a substring the
/// client may match against its available model identifiers (e.g. "claude-3",
/// "sonnet", "gemini").
struct ModelHint
{
	string name;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["name"] = name;
		return j;
	}

	static ModelHint fromJson(Json j) @safe
	{
		ModelHint h;
		h.name = ("name" in j) ? j["name"].get!string : "";
		return h;
	}
}

/// The server's preferences for model selection during sampling. All fields are
/// optional. The priority values, when set, are clamped at the wire boundary to
/// the spec's 0..1 range by the consuming client.
struct ModelPreferences
{
	ModelHint[] hints; /// ordered model name hints, most preferred first
	Nullable!double costPriority; /// 0..1: importance of minimizing cost
	Nullable!double speedPriority; /// 0..1: importance of minimizing latency
	Nullable!double intelligencePriority; /// 0..1: importance of capability

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (hints.length)
		{
			Json arr = Json.emptyArray;
			foreach (h; hints)
				arr ~= h.toJson();
			j["hints"] = arr;
		}
		if (!costPriority.isNull)
			j["costPriority"] = costPriority.get;
		if (!speedPriority.isNull)
			j["speedPriority"] = speedPriority.get;
		if (!intelligencePriority.isNull)
			j["intelligencePriority"] = intelligencePriority.get;
		return j;
	}

	static ModelPreferences fromJson(Json j) @safe
	{
		ModelPreferences p;
		if ("hints" in j && j["hints"].type == Json.Type.array)
			foreach (i; 0 .. j["hints"].length)
				p.hints ~= ModelHint.fromJson(j["hints"][i]);
		if ("costPriority" in j && j["costPriority"].type != Json.Type.undefined
				&& j["costPriority"].type != Json.Type.null_)
			p.costPriority = j["costPriority"].to!double;
		if ("speedPriority" in j && j["speedPriority"].type != Json.Type.undefined
				&& j["speedPriority"].type != Json.Type.null_)
			p.speedPriority = j["speedPriority"].to!double;
		if ("intelligencePriority" in j && j["intelligencePriority"].type != Json.Type.undefined
				&& j["intelligencePriority"].type != Json.Type.null_)
			p.intelligencePriority = j["intelligencePriority"].to!double;
		return p;
	}

	/// True when no preference is set (so `CreateMessageRequest.toJson` can omit
	/// the whole `modelPreferences` object).
	bool empty() const @safe
	{
		return hints.length == 0 && costPriority.isNull && speedPriority.isNull
			&& intelligencePriority.isNull;
	}
}

/// Controls the tool-use ability of the model during tool-enabled sampling.
/// `mode` is one of "auto" (model decides, the default), "required" (model MUST
/// use at least one tool before completing), or "none" (model MUST NOT use any
/// tools). Added by the 2025-11-25 / draft revisions; see client/sampling
/// Tool Choice Modes.
struct ToolChoice
{
	Nullable!string mode; /// "auto" | "required" | "none"

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (!mode.isNull)
			j["mode"] = mode.get;
		return j;
	}

	static ToolChoice fromJson(Json j) @safe
	{
		ToolChoice c;
		if (j.type == Json.Type.object && "mode" in j && j["mode"].type == Json.Type.string)
			c.mode = j["mode"].get!string;
		return c;
	}

	/// True when no mode is set (so `CreateMessageRequest.toJson` can decide
	/// whether to emit a `toolChoice` object at all).
	bool empty() const @safe
	{
		return mode.isNull;
	}
}

/// Parameters of a `sampling/createMessage` request the server sends to the
/// client. Build one, call `toJson`, and pass it to `RequestContext.sample`.
struct CreateMessageRequest
{
	SamplingMessage[] messages;
	ModelPreferences modelPreferences;
	Nullable!string systemPrompt;
	Nullable!string includeContext; /// "none" | "thisServer" | "allServers"
	Nullable!double temperature;
	Nullable!long maxTokens;
	string[] stopSequences;
	Json metadata = Json.undefined; /// opaque provider-specific metadata
	Tool[] tools; /// tools the model may call during sampling (2025-11-25 / draft)
	ToolChoice toolChoice; /// optional tool-choice mode; omitted when unset

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (m; messages)
			arr ~= m.toJson();
		j["messages"] = arr;
		// `maxTokens` is REQUIRED by CreateMessageRequestParams in every spec
		// version (schema.ts: `maxTokens: number;`, no `?`). Refuse to serialize a
		// request that would omit it rather than silently emit spec-invalid params.
		if (maxTokens.isNull)
			throw invalidParams("CreateMessageRequest.maxTokens is required and must be set");
		if (!modelPreferences.empty)
			j["modelPreferences"] = modelPreferences.toJson();
		if (!systemPrompt.isNull)
			j["systemPrompt"] = systemPrompt.get;
		if (!includeContext.isNull)
			j["includeContext"] = includeContext.get;
		if (!temperature.isNull)
			j["temperature"] = temperature.get;
		if (!maxTokens.isNull)
			j["maxTokens"] = maxTokens.get;
		if (stopSequences.length)
		{
			Json s = Json.emptyArray;
			foreach (seq; stopSequences)
				s ~= Json(seq);
			j["stopSequences"] = s;
		}
		if (metadata.type != Json.Type.undefined)
			j["metadata"] = metadata;
		if (tools.length)
		{
			Json t = Json.emptyArray;
			foreach (tool; tools)
				t ~= tool.toJson();
			j["tools"] = t;
		}
		if (!toolChoice.empty)
			j["toolChoice"] = toolChoice.toJson();
		return j;
	}

	static CreateMessageRequest fromJson(Json j) @safe
	{
		CreateMessageRequest r;
		if ("messages" in j && j["messages"].type == Json.Type.array)
			foreach (i; 0 .. j["messages"].length)
				r.messages ~= SamplingMessage.fromJson(j["messages"][i]);
		if ("modelPreferences" in j && j["modelPreferences"].type == Json.Type.object)
			r.modelPreferences = ModelPreferences.fromJson(j["modelPreferences"]);
		if ("systemPrompt" in j && j["systemPrompt"].type == Json.Type.string)
			r.systemPrompt = j["systemPrompt"].get!string;
		if ("includeContext" in j && j["includeContext"].type == Json.Type.string)
			r.includeContext = j["includeContext"].get!string;
		if ("temperature" in j && j["temperature"].type != Json.Type.undefined
				&& j["temperature"].type != Json.Type.null_)
			r.temperature = j["temperature"].to!double;
		if ("maxTokens" in j && j["maxTokens"].type == Json.Type.int_)
			r.maxTokens = j["maxTokens"].get!long;
		if ("stopSequences" in j && j["stopSequences"].type == Json.Type.array)
			foreach (i; 0 .. j["stopSequences"].length)
				r.stopSequences ~= j["stopSequences"][i].get!string;
		if ("tools" in j && j["tools"].type == Json.Type.array)
			foreach (i; 0 .. j["tools"].length)
				r.tools ~= Tool.fromJson(j["tools"][i]);
		if ("toolChoice" in j && j["toolChoice"].type == Json.Type.object)
			r.toolChoice = ToolChoice.fromJson(j["toolChoice"]);
		if ("metadata" in j)
			r.metadata = j["metadata"];
		return r;
	}
}

/// Validate a `sampling/createMessage` request's `messages` against the
/// tool-result message-content constraints in client/sampling §Tool Result
/// Messages and §Tool Use and Result Balance:
///
/// - A `user` message that contains any `tool_result` content block MUST
///   contain ONLY `tool_result` blocks (no text/image/audio mixed in).
/// - Every `assistant` message that contains `tool_use` blocks MUST be
///   immediately followed by a `user` message that consists entirely of
///   `tool_result` blocks, with each `tool_use` `id` matched by a
///   `tool_result` `toolUseId`, before any other message.
///
/// On violation throws an `McpException` with the spec's `-32602` (Invalid
/// params) code; the message distinguishes "Tool result missing in request"
/// from "Tool results mixed with other content". A well-formed (or
/// tool-free) request returns normally.
///
/// `params` is the raw `sampling/createMessage` params JSON — the same value
/// passed to a client `onSampling` delegate — so a delegate can call this as a
/// one-liner before forwarding to its model. Content blocks may be a single
/// object or an array of blocks; both shapes are accepted.
void validateSamplingMessages(Json params) @safe
{
	if (params.type != Json.Type.object || "messages" !in params)
		return;
	auto msgs = params["messages"];
	if (msgs.type != Json.Type.array)
		return;

	// Normalize a message's `content` to a list of content-block objects.
	static Json[] blocksOf(Json msg) @safe
	{
		Json[] blocks;
		if (msg.type != Json.Type.object || "content" !in msg)
			return blocks;
		auto c = msg["content"];
		if (c.type == Json.Type.array)
			foreach (i; 0 .. c.length)
				blocks ~= c[i];
		else
			blocks ~= c;
		return blocks;
	}

	static string blockType(Json b) @safe
	{
		return (b.type == Json.Type.object && "type" in b && b["type"].type == Json.Type.string) ? b["type"]
			.get!string : "";
	}

	foreach (mi; 0 .. msgs.length)
	{
		auto msg = msgs[mi];
		const role = (msg.type == Json.Type.object && "role" in msg
				&& msg["role"].type == Json.Type.string) ? msg["role"].get!string : "";
		auto blocks = blocksOf(msg);

		// §Tool Result Messages: a user message containing any tool_result
		// block must contain ONLY tool_result blocks.
		if (role == "user")
		{
			bool hasToolResult, hasOther;
			foreach (b; blocks)
			{
				if (blockType(b) == "tool_result")
					hasToolResult = true;
				else
					hasOther = true;
			}
			if (hasToolResult && hasOther)
				throw invalidParams("Tool results mixed with other content");
		}

		// §Tool Use and Result Balance: every assistant message with tool_use
		// blocks must be followed by a user message that is entirely
		// tool_result blocks, each tool_use id matched by a toolUseId.
		if (role == "assistant")
		{
			string[] toolUseIds;
			foreach (b; blocks)
				if (blockType(b) == "tool_use")
					toolUseIds ~= (b.type == Json.Type.object && "id" in b
							&& b["id"].type == Json.Type.string) ? b["id"].get!string : "";
			if (toolUseIds.length == 0)
				continue;

			if (mi + 1 >= msgs.length)
				throw invalidParams("Tool result missing in request");
			auto next = msgs[mi + 1];
			const nextRole = (next.type == Json.Type.object && "role" in next
					&& next["role"].type == Json.Type.string) ? next["role"].get!string : "";
			auto nextBlocks = blocksOf(next);
			if (nextRole != "user" || nextBlocks.length == 0)
				throw invalidParams("Tool result missing in request");

			bool[string] resultIds;
			foreach (b; nextBlocks)
			{
				if (blockType(b) != "tool_result")
					throw invalidParams("Tool results mixed with other content");
				const id = (b.type == Json.Type.object && "toolUseId" in b
						&& b["toolUseId"].type == Json.Type.string) ? b["toolUseId"].get!string
					: "";
				resultIds[id] = true;
			}
			foreach (id; toolUseIds)
				if (id !in resultIds)
					throw invalidParams("Tool result missing in request");
		}
	}
}

/// The reason a sampling completion stopped. `endTurn`/`stopSequence`/
/// `maxTokens` are defined for all spec versions; `toolUse` is added by the
/// tool-enabled sampling revisions. Servers may also receive other
/// provider-specific strings — see `stopReasonFromString`.
enum StopReason
{
	endTurn,
	stopSequence,
	maxTokens,
	toolUse
}

/// The spec wire string for a `StopReason`.
string toWire(StopReason r) @safe
{
	final switch (r)
	{
	case StopReason.endTurn:
		return "endTurn";
	case StopReason.stopSequence:
		return "stopSequence";
	case StopReason.maxTokens:
		return "maxTokens";
	case StopReason.toolUse:
		return "toolUse";
	}
}

/// Parse a wire stop-reason string into a `StopReason`. Returns null for
/// provider-specific values not in the enum (the raw string is then preserved
/// in `CreateMessageResult.stopReason`).
Nullable!StopReason stopReasonFromString(string s) @safe
{
	switch (s)
	{
	case "endTurn":
		return nullable(StopReason.endTurn);
	case "stopSequence":
		return nullable(StopReason.stopSequence);
	case "maxTokens":
		return nullable(StopReason.maxTokens);
	case "toolUse":
		return nullable(StopReason.toolUse);
	default:
		return Nullable!StopReason.init;
	}
}

/// Result of a `sampling/createMessage` request, returned by the client. Parse
/// the client's reply with `fromJson`; build one (client side) with the
/// constructor-style fields and `toJson`. `stopReason` is the raw wire string
/// (which may be a known `StopReason` or a provider-specific value); use
/// `stopReasonEnum` for the typed view.
struct CreateMessageResult
{
	string role; /// "user" or "assistant" (typically "assistant")
	/// All content blocks of the reply. The spec models `content` as a single
	/// block OR an array of blocks (`SamplingMessageContentBlock |
	/// SamplingMessageContentBlock[]`); a tool-use reply (`stopReason:"toolUse"`)
	/// returns an array of `tool_use` blocks. This field holds every block so no
	/// `tool_use` id/name/input is dropped. For the common single-block reply,
	/// use the `content` accessor.
	Content[] contentBlocks;
	string model; /// the model identifier the client actually used
	string stopReason; /// raw stop-reason wire string (may be empty)
	Json meta = Json.undefined; /// optional message-level `_meta` object (CreateMessageResult extends SamplingMessage)

	/// The first (or only) content block, for the common single-block reply.
	/// Returns an empty text block when there are no blocks. For tool-use
	/// replies (which carry several `tool_use` blocks) iterate `contentBlocks`.
	Content content() const @safe
	{
		return contentBlocks.length ? contentBlocks[0].dupSelf() : Content.makeText("");
	}

	/// Set the result to a single content block (back-compat convenience).
	void content(Content c) @safe
	{
		contentBlocks = [c];
	}

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["role"] = role;
		// Preserve the single-object wire shape for the common one-block reply
		// (no change to existing output); emit an array only for multi-block
		// (tool-use) replies, both of which the spec accepts.
		if (contentBlocks.length == 1)
			j["content"] = contentBlocks[0].toJson();
		else
		{
			Json arr = Json.emptyArray;
			foreach (b; contentBlocks)
				arr ~= b.toJson();
			j["content"] = arr;
		}
		j["model"] = model;
		if (stopReason.length)
			j["stopReason"] = stopReason;
		if (meta.type == Json.Type.object)
			j["_meta"] = meta;
		return j;
	}

	static CreateMessageResult fromJson(Json j) @safe
	{
		CreateMessageResult r;
		r.role = ("role" in j) ? j["role"].get!string : "";
		// `content` may be a single block (object) or an array of blocks; accept
		// both so a tool-use reply (array of tool_use blocks) round-trips.
		if ("content" in j)
		{
			auto c = j["content"];
			if (c.type == Json.Type.array)
				foreach (i; 0 .. c.length)
					r.contentBlocks ~= Content.fromJson(c[i]);
			else
				r.contentBlocks ~= Content.fromJson(c);
		}
		r.model = ("model" in j) ? j["model"].get!string : "";
		if ("stopReason" in j && j["stopReason"].type == Json.Type.string)
			r.stopReason = j["stopReason"].get!string;
		if ("_meta" in j && j["_meta"].type == Json.Type.object)
			r.meta = j["_meta"];
		return r;
	}

	/// The typed view of `stopReason`, or null when it is empty or a
	/// provider-specific value not in the `StopReason` enum.
	Nullable!StopReason stopReasonEnum() const @safe
	{
		if (stopReason.length == 0)
			return Nullable!StopReason.init;
		return stopReasonFromString(stopReason);
	}
}

unittest  // SamplingMessage round-trips role and content
{
	auto m = SamplingMessage("user", Content.makeText("hello"));
	auto j = m.toJson();
	assert(j["role"].get!string == "user");
	assert(j["content"]["type"].get!string == "text");
	auto back = SamplingMessage.fromJson(j);
	assert(back.role == "user");
	assert(back.content.text == "hello");
}

unittest  // SamplingMessage emits and parses _meta (spec: SamplingMessage._meta)
{
	// schema.ts: `interface SamplingMessage { role; content; _meta?: MetaObject; }`
	auto m = SamplingMessage("user", Content.makeText("hi"));
	Json meta = Json.emptyObject;
	meta["x.example/k"] = "v";
	m.meta = meta;
	auto j = m.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = SamplingMessage.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // SamplingMessage omits _meta when none is set (no wire change)
{
	auto m = SamplingMessage("user", Content.makeText("hi"));
	assert("_meta" !in m.toJson());
}

unittest  // ModelPreferences emits hints and priorities; empty omits all
{
	ModelPreferences p;
	p.hints = [ModelHint("claude-3"), ModelHint("sonnet")];
	p.costPriority = 0.2;
	p.intelligencePriority = 0.9;
	auto j = p.toJson();
	assert(j["hints"].length == 2);
	assert(j["hints"][0]["name"].get!string == "claude-3");
	assert(j["costPriority"].to!double == 0.2);
	assert(j["intelligencePriority"].to!double == 0.9);
	assert("speedPriority" !in j);

	ModelPreferences e;
	assert(e.empty);
	assert(e.toJson().length == 0);
}

unittest  // ModelPreferences round-trips through fromJson
{
	ModelPreferences p;
	p.hints = [ModelHint("gemini")];
	p.speedPriority = 0.5;
	auto back = ModelPreferences.fromJson(p.toJson());
	assert(back.hints.length == 1 && back.hints[0].name == "gemini");
	assert(back.speedPriority.get == 0.5);
	assert(back.costPriority.isNull);
}

unittest  // CreateMessageRequest serializes all set params and omits unset
{
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.systemPrompt = "be terse";
	req.maxTokens = 100;
	req.temperature = 0.7;
	req.includeContext = "thisServer";
	req.stopSequences = ["STOP"];
	auto j = req.toJson();
	assert(j["messages"].length == 1);
	assert(j["systemPrompt"].get!string == "be terse");
	assert(j["maxTokens"].get!long == 100);
	assert(j["temperature"].to!double == 0.7);
	assert(j["includeContext"].get!string == "thisServer");
	assert(j["stopSequences"][0].get!string == "STOP");
	assert("modelPreferences" !in j);
	assert("metadata" !in j);
}

unittest  // CreateMessageRequest.toJson throws when the REQUIRED maxTokens is unset
{
	import mcp.protocol.errors : ErrorCode;

	// maxTokens is required by CreateMessageRequestParams in every spec version
	// (schema.ts: `maxTokens: number;`). A request that never sets it must not
	// silently serialize to spec-invalid params; toJson must reject it.
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	assert(req.maxTokens.isNull);

	bool threw;
	try
		cast(void) req.toJson();
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw, "toJson must throw invalidParams when maxTokens is unset");
}

unittest  // CreateMessageRequest.toJson emits maxTokens once it is set
{
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 256;
	auto j = req.toJson();
	assert(j["maxTokens"].get!long == 256);
}

unittest  // CreateMessageRequest with modelPreferences round-trips
{
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 100; // required field
	req.modelPreferences.hints = [ModelHint("claude")];
	req.modelPreferences.intelligencePriority = 0.8;
	auto back = CreateMessageRequest.fromJson(req.toJson());
	assert(back.messages.length == 1 && back.messages[0].content.text == "hi");
	assert(back.modelPreferences.hints[0].name == "claude");
	assert(back.modelPreferences.intelligencePriority.get == 0.8);
}

unittest  // ToolChoice serializes mode and omits when unset
{
	ToolChoice c;
	assert(c.empty);
	assert(c.toJson().length == 0);

	c.mode = "required";
	auto j = c.toJson();
	assert(j["mode"].get!string == "required");
	auto back = ToolChoice.fromJson(j);
	assert(back.mode.get == "required");
}

unittest  // ToolChoice accepts each spec mode (auto/required/none)
{
	foreach (m; ["auto", "required", "none"])
	{
		ToolChoice c;
		c.mode = m;
		assert(ToolChoice.fromJson(c.toJson()).mode.get == m);
	}
}

unittest  // CreateMessageRequest emits tools and toolChoice; omits when unset
{
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("weather?"))];
	req.maxTokens = 100; // required field
	auto bare = req.toJson();
	assert("tools" !in bare);
	assert("toolChoice" !in bare);

	Tool t;
	t.name = "get_weather";
	t.description = "Get the weather";
	req.tools = [t];
	req.toolChoice.mode = "auto";
	auto j = req.toJson();
	assert(j["tools"].length == 1);
	assert(j["tools"][0]["name"].get!string == "get_weather");
	assert(j["toolChoice"]["mode"].get!string == "auto");
}

unittest  // CreateMessageRequest with tools/toolChoice round-trips
{
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 100; // required field
	Tool t;
	t.name = "calc";
	req.tools = [t];
	req.toolChoice.mode = "required";
	auto back = CreateMessageRequest.fromJson(req.toJson());
	assert(back.tools.length == 1 && back.tools[0].name == "calc");
	assert(back.toolChoice.mode.get == "required");
}

unittest  // CreateMessageResult parses role/content/model/stopReason
{
	Json j = Json.emptyObject;
	j["role"] = "assistant";
	j["content"] = Content.makeText("answer").toJson();
	j["model"] = "claude-3-5-sonnet";
	j["stopReason"] = "endTurn";
	auto r = CreateMessageResult.fromJson(j);
	assert(r.role == "assistant");
	assert(r.content.text == "answer");
	assert(r.model == "claude-3-5-sonnet");
	assert(r.stopReason == "endTurn");
	assert(r.stopReasonEnum.get == StopReason.endTurn);
}

unittest  // CreateMessageResult round-trips through toJson
{
	auto r = CreateMessageResult("assistant", [Content.makeText("hi")], "m", "maxTokens");
	auto back = CreateMessageResult.fromJson(r.toJson());
	assert(back.role == "assistant" && back.content.text == "hi");
	assert(back.model == "m" && back.stopReasonEnum.get == StopReason.maxTokens);
}

unittest  // CreateMessageResult emits and parses _meta (extends SamplingMessage._meta)
{
	// CreateMessageResult extends SamplingMessage, so it may carry `_meta`.
	auto r = CreateMessageResult("assistant", [Content.makeText("hi")], "m", "endTurn");
	Json meta = Json.emptyObject;
	meta["x.example/k"] = "v";
	r.meta = meta;
	auto j = r.toJson();
	assert(j["_meta"]["x.example/k"].get!string == "v");
	auto back = CreateMessageResult.fromJson(j);
	assert(back.meta["x.example/k"].get!string == "v");
}

unittest  // CreateMessageResult omits _meta when none is set (no wire change)
{
	auto r = CreateMessageResult("assistant", [Content.makeText("hi")], "m", "endTurn");
	assert("_meta" !in r.toJson());
}

unittest  // single-content reply keeps the single-object wire shape (no regress)
{
	auto r = CreateMessageResult("assistant", [Content.makeText("hi")], "m", "endTurn");
	auto j = r.toJson();
	// content must be a single object, exactly as before this change.
	assert(j["content"].type == Json.Type.object);
	assert(j["content"]["type"].get!string == "text");
	assert(j["content"]["text"].get!string == "hi");
}

unittest  // a tool_use reply (content array, stopReason toolUse) round-trips
{
	// The spec's "Sampling with Tools" response: content is an ARRAY of
	// tool_use blocks with stopReason "toolUse".
	Json input = Json.emptyObject;
	input["location"] = "Paris";
	Json b1 = Json.emptyObject;
	b1["type"] = "tool_use";
	b1["id"] = "call_1";
	b1["name"] = "get_weather";
	b1["input"] = input;
	Json b2 = Json.emptyObject;
	b2["type"] = "tool_use";
	b2["id"] = "call_2";
	b2["name"] = "get_time";
	b2["input"] = Json.emptyObject;

	Json j = Json.emptyObject;
	j["role"] = "assistant";
	j["content"] = Json([b1, b2]);
	j["model"] = "claude";
	j["stopReason"] = "toolUse";

	auto r = CreateMessageResult.fromJson(j);
	assert(r.stopReasonEnum.get == StopReason.toolUse);
	assert(r.contentBlocks.length == 2);
	assert(r.contentBlocks[0].kind == ContentKind.toolUse);
	assert(r.contentBlocks[0].id == "call_1");
	assert(r.contentBlocks[0].name == "get_weather");
	assert(r.contentBlocks[0].input["location"].get!string == "Paris");
	assert(r.contentBlocks[1].id == "call_2");
	assert(r.contentBlocks[1].name == "get_time");

	// Re-serializing a multi-block reply emits an array of tool_use blocks.
	auto back = r.toJson();
	assert(back["content"].type == Json.Type.array);
	assert(back["content"].length == 2);
	assert(back["content"][0]["name"].get!string == "get_weather");
}

unittest  // a single tool_use block reply preserves id/name/input
{
	Json input = Json.emptyObject;
	input["q"] = "x";
	Json b = Json.emptyObject;
	b["type"] = "tool_use";
	b["id"] = "c1";
	b["name"] = "search";
	b["input"] = input;
	Json j = Json.emptyObject;
	j["role"] = "assistant";
	j["content"] = b; // single object, not an array
	j["model"] = "m";
	j["stopReason"] = "toolUse";

	auto r = CreateMessageResult.fromJson(j);
	assert(r.contentBlocks.length == 1);
	assert(r.content.kind == ContentKind.toolUse);
	assert(r.content.id == "c1");
	assert(r.content.name == "search");
	assert(r.content.input["q"].get!string == "x");
}

unittest  // StopReason wire mapping is exact and reversible
{
	assert(StopReason.endTurn.toWire == "endTurn");
	assert(StopReason.stopSequence.toWire == "stopSequence");
	assert(StopReason.maxTokens.toWire == "maxTokens");
	assert(StopReason.toolUse.toWire == "toolUse");
	assert(stopReasonFromString("toolUse").get == StopReason.toolUse);
}

unittest  // unknown / provider-specific stop reasons stay as raw string
{
	auto v = stopReasonFromString("contentFilter");
	assert(v.isNull);
	CreateMessageResult r;
	r.stopReason = "contentFilter";
	assert(r.stopReasonEnum.isNull);
	assert(r.stopReason == "contentFilter");
}

version (unittest)
{
	import mcp.protocol.errors : ErrorCode;

	// Build a sampling params object from raw message JSON objects.
	private Json samplingParams(Json[] messages...) @safe
	{
		Json p = Json.emptyObject;
		Json arr = Json.emptyArray;
		foreach (m; messages)
			arr ~= m;
		p["messages"] = arr;
		return p;
	}

	private Json textMsg(string role, string text) @safe
	{
		Json b = Json.emptyObject;
		b["type"] = "text";
		b["text"] = text;
		Json m = Json.emptyObject;
		m["role"] = role;
		m["content"] = Json([b]);
		return m;
	}

	private Json toolUse(string id, string name) @safe
	{
		Json b = Json.emptyObject;
		b["type"] = "tool_use";
		b["id"] = id;
		b["name"] = name;
		b["input"] = Json.emptyObject;
		return b;
	}

	private Json toolResult(string toolUseId) @safe
	{
		Json b = Json.emptyObject;
		b["type"] = "tool_result";
		b["toolUseId"] = toolUseId;
		b["content"] = Json.emptyArray;
		return b;
	}

	private Json msg(string role, Json[] blocks...) @safe
	{
		Json arr = Json.emptyArray;
		foreach (b; blocks)
			arr ~= b;
		Json m = Json.emptyObject;
		m["role"] = role;
		m["content"] = arr;
		return m;
	}
}

unittest  // a plain text conversation with no tool use validates cleanly
{
	auto p = samplingParams(textMsg("user", "hi"), textMsg("assistant", "hello"));
	validateSamplingMessages(p); // must not throw
}

unittest  // a user message mixing tool_result with text is rejected (-32602)
{
	Json text = Json.emptyObject;
	text["type"] = "text";
	text["text"] = "extra";
	auto bad = msg("user", toolResult("call_1"), text);
	auto p = samplingParams(msg("assistant", toolUse("call_1", "get_weather")), bad);

	bool threw;
	try
		validateSamplingMessages(p);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
		assert(e.msg == "Tool results mixed with other content");
	}
	assert(threw);
}

unittest  // a tool_use with no following tool_result is rejected (-32602)
{
	auto p = samplingParams(msg("assistant", toolUse("call_1", "get_weather")));

	bool threw;
	try
		validateSamplingMessages(p);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
		assert(e.msg == "Tool result missing in request");
	}
	assert(threw);
}

unittest  // an unmatched toolUseId among parallel tool uses is rejected
{
	auto p = samplingParams(msg("assistant", toolUse("call_1", "get_weather"),
			toolUse("call_2", "get_weather")), msg("user", toolResult("call_1")));

	bool threw;
	try
		validateSamplingMessages(p);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
		assert(e.msg == "Tool result missing in request");
	}
	assert(threw);
}

unittest  // balanced parallel tool use + matching results validates cleanly
{
	auto p = samplingParams(textMsg("user", "weather in Paris and London?"),
			msg("assistant", toolUse("call_1",
				"get_weather"), toolUse("call_2", "get_weather")), msg("user",
				toolResult("call_1"), toolResult("call_2")), textMsg("assistant", "both nice"));
	validateSamplingMessages(p); // must not throw
}

unittest  // a tool_use followed by an assistant message (not user) is rejected
{
	auto p = samplingParams(msg("assistant", toolUse("call_1", "get_weather")),
			textMsg("assistant", "ignoring tools"));

	bool threw;
	try
		validateSamplingMessages(p);
	catch (McpException e)
	{
		threw = true;
		assert(e.msg == "Tool result missing in request");
	}
	assert(threw);
}

unittest  // a lone user tool_result message (no other content) is allowed
{
	auto p = samplingParams(msg("user", toolResult("call_1")));
	validateSamplingMessages(p); // single-block tool_result-only user msg is fine
}

unittest  // missing/empty messages is a no-op (nothing to validate)
{
	validateSamplingMessages(Json.emptyObject);
	Json p = Json.emptyObject;
	p["messages"] = Json.emptyArray;
	validateSamplingMessages(p);
}
