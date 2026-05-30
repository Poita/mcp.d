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
import mcp.protocol.types : Content;

@safe:

/// A single message in a sampling conversation. `role` is "user" or
/// "assistant"; `content` reuses the SDK's `Content` block (text/image/audio).
struct SamplingMessage
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

    static SamplingMessage fromJson(Json j) @safe
    {
        SamplingMessage m;
        m.role = ("role" in j) ? j["role"].get!string : "";
        if ("content" in j)
            m.content = Content.fromJson(j["content"]);
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

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        Json arr = Json.emptyArray;
        foreach (m; messages)
            arr ~= m.toJson();
        j["messages"] = arr;
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
        if ("metadata" in j)
            r.metadata = j["metadata"];
        return r;
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
    Content content;
    string model; /// the model identifier the client actually used
    string stopReason; /// raw stop-reason wire string (may be empty)

    Json toJson() const @safe
    {
        Json j = Json.emptyObject;
        j["role"] = role;
        j["content"] = content.toJson();
        j["model"] = model;
        if (stopReason.length)
            j["stopReason"] = stopReason;
        return j;
    }

    static CreateMessageResult fromJson(Json j) @safe
    {
        CreateMessageResult r;
        r.role = ("role" in j) ? j["role"].get!string : "";
        if ("content" in j)
            r.content = Content.fromJson(j["content"]);
        r.model = ("model" in j) ? j["model"].get!string : "";
        if ("stopReason" in j && j["stopReason"].type == Json.Type.string)
            r.stopReason = j["stopReason"].get!string;
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

unittest  // CreateMessageRequest with modelPreferences round-trips
{
    CreateMessageRequest req;
    req.messages = [SamplingMessage("user", Content.makeText("hi"))];
    req.modelPreferences.hints = [ModelHint("claude")];
    req.modelPreferences.intelligencePriority = 0.8;
    auto back = CreateMessageRequest.fromJson(req.toJson());
    assert(back.messages.length == 1 && back.messages[0].content.text == "hi");
    assert(back.modelPreferences.hints[0].name == "claude");
    assert(back.modelPreferences.intelligencePriority.get == 0.8);
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
    auto r = CreateMessageResult("assistant", Content.makeText("hi"), "m", "maxTokens");
    auto back = CreateMessageResult.fromJson(r.toJson());
    assert(back.role == "assistant" && back.content.text == "hi");
    assert(back.model == "m" && back.stopReasonEnum.get == StopReason.maxTokens);
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
