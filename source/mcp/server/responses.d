/// The handler signatures `McpServer` registers and the outcome DTOs its tool
/// and prompt handlers return.
///
/// `ToolResponse` and `PromptResponse` are the values a handler returns: either
/// a final result, or — on a stateless (MRTR) request — a set of `InputRequest`s
/// the client must satisfy and resubmit. They form part of the `api.reflection`
/// registration contract and are re-exported by the top-level `mcp` module.
module mcp.server.responses;

import vibe.data.json : Json;

import mcp.protocol.errors : internalError;
import mcp.protocol.versions : ProtocolVersion, isModern, usesMRTR;
import mcp.protocol.types : CallToolResult, GetPromptResult, Content, ResourceContents;
import mcp.protocol.mrtr : InputRequest, InputRequiredResult;
import mcp.server.context : RequestContext;

@safe:

/// A tool execution failure whose message is written for the client. Thrown from
/// a tool handler, it becomes a `CallToolResult` with `isError: true` and the
/// message as its text content, so the model can see what went wrong and
/// retry. Any other non-`McpException` a tool handler throws is logged
/// server-side and reported as a generic "Internal error" tool result (its
/// message is shown only after `McpServer.exposeInternalErrors`), since such a
/// message can carry file paths, SQL, or other internals.
class ToolError : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe
	{
		super(msg, file, line);
	}
}

/// A tool handler receiving the parsed arguments and the per-request context.
alias ToolHandler = CallToolResult delegate(Json arguments, RequestContext ctx) @safe;

/// A tool handler that may, on a stateless (MRTR) request, ask the client for
/// more input instead of returning a final result. See `ToolResponse`.
alias MrtrToolHandler = ToolResponse delegate(Json arguments, RequestContext ctx) @safe;

/// A prompt handler receiving the raw `Json arguments` and the per-request
/// `RequestContext`, always producing a final result. See `MrtrPromptHandler`
/// for one that may ask the client for more input.
alias PromptHandler = GetPromptResult delegate(Json arguments, RequestContext ctx) @safe;

/// A prompt handler that may, on a stateless (MRTR) modern request, ask the client
/// for more input instead of returning a final result. See `PromptResponse`.
alias MrtrPromptHandler = PromptResponse delegate(Json arguments, RequestContext ctx) @safe;

/// A direct resource reader receiving the per-request `RequestContext` (so it
/// can log, observe cancellation, or elicit through the real request channel).
/// It returns every content item of the `resources/read` result.
alias ResourceReader = ResourceContents[]delegate(RequestContext ctx) @safe;

/// A resource template reader receiving the concrete URI, the captured `{var}`
/// parameters, and the per-request `RequestContext` (so a template handler can
/// log, observe cancellation, or elicit through the real request channel).
/// It returns every content item of the `resources/read` result.
alias TemplateReader = ResourceContents[]delegate(string uri,
		string[string] params, RequestContext ctx) @safe;

/// The MRTR (input-required) machinery shared by `ToolResponse` and
/// `PromptResponse`: the `needsInput_`/`required_` state, the
/// `needsInput`/`inputRequests`/`requestState` accessors, the `inputRequired`
/// factories (verbatim and typed `requestState`), and
/// `withInputRequests`. Both response types carry an `InputRequiredResult
/// required_` plus a `result_` final result of their respective type. The mixin
/// keeps these in lockstep so MRTR edits land on both. The genuine divergences —
/// `ToolResponse`'s task outcome and typed `complete(T)` helper, and each
/// type's `toJson` — stay per-struct.
private mixin template InputRequiredPart()
{
	private bool needsInput_;
	private InputRequiredResult required_;

	/// The handler needs input; the client must gather it and resubmit with the
	/// matching `inputResponses`.
	static typeof(this) inputRequired(InputRequest[] requests) @safe
	{
		typeof(this) r;
		r.needsInput_ = true;
		r.required_.inputRequests = requests;
		return r;
	}

	/// As `inputRequired`, but also attaches an opaque `requestState`
	/// (SEP-2322): a modern server encodes whatever context it needs
	/// to resume the call into this blob, which the client echoes verbatim on
	/// the retry and the handler reads back via `RequestContext.requestState`.
	static typeof(this) inputRequired(InputRequest[] requests, string requestState) @safe
	{
		typeof(this) r;
		r.needsInput_ = true;
		r.required_.inputRequests = requests;
		r.required_.requestState = requestState;
		return r;
	}

	/// As `inputRequired`, but encodes a typed `state` as the opaque
	/// `requestState`. Serialises `state` to JSON and stores its string form.
	/// ENCODING CONTRACT: the stored value is `serializeToJson(state).toString()`,
	/// which `RequestContext.requestStateAs!T()` decodes via
	/// `deserializeJson!T(parseJsonString(state))`. Constrained off `string` so it
	/// does not collide with the verbatim-string overload above.
	static typeof(this) inputRequired(T)(InputRequest[] requests, T state) @safe
			if (!is(T : string))
	{
		import vibe.data.json : serializeToJson;

		return inputRequired(requests, serializeToJson(state).toString());
	}

	/// Whether this outcome asks the client for more input.
	bool needsInput() const @safe
	{
		return needsInput_;
	}

	/// The MRTR `inputRequests` this outcome carries (empty unless `needsInput`).
	/// Read by the dispatch path so it can drop requests whose kind the client
	/// never declared.
	const(InputRequest)[] inputRequests() const @safe
	{
		return required_.inputRequests;
	}

	/// The opaque MRTR `requestState` this outcome carries (empty unless set).
	string requestState() const @safe
	{
		return required_.requestState;
	}

	/// Return a copy of this input-required outcome with its `inputRequests`
	/// replaced by `reqs` (preserving `requestState`). Used by the dispatch path
	/// after filtering out unsupported request kinds.
	typeof(this) withInputRequests(InputRequest[] reqs) const @safe
	{
		return typeof(this).inputRequired(reqs, required_.requestState);
	}
}

/// The outcome of a tool call: either the final `CallToolResult`, or — on a
/// stateless (MRTR) request — a set of `InputRequest`s the client must satisfy
/// and resubmit. There is no suspension or shared state: `inputRequired` simply
/// ends this request, and the client opens a fresh one carrying the answers.
struct ToolResponse
{
	private CallToolResult result_;

	mixin InputRequiredPart;

	/// The handler is done; `r` is the final result. A `CallToolResult` carrying
	/// a task handle or MRTR `inputRequests`/`requestState` is classified as
	/// `task` or `inputRequired`, so it gets the same capability filtering,
	/// validation, and version gating as one built through those factories.
	static ToolResponse complete(CallToolResult r) @safe
	{
		if (r.isTask)
			return ToolResponse.task(r.toJson());
		if (r.isInputRequired)
			return ToolResponse.inputRequired(r.inputRequests, r.requestState);
		ToolResponse t;
		t.result_ = r;
		return t;
	}

	/// Convenience: build a final result from a typed `value` via
	/// `CallToolResult.structured`, so a fieldwise struct becomes the
	/// `structuredContent` object and any other value is wrapped under `result`,
	/// with `content` defaulting to a text block holding that same JSON.
	static ToolResponse complete(T)(T value) @safe if (!is(T : CallToolResult))
	{
		return ToolResponse.complete(CallToolResult.structured(value));
	}

	/// The handler created an asynchronous task: `j` is the `CreateTaskResult`
	/// (`resultType:"task"`) returned verbatim in lieu of a `CallToolResult`. Task
	/// results are modern-only; `forVersion` rejects them on a legacy session.
	static ToolResponse task(Json j) @safe
	{
		ToolResponse t;
		t.isTask_ = true;
		t.taskResult_ = j;
		return t;
	}

	/// Whether this outcome is an asynchronous task handle (`CreateTaskResult`).
	bool isTask() const @safe
	{
		return isTask_;
	}

	private bool isTask_;
	private Json taskResult_;

	/// The JSON-RPC `result` payload: the verbatim `CreateTaskResult` for a task
	/// outcome, else the `InputRequiredResult` or final `CallToolResult`.
	Json toJson() const @safe
	{
		if (isTask_)
			return taskResult_;
		return needsInput_ ? required_.toJson() : result_.toJson();
	}

	/// Project the final `CallToolResult` to the negotiated protocol version so
	/// version-gated fields are not emitted to peers that don't understand them.
	/// `CallToolResult.structuredContent` is a 2025-06-18+ field and is stripped
	/// for 2024-11-05 / 2025-03-26. An `InputRequiredResult` is modern-only (MRTR):
	/// its `{inputRequests, [requestState]}` shape carries no `content` and exists
	/// only on versions whose schema permits it. Emitting it to a non-MRTR peer,
	/// whose `CallToolResult` requires `content`, is a programming error (a handler
	/// ignoring the documented stateless contract), so reject it rather than
	/// projecting an off-schema result onto the wire.
	ToolResponse forVersion(ProtocolVersion v) const @safe
	{
		if (isTask_)
		{
			if (!v.isModern)
				throw internalError("tools/call handler returned a task result on a legacy session");
			return ToolResponse.task(taskResult_);
		}
		if (needsInput_)
		{
			if (!v.usesMRTR)
				throw internalError("tools/call handler returned an input-required result on a session that does not support MRTR");
			return ToolResponse.inputRequired(required_.inputRequests.dup, required_.requestState);
		}
		return ToolResponse.complete(result_.forVersion(v));
	}
}

/// The outcome of a `prompts/get` call: either the final `GetPromptResult`, or
/// — on a stateless (MRTR) modern request — a set of `InputRequest`s the client
/// must satisfy and resubmit. This mirrors `ToolResponse` for the prompts path:
/// the 2026-07-28 schema types `GetPromptResultResponse.result` as
/// `GetPromptResult | InputRequiredResult`, so a prompt handler that needs more
/// input ends the request with `inputRequired(...)` and the client opens a fresh
/// `prompts/get` carrying the matching `inputResponses` (and any `requestState`).
struct PromptResponse
{
	private GetPromptResult result_;

	mixin InputRequiredPart;

	/// The handler is done; `r` is the final prompt result. A `GetPromptResult`
	/// carrying MRTR `inputRequests`/`requestState` is classified as
	/// `inputRequired`, so it gets the same capability filtering and version
	/// gating as one built through that factory.
	static PromptResponse complete(GetPromptResult r) @safe
	{
		if (r.isInputRequired)
			return PromptResponse.inputRequired(r.inputRequests, r.requestState);
		PromptResponse p;
		p.result_ = r;
		return p;
	}

	/// The JSON-RPC `result` payload (the final result, or an
	/// `InputRequiredResult`).
	Json toJson() const @safe
	{
		return needsInput_ ? required_.toJson() : result_.toJson();
	}

	/// Project the final `GetPromptResult` to the negotiated protocol version so
	/// version-gated message content (audio/resource_link/tool_use/tool_result
	/// plus content-level `_meta`/`lastModified`) is not emitted to peers that do
	/// not understand it. Mirrors `ToolResponse.forVersion`: an
	/// `InputRequiredResult` is modern-only (MRTR) and has no `messages`, so
	/// emitting it to a non-MRTR peer is rejected rather than sent off-schema.
	PromptResponse forVersion(ProtocolVersion v) const @safe
	{
		if (needsInput_)
		{
			if (!v.usesMRTR)
				throw internalError("prompts/get handler returned an input-required result on a session that does not support MRTR");
			return PromptResponse.inputRequired(required_.inputRequests.dup,
					required_.requestState);
		}
		return PromptResponse.complete(result_.forVersion(v));
	}
}

unittest  // PromptResponse.complete classifies a GetPromptResult carrying MRTR fields as input-required
{
	GetPromptResult r;
	r.inputRequests = [InputRequest("q1", "elicitation", Json.emptyObject)];
	r.requestState = "s1";
	auto pr = PromptResponse.complete(r);
	assert(pr.needsInput);
	assert(pr.inputRequests.length == 1);
	assert(pr.requestState == "s1");
}

unittest  // PromptResponse.forVersion rejects an input-required result on a non-MRTR session
{
	import std.exception : assertThrown, assertNotThrown;
	import mcp.protocol.errors : McpException;

	auto pr = PromptResponse.inputRequired([
		InputRequest("q1", "elicitation", Json.emptyObject)
	]);
	assertThrown!McpException(pr.forVersion(ProtocolVersion.v2025_11_25));
	assertNotThrown(pr.forVersion(ProtocolVersion.v2026_07_28));
}

unittest  // PromptResponse.inputRequired(T) encodes a typed requestState like ToolResponse's
{
	import vibe.data.json : parseJsonString;

	static struct Step
	{
		int round;
		string topic;
	}

	auto reqs = [InputRequest("q1", "elicitation", Json.emptyObject)];
	auto pr = PromptResponse.inputRequired(reqs, Step(2, "d"));
	assert(pr.needsInput);
	auto state = parseJsonString(pr.requestState);
	assert(state["round"].get!int == 2);
	assert(state["topic"].get!string == "d");
	assert(pr.requestState == ToolResponse.inputRequired(reqs, Step(2, "d")).requestState);
	assert(PromptResponse.inputRequired(reqs, "raw").requestState == "raw");
}

unittest  // ToolResponse.complete(T) wraps a non-struct value under `result`
{
	auto r = ToolResponse.complete(42).toJson();
	assert(r["structuredContent"].type == Json.Type.object);
	assert(r["structuredContent"]["result"].get!int == 42);
}

unittest  // ToolResponse.complete(T) emits a fieldwise struct as the object itself
{
	static struct Point
	{
		int x;
		int y;
	}

	auto r = ToolResponse.complete(Point(1, 2)).toJson();
	assert(r["structuredContent"]["x"].get!int == 1);
	assert(r["structuredContent"]["y"].get!int == 2);
}
