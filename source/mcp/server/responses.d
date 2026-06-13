/// The tool/prompt handler outcome DTOs returned by `McpServer` handlers.
///
/// `ToolResponse` and `PromptResponse` are the values a handler returns: either
/// a final result, or — on a stateless (MRTR) request — a set of `InputRequest`s
/// the client must satisfy and resubmit. They form part of the `api.reflection`
/// registration contract and are re-exported from `mcp.server.server` so the
/// public surface reaching them through `McpServer` is unchanged.
module mcp.server.responses;

import vibe.data.json : Json;

import mcp.protocol.errors : internalError;
import mcp.protocol.versions : ProtocolVersion, isModern, usesMRTR;
import mcp.protocol.types : CallToolResult, GetPromptResult, Content;
import mcp.protocol.mrtr : InputRequest, InputRequiredResult;
import mcp.server.context : RequestContext;

@safe:

/// A tool handler receiving the parsed arguments and the per-request context.
alias ToolHandler = CallToolResult delegate(Json arguments, RequestContext ctx) @safe;

/// A tool handler that may, on a stateless (MRTR) request, ask the client for
/// more input instead of returning a final result. See `ToolResponse`.
alias MrtrToolHandler = ToolResponse delegate(Json arguments, RequestContext ctx) @safe;

/// The MRTR (input-required) machinery shared by `ToolResponse` and
/// `PromptResponse`: the `needsInput_`/`required_` state, the
/// `needsInput`/`inputRequests`/`requestState` accessors, the two non-typed
/// `inputRequired` factories, and `withInputRequests`/`toJson`. Both response
/// types carry an `InputRequiredResult required_` plus a `result_` final result
/// of their respective type; `toJson` switches on `needsInput_`. The mixin keeps
/// these in lockstep so MRTR edits land on both. The genuine divergences —
/// `forVersion` (throw vs return on a non-MRTR peer) and `ToolResponse`'s typed
/// `complete(T)`/`inputRequired(T)` helpers — stay per-struct.
mixin template InputRequiredPart()
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
	/// (SEP-2322): a stateless draft server encodes whatever context it needs
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

	/// The JSON-RPC `result` payload (the final result, or an
	/// `InputRequiredResult`).
	Json toJson() const @safe
	{
		return needsInput_ ? required_.toJson() : result_.toJson();
	}
}

/// The outcome of a tool call: either the final `CallToolResult`, or — on a
/// stateless (MRTR) request — a set of `InputRequest`s the client must satisfy
/// and resubmit. There is no suspension or shared state: `inputRequired` simply
/// ends this request, and the client opens a fresh one carrying the answers.
struct ToolResponse
{
	private CallToolResult result_;

	mixin InputRequiredPart ireq;
	// Merge the mixed-in non-typed `inputRequired` factories into the same
	// overload set as the typed `inputRequired(T)` declared below; without this
	// the local template would hide the mixin's overloads.
	alias inputRequired = ireq.inputRequired;

	/// The handler is done; `r` is the final result.
	static ToolResponse complete(CallToolResult r) @safe
	{
		ToolResponse t;
		t.result_ = r;
		return t;
	}

	/// Convenience: build a final result from a typed `value`. Serialises `value`
	/// to JSON and uses it as the result's `structuredContent`, defaulting the
	/// human-readable `content` to a single text block holding that same JSON.
	/// The serialisation is done inline here (independent of any
	/// `CallToolResult.structured!T` helper) so this overload stays compilable on
	/// its own.
	static ToolResponse complete(T)(T value) @safe if (!is(T : CallToolResult))
	{
		import vibe.data.json : serializeToJson;

		Json sc = serializeToJson(value);
		CallToolResult r;
		r.structuredContent = sc;
		r.content = [Content.makeText(sc.toString())];
		return ToolResponse.complete(r);
	}

	/// As `inputRequired`, but encodes a typed `state` as the opaque
	/// `requestState`. Serialises `state` to JSON and stores its string form.
	/// ENCODING CONTRACT: the stored value is `serializeToJson(state).toString()`,
	/// which `RequestContext.requestStateAs!T()` decodes via
	/// `deserializeJson!T(parseJsonString(state))`. Constrained off `string` so it
	/// does not collide with the verbatim-string overload above.
	static ToolResponse inputRequired(T)(InputRequest[] requests, T state) @safe
			if (!is(T : string))
	{
		import vibe.data.json : serializeToJson;

		return ToolResponse.inputRequired(requests, serializeToJson(state).toString());
	}

	/// The handler created an asynchronous task: `j` is the `CreateTaskResult`
	/// (`resultType:"task"`) returned verbatim in lieu of a `CallToolResult`. Task
	/// results are draft-only; `forVersion` rejects them on a non-draft session.
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
	/// outcome, else the `InputRequiredResult` or final `CallToolResult`. Shadows
	/// the mixed-in `toJson` to add the task case.
	Json toJson() const @safe
	{
		if (isTask_)
			return taskResult_;
		return needsInput_ ? required_.toJson() : result_.toJson();
	}

	/// Project the final `CallToolResult` to the negotiated protocol version so
	/// version-gated fields are not emitted to peers that don't understand them.
	/// `CallToolResult.structuredContent` is a 2025-06-18+ field and is stripped
	/// for 2024-11-05 / 2025-03-26. An `InputRequiredResult` is draft-only (MRTR):
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
				throw internalError(
						"tools/call handler returned a task result on a non-draft session");
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
/// — on a stateless (MRTR) draft request — a set of `InputRequest`s the client
/// must satisfy and resubmit. This mirrors `ToolResponse` for the prompts path:
/// the draft schema types `GetPromptResultResponse.result` as
/// `GetPromptResult | InputRequiredResult`, so a prompt handler that needs more
/// input ends the request with `inputRequired(...)` and the client opens a fresh
/// `prompts/get` carrying the matching `inputResponses` (and any `requestState`).
struct PromptResponse
{
	private GetPromptResult result_;

	mixin InputRequiredPart;

	/// The handler is done; `r` is the final prompt result.
	static PromptResponse complete(GetPromptResult r) @safe
	{
		PromptResponse p;
		p.result_ = r;
		return p;
	}

	/// Project the final `GetPromptResult` to the negotiated protocol version so
	/// version-gated message content (audio/resource_link/tool_use/tool_result
	/// plus content-level `_meta`/`lastModified`) is not emitted to peers that do
	/// not understand it. Mirrors `ToolResponse.forVersion`: an
	/// `InputRequiredResult` is draft-only (MRTR) and carries no version-gated
	/// content, so it is returned unchanged.
	PromptResponse forVersion(ProtocolVersion v) const @safe
	{
		if (needsInput_)
			return PromptResponse.inputRequired(required_.inputRequests.dup,
					required_.requestState);
		return PromptResponse.complete(result_.forVersion(v));
	}
}

/// A prompt handler that may, on a stateless (MRTR) draft request, ask the client
/// for more input instead of returning a final result. See `PromptResponse`.
alias MrtrPromptHandler = PromptResponse delegate(Json arguments, RequestContext ctx) @safe;
