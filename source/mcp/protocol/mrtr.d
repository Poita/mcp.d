/// Multi Round-Trip Requests (MRTR, SEP-2322): the `InputRequiredResult` a
/// server returns to ask the client for input, and the `inputResponses` /
/// `requestState` the client sends back on the retried request.
module mcp.protocol.mrtr;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.sampling : CreateMessageRequest;
import mcp.protocol.errors : isValidElicitationUrl;
import mcp.protocol.jsonhelpers : tryGet, requireObject;

@safe:

/// The kind of server->client request an MRTR `InputRequest` stands in for.
/// The wire identifies it only by the request object's `method`
/// (`sampling/createMessage`, `elicitation/create`, `roots/list`); see
/// `InputRequest.type` for the short name the SDK keeps instead.
enum InputKind
{
	sampling,
	elicitation,
	roots,
}

/// One unit of input the server needs from the client to continue (replacing a
/// server-initiated `sampling/createMessage`, `elicitation/create`, or
/// `roots/list` request).
struct InputRequest
{
	string id; /// correlation id chosen by the server (the `InputRequests` map key)
	/// The SDK's short name for the request kind: "sampling", "elicitation" or
	/// "roots". It is not on the wire, which carries the full `method` instead
	/// (`methodForType`). An `InputRequest` parsed from an unrecognised method
	/// keeps that method here.
	string type;
	Json params = Json.emptyObject; /// the would-be request params

	/// The typed `InputKind` for this request's `type`, or null when the
	/// `type` is not one of the three recognised kinds.
	Nullable!InputKind kind() const @safe
	{
		switch (type)
		{
		case "sampling":
			return Nullable!InputKind(InputKind.sampling);
		case "elicitation":
			return Nullable!InputKind(InputKind.elicitation);
		case "roots":
			return Nullable!InputKind(InputKind.roots);
		default:
			return Nullable!InputKind.init;
		}
	}

	/// Build a `sampling` input-request from a typed `CreateMessageRequest` — no
	/// hand-built params `Json`.
	static InputRequest sampling(string id, CreateMessageRequest req) @safe
	{
		return InputRequest(id, "sampling", req.toJson());
	}

	/// Build a form-`elicitation` input-request from a message and an optional
	/// JSON Schema (`requestedSchema`). Form mode requires a `requestedSchema`, so
	/// without one the request carries an empty object schema (a plain
	/// confirmation). For a `requestedSchema` derived from a flat
	/// struct `T`, use `mcp.api.binding.elicitationRequest!T` (where
	/// reflection-driven schema generation lives, so this module stays free of any
	/// schema/reflection dependency).
	static InputRequest elicitation(string id, string message, Json requestedSchema = Json
			.undefined) @safe
	{
		Json p = Json.emptyObject;
		p["message"] = message;
		if (requestedSchema.type == Json.Type.object)
			p["requestedSchema"] = requestedSchema;
		else
			p["requestedSchema"] = Json([
			"type": Json("object"),
			"properties": Json.emptyObject
		]);
		return InputRequest(id, "elicitation", p);
	}

	/// Build a url-mode `elicitation` input-request: instead of a `requestedSchema`
	/// form, the client is directed to a `url` to gather input out-of-band. The
	/// modern `ElicitRequestURLParams` is `{mode:"url", message, url}` — correlation
	/// is the MRTR `InputRequest.id`, so the request carries no `elicitationId`
	/// (removed from 2026-07-28). `url` MUST be an http(s) URL with a host
	/// (`isValidElicitationUrl`);
	/// otherwise this throws a plain `Exception` (a local programming error, not
	/// a peer `-32602`).
	static InputRequest elicitationUrl(string id, string message, string url) @safe
	{
		import std.exception : enforce;

		enforce(url.length > 0, "URL-mode elicitation requires a non-empty url");
		enforce(isValidElicitationUrl(url), "URL-mode elicitation requires an http(s) url: " ~ url);
		Json p = Json.emptyObject;
		p["mode"] = "url";
		p["message"] = message;
		p["url"] = url;
		return InputRequest(id, "elicitation", p);
	}

	/// Build a `roots` input-request (no params).
	static InputRequest roots(string id) @safe
	{
		return InputRequest(id, "roots", Json.emptyObject);
	}

	/// Parse this request's `params` as a typed `CreateMessageRequest` — the typed
	/// reader counterpart to the `sampling` builder. Only meaningful when
	/// `kind == InputKind.sampling`.
	CreateMessageRequest asSampling() @safe
	{
		return CreateMessageRequest.fromJson(params);
	}

	/// Read `params["message"]` as a string (`""` when absent) — the reader
	/// counterpart to the `elicitation` builder, for `kind == InputKind.elicitation`.
	string elicitationMessage() @safe
	{
		if (params.type == Json.Type.object && "message" in params
				&& params["message"].type == Json.Type.string)
			return params["message"].get!string;
		return "";
	}

	/// Read `params["requestedSchema"]` (`Json.undefined` when absent) — the
	/// reader counterpart to the `elicitation` builder, for
	/// `kind == InputKind.elicitation`.
	Json requestedSchema() @safe
	{
		if (params.type == Json.Type.object && "requestedSchema" in params)
			return params["requestedSchema"];
		return Json.undefined;
	}

	/// Read `params["url"]` as a string (`""` when absent) — the reader
	/// counterpart to the `elicitationUrl` builder. Non-empty only for url-mode
	/// elicitation requests (`params["mode"] == "url"`). Throws -32602 when the
	/// url is present but not a valid http(s) URL, since the client would
	/// otherwise navigate to a server-chosen `javascript:` or `file:` target.
	string url() @safe
	{
		import mcp.protocol.errors : invalidParams;

		if (params.type == Json.Type.object && "url" in params
				&& params["url"].type == Json.Type.string)
		{
			const u = params["url"].get!string;
			if (!isValidElicitationUrl(u))
				throw invalidParams("URL-mode elicitation requires a valid http(s) url");
			return u;
		}
		return "";
	}

	/// The spec wire `method` for a `type`: an `InputRequests` value is a
	/// request object whose `method` is the full JSON-RPC method name
	/// (`elicitation/create`, `sampling/createMessage`, `roots/list`) — not the
	/// short `type`. A `type` holding a method (one containing `/`, as kept
	/// from an unrecognised wire method by `fromJson`) is returned as is; any
	/// other unrecognised `type` yields null.
	static string methodForType(string type) @safe pure nothrow
	{
		switch (type)
		{
		case "elicitation":
			return "elicitation/create";
		case "sampling":
			return "sampling/createMessage";
		case "roots":
			return "roots/list";
		default:
			foreach (char c; type)
				if (c == '/')
					return type;
			return null;
		}
	}

	/// Inverse of `methodForType`: recover the short internal discriminator from
	/// the spec wire `method`.
	static string typeForMethod(string method) @safe pure nothrow
	{
		switch (method)
		{
		case "elicitation/create":
			return "elicitation";
		case "sampling/createMessage":
			return "sampling";
		case "roots/list":
			return "roots";
		default:
			return method;
		}
	}

	/// Serialize this request as an `InputRequests` *value* (the request object):
	/// a `{ method, params }` object. The `id` is the surrounding map key and is
	/// therefore not part of the value (see `InputRequiredResult.toJson`).
	/// Throws when `type` names no method (`methodForType`), such as a
	/// misspelled kind; that is a local builder mistake, so it is a plain
	/// Exception.
	Json toJson() const @safe
	{
		import std.exception : enforce;

		const method = methodForType(type);
		enforce(method.length, "InputRequest '" ~ id ~ "' has unrecognised type '"
				~ type ~ "'; expected sampling, elicitation or roots");
		Json j = Json.emptyObject;
		j["method"] = method;
		j["params"] = params;
		return j;
	}

	/// Parse an `InputRequests` value (request object) given its map `key` (the
	/// server-assigned id).
	static InputRequest fromJson(string key, Json j) @safe
	{
		requireObject(j, "inputRequests." ~ key);
		InputRequest r;
		r.id = key;
		r.type = ("method" in j && j["method"].type == Json.Type.string)
			? typeForMethod(j["method"].get!string) : "";
		if ("params" in j)
			r.params = j["params"];
		return r;
	}
}

/// A result that asks the client to gather input and retry the original request
/// with matching `inputResponses`.
struct InputRequiredResult
{
	InputRequest[] inputRequests;
	/// SEP-2322 `requestState`: an opaque, server-owned string that lets a
	/// stateless server reconstruct its in-progress work on the retry. When
	/// non-empty it is emitted as a top-level `requestState` field; the client
	/// MUST echo it back verbatim (and MUST NOT inspect or modify it).
	string requestState;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		// The 2026-07-28 base Result mandates a `resultType` discriminator on every
		// result; an InputRequiredResult declares "input_required" so the
		// client knows to gather input and retry rather than treat this as a
		// completed response.
		j["resultType"] = "input_required";
		emitInputRequired(j, inputRequests, requestState);
		return j;
	}

	static InputRequiredResult fromJson(Json j) @safe
	{
		requireObject(j, "InputRequiredResult");
		InputRequiredResult r;
		parseInputRequired(j, r.inputRequests, r.requestState);
		return r;
	}
}

/// Emit the shared MRTR (SEP-2322) `InputRequiredResult` payload onto `j`: the
/// `inputRequests` map plus the optional top-level `requestState`. This is the
/// glue common to `InputRequiredResult.toJson` and `CallToolResult.toJson`; it
/// deliberately does NOT write the `resultType` discriminator (a `CallToolResult`
/// stamps that elsewhere), so callers add it themselves when required.
void emitInputRequired(ref Json j, const(InputRequest)[] requests, string requestState) @safe
{
	// SEP-2322: `inputRequests` is an `InputRequests` object — a map whose
	// keys are the server-assigned ids and whose values are request objects
	// (`{ method, params }`), not an array.
	j["inputRequests"] = inputRequestsToJson(requests);
	// SEP-2322: `requestState` is an optional top-level field; omit it when
	// empty so the client knows not to echo one back.
	if (requestState.length)
		j["requestState"] = requestState;
}

/// Parse the shared MRTR (SEP-2322) `InputRequiredResult` payload from `j` into
/// `requests` and `requestState`. Inverse of `emitInputRequired`; shared by
/// `InputRequiredResult.fromJson` and `CallToolResult.fromJson`. Both reads are
/// guarded, so a `j` carrying neither field leaves the outputs untouched. A
/// string `resultType` other than `"input_required"` declares the result
/// complete, so any stray MRTR fields beside it are ignored; without a
/// `resultType` the fields alone decide. A `resultType: "input_required"`
/// carrying neither input requests nor a `requestState` throws -32602, since it
/// would otherwise read as an empty completed result.
void parseInputRequired(Json j, ref InputRequest[] requests, ref string requestState) @safe
{
	import mcp.protocol.errors : invalidParams;

	const declared = "resultType" in j && j["resultType"].type == Json.Type.string;
	if (declared && j["resultType"].get!string != "input_required")
		return;
	if ("inputRequests" in j && j["inputRequests"].type == Json.Type.object)
		requests = inputRequestsFromJson(j["inputRequests"]);
	tryGet(j, "requestState", requestState);
	if (declared && requests.length == 0 && requestState.length == 0)
		throw invalidParams("an input_required result must carry inputRequests or a requestState");
}

/// Serialize a list of `InputRequest`s as a spec `InputRequests` object: a map
/// keyed by each request's server-assigned `id`, with `{ method, params }`
/// request objects as values (SEP-2322, 2026-07-28 basic/utilities/mrtr).
/// Throws when two requests share an `id`, since the map would keep only one,
/// or when a request's `type` names no method (`InputRequest.toJson`); both are
/// local builder mistakes, so it is a plain Exception.
Json inputRequestsToJson(const(InputRequest)[] requests) @safe
{
	import std.exception : enforce;

	Json obj = Json.emptyObject;
	foreach (r; requests)
	{
		enforce(r.id !in obj, "duplicate InputRequest id '" ~ r.id ~ "'");
		obj[r.id] = r.toJson();
	}
	return obj;
}

unittest  // inputRequestsToJson rejects duplicate request ids
{
	import std.exception : assertThrown;

	assertThrown(inputRequestsToJson([
		InputRequest("a", "elicitation", Json.emptyObject),
		InputRequest("a", "roots", Json.emptyObject)
	]));
	assert(inputRequestsToJson([
		InputRequest("a", "elicitation", Json.emptyObject),
		InputRequest("b", "roots", Json.emptyObject)
	]).length == 2);
}

unittest  // an InputRequest of an unrecognised kind is refused rather than sent as its method
{
	import std.exception : assertThrown;

	assertThrown(InputRequest("a", "elicit", Json.emptyObject).toJson());
	assertThrown(inputRequestsToJson([
		InputRequest("a", "elicit", Json.emptyObject)
	]));
}

unittest  // an InputRequest parsed from an unknown wire method serializes back to that method
{
	auto r = InputRequest.fromJson("a", Json(["method": Json("vendor/ask")]));
	assert(r.kind.isNull);
	assert(r.toJson()["method"].get!string == "vendor/ask");
}

/// Parse a spec `InputRequests` object (map keyed by id) back into the internal
/// `InputRequest` list. A non-object value yields no requests.
InputRequest[] inputRequestsFromJson(Json j) @safe
{
	InputRequest[] requests;
	if (j.type == Json.Type.object)
	{
		// `Json.opApply` is `@system`; iterating a plain object is safe here.
		foreach (key, value; j.byKeyValue)
			requests ~= InputRequest.fromJson(key, value);
	}
	return requests;
}

/// A client's answer to one `InputRequest`, supplied on the retried request as
/// a value of the top-level `params.inputResponses` map (SEP-2322).
struct InputResponse
{
	string id; /// the originating `InputRequest.id` (the `InputResponses` map key)
	Json result = Json.emptyObject; /// the bare client result (the map value)
}

/// Serialize a list of `InputResponse`s as a spec `InputResponses` object: a map
/// whose keys are the originating `InputRequest.id`s and whose values are the
/// *bare* client results (e.g. `{action, content}` or
/// `{role, content, model, stopReason}`) — not `{id, result}` wrappers and not a
/// JSON array (SEP-2322, 2026-07-28 basic/utilities/mrtr).
Json inputResponsesToJson(const(InputResponse)[] responses) @safe
{
	Json obj = Json.emptyObject;
	foreach (resp; responses)
		obj[resp.id] = resp.result;
	return obj;
}

/// Read the input responses a client attached to a retried request, keyed by
/// the originating `InputRequest.id`. Per SEP-2322 the wire location is the
/// top-level `params.inputResponses` field (an `InputResponses` map, id -> bare
/// client result) — NOT `_meta`.
Json[string] readInputResponses(Json params) @safe
{
	Json[string] out_;
	if (params.type != Json.Type.object || "inputResponses" !in params)
		return out_;
	auto map = params["inputResponses"];
	if (map.type != Json.Type.object)
		return out_;
	// `Json.opApply` is `@system`; iterating a plain object is safe here.
	foreach (key, value; map.byKeyValue)
		out_[key] = value;
	return out_;
}

/// Read the opaque SEP-2322 `requestState` the client echoed back on a retried
/// request. It lives in the top-level `params.requestState` field. Returns an
/// empty string when absent. The server owns this value (the client treats it
/// as opaque), so servers MUST validate it as untrusted input.
string readRequestState(Json params) @safe
{
	if (params.type != Json.Type.object || "requestState" !in params)
		return "";
	auto rs = params["requestState"];
	if (rs.type != Json.Type.string)
		return "";
	return rs.get!string;
}

unittest  // InputRequiredResult.toJson carries resultType:"input_required"
{
	InputRequiredResult r;
	r.inputRequests = [InputRequest("date", "elicitation", Json.emptyObject)];
	auto j = r.toJson();
	// The 2026-07-28 base Result mandates a resultType discriminator on every result;
	// an InputRequiredResult uses "input_required".
	assert("resultType" in j);
	assert(j["resultType"].get!string == "input_required");
	assert("inputRequests" in j);
}

unittest  // SEP-2322: inputRequests serializes as a map keyed by id, value {method, params}
{
	InputRequiredResult r;
	r.inputRequests = [
		InputRequest("github_login", "elicitation", Json(["message": Json("hi")]))
	];
	auto j = r.toJson();
	// The `InputRequests` field MUST be a JSON object (map), not an array.
	assert(j["inputRequests"].type == Json.Type.object);
	// Keyed by the server-assigned id.
	assert("github_login" in j["inputRequests"]);
	auto value = j["inputRequests"]["github_login"];
	// Value is a request object with the full JSON-RPC `method`, no `id`/`type`.
	assert(value["method"].get!string == "elicitation/create");
	assert("id" !in value);
	assert("type" !in value);
	assert(value["params"]["message"].get!string == "hi");
}

unittest  // emitInputRequired/parseInputRequired round-trip the shared MRTR glue
{
	Json j = Json.emptyObject;
	auto reqs = [InputRequest("date", "elicitation", Json.emptyObject)];
	emitInputRequired(j, reqs, "opaque-state");
	// resultType is NOT written by the shared helper (callers stamp it).
	assert("resultType" !in j);
	assert(j["inputRequests"].type == Json.Type.object);
	assert(j["requestState"].get!string == "opaque-state");

	InputRequest[] outReqs;
	string outState;
	parseInputRequired(j, outReqs, outState);
	assert(outReqs.length == 1);
	assert(outReqs[0].id == "date");
	assert(outState == "opaque-state");
}

unittest  // an input_required result carrying neither inputRequests nor requestState is rejected
{
	import mcp.protocol.errors : ErrorCode, McpException;
	import std.exception : collectException;

	InputRequest[] reqs;
	string state;
	auto ex = cast(McpException) collectException(parseInputRequired(
			Json(["resultType": Json("input_required")]), reqs, state));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // an input_required result with an empty inputRequests map and no requestState is rejected
{
	import mcp.protocol.errors : ErrorCode, McpException;
	import std.exception : collectException;

	InputRequest[] reqs;
	string state;
	auto ex = cast(McpException) collectException(
			parseInputRequired(Json([
		"resultType": Json("input_required"),
		"inputRequests": Json.emptyObject
	]), reqs, state));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // an input_required result carrying only a requestState parses
{
	InputRequest[] reqs;
	string state;
	parseInputRequired(Json([
		"resultType": Json("input_required"),
		"requestState": Json("s")
	]), reqs, state);
	assert(reqs.length == 0 && state == "s");
}

unittest  // emitInputRequired omits an empty requestState
{
	Json j = Json.emptyObject;
	emitInputRequired(j, [InputRequest("x", "roots", Json.emptyObject)], "");
	assert("requestState" !in j);
}

unittest  // SEP-2322: sampling/roots methods map to their full JSON-RPC names
{
	InputRequiredResult r;
	r.inputRequests = [
		InputRequest("s1", "sampling", Json.emptyObject),
		InputRequest("r1", "roots", Json.emptyObject)
	];
	auto j = r.toJson();
	assert(j["inputRequests"]["s1"]["method"].get!string == "sampling/createMessage");
	assert(j["inputRequests"]["r1"]["method"].get!string == "roots/list");
}

unittest  // InputRequest.sampling builder sets the sampling type + request params
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage;
	import mcp.protocol.types : Content;

	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 32;
	auto ir = InputRequest.sampling("s1", req);
	assert(ir.id == "s1");
	assert(ir.type == "sampling");
	assert(ir.params == req.toJson());
	assert(ir.kind.get == InputKind.sampling);
}

unittest  // InputRequest.elicitation builder sets message + requestedSchema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.type == "elicitation");
	assert(ir.params["message"].get!string == "Your name?");
	assert(ir.params["requestedSchema"] == schema);
	assert(ir.kind.get == InputKind.elicitation);
}

unittest  // InputRequest.roots builder sets the roots type with empty params
{
	auto ir = InputRequest.roots("r1");
	assert(ir.type == "roots");
	assert(ir.kind.get == InputKind.roots);
}

unittest  // InputRequest.kind returns null for an unrecognised type
{
	auto ir = InputRequest("x", "bogus", Json.emptyObject);
	assert(ir.kind.isNull);
}

unittest  // InputRequest.asSampling reads back the CreateMessageRequest builder input
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage;
	import mcp.protocol.types : Content;

	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 64;
	req.systemPrompt = "be terse";
	auto ir = InputRequest.sampling("s1", req);

	auto back = ir.asSampling();
	assert(back.messages.length == 1);
	assert(back.messages[0].content.text == "hi");
	assert(back.maxTokens.get == 64);
	assert(back.systemPrompt.get == "be terse");
}

unittest  // InputRequest.elicitationMessage reads back the elicitation builder message
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.elicitationMessage() == "Your name?");
}

unittest  // InputRequest.elicitationMessage is empty when no message is present
{
	auto ir = InputRequest.roots("r1");
	assert(ir.elicitationMessage() == "");
}

unittest  // InputRequest.requestedSchema reads back the elicitation builder schema
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	auto ir = InputRequest.elicitation("e1", "Your name?", schema);
	assert(ir.requestedSchema() == schema);
}

unittest  // InputRequest.requestedSchema is undefined when no schema is present
{
	auto ir = InputRequest("e1", "elicitation", Json([
		"message": Json("Just a message")
	]));
	assert(ir.requestedSchema().type == Json.Type.undefined);
}

unittest  // InputRequest.elicitation without a schema sends an empty object schema
{
	auto ir = InputRequest.elicitation("e1", "Just a message");
	auto schema = ir.params["requestedSchema"];
	assert(schema["type"].get!string == "object");
	assert(schema["properties"].type == Json.Type.object);
	assert(schema["properties"].length == 0);
}

unittest  // InputRequiredResult.fromJson rejects a non-object result with -32602
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	foreach (v; [Json(5), Json("x"), Json.emptyArray, Json(null)])
	{
		auto ex = cast(McpException) collectException(InputRequiredResult.fromJson(v));
		assert(ex !is null && ex.code == ErrorCode.invalidParams);
	}
}

unittest  // MRTR InputRequiredResult round-trips and input responses parse
{
	InputRequiredResult ir;
	ir.inputRequests = [
		InputRequest("r1", "elicitation", Json(["message": Json("hi")]))
	];
	auto back = InputRequiredResult.fromJson(ir.toJson());
	assert(back.inputRequests.length == 1);
	assert(back.inputRequests[0].id == "r1");
	assert(back.inputRequests[0].type == "elicitation");
	assert(back.inputRequests[0].params["message"].get!string == "hi");

	Json params = Json.emptyObject;
	params["inputResponses"] = inputResponsesToJson([
		InputResponse("r1", Json(["action": Json("accept")]))
	]);
	auto resps = readInputResponses(params);
	assert("r1" in resps);
	assert(resps["r1"]["action"].get!string == "accept");
}

unittest  // SEP-2322: inputResponses is a map keyed by id with bare result values
{
	// The spec `InputResponses` field is a JSON object whose keys are the
	// server-assigned `InputRequest` ids and whose values are the *bare* client
	// results (e.g. `{action, content}`) — not `{id, result}` wrapper objects,
	// and not a JSON array.
	auto obj = inputResponsesToJson([
		InputResponse("github_login", Json([
			"action": Json("accept"),
			"content": Json(["name": Json("octocat")])
		]))
	]);
	assert(obj.type == Json.Type.object);
	assert("github_login" in obj);
	auto value = obj["github_login"];
	// The value is the bare result, with no `id`/`result` wrapper.
	assert("id" !in value);
	assert("result" !in value);
	assert(value["action"].get!string == "accept");
	assert(value["content"]["name"].get!string == "octocat");
}

unittest  // SEP-2322: readInputResponses parses the spec map shape keyed by id
{
	Json responses = Json.emptyObject;
	responses["date"] = Json(["action": Json("accept")]);
	Json params = Json.emptyObject;
	// SEP-2322: inputResponses is a top-level params field, not under _meta.
	params["inputResponses"] = responses;

	auto parsed = readInputResponses(params);
	assert("date" in parsed);
	// The parsed value is the bare result the client supplied.
	assert(parsed["date"]["action"].get!string == "accept");
	// Nothing under _meta is consulted.
	assert("_meta" !in params);
}

unittest  // SEP-2322: inputResponses lives in params, NOT under params._meta
{
	// Regression guard for the wire location. A spec server reads
	// `params.inputResponses`; the invented reserved `_meta` key must not exist.
	Json responses = Json.emptyObject;
	responses["github_login"] = Json([
		"action": Json("accept"),
		"content": Json(["name": Json("octocat")])
	]);

	// Placed at top level: parsed.
	Json good = Json.emptyObject;
	good["name"] = "get_weather";
	good["inputResponses"] = responses;
	auto parsed = readInputResponses(good);
	assert("github_login" in parsed);
	assert(parsed["github_login"]["content"]["name"].get!string == "octocat");

	// Placed under _meta (the old, invented shape): ignored.
	Json bad = Json.emptyObject;
	Json meta = Json.emptyObject;
	meta["io.modelcontextprotocol/inputResponses"] = responses;
	bad["_meta"] = meta;
	assert(readInputResponses(bad).length == 0);
}

unittest  // SEP-2322: InputRequiredResult carries the opaque requestState round-trip
{
	InputRequiredResult ir;
	ir.inputRequests = [
		InputRequest("github_login", "elicitation", Json.emptyObject)
	];
	ir.requestState = "foo";
	auto j = ir.toJson();
	// requestState is a top-level field on the result, alongside inputRequests.
	assert(j["requestState"].get!string == "foo");
	auto back = InputRequiredResult.fromJson(j);
	assert(back.requestState == "foo");
}

unittest  // SEP-2322: an empty requestState is omitted from the wire result
{
	InputRequiredResult ir;
	ir.inputRequests = [InputRequest("r1", "elicitation", Json.emptyObject)];
	auto j = ir.toJson();
	// The client MUST NOT echo a requestState the server never sent.
	assert("requestState" !in j);
}

unittest  // SEP-2322: readRequestState reads the opaque top-level params.requestState
{
	Json params = Json.emptyObject;
	params["name"] = "get_weather";
	params["requestState"] = "eyJyZXNvbHV0aW9uIjoiRHVwbGljYXRlIn0";
	assert(readRequestState(params) == "eyJyZXNvbHV0aW9uIjoiRHVwbGljYXRlIn0");

	// Absent / wrong type -> empty.
	assert(readRequestState(Json.emptyObject) == "");
	Json wrong = Json.emptyObject;
	wrong["requestState"] = 7;
	assert(readRequestState(wrong) == "");
}

unittest  // InputRequest.elicitationUrl builds modern url-mode params (no elicitationId)
{
	auto ir = InputRequest.elicitationUrl("e1", "Authorize access", "https://example.com/consent");
	assert(ir.type == "elicitation");
	assert(ir.kind.get == InputKind.elicitation);
	assert(ir.params["mode"].get!string == "url");
	assert(ir.params["message"].get!string == "Authorize access");
	assert(ir.params["url"].get!string == "https://example.com/consent");
	// The modern removed elicitationId from url-mode requests; correlation is the
	// MRTR request id.
	assert("elicitationId" !in ir.params);
}

unittest  // InputRequest.elicitationUrl readers round-trip url and message
{
	auto ir = InputRequest.elicitationUrl("e1", "msg", "https://example.com/consent");
	assert(ir.url() == "https://example.com/consent");
	assert(ir.elicitationMessage() == "msg");
}

unittest  // InputRequest.url rejects a server-sent url that is not a valid web URL
{
	import std.exception : collectException;
	import mcp.protocol.errors : ErrorCode, McpException;

	Json p = Json.emptyObject;
	p["mode"] = "url";
	p["message"] = "msg";
	p["url"] = "javascript:alert(1)";
	auto ir = InputRequest.fromJson("e1",
			Json(["method": Json("elicitation/create"), "params": p]));
	auto e = collectException!McpException(ir.url());
	assert(e !is null && e.code == ErrorCode.invalidParams);
}

unittest  // InputRequest.elicitationUrl rejects empty url as a local error
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException;

	auto e = collectException(InputRequest.elicitationUrl("e", "m", ""));
	assert(e !is null);
	assert(cast(McpException) e is null);
}

unittest  // InputRequest.elicitationUrl names the http(s) requirement when it rejects a url
{
	import std.algorithm.searching : canFind;
	import std.exception : collectException;

	auto e = collectException(InputRequest.elicitationUrl("e", "m", "file:///etc/passwd"));
	assert(e !is null && e.msg.canFind("http(s)"));
}

unittest  // InputRequest.elicitationUrl rejects a malformed (non-absolute) url as a local error
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException;

	auto e = collectException(InputRequest.elicitationUrl("e", "m", "not a url"));
	assert(e !is null);
	assert(cast(McpException) e is null);
}

unittest  // InputRequest.fromJson rejects a non-object request value with -32602
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	foreach (v; [Json(5), Json("x"), Json.emptyArray, Json(null)])
	{
		auto ex = collectException!McpException(InputRequest.fromJson("r1", v));
		assert(ex !is null && ex.code == ErrorCode.invalidParams);
	}
	Json map = Json.emptyObject;
	map["r1"] = Json(5);
	auto ex = collectException!McpException(inputRequestsFromJson(map));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // InputRequest.fromJson: non-string "method" field is treated as unknown type
{
	// A peer may emit a non-string value for "method" (e.g. a number); the parser
	// must not throw a JSONException — it should degrade gracefully to an empty type.
	Json j = Json.emptyObject;
	j["method"] = Json(99); // integer, not a string
	j["params"] = Json.emptyObject;
	auto r = InputRequest.fromJson("req-1", j);
	assert(r.id == "req-1");
	assert(r.type == ""); // unknown type, not a crash
}
