module mcp.protocol.jsonrpc;

import vibe.data.json : Json, parseJsonString;
import mcp.protocol.errors;

@safe:

/// What a JSON-RPC message represents.
enum MessageKind
{
	request,
	notification,
	response,
	errorResponse
}

/// A classified JSON-RPC message wrapping its raw Json.
struct Message
{
	Json raw;

	MessageKind kind() const @safe
	{
		const hasId = "id" in raw && raw["id"].type != Json.Type.undefined
			&& raw["id"].type != Json.Type.null_;
		const hasMethod = "method" in raw;
		if (hasMethod)
			return hasId ? MessageKind.request : MessageKind.notification;
		if ("error" in raw)
			return MessageKind.errorResponse;
		return MessageKind.response;
	}

	string method() const @safe
	{
		return ("method" in raw) ? raw["method"].get!string : null;
	}

	Json id() const @safe
	{
		return ("id" in raw) ? raw["id"] : Json(null);
	}

	Json params() const @safe
	{
		return ("params" in raw) ? raw["params"] : Json.emptyObject;
	}

	Json result() const @safe
	{
		return ("result" in raw) ? raw["result"] : Json.undefined;
	}

	Json error() const @safe
	{
		return ("error" in raw) ? raw["error"] : Json.undefined;
	}
}

/// An envelope error for a request whose id is known, so the error reply
/// carries that id rather than null (JSON-RPC 2.0 §5).
class RequestEnvelopeException : McpException
{
	Json id; /// the offending request's id

	this(int code, string message, Json data, Json id, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(code, message, data, file, line);
		this.id = id;
	}
}

/// The id for the error reply to a message that failed parsing or envelope
/// validation with `e`: the request's id when one was determined, else null.
Json errorReplyId(Exception e) @safe
{
	if (auto re = cast(RequestEnvelopeException) e)
		return re.id;
	return Json(null);
}

/// `e` rebound to the id of request `j` when `j` is a request, else `e` itself.
private McpException requestError(Json j, McpException e) @safe
{
	if (("method" in j) && ("id" in j) && j["id"].type != Json.Type.null_)
		return new RequestEnvelopeException(e.code, e.msg, e.data, j["id"]);
	return e;
}

private void validateEnvelope(Json j) @safe
{
	if (j.type != Json.Type.object)
		throw invalidRequest("JSON-RPC message must be an object");
	// The id is validated first so every later envelope error on a request
	// can carry it.
	// A message bearing a `method` with an explicit `id:null` is neither a valid
	// request (the spec requires a request id that is not null) nor a
	// notification (which omits `id` entirely). Reject it so the peer receives a
	// -32600 rather than having the message silently classified as a
	// notification and dropped.
	if (("method" in j) && ("id" in j) && j["id"].type == Json.Type.null_)
		throw invalidRequest("Request id MUST NOT be null");
	// JSON-RPC 2.0 §5 requires that `id` is a String, Number, or null. Bool,
	// object, and array ids are not permitted; reject them so misrouted
	// responses (e.g. two requests with bool ids both resolving to id string "")
	// are caught at the boundary rather than silently mangled.
	if (("id" in j) && j["id"].type != Json.Type.string
			&& j["id"].type != Json.Type.int_
			&& j["id"].type != Json.Type.float_
			&& j["id"].type != Json.Type.bigInt && j["id"].type != Json.Type.null_)
		throw invalidRequest("JSON-RPC id MUST be a String, Number, or null");
	// JSON-RPC 2.0 §5 allows a Number id but RECOMMENDS it have no fractional
	// part. A fractional float id (e.g. 1.5) cannot round-trip cleanly as an
	// integer and cannot be matched by a conformant implementation; reject it.
	if (("id" in j) && j["id"].type == Json.Type.float_)
	{
		immutable v = j["id"].get!double;
		if (v != cast(long) v)
			throw invalidRequest("JSON-RPC id MUST NOT have a fractional part");
	}
	if (("jsonrpc" !in j) || j["jsonrpc"].type != Json.Type.string
			|| j["jsonrpc"].get!string != "2.0")
		throw requestError(j,
				invalidRequest("Missing or invalid jsonrpc version (expected \"2.0\")"));
	// A present `method` must be a string. Without this guard a non-string method
	// (number, object, array, boolean, null) is classified by presence alone and
	// later read with `.get!string`, throwing an uncaught JSONException instead of
	// yielding a clean -32600 across every transport.
	if (("method" in j) && j["method"].type != Json.Type.string)
		throw requestError(j, invalidRequest("`method` must be a string"));
	// JSON-RPC 2.0 §4.2: `params`, when present, MUST be a structured value
	// (object or array); a primitive is an invalid request. MCP further defines
	// every request's and notification's params as an object, so by-position
	// (array) params are invalid params. Rejecting both here keeps every handler
	// from having to guard against reading fields off a non-object. The id is
	// valid by this point, so a request's error reply carries it.
	if (("params" in j) && j["params"].type == Json.Type.array)
		throw requestError(j, invalidParams("`params` must be an object"));
	if (("params" in j) && j["params"].type != Json.Type.object)
		throw requestError(j, invalidRequest("`params` must be an object or array"));
	// Every JSON-RPC 2.0 message is exactly one of: request (has method + non-null id),
	// notification (has method, no id), response (no method, has non-null id), or an
	// error response with `id:null`, which JSON-RPC 2.0 §5 prescribes when the
	// request id could not be determined (e.g. a parse error). Any other method-less
	// message fits no category and is rejected so that truncated or malformed frames
	// never reach the dispatcher.
	const hasNonNullId = ("id" in j) && j["id"].type != Json.Type.null_
		&& j["id"].type != Json.Type.undefined;
	const isNullIdError = ("method" !in j) && ("id" in j)
		&& j["id"].type == Json.Type.null_ && ("error" in j) && ("result" !in j);
	if (("method" !in j) && !hasNonNullId && !isNullIdError)
		throw invalidRequest("Message must have either method (request/notification), "
				~ "a non-null id with result/error (response), or a null id with error");
	// A `method`-less message with a non-null `id` is a response. JSON-RPC 2.0 §5
	// requires a response to carry exactly one of `result`/`error`; otherwise
	// `Message.kind` would silently classify a both-present reply as an error (the
	// result dropped) and a neither-present reply as a bogus success. Reject both
	// shapes so a malformed peer response yields -32600 rather than corrupting the
	// awaited result.
	const isResponse = ("method" !in j) && hasNonNullId;
	if (isResponse)
	{
		const hasResult = ("result" in j) !is null;
		const hasError = ("error" in j) !is null;
		if (hasResult == hasError)
			throw invalidRequest("Response must contain exactly one of result or error");
	}
	// JSON-RPC 2.0 §5.1: a response's `error` is an object with an integer `code`
	// and a string `message`. Readers of an error response index those members
	// directly, so any other shape is rejected here.
	if (("method" !in j) && ("error" in j))
	{
		const err = j["error"];
		if (err.type != Json.Type.object)
			throw invalidRequest("Response `error` must be an object");
		if ("code" !in err || (err["code"].type != Json.Type.int_
				&& err["code"].type != Json.Type.bigInt))
			throw invalidRequest("Response `error.code` must be an integer");
		if ("message" !in err || err["message"].type != Json.Type.string)
			throw invalidRequest("Response `error.message` must be a string");
	}
}

/// The deepest array/object nesting accepted in JSON text from a peer.
enum maxJsonNestingDepth = 128;

/// Parse JSON text from an untrusted peer. The vibe.d parser recurses once per
/// nested array or object, so the nesting depth is checked with a flat scan
/// first: deeper input is rejected instead of overflowing the stack. Throws a
/// -32700 `McpException` for over-deep or invalid JSON.
Json parseJsonBounded(string text) @safe
{
	size_t depth;
	bool inString;
	for (size_t i = 0; i < text.length; i++)
	{
		const c = text[i];
		if (inString)
		{
			if (c == '\\')
				i++;
			else if (c == '"')
				inString = false;
			continue;
		}
		if (c == '"')
			inString = true;
		else if (c == '[' || c == '{')
		{
			if (++depth > maxJsonNestingDepth)
			{
				import std.conv : to;

				throw parseError(
						"Invalid JSON: nesting deeper than "
						~ maxJsonNestingDepth.to!string ~ " levels");
			}
		}
		else if ((c == ']' || c == '}') && depth > 0)
			depth--;
	}
	try
		return parseJsonString(text);
	catch (Exception e)
		throw parseError("Invalid JSON: " ~ e.msg);
}

/// Parse and classify a single JSON-RPC message from text.
Message parseMessage(string text) @safe
{
	Json j = parseJsonBounded(text);
	validateEnvelope(j);
	return Message(j);
}

/// A malformed batch member: its position in the array, the raw member item, and
/// the validation error. The raw `item` is retained so a dispatcher can recover the
/// member's `id` (which may still be present even when the envelope is invalid) and
/// resolve a pending request rather than letting it time out.
struct BatchMemberError
{
	size_t index;
	Json item;
	McpException error;
}

/// `parseBatchTolerant` result: the well-formed members plus each malformed one.
struct BatchResult
{
	Message[] messages;
	BatchMemberError[] errors;
}

/// Parse a JSON-RPC batch (array) from text, keeping well-formed members and
/// recording each malformed one in `errors` rather than failing the whole batch.
/// Throws `McpException` when the input is not valid JSON, is not an array, or is
/// an empty array.
BatchResult parseBatchTolerant(string text) @safe
{
	Json arr = parseJsonBounded(text);
	if (arr.type != Json.Type.array)
		throw invalidRequest("Batch must be a JSON array");
	if (arr.length == 0)
		throw invalidRequest("Batch must not be empty");
	BatchResult result;
	foreach (i; 0 .. arr.length)
	{
		auto item = arr[i];
		try
		{
			validateEnvelope(item);
			result.messages ~= Message(item);
		}
		catch (McpException e)
			result.errors ~= BatchMemberError(i, item, e);
	}
	return result;
}

/// Result of `parseAny`: a single message or a batch, normalized to a list. For a
/// batch, `errors` carries any malformed members (empty otherwise) so the
/// dispatcher can emit a distinct `id:null` error per malformed member.
struct ParsedInput
{
	bool isBatch;
	Message[] messages;
	BatchMemberError[] errors;
}

/// Parse text that may be either a single message or a batch array.
ParsedInput parseAny(string text) @safe
{
	import std.string : strip, startsWith;

	if (text.strip.startsWith("["))
	{
		auto batch = parseBatchTolerant(text);
		return ParsedInput(true, batch.messages, batch.errors);
	}
	return ParsedInput(false, [parseMessage(text)]);
}

/// Split the client replies out of the batch text `raw`: each well-formed
/// response or error response member is passed to `onReply`, and the text of a
/// batch holding the remaining members, in their original order, is returned
/// for the server core to dispatch. A server core answers requests and
/// notifications only, so a reply left in the batch would never reach the
/// handler awaiting it. Returns `raw` unchanged when it is not a parseable batch
/// or holds no reply, and `null` when it holds nothing but replies.
string takeBatchReplies(string raw, scope void delegate(Message) @safe onReply) @safe
{
	import std.string : strip, startsWith;

	if (!raw.strip.startsWith("["))
		return raw;
	Json arr;
	try
		arr = parseJsonBounded(raw);
	catch (McpException)
		return raw;
	if (arr.type != Json.Type.array)
		return raw;
	Json[] rest;
	bool tookReply;
	foreach (i; 0 .. arr.length)
	{
		auto item = arr[i];
		bool wellFormed = true;
		try
			validateEnvelope(item);
		catch (McpException)
			wellFormed = false;
		const kind = wellFormed ? Message(item).kind : MessageKind.request;
		if (kind == MessageKind.response || kind == MessageKind.errorResponse)
		{
			onReply(Message(item));
			tookReply = true;
		}
		else
			rest ~= item;
	}
	if (!tookReply)
		return raw;
	return rest.length ? Json(rest).toString() : null;
}

/// Build a request object.
Json makeRequest(Json id, string method, Json params = Json.undefined) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["method"] = method;
	if (params.type != Json.Type.undefined)
		j["params"] = params;
	return j;
}

unittest  // parseMessage rejects nesting beyond the depth cap as a parse error
{
	import std.array : replicate;
	import std.exception : collectException;

	const text = `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":` ~ "[".replicate(
			maxJsonNestingDepth) ~ "]".replicate(maxJsonNestingDepth) ~ "}}";
	auto e = collectException!McpException(parseMessage(text));
	assert(e !is null);
	assert(e.code == ErrorCode.parseError);
}

unittest  // a batch of huge nesting depth is rejected rather than overflowing the stack
{
	import std.array : replicate;
	import std.exception : collectException;

	auto e = collectException!McpException(parseBatchTolerant("[".replicate(200_000)));
	assert(e !is null);
	assert(e.code == ErrorCode.parseError);
	e = collectException!McpException(parseAny("[".replicate(200_000)));
	assert(e !is null && e.code == ErrorCode.parseError);
	assert(takeBatchReplies("[".replicate(200_000), (Message) {}) !is null);
}

unittest  // nesting at the depth cap parses
{
	import std.array : replicate;

	const text = `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":` ~ "[".replicate(
			maxJsonNestingDepth - 2) ~ "]".replicate(maxJsonNestingDepth - 2) ~ "}}";
	assert(parseMessage(text).kind == MessageKind.request);
}

unittest  // brackets inside strings, including escaped quotes, do not count as nesting
{
	import std.array : replicate;

	const s = `\"` ~ "[".replicate(500);
	const j = parseJsonBounded(`{"s":"` ~ s ~ `"}`);
	assert(j["s"].get!string == `"` ~ "[".replicate(500));
}

unittest  // parseJsonBounded reports invalid JSON as a parse error
{
	import std.exception : collectException;

	auto e = collectException!McpException(parseJsonBounded("{nope"));
	assert(e !is null && e.code == ErrorCode.parseError);
}

unittest  // parseMessage rejects a request with a fractional float id
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`));
}

/// Build a notification object (no id).
Json makeNotification(string method, Json params = Json.undefined) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["method"] = method;
	if (params.type != Json.Type.undefined)
		j["params"] = params;
	return j;
}

/// Build a success response object. An undefined `result` becomes `{}`, since
/// assigning undefined would drop the member and leave a reply with neither
/// `result` nor `error`.
Json makeResponse(Json id, Json result) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["result"] = result.type == Json.Type.undefined ? Json.emptyObject : result;
	return j;
}

unittest  // makeResponse with an undefined result still carries a result member
{
	const j = makeResponse(Json(1), Json.undefined);
	assert("result" in j);
	assert(j["result"] == Json.emptyObject);
	assert(parseMessage(j.toString()).kind == MessageKind.response);
}

/// Build an error response object from an McpException.
Json makeErrorResponse(Json id, const McpException e) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["error"] = toErrorJson(e);
	return j;
}

unittest  // classify a request
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	assert(m.kind == MessageKind.request);
	assert(m.method == "ping");
	assert(m.id == Json(1));
}

unittest  // classify a notification (no id)
{
	auto m = parseMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
	assert(m.kind == MessageKind.notification);
	assert(m.method == "notifications/initialized");
}

unittest  // classify a success response
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":"abc","result":{"ok":true}}`);
	assert(m.kind == MessageKind.response);
	assert(m.id == Json("abc"));
	assert(m.result["ok"].get!bool);
}

unittest  // classify an error response
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"x"}}`);
	assert(m.kind == MessageKind.errorResponse);
	assert(m.error["code"].get!int == -32601);
}

unittest  // reject wrong jsonrpc version
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"1.0","id":1,"method":"x"}`));
}

unittest  // reject a numeric method as -32600 rather than throwing JSONException
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":1,"method":42}`));
}

unittest  // reject an object method as -32600
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":1,"method":{}}`));
}

unittest  // reject a null method as -32600
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":1,"method":null}`));
}

unittest  // reject a non-string jsonrpc version as -32600 rather than throwing
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":2.0,"id":1,"method":"x"}`));
}

unittest  // reject malformed json with a parse error
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{not json`));
}

unittest  // builders produce spec-shaped objects
{
	auto req = makeRequest(Json(7), "tools/list", Json(["cursor": Json("c1")]));
	assert(req["jsonrpc"].get!string == "2.0");
	assert(req["id"].get!int == 7);
	assert(req["method"].get!string == "tools/list");
	assert(req["params"]["cursor"].get!string == "c1");

	auto note = makeNotification("notifications/cancelled", Json([
		"requestId": Json(7)
	]));
	assert("id" !in note);
	assert(note["method"].get!string == "notifications/cancelled");

	auto ok = makeResponse(Json(7), Json(["tools": Json.emptyArray]));
	assert(ok["result"]["tools"].length == 0);

	auto err = makeErrorResponse(Json(7), new McpException(ErrorCode.methodNotFound, "no"));
	assert(err["error"]["code"].get!int == -32601);
	assert("result" !in err);
}

unittest  // batch parsing: array of messages
{
	auto batch = parseBatchTolerant(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}]`);
	assert(batch.messages.length == 2);
	assert(batch.messages[0].kind == MessageKind.request);
	assert(batch.messages[1].kind == MessageKind.notification);
	assert(batch.errors.length == 0);
}

unittest  // parseAny distinguishes single vs batch
{
	auto single = parseAny(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	assert(!single.isBatch && single.messages.length == 1);

	auto many = parseAny(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`);
	assert(many.isBatch && many.messages.length == 1);
}

unittest  // a mixed batch keeps valid members and reports malformed ones
{
	auto batch = parseAny(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"1.0","id":2,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}]`);
	assert(batch.isBatch);
	assert(batch.messages.length == 2);
	assert(batch.messages[0].kind == MessageKind.request);
	assert(batch.messages[1].kind == MessageKind.notification);
	assert(batch.errors.length == 1);
	assert(batch.errors[0].index == 1);
	assert(batch.errors[0].error.code == ErrorCode.invalidRequest);
}

unittest  // a batch of only malformed members reports each error, no messages
{
	auto batch = parseAny(`[{"id":1,"method":"ping"},{"jsonrpc":"1.0"}]`);
	assert(batch.isBatch);
	assert(batch.messages.length == 0);
	assert(batch.errors.length == 2);
}

unittest  // an unrecognizable batch (empty / non-array) still throws
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseBatchTolerant(`[]`));
	assertThrown!McpException(parseBatchTolerant(`{"jsonrpc":"2.0"}`));
}

unittest  // parseBatch is not part of the API; parseBatchTolerant is the one batch parser
{
	static assert(!__traits(compiles, parseBatch(`[]`)));
}

unittest  // a message with no method and no id is rejected as unclassifiable
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0"}`));
	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","result":{}}`));
}

unittest  // method with explicit null id is rejected, not treated as notification
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`));
}

unittest  // an error response with a null id is accepted as an errorResponse
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"bad"}}`);
	assert(m.kind == MessageKind.errorResponse);
	assert(m.id.type == Json.Type.null_);
	assert(m.error["code"].get!int == -32700);
}

unittest  // a success response with a null id is rejected
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":null,"result":{}}`));
	assertThrown!McpException(parseMessage(
			`{"jsonrpc":"2.0","id":null,"result":{},"error":{"code":-1,"message":"x"}}`));
}

unittest  // a genuine notification (no id) is still accepted
{
	auto m = parseMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
	assert(m.kind == MessageKind.notification);
}

unittest  // a response carrying both result and error is rejected
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(
			`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}`));
}

unittest  // a response carrying neither result nor error is rejected
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":1}`));
}

unittest  // boolean id is rejected (JSON-RPC 2.0 §5: id must be string, number, or null)
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":true,"method":"ping"}`));
	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":false,"method":"ping"}`));
}

unittest  // object id is rejected (JSON-RPC 2.0 §5: id must be string, number, or null)
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":{},"method":"ping"}`));
}

unittest  // array id is rejected (JSON-RPC 2.0 §5: id must be string, number, or null)
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":[],"method":"ping"}`));
}

unittest  // a request with primitive params is rejected (JSON-RPC 2.0 §4.2: params is structured)
{
	import std.exception : collectException;

	foreach (p; [`5`, `"x"`, `true`, `null`])
	{
		auto ex = collectException!McpException(parseMessage(
				`{"jsonrpc":"2.0","id":1,"method":"ping","params":` ~ p ~ `}`));
		assert(ex !is null && ex.code == ErrorCode.invalidRequest, p);
	}
}

unittest  // a notification with primitive params is rejected
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(
			`{"jsonrpc":"2.0","method":"notifications/initialized","params":7}`));
}

unittest  // object and absent params are accepted
{
	cast(void) parseMessage(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`);
	cast(void) parseMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
}

unittest  // by-position (array) params are rejected with -32602 on requests and notifications
{
	import std.exception : collectException;

	foreach (msg; [
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["x",{}]}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":[1]}`
	])
	{
		auto ex = collectException!McpException(parseMessage(msg));
		assert(ex !is null && ex.code == ErrorCode.invalidParams, msg);
	}
}

unittest  // a params error carries a request's id and a null id for a notification
{
	import std.exception : collectException;

	auto req = collectException!McpException(
			parseMessage(`{"jsonrpc":"2.0","id":"a","method":"ping","params":7}`));
	assert(req.code == ErrorCode.invalidRequest && errorReplyId(req) == Json("a"));
	auto note = collectException!McpException(
			parseMessage(`{"jsonrpc":"2.0","method":"notifications/x","params":[]}`));
	assert(note.code == ErrorCode.invalidParams && errorReplyId(note).type == Json.Type.null_);
}

unittest  // a bad jsonrpc version on a request carries the request's id
{
	import std.exception : collectException;

	auto ex = collectException!McpException(
			parseMessage(`{"jsonrpc":"1.0","id":5,"method":"ping"}`));
	assert(ex.code == ErrorCode.invalidRequest && errorReplyId(ex) == Json(5));
}

unittest  // a non-string method on a request carries the request's id
{
	import std.exception : collectException;

	auto ex = collectException!McpException(parseMessage(`{"jsonrpc":"2.0","id":"x","method":42}`));
	assert(ex.code == ErrorCode.invalidRequest && errorReplyId(ex) == Json("x"));
}

unittest  // an invalid id is reported with a null reply id
{
	import std.exception : collectException;

	auto ex = collectException!McpException(
			parseMessage(`{"jsonrpc":"1.0","id":true,"method":"ping"}`));
	assert(ex.code == ErrorCode.invalidRequest && errorReplyId(ex).type == Json.Type.null_);
}

unittest  // a batch member with array params is reported as a -32602 member error
{
	auto r = parseBatchTolerant(`[{"jsonrpc":"2.0","id":1,"method":"ping","params":[]},`
			~ `{"jsonrpc":"2.0","id":2,"method":"ping"}]`);
	assert(r.messages.length == 1 && r.errors.length == 1);
	assert(r.errors[0].index == 0 && r.errors[0].error.code == ErrorCode.invalidParams);
}

unittest  // an error response whose error is not an object is rejected with -32600
{
	import std.exception : collectException;

	foreach (e; [`"boom"`, `5`, `null`, `[]`, `true`])
		foreach (id; [`1`, `null`])
		{
			auto ex = collectException!McpException(
					parseMessage(`{"jsonrpc":"2.0","id":` ~ id ~ `,"error":` ~ e ~ `}`));
			assert(ex !is null && ex.code == ErrorCode.invalidRequest, e);
		}
}

unittest  // an error object needs an integer code and a string message
{
	import std.exception : collectException;

	foreach (e; [
		`{}`, `{"message":"x"}`, `{"code":-1}`, `{"code":"-1","message":"x"}`,
		`{"code":-1.5,"message":"x"}`, `{"code":-1,"message":7}`
	])
	{
		auto ex = collectException!McpException(
				parseMessage(`{"jsonrpc":"2.0","id":1,"error":` ~ e ~ `}`));
		assert(ex !is null && ex.code == ErrorCode.invalidRequest, e);
	}
}

unittest  // a well-formed error object with data is accepted
{
	auto m = parseMessage(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad","data":[1]}}`);
	assert(m.kind == MessageKind.errorResponse);
	assert(m.error["code"].get!long == -32602);
}

unittest  // takeBatchReplies hands replies to onReply and keeps the other members in order
{
	Json[] replies;
	const rest = takeBatchReplies(`[{"jsonrpc":"2.0","id":1,"method":"ping"},`
			~ `{"jsonrpc":"2.0","id":7,"result":{}},{"jsonrpc":"2.0","method":"n"},`
			~ `{"jsonrpc":"2.0","id":8,"error":{"code":-1,"message":"no"}}]`, (Message m) @safe {
		replies ~= m.id;
	});
	assert(replies == [Json(7), Json(8)]);
	auto arr = parseJsonString(rest);
	assert(arr.length == 2 && arr[0]["method"].get!string == "ping"
			&& arr[1]["method"].get!string == "n");
}

unittest  // takeBatchReplies returns null for a batch of replies only
{
	assert(takeBatchReplies(`[{"jsonrpc":"2.0","id":7,"result":{}}]`, (Message) @safe {
		}) is null);
}

unittest  // takeBatchReplies leaves a batch without replies, or a single message, untouched
{
	const batch = `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`;
	const single = `{"jsonrpc":"2.0","id":7,"result":{}}`;
	bool called;
	assert(takeBatchReplies(batch, (Message) @safe { called = true; }) is batch);
	assert(takeBatchReplies(single, (Message) @safe { called = true; }) is single);
	assert(!called);
}
