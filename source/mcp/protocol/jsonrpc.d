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

private void validateEnvelope(Json j) @safe
{
	if (j.type != Json.Type.object)
		throw invalidRequest("JSON-RPC message must be an object");
	if (("jsonrpc" !in j) || j["jsonrpc"].type != Json.Type.string
			|| j["jsonrpc"].get!string != "2.0")
		throw invalidRequest("Missing or invalid jsonrpc version (expected \"2.0\")");
	// A present `method` must be a string. Without this guard a non-string method
	// (number, object, array, boolean, null) is classified by presence alone and
	// later read with `.get!string`, throwing an uncaught JSONException instead of
	// yielding a clean -32600 across every transport.
	if (("method" in j) && j["method"].type != Json.Type.string)
		throw invalidRequest("`method` must be a string");
	// A message bearing a `method` with an explicit `id:null` is neither a valid
	// request (the spec requires a request id that is not null) nor a
	// notification (which omits `id` entirely). Reject it so the peer receives a
	// -32600 rather than having the message silently classified as a
	// notification and dropped.
	if (("method" in j) && ("id" in j) && j["id"].type == Json.Type.null_)
		throw invalidRequest("Request id MUST NOT be null");
	// A `method`-less message with a non-null `id` is a response. JSON-RPC 2.0 5
	// requires a response to carry exactly one of `result`/`error`; otherwise
	// `Message.kind` would silently classify a both-present reply as an error (the
	// result dropped) and a neither-present reply as a bogus success. Reject both
	// shapes so a malformed peer response yields -32600 rather than corrupting the
	// awaited result.
	const isResponse = ("method" !in j) && ("id" in j)
		&& j["id"].type != Json.Type.null_ && j["id"].type != Json.Type.undefined;
	if (isResponse)
	{
		const hasResult = ("result" in j) !is null;
		const hasError = ("error" in j) !is null;
		if (hasResult == hasError)
			throw invalidRequest("Response must contain exactly one of result or error");
	}
}

/// Parse and classify a single JSON-RPC message from text.
Message parseMessage(string text) @safe
{
	Json j;
	try
		j = parseJsonString(text);
	catch (Exception e)
		throw parseError("Invalid JSON: " ~ e.msg);
	validateEnvelope(j);
	return Message(j);
}

/// Parse a JSON-RPC batch (array) from text.
///
/// JSON-RPC 2.0 requires a recognizable batch to be processed member-by-member:
/// each well-formed member yields its own response and only the malformed members
/// produce individual `id:null` errors. So a member that fails `validateEnvelope`
/// is not fatal to the batch — it is collected into `errors` (with its position)
/// while the well-formed members are returned in `messages`, letting the
/// dispatcher answer every member. Only a genuinely unrecognizable batch (not
/// valid JSON, not an array, empty array) throws.
Message[] parseBatch(string text) @safe
{
	return parseBatchTolerant(text).messages;
}

/// A malformed batch member: its position in the array and the validation error.
struct BatchMemberError
{
	size_t index;
	McpException error;
}

/// `parseBatch` result that keeps malformed members rather than discarding the
/// whole batch.
struct BatchResult
{
	Message[] messages;
	BatchMemberError[] errors;
}

/// As `parseBatch`, but tolerant of individual malformed members (see `parseBatch`).
BatchResult parseBatchTolerant(string text) @safe
{
	Json arr;
	try
		arr = parseJsonString(text);
	catch (Exception e)
		throw parseError("Invalid JSON: " ~ e.msg);
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
			result.errors ~= BatchMemberError(i, e);
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

/// Render a JSON-RPC request id (a string or a number per the spec) to a stable
/// string form. Used where an id must be carried as a string value — e.g. the
/// draft `subscriptions/listen` id stamped into outbound notifications'
/// `_meta["io.modelcontextprotocol/subscriptionId"]`. A string id is returned
/// verbatim; a numeric id is rendered as its decimal text; anything else (null /
/// absent) yields an empty string.
string rpcIdString(Json id) @safe
{
	import std.conv : to;

	switch (id.type)
	{
	case Json.Type.string:
		return id.get!string;
	case Json.Type.int_:
		return id.get!long
			.to!string;
	case Json.Type.bigInt:
		return id.toString();
	case Json.Type.float_:
		return id.get!double
			.to!string;
	default:
		return "";
	}
}

unittest  // rpcIdString renders string and numeric ids, empties null
{
	assert(rpcIdString(Json("abc")) == "abc");
	assert(rpcIdString(Json(42)) == "42");
	assert(rpcIdString(Json(null)) == "");
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

/// Build a success response object.
Json makeResponse(Json id, Json result) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["result"] = result;
	return j;
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
	auto batch = parseBatch(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}]`);
	assert(batch.length == 2);
	assert(batch[0].kind == MessageKind.request);
	assert(batch[1].kind == MessageKind.notification);
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

	assertThrown!McpException(parseBatch(`[]`));
	assertThrown!McpException(parseBatch(`{"jsonrpc":"2.0"}`));
}

unittest  // method with explicit null id is rejected, not treated as notification
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`));
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
