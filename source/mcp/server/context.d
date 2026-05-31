module mcp.server.context;

import std.typecons : Nullable;
import vibe.data.json : Json;

import mcp.protocol.errors;
import mcp.protocol.sampling : CreateMessageRequest, CreateMessageResult;
import mcp.protocol.types : ListRootsResult;
import mcp.auth.resource_server : TokenInfo;
import mcp.protocol.jsonrpc : makeNotification;
import mcp.protocol.versions : ProtocolVersion, latestStable;

@safe:

/// The RFC 5424 severity ordering used by `notifications/message` logging
/// (server/utilities/logging). Lower index == less severe; a message is emitted
/// only when its severity is at or above the client's configured minimum (set
/// via `logging/setLevel`). Returns `-1` for an unrecognised level name.
int logLevelRank(string level) @safe pure nothrow @nogc
{
	switch (level)
	{
	case "debug":
		return 0;
	case "info":
		return 1;
	case "notice":
		return 2;
	case "warning":
		return 3;
	case "error":
		return 4;
	case "critical":
		return 5;
	case "alert":
		return 6;
	case "emergency":
		return 7;
	default:
		return -1;
	}
}

/// Whether a log message at `level` should be emitted when the client's
/// configured minimum is `minLevel` (RFC 5424 ordering). After
/// `logging/setLevel(error)` only `error` and above pass. An unrecognised
/// `level` is treated as always emitted (fail-open, so custom levels are not
/// silently dropped); an unrecognised `minLevel` admits everything.
bool shouldLog(string level, string minLevel) @safe pure nothrow @nogc
{
	const lvl = logLevelRank(level);
	const min = logLevelRank(minLevel);
	if (lvl < 0 || min < 0)
		return true;
	return lvl >= min;
}

unittest  // RFC 5424 ordering: debug < info < ... < emergency
{
	assert(logLevelRank("debug") < logLevelRank("info"));
	assert(logLevelRank("info") < logLevelRank("notice"));
	assert(logLevelRank("notice") < logLevelRank("warning"));
	assert(logLevelRank("warning") < logLevelRank("error"));
	assert(logLevelRank("error") < logLevelRank("critical"));
	assert(logLevelRank("critical") < logLevelRank("alert"));
	assert(logLevelRank("alert") < logLevelRank("emergency"));
	assert(logLevelRank("bogus") == -1);
}

unittest  // shouldLog gates by the configured minimum level
{
	// minLevel "error": only error and above pass.
	assert(!shouldLog("debug", "error"));
	assert(!shouldLog("warning", "error"));
	assert(shouldLog("error", "error"));
	assert(shouldLog("critical", "error"));
	assert(shouldLog("emergency", "error"));
}

unittest  // shouldLog with the default minimum "info" drops only debug
{
	assert(!shouldLog("debug", "info"));
	assert(shouldLog("info", "info"));
	assert(shouldLog("warning", "info"));
}

unittest  // shouldLog fails open on unrecognised level names
{
	assert(shouldLog("custom", "error"));
	assert(shouldLog("debug", "bogus"));
}

/// A shared, mutable cancellation flag for one in-flight request. The server
/// hands the same token to the request's `RequestContext` (so the handler can
/// poll `ctx.isCancelled`) and to its in-flight registry (so an inbound
/// `notifications/cancelled` for the matching request id can flip it). It is a
/// class so the flag is observed across the two tasks that a Streamable HTTP
/// transport runs the request and its cancellation on. See
/// basic/utilities/cancellation: a receiver "SHOULD: Stop processing the
/// cancelled request, Free associated resources, Not send a response".
final class CancellationToken
{
	private bool cancelled_;

	/// Whether a cancellation has been requested for this token's request.
	bool cancelled() const @safe nothrow @nogc
	{
		return cancelled_;
	}

	/// Mark the request cancelled. Idempotent.
	void cancel() @safe nothrow @nogc
	{
		cancelled_ = true;
	}
}

/// Per-request context handed to tool handlers. It is the channel through which
/// a handler emits server->client traffic while a request is in flight:
/// progress + logging notifications, and (blocking) sampling / elicitation
/// requests. Transports supply a concrete implementation; the in-process and
/// stdio paths use `NullContext` (notifications are dropped, server->client
/// requests are unsupported).
interface RequestContext
{
	/// Whether the client has sent a `notifications/cancelled` for this request
	/// (basic/utilities/cancellation). A long-running handler SHOULD poll this
	/// and, when true, stop work and free resources promptly; the server
	/// suppresses the late response for a cancelled request regardless. Always
	/// false on transports that cannot deliver an out-of-band cancellation while
	/// a request is in flight (e.g. the in-process / stdio `NullContext`).
	bool isCancelled() @safe;

	/// Emit a `notifications/progress`. No-op if the originating request carried
	/// no `_meta.progressToken`.
	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe;

	/// Emit a `notifications/message` (logging) at the given level. `data` may be
	/// any JSON value (commonly a string or object); `logger` is optional.
	void log(string level, Json data, string logger = null) @safe;

	/// Send a server->client request and block until the client responds.
	/// Returns the result, or throws `McpException` if the client returned an
	/// error or does not support the feature.
	Json sendRequest(string method, Json params) @safe;

	/// Whether the connected client advertised the named capability
	/// ("sampling", "elicitation", "roots").
	bool clientSupports(string capability) @safe;

	/// True when this request is on a stateless (MRTR) protocol — the draft
	/// revision, where there is no server->client channel. On such requests a
	/// tool handler must NOT call `elicit`/`sample` (they throw); instead it
	/// returns `ToolResponse.inputRequired(...)` and reads the client's answers
	/// from `inputResponses` on the retried request. False on 2025-era requests.
	bool isStateless() @safe;

	/// The input responses the client attached when resubmitting an MRTR
	/// request, keyed by the `InputRequest.id` the server issued on the prior
	/// round. Empty on the first call and on non-stateless requests.
	Json[string] inputResponses() @safe;

	/// The opaque MRTR (SEP-2322) `requestState` the client echoed back from the
	/// server's prior `InputRequiredResult` (`params.requestState`). Empty on the
	/// first call and when the server sent no state. The server owns this value
	/// (the client treats it as opaque), so handlers MUST validate it as
	/// untrusted input.
	string requestState() @safe;

	/// The validated OAuth 2.1 access-token info for this request, when the
	/// transport enforces authorization (Streamable HTTP with a configured
	/// `ResourceServerConfig`). `TokenInfo.valid` is false on transports without
	/// auth (stdio, in-process) or when no token was required; handlers that need
	/// the authenticated subject or token scopes read it here.
	TokenInfo auth() @safe;

	/// Request an LLM completion from the client (`sampling/createMessage`).
	/// Throws on a stateless (MRTR) request — use `ToolResponse.inputRequired`
	/// instead — or if the client does not support sampling.
	final Json sample(Json params) @safe
	{
		if (isStateless)
			throw invalidRequest("sample() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
		if (!clientSupports("sampling"))
			throw invalidRequest("Client does not support sampling");
		// Per spec, servers MUST NOT send tool-enabled sampling requests to
		// clients that have not declared the `sampling.tools` sub-capability.
		if (params.type == Json.Type.object && "tools" in params
				&& !clientSupports("sampling.tools"))
			throw invalidRequest("Client does not support tool use in sampling (sampling.tools)");
		// The soft-deprecated `sampling.context` sub-capability gates the
		// `includeContext` values `thisServer`/`allServers`.
		if (params.type == Json.Type.object && "includeContext" in params
				&& params["includeContext"].type == Json.Type.string)
		{
			const inc = params["includeContext"].get!string;
			if ((inc == "thisServer" || inc == "allServers") && !clientSupports("sampling.context"))
				throw invalidRequest(
						"Client does not support context-enabled sampling (sampling.context)");
		}
		return sendRequest("sampling/createMessage", params);
	}

	/// Typed convenience over `sample(Json)`: build a `CreateMessageRequest`,
	/// send it, and parse the client's reply into a `CreateMessageResult`. Same
	/// preconditions and exceptions as the JSON overload.
	final CreateMessageResult sample(CreateMessageRequest request) @safe
	{
		return CreateMessageResult.fromJson(sample(request.toJson()));
	}

	/// Request structured user input from the client (`elicitation/create`).
	/// `requestedSchema` must be a JSON Schema object. Throws on a stateless
	/// (MRTR) request — use `ToolResponse.inputRequired` instead — or if the
	/// client does not support elicitation.
	///
	/// This is form-mode elicitation; per spec the `mode` field is omitted and
	/// defaults to `"form"`. For URL-mode elicitation use `elicitUrl`. Throws
	/// when the client did not declare the `elicitation.form` submode (a bare
	/// `elicitation:{}` is treated as form-only for 2025-06-18 compatibility).
	final Json elicit(string message, Json requestedSchema) @safe
	{
		if (isStateless)
			throw invalidRequest("elicit() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
		// Per client/elicitation: servers MUST NOT send elicitation requests
		// with modes the client does not support. A bare `elicitation:{}` is
		// form-only, so a generic declaration already sets the form submode.
		if (!clientSupports("elicitation.form"))
			throw invalidRequest("Client does not support form-mode elicitation");
		Json params = Json.emptyObject;
		params["message"] = message;
		params["requestedSchema"] = requestedSchema;
		return sendRequest("elicitation/create", params);
	}

	/// Request URL-mode elicitation from the client (`elicitation/create` with
	/// `mode: "url"`, introduced in 2025-11-25). Directs the user to complete an
	/// out-of-band interaction (e.g. an OAuth consent or a web form) at `url`;
	/// `elicitationId` correlates the request with the outcome the client reports
	/// back. Per spec a URL-mode request MUST specify `mode: "url"`, a `message`,
	/// `url`, and `elicitationId`. Throws when the client did not declare the
	/// `elicitation.url` submode.
	///
	/// Returns the client's `{action}` response (typically `accept`/`decline`/
	/// `cancel`). Throws on a stateless (MRTR) request — use
	/// `ToolResponse.inputRequired` instead — or if the client does not support
	/// elicitation, if `url`/`elicitationId` are empty, or if `url` is not a
	/// valid absolute URI (the spec requires `url` to contain a valid URL).
	final Json elicitUrl(string message, string url, string elicitationId) @safe
	{
		if (isStateless)
			throw invalidRequest("elicitUrl() is unavailable on a stateless (MRTR) request; return ToolResponse.inputRequired instead");
		// Per client/elicitation: servers MUST NOT send a url-mode request to a
		// client that only declared form mode (e.g. a bare `elicitation:{}`).
		if (!clientSupports("elicitation.url"))
			throw invalidRequest("Client does not support url-mode elicitation");
		if (url.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty url");
		if (!isValidElicitationUrl(url))
			throw invalidParams("URL-mode elicitation requires a valid url (absolute URI): " ~ url);
		if (elicitationId.length == 0)
			throw invalidParams("URL-mode elicitation requires a non-empty elicitationId");
		Json params = Json.emptyObject;
		params["mode"] = "url";
		params["message"] = message;
		params["url"] = url;
		params["elicitationId"] = elicitationId;
		return sendRequest("elicitation/create", params);
	}

	/// List the client's filesystem roots (`roots/list`). Per client/roots
	/// §Implementation Guidelines, checks the client's `roots` capability before
	/// usage and throws `McpException` if the client does not support it; parses
	/// the client's reply into a typed `ListRootsResult`.
	final ListRootsResult listRoots() @safe
	{
		if (!clientSupports("roots"))
			throw invalidRequest("Client does not support roots");
		return ListRootsResult.fromJson(sendRequest("roots/list", Json.emptyObject));
	}
}

/// A context with no client channel: notifications are dropped and
/// server->client requests are rejected. Used by transports that do not (yet)
/// support streaming, and as the default when none is supplied.
final class NullContext : RequestContext
{
	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string, Json, string = null) @safe
	{
	}

	Json sendRequest(string, Json) @safe
	{
		throw invalidRequest("This transport has no server-to-client channel");
	}

	bool clientSupports(string) @safe
	{
		return false;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

/// A `RequestContext` for the stdio transport. The stdio transport is a single
/// newline-delimited byte stream, and the MCP stdio spec permits the server to
/// write any valid MCP message to stdout at any time — so server->client
/// notifications (`notifications/message` logging and `notifications/progress`)
/// are serialised and pushed to the transport's write sink as the handler emits
/// them, out-of-band of the request's eventual reply.
///
/// There is no out-of-band path for the client to answer a server->client
/// *request* while a stdio request is in flight (replies arrive on the same
/// stdin the server is blocked reading), so `sendRequest` is unsupported and
/// `clientSupports` reports false, exactly like `NullContext`. Severity gating
/// for logging and the `progressToken` gate for progress are applied by the
/// server's per-request `RequestScope` and the token captured here.
final class StdioContext : RequestContext
{
	private void delegate(string) @safe sink;
	private Json progressTok;

	/// `sink` receives one serialised JSON-RPC frame per call (the transport
	/// adds the newline terminator). `progressToken` is the originating request's
	/// `_meta.progressToken`, or `Json.undefined` when it carried none.
	this(void delegate(string) @safe sink, Json progressToken = Json.undefined) @safe
	{
		this.sink = sink;
		this.progressTok = progressToken;
	}

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe
	{
		if (progressTok.type == Json.Type.undefined)
			return;
		Json p = Json.emptyObject;
		p["progressToken"] = progressTok;
		p["progress"] = progress;
		if (!total.isNull)
			p["total"] = total.get;
		if (message.length)
			p["message"] = message;
		emit(makeNotification("notifications/progress", p));
	}

	void log(string level, Json data, string logger = null) @safe
	{
		Json p = Json.emptyObject;
		p["level"] = level;
		if (logger.length)
			p["logger"] = logger;
		// `data` is REQUIRED by server/utilities/logging; emit explicit JSON
		// null for an undefined payload so vibe does not drop the key.
		p["data"] = data.type == Json.Type.undefined ? Json(null) : data;
		emit(makeNotification("notifications/message", p));
	}

	private void emit(Json frame) @safe
	{
		if (sink !is null)
			sink(frame.toString());
	}

	Json sendRequest(string, Json) @safe
	{
		throw invalidRequest("The stdio transport has no server-to-client request channel");
	}

	bool clientSupports(string) @safe
	{
		return false;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

/// Wraps a transport-supplied `RequestContext` with the per-request protocol
/// state the server determines only after parsing the message: whether the
/// request is stateless (MRTR), and the input responses the client attached.
/// The server installs this around the transport context before dispatching, so
/// handlers observe correct `isStateless`/`inputResponses` and `elicit`/`sample`
/// fail fast on stateless requests. Notifications and server->client requests
/// delegate to the wrapped context unchanged.
final class RequestScope : RequestContext
{
	private RequestContext inner;
	private bool stateless;
	private Json[string] responses;
	private string requestState_;
	private string minLevel;
	private bool loggingRequested;
	private CancellationToken cancellation;
	private ProtocolVersion effectiveVersion_;

	this(RequestContext inner, bool stateless, Json[string] responses, string minLevel = "info",
			bool loggingRequested = true, CancellationToken cancellation = null,
			string requestState = "", ProtocolVersion effectiveVersion = latestStable) @safe
	{
		this.inner = inner;
		this.stateless = stateless;
		this.responses = responses;
		this.requestState_ = requestState;
		this.minLevel = minLevel;
		this.loggingRequested = loggingRequested;
		this.cancellation = cancellation;
		this.effectiveVersion_ = effectiveVersion;
	}

	/// The protocol version in effect for THIS request (negotiated version on the
	/// stateful 2025-era protocols; the per-request `_meta.protocolVersion` on the
	/// stateless draft). Request-scoped so a concurrent request that yields mid-
	/// handle cannot have its effective version flipped by another in-flight
	/// request: the dispatcher reads it from here, not from a mutable field on the
	/// shared server instance.
	ProtocolVersion effectiveVersion() @safe
	{
		return effectiveVersion_;
	}

	/// True once the client has cancelled this request via
	/// `notifications/cancelled`. Reads the shared token the server installed for
	/// this request; if none was installed it delegates to the wrapped context.
	bool isCancelled() @safe
	{
		if (cancellation !is null && cancellation.cancelled)
			return true;
		return inner.isCancelled();
	}

	void reportProgress(double progress,
			Nullable!double total = Nullable!double.init, string message = null) @safe
	{
		inner.reportProgress(progress, total, message);
	}

	/// Emit a logging notification, but drop it when its severity is below the
	/// client-configured minimum (`logging/setLevel`) per the RFC 5424 ordering.
	/// This is where the server honours "Only sends error level and above".
	///
	/// On the draft (stateless) protocol the server MUST NOT emit
	/// `notifications/message` for a request that did not carry
	/// `_meta["io.modelcontextprotocol/logLevel"]`; the server signals that by
	/// constructing this scope with `loggingRequested = false`, in which case
	/// every log is dropped regardless of severity.
	void log(string level, Json data, string logger = null) @safe
	{
		if (!loggingRequested)
			return;
		if (!shouldLog(level, minLevel))
			return;
		inner.log(level, data, logger);
	}

	Json sendRequest(string method, Json params) @safe
	{
		return inner.sendRequest(method, params);
	}

	bool clientSupports(string capability) @safe
	{
		return inner.clientSupports(capability);
	}

	bool isStateless() @safe
	{
		return stateless;
	}

	Json[string] inputResponses() @safe
	{
		return responses;
	}

	string requestState() @safe
	{
		return requestState_;
	}

	TokenInfo auth() @safe
	{
		return inner.auth();
	}
}

version (unittest) private final class SamplingProbe : RequestContext
{
	Json lastParams;

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string, Json, string = null) @safe
	{
	}

	Json sendRequest(string method, Json params) @safe
	{
		lastParams = params;
		// Echo back a typed-looking sampling result.
		Json r = Json.emptyObject;
		r["role"] = "assistant";
		Json content = Json.emptyObject;
		content["type"] = "text";
		content["text"] = "echoed";
		r["content"] = content;
		r["model"] = "test-model";
		r["stopReason"] = "endTurn";
		return r;
	}

	bool clientSupports(string capability) @safe
	{
		return capability == "sampling";
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

version (unittest) private final class RootsProbe : RequestContext
{
	string lastMethod;
	Json lastParams;
	bool supportsRoots = true;

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string, Json, string = null) @safe
	{
	}

	Json sendRequest(string method, Json params) @safe
	{
		lastMethod = method;
		lastParams = params;
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		Json root = Json.emptyObject;
		root["uri"] = "file:///home/user/project";
		root["name"] = "My Project";
		arr ~= root;
		r["roots"] = arr;
		return r;
	}

	bool clientSupports(string capability) @safe
	{
		return capability == "roots" && supportsRoots;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

version (unittest) private final class ElicitProbe : RequestContext
{
	string lastMethod;
	Json lastParams;
	bool supportsElicitation = true;
	/// Per-mode submodes. When `supportsElicitation` is true these default to
	/// true so a bare elicitation declaration behaves like form+url; tests set
	/// them individually to model form-only / url-only clients.
	bool supportsForm = true;
	bool supportsUrl = true;
	bool stateless = false;

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string, Json, string = null) @safe
	{
	}

	Json sendRequest(string method, Json params) @safe
	{
		lastMethod = method;
		lastParams = params;
		Json r = Json.emptyObject;
		r["action"] = "accept";
		return r;
	}

	bool clientSupports(string capability) @safe
	{
		switch (capability)
		{
		case "elicitation":
			return supportsElicitation;
		case "elicitation.form":
			return supportsElicitation && supportsForm;
		case "elicitation.url":
			return supportsElicitation && supportsUrl;
		default:
			return false;
		}
	}

	bool isStateless() @safe
	{
		return stateless;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

unittest  // elicitUrl() emits mode:"url" with message, url, and elicitationId
{
	auto probe = new ElicitProbe;
	auto result = probe.elicitUrl("Authorize access", "https://example.com/consent", "elic-123");

	assert(probe.lastMethod == "elicitation/create");
	assert(probe.lastParams["mode"].get!string == "url");
	assert(probe.lastParams["message"].get!string == "Authorize access");
	assert(probe.lastParams["url"].get!string == "https://example.com/consent");
	assert(probe.lastParams["elicitationId"].get!string == "elic-123");
	assert(result["action"].get!string == "accept");
}

unittest  // form-mode elicit() does not set a mode field
{
	auto probe = new ElicitProbe;
	probe.elicit("Pick one", Json.emptyObject);

	assert(probe.lastParams["mode"].type == Json.Type.undefined);
	assert(probe.lastParams["message"].get!string == "Pick one");
}

unittest  // elicitUrl() rejects an empty url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "", "elic-1"));
}

unittest  // elicitUrl() rejects an empty elicitationId
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", ""));
}

unittest  // elicitUrl() rejects a malformed (non-URI) url
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "not a url", "elic-1"));
}

unittest  // elicitUrl() rejects a relative url without a scheme/authority
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	assertThrown!McpException(probe.elicitUrl("msg", "example.com/path", "elic-1"));
}

unittest  // elicitUrl() throws when the client does not support elicitation
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	probe.supportsElicitation = false;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // elicitUrl() is rejected on a stateless (MRTR) request
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new ElicitProbe;
	probe.stateless = true;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // form-mode elicit() throws when the client supports url mode only
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	// Per client/elicitation: "Servers MUST NOT send elicitation requests with
	// modes that are not supported by the client." A url-only client
	// (elicitation:{url:{}}) must not be sent a form-mode request.
	auto probe = new ElicitProbe;
	probe.supportsForm = false;
	probe.supportsUrl = true;
	assertThrown!McpException(probe.elicit("Pick one", Json.emptyObject));
}

unittest  // url-mode elicitUrl() throws when the client supports form mode only
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	// A form-only client (elicitation:{} or {form:{}}) must not be sent a
	// url-mode request.
	auto probe = new ElicitProbe;
	probe.supportsForm = true;
	probe.supportsUrl = false;
	assertThrown!McpException(probe.elicitUrl("msg", "https://example.com", "elic-1"));
}

unittest  // form-mode elicit() succeeds when the client supports form mode
{
	auto probe = new ElicitProbe;
	probe.supportsForm = true;
	probe.supportsUrl = false;
	probe.elicit("Pick one", Json.emptyObject);
	assert(probe.lastMethod == "elicitation/create");
}

unittest  // url-mode elicitUrl() succeeds when the client supports url mode
{
	auto probe = new ElicitProbe;
	probe.supportsForm = false;
	probe.supportsUrl = true;
	auto r = probe.elicitUrl("msg", "https://example.com", "elic-1");
	assert(probe.lastParams["mode"].get!string == "url");
	assert(r["action"].get!string == "accept");
}

unittest  // listRoots() sends roots/list and parses the typed result
{
	auto probe = new RootsProbe;
	auto result = probe.listRoots();

	assert(probe.lastMethod == "roots/list");
	assert(result.roots.length == 1);
	assert(result.roots[0].uri == "file:///home/user/project");
	assert(result.roots[0].name.get == "My Project");
}

unittest  // listRoots() throws when client does not support roots
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto probe = new RootsProbe;
	probe.supportsRoots = false;
	assertThrown!McpException(probe.listRoots());
}

unittest  // typed sample() builds params and parses the typed result
{
	import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage, StopReason;
	import mcp.protocol.types : Content;

	auto probe = new SamplingProbe;
	CreateMessageRequest req;
	req.messages = [SamplingMessage("user", Content.makeText("hi"))];
	req.maxTokens = 50;
	auto result = probe.sample(req);

	// Request was serialized to the wire shape.
	assert(probe.lastParams["messages"][0]["content"]["text"].get!string == "hi");
	assert(probe.lastParams["maxTokens"].get!long == 50);

	// Result parsed into a typed struct.
	assert(result.role == "assistant");
	assert(result.content.text == "echoed");
	assert(result.model == "test-model");
	assert(result.stopReasonEnum.get == StopReason.endTurn);
}

version (unittest) private final class LogProbe : RequestContext
{
	string[] emittedLevels;

	bool isCancelled() @safe
	{
		return false;
	}

	void reportProgress(double, Nullable!double = Nullable!double.init, string = null) @safe
	{
	}

	void log(string level, Json, string = null) @safe
	{
		emittedLevels ~= level;
	}

	Json sendRequest(string, Json) @safe
	{
		return Json.undefined;
	}

	bool clientSupports(string) @safe
	{
		return false;
	}

	bool isStateless() @safe
	{
		return false;
	}

	Json[string] inputResponses() @safe
	{
		Json[string] empty;
		return empty;
	}

	string requestState() @safe
	{
		return "";
	}

	TokenInfo auth() @safe
	{
		return TokenInfo.invalid();
	}
}

unittest  // RequestScope drops log messages below the configured minimum level
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto scope_ = new RequestScope(probe, false, empty, "error");

	scope_.log("debug", Json("d"));
	scope_.log("warning", Json("w"));
	scope_.log("error", Json("e"));
	scope_.log("critical", Json("c"));

	// Only error and above passed through to the inner transport context.
	assert(probe.emittedLevels == ["error", "critical"]);
}

unittest  // RequestScope with the default "info" minimum drops only debug
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto scope_ = new RequestScope(probe, false, empty);

	scope_.log("debug", Json("d"));
	scope_.log("info", Json("i"));
	scope_.log("warning", Json("w"));

	assert(probe.emittedLevels == ["info", "warning"]);
}

unittest  // RequestScope exposes the shared cancellation token via isCancelled
{
	Json[string] empty;
	auto probe = new LogProbe;
	auto token = new CancellationToken;
	auto scope_ = new RequestScope(probe, false, empty, "info", true, token);

	assert(!scope_.isCancelled);
	token.cancel();
	assert(scope_.isCancelled);
}

unittest  // a CancellationToken starts uncancelled and cancel() is idempotent
{
	auto token = new CancellationToken;
	assert(!token.cancelled);
	token.cancel();
	assert(token.cancelled);
	token.cancel();
	assert(token.cancelled);
}

unittest  // NullContext reports never-cancelled (no out-of-band channel)
{
	auto ctx = new NullContext;
	assert(!ctx.isCancelled);
}

unittest  // StdioContext.log serialises a notifications/message frame to the sink
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("warning", Json("hi"), "lg");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["jsonrpc"].get!string == "2.0");
	assert(j["method"].get!string == "notifications/message");
	assert(j["params"]["level"].get!string == "warning");
	assert(j["params"]["logger"].get!string == "lg");
	assert(j["params"]["data"].get!string == "hi");
	assert("id" !in j);
}

unittest  // StdioContext.log omits the optional logger field when none is given
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("info", Json("plain"));
	auto j = parseJsonString(frames[0]);
	assert("logger" !in j["params"]);
}

unittest  // StdioContext.log always emits the REQUIRED data field, even for an undefined payload
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto ctx = new StdioContext((string s) @safe { frames ~= s; });
	ctx.log("info", Json.undefined);
	auto j = parseJsonString(frames[0]);
	// `data` is required by server/utilities/logging; an undefined payload
	// must serialise as an explicit JSON null rather than being dropped.
	assert("data" in j["params"]);
	assert(j["params"]["data"].type == Json.Type.null_);
}

unittest  // StdioContext.reportProgress emits a frame only with a progress token
{
	import vibe.data.json : parseJsonString;

	string[] frames;
	auto withTok = new StdioContext((string s) @safe { frames ~= s; }, Json("tok"));
	withTok.reportProgress(0.25, nullableProgress(0.5), "quarter");
	assert(frames.length == 1);
	auto j = parseJsonString(frames[0]);
	assert(j["method"].get!string == "notifications/progress");
	assert(j["params"]["progressToken"].get!string == "tok");
	assert(j["params"]["progress"].get!double == 0.25);
	assert(j["params"]["total"].get!double == 0.5);
	assert(j["params"]["message"].get!string == "quarter");
}

unittest  // StdioContext.reportProgress is a no-op without a progress token
{
	string[] frames;
	auto noTok = new StdioContext((string s) @safe { frames ~= s; });
	noTok.reportProgress(0.9);
	assert(frames.length == 0);
}

unittest  // StdioContext has no server->client request channel
{
	import mcp.protocol.errors : McpException;

	auto ctx = new StdioContext((string) @safe {});
	assert(!ctx.clientSupports("sampling"));
	assert(!ctx.isCancelled);
	bool threw;
	try
		ctx.sendRequest("sampling/createMessage", Json.emptyObject);
	catch (McpException)
		threw = true;
	assert(threw);
}

version (unittest) private Nullable!double nullableProgress(double v) @safe
{
	Nullable!double n = v;
	return n;
}
