module mcp.protocol.errors;

import vibe.data.json : Json;
import mcp.protocol.capabilities : ClientCapabilities;
import mcp.protocol.versions : ProtocolVersion, resourceNotFoundCode;

@safe:

/// Standard JSON-RPC 2.0 + MCP error codes.
enum ErrorCode : int
{
	parseError = -32700,
	invalidRequest = -32600,
	methodNotFound = -32601,
	invalidParams = -32602,
	internalError = -32603,
	// MCP-specific
	resourceNotFound = -32002,
	requestCancelled = -32800,
	// draft Streamable HTTP: header/body validation failure
	headerMismatch = -32001,
	// draft: requested protocol version not supported (data: {supported, requested})
	unsupportedProtocolVersion = -32004,
	// 2025-11-25 (elicitation §"URL Elicitation Required Error"): a request
	// cannot be processed until a URL-mode elicitation is completed. The error
	// MUST carry a `data.elicitations` list of URL-mode elicitations.
	// draft basic/lifecycle (draft/schema MissingRequiredClientCapabilityError):
	// returned when processing a request requires a capability the client did
	// NOT declare in its `clientCapabilities`. HTTP transports MUST map this to
	// a 400 response. The error carries `data.requiredCapabilities` (a
	// ClientCapabilities object describing the capabilities the request needs).
	missingRequiredClientCapability = -32003,
	urlElicitationRequired = -32042,
	// sampling (client/sampling §Error Handling): the user declined the
	// server's `sampling/createMessage` request. Not a JSON-RPC reserved code;
	// the spec assigns this conventional value.
	userRejected = -1
}

/// An error that maps onto a JSON-RPC error object.
class McpException : Exception
{
	int code;
	Json data; /// optional structured payload; `Json.undefined` if none

	this(int code, string message, Json data = Json.undefined,
			string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(message, file, line);
		this.code = code;
		this.data = data;
	}
}

/// Build the JSON-RPC error object `{code, message, data?}`.
Json toErrorJson(const McpException e) @safe
{
	Json j = Json.emptyObject;
	j["code"] = e.code;
	j["message"] = e.msg;
	if (e.data.type != Json.Type.undefined)
		j["data"] = e.data;
	return j;
}

McpException parseError(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.parseError, message, data);
}

McpException invalidRequest(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.invalidRequest, message, data);
}

McpException methodNotFound(string method, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.methodNotFound, "Method not found: " ~ method, data);
}

McpException invalidParams(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.invalidParams, message, data);
}

McpException internalError(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.internalError, message, data);
}

/// Build a "resource not found" error using the legacy MCP-specific code
/// (-32002). Kept for backwards compatibility; this form always emits -32002.
/// Draft connections should instead use the version-aware overload below, which
/// selects the version-appropriate code (draft aligns it to invalidParams /
/// -32602).
McpException resourceNotFound(string uri, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.resourceNotFound, "Resource not found: " ~ uri, data);
}

/// Build a "resource not found" error whose code is selected for the negotiated
/// protocol version: draft aligns it to invalidParams (-32602), while earlier
/// versions use the MCP-specific -32002 (see `versions.resourceNotFoundCode`).
McpException resourceNotFound(string uri, ProtocolVersion v, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(v.resourceNotFoundCode, "Resource not found: " ~ uri, data);
}

/// True if `url` is a valid absolute URI suitable for a URL-mode elicitation.
///
/// Per client/elicitation §"URL Mode Elicitation Requests" (2025-11-25) the
/// `url` parameter MUST contain a valid URL, and its schema marks the field
/// `format: uri`. URL-mode elicitation drives browser navigation, so the scheme
/// is additionally restricted (case-insensitively) to `http` or `https`: a
/// non-web scheme such as `file://`, `ftp://` or `ws://` is rejected even when
/// it carries a `//authority`. (The spec only SHOULDs HTTPS, so plain `http` is
/// accepted rather than rejected here.) Beyond the scheme this requires an
/// absolute URI: the scheme is followed by `:` and a hierarchical `//authority`
/// with a non-empty host. Relative references, bare strings such as
/// `"not a url"`, and `scheme:`-only values are rejected. Validation is
/// permissive about the path/query/fragment so any real `https://…` consent or
/// OAuth URL passes.
bool isValidElicitationUrl(string url) @safe pure nothrow @nogc
{
	import std.ascii : isAlpha, isAlphaNum;

	if (url.length == 0)
		return false;

	// Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":" (RFC 3986 §3.1)
	if (!isAlpha(url[0]))
		return false;
	size_t i = 1;
	while (i < url.length)
	{
		const c = url[i];
		if (isAlphaNum(c) || c == '+' || c == '-' || c == '.')
			i++;
		else
			break;
	}
	if (i >= url.length || url[i] != ':')
		return false;
	const scheme = url[0 .. i]; // scheme text, before the ':' delimiter
	i++; // consume ':'

	// Restrict to web schemes (case-insensitive). URL-mode elicitation drives
	// browser navigation, so non-web schemes such as `file`, `ftp` or `ws` are
	// rejected even though they carry a `//authority`. Only `http`/`https` pass.
	if (!schemeEquals(scheme, "http") && !schemeEquals(scheme, "https"))
		return false;

	// Require a hierarchical authority ("//host…"). URL-mode elicitation always
	// points at a navigable web location, so opaque (authority-less) URIs such
	// as `mailto:` or `urn:` are not accepted.
	if (i + 2 > url.length || url[i] != '/' || url[i + 1] != '/')
		return false;
	i += 2; // consume "//"

	// Authority must contain a non-empty host (terminated by '/', '?' or '#').
	// Strip any "userinfo@" prefix before checking the host is non-empty.
	size_t authEnd = i;
	while (authEnd < url.length && url[authEnd] != '/' && url[authEnd] != '?' && url[authEnd] != '#')
		authEnd++;
	auto authority = url[i .. authEnd];
	foreach (j, c; authority)
	{
		if (c == '@')
			authority = authority[j + 1 .. $]; // host is whatever follows last '@'
	}
	return authority.length > 0;
}

/// ASCII case-insensitive equality for an elicitation URL scheme. Avoids the
/// allocation/`@nogc` cost of `std.uni.toLower` so `isValidElicitationUrl` can
/// stay `pure nothrow @nogc`.
private bool schemeEquals(scope const(char)[] scheme, scope string lower) @safe pure nothrow @nogc
{
	import std.ascii : toLower;

	if (scheme.length != lower.length)
		return false;
	foreach (i, c; scheme)
		if (toLower(c) != lower[i])
			return false;
	return true;
}

/// A single URL-mode elicitation entry carried by a `-32042`
/// `URLElicitationRequiredError` (2025-11-25 elicitation §"URL Elicitation
/// Required Error"). Each entry directs the user to complete an out-of-band
/// interaction at `url`; `elicitationId` correlates the request with the
/// outcome the client later reports back.
struct UrlElicitation
{
	string elicitationId; /// correlation id for the elicitation outcome
	string url; /// where the user completes the interaction
	string message; /// human-readable description shown to the user

	/// Serialize to the wire shape `{mode:"url", elicitationId, url, message}`.
	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["mode"] = "url";
		j["elicitationId"] = elicitationId;
		j["url"] = url;
		j["message"] = message;
		return j;
	}
}

/// Build the `-32042` `URLElicitationRequiredError` a server returns when a
/// request cannot be processed until one or more URL-mode elicitations are
/// completed (2025-11-25 elicitation §"URL Elicitation Required Error"). The
/// error's `data.elicitations` array carries the URL-mode elicitations the
/// client must complete first; each entry is emitted as
/// `{mode:"url", elicitationId, url, message}`.
///
/// At least one elicitation is required, and every entry MUST have a non-empty
/// `elicitationId` and a `url` that is a valid absolute URI (per the spec's
/// `format: uri` / "MUST contain a valid URL"); otherwise this throws.
McpException urlElicitationRequired(const UrlElicitation[] elicitations,
		string message = "URL elicitation required") @safe
{
	import std.exception : enforce;

	enforce(elicitations.length > 0,
			"URLElicitationRequiredError requires at least one elicitation");
	Json arr = Json.emptyArray;
	foreach (const ref e; elicitations)
	{
		enforce(e.elicitationId.length > 0, "URL elicitation requires a non-empty elicitationId");
		enforce(isValidElicitationUrl(e.url),
				"URL elicitation requires a valid url (absolute URI): " ~ e.url);
		arr ~= e.toJson();
	}
	Json data = Json.emptyObject;
	data["elicitations"] = arr;
	return new McpException(ErrorCode.urlElicitationRequired, message, data);
}

/// Build the conventional `-1` "User rejected sampling request" error a client
/// `onSampling` delegate SHOULD return when the user declines the request
/// (client/sampling §Error Handling).
McpException userRejected(string message = "User rejected sampling request",
		Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.userRejected, message, data);
}

/// Build the `-32003` `MissingRequiredClientCapabilityError` a server returns
/// when processing a request requires a client capability that was not declared
/// in the peer's `clientCapabilities` (draft basic/lifecycle,
/// draft/schema MissingRequiredClientCapabilityError). HTTP transports MUST map
/// this onto a `400 Bad Request`. The error's `data.requiredCapabilities` carries
/// a ClientCapabilities object describing the capabilities the request needs.
McpException missingRequiredClientCapability(const ClientCapabilities requiredCapabilities,
		string message = "Missing required client capability") @safe
{
	Json data = Json.emptyObject;
	data["requiredCapabilities"] = requiredCapabilities.toJson();
	return new McpException(ErrorCode.missingRequiredClientCapability, message, data);
}

unittest  // McpException carries code and message
{
	auto e = new McpException(ErrorCode.invalidParams, "bad arg");
	assert(e.code == -32602);
	assert(e.msg == "bad arg");
}

unittest  // convenience constructors set the right code
{
	assert(methodNotFound("nope").code == ErrorCode.methodNotFound);
	assert(invalidParams("x").code == ErrorCode.invalidParams);
	assert(resourceNotFound("file:///x").code == ErrorCode.resourceNotFound);
}

unittest  // resourceNotFound (no-version) keeps the legacy -32002 code
{
	auto e = resourceNotFound("file:///x");
	assert(e.code == -32002);
	assert(e.code == ErrorCode.resourceNotFound);
	assert(e.msg == "Resource not found: file:///x");
}

unittest  // resourceNotFound(version) selects -32602 for draft, -32002 otherwise
{
	assert(resourceNotFound("file:///x", ProtocolVersion.draft).code == -32602);
	assert(resourceNotFound("file:///x", ProtocolVersion.v2025_11_25).code == -32002);
	assert(resourceNotFound("file:///x", ProtocolVersion.v2024_11_05).code == -32002);
	// message still carries the uri
	assert(resourceNotFound("file:///x", ProtocolVersion.draft)
			.msg == "Resource not found: file:///x");
}

unittest  // toErrorJson produces a JSON-RPC error object
{
	auto e = new McpException(ErrorCode.internalError, "boom");
	auto j = e.toErrorJson();
	assert(j["code"].get!int == -32603);
	assert(j["message"].get!string == "boom");
	assert("data" !in j); // undefined data omitted
}

unittest  // userRejected uses the conventional -1 sampling code
{
	auto e = userRejected();
	assert(e.code == -1);
	assert(e.code == ErrorCode.userRejected);
	assert(e.msg == "User rejected sampling request");
}

unittest  // userRejected accepts a custom message
{
	auto e = userRejected("nope, not this time");
	assert(e.code == ErrorCode.userRejected);
	assert(e.msg == "nope, not this time");
}

unittest  // toErrorJson includes data when present
{
	auto e = new McpException(ErrorCode.invalidParams, "bad", Json([
		"field": Json("name")
	]));
	auto j = e.toErrorJson();
	assert(j["data"]["field"].get!string == "name");
}

unittest  // urlElicitationRequired uses the -32042 code
{
	auto e = urlElicitationRequired([
		UrlElicitation("elic-1", "https://example.com/consent", "Authorize access")
	]);
	assert(e.code == -32042);
	assert(e.code == ErrorCode.urlElicitationRequired);
}

unittest  // urlElicitationRequired attaches the data.elicitations array
{
	auto e = urlElicitationRequired([
		UrlElicitation("elic-1", "https://example.com/consent", "Authorize access")
	]);
	auto j = e.toErrorJson();
	auto elics = j["data"]["elicitations"];
	assert(elics.type == Json.Type.array);
	assert(elics.length == 1);
	assert(elics[0]["mode"].get!string == "url");
	assert(elics[0]["elicitationId"].get!string == "elic-1");
	assert(elics[0]["url"].get!string == "https://example.com/consent");
	assert(elics[0]["message"].get!string == "Authorize access");
}

unittest  // urlElicitationRequired carries multiple elicitations
{
	auto e = urlElicitationRequired([
		UrlElicitation("a", "https://example.com/a", "first"),
		UrlElicitation("b", "https://example.com/b", "second")
	]);
	auto j = e.toErrorJson();
	assert(j["data"]["elicitations"].length == 2);
	assert(j["data"]["elicitations"][1]["elicitationId"].get!string == "b");
}

unittest  // urlElicitationRequired requires at least one elicitation
{
	import std.exception : assertThrown;

	assertThrown!Exception(urlElicitationRequired([]));
}

unittest  // urlElicitationRequired rejects an entry missing elicitationId
{
	import std.exception : assertThrown;

	assertThrown!Exception(urlElicitationRequired([
		UrlElicitation("", "https://example.com", "msg")
	]));
}

unittest  // urlElicitationRequired rejects an entry missing url
{
	import std.exception : assertThrown;

	assertThrown!Exception(urlElicitationRequired([
		UrlElicitation("id", "", "msg")
	]));
}

unittest  // missingRequiredClientCapability uses the -32003 code
{
	ClientCapabilities req;
	req.sampling = true;
	auto e = missingRequiredClientCapability(req);
	assert(e.code == -32003);
	assert(e.code == ErrorCode.missingRequiredClientCapability);
}

unittest  // missingRequiredClientCapability carries data.requiredCapabilities
{
	ClientCapabilities req;
	req.sampling = true;
	auto e = missingRequiredClientCapability(req);
	auto j = e.toErrorJson();
	assert("requiredCapabilities" in j["data"]);
	assert(j["data"]["requiredCapabilities"]["sampling"].type == Json.Type.object);
}

unittest  // missingRequiredClientCapability requiredCapabilities matches ClientCapabilities.toJson
{
	ClientCapabilities req;
	req.elicitation = true;
	req.elicitationUrl = true;
	auto e = missingRequiredClientCapability(req);
	auto j = e.toErrorJson();
	assert(j["data"]["requiredCapabilities"] == req.toJson());
}

unittest  // missingRequiredClientCapability has a default message
{
	ClientCapabilities req;
	req.roots = true;
	auto e = missingRequiredClientCapability(req);
	assert(e.msg.length > 0);
}

unittest  // missingRequiredClientCapability accepts a custom message
{
	ClientCapabilities req;
	req.sampling = true;
	auto e = missingRequiredClientCapability(req, "needs sampling");
	assert(e.code == ErrorCode.missingRequiredClientCapability);
	assert(e.msg == "needs sampling");
}

unittest  // isValidElicitationUrl accepts ordinary https/http URLs
{
	assert(isValidElicitationUrl("https://example.com/consent"));
	assert(isValidElicitationUrl("http://example.com"));
	assert(isValidElicitationUrl("https://mcp.example.com/connect?elicitationId=abc#frag"));
	assert(isValidElicitationUrl("https://user@host.example/path"));
}

unittest  // isValidElicitationUrl rejects malformed / non-absolute values
{
	assert(!isValidElicitationUrl(""));
	assert(!isValidElicitationUrl("not a url"));
	assert(!isValidElicitationUrl("example.com"));
	assert(!isValidElicitationUrl("/relative/path"));
	assert(!isValidElicitationUrl("https://")); // no host
	assert(!isValidElicitationUrl("https:///path")); // empty authority
	assert(!isValidElicitationUrl("mailto:user@example.com")); // no //authority
	assert(!isValidElicitationUrl("://example.com")); // no scheme
}

unittest  // isValidElicitationUrl rejects non-web schemes that still carry a //authority
{
	// URL-mode elicitation drives browser navigation, so only http/https are
	// acceptable even though these all have a hierarchical "//host" authority.
	assert(!isValidElicitationUrl("file://host/path"));
	assert(!isValidElicitationUrl("ftp://host/x"));
	assert(!isValidElicitationUrl("ws://host"));
	assert(!isValidElicitationUrl("wss://host/socket"));
}

unittest  // isValidElicitationUrl still accepts http/https (case-insensitive scheme)
{
	assert(isValidElicitationUrl("http://example.com"));
	assert(isValidElicitationUrl("https://example.com/consent"));
	assert(isValidElicitationUrl("HTTPS://example.com/consent"));
	assert(isValidElicitationUrl("HtTp://example.com"));
}

unittest  // urlElicitationRequired throws on a malformed url
{
	import std.exception : assertThrown;

	auto bad = [UrlElicitation("elic-1", "not a url", "msg")];
	assertThrown(urlElicitationRequired(bad));
}

unittest  // urlElicitationRequired accepts a valid absolute url
{
	auto ok = [UrlElicitation("elic-1", "https://example.com/connect", "msg")];
	auto e = urlElicitationRequired(ok);
	assert(e.code == ErrorCode.urlElicitationRequired);
	assert(e.data["elicitations"].length == 1);
	assert(e.data["elicitations"][0]["url"].get!string == "https://example.com/connect");
}
