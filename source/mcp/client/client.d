module mcp.client.client;

import std.algorithm : canFind, startsWith;
import std.typecons : Nullable, nullable;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.protocol.sampling : validateSamplingMessages, CreateMessageRequest, CreateMessageResult;
import mcp.protocol.draft;
import mcp.client.transport : ClientTransport, ClientProtocol;
import mcp.client.http_transport : HttpClientTransport, LegacyFallbackException;
import mcp.client.stdio : StdioClientTransport, spawnStdioTransport;
import mcp.client.subscription : SubscriptionStream, SubscriptionFilter;

/// A progress token attached to an outgoing request so the server may emit
/// `notifications/progress` for it. Per basic/utilities/progress, "Progress
/// tokens MUST be a string or integer value" and "MUST be unique across all
/// active requests". Construct one from either a `string` or a `long`; an
/// unset token is omitted from the request.
struct ProgressToken
{
	private Json value_ = Json.undefined;

	/// A string-valued progress token.
	this(string token) @safe nothrow
	{
		value_ = Json(token);
	}

	/// An integer-valued progress token.
	this(long token) @safe nothrow
	{
		value_ = Json(token);
	}

	/// Whether a token has been set (false for a default-constructed token).
	bool isSet() const @safe nothrow
	{
		return value_.type != Json.Type.undefined;
	}

	/// The token as JSON (a string or integer), or `Json.undefined` when unset.
	Json toJson() const @safe nothrow
	{
		return value_;
	}
}

/// Merge `progressToken` into a request's `params._meta.progressToken`, per
/// basic/utilities/progress ("a party ... includes a progressToken in the
/// request metadata", at `params._meta.progressToken`). Returns `params`
/// unchanged when the token is unset. Any existing `_meta` keys are preserved.
/// Exposed so callers can attach a progress token to a hand-built params object
/// (e.g. for request methods without a dedicated progress-token overload).
Json withProgressToken(Json params, ProgressToken token) @safe
{
	if (!token.isSet)
		return params;
	if (params.type != Json.Type.object)
		params = Json.emptyObject;
	Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
		: Json.emptyObject;
	meta["progressToken"] = token.toJson();
	params["_meta"] = meta;
	return params;
}

/// A Model Context Protocol client, transport-agnostic.
///
/// Speaks pure JSON-RPC + protocol logic over a `ClientTransport` (Streamable
/// HTTP via `McpClient.http`/`McpClient.spawn`, or stdio via `McpClient.stdio`).
/// Drives the lifecycle (`initialize` + `notifications/initialized`) and the
/// server features (tools, resources, prompts, completion, logging,
/// subscriptions) with auto-pagination. Server->client requests received on an
/// inbound stream (sampling / elicitation / roots) are dispatched to the
/// user-supplied handlers and answered via the transport.
final class McpClient : ClientProtocol
{
	// The byte transport (HTTP/stdio). All JSON-RPC I/O routes through it.
	private ClientTransport transport;
	private ProtocolVersion negotiated = latestStable;
	private bool didInitialize;
	private bool useDraft;
	private long nextId = 1;
	// Opt-in: validate tool results against the tool's outputSchema (client side).
	private bool validateOutputSchema_;
	// URL-mode elicitation correlation: ids the server asked us to complete via
	// an `elicitation/create` with `mode:"url"`, mapped to whether we have already
	// observed their `notifications/elicitation/complete`. Used to honour the spec
	// rule "Clients MUST ignore notifications referencing unknown or
	// already-completed IDs."
	private bool[string] elicitationIds_;
	// Request ids this client has cancelled via notifications/cancelled. Per
	// basic/utilities/cancellation, "The sender of the cancellation notification
	// SHOULD ignore any response to the request that arrives afterward", so a
	// late response correlated to one of these ids is dropped rather than
	// returned. Keyed by the JSON-RPC id under which the request was POSTed.
	private bool[long] cancelledRequests_;
	// The JSON-RPC id used for the `initialize` request, so cancel() can enforce
	// the spec rule that clients MUST NOT cancel initialize. 0 until sent.
	private long initializeRequestId;
	// Tool inputSchemas seen via tools/list, keyed by tool name. Used by the
	// draft client to mirror x-mcp-header-annotated tool-call arguments into
	// Mcp-Param-{Name} headers (draft basic/transports, "Custom Headers from
	// Tool Parameters"). Populated by listTools; consumed by `headersFor`,
	// which the HTTP transport calls to obtain the per-message headers.
	private Json[string] toolInputSchemas_;

	/// Capabilities this client advertises at initialize. Treated as a baseline:
	/// unless `autoAdvertiseCapabilities` is disabled, the capabilities actually
	/// sent are this value augmented from the installed handlers (see
	/// `effectiveCapabilities`), so installing `onSampling`/`onElicitation`/
	/// `onListRoots` auto-advertises `sampling`/`elicitation`/`roots`.
	ClientCapabilities capabilities;
	/// When true (the default), the capabilities advertised at `initialize`
	/// (and in every draft per-request `_meta`) are derived from which handlers
	/// are installed: `onSampling` implies `sampling`, `onElicitation` implies
	/// `elicitation` (form submode), `onListRoots` implies `roots`. Anything
	/// already set on `capabilities` is preserved (e.g. submodes, `listChanged`,
	/// `tasks`), so this only ever adds the presence flags a handler implies and
	/// never clears an explicit advertisement. Set to false to advertise exactly
	/// `capabilities` and nothing more (the explicit-override escape hatch).
	bool autoAdvertiseCapabilities = true;
	/// This client's identity.
	Implementation clientInfo;

	/// Handler for `sampling/createMessage`; receives the typed
	/// `CreateMessageRequest` params and returns the typed `CreateMessageResult`.
	/// Null => unsupported (the client answers `roots/list`-style with
	/// `Method not found`). The SDK validates the request's tool-result message
	/// constraints (client/sampling §Error Handling) before invoking this.
	CreateMessageResult delegate(CreateMessageRequest request) @safe onSampling;
	/// Handler for `elicitation/create`; receives the typed `ElicitParams` and
	/// returns the typed `ElicitResult`. Null => unsupported.
	///
	/// Form-mode requests (the default, when `mode` is absent or `"form"`)
	/// populate `message` and `requestedSchema`; collect the input and return
	/// `ElicitResult.accept(content)` (or `decline()`/`cancel()`). URL-mode
	/// requests (2025-11-25+) set `mode == "url"` and carry `url` and
	/// `elicitationId` instead of a schema — present the URL for the user to
	/// complete out-of-band and return an action (no content). The SDK enforces
	/// the advertised-mode capability check before invoking this.
	ElicitResult delegate(ElicitParams params) @safe onElicitation;
	/// Handler for `roots/list`; returns the typed `ListRootsResult`. Null =>
	/// unsupported. (`roots/list` carries no meaningful params, so the handler
	/// takes none; prefer `setRoots` for the common static-roots case.)
	ListRootsResult delegate() @safe onListRoots;
	/// Observer for inbound notifications (progress, message, resource updates).
	void delegate(string method, Json params) @safe onNotification;
	/// Typed observer for `notifications/progress` (basic/utilities/progress).
	///
	/// When set, an inbound `notifications/progress` is parsed into a
	/// `ProgressNotification` and delivered here in addition to the generic
	/// `onNotification`. Correlate `n.progressToken` against the
	/// `ProgressToken` you attached to the originating request (see the
	/// `callTool`/`readResource`/`getPrompt` overloads taking a `ProgressToken`)
	/// to track an individual request's progress.
	void delegate(ProgressNotification n) @safe onProgress;
	/// Typed observer for `notifications/message` (server/utilities/logging).
	///
	/// When set, an inbound `notifications/message` is parsed into a
	/// `LogMessageNotification` and delivered here in addition to the generic
	/// `onNotification`. Inspect `n.level` (a `LogLevel`), the optional
	/// `n.logger`, and the arbitrary `n.data` payload to present log output in
	/// the UI / display severity visually.
	void delegate(LogMessageNotification n) @safe onLogMessage;

	/// Construct over an explicit `ClientTransport`. The client installs its
	/// inbound dispatcher (and, for the HTTP transport, the per-message header /
	/// cancelled-response callbacks) on the transport.
	this(ClientTransport transport,
			Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
	{
		this.transport = transport;
		this.clientInfo = clientInfo;
		transport.setInboundHandler(&dispatchInbound);
		// Hand the transport this client as its `ClientProtocol`: it pulls the
		// protocol-derived request headers (`headersFor`) and the cancelled-response
		// predicate (`isCancelled`) through that single seam, so the draft-header /
		// schema-cache logic and the cancellation set stay here and no transport has
		// to be a concrete type the client downcasts to.
		transport.setProtocol(this);
	}

	/// Build a client over the Streamable HTTP transport at `url`.
	static McpClient http(string url,
			Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
	{
		return new McpClient(new HttpClientTransport(url), clientInfo);
	}

	/// Build a client over the stdio transport, exchanging newline-delimited
	/// JSON-RPC over the supplied `readLine`/`writeLine` channel (symmetric to
	/// `mcp.transport.stdio.serveStdio`). `readLine` returns the next server line
	/// (without its terminator) or `null` at end-of-input; `writeLine` emits one
	/// message line (the sink appends the terminator).
	static McpClient stdio(string delegate() @safe readLine, void delegate(string) @safe writeLine,
			Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
	{
		return new McpClient(new StdioClientTransport(readLine, writeLine), clientInfo);
	}

	/// Launch an MCP server as a subprocess and build a client over its
	/// stdin/stdout (stderr inherited for logging). `command` is the command line
	/// (`command[0]` is the executable). The returned client is NOT yet
	/// initialized — call `initialize()` (or `ping()` for a stateless probe).
	/// `close()` runs the MCP stdio shutdown sequence on the subprocess.
	static McpClient spawn(string[] command,
			Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
	{
		return new McpClient(spawnStdioTransport(command), clientInfo);
	}

	/// Release the underlying transport (stdio terminates the subprocess; HTTP
	/// stops any background streams).
	void close() @safe
	{
		transport.close();
	}

	/// The protocol version negotiated with the server (valid after initialize).
	ProtocolVersion protocolVersion() const @safe
	{
		return negotiated;
	}

	/// Switch to the stateless draft (2026-07-28) protocol: no `initialize`
	/// handshake; every request carries `_meta` (protocolVersion / clientInfo /
	/// clientCapabilities) and the standard `Mcp-Method` / `Mcp-Name` /
	/// `MCP-Protocol-Version` headers. Call `discover()` for up-front version
	/// selection, or just issue requests.
	void enableDraft() @safe
	{
		useDraft = true;
		negotiated = ProtocolVersion.draft;
	}

	/// `server/discover` (draft): fetch the server's supported versions,
	/// capabilities, and identity.
	DiscoverResult discover() @safe
	{
		return DiscoverResult.fromJson(rpc("server/discover", Json.emptyObject));
	}

	/// Attach an OAuth bearer access token, sent as `Authorization: Bearer
	/// <token>` on every subsequent request (HTTP transport). Pass an empty
	/// string to clear it; a no-op over stdio.
	void setBearerToken(string token) @safe
	{
		transport.setBearerToken(token);
	}

	/// Perform the initialize handshake and send `notifications/initialized`.
	InitializeResult initialize(string requestedVersion = latestStable.toWire) @safe
	{
		InitializeParams params;
		params.protocolVersion = requestedVersion;
		params.capabilities = effectiveCapabilities();
		params.clientInfo = clientInfo;

		// Record the id the initialize request will use so cancel() can refuse
		// to cancel it (clients MUST NOT cancel initialize).
		initializeRequestId = nextId;
		auto result = rpc("initialize", params.toJson());
		auto init = InitializeResult.fromJson(result);
		// Per the Lifecycle / Version Negotiation rules: if the client does not
		// support the version in the server's response it SHOULD disconnect.
		// Validate before completing the handshake so we never silently proceed
		// under a version the server did not agree to.
		negotiated = resolveNegotiatedVersion(init.protocolVersion);
		didInitialize = true;
		notify("notifications/initialized", Json.emptyObject);
		return init;
	}

	/// Connect to a server whose protocol era is unknown, per the transport
	/// backward-compatibility rules. Probes `server/discover` first:
	///   - success → modern server; switch to the newest mutually-supported
	///     version (stateless draft mode if that version uses per-request
	///     `_meta`, otherwise an `initialize` handshake for that stable version);
	///   - `Method not found` (-32601) → legacy server; fall back to the
	///     `initialize` handshake;
	///   - `UnsupportedProtocolVersionError` (-32004) → modern server; pick from
	///     the advertised `supported` list rather than falling back.
	/// Returns the negotiated protocol version. Throws if there is no mutually
	/// supported version, or on any other error.
	ProtocolVersion connect() @safe
	{
		string[] serverVersions;
		try
		{
			serverVersions = discover().protocolVersions;
		}
		catch (LegacyFallbackException)
		{
			// Modern POST rejected with 400/404/405: this is (or may be) an old
			// HTTP+SSE server. Ask the transport to open its backward-compatibility
			// fallback (HTTP: the legacy two-endpoint GET-SSE transport; a no-op on
			// transports without one), then run the legacy initialize handshake.
			transport.startLegacyFallback();
			initialize(ProtocolVersion.v2024_11_05.toWire);
			return negotiated;
		}
		catch (McpException e)
		{
			if (e.code == ErrorCode.methodNotFound)
			{
				initialize(); // legacy initialize-based server
				return negotiated;
			}
			if (e.code == ErrorCode.unsupportedProtocolVersion)
				serverVersions = supportedListFromError(e);
			else
				throw e;
		}

		ProtocolVersion chosen;
		if (!selectMutualVersion(serverVersions, chosen))
			throw new McpException(ErrorCode.unsupportedProtocolVersion,
					"No mutually supported protocol version");

		if (chosen.isDraft)
		{
			useDraft = true;
			negotiated = chosen;
		}
		else
			initialize(chosen.toWire); // modern discovery, pre-draft version
		return negotiated;
	}

	/// Extract the `supported` wire-version list from an
	/// `UnsupportedProtocolVersionError`. `errorFrom` stores the whole JSON-RPC
	/// error object in `data`, so the list lives at `data.data.supported`.
	private static string[] supportedListFromError(McpException e) @safe
	{
		auto d = e.data;
		if (d.type == Json.Type.object && "data" in d && d["data"].type == Json.Type.object)
			d = d["data"];
		string[] versions;
		if (d.type == Json.Type.object && "supported" in d && d["supported"].type == Json
				.Type.array)
		{
			auto arr = d["supported"];
			foreach (i; 0 .. arr.length)
				if (arr[i].type == Json.Type.string)
					versions ~= arr[i].get!string;
		}
		return versions;
	}

	/// `ping` — returns when the server acknowledges.
	void ping() @safe
	{
		rpc("ping", Json.emptyObject);
	}

	/// `tools/list`, following pagination cursors to completion. Returns the
	/// drained `ListToolsResult`: `tools` aggregates every page's items,
	/// `nextCursor` is null, and `cache` carries the first page's parsed draft
	/// `CacheableResult` freshness hint (if any).
	ListToolsResult listTools() @safe
	{
		ListToolsResult acc;
		Nullable!string cursor;
		bool first = true;
		do
		{
			Json p = Json.emptyObject;
			if (!cursor.isNull)
				p["cursor"] = cursor.get;
			auto res = ListToolsResult.fromJson(rpc("tools/list", p));
			acc.tools ~= res.tools;
			if (first)
			{
				acc.cache = res.cache;
				first = false;
			}
			cursor = res.nextCursor;
		}
		while (!cursor.isNull);
		acc.nextCursor = Nullable!string.init;
		// Cache each tool's inputSchema so a subsequent tools/call can mirror any
		// x-mcp-header-annotated arguments into Mcp-Param-{Name} headers (draft
		// basic/transports, "Custom Headers from Tool Parameters").
		foreach (t; acc.tools)
			cacheToolSchema(t.name, t.inputSchema);
		return acc;
	}

	/// Record a tool's `inputSchema` (keyed by tool name) so the draft client can
	/// mirror its x-mcp-header-annotated arguments into `Mcp-Param-*` headers on a
	/// later `tools/call`. Normally populated automatically by `listTools`; exposed
	/// so callers that obtain a `Tool` descriptor by other means (e.g. a cached
	/// `tools/list` result, or a `notifications/tools/list_changed` refresh) can
	/// register it too. A non-object schema is ignored.
	void cacheToolSchema(string name, Json inputSchema) @safe
	{
		if (name.length && inputSchema.type == Json.Type.object)
			toolInputSchemas_[name] = inputSchema;
	}

	/// `tools/call`.
	///
	/// Against a draft (MRTR / SEP-2322) server this transparently completes a
	/// Multi Round-Trip Request: if the server answers with an
	/// `InputRequiredResult` (the result carries `inputRequests`), each request is
	/// dispatched to the matching `onSampling` / `onElicitation` / `onListRoots`
	/// handler and the original `tools/call` is resubmitted with the answers in
	/// the top-level `params.inputResponses` map (and the server's opaque
	/// `requestState` echoed back), looping until the server returns a completed
	/// `CallToolResult`. The loop only
	/// engages when draft mode is enabled (see `enableDraft`/`connect`); other
	/// protocol versions never see `inputRequests`.
	CallToolResult callTool(string name, Json arguments = Json.emptyObject) @safe
	{
		return callToolLoop(name, arguments, ProgressToken.init);
	}

	/// `tools/call`, requesting progress updates for the call. The server may
	/// then emit `notifications/progress` carrying `progressToken`, observable
	/// via `onNotification`. Per basic/utilities/progress, the token is sent in
	/// `params._meta.progressToken`. Drives the same MRTR loop as the no-token
	/// overload (see `callTool`).
	CallToolResult callTool(string name, Json arguments, ProgressToken progressToken) @safe
	{
		return callToolLoop(name, arguments, progressToken);
	}

	/// Issue `tools/call` and, against a draft server, complete any MRTR
	/// (SEP-2322) round-trips by satisfying each `InputRequest` and resubmitting
	/// the request with the answers. Returns the first completed `CallToolResult`.
	///
	/// A bound is placed on the number of rounds so a misbehaving server that
	/// keeps asking for input cannot loop forever. If a handler for a requested
	/// input type is missing, or the loop bound is exceeded, the (still
	/// `inputRequired`) result is returned so the caller can inspect it via
	/// `CallToolResult.isInputRequired`.
	private CallToolResult callToolLoop(string name, Json arguments, ProgressToken progressToken) @safe
	{
		enum maxRounds = 16;
		InputResponse[] responses;
		// SEP-2322: the opaque requestState the server attached on the prior
		// round, which the client MUST echo back verbatim on the retry.
		string requestState;
		foreach (round; 0 .. maxRounds)
		{
			auto params = buildToolCallParams(name, arguments, progressToken,
					responses, requestState);
			auto result = CallToolResult.fromJson(rpc("tools/call", params));
			if (!result.isInputRequired)
				return result;
			// Gather an answer for each requested input. If any cannot be
			// satisfied (no handler registered), stop and hand the
			// inputRequired result back to the caller.
			InputResponse[] answers;
			foreach (req; result.inputRequests)
			{
				InputResponse answer;
				if (!resolveInputRequest(req, answer))
					return result;
				answers ~= answer;
			}
			responses = answers;
			// Echo the server's opaque requestState on the next retry (empty
			// when the server sent none).
			requestState = result.requestState;
		}
		// Bound exceeded: return whatever the last round produced (still an
		// inputRequired result) rather than looping forever.
		return CallToolResult.fromJson(rpc("tools/call", buildToolCallParams(name,
				arguments, progressToken, responses, requestState)));
	}

	/// Satisfy one MRTR `InputRequest` by dispatching it to the matching client
	/// handler, writing the answer into `answer` (keyed by `req.id`). Returns
	/// `false` (leaving `answer` untouched) when no handler is registered for the
	/// request's type, so the caller can surface the unanswered
	/// `InputRequiredResult`. `req.type` maps to the server-initiated request the
	/// MRTR round replaces: `"sampling"`→`onSampling`, `"elicitation"`→
	/// `onElicitation`, `"roots"`→`onListRoots`.
	private bool resolveInputRequest(InputRequest req, out InputResponse answer) @safe
	{
		Json result;
		switch (req.type)
		{
		case "sampling":
			if (onSampling is null)
				return false;
			validateSamplingMessages(req.params);
			result = onSampling(CreateMessageRequest.fromJson(req.params)).toJson();
			break;
		case "elicitation":
			if (onElicitation is null)
				return false;
			result = onElicitation(ElicitParams.fromJson(req.params)).toJson();
			break;
		case "roots":
			if (onListRoots is null)
				return false;
			result = onListRoots().toJson();
			break;
		default:
			return false;
		}
		answer = InputResponse(req.id, result);
		return true;
	}

	/// Build the `tools/call` params, optionally attaching a progress token.
	/// Separated so the param shaping (including `_meta.progressToken`) can be
	/// unit-tested without a live server.
	package static Json buildToolCallParams(string name, Json arguments,
			ProgressToken progressToken) @safe
	{
		Json p = Json.emptyObject;
		p["name"] = name;
		p["arguments"] = arguments;
		return withProgressToken(p, progressToken);
	}

	/// Build the `tools/call` params with any gathered MRTR (SEP-2322) input
	/// responses attached as the top-level `params.inputResponses` map, and the
	/// opaque `requestState` echoed back as `params.requestState`. Per SEP-2322
	/// these are RequestParams fields, NOT `_meta` entries. With no responses
	/// and no requestState this is identical to the plain `buildToolCallParams`.
	/// Separated as a package static so the resubmission param shaping can be
	/// unit-tested without a live server.
	package static Json buildToolCallParams(string name, Json arguments,
			ProgressToken progressToken, InputResponse[] responses, string requestState = "") @safe
	{
		Json p = buildToolCallParams(name, arguments, progressToken);
		p = withInputResponses(p, responses);
		return withRequestState(p, requestState);
	}

	/// Attach MRTR (SEP-2322) input responses to a request as the top-level
	/// `params.inputResponses` map (id -> bare client result). An empty
	/// `responses` list returns `params` unchanged. Exposed so callers can
	/// attach answers to a hand-built params object.
	static Json withInputResponses(Json params, InputResponse[] responses) @safe
	{
		if (responses.length == 0)
			return params;
		if (params.type != Json.Type.object)
			params = Json.emptyObject;
		// SEP-2322: `inputResponses` is a top-level RequestParams field — an
		// `InputResponses` object keyed by the originating `InputRequest.id`
		// whose values are the bare client results — NOT a `_meta` entry.
		params["inputResponses"] = inputResponsesToJson(responses);
		return params;
	}

	/// Echo the server's opaque MRTR (SEP-2322) `requestState` back on a retried
	/// request as the top-level `params.requestState` field. The client MUST NOT
	/// inspect or modify the value, and MUST NOT include one when the server sent
	/// none — so an empty `requestState` returns `params` unchanged.
	static Json withRequestState(Json params, string requestState) @safe
	{
		if (requestState.length == 0)
			return params;
		if (params.type != Json.Type.object)
			params = Json.emptyObject;
		params["requestState"] = requestState;
		return params;
	}

	/// `tools/call` for a tool whose descriptor (and therefore `outputSchema`) is
	/// known — typically one returned by `listTools`. When the client has output-
	/// schema validation enabled (see `enableOutputSchemaValidation`) and `tool`
	/// carries an `outputSchema`, the returned `structuredContent` is validated
	/// against it: per the spec, "Clients SHOULD validate structured results
	/// against this schema." A non-conforming result raises a clear
	/// `McpException` rather than being accepted silently.
	CallToolResult callTool(const Tool tool, Json arguments = Json.emptyObject) @safe
	{
		auto result = callTool(tool.name, arguments);
		if (validateOutputSchema_)
		{
			const msg = validateOutput(tool, result);
			if (msg.length)
				throw new McpException(ErrorCode.invalidParams, "Tool '" ~ tool.name
						~ "' returned structuredContent that does not conform to its outputSchema: " ~ msg);
		}
		return result;
	}

	/// Opt in to validating tool results against the tool's `outputSchema` when
	/// calling `callTool(Tool, ...)`. Off by default; existing call sites are
	/// unaffected.
	void enableOutputSchemaValidation() @safe
	{
		validateOutputSchema_ = true;
	}

	/// Validate a `CallToolResult`'s `structuredContent` against `tool`'s
	/// `outputSchema`, independent of the opt-in flag. Returns an empty string
	/// when it conforms (including when the tool has no output schema or the
	/// result has no structured content), otherwise a description of the first
	/// violation. Exposed so callers can validate explicitly without enabling
	/// automatic validation.
	static string validateOutput(const Tool tool, const CallToolResult result) @safe
	{
		import mcp.api.schema : validateAgainstSchema;

		if (tool.outputSchema.type != Json.Type.object)
			return "";
		if (result.structuredContent.type == Json.Type.undefined)
			return "";
		return validateAgainstSchema(result.structuredContent, tool.outputSchema);
	}

	/// `resources/list`, auto-paginated. Returns the drained
	/// `ListResourcesResult`: `resources` aggregates every page, `nextCursor` is
	/// null, and `cache` carries the first page's parsed freshness hint.
	ListResourcesResult listResources() @safe
	{
		ListResourcesResult acc;
		Nullable!string cursor;
		bool first = true;
		do
		{
			Json p = Json.emptyObject;
			if (!cursor.isNull)
				p["cursor"] = cursor.get;
			auto res = ListResourcesResult.fromJson(rpc("resources/list", p));
			acc.resources ~= res.resources;
			if (first)
			{
				acc.cache = res.cache;
				first = false;
			}
			cursor = res.nextCursor;
		}
		while (!cursor.isNull);
		acc.nextCursor = Nullable!string.init;
		return acc;
	}

	/// `resources/templates/list`, auto-paginated. Returns the drained
	/// `ListResourceTemplatesResult` (URI templates clients can expand and
	/// `resources/read`). `resourceTemplates` aggregates every page, `nextCursor`
	/// is null, and `cache` carries the first page's parsed freshness hint.
	ListResourceTemplatesResult listResourceTemplates() @safe
	{
		ListResourceTemplatesResult acc;
		Nullable!string cursor;
		bool first = true;
		do
		{
			Json p = Json.emptyObject;
			if (!cursor.isNull)
				p["cursor"] = cursor.get;
			auto res = ListResourceTemplatesResult.fromJson(rpc("resources/templates/list", p));
			acc.resourceTemplates ~= res.resourceTemplates;
			if (first)
			{
				acc.cache = res.cache;
				first = false;
			}
			cursor = res.nextCursor;
		}
		while (!cursor.isNull);
		acc.nextCursor = Nullable!string.init;
		return acc;
	}

	/// `resources/read`.
	ReadResourceResult readResource(string uri) @safe
	{
		return ReadResourceResult.fromJson(rpc("resources/read",
				buildReadResourceParams(uri, ProgressToken.init)));
	}

	/// `resources/read`, requesting progress updates for the read (see
	/// `callTool` with a `ProgressToken`).
	ReadResourceResult readResource(string uri, ProgressToken progressToken) @safe
	{
		return ReadResourceResult.fromJson(rpc("resources/read",
				buildReadResourceParams(uri, progressToken)));
	}

	/// Build the `resources/read` params, optionally attaching a progress token.
	package static Json buildReadResourceParams(string uri, ProgressToken progressToken) @safe
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		return withProgressToken(p, progressToken);
	}

	/// `prompts/list`, auto-paginated. Returns the drained `ListPromptsResult`:
	/// `prompts` aggregates every page, `nextCursor` is null, and `cache` carries
	/// the first page's parsed freshness hint.
	ListPromptsResult listPrompts() @safe
	{
		ListPromptsResult acc;
		Nullable!string cursor;
		bool first = true;
		do
		{
			Json p = Json.emptyObject;
			if (!cursor.isNull)
				p["cursor"] = cursor.get;
			auto res = ListPromptsResult.fromJson(rpc("prompts/list", p));
			acc.prompts ~= res.prompts;
			if (first)
			{
				acc.cache = res.cache;
				first = false;
			}
			cursor = res.nextCursor;
		}
		while (!cursor.isNull);
		acc.nextCursor = Nullable!string.init;
		return acc;
	}

	/// `prompts/get`.
	GetPromptResult getPrompt(string name, Json arguments = Json.emptyObject) @safe
	{
		return GetPromptResult.fromJson(rpc("prompts/get",
				buildGetPromptParams(name, arguments, ProgressToken.init)));
	}

	/// `prompts/get`, requesting progress updates for the request (see
	/// `callTool` with a `ProgressToken`).
	GetPromptResult getPrompt(string name, Json arguments, ProgressToken progressToken) @safe
	{
		return GetPromptResult.fromJson(rpc("prompts/get",
				buildGetPromptParams(name, arguments, progressToken)));
	}

	/// Build the `prompts/get` params, optionally attaching a progress token.
	package static Json buildGetPromptParams(string name, Json arguments,
			ProgressToken progressToken) @safe
	{
		Json p = Json.emptyObject;
		p["name"] = name;
		p["arguments"] = arguments;
		return withProgressToken(p, progressToken);
	}

	/// `completion/complete` — request autocompletion suggestions for an
	/// argument of a prompt or resource template, per server/utilities/completion
	/// §"Requesting Completions". `reference` identifies what is being completed
	/// (use `CompletionReference.forPrompt` / `forResource`); `argumentName` and
	/// `argumentValue` are the argument being filled in and its partial value.
	/// `context`, when non-null, supplies previously-resolved argument values
	/// (`{name: value}`) so the server can give context-aware completions.
	CompleteResult complete(CompletionReference reference, string argumentName,
			string argumentValue, string[string] context = null) @safe
	{
		return CompleteResult.fromJson(rpc("completion/complete",
				buildCompleteParams(reference, argumentName, argumentValue, context)));
	}

	/// Build the `completion/complete` request params. Separated from `complete`
	/// so the param shaping can be unit-tested without a live server.
	package static Json buildCompleteParams(CompletionReference reference,
			string argumentName, string argumentValue, string[string] context) @safe
	{
		Json p = Json.emptyObject;
		p["ref"] = reference.toJson();
		Json arg = Json.emptyObject;
		arg["name"] = argumentName;
		arg["value"] = argumentValue;
		p["argument"] = arg;
		if (context.length)
		{
			Json args = Json.emptyObject;
			foreach (k, v; context)
				args[k] = v;
			Json ctx = Json.emptyObject;
			ctx["arguments"] = args;
			p["context"] = ctx;
		}
		return p;
	}

	/// `resources/subscribe` / `resources/unsubscribe`.
	void subscribe(string uri) @safe
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		rpc("resources/subscribe", p);
	}

	void unsubscribe(string uri) @safe
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		rpc("resources/unsubscribe", p);
	}

	/// Open a draft `subscriptions/listen` notification stream (draft
	/// basic/utilities/subscriptions). This replaces the removed
	/// `resources/subscribe` RPC and the standalone HTTP GET notification
	/// endpoint: it POSTs `subscriptions/listen` with a `{notifications:{...}}`
	/// filter (built from `filter`), the server upgrades the response to a
	/// long-lived `text/event-stream`, and this client reads it on a background
	/// task — delivering the leading `notifications/subscriptions/acknowledged`
	/// and every subsequent opted-in change notification to `onNotification`
	/// (and `onProgress` for progress). Returns a `SubscriptionStream` handle;
	/// call its `cancel()`/`close()` to stop listening and close the stream.
	///
	/// Only meaningful for draft servers (call `enableDraft`/`connect` first);
	/// pre-draft servers do not implement `subscriptions/listen`.
	SubscriptionStream subscriptionsListen(SubscriptionFilter filter) @safe
	{
		const id = nextId++;
		Json params = buildSubscriptionsListenParams(filter);
		if (useDraft)
			params = injectDraftMeta(params);
		auto message = makeRequest(Json(id), "subscriptions/listen", params);
		return transport.openListen(message);
	}

	/// Build the `subscriptions/listen` params, nesting the filter under
	/// `params.notifications` exactly as the draft spec's `SubscriptionFilter`
	/// requires (boolean list-changed flags emitted only when set;
	/// `resourceSubscriptions` as a string array of URIs). Separated so the param
	/// shaping can be unit-tested without a live server.
	package static Json buildSubscriptionsListenParams(SubscriptionFilter filter) @safe
	{
		Json notifications = Json.emptyObject;
		if (filter.toolsListChanged)
			notifications["toolsListChanged"] = true;
		if (filter.promptsListChanged)
			notifications["promptsListChanged"] = true;
		if (filter.resourcesListChanged)
			notifications["resourcesListChanged"] = true;
		if (filter.resourceSubscriptions.length)
		{
			Json uris = Json.emptyArray;
			foreach (uri; filter.resourceSubscriptions)
				uris ~= Json(uri);
			notifications["resourceSubscriptions"] = uris;
		}
		Json p = Json.emptyObject;
		p["notifications"] = notifications;
		return p;
	}

	/// `logging/setLevel`.
	void setLogLevel(string level) @safe
	{
		Json p = Json.emptyObject;
		p["level"] = level;
		rpc("logging/setLevel", p);
	}

	// --- transport internals -------------------------------------------------

	/// Test seam: when set, `rpc` routes the (method, params) pair here and
	/// returns the delegate's `result` payload instead of POSTing to a server,
	/// so paginating request methods can be exercised without a live server.
	/// Production code never sets this.
	package Json delegate(string method, Json params) @safe onRpcForTest;

	/// Send a request and return its result (or throw `McpException`).
	private Json rpc(string method, Json params) @safe
	{
		if (onRpcForTest !is null)
			return onRpcForTest(method, params);
		const id = nextId++;
		if (useDraft)
			params = injectDraftMeta(params);
		auto message = makeRequest(Json(id), method, params);
		return transport.deliver(message, id);
	}

	/// The capabilities actually advertised on the wire: `capabilities` augmented
	/// from the installed handlers when `autoAdvertiseCapabilities` is true.
	/// Installing `onSampling` advertises `sampling`, `onElicitation` advertises
	/// `elicitation` (defaulting to the form submode unless a submode is already
	/// declared), and `onListRoots` advertises `roots`. Explicit flags already set
	/// on `capabilities` are never cleared. When `autoAdvertiseCapabilities` is
	/// false, `capabilities` is returned verbatim. Drives both the `initialize`
	/// handshake and the draft per-request `_meta`.
	ClientCapabilities effectiveCapabilities() const @safe
	{
		ClientCapabilities caps = capabilities;
		if (!autoAdvertiseCapabilities)
			return caps;
		if (onSampling !is null)
			caps.sampling = true;
		if (onElicitation !is null)
		{
			caps.elicitation = true;
			// A bare `elicitation` object means form mode only; declare the form
			// submode unless the caller has already advertised a submode explicitly.
			if (!caps.elicitationForm && !caps.elicitationUrl)
				caps.elicitationForm = true;
		}
		if (onListRoots !is null)
			caps.roots = true;
		return caps;
	}

	/// Add the draft per-request `_meta` (protocol version, client identity,
	/// capabilities) to a request's params.
	private Json injectDraftMeta(Json params) @safe
	{
		if (params.type != Json.Type.object)
			params = Json.emptyObject;
		Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"] : Json
			.emptyObject;
		meta[MetaKey.protocolVersion] = negotiated.toWire;
		meta[MetaKey.clientInfo] = clientInfo.toJson();
		meta[MetaKey.clientCapabilities] = effectiveCapabilities().toJson();
		params["_meta"] = meta;
		return params;
	}

	/// Test seam: when set, `notify` routes the built notification message here
	/// instead of POSTing it, so the public notification API can be exercised
	/// without a live server. Production code never sets this.
	package void delegate(Json message) @safe onNotifyForTest;

	/// Send a notification (no reply expected).
	private void notify(string method, Json params) @safe
	{
		auto message = makeNotification(method, params);
		if (onNotifyForTest !is null)
		{
			onNotifyForTest(message);
			return;
		}
		transport.sendOneway(message);
	}

	/// Send an arbitrary client-originated JSON-RPC notification to the server
	/// (no reply expected). This is the public entry point for client→server
	/// notifications such as `notifications/roots/list_changed`; the lifecycle's
	/// `notifications/initialized` is sent automatically by `initialize`.
	void sendNotification(string method, Json params = Json.emptyObject) @safe
	{
		notify(method, params);
	}

	/// The JSON-RPC id assigned to the most recently issued request. Useful to
	/// learn the id of an in-flight request so it can be `cancel`led from another
	/// task (the blocking `rpc` does not otherwise surface it). Returns `0`
	/// before any request has been sent.
	long lastRequestId() const @safe nothrow @nogc
	{
		return nextId - 1;
	}

	/// Cancel an in-flight request by sending `notifications/cancelled` for
	/// `requestId` (basic/utilities/cancellation: "Either side can send a
	/// cancellation notification ... to indicate that a previously-issued request
	/// should be terminated"). After this call, any response the server still
	/// sends for `requestId` is ignored, per "The sender of the cancellation
	/// notification SHOULD ignore any response to the request that arrives
	/// afterward". `reason` is an optional free-form explanation included in the
	/// notification when non-empty.
	///
	/// Per spec, the `initialize` request MUST NOT be cancelled by clients;
	/// attempting to cancel the id of the `initialize` request throws.
	void cancel(long requestId, string reason = null) @safe
	{
		if (requestId == initializeRequestId && initializeRequestId != 0)
			throw invalidRequest("The initialize request MUST NOT be cancelled by clients");
		cancelledRequests_[requestId] = true;
		Json params = Json.emptyObject;
		params["requestId"] = requestId;
		if (reason.length)
			params["reason"] = reason;
		notify("notifications/cancelled", params);
	}

	/// Register the client's filesystem roots using the typed `Root` API,
	/// mirroring the typed result types the SDK provides for tools, resources
	/// and prompts. This installs an `onListRoots` handler that answers
	/// `roots/list` with a properly-shaped `{roots: [{uri, name}]}` envelope, so
	/// callers no longer have to hand-construct the raw JSON. Each `uri` MUST be
	/// a `file://` URI per client/roots §Data Types.
	void setRoots(Root[] roots) @safe
	{
		auto rs = roots.dup;
		onListRoots = () @safe {
			ListRootsResult result;
			result.roots = rs;
			return result;
		};
	}

	/// Emit `notifications/roots/list_changed`, informing the server that this
	/// client's set of roots has changed. Per client/roots §Root List Changes,
	/// a client that advertises the roots `listChanged` capability MUST send
	/// this notification whenever its roots change. Call this after updating the
	/// roots returned by `onListRoots` (or after `setRoots`).
	void notifyRootsListChanged() @safe
	{
		notify("notifications/roots/list_changed", Json.emptyObject);
	}

	/// `ClientProtocol.headersFor`: compute the protocol-derived request headers
	/// for an outgoing `message`, which the transport pulls through the
	/// `ClientProtocol` seam. For a draft client this is the `MCP-Protocol-Version`
	/// header plus the standard `Mcp-Method` / `Mcp-Name` headers and any
	/// `Mcp-Param-*` mirrored tool arguments (draft basic/transports). For a stable
	/// client it is just `MCP-Protocol-Version` after initialize. Called with
	/// `Json.undefined` (no message — e.g. the GET server stream) it returns only
	/// the version header. Keeps the draft-header logic and the tool inputSchema
	/// cache in the client rather than the transport.
	string[string] headersFor(Json message) @safe
	{
		string[string] headers;
		if (useDraft)
		{
			headers[HttpHeader.protocolVersion] = negotiated.toWire;
			if (message.type != Json.Type.object || "method" !in message)
				return headers; // no message (GET stream) or a response: version only
			const method = message["method"].get!string;
			headers[HttpHeader.method] = method;
			auto params = ("params" in message) ? message["params"] : Json.emptyObject;
			string name;
			if (method == "tools/call" || method == "prompts/get")
			{
				if ("name" in params && params["name"].type == Json.Type.string)
					name = params["name"].get!string;
			}
			else if (method == "resources/read")
			{
				if ("uri" in params && params["uri"].type == Json.Type.string)
					name = params["uri"].get!string;
			}
			if (name.length)
				headers[HttpHeader.name] = name;

			// Mirror x-mcp-header-annotated tool arguments into Mcp-Param-{Name}
			// headers (draft basic/transports, "Custom Headers from Tool
			// Parameters"): clients MUST inspect the tool's inputSchema and append a
			// header for each annotated argument that is present and non-null.
			if (method == "tools/call" && name.length)
			{
				auto schema = name in toolInputSchemas_;
				if (schema !is null)
				{
					auto args = ("arguments" in params) ? params["arguments"] : Json.emptyObject;
					foreach (header, value; paramHeaders(*schema, args))
						headers[header] = value;
				}
			}
		}
		else if (didInitialize)
			headers["MCP-Protocol-Version"] = negotiated.toWire;
		return headers;
	}

	/// Compute the `Mcp-Param-*` headers to emit for a `tools/call`, given the
	/// tool's `inputSchema` and the call `arguments`. For each top-level property
	/// annotated with `x-mcp-header` (see `paramHeaderMap`), the matching argument
	/// value is encoded with `encodeHeaderValue` and mapped to its
	/// `Mcp-Param-{Name}` header. Per the draft spec's mirroring table, an
	/// argument that is absent or `null` produces no header. Non-string scalars
	/// (numbers, booleans) are stringified; object/array values are emitted as
	/// their compact JSON. Separated as a pure static helper so the mirroring can
	/// be unit-tested without a live server.
	package static string[string] paramHeaders(Json inputSchema, Json arguments) @safe
	{
		string[string] headers;
		auto map = paramHeaderMap(inputSchema);
		if (map.length == 0 || arguments.type != Json.Type.object)
			return headers;
		foreach (param, header; map)
		{
			if (param !in arguments)
				continue; // absent -> no header
			auto v = arguments[param];
			if (v.type == Json.Type.null_ || v.type == Json.Type.undefined)
				continue; // null -> no header
			string raw;
			final switch (v.type)
			{
			case Json.Type.string:
				raw = v.get!string;
				break;
			case Json.Type.int_:
			case Json.Type.bigInt:
			case Json.Type.float_:
			case Json.Type.bool_:
				raw = v.toString();
				break;
			case Json.Type.object:
			case Json.Type.array:
				raw = v.toString();
				break;
			case Json.Type.null_:
			case Json.Type.undefined:
				continue;
			}
			headers[header] = encodeHeaderValue(raw);
		}
		return headers;
	}

	/// Forward an inbound notification to `onNotification`, applying the protocol
	/// rules for notifications the SDK understands. Currently this enforces the
	/// URL-mode elicitation rule (basic/utilities/elicitation §"Completion
	/// Notifications for URL Mode Elicitation"): "Clients MUST ignore
	/// notifications referencing unknown or already-completed IDs." A
	/// `notifications/elicitation/complete` for an `elicitationId` we never issued
	/// a URL-mode request for, or one we have already seen completed, is dropped
	/// (never forwarded); the first valid completion for a known id is forwarded
	/// and then marked completed. Every other notification is forwarded unchanged.
	private void dispatchNotification(string method, Json params) @safe
	{
		if (method == "notifications/elicitation/complete")
		{
			if (params.type != Json.Type.object || "elicitationId" !in params
					|| params["elicitationId"].type != Json.Type.string)
				return; // malformed: no id to correlate -> ignore
			const eid = params["elicitationId"].get!string;
			auto seen = eid in elicitationIds_;
			if (seen is null || *seen)
				return; // unknown or already-completed id -> ignore per spec
			elicitationIds_[eid] = true; // mark completed
		}
		// Deliver progress updates as a typed value to the dedicated observer,
		// in addition to the generic catch-all below.
		if (method == "notifications/progress" && onProgress !is null)
			onProgress(ProgressNotification.fromJson(params));
		// Deliver log messages as a typed value to the dedicated observer,
		// in addition to the generic catch-all below.
		if (method == "notifications/message" && onLogMessage !is null)
			onLogMessage(LogMessageNotification.fromJson(params));
		if (onNotification !is null)
			onNotification(method, params);
	}

	/// Dispatch an inbound message handed up by the transport: server->
	/// client requests and notifications (never an awaited response).
	private void dispatchInbound(Message msg) @safe
	{
		final switch (msg.kind)
		{
		case MessageKind.request:
			handleServerRequest(msg);
			break;
		case MessageKind.notification:
			dispatchNotification(msg.method, msg.params);
			break;
		case MessageKind.response:
		case MessageKind.errorResponse:
			break; // not expected on the listening stream
		}
	}

	/// Open the standalone server->client stream (HTTP GET SSE), so the server
	/// can deliver sampling / elicitation / roots requests and notifications
	/// outside of any request response. A no-op on stdio (and tolerated as a
	/// no-op when an HTTP server does not offer the stream).
	void startServerStream() @safe
	{
		transport.startServerStream();
	}

	/// Answer a server->client request by dispatching to the matching handler
	/// and sending the response on a *separate* task. Sending on its own task is
	/// essential: we are currently inside the transport's inbound-read callback of
	/// the original request, and the server will not send that request's final
	/// response until it receives this one — a synchronous nested send here would
	/// deadlock.
	private void handleServerRequest(Message msg) @safe
	{
		import vibe.core.core : runTask;

		Json response;
		try
		{
			Json result = dispatchServerMethod(msg.method, msg.params);
			response = makeResponse(msg.id, result);
		}
		catch (McpException e)
			response = makeErrorResponse(msg.id, e);
		catch (Exception e)
			response = makeErrorResponse(msg.id, internalError(e.msg));

		runTask((Json r) nothrow{
			try
				transport.sendOneway(r);
			catch (Exception)
			{
			}
		}, response);
	}

	private Json dispatchServerMethod(string method, Json params) @safe
	{
		switch (method)
		{
		case "sampling/createMessage":
			if (onSampling is null)
				throw methodNotFound(method);
			// Enforce the spec's tool-result message-content constraints
			// before handing off to the delegate: a tool_result user message
			// must contain only tool results, and every assistant tool_use
			// must be answered by a matching tool_result. Violations surface
			// as -32602 (Invalid params) per client/sampling §Error Handling.
			validateSamplingMessages(params);
			return onSampling(CreateMessageRequest.fromJson(params)).toJson();
		case "elicitation/create":
			if (onElicitation is null)
				throw methodNotFound(method);
			// Per client/elicitation §Error Handling (2025-11-25): reject a
			// request whose `mode` was not declared in client capabilities with
			// -32602 (Invalid params). `mode` defaults to "form" when absent.
			// A bare `elicitation` declaration is equivalent to form-mode only,
			// so `elicitation` alone satisfies the form case.
			{
				const mode = ("mode" in params && params["mode"].type == Json.Type.string) ? params["mode"]
					.get!string : "form";
				bool supported;
				switch (mode)
				{
				case "form":
					// A bare `elicitation` declaration is parsed as form-capable
					// (elicitationForm=true). An explicit url-only declaration
					// (`{"url":{}}` => elicitation=true, elicitationUrl=true,
					// elicitationForm=false) does NOT declare form mode, so it must
					// not satisfy the form case.
					supported = capabilities.elicitationForm
						|| (capabilities.elicitation && !capabilities.elicitationUrl);
					break;
				case "url":
					supported = capabilities.elicitationUrl;
					break;
				default:
					supported = false;
					break;
				}
				if (!supported)
					throw invalidParams("Unsupported elicitation mode: " ~ mode);
				// Remember the id of a URL-mode request so a later
				// notifications/elicitation/complete can be correlated; an
				// unknown id is ignored per the spec.
				if (mode == "url" && "elicitationId" in params
						&& params["elicitationId"].type == Json.Type.string)
				{
					const eid = params["elicitationId"].get!string;
					if (eid.length && eid !in elicitationIds_)
						elicitationIds_[eid] = false; // tracked, not yet completed
				}
			}
			return onElicitation(ElicitParams.fromJson(params)).toJson();
		case "roots/list":
			if (onListRoots is null)
				throw methodNotFound(method);
			return onListRoots().toJson();
		case "ping":
			return Json.emptyObject;
		default:
			throw methodNotFound(method);
		}
	}

	/// Whether a response with JSON-RPC id `id` belongs to a request this client
	/// has cancelled (and so should be ignored per basic/utilities/cancellation).
	/// Exposed for tests; cheap membership check on the cancelled-id set.
	package bool isResponseCancelled(long id) const @safe nothrow
	{
		return (id in cancelledRequests_) !is null;
	}

	/// `ClientProtocol.isCancelled`: the transport consults this through the
	/// `ClientProtocol` seam to drop a late response for a request the client has
	/// cancelled (basic/utilities/cancellation).
	bool isCancelled(long id) @safe
	{
		return isResponseCancelled(id);
	}

	/// Test seam: set the id `cancel()` treats as the (uncancellable) initialize
	/// request, without driving the live `initialize` handshake.
	package void setInitializeRequestIdForTest(long id) @safe nothrow @nogc
	{
		initializeRequestId = id;
	}

	private static McpException errorFrom(Json error) @safe
	{
		const code = ("code" in error) ? error["code"].get!int : ErrorCode.internalError;
		const m = ("message" in error) ? error["message"].get!string : "server error";
		return new McpException(code, m, error);
	}
}

/// Pick the newest protocol version both this SDK and the server support, given
/// the server's advertised wire-string list (from `server/discover` or the
/// `supported` field of an `UnsupportedProtocolVersionError`). Returns false
/// when there is no overlap. Used by `McpClient.connect` for modern-vs-legacy
/// server detection per the transport backward-compatibility rules.
bool selectMutualVersion(const string[] serverVersions, out ProtocolVersion chosen) @safe
{
	import std.range : retro;

	foreach (cand; supportedVersions.retro) // newest (draft) first
	{
		foreach (s; serverVersions)
		{
			ProtocolVersion sv;
			if (tryParseVersion(s, sv) && sv == cand)
			{
				chosen = cand;
				return true;
			}
		}
	}
	return false;
}

/// Validate the protocol version the server returned in its `initialize`
/// response and return the version to operate under. Per the Lifecycle /
/// Version Negotiation requirement ("If the client does not support the version
/// in the server's response, it SHOULD disconnect"), throws an
/// `UnsupportedProtocolVersionError` `McpException` when the server's version is
/// unparseable or not in `supportedVersions`, rather than silently proceeding
/// under a stale negotiated version.
ProtocolVersion resolveNegotiatedVersion(string serverVersion) @safe
{
	ProtocolVersion v;
	if (!tryParseVersion(serverVersion, v))
		throw new McpException(ErrorCode.unsupportedProtocolVersion,
				"Server returned unsupported protocol version: " ~ serverVersion);
	return v;
}

unittest  // public flagship type uses single-cap Mcp* casing (issue #304)
{
	// The client class must be reachable under the consistent `McpClient`
	// name (matching McpServer, McpException, etc.), not `MCPClient`.
	static assert(is(McpClient == class));
	auto c = McpClient.http("http://localhost");
	assert(c !is null);
}

unittest  // resolveNegotiatedVersion accepts a supported server version
{
	assert(resolveNegotiatedVersion("2025-06-18") == ProtocolVersion.v2025_06_18);
	assert(resolveNegotiatedVersion("2026-07-28") == ProtocolVersion.draft);
}

unittest  // resolveNegotiatedVersion throws on an unparseable server version
{
	import std.exception : assertThrown;

	assertThrown!McpException(resolveNegotiatedVersion("1999-01-01"));
}

unittest  // resolveNegotiatedVersion throws with the unsupported-version error code
{
	bool threw;
	try
		resolveNegotiatedVersion("not-a-version");
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.unsupportedProtocolVersion);
	}
	assert(threw);
}

unittest  // selectMutualVersion prefers the newest mutually-supported version
{
	ProtocolVersion v;
	assert(selectMutualVersion(["2025-11-25", "2026-07-28"], v) && v == ProtocolVersion.draft);
	assert(selectMutualVersion(["2024-11-05", "2025-03-26"], v) && v == ProtocolVersion.v2025_03_26);
}

unittest  // selectMutualVersion reports no overlap
{
	ProtocolVersion v;
	assert(!selectMutualVersion(["1999-01-01"], v));
	assert(!selectMutualVersion([], v));
}

unittest  // validateOutput passes a conforming structured result
{
	import mcp.api.schema : jsonSchemaOf;

	struct AddResult
	{
		int result;
	}

	Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
	CallToolResult r;
	r.structuredContent = Json(["result": Json(5)]);
	assert(McpClient.validateOutput(t, r) == "");
}

unittest  // validateOutput rejects a non-conforming structured result
{
	import mcp.api.schema : jsonSchemaOf;

	struct AddResult
	{
		int result;
	}

	Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
	CallToolResult r;
	r.structuredContent = Json(["result": Json("oops")]);
	assert(McpClient.validateOutput(t, r).length > 0);
}

unittest  // validateOutput is a no-op when the tool has no output schema
{
	Tool t = {name: "noschema"};
	CallToolResult r;
	r.structuredContent = Json(["anything": Json(1)]);
	assert(McpClient.validateOutput(t, r) == "");
}

unittest  // validateOutput is a no-op when there is no structured content
{
	import mcp.api.schema : jsonSchemaOf;

	struct AddResult
	{
		int result;
	}

	Tool t = {name: "add", outputSchema: jsonSchemaOf!AddResult};
	CallToolResult r; // structuredContent stays undefined
	assert(McpClient.validateOutput(t, r) == "");
}

unittest  // sampling dispatch rejects an unbalanced tool_use with -32602
{
	auto c = McpClient.http("http://localhost");
	bool delegateCalled;
	c.onSampling = (CreateMessageRequest request) @safe {
		delegateCalled = true;
		return CreateMessageResult.init;
	};

	// assistant tool_use with no following tool_result user message.
	Json tu = Json.emptyObject;
	tu["type"] = "tool_use";
	tu["id"] = "call_1";
	tu["name"] = "get_weather";
	tu["input"] = Json.emptyObject;
	Json m = Json.emptyObject;
	m["role"] = "assistant";
	m["content"] = Json([tu]);
	Json params = Json.emptyObject;
	params["messages"] = Json([m]);

	bool threw;
	try
		c.dispatchServerMethod("sampling/createMessage", params);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
		assert(e.msg == "Tool result missing in request");
	}
	assert(threw);
	assert(!delegateCalled); // validation runs before the delegate
}

unittest  // notifyRootsListChanged emits the spec notification method
{
	auto c = McpClient.http("http://localhost");
	Json sent = Json.undefined;
	c.onNotifyForTest = (Json message) @safe { sent = message; };

	c.notifyRootsListChanged();

	assert(sent.type == Json.Type.object);
	assert(sent["jsonrpc"].get!string == "2.0");
	assert("id" !in sent); // a notification has no id
	assert(sent["method"].get!string == "notifications/roots/list_changed");
}

unittest  // setRoots answers roots/list with the typed envelope
{
	auto c = McpClient.http("http://localhost");
	c.setRoots([
		Root("file:///home/user/project", nullable("My Project")),
		Root("file:///tmp")
	]);

	assert(c.onListRoots !is null);
	auto parsed = c.onListRoots();
	auto result = parsed.toJson();
	assert(result["roots"].type == Json.Type.array);
	assert(result["roots"].length == 2);
	assert(result["roots"][0]["uri"].get!string == "file:///home/user/project");
	assert(result["roots"][0]["name"].get!string == "My Project");
	assert(result["roots"][1]["uri"].get!string == "file:///tmp");
	assert("name" !in result["roots"][1]);
	assert(parsed.roots.length == 2);
	assert(parsed.roots[0].name.get == "My Project");
}

unittest  // installing onSampling auto-advertises the sampling capability
{
	auto c = McpClient.http("http://localhost");
	assert(!c.effectiveCapabilities().sampling); // nothing installed yet
	c.onSampling = (CreateMessageRequest request) @safe {
		return CreateMessageResult.init;
	};
	auto caps = c.effectiveCapabilities();
	assert(caps.sampling);
	assert("sampling" in caps.toJson());
}

unittest  // installing onElicitation auto-advertises elicitation (form submode)
{
	auto c = McpClient.http("http://localhost");
	assert(!c.effectiveCapabilities().elicitation);
	c.onElicitation = (ElicitParams params) @safe { return ElicitResult.init; };
	auto caps = c.effectiveCapabilities();
	assert(caps.elicitation);
	assert(caps.elicitationForm); // a bare handler means form mode only
	auto j = caps.toJson();
	assert(j["elicitation"].type == Json.Type.object);
	assert("form" in j["elicitation"]);
}

unittest  // installing onListRoots auto-advertises the roots capability
{
	auto c = McpClient.http("http://localhost");
	assert(!c.effectiveCapabilities().roots);
	c.setRoots([Root("file:///tmp")]); // installs onListRoots
	auto caps = c.effectiveCapabilities();
	assert(caps.roots);
	assert("roots" in caps.toJson());
}

unittest  // auto-advertise preserves explicitly declared submodes (url)
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationUrl = true; // explicit url-only advertisement
	c.onElicitation = (ElicitParams params) @safe { return ElicitResult.init; };
	auto caps = c.effectiveCapabilities();
	assert(caps.elicitationUrl);
	assert(!caps.elicitationForm); // not forced to form when a submode is set
}

unittest  // disabling autoAdvertiseCapabilities is the explicit override escape hatch
{
	auto c = McpClient.http("http://localhost");
	c.autoAdvertiseCapabilities = false;
	c.onSampling = (CreateMessageRequest request) @safe {
		return CreateMessageResult.init;
	};
	auto caps = c.effectiveCapabilities();
	assert(!caps.sampling); // handler is installed but not advertised
	assert("sampling" !in caps.toJson());
}

unittest  // initialize advertises capabilities derived from installed handlers
{
	auto c = McpClient.http("http://localhost");
	c.onSampling = (CreateMessageRequest request) @safe {
		return CreateMessageResult.init;
	};
	Json initParams = Json.undefined;
	c.onNotifyForTest = (Json message) @safe {}; // swallow notifications/initialized
	c.onRpcForTest = (string method, Json params) @safe {
		if (method == "initialize")
			initParams = params;
		// Minimal initialize result so the handshake completes.
		Json res = Json.emptyObject;
		res["protocolVersion"] = latestStable.toWire;
		res["capabilities"] = Json.emptyObject;
		Json info = Json.emptyObject;
		info["name"] = "srv";
		info["version"] = "1.0";
		res["serverInfo"] = info;
		return res;
	};
	c.initialize();
	assert(initParams.type == Json.Type.object);
	auto advertised = initParams["capabilities"];
	assert(advertised.type == Json.Type.object);
	assert("sampling" in advertised); // auto-derived from onSampling
}

unittest  // sendNotification sends an arbitrary client-originated notification
{
	auto c = McpClient.http("http://localhost");
	Json sent = Json.undefined;
	c.onNotifyForTest = (Json message) @safe { sent = message; };

	Json params = Json.emptyObject;
	params["progressToken"] = "tok-1";
	params["progress"] = 42;
	c.sendNotification("notifications/progress", params);

	assert(sent.type == Json.Type.object);
	assert(sent["method"].get!string == "notifications/progress");
	assert("id" !in sent);
	assert(sent["params"]["progressToken"].get!string == "tok-1");
	assert(sent["params"]["progress"].get!int == 42);
}

unittest  // cancel() emits notifications/cancelled with the requestId and reason
{
	auto c = McpClient.http("http://localhost");
	Json sent = Json.undefined;
	c.onNotifyForTest = (Json message) @safe { sent = message; };

	c.cancel(7, "user aborted");

	assert(sent.type == Json.Type.object);
	assert(sent["jsonrpc"].get!string == "2.0");
	assert("id" !in sent); // a notification has no id
	assert(sent["method"].get!string == "notifications/cancelled");
	assert(sent["params"]["requestId"].get!long == 7);
	assert(sent["params"]["reason"].get!string == "user aborted");
}

unittest  // cancel() without a reason omits the reason field
{
	auto c = McpClient.http("http://localhost");
	Json sent = Json.undefined;
	c.onNotifyForTest = (Json message) @safe { sent = message; };

	c.cancel(3);

	assert(sent["params"]["requestId"].get!long == 3);
	assert("reason" !in sent["params"]);
}

unittest  // after cancel(), a response for that id is treated as cancelled (ignored)
{
	auto c = McpClient.http("http://localhost");
	c.onNotifyForTest = (Json message) @safe {};

	assert(!c.isResponseCancelled(11));
	c.cancel(11);
	assert(c.isResponseCancelled(11));
	// Unrelated ids are unaffected.
	assert(!c.isResponseCancelled(12));
}

unittest  // cancel() refuses to cancel the initialize request per spec
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto c = McpClient.http("http://localhost");
	c.onNotifyForTest = (Json message) @safe {};
	// Simulate that the initialize request used id 5.
	c.setInitializeRequestIdForTest(5);
	assertThrown!McpException(c.cancel(5));
	// A different in-flight request id is still cancellable.
	c.cancel(6);
	assert(c.isResponseCancelled(6));
}

unittest  // sampling dispatch forwards a valid request to the delegate
{
	auto c = McpClient.http("http://localhost");
	bool delegateCalled;
	string seenText;
	c.onSampling = (CreateMessageRequest request) @safe {
		delegateCalled = true;
		// The handler now receives the typed request, parsed from the wire.
		if (request.messages.length)
			seenText = request.messages[0].content.text;
		return CreateMessageResult.init;
	};

	// A SamplingMessage's content is a single content block (object) per the
	// schema, not an array.
	Json b = Json.emptyObject;
	b["type"] = "text";
	b["text"] = "hi";
	Json m = Json.emptyObject;
	m["role"] = "user";
	m["content"] = b;
	Json params = Json.emptyObject;
	params["messages"] = Json([m]);

	c.dispatchServerMethod("sampling/createMessage", params);
	assert(delegateCalled);
	assert(seenText == "hi");
}

unittest  // elicitation/create rejects a mode the client did not advertise (-32602)
{
	auto c = McpClient.http("http://localhost");
	// Advertise form mode only (the default bare elicitation declaration).
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["mode"] = "url"; // not advertised
	params["url"] = "https://example.com/elicit";
	params["elicitationId"] = "e1";

	bool threw;
	try
		c.dispatchServerMethod("elicitation/create", params);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw);
	assert(!delegateCalled); // validation runs before the delegate
}

unittest  // elicitation/create rejects an unknown mode (-32602)
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["mode"] = "telepathy"; // not a known mode

	bool threw;
	try
		c.dispatchServerMethod("elicitation/create", params);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw);
	assert(!delegateCalled);
}

unittest  // elicitation/create forwards an advertised mode to the delegate
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;
	c.capabilities.elicitationUrl = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["mode"] = "url";
	params["url"] = "https://example.com/elicit";
	params["elicitationId"] = "e1";

	c.dispatchServerMethod("elicitation/create", params);
	assert(delegateCalled);
}

unittest  // url-only client rejects a form-mode elicitation/create (-32602)
{
	auto c = McpClient.http("http://localhost");
	// A url-only client is the canonical shape parsed from `{"url":{}}`:
	// elicitation present + url submode, but no form submode.
	c.capabilities.elicitation = true;
	c.capabilities.elicitationUrl = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["mode"] = "form"; // not advertised by a url-only client
	params["requestedSchema"] = Json.emptyObject;

	bool threw;
	try
		c.dispatchServerMethod("elicitation/create", params);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw);
	assert(!delegateCalled); // validation runs before the delegate
}

unittest  // url-only client rejects a mode-absent (defaults to form) elicitation/create (-32602)
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationUrl = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	// No `mode` field => defaults to "form", which the url-only client did not advertise.
	Json params = Json.emptyObject;
	params["requestedSchema"] = Json.emptyObject;

	bool threw;
	try
		c.dispatchServerMethod("elicitation/create", params);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw);
	assert(!delegateCalled);
}

unittest  // bare elicitation declaration still accepts form-mode requests
{
	auto c = McpClient.http("http://localhost");
	// A bare `{}` declaration is parsed as elicitationForm=true; ensure the
	// tightened check does not regress that case.
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["requestedSchema"] = Json.emptyObject; // mode absent => form

	c.dispatchServerMethod("elicitation/create", params);
	assert(delegateCalled);
}

unittest  // elicitation/complete for a known id is forwarded once, then ignored
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;
	c.capabilities.elicitationUrl = true;
	c.onElicitation = (ElicitParams) @safe { return ElicitResult.init; };

	// The server issues a URL-mode request; the client records the id.
	Json create = Json.emptyObject;
	create["mode"] = "url";
	create["url"] = "https://example.com/elicit";
	create["elicitationId"] = "e-known";
	c.dispatchServerMethod("elicitation/create", create);

	string[] seenMethods;
	c.onNotification = (string method, Json) @safe { seenMethods ~= method; };

	Json note = Json.emptyObject;
	note["elicitationId"] = "e-known";
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(seenMethods.length == 1); // forwarded once

	// A second completion for the same (already-completed) id is ignored.
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(seenMethods.length == 1);
}

unittest  // elicitation/complete for an unknown id is ignored
{
	auto c = McpClient.http("http://localhost");
	bool forwarded;
	c.onNotification = (string, Json) @safe { forwarded = true; };

	Json note = Json.emptyObject;
	note["elicitationId"] = "never-issued";
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(!forwarded);
}

unittest  // elicitation/complete without an elicitationId is ignored
{
	auto c = McpClient.http("http://localhost");
	bool forwarded;
	c.onNotification = (string, Json) @safe { forwarded = true; };

	c.dispatchNotification("notifications/elicitation/complete", Json.emptyObject);
	assert(!forwarded);
}

unittest  // other notifications are forwarded unchanged
{
	auto c = McpClient.http("http://localhost");
	string forwarded;
	c.onNotification = (string method, Json) @safe { forwarded = method; };

	c.dispatchNotification("notifications/message", Json.emptyObject);
	assert(forwarded == "notifications/message");
}

unittest  // notifications/progress is delivered to the typed onProgress observer
{
	auto c = McpClient.http("http://localhost");
	ProgressNotification got;
	bool called;
	c.onProgress = (ProgressNotification n) @safe { got = n; called = true; };

	Json p = Json.emptyObject;
	p["progressToken"] = "job-1";
	p["progress"] = 3;
	p["total"] = 4;
	p["message"] = "working";
	c.dispatchNotification("notifications/progress", p);

	assert(called);
	assert(got.progressToken.get!string == "job-1");
	assert(got.progress == 3);
	assert(!got.total.isNull && got.total.get == 4);
	assert(!got.message.isNull && got.message.get == "working");
}

unittest  // a non-progress notification does not invoke onProgress
{
	auto c = McpClient.http("http://localhost");
	bool called;
	c.onProgress = (ProgressNotification) @safe { called = true; };
	c.dispatchNotification("notifications/message", Json.emptyObject);
	assert(!called);
}

unittest  // progress is still forwarded to the generic onNotification observer
{
	auto c = McpClient.http("http://localhost");
	string forwarded;
	c.onNotification = (string method, Json) @safe { forwarded = method; };
	c.dispatchNotification("notifications/progress", Json.emptyObject);
	assert(forwarded == "notifications/progress");
}

unittest  // notifications/message is delivered to the typed onLogMessage observer
{
	auto c = McpClient.http("http://localhost");
	LogMessageNotification got;
	bool called;
	c.onLogMessage = (LogMessageNotification n) @safe { got = n; called = true; };

	Json p = Json.emptyObject;
	p["level"] = "warning";
	p["logger"] = "db";
	p["data"] = "disk almost full";
	c.dispatchNotification("notifications/message", p);

	assert(called);
	assert(got.level == "warning");
	assert(got.level == LogLevel.warning);
	assert(!got.logger.isNull && got.logger.get == "db");
	assert(got.data.get!string == "disk almost full");
}

unittest  // a non-message notification does not invoke onLogMessage
{
	auto c = McpClient.http("http://localhost");
	bool called;
	c.onLogMessage = (LogMessageNotification) @safe { called = true; };
	c.dispatchNotification("notifications/progress", Json.emptyObject);
	assert(!called);
}

unittest  // a log message is still forwarded to the generic onNotification observer
{
	auto c = McpClient.http("http://localhost");
	string forwarded;
	c.onNotification = (string method, Json) @safe { forwarded = method; };
	c.dispatchNotification("notifications/message", Json.emptyObject);
	assert(forwarded == "notifications/message");
}

unittest  // elicitation/create defaults to form mode when mode is absent
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationForm = true;

	bool delegateCalled;
	c.onElicitation = (ElicitParams params) @safe {
		delegateCalled = true;
		return ElicitResult.init;
	};

	Json params = Json.emptyObject;
	params["message"] = "Please fill this in";
	params["requestedSchema"] = Json.emptyObject;

	c.dispatchServerMethod("elicitation/create", params);
	assert(delegateCalled);
}

unittest  // buildCompleteParams shapes a prompt completion request
{
	auto p = McpClient.buildCompleteParams(CompletionReference.forPrompt("greet"),
			"name", "pa", null);
	assert(p["ref"]["type"].get!string == "ref/prompt");
	assert(p["ref"]["name"].get!string == "greet");
	assert(p["argument"]["name"].get!string == "name");
	assert(p["argument"]["value"].get!string == "pa");
	assert("context" !in p);
}

unittest  // buildCompleteParams shapes a resource completion request
{
	auto p = McpClient.buildCompleteParams(
			CompletionReference.forResource("file:///{path}"), "path", "/ho", null);
	assert(p["ref"]["type"].get!string == "ref/resource");
	assert(p["ref"]["uri"].get!string == "file:///{path}");
	assert(p["argument"]["value"].get!string == "/ho");
}

unittest  // buildCompleteParams includes the resolved-argument context when given
{
	string[string] ctx = ["owner": "octocat"];
	auto p = McpClient.buildCompleteParams(CompletionReference.forPrompt("pr"), "repo", "m", ctx);
	assert(p["context"]["arguments"]["owner"].get!string == "octocat");
}

unittest  // a string progress token serialises as a string under _meta
{
	auto t = ProgressToken("tok-1");
	assert(t.isSet);
	assert(t.toJson().type == Json.Type.string);
	assert(t.toJson().get!string == "tok-1");
}

unittest  // an integer progress token serialises as an integer
{
	auto t = ProgressToken(42L);
	assert(t.isSet);
	assert(t.toJson().type == Json.Type.int_);
	assert(t.toJson().get!long == 42);
}

unittest  // a default-constructed progress token is unset
{
	ProgressToken t;
	assert(!t.isSet);
	assert(t.toJson().type == Json.Type.undefined);
}

unittest  // withProgressToken merges the token into params._meta
{
	Json p = Json.emptyObject;
	p["name"] = "x";
	auto out_ = withProgressToken(p, ProgressToken("abc"));
	assert(out_["_meta"]["progressToken"].get!string == "abc");
	assert(out_["name"].get!string == "x"); // domain fields preserved
}

unittest  // withProgressToken preserves existing _meta keys
{
	Json meta = Json.emptyObject;
	meta["existing"] = "keep";
	Json p = Json.emptyObject;
	p["_meta"] = meta;
	auto out_ = withProgressToken(p, ProgressToken(7L));
	assert(out_["_meta"]["existing"].get!string == "keep");
	assert(out_["_meta"]["progressToken"].get!long == 7);
}

unittest  // withProgressToken leaves params untouched when the token is unset
{
	Json p = Json.emptyObject;
	p["name"] = "x";
	auto out_ = withProgressToken(p, ProgressToken.init);
	assert("_meta" !in out_);
}

unittest  // buildToolCallParams attaches a progressToken under _meta
{
	auto p = McpClient.buildToolCallParams("add", Json(["a": Json(1)]), ProgressToken("p1"));
	assert(p["name"].get!string == "add");
	assert(p["_meta"]["progressToken"].get!string == "p1");
}

unittest  // buildToolCallParams omits _meta when no progress token is requested
{
	auto p = McpClient.buildToolCallParams("add", Json.emptyObject, ProgressToken.init);
	assert("_meta" !in p);
}

unittest  // buildReadResourceParams attaches a progressToken under _meta
{
	auto p = McpClient.buildReadResourceParams("file:///x", ProgressToken(99L));
	assert(p["uri"].get!string == "file:///x");
	assert(p["_meta"]["progressToken"].get!long == 99);
}

unittest  // buildSubscriptionsListenParams nests the boolean list-changed flags under notifications
{
	SubscriptionFilter f;
	f.toolsListChanged = true;
	f.resourcesListChanged = true;
	auto p = McpClient.buildSubscriptionsListenParams(f);
	assert(p["notifications"]["toolsListChanged"].get!bool == true);
	assert(p["notifications"]["resourcesListChanged"].get!bool == true);
	// Flags left false are omitted (not sent as false) per the spec filter shape.
	assert("promptsListChanged" !in p["notifications"]);
}

unittest  // buildSubscriptionsListenParams nests resourceSubscriptions URIs as a string array
{
	SubscriptionFilter f;
	f.resourceSubscriptions = ["file:///a", "file:///b"];
	auto p = McpClient.buildSubscriptionsListenParams(f);
	auto rs = p["notifications"]["resourceSubscriptions"];
	assert(rs.type == Json.Type.array);
	assert(rs.length == 2);
	assert(rs[0].get!string == "file:///a");
	assert(rs[1].get!string == "file:///b");
}

unittest  // buildSubscriptionsListenParams emits an empty notifications filter for an empty subscription
{
	SubscriptionFilter f;
	auto p = McpClient.buildSubscriptionsListenParams(f);
	assert(p["notifications"].type == Json.Type.object);
	assert(p["notifications"].length == 0);
}

unittest  // a subscriptions/listen stream delivers the acknowledgement + change notifications to onNotification
{
	// Exercise the delivery path the listen stream uses (dispatchInbound):
	// the leading subscriptions/acknowledged event and a subsequent list-changed
	// notification must both reach onNotification.
	auto c = McpClient.http("http://localhost");
	string[] seen;
	c.onNotification = (string method, Json params) @safe { seen ~= method; };

	c.dispatchInbound(Message(parseJsonString(`{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"1"},"notifications":{"toolsListChanged":true}}}`)));
	c.dispatchInbound(Message(parseJsonString(
			`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)));

	assert(seen.length == 2);
	assert(seen[0] == "notifications/subscriptions/acknowledged");
	assert(seen[1] == "notifications/tools/list_changed");
}

unittest  // buildGetPromptParams attaches a progressToken under _meta
{
	auto p = McpClient.buildGetPromptParams("greet", Json.emptyObject, ProgressToken("g1"));
	assert(p["name"].get!string == "greet");
	assert(p["_meta"]["progressToken"].get!string == "g1");
}

unittest  // paramHeaders mirrors an x-mcp-header-annotated argument into Mcp-Param-{Name}
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	props["query"] = Json(["type": Json("string")]);
	schema["properties"] = props;

	Json args = Json.emptyObject;
	args["region"] = "us-west1";
	args["query"] = "weather";

	auto headers = McpClient.paramHeaders(schema, args);
	assert("Mcp-Param-Region" in headers);
	assert(headers["Mcp-Param-Region"] == "us-west1");
	// A non-annotated argument never becomes a header.
	assert("Mcp-Param-query" !in headers);
}

unittest  // paramHeaders omits headers for absent or null annotated arguments
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	props["zone"] = Json(["type": Json("string"), "x-mcp-header": Json("Zone")]);
	schema["properties"] = props;

	Json args = Json.emptyObject;
	args["zone"] = null; // explicit null -> no header
	// region absent entirely -> no header

	auto headers = McpClient.paramHeaders(schema, args);
	assert("Mcp-Param-Region" !in headers);
	assert("Mcp-Param-Zone" !in headers);
}

unittest  // paramHeaders base64-encodes a non-ASCII annotated value
{
	import mcp.protocol.draft : decodeHeaderValue;

	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["label"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Label")
	]);
	schema["properties"] = props;

	Json args = Json.emptyObject;
	args["label"] = "Hello, 世界";

	auto headers = McpClient.paramHeaders(schema, args);
	assert("Mcp-Param-Label" in headers);
	assert(headers["Mcp-Param-Label"][0 .. 9] == "=?base64?");
	assert(decodeHeaderValue(headers["Mcp-Param-Label"]) == "Hello, 世界");
}

unittest  // paramHeaders stringifies a non-string scalar annotated value
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["limit"] = Json([
		"type": Json("integer"),
		"x-mcp-header": Json("Limit")
	]);
	schema["properties"] = props;

	Json args = Json.emptyObject;
	args["limit"] = 42;

	auto headers = McpClient.paramHeaders(schema, args);
	assert(headers["Mcp-Param-Limit"] == "42");
}

unittest  // paramHeaders yields nothing when the schema has no x-mcp-header annotations
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["query"] = Json(["type": Json("string")]);
	schema["properties"] = props;

	Json args = Json.emptyObject;
	args["query"] = "x";

	auto headers = McpClient.paramHeaders(schema, args);
	assert(headers.length == 0);
}

unittest  // cacheToolSchema records a schema and ignores a non-object one
{
	auto c = McpClient.http("http://localhost/mcp");
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	c.cacheToolSchema("search", schema);
	assert("search" in c.toolInputSchemas_);
	// Non-object schema is ignored.
	c.cacheToolSchema("bad", Json("not-an-object"));
	assert("bad" !in c.toolInputSchemas_);
}

unittest  // MRTR: withInputResponses attaches answers in top-level params.inputResponses
{
	auto resp = InputResponse("date", Json([
			"content": Json(["day": Json("monday")])
	]));
	auto params = McpClient.buildToolCallParams("book", Json.emptyObject,
			ProgressToken.init, [resp]);
	// SEP-2322: a top-level map keyed by the InputRequest id, value is the bare
	// result — NOT under _meta and NOT an array of {id, result} wrappers.
	auto map = params["inputResponses"];
	assert(map.type == Json.Type.object);
	assert("date" in map);
	assert("id" !in map["date"]);
	assert(map["date"]["content"]["day"].get!string == "monday");
	// The invented reserved _meta key must not be produced.
	assert("_meta" !in params || "io.modelcontextprotocol/inputResponses" !in params["_meta"]);
}

unittest  // MRTR: withInputResponses with no answers leaves params untouched
{
	auto params = McpClient.buildToolCallParams("book", Json.emptyObject, ProgressToken.init, [
	]);
	assert("inputResponses" !in params);
	assert("_meta" !in params);
}

unittest  // MRTR: withInputResponses preserves an existing params payload
{
	Json p = Json.emptyObject;
	p["name"] = "book";
	Json meta = Json.emptyObject;
	meta["progressToken"] = "p1";
	p["_meta"] = meta;
	auto resp = InputResponse("q1", Json(["action": Json("accept")]));
	auto out_ = McpClient.withInputResponses(p, [resp]);
	// Existing fields are preserved; inputResponses is added at the top level.
	assert(out_["name"].get!string == "book");
	assert(out_["_meta"]["progressToken"].get!string == "p1");
	assert(out_["inputResponses"].type == Json.Type.object);
	assert("q1" in out_["inputResponses"]);
}

unittest  // MRTR: withRequestState echoes the opaque requestState at the top level
{
	auto resp = InputResponse("date", Json(["action": Json("accept")]));
	auto params = McpClient.buildToolCallParams("book", Json.emptyObject,
			ProgressToken.init, [resp], "eyJyIjoiRHVwIn0");
	// SEP-2322: requestState is echoed verbatim as a top-level params field.
	assert(params["requestState"].get!string == "eyJyIjoiRHVwIn0");
}

unittest  // MRTR: an empty requestState is never echoed (client MUST NOT invent one)
{
	auto resp = InputResponse("date", Json(["action": Json("accept")]));
	auto params = McpClient.buildToolCallParams("book", Json.emptyObject,
			ProgressToken.init, [resp]);
	assert("requestState" !in params);
}

unittest  // MRTR: resolveInputRequest routes an elicitation request to onElicitation
{
	auto c = McpClient.http("http://localhost/mcp");
	string seenMessage;
	c.onElicitation = (ElicitParams params) @safe {
		seenMessage = params.message;
		return ElicitResult.accept(Json(["day": Json("tuesday")]));
	};
	Json ep = Json.emptyObject;
	ep["message"] = "When?";
	InputResponse answer;
	const ok = c.resolveInputRequest(InputRequest("date", "elicitation", ep), answer);
	assert(ok);
	assert(seenMessage == "When?");
	assert(answer.id == "date");
	assert(answer.result["content"]["day"].get!string == "tuesday");
}

unittest  // MRTR: resolveInputRequest routes a sampling request to onSampling
{
	auto c = McpClient.http("http://localhost/mcp");
	c.onSampling = (CreateMessageRequest request) @safe {
		CreateMessageResult r;
		r.role = "assistant";
		return r;
	};
	InputResponse answer;
	const ok = c.resolveInputRequest(InputRequest("s1", "sampling", Json.emptyObject), answer);
	assert(ok);
	assert(answer.id == "s1");
	assert(answer.result["role"].get!string == "assistant");
}

unittest  // MRTR: resolveInputRequest routes a roots request to onListRoots
{
	auto c = McpClient.http("http://localhost/mcp");
	c.onListRoots = () @safe { return ListRootsResult.init; };
	InputResponse answer;
	const ok = c.resolveInputRequest(InputRequest("r1", "roots", Json.emptyObject), answer);
	assert(ok);
	assert(answer.id == "r1");
	assert(answer.result["roots"].type == Json.Type.array);
}

unittest  // MRTR: resolveInputRequest fails (no answer) when no handler is registered
{
	auto c = McpClient.http("http://localhost/mcp");
	InputResponse answer;
	// onElicitation is null by default -> cannot satisfy the request.
	const ok = c.resolveInputRequest(InputRequest("x", "elicitation", Json.emptyObject), answer);
	assert(!ok);
	assert(answer.id.length == 0);
}

unittest  // MRTR: resolveInputRequest fails for an unknown input type
{
	auto c = McpClient.http("http://localhost/mcp");
	c.onElicitation = (ElicitParams) @safe { return ElicitResult.init; };
	InputResponse answer;
	const ok = c.resolveInputRequest(InputRequest("x", "bogus", Json.emptyObject), answer);
	assert(!ok);
}

unittest  // listResourceTemplates calls resources/templates/list and auto-paginates
{
	auto c = McpClient.http("http://localhost");
	string[] methods;
	int call;
	c.onRpcForTest = (string method, Json params) @safe {
		methods ~= method;
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		if (call == 0)
		{
			ResourceTemplate t;
			t.uriTemplate = "file:///a/{x}";
			t.name = "a";
			arr ~= t.toJson();
			r["resourceTemplates"] = arr;
			r["nextCursor"] = "p2";
		}
		else
		{
			assert("cursor" in params && params["cursor"].get!string == "p2");
			ResourceTemplate t;
			t.uriTemplate = "file:///b/{y}";
			t.name = "b";
			arr ~= t.toJson();
			r["resourceTemplates"] = arr;
		}
		call++;
		return r;
	};

	auto templates = c.listResourceTemplates().resourceTemplates;
	assert(methods.length == 2);
	assert(methods[0] == "resources/templates/list");
	assert(methods[1] == "resources/templates/list");
	assert(templates.length == 2);
	assert(templates[0].uriTemplate == "file:///a/{x}");
	assert(templates[1].name == "b");
}

unittest  // readResource exposes the parsed CacheableResult freshness hint as .cache
{
	auto c = McpClient.http("http://localhost");
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= ResourceContents.makeText("test://x", "text/plain", "hi").toJson();
		r["contents"] = arr;
		r["ttlMs"] = 6000;
		r["cacheScope"] = "private";
		return r;
	};
	auto res = c.readResource("test://x");
	assert(!res.cache.isNull);
	assert(res.cache.get.ttlMs == 6000);
	assert(res.cache.get.cacheScope == CacheScope.private_);
}

unittest  // a list result exposes .cache from the first page's freshness hint
{
	auto c = McpClient.http("http://localhost");
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		r["tools"] = Json.emptyArray;
		r["ttlMs"] = 5000;
		r["cacheScope"] = "public";
		return r;
	};
	auto res = c.listTools();
	assert(!res.cache.isNull);
	assert(res.cache.get.ttlMs == 5000);
	assert(res.cache.get.cacheScope == CacheScope.public_);
}

version (unittest)
{
	// A minimal, HTTP-free `ClientTransport` used to prove that `McpClient`
	// drives an arbitrary transport through the `ClientProtocol` seam alone — it
	// installs no HTTP-specific hooks (no `setCustomHeaders` /
	// `setResponseCancelledPredicate` / `startLegacyHttpSse` downcast). The
	// transport records the protocol collaborator the client hands it and pumps a
	// canned response.
	private final class RecordingClientTransport : ClientTransport
	{
		ClientProtocol protocol; // installed by McpClient via setProtocol
		bool legacyFallbackCalled;
		Json delegate(Json message, long expectId) @safe responder;

		void setProtocol(ClientProtocol p) @safe
		{
			protocol = p;
		}

		void setInboundHandler(void delegate(Message) @safe handler) @safe
		{
		}

		void setBearerToken(string token) @safe
		{
		}

		void startServerStream() @safe
		{
		}

		void startLegacyFallback() @safe
		{
			legacyFallbackCalled = true;
		}

		SubscriptionStream openListen(Json message) @safe
		{
			auto cancelled = () @trusted { return new shared bool(false); }();
			return new SubscriptionStream(cancelled);
		}

		Json deliver(Json message, long expectId) @safe
		{
			return responder is null ? Json.emptyObject : responder(message, expectId);
		}

		void sendOneway(Json message) @safe
		{
		}

		void close() @safe
		{
		}
	}
}

unittest  // McpClient installs its ClientProtocol collaborator on an arbitrary transport
{
	// No HTTP downcast: the client must hand the transport a single collaborator
	// at construction, through which the transport reads protocol-derived headers
	// and the cancelled-response predicate.
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	assert(transport.protocol !is null);
	// Default (non-draft, pre-initialize) headers are empty for an arbitrary
	// outgoing message — the same logic the HTTP transport reads.
	assert(transport.protocol.headersFor(Json.undefined).length == 0);
}

unittest  // a custom transport reads cancellation state through ClientProtocol
{
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	assert(!transport.protocol.isCancelled(7));
	c.cancel(7);
	assert(transport.protocol.isCancelled(7));
}

unittest  // a draft client's ClientProtocol yields the MCP-Protocol-Version header
{
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	c.enableDraft();
	auto headers = transport.protocol.headersFor(Json.undefined);
	assert(headers["MCP-Protocol-Version"] == ProtocolVersion.draft.toWire);
}

unittest  // connect() routes a legacy HTTP+SSE fallback through the transport seam, not a downcast
{
	// When discover() raises LegacyFallbackException, the client must initiate the
	// fallback via ClientTransport.startLegacyFallback(), with no cast to
	// HttpClientTransport. A custom transport observes the call and then answers
	// the subsequent legacy initialize handshake.
	import mcp.client.http_transport : LegacyFallbackException;

	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	bool firstCall = true;
	transport.responder = (Json message, long expectId) @safe {
		if (firstCall)
		{
			firstCall = false;
			throw new LegacyFallbackException(404);
		}
		// The legacy initialize handshake: echo a minimal initialize result.
		Json r = Json.emptyObject;
		r["protocolVersion"] = ProtocolVersion.v2024_11_05.toWire;
		r["capabilities"] = Json.emptyObject;
		Json info = Json.emptyObject;
		info["name"] = "legacy-srv";
		info["version"] = "1.0";
		r["serverInfo"] = info;
		return r;
	};
	c.connect();
	assert(transport.legacyFallbackCalled);
}
