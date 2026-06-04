module mcp.client.client;

import std.algorithm : canFind, startsWith;
import std.typecons : Nullable, nullable;

import vibe.data.json : Json, parseJsonString, serializeToJson;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.protocol.sampling : validateSamplingMessages, CreateMessageRequest, CreateMessageResult;
import mcp.protocol.modern;
import mcp.server.context : logLevelRank;
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

/// Per-request options shared by every `McpClient` request verb (`callTool`,
/// `readResource`, `getPrompt`, `complete`). All fields are independently
/// combinable and default to "unset":
///
/// - `progressToken`: attached as `params._meta.progressToken` so the server may
///   emit `notifications/progress` for the request (basic/utilities/progress).
/// - `logLevel`: minimum `notifications/message` severity for this request,
///   carried in `params._meta["io.modelcontextprotocol/logLevel"]` (draft
///   server/utilities/logging, SEP-2575/2577); ignored on a released protocol,
///   empty attaches nothing.
/// - `onProgress`: a per-call progress sink. When non-null and no explicit
///   `progressToken` is given, the verb mints a unique token; for the duration
///   of the call, progress correlated to that token is routed here while
///   progress for other tokens still reaches the global `onProgress`.
struct RequestOptions
{
	ProgressToken progressToken;
	string logLevel;
	void delegate(ProgressNotification) @safe onProgress;

	/// Convenience factory for the dominant per-call case: route this request's
	/// progress to `cb` (the verb mints a unique token), leaving `progressToken`
	/// and `logLevel` unset. Spelled out so a single-callback caller need not pad
	/// the leading positional fields with throwaway values.
	static RequestOptions withProgress(void delegate(ProgressNotification) @safe cb) @safe
	{
		RequestOptions opts;
		opts.onProgress = cb;
		return opts;
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

/// Merge a per-request log level into a request's
/// `params._meta["io.modelcontextprotocol/logLevel"]` (`MetaKey.logLevel`), per
/// the draft (2026-07-28) server/utilities/logging rule that "Clients control
/// logging verbosity per-request via `_meta`" (SEP-2575/2577, which removed the
/// `logging/setLevel` RPC). A conformant draft server MUST NOT emit
/// `notifications/message` for a request that omits this field, so attaching it
/// is the only way a draft client can opt in to log messages for the request.
/// An empty `level` leaves `params` unchanged. Any existing `_meta` keys are
/// preserved. Exposed so callers can attach a log level to a hand-built params
/// object; only meaningful on a draft-negotiated session.
Json withRequestLogLevel(Json params, string level) @safe
{
	if (level.length == 0)
		return params;
	if (params.type != Json.Type.object)
		params = Json.emptyObject;
	Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"]
		: Json.emptyObject;
	meta[MetaKey.logLevel] = level;
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
	private bool useModern;
	private long nextId = 1;
	// Opt-in: validate tool results against the tool's outputSchema (client side).
	private bool validateOutputSchema_;
	// URL-mode elicitation correlation: in-flight ids the server asked us to
	// complete via an `elicitation/create` with `mode:"url"`. An id is added
	// (value false) when the request is seen and evicted once its
	// `notifications/elicitation/complete` has been forwarded, so the set holds
	// only ids still awaiting completion. Used to honour the spec rule "Clients
	// MUST ignore notifications referencing unknown or already-completed IDs": an
	// evicted (completed) or never-issued id is absent and so ignored.
	private bool[string] elicitationIds_;
	// Request ids this client has cancelled via notifications/cancelled. Per
	// basic/utilities/cancellation, "The sender of the cancellation notification
	// SHOULD ignore any response to the request that arrives afterward", so a
	// late response correlated to one of these ids is dropped rather than
	// returned. Keyed by the JSON-RPC id under which the request was POSTed.
	private bool[long] cancelledRequests_;
	// Insertion order of the ids in `cancelledRequests_`, used to evict the
	// single oldest id when the set is full (FIFO) rather than clearing it
	// wholesale. May contain ids already removed by `isCancelled`; those are
	// skipped during eviction.
	private long[] cancelledOrder_;
	// Size backstop for `cancelledRequests_`: ids are normally evicted when their
	// late response is observed (`isCancelled`), but a late response that never
	// arrives would otherwise pin its id forever. Once the tracked set is full,
	// the next `cancel` evicts only the OLDEST tracked id, so recently-cancelled
	// ids stay remembered and their late responses are still dropped per
	// basic/utilities/cancellation. The only id at risk is the oldest one, whose
	// as-yet-unseen late response is the least likely to still be relevant.
	private enum size_t maxCancelledTracked_ = 4096;
	// The JSON-RPC id used for the `initialize` request, so cancel() can enforce
	// the spec rule that clients MUST NOT cancel initialize. 0 until sent.
	private long initializeRequestId;
	// Tool inputSchemas seen via tools/list, keyed by tool name. Used by the
	// draft client to mirror x-mcp-header-annotated tool-call arguments into
	// Mcp-Param-{Name} headers (draft basic/transports, "Custom Headers from
	// Tool Parameters"). Populated by listTools; consumed by `headersFor`,
	// which the HTTP transport calls to obtain the per-message headers.
	private Json[string] toolInputSchemas_;
	// Draft (2026-07-28) per-request logging opt-in. The draft removed the
	// `logging/setLevel` RPC; a client instead controls verbosity by stamping
	// `_meta["io.modelcontextprotocol/logLevel"]` on each request, and a
	// conformant server emits no `notifications/message` for a request that
	// omits it (server/utilities/logging, SEP-2575/2577). This is the sticky
	// default level applied to every draft request by `injectModernMeta`; empty
	// means "no opt-in" (no field stamped). Set via `setLogLevel` on a draft
	// session. Per-request overrides go through `RequestOptions.logLevel` /
	// `withRequestLogLevel` and are NOT stored here.
	private string requestLogLevel_;
	// Monotonic counter behind `mintProgressToken`, which mints a unique string
	// progress token for a per-call `RequestOptions.onProgress` sink. A
	// distinct counter (not `nextId`) keeps the minted token stable regardless of
	// how many requests the call's MRTR loop issues, and unique across calls per
	// basic/utilities/progress ("MUST be unique across all active requests").
	private long nextProgressToken_ = 1;
	// Per-call progress sinks keyed by the request's `ProgressToken` rendered as a
	// JSON string (so string and integer tokens both key uniquely). A
	// `RequestOptions.onProgress` sink is registered here for the duration of its
	// call and removed on return; `dispatchNotification` routes an inbound
	// `notifications/progress` to the entry matching its token, falling back to the
	// global `onProgress` when no per-call sink is registered for that token. Keyed
	// by token (not stacked on a single mutable field) so overlapping concurrent
	// calls never clobber each other's sink or leave a stale wrapper installed.
	private void delegate(ProgressNotification) @safe[string] perCallProgress_;
	// Server identity/capabilities discovered at connect/initialize, exposed via
	// the `serverCapabilities`/`serverInfo`/`serverInstructions` accessors. Both
	// the stable initialize handshake and the stateless draft `server/discover`
	// path populate these so a connected caller can inspect what the peer
	// advertised without re-issuing discovery.
	private ServerCapabilities serverCapabilities_;
	private Implementation serverInfo_;
	private Nullable!string serverInstructions_;
	// Upper bound on the number of pages any auto-paginating list call will
	// follow before giving up, guarding against a peer that returns a
	// non-progressing or cycling `nextCursor` (which would otherwise loop and
	// accumulate items without bound). Mirrors the bounded-iteration style used
	// elsewhere (e.g. `maxActive`, `idleTtl`). Set to 0 to disable the cap (the
	// non-progress/cycle checks still apply).
	size_t maxListPages_ = 1000;

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
	/// `ProgressToken` you attached to the originating request (via
	/// `RequestOptions.progressToken` on `callTool`/`readResource`/`getPrompt`/
	/// `complete`) to track an individual request's progress.
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

	/// Launch an MCP server binary that ships *next to this executable* and build a
	/// client over its stdin/stdout. Resolves `exeName` against the running
	/// program's own directory (`dirName(thisExePath())`) — the common case of a
	/// host bundling a sibling helper server — then `spawn`s
	/// `[resolvedPath] ~ extraArgs`. On Windows (or whenever the bare resolved path
	/// does not exist) a `.exe` suffix is tried as a fallback. As with `spawn`, the
	/// returned client is NOT yet initialized — call `initialize()` (or `ping()`).
	static McpClient spawnSibling(string exeName, string[] extraArgs = null,
			Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
	{
		return spawn([resolveSiblingPath(exeName)] ~ extraArgs, clientInfo);
	}

	/// Resolve `exeName` to an absolute path next to the running executable
	/// (`buildPath(dirName(thisExePath()), exeName)`). When that path does not
	/// exist but a `.exe`-suffixed sibling does, the suffixed path is returned (the
	/// Windows / bare-name fallback). Separated from `spawnSibling` so the
	/// path-resolution can be unit-tested without actually spawning a subprocess.
	package static string resolveSiblingPath(string exeName) @safe
	{
		import std.file : thisExePath, exists;
		import std.path : dirName, buildPath;

		const dir = dirName(thisExePath());
		const bare = buildPath(dir, exeName);
		if (exists(bare))
			return bare;
		const withExe = bare ~ ".exe";
		if (exists(withExe))
			return withExe;
		return bare;
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

	/// Switch to the stateless modern (>= 2026-07-28) protocol: no `initialize`
	/// handshake; every request carries `_meta` (protocolVersion / clientInfo /
	/// clientCapabilities) and the standard `Mcp-Method` / `Mcp-Name` /
	/// `MCP-Protocol-Version` headers. Call `discover()` for up-front version
	/// selection, or just issue requests.
	void enableModern() @safe
	{
		useModern = true;
		negotiated = ProtocolVersion.modern;
	}

	/// `server/discover` (draft): fetch the server's supported versions,
	/// capabilities, and identity.
	DiscoverResult discover() @safe
	{
		return DiscoverResult.fromJson(rpc("server/discover", Json.emptyObject));
	}

	/// `server/discover` self-advertising draft framing, used by `connect()` to
	/// auto-detect a draft/stateless server before any version is negotiated.
	///
	/// `route()`/`freshStatelessState` gate `server/discover` on a draft effective
	/// version, which a stateless server only resolves when the probe carries draft
	/// framing (the `MCP-Protocol-Version` draft header and a draft
	/// `_meta.protocolVersion`). Without it the server falls back to its stable
	/// default and answers methodNotFound, so an undecorated probe can never select
	/// draft. This temporarily stamps draft framing on the single probe request and
	/// restores the prior (unnegotiated) state on any non-draft outcome, so a
	/// genuine legacy server is still detected by the caller.
	private DiscoverResult discoverProbe() @safe
	{
		const priorUseModern = useModern;
		const priorNegotiated = negotiated;
		useModern = true;
		negotiated = ProtocolVersion.modern;
		bool keepModernFraming;
		scope (exit)
			if (!keepModernFraming)
			{
				useModern = priorUseModern;
				negotiated = priorNegotiated;
			}
		auto result = DiscoverResult.fromJson(rpc("server/discover", Json.emptyObject));
		// The probe succeeded as draft; leave the framing in place so `connect`'s
		// version selection runs against a draft-capable peer.
		keepModernFraming = true;
		return result;
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
		// Advertise capabilities in the wire shape for the requested version:
		// e.g. for draft, `tasks` is folded into the `extensions` map rather than
		// emitted as a top-level capability the draft schema does not define.
		ProtocolVersion reqVer;
		if (!tryParseVersion(requestedVersion, reqVer))
			reqVer = latestStable;
		params.capabilities = effectiveCapabilities().forVersion(reqVer);
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
		// Record what the server advertised so `serverCapabilities`/`serverInfo`/
		// `serverInstructions` work uniformly across the initialize and draft
		// discovery paths (symmetry with `connect`'s draft branch).
		serverCapabilities_ = init.capabilities;
		serverInfo_ = init.serverInfo;
		serverInstructions_ = init.instructions;
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
		DiscoverResult disc;
		bool haveDisc;
		try
		{
			// Probe with draft framing so a stateless/draft server resolves the
			// request to draft and serves `server/discover`; an undecorated probe
			// would fall back to the server's stable default and be rejected.
			disc = discoverProbe();
			haveDisc = true;
			serverVersions = disc.protocolVersions;
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

		if (chosen.isModern)
		{
			useModern = true;
			negotiated = chosen;
			// No initialize handshake follows on the stateless draft path, so
			// capture what `server/discover` advertised; otherwise the caller
			// would have no way to inspect the server's capabilities/identity.
			if (haveDisc)
			{
				serverCapabilities_ = disc.capabilities;
				serverInfo_ = disc.serverInfo;
				serverInstructions_ = disc.instructions;
			}
		}
		else
		{
			// The draft-framed probe left draft framing set; the mutually-chosen
			// version is stable, so clear it before the `initialize` handshake runs
			// under that stable version.
			useModern = false;
			negotiated = chosen;
			initialize(chosen.toWire); // modern discovery, pre-draft version
		}
		return negotiated;
	}

	/// Extract the `supported` wire-version list from an
	/// `UnsupportedProtocolVersionError`. The transport's `errorFrom`
	/// (http_transport.d) stores the whole JSON-RPC error object in `data`, so the
	/// list lives at `data.data.supported`.
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

	/// Drive an auto-paginating list call. `fetchPage` is invoked once per page
	/// with the current cursor (`Nullable!string.init` for the first page) and
	/// returns that page's `nextCursor`; iteration stops when it is null.
	///
	/// Guards against a peer that never makes forward progress: a returned
	/// `nextCursor` equal to the one just sent, or any cursor already seen on a
	/// prior page (a cycle), throws `McpException(invalidParams)` rather than
	/// looping; a configurable `maxListPages_` cap throws
	/// `McpException(internalError)` once exceeded. Without these checks a
	/// malicious or buggy server could make the client loop forever, growing the
	/// accumulator without bound.
	private void paginate(scope Nullable!string delegate(Nullable!string cursor) @safe fetchPage) @safe
	{
		Nullable!string cursor;
		bool[string] seenCursors;
		size_t pages;
		do
		{
			if (maxListPages_ != 0 && pages >= maxListPages_)
				throw new McpException(ErrorCode.internalError,
						"List pagination exceeded the page cap; the server is not converging");
			auto next = fetchPage(cursor);
			pages++;
			if (!next.isNull)
			{
				const advanced = next.get;
				if (!cursor.isNull && advanced == cursor.get)
					throw new McpException(ErrorCode.invalidParams,
							"Server returned a non-progressing pagination cursor");
				if (advanced in seenCursors)
					throw new McpException(ErrorCode.invalidParams,
							"Server returned a cycling pagination cursor");
				seenCursors[advanced] = true;
			}
			cursor = next;
		}
		while (!cursor.isNull);
	}

	/// Drain a paginated `<method>` list into a single accumulated result `R`.
	/// Owns the cursor-param building, the first-page `cache` capture, and the
	/// `nextCursor` reset shared by every `list*` method; `append` is the only
	/// per-call variation, concatenating one page's items onto the accumulator.
	private R drainList(R)(string method, scope void delegate(ref R acc, ref R page) @safe append) @safe
	{
		R acc;
		bool first = true;
		paginate((Nullable!string cursor) @safe {
			Json p = Json.emptyObject;
			if (!cursor.isNull)
				p["cursor"] = cursor.get;
			auto res = R.fromJson(rpc(method, p));
			append(acc, res);
			if (first)
			{
				acc.cache = res.cache;
				first = false;
			}
			return res.nextCursor;
		});
		acc.nextCursor = Nullable!string.init;
		return acc;
	}

	/// `tools/list`, following pagination cursors to completion. Returns the
	/// drained `ListToolsResult`: `tools` aggregates every page's items,
	/// `nextCursor` is null, and `cache` carries the first page's parsed draft
	/// `CacheableResult` freshness hint (if any).
	ListToolsResult listTools() @safe
	{
		auto acc = drainList!ListToolsResult("tools/list",
				(ref ListToolsResult a, ref ListToolsResult r) @safe {
			a.tools ~= r.tools;
		});
		// On a draft session over HTTP (the x-mcp-header feature), the client MUST
		// exclude from tools/list any tool whose inputSchema carries an invalid
		// `x-mcp-header` annotation (draft server/tools #x-mcp-header). Validate each
		// tool's schema; drop offenders (and skip caching them), keeping siblings.
		// stdio / non-draft sessions MAY ignore x-mcp-header, so they are unaffected.
		if (useModern)
			acc.tools = excludeInvalidHeaderTools(acc.tools);
		// Cache each tool's inputSchema so a subsequent tools/call can mirror any
		// x-mcp-header-annotated arguments into Mcp-Param-{Name} headers (draft
		// basic/transports, "Custom Headers from Tool Parameters").
		foreach (t; acc.tools)
			cacheToolSchema(t.name, t.inputSchema);
		return acc;
	}

	/// Filter out any tool whose `inputSchema` has an invalid `x-mcp-header`
	/// annotation, per the draft requirement that a client MUST exclude such tools
	/// from `tools/list` (`server/tools` #x-mcp-header). Each excluded tool is
	/// reported via `logWarn` (tool name + the validation reason). Valid tools pass
	/// through unchanged and in order. Separated as a pure static helper so the
	/// exclusion can be unit-tested without a live server; `listTools` calls it only
	/// for a draft session (the feature is draft-only and HTTP-transport-specific).
	package static Tool[] excludeInvalidHeaderTools(Tool[] tools) @safe
	{
		import mcp.protocol.modern : validateInputSchemaHeaders;
		import vibe.core.log : logWarn;

		Tool[] kept;
		foreach (t; tools)
		{
			const reason = validateInputSchemaHeaders(t.inputSchema);
			if (reason !is null)
			{
				logWarn("Excluding tool '%s' from tools/list: invalid x-mcp-header annotation: %s",
						t.name, reason);
				continue;
			}
			kept ~= t;
		}
		return kept;
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

	/// `tools/call`. Per-request `progressToken` / `logLevel` / `onProgress` are
	/// carried in `opts` (see `RequestOptions`).
	///
	/// Against a draft (MRTR / SEP-2322) server this transparently completes a
	/// Multi Round-Trip Request: if the server answers with an
	/// `InputRequiredResult` (the result carries `inputRequests`), each request is
	/// dispatched to the matching `onSampling` / `onElicitation` / `onListRoots`
	/// handler and the original `tools/call` is resubmitted with the answers in
	/// the top-level `params.inputResponses` map (and the server's opaque
	/// `requestState` echoed back), looping until the server returns a completed
	/// `CallToolResult`. The loop only
	/// engages when draft mode is enabled (see `enableModern`/`connect`); other
	/// protocol versions never see `inputRequests`.
	CallToolResult callTool(string name, Json arguments = Json.emptyObject,
			RequestOptions opts = RequestOptions.init) @safe
	{
		auto token = effectiveToken(opts);
		return withPerCallProgress!CallToolResult(opts,
				() @safe => callToolLoop(name, arguments, token, opts.logLevel));
	}

	/// Typed-arguments convenience: serialize the struct `args` to its JSON wire
	/// shape via vibe's `serializeToJson` and forward to the `Json`-arguments
	/// `callTool`. Lets callers pass a strongly typed parameter struct instead of
	/// hand-building a `Json` object.
	CallToolResult callTool(T)(string name, T args, RequestOptions opts = RequestOptions.init) @safe
			if (!is(T : Json))
	{
		return callTool(name, serializeToJson(args), opts);
	}

	/// Convenience overload for the dominant single-callback case: route this
	/// call's progress to `onProgress` (a unique token is minted) without padding
	/// the leading `RequestOptions` fields.
	CallToolResult callTool(string name, Json arguments,
			void delegate(ProgressNotification) @safe onProgress) @safe
	{
		return callTool(name, arguments, RequestOptions.withProgress(onProgress));
	}

	/// Typed-arguments twin of the progress-callback `callTool` convenience
	/// overload: serialize the struct `args` and route this call's progress to
	/// `onProgress`.
	CallToolResult callTool(T)(string name, T args,
			void delegate(ProgressNotification) @safe onProgress) @safe
			if (!is(T : Json))
	{
		return callTool(name, serializeToJson(args), RequestOptions.withProgress(onProgress));
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
	private CallToolResult callToolLoop(string name, Json arguments,
			ProgressToken progressToken, string logLevel = "") @safe
	{
		enum maxRounds = 16;
		InputResponse[] responses;
		// SEP-2322: the opaque requestState the server attached on the prior
		// round, which the client MUST echo back verbatim on the retry.
		string requestState;
		// Hoisted so `maxRounds` is a true cap: after the last bounded round we
		// return whatever it produced (still an inputRequired result when the
		// server kept asking) without issuing an extra `tools/call`.
		CallToolResult result;
		foreach (round; 0 .. maxRounds)
		{
			auto params = buildToolCallParams(name, arguments, progressToken,
					responses, requestState);
			// Per-request draft logging opt-in: stamp the explicit level so
			// `injectModernMeta` carries it (and leaves it to win over any sticky
			// `setLogLevel` default). Empty -> no field.
			params = withRequestLogLevel(params, logLevel);
			result = CallToolResult.fromJson(rpc("tools/call", params));
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
		// Bound exceeded: return the last bounded round's still-inputRequired
		// result rather than looping forever (and without an extra round-trip).
		return result;
	}

	/// Mint a process-unique string `ProgressToken` for a per-call progress sink.
	/// Combines a per-client monotonic counter with the client's identity-derived
	/// hash so tokens minted by different clients/instances do not collide, per
	/// basic/utilities/progress ("MUST be unique across all active requests").
	private ProgressToken mintProgressToken() @safe
	{
		import std.conv : to;

		const n = nextProgressToken_++;
		return ProgressToken("mcp-progress-" ~ (cast(size_t)(cast(void*) this))
				.to!string ~ "-" ~ n.to!string);
	}

	/// The progress token a request should attach: the caller's explicit
	/// `opts.progressToken` when set, else a freshly minted one when an
	/// `opts.onProgress` sink needs a token to correlate against, else unset.
	private ProgressToken effectiveToken(ref RequestOptions opts) @safe
	{
		if (opts.progressToken.isSet)
			return opts.progressToken;
		if (opts.onProgress !is null)
			opts.progressToken = mintProgressToken();
		return opts.progressToken;
	}

	/// Run `body_` with `opts.onProgress` registered as a per-call sink (when
	/// non-null): while it executes, inbound progress correlated to
	/// `opts.progressToken` is delivered to `opts.onProgress`, and progress for any
	/// other token still reaches the global `this.onProgress`. The sink is
	/// registered under its token in `perCallProgress_` on entry and removed on
	/// return (including on throw). A null `opts.onProgress` runs `body_` directly.
	///
	/// The registration is keyed by token rather than stacked on a single mutable
	/// field, so two overlapping concurrent calls each route to their own sink and
	/// neither leaves a stale handler installed when it completes.
	private R withPerCallProgress(R)(RequestOptions opts, scope R delegate() @safe body_) @safe
	{
		if (opts.onProgress is null)
			return body_();
		const key = opts.progressToken.toJson().toString();
		perCallProgress_[key] = opts.onProgress;
		scope (exit)
			perCallProgress_.remove(key);
		return body_();
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
	CallToolResult callTool(const Tool tool, Json arguments = Json.emptyObject,
			RequestOptions opts = RequestOptions.init) @safe
	{
		auto result = callTool(tool.name, arguments, opts);
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
		return drainList!ListResourcesResult("resources/list",
				(ref ListResourcesResult a, ref ListResourcesResult r) @safe {
			a.resources ~= r.resources;
		});
	}

	/// `resources/templates/list`, auto-paginated. Returns the drained
	/// `ListResourceTemplatesResult` (URI templates clients can expand and
	/// `resources/read`). `resourceTemplates` aggregates every page, `nextCursor`
	/// is null, and `cache` carries the first page's parsed freshness hint.
	ListResourceTemplatesResult listResourceTemplates() @safe
	{
		return drainList!ListResourceTemplatesResult("resources/templates/list",
				(ref ListResourceTemplatesResult a, ref ListResourceTemplatesResult r) @safe {
			a.resourceTemplates ~= r.resourceTemplates;
		});
	}

	/// `resources/read`. Per-request `progressToken` / `logLevel` / `onProgress`
	/// are carried in `opts` (see `RequestOptions`).
	ReadResourceResult readResource(string uri, RequestOptions opts = RequestOptions.init) @safe
	{
		auto token = effectiveToken(opts);
		auto params = withRequestLogLevel(buildReadResourceParams(uri, token), opts.logLevel);
		return withPerCallProgress!ReadResourceResult(opts,
				() @safe => ReadResourceResult.fromJson(rpc("resources/read", params)));
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
		return drainList!ListPromptsResult("prompts/list",
				(ref ListPromptsResult a, ref ListPromptsResult r) @safe {
			a.prompts ~= r.prompts;
		});
	}

	/// `prompts/get`. Per-request `progressToken` / `logLevel` / `onProgress` are
	/// carried in `opts` (see `RequestOptions`).
	GetPromptResult getPrompt(string name, Json arguments = Json.emptyObject,
			RequestOptions opts = RequestOptions.init) @safe
	{
		auto token = effectiveToken(opts);
		auto params = withRequestLogLevel(buildGetPromptParams(name, arguments,
				token), opts.logLevel);
		return withPerCallProgress!GetPromptResult(opts,
				() @safe => GetPromptResult.fromJson(rpc("prompts/get", params)));
	}

	/// Typed-arguments convenience: serialize the struct `args` to its JSON wire
	/// shape via vibe's `serializeToJson` and forward to the `Json`-arguments
	/// `getPrompt`. Mirrors the typed `callTool(T)` so callers can pass a
	/// strongly typed prompt-argument struct instead of hand-building a `Json`
	/// object.
	GetPromptResult getPrompt(T)(string name, T args, RequestOptions opts = RequestOptions.init) @safe
			if (!is(T : Json))
	{
		return getPrompt(name, serializeToJson(args), opts);
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
	/// Per-request `progressToken` / `logLevel` / `onProgress` are carried in
	/// `opts` (see `RequestOptions`).
	CompleteResult complete(CompletionReference reference, string argumentName,
			string argumentValue, string[string] context = null,
			RequestOptions opts = RequestOptions.init) @safe
	{
		auto token = effectiveToken(opts);
		auto params = withRequestLogLevel(withProgressToken(buildCompleteParams(reference,
				argumentName, argumentValue, context), token), opts.logLevel);
		return withPerCallProgress!CompleteResult(opts,
				() @safe => CompleteResult.fromJson(rpc("completion/complete", params)));
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
	/// Only meaningful for draft servers (call `enableModern`/`connect` first);
	/// pre-draft servers do not implement `subscriptions/listen`.
	SubscriptionStream subscriptionsListen(SubscriptionFilter filter) @safe
	{
		const id = nextId++;
		Json params = buildSubscriptionsListenParams(filter);
		if (useModern)
			params = injectModernMeta(params);
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

	/// Set the minimum severity of `notifications/message` the server should
	/// emit to this client.
	///
	/// On a released protocol (<= 2025-11-25) this sends the `logging/setLevel`
	/// RPC. The draft (2026-07-28) REMOVED that RPC (SEP-2575/2577): a conformant
	/// draft server answers `logging/setLevel` with -32601 and emits no
	/// `notifications/message` for any request that does not carry
	/// `_meta["io.modelcontextprotocol/logLevel"]`. So on a draft-negotiated
	/// session this does NOT send the removed RPC; instead it records `level` as
	/// the sticky per-request opt-in that `injectModernMeta` stamps onto every
	/// subsequent request's `_meta` (see `withRequestLogLevel` and
	/// `RequestOptions.logLevel` for a single-request override). Passing
	/// an empty `level` clears the draft opt-in.
	///
	/// Typed entry point: pass a `LogLevel` for compile-time safety, so an invalid
	/// level name can never reach the wire. Forwards to the string overload (whose
	/// runtime validation always passes for a `LogLevel`).
	void setLogLevel(LogLevel level) @safe
	{
		setLogLevel(cast(string) level);
	}

	/// an empty `level` clears the draft opt-in.
	void setLogLevel(string level) @safe
	{
		// Reject an unrecognised level locally rather than POSTing it to a server
		// that will reject it (released protocol) or silently stamping it into
		// every draft request's `_meta` (draft). The empty string is the documented
		// draft-opt-in clear and is left to pass through. Mirrors the server-side
		// guard at server.d:1118.
		if (level.length && logLevelRank(level) < 0)
			throw new McpException(ErrorCode.invalidParams, "Invalid log level: " ~ level);
		if (useModern)
		{
			requestLogLevel_ = level;
			return;
		}
		Json p = Json.emptyObject;
		p["level"] = level;
		rpc("logging/setLevel", p);
	}

	// --- transport internals -------------------------------------------------

	/// Test seam: when set, `rpc` routes the (method, params) pair here and
	/// returns the delegate's `result` payload instead of POSTing to a server,
	/// so paginating request methods can be exercised without a live server.
	/// Production code never sets this.
	version (unittest) package Json delegate(string method, Json params) @safe onRpcForTest;

	/// Send a request and return its result (or throw `McpException`).
	///
	/// When the server answers with a `URLElicitationRequiredError`
	/// (`-32042`, client/elicitation Â§"URL Elicitation Required Error",
	/// 2025-11-25 / draft), its `data.elicitations[]` carries URL-mode
	/// elicitations the server has begun out-of-band. Per SEP-1036 the client
	/// MUST treat such an error as equivalent to an `elicitation/create` request,
	/// so we register every announced `elicitationId` before rethrowing. This is
	/// what later lets a `notifications/elicitation/complete` for one of those ids
	/// correlate (in `dispatchNotification`) and be forwarded to the application
	/// rather than dropped as "unknown".
	private Json rpc(string method, Json params) @safe
	{
		try
		{
			version (unittest)
				if (onRpcForTest !is null)
					return onRpcForTest(method, params);
			const id = nextId++;
			if (useModern)
				params = injectModernMeta(params);
			auto message = makeRequest(Json(id), method, params);
			return transport.deliver(message, id);
		}
		catch (McpException e)
		{
			if (e.code == ErrorCode.urlElicitationRequired)
				registerUrlElicitations(e.data);
			throw e;
		}
	}

	/// Register the `elicitationId`s announced by a `URLElicitationRequiredError`
	/// (`-32042`) so a subsequent `notifications/elicitation/complete` correlates
	/// and is forwarded. `error` is the JSON-RPC error object; the URL-mode
	/// elicitations live under `error.data.elicitations[]`, each an
	/// `ElicitRequestURLParams` carrying an `elicitationId` (2025-11-25 / draft
	/// schema `URLElicitationRequiredError`). Ids already tracked are left as-is so
	/// an in-flight completion state is not reset; malformed entries are skipped.
	package void registerUrlElicitations(Json error) @safe
	{
		if (error.type != Json.Type.object || "data" !in error)
			return;
		auto data = error["data"];
		if (data.type != Json.Type.object || "elicitations" !in data)
			return;
		auto elicitations = data["elicitations"];
		if (elicitations.type != Json.Type.array)
			return;
		foreach (i; 0 .. elicitations.length)
		{
			auto e = elicitations[i];
			if (e.type != Json.Type.object || "elicitationId" !in e
					|| e["elicitationId"].type != Json.Type.string)
				continue;
			const eid = e["elicitationId"].get!string;
			if (eid.length && eid !in elicitationIds_)
				elicitationIds_[eid] = false; // tracked, not yet completed
		}
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
	private Json injectModernMeta(Json params) @safe
	{
		if (params.type != Json.Type.object)
			params = Json.emptyObject;
		Json meta = ("_meta" in params && params["_meta"].type == Json.Type.object) ? params["_meta"] : Json
			.emptyObject;
		meta[MetaKey.protocolVersion] = negotiated.toWire;
		meta[MetaKey.clientInfo] = clientInfo.toJson();
		// Project to the negotiated (draft) wire shape: draft has no top-level
		// client `tasks` capability, so it is folded into the `extensions` map.
		meta[MetaKey.clientCapabilities] = effectiveCapabilities().forVersion(negotiated).toJson();
		// Draft per-request logging opt-in: stamp the sticky default level (set via
		// `setLogLevel`) unless this request already carries an explicit
		// `MetaKey.logLevel` (a per-request override via `withRequestLogLevel` / an
		// overload), which must win. server/utilities/logging (SEP-2575/2577).
		if (requestLogLevel_.length && MetaKey.logLevel !in meta)
			meta[MetaKey.logLevel] = requestLogLevel_;
		params["_meta"] = meta;
		return params;
	}

	/// Test seam: run `injectModernMeta` from a unittest so the per-request draft
	/// `_meta` (including the logging opt-in) can be asserted without a live
	/// server. Production code never calls this.
	version (unittest) package Json injectModernMetaForTest(Json params) @safe
	{
		return injectModernMeta(params);
	}

	/// Test seam: when set, `notify` routes the built notification message here
	/// instead of POSTing it, so the public notification API can be exercised
	/// without a live server. Production code never sets this.
	version (unittest) package void delegate(Json message) @safe onNotifyForTest;

	/// Send a notification (no reply expected).
	private void notify(string method, Json params) @safe
	{
		auto message = makeNotification(method, params);
		version (unittest)
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

	/// The server capabilities advertised at connect time. Populated by both the
	/// stable `initialize` handshake and the stateless draft `server/discover`
	/// path; default-constructed before either has run.
	ServerCapabilities serverCapabilities() @safe nothrow
	{
		return serverCapabilities_;
	}

	/// The server's identity (`name`/`version`) advertised at connect time.
	/// Populated by both the `initialize` handshake and draft discovery;
	/// default-constructed before either has run.
	Implementation serverInfo() @safe nothrow
	{
		return serverInfo_;
	}

	/// The optional server `instructions` advertised at connect time (null when
	/// the server sent none, or before connecting). Populated by both the
	/// `initialize` handshake and draft discovery.
	Nullable!string serverInstructions() @safe nothrow
	{
		return serverInstructions_;
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
		// Already tracked: nothing to add (and avoid a duplicate order entry).
		if (requestId !in cancelledRequests_)
		{
			// Bounded FIFO: when full, evict the oldest still-tracked id rather
			// than clearing the whole set, so recently-cancelled ids remain
			// remembered and their late responses are still dropped.
			while (cancelledRequests_.length >= maxCancelledTracked_ && cancelledOrder_.length)
			{
				const oldest = cancelledOrder_[0];
				cancelledOrder_ = cancelledOrder_[1 .. $];
				if (oldest in cancelledRequests_)
				{
					cancelledRequests_.remove(oldest);
					break;
				}
			}
			cancelledRequests_[requestId] = true;
			cancelledOrder_ ~= requestId;
		}
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
	/// callers need not hand-construct the raw JSON. Each `uri` MUST be
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
		if (useModern)
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
				headers[HttpHeader.name] = encodeHeaderValue(name);

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
	/// tool's `inputSchema` and the call `arguments`. Uses the path-aware
	/// `mcp.protocol.modern.paramHeaders`, which discovers every valid `x-mcp-header`
	/// annotation at *any* nesting depth (not only top-level properties), and
	/// descends each annotation's `path` into the arguments object: for each path
	/// segment it indexes into the current `Json` object; if any intermediate node
	/// is absent, `null`, or not an object, the header is skipped (emitting none).
	/// When the full path resolves to a present, non-null primitive (string / int /
	/// bigInt / bool — `number`/float is already excluded by header validation), the
	/// value is encoded with `encodeHeaderValue` and emitted under
	/// `ParamHeader.header`. This preserves the spec's absent/null omission
	/// semantics (draft basic/transports mirroring table). Array-item paths (which
	/// cross an `items` schema) are not mirrored: a single repeated header name
	/// cannot unambiguously represent per-element values, so they are skipped — only
	/// the well-defined object-nesting case is handled. Separated as a pure static
	/// helper so the mirroring can be unit-tested without a live server.
	package static string[string] paramHeaders(Json inputSchema, Json arguments) @safe
	{
		import mcp.protocol.modern : draftParamHeaders = paramHeaders;

		string[string] headers;
		if (arguments.type != Json.Type.object)
			return headers;
		foreach (ph; draftParamHeaders(inputSchema))
		{
			// Descend the path into the arguments object. Any missing / null /
			// non-object intermediate node means the value is not present -> no header.
			Json node = arguments;
			bool resolved = true;
			foreach (seg; ph.path)
			{
				if (node.type != Json.Type.object || seg !in node)
				{
					resolved = false;
					break;
				}
				node = node[seg];
			}
			if (!resolved)
				continue;
			// Absent / null -> no header (mirroring table).
			if (node.type == Json.Type.null_ || node.type == Json.Type.undefined)
				continue;
			string raw;
			switch (node.type)
			{
			case Json.Type.string:
				raw = node.get!string;
				break;
			case Json.Type.int_:
			case Json.Type.bigInt:
			case Json.Type.bool_:
				raw = node.toString();
				break;
			default:
				// float (number) is excluded by header validation; object/array at a
				// leaf path is not a primitive the spec mirrors -> skip.
				continue;
			}
			headers[ph.header] = encodeHeaderValue(raw);
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
	/// and then evicted, so the tracking set keeps only in-flight ids and does not
	/// grow without bound. A later duplicate completion for an evicted id no
	/// longer matches a tracked id and is dropped as unknown, the same ignore
	/// outcome. Every other notification is forwarded unchanged.
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
			elicitationIds_.remove(eid); // completion forwarded -> stop tracking
		}
		// Deliver progress updates as a typed value: route to the per-call sink
		// registered for the notification's token when one exists (so overlapping
		// concurrent calls each see only their own progress), otherwise to the
		// global observer.
		if (method == "notifications/progress")
		{
			auto pn = ProgressNotification.fromJson(params);
			auto perCall = pn.progressToken.toString() in perCallProgress_;
			if (perCall !is null)
				(*perCall)(pn);
			else if (onProgress !is null)
				onProgress(pn);
		}
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

	/// Answer a server->client request by dispatching to the matching handler and
	/// sending the response. We are inside the transport's inbound-read callback of
	/// an in-flight request, and the server withholds that request's final response
	/// until it receives this reply, so *how* we send it depends on
	/// `transport.repliesSynchronously` (see `ClientTransport` for the rationale):
	/// true sends the reply inline, false defers it via `runTask` so the read loop
	/// keeps draining and the two directions cannot wedge each other.
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

		if (transport.repliesSynchronously())
		{
			transport.sendOneway(response);
			return;
		}

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
				// Gate on the capabilities actually advertised at the handshake
				// (`effectiveCapabilities`), not the raw `capabilities` field:
				// installing `onElicitation` alone auto-advertises the form submode
				// on the wire, so an inbound form request must be accepted
				// even when no manual capability flags were set.
				const advertised = effectiveCapabilities();
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
					supported = advertised.elicitationForm
						|| (advertised.elicitation && !advertised.elicitationUrl);
					break;
				case "url":
					supported = advertised.elicitationUrl;
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
	/// cancelled (basic/utilities/cancellation). The id is evicted from the
	/// cancelled-id set once its late response has been observed and dropped here,
	/// so the set does not grow without bound over a long-lived client; an id
	/// whose late response never arrives is reclaimed by the size backstop in
	/// `cancel`.
	bool isCancelled(long id) @safe
	{
		if (id !in cancelledRequests_)
			return false;
		cancelledRequests_.remove(id);
		return true;
	}

	/// Test seam: set the id `cancel()` treats as the (uncancellable) initialize
	/// request, without driving the live `initialize` handshake.
	version (unittest) package void setInitializeRequestIdForTest(long id) @safe nothrow @nogc
	{
		initializeRequestId = id;
	}
}

/// Find a `Tool` by its `name` in a drained `tools/list` slice (typically
/// `client.listTools().tools`). Returns the first match wrapped in a
/// `Nullable!Tool`, or a null `Nullable` when no tool carries that name, so
/// callers can branch on presence without hand-rolling the scan. Usable via
/// UFCS as `tools.byName("calc")`.
Nullable!Tool byName(Tool[] tools, string name) @safe
{
	foreach (t; tools)
		if (t.name == name)
			return nullable(t);
	return Nullable!Tool.init;
}

/// Find a `Prompt` by its `name` in a drained `prompts/list` slice (typically
/// `client.listPrompts().prompts`). Returns the first match wrapped in a
/// `Nullable!Prompt`, or a null `Nullable` when absent. Usable via UFCS as
/// `prompts.byName("greet")`.
Nullable!Prompt byName(Prompt[] prompts, string name) @safe
{
	foreach (p; prompts)
		if (p.name == name)
			return nullable(p);
	return Nullable!Prompt.init;
}

unittest  // byName returns the matching Tool wrapped in a non-null Nullable
{
	Tool[] tools = [Tool("calc"), Tool("greet")];
	auto found = tools.byName("greet");
	assert(!found.isNull);
	assert(found.get.name == "greet");
}

unittest  // byName over Tool[] returns a null Nullable when no name matches
{
	Tool[] tools = [Tool("calc")];
	assert(tools.byName("missing").isNull);
}

unittest  // byName returns the matching Prompt wrapped in a non-null Nullable
{
	Prompt[] prompts = [Prompt("greet"), Prompt("code_review")];
	auto found = prompts.byName("code_review");
	assert(!found.isNull);
	assert(found.get.name == "code_review");
}

unittest  // byName over Prompt[] returns a null Nullable when no name matches
{
	Prompt[] prompts = [Prompt("greet")];
	assert(prompts.byName("missing").isNull);
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

unittest  // public flagship type uses single-cap Mcp* casing
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
	assert(resolveNegotiatedVersion("2026-07-28") == ProtocolVersion.modern);
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
	assert(selectMutualVersion(["2025-11-25", "2026-07-28"], v) && v == ProtocolVersion.modern);
	assert(selectMutualVersion(["2024-11-05", "2025-03-26"], v) && v == ProtocolVersion.v2025_03_26);
}

unittest  // selectMutualVersion reports no overlap
{
	ProtocolVersion v;
	assert(!selectMutualVersion(["1999-01-01"], v));
	assert(!selectMutualVersion([], v));
}

unittest  // withRequestLogLevel stamps the draft per-request logLevel meta key
{
	// draft server/utilities/logging (SEP-2575/2577): the per-request opt-in is
	// `_meta["io.modelcontextprotocol/logLevel"]`.
	Json p = Json.emptyObject;
	p["name"] = "tool";
	auto stamped = withRequestLogLevel(p, "debug");
	assert(stamped["_meta"][MetaKey.logLevel].get!string == "debug");
	assert(stamped["name"].get!string == "tool"); // existing fields preserved
}

unittest  // withRequestLogLevel with an empty level is a no-op
{
	Json p = Json.emptyObject;
	p["name"] = "tool";
	auto same = withRequestLogLevel(p, "");
	assert("_meta" !in same);
}

unittest  // withRequestLogLevel preserves existing _meta entries
{
	Json p = Json.emptyObject;
	Json meta = Json.emptyObject;
	meta["progressToken"] = "tok-1";
	p["_meta"] = meta;
	auto stamped = withRequestLogLevel(p, "warning");
	assert(stamped["_meta"]["progressToken"].get!string == "tok-1");
	assert(stamped["_meta"][MetaKey.logLevel].get!string == "warning");
}

unittest  // draft setLogLevel does NOT send the removed logging/setLevel RPC
{
	// The draft (2026-07-28) removed logging/setLevel (SEP-2575/2577); a conformant
	// draft server answers it with -32601. So on a draft session setLogLevel must
	// NOT POST that RPC — it records the sticky per-request opt-in instead.
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	bool sentRpc;
	c.onRpcForTest = (string method, Json params) @safe {
		if (method == "logging/setLevel")
			sentRpc = true;
		return Json.emptyObject;
	};
	c.setLogLevel("debug");
	assert(!sentRpc);
}

unittest  // draft setLogLevel makes injectModernMeta stamp the per-request logLevel
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	c.setLogLevel("info");
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	// Every subsequent draft request carries the opt-in field the server needs
	// before it may emit notifications/message.
	assert(meta["_meta"][MetaKey.logLevel].get!string == "info");
}

unittest  // injectModernMeta omits logLevel when no opt-in level has been set
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	// No setLogLevel/per-request level -> the server emits no notifications/message.
	assert(MetaKey.logLevel !in meta["_meta"]);
}

unittest  // an explicit per-request logLevel wins over the sticky setLogLevel default
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	c.setLogLevel("error"); // sticky default
	Json p = Json.emptyObject;
	p = withRequestLogLevel(p, "debug"); // explicit per-request override
	auto meta = c.injectModernMetaForTest(p);
	assert(meta["_meta"][MetaKey.logLevel].get!string == "debug");
}

unittest  // released-protocol setLogLevel still sends logging/setLevel
{
	// On a non-draft session the RPC still exists; setLogLevel must POST it.
	auto c = McpClient.http("http://localhost");
	string sentMethod;
	Json sentParams = Json.undefined;
	c.onRpcForTest = (string method, Json params) @safe {
		sentMethod = method;
		sentParams = params;
		return Json.emptyObject;
	};
	c.setLogLevel("warning");
	assert(sentMethod == "logging/setLevel");
	assert(sentParams["level"].get!string == "warning");
}

unittest  // setLogLevel rejects an invalid level locally (released protocol)
{
	import std.exception : assertThrown;

	// "warn" is not an RFC-5424 level name ("warning" is). On a released session
	// it must be rejected locally rather than POSTed to a server that will reject it.
	auto c = McpClient.http("http://localhost");
	bool sent;
	c.onRpcForTest = (string method, Json params) @safe {
		sent = true;
		return Json.emptyObject;
	};
	assertThrown!McpException(c.setLogLevel("warn"));
	assert(!sent, "an invalid level must not reach the wire");
}

unittest  // setLogLevel rejects an invalid level locally (draft) without storing it
{
	import std.exception : assertThrown;

	auto c = McpClient.http("http://localhost");
	c.enableModern();
	assertThrown!McpException(c.setLogLevel("verbose"));
	// The bad level must not be stamped into subsequent draft requests' _meta.
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	assert(MetaKey.logLevel !in meta["_meta"], "an invalid level must not be stored");
}

unittest  // the typed LogLevel overload is accepted and forwarded
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	c.setLogLevel(LogLevel.warning);
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	assert(meta["_meta"][MetaKey.logLevel].get!string == "warning");
}

unittest  // a valid string level still passes
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	c.setLogLevel("debug");
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	assert(meta["_meta"][MetaKey.logLevel].get!string == "debug");
}

unittest  // empty level clears the draft opt-in
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	c.setLogLevel("info");
	c.setLogLevel(""); // clear
	auto meta = c.injectModernMetaForTest(Json.emptyObject);
	assert(MetaKey.logLevel !in meta["_meta"]);
}

private Tool headerTool(string name, Json[string] props) @safe
{
	import std.algorithm : map;
	import std.array : array;

	Json p = Json.emptyObject;
	foreach (k, v; props)
		p[k] = v;
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	schema["properties"] = p;
	Tool t;
	t.name = name;
	t.inputSchema = schema;
	return t;
}

unittest  // listTools excludes a tool whose x-mcp-header value is empty (draft)
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Tool bad = headerTool("bad", [
		"region": Json(["type": Json("string"), "x-mcp-header": Json("")])
	]);
	Tool good = headerTool("good", [
		"region": Json(["type": Json("string"), "x-mcp-header": Json("Region")])
	]);
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= bad.toJson();
		arr ~= good.toJson();
		r["tools"] = arr;
		return r;
	};
	auto res = c.listTools();
	import std.algorithm : canFind, map;
	import std.array : array;

	auto names = res.tools.map!(t => t.name).array;
	assert(!names.canFind("bad"), "tool with empty x-mcp-header must be excluded");
	assert(names.canFind("good"), "sibling valid tool must remain");
	// The offending tool must not be cached for header mirroring.
	assert("bad" !in c.toolInputSchemas_);
	assert("good" in c.toolInputSchemas_);
}

unittest  // listTools excludes a tool whose x-mcp-header value contains CR/LF
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Tool bad = headerTool("crlf", [
		"region": Json([
			"type": Json("string"),
			"x-mcp-header": Json("Re\r\ngion")
		])
	]);
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= bad.toJson();
		r["tools"] = arr;
		return r;
	};
	auto res = c.listTools();
	assert(res.tools.length == 0, "tool with CR/LF header must be excluded");
	assert("crlf" !in c.toolInputSchemas_);
}

unittest  // listTools excludes a tool annotating a number-typed parameter
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Tool bad = headerTool("num", [
		"amount": Json(["type": Json("number"), "x-mcp-header": Json("Amount")])
	]);
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= bad.toJson();
		r["tools"] = arr;
		return r;
	};
	auto res = c.listTools();
	assert(res.tools.length == 0, "number-typed x-mcp-header must be excluded");
	assert("num" !in c.toolInputSchemas_);
}

unittest  // listTools excludes a tool with case-insensitively duplicate header values
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Tool bad = headerTool("dup", [
		"a": Json(["type": Json("string"), "x-mcp-header": Json("Region")]),
		"b": Json(["type": Json("string"), "x-mcp-header": Json("region")])
	]);
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= bad.toJson();
		r["tools"] = arr;
		return r;
	};
	auto res = c.listTools();
	assert(res.tools.length == 0, "duplicate header values must be excluded");
	assert("dup" !in c.toolInputSchemas_);
}

unittest  // a non-draft session does NOT exclude tools (x-mcp-header MAY be ignored)
{
	auto c = McpClient.http("http://localhost");
	// no enableModern() -> released session
	Tool bad = headerTool("bad", [
		"region": Json(["type": Json("string"), "x-mcp-header": Json("")])
	]);
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		Json arr = Json.emptyArray;
		arr ~= bad.toJson();
		r["tools"] = arr;
		return r;
	};
	auto res = c.listTools();
	assert(res.tools.length == 1, "non-draft session must not exclude on x-mcp-header");
}

unittest  // paramHeaders mirrors a nested annotated object property
{
	// inputSchema: { properties: { filter: { type: object, properties: {
	//   region: { type: string, x-mcp-header: Region } } } } }
	Json inner = Json.emptyObject;
	inner["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json filter = Json.emptyObject;
	filter["type"] = "object";
	filter["properties"] = inner;
	Json props = Json.emptyObject;
	props["filter"] = filter;
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	schema["properties"] = props;

	Json innerArgs = Json.emptyObject;
	innerArgs["region"] = "us-west1";
	Json args = Json.emptyObject;
	args["filter"] = innerArgs;

	auto headers = McpClient.paramHeaders(schema, args);
	assert(HttpHeader.paramPrefix ~ "Region" in headers,
			"nested annotated property must be mirrored to a header");
	assert(decodeHeaderValue(headers[HttpHeader.paramPrefix ~ "Region"]) == "us-west1");
}

unittest  // an absent nested intermediate node emits no header
{
	Json inner = Json.emptyObject;
	inner["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json filter = Json.emptyObject;
	filter["type"] = "object";
	filter["properties"] = inner;
	Json props = Json.emptyObject;
	props["filter"] = filter;
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	schema["properties"] = props;

	// `filter` is absent in the arguments -> no header (absent/null omission).
	auto headers = McpClient.paramHeaders(schema, Json.emptyObject);
	assert(HttpHeader.paramPrefix ~ "Region" !in headers);
}

unittest  // callTool RequestOptions.logLevel attaches the draft per-request opt-in
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Json seen = Json.undefined;
	c.onNotifyForTest = (Json) @safe {};
	c.onRpcForTest = (string method, Json params) @safe {
		// onRpcForTest runs before injectModernMeta, so the explicit per-request
		// level pre-stamped by the overload is already present here.
		if (method == "tools/call")
			seen = params;
		Json res = Json.emptyObject;
		res["content"] = Json.emptyArray;
		return res;
	};
	c.callTool("countdown", Json.emptyObject, RequestOptions(ProgressToken.init, "debug"));
	assert(seen.type == Json.Type.object);
	assert(seen["_meta"][MetaKey.logLevel].get!string == "debug");
}

unittest  // readResource RequestOptions.logLevel attaches the draft per-request opt-in
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Json seen = Json.undefined;
	c.onRpcForTest = (string method, Json params) @safe {
		if (method == "resources/read")
			seen = params;
		Json res = Json.emptyObject;
		res["contents"] = Json.emptyArray;
		return res;
	};
	c.readResource("file:///x", RequestOptions(ProgressToken.init, "notice"));
	assert(seen["_meta"][MetaKey.logLevel].get!string == "notice");
}

unittest  // getPrompt RequestOptions.logLevel attaches the draft per-request opt-in
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();
	Json seen = Json.undefined;
	c.onRpcForTest = (string method, Json params) @safe {
		if (method == "prompts/get")
			seen = params;
		Json res = Json.emptyObject;
		res["messages"] = Json.emptyArray;
		return res;
	};
	c.getPrompt("greet", Json.emptyObject, RequestOptions(ProgressToken.init, "warning"));
	assert(seen["_meta"][MetaKey.logLevel].get!string == "warning");
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

unittest  // overflowing the cancelled set evicts only the oldest, keeping recent ids
{
	auto c = McpClient.http("http://localhost");
	c.onNotifyForTest = (Json message) @safe {};

	// The first id cancelled is the oldest; it is the only one at risk once the
	// set overflows. A wholesale clear (the bug) would instead drop EVERY id.
	const oldest = 1L;
	c.cancel(oldest);

	// Fill the rest of the set right up to its bound with distinct ids.
	foreach (i; 0 .. McpClient.maxCancelledTracked_ - 1)
		c.cancel(1000L + i);

	// One more, recently cancelled id tips the set over the bound; FIFO eviction
	// removes the single oldest entry (`oldest`) and keeps everything else.
	const recent = 999L;
	c.cancel(recent);

	// The bug accepted late responses for still-relevant cancelled ids after the
	// clear; the fix keeps recently-cancelled ids suppressed and only drops the
	// oldest.
	assert(c.isResponseCancelled(recent));
	assert(c.isResponseCancelled(1000L)); // a mid-set filler survives
	assert(!c.isResponseCancelled(oldest));
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

unittest  // installing onElicitation alone accepts an inbound form elicitation/create
{
	auto c = McpClient.http("http://localhost");
	// Install ONLY the handler; set NO manual capability flags. The documented
	// auto-advertise contract sends the form submode via effectiveCapabilities()
	// at the handshake, so an inbound form request must be accepted (not -32602).
	assert(!c.capabilities.elicitation);
	assert(!c.capabilities.elicitationForm);

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

unittest  // -32042 URLElicitationRequiredError registers its elicitationIds (client/elicitation, 2025-11-25/draft)
{
	auto c = McpClient.http("http://localhost");

	// Build the error object exactly as the transport hands it to rpc():
	// {code: -32042, message, data: {elicitations: [ElicitRequestURLParams...]}}.
	Json e0 = Json.emptyObject;
	e0["mode"] = "url";
	e0["url"] = "https://example.com/elicit/a";
	e0["elicitationId"] = "e-from-error";
	Json data = Json.emptyObject;
	data["elicitations"] = Json([e0]);
	Json error = Json.emptyObject;
	error["code"] = cast(int) ErrorCode.urlElicitationRequired;
	error["message"] = "URL elicitation required";
	error["data"] = data;

	// rpc() must surface the error AND, as a side effect, register the id so a
	// later completion correlates. Drive it through the real rpc() path via the
	// test seam, which throws the McpException the transport
	// (HttpClientTransport.errorFrom) would build.
	c.onRpcForTest = (string, Json) @safe {
		throw new McpException(cast(int) ErrorCode.urlElicitationRequired,
				"URL elicitation required", error);
	};

	bool threw;
	try
		cast(void) c.callTool("any");
	catch (McpException ex)
		threw = (ex.code == ErrorCode.urlElicitationRequired);
	assert(threw);

	// The completion notification for the error-announced id is forwarded
	// (an unregistered id would be dropped as "unknown").
	string forwardedMethod;
	c.onNotification = (string method, Json) @safe { forwardedMethod = method; };
	Json note = Json.emptyObject;
	note["elicitationId"] = "e-from-error";
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(forwardedMethod == "notifications/elicitation/complete");
}

unittest  // registerUrlElicitations records every announced id; a non-32042 error registers nothing
{
	auto c = McpClient.http("http://localhost");

	Json e0 = Json.emptyObject;
	e0["elicitationId"] = "id-1";
	Json e1 = Json.emptyObject;
	e1["elicitationId"] = "id-2";
	Json data = Json.emptyObject;
	data["elicitations"] = Json([e0, e1]);
	Json error = Json.emptyObject;
	error["data"] = data;

	c.registerUrlElicitations(error);

	string[] seen;
	c.onNotification = (string method, Json) @safe { seen ~= method; };
	foreach (id; ["id-1", "id-2"])
	{
		Json note = Json.emptyObject;
		note["elicitationId"] = id;
		c.dispatchNotification("notifications/elicitation/complete", note);
	}
	assert(seen.length == 2); // both ids correlated and forwarded
}

unittest  // registerUrlElicitations tolerates a malformed/absent elicitations payload
{
	auto c = McpClient.http("http://localhost");
	c.registerUrlElicitations(Json.emptyObject); // no data
	Json missingArray = Json.emptyObject;
	missingArray["data"] = Json.emptyObject; // data present, elicitations absent
	c.registerUrlElicitations(missingArray);
	Json badEntries = Json.emptyObject;
	Json d = Json.emptyObject;
	d["elicitations"] = Json([Json("not-an-object"), Json.emptyObject]);
	badEntries["data"] = d;
	c.registerUrlElicitations(badEntries); // entries without a string id are skipped

	// None of the above should have registered a correlatable id.
	bool forwarded;
	c.onNotification = (string, Json) @safe { forwarded = true; };
	Json note = Json.emptyObject;
	note["elicitationId"] = "not-an-object";
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

unittest  // complete() RequestOptions.progressToken attaches the token under _meta.progressToken
{
	auto c = McpClient.http("http://localhost");
	Json sent;
	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "completion/complete");
		sent = params;
		Json r = Json.emptyObject;
		Json comp = Json.emptyObject;
		comp["values"] = Json.emptyArray;
		r["completion"] = comp;
		return r;
	};

	c.complete(CompletionReference.forPrompt("greet"), "name", "al", null,
			RequestOptions(ProgressToken("comp-tok")));

	assert(sent["_meta"]["progressToken"].get!string == "comp-tok");
	// The base completion params are still shaped as usual.
	assert(sent["argument"]["name"].get!string == "name");
	assert(sent["argument"]["value"].get!string == "al");
}

unittest  // complete() with RequestOptions.progressToken still carries the resolved-argument context
{
	auto c = McpClient.http("http://localhost");
	Json sent;
	c.onRpcForTest = (string method, Json params) @safe {
		sent = params;
		Json r = Json.emptyObject;
		Json comp = Json.emptyObject;
		comp["values"] = Json.emptyArray;
		r["completion"] = comp;
		return r;
	};

	string[string] ctx = ["owner": "octocat"];
	c.complete(CompletionReference.forPrompt("pr"), "repo", "m", ctx,
			RequestOptions(ProgressToken(7L)));

	assert(sent["_meta"]["progressToken"].get!long == 7);
	assert(sent["context"]["arguments"]["owner"].get!string == "octocat");
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

unittest  // typed callTool args serialize to the same wire object as hand-built Json
{
	import vibe.data.json : serializeToJson;

	static struct AddArgs
	{
		int a;
		int b;
	}

	// The typed overload forwards `serializeToJson(args)` to the Json overload,
	// so the wire arguments object must match a hand-built Json exactly.
	auto typed = serializeToJson(AddArgs(2, 3));
	Json hand = Json.emptyObject;
	hand["a"] = 2;
	hand["b"] = 3;

	auto fromTyped = McpClient.buildToolCallParams("add", typed, ProgressToken.init);
	auto fromHand = McpClient.buildToolCallParams("add", hand, ProgressToken.init);
	assert(fromTyped == fromHand);
	assert(fromTyped["arguments"]["a"].get!int == 2);
	assert(fromTyped["arguments"]["b"].get!int == 3);
}

unittest  // callTool with a per-call progress callback receives that call's progress
{
	auto c = McpClient.http("http://localhost");

	// The server side: read the minted progress token from the request and emit
	// a correlated notifications/progress for it (delivered via dispatchInbound,
	// the same path a live transport uses) before returning the tool result.
	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "tools/call");
		auto tok = params["_meta"]["progressToken"];
		Json pn = Json.emptyObject;
		pn["progressToken"] = tok;
		pn["progress"] = 0.5;
		c.dispatchInbound(Message(makeNotification("notifications/progress", pn)));
		Json r = Json.emptyObject;
		r["content"] = Json.emptyArray;
		return r;
	};

	ProgressNotification[] received;
	c.callTool("work", Json.emptyObject, RequestOptions(ProgressToken.init, "",
			(ProgressNotification n) @safe { received ~= n; }));

	assert(received.length == 1);
	assert(received[0].progress == 0.5);
}

unittest  // a per-call progress callback restores the prior global onProgress
{
	auto c = McpClient.http("http://localhost");
	ProgressNotification[] global;
	c.onProgress = (ProgressNotification n) @safe { global ~= n; };
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		r["content"] = Json.emptyArray;
		return r;
	};

	c.callTool("work", Json.emptyObject, RequestOptions(ProgressToken.init, "",
			(ProgressNotification n) @safe {}));

	// After the call the global onProgress field must be restored, and a later
	// progress notification reaches it.
	assert(c.onProgress !is null);
	Json pn = Json.emptyObject;
	pn["progressToken"] = "after";
	pn["progress"] = 1.0;
	c.dispatchInbound(Message(makeNotification("notifications/progress", pn)));
	assert(global.length == 1);
}

unittest  // RequestOptions combines an explicit progressToken, logLevel and onProgress
{
	auto c = McpClient.http("http://localhost");
	c.enableModern();

	// The caller supplies its own token; onProgress must correlate against THAT
	// token (no minting), and logLevel must still ride along in the same request.
	Json seen = Json.undefined;
	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "tools/call");
		seen = params;
		Json pn = Json.emptyObject;
		pn["progressToken"] = params["_meta"]["progressToken"];
		pn["progress"] = 0.25;
		c.dispatchInbound(Message(makeNotification("notifications/progress", pn)));
		Json r = Json.emptyObject;
		r["content"] = Json.emptyArray;
		return r;
	};

	ProgressNotification[] received;
	c.callTool("work", Json.emptyObject, RequestOptions(ProgressToken("caller-tok"),
			"debug", (ProgressNotification n) @safe { received ~= n; }));

	assert(seen["_meta"]["progressToken"].get!string == "caller-tok");
	assert(seen["_meta"][MetaKey.logLevel].get!string == "debug");
	assert(received.length == 1);
	assert(received[0].progress == 0.25);
}

unittest  // overlapping per-call progress sinks each receive only their own token
{
	auto c = McpClient.http("http://localhost");

	ProgressNotification[] globalSeen;
	c.onProgress = (ProgressNotification n) @safe { globalSeen ~= n; };

	ProgressNotification[] sinkA;
	ProgressNotification[] sinkB;

	// Simulate two concurrent calls A and B by nesting B's call inside A's RPC,
	// so B opens (and its sink registers) while A is still in flight. Each emits a
	// progress notification correlated to its own minted token. The single
	// mutable-field save/restore could not keep both sinks live at once; the
	// per-token registry must route each token to its own sink.
	string tokenA;
	c.onRpcForTest = (string method, Json paramsA) @safe {
		tokenA = paramsA["_meta"]["progressToken"].get!string;

		c.onRpcForTest = (string method2, Json paramsB) @safe {
			const tokenB = paramsB["_meta"]["progressToken"].get!string;
			assert(tokenB != tokenA);
			// Progress for A's token arrives while B is also in flight: it must
			// still reach A's sink, not B's.
			Json pa = Json.emptyObject;
			pa["progressToken"] = tokenA;
			pa["progress"] = 0.1;
			c.dispatchInbound(Message(makeNotification("notifications/progress", pa)));
			// Progress for B's token reaches B's sink.
			Json pb = Json.emptyObject;
			pb["progressToken"] = tokenB;
			pb["progress"] = 0.2;
			c.dispatchInbound(Message(makeNotification("notifications/progress", pb)));
			Json rb = Json.emptyObject;
			rb["content"] = Json.emptyArray;
			return rb;
		};
		c.callTool("inner", Json.emptyObject, (ProgressNotification n) @safe {
			sinkB ~= n;
		});

		Json ra = Json.emptyObject;
		ra["content"] = Json.emptyArray;
		return ra;
	};

	c.callTool("outer", Json.emptyObject, (ProgressNotification n) @safe {
		sinkA ~= n;
	});

	assert(sinkA.length == 1 && sinkA[0].progress == 0.1);
	assert(sinkB.length == 1 && sinkB[0].progress == 0.2);
	// No per-call progress was misrouted to the global handler.
	assert(globalSeen.length == 0);
	// Both calls have returned: every per-call sink is unregistered (no stale
	// wrapper left behind), and the global field was never swapped out.
	assert(c.perCallProgress_.length == 0);
	assert(c.onProgress !is null);

	// After both calls complete, the global handler is intact and still receives
	// progress for any other (unregistered) token.
	Json pg = Json.emptyObject;
	pg["progressToken"] = "other";
	pg["progress"] = 0.9;
	c.dispatchInbound(Message(makeNotification("notifications/progress", pg)));
	assert(globalSeen.length == 1 && globalSeen[0].progress == 0.9);
}

unittest  // callTool delegate overload routes a single callback as a per-call sink
{
	auto c = McpClient.http("http://localhost");

	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "tools/call");
		// The convenience overload still mints a token and stamps it on the request.
		auto tok = params["_meta"]["progressToken"];
		Json pn = Json.emptyObject;
		pn["progressToken"] = tok;
		pn["progress"] = 0.75;
		c.dispatchInbound(Message(makeNotification("notifications/progress", pn)));
		Json r = Json.emptyObject;
		r["content"] = Json.emptyArray;
		return r;
	};

	ProgressNotification[] received;
	c.callTool("work", Json.emptyObject, (ProgressNotification n) @safe {
		received ~= n;
	});

	assert(received.length == 1);
	assert(received[0].progress == 0.75);
}

unittest  // RequestOptions.withProgress sets only the onProgress sink
{
	bool called;
	auto opts = RequestOptions.withProgress((ProgressNotification) @safe {
		called = true;
	});
	assert(opts.onProgress !is null);
	assert(!opts.progressToken.isSet);
	assert(opts.logLevel.length == 0);
}

unittest  // typed getPrompt produces the same wire args as the Json form
{
	static struct GreetArgs
	{
		string who;
	}

	Json[] sentArgs;
	auto c = McpClient.http("http://localhost");
	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "prompts/get");
		sentArgs ~= params["arguments"];
		Json r = Json.emptyObject;
		r["messages"] = Json.emptyArray;
		return r;
	};

	c.getPrompt("greet", GreetArgs("world"));
	Json hand = Json.emptyObject;
	hand["who"] = "world";
	c.getPrompt("greet", hand);

	assert(sentArgs.length == 2);
	assert(sentArgs[0] == sentArgs[1]);
	assert(sentArgs[0]["who"].get!string == "world");
}

unittest  // spawnSibling resolves a binary next to the running executable
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	// The path-resolution helper places the sibling name next to thisExePath.
	auto resolved = McpClient.resolveSiblingPath("peer-server");
	assert(resolved == buildPath(dirName(thisExePath()), "peer-server"));
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
	import mcp.protocol.modern : decodeHeaderValue;

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

unittest  // a server that keeps requesting input stops at exactly maxRounds tools/call requests
{
	import mcp.protocol.modern : InputRequiredResult;

	auto c = McpClient.http("http://localhost/mcp");
	c.onElicitation = (ElicitParams) @safe {
		return ElicitResult.accept(Json.emptyObject);
	};
	int calls;
	c.onRpcForTest = (string method, Json params) @safe {
		assert(method == "tools/call");
		calls++;
		// Always answer with an inputRequired result so the loop runs to its bound.
		InputRequiredResult ir;
		ir.inputRequests = [InputRequest("q", "elicitation", Json.emptyObject)];
		return ir.toJson();
	};

	auto result = c.callTool("work", Json.emptyObject);
	// The bound (maxRounds == 16) must be a true cap: no extra 17th request after
	// it is exceeded, and the still-inputRequired result is handed back.
	assert(calls == 16);
	assert(result.isInputRequired);
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

unittest  // listTools throws (rather than looping) when the server never advances the cursor
{
	import std.exception : assertThrown;

	auto c = McpClient.http("http://localhost");
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		r["tools"] = Json.emptyArray;
		r["nextCursor"] = "stuck"; // same cursor forever, even after we send it back
		return r;
	};
	assertThrown!McpException(c.listTools());
}

unittest  // listResources throws when the server cycles the pagination cursor
{
	import std.exception : assertThrown;

	auto c = McpClient.http("http://localhost");
	int call;
	c.onRpcForTest = (string method, Json params) @safe {
		Json r = Json.emptyObject;
		r["resources"] = Json.emptyArray;
		// A -> B -> A cycle: each page makes apparent progress but revisits A.
		r["nextCursor"] = (call++ % 2 == 0) ? "A" : "B";
		return r;
	};
	assertThrown!McpException(c.listResources());
}

unittest  // a cancelled-request id is evicted once its late response has been dropped
{
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	c.cancel(42);
	// First observation of the late response: dropped (true) and the id evicted.
	assert(c.isCancelled(42));
	// A second response for the same id is no longer suppressed: the set shrank.
	assert(!c.isCancelled(42));
}

unittest  // a completed URL-elicitation id is evicted from the in-flight tracking set
{
	auto c = McpClient.http("http://localhost");
	c.capabilities.elicitation = true;
	c.capabilities.elicitationUrl = true;
	c.onElicitation = (ElicitParams) @safe { return ElicitResult.init; };

	Json create = Json.emptyObject;
	create["mode"] = "url";
	create["url"] = "https://example.com/elicit";
	create["elicitationId"] = "e-evict";
	c.dispatchServerMethod("elicitation/create", create);

	int forwarded;
	c.onNotification = (string, Json) @safe { forwarded++; };

	Json note = Json.emptyObject;
	note["elicitationId"] = "e-evict";
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(forwarded == 1); // forwarded once, then the id is evicted
	// A duplicate completion for the now-untracked id is ignored, not forwarded.
	c.dispatchNotification("notifications/elicitation/complete", note);
	assert(forwarded == 1);
}

unittest  // initialize records the server's advertised capabilities/info/instructions
{
	auto c = McpClient.http("http://localhost");
	c.onNotifyForTest = (Json message) @safe {}; // swallow notifications/initialized
	c.onRpcForTest = (string method, Json params) @safe {
		Json res = Json.emptyObject;
		res["protocolVersion"] = latestStable.toWire;
		Json caps = Json.emptyObject;
		caps["logging"] = Json.emptyObject;
		res["capabilities"] = caps;
		Json info = Json.emptyObject;
		info["name"] = "demo-server";
		info["version"] = "9.9.9";
		res["serverInfo"] = info;
		res["instructions"] = "be nice";
		return res;
	};
	c.initialize(latestStable.toWire);
	assert(c.serverInfo().name == "demo-server");
	assert(c.serverInfo().version_ == "9.9.9");
	assert(!c.serverInstructions().isNull);
	assert(c.serverInstructions().get == "be nice");
}

unittest  // readResource exposes the parsed CacheableResult freshness hint as .cache
{
	import core.time : seconds;

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
	assert(res.cache.get.ttl == 6.seconds);
	assert(res.cache.get.cacheScope == CacheScope.private_);
}

unittest  // a list result exposes .cache from the first page's freshness hint
{
	import core.time : seconds;

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
	assert(res.cache.get.ttl == 5.seconds);
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

		bool repliesSynchronously() @safe
		{
			return false;
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
	assert(c !is null);
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
	c.enableModern();
	auto headers = transport.protocol.headersFor(Json.undefined);
	assert(headers["MCP-Protocol-Version"] == ProtocolVersion.modern.toWire);
}

unittest  // a resources/read URI is encoded in Mcp-Name, never placed raw (no CR/LF injection)
{
	import mcp.protocol.modern : decodeHeaderValue;

	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	c.enableModern();

	// A server-advertised URI carrying CR/LF must not appear verbatim in the
	// header value; it round-trips through encodeHeaderValue instead.
	const evil = "file:///x\r\nMcp-Injected: 1";
	Json msg = Json.emptyObject;
	msg["method"] = "resources/read";
	Json params = Json.emptyObject;
	params["uri"] = evil;
	msg["params"] = params;

	auto headers = transport.protocol.headersFor(msg);
	const wire = headers[HttpHeader.name];
	import std.algorithm : canFind;

	assert(!wire.canFind('\r') && !wire.canFind('\n'),
			"Mcp-Name must not carry raw CR/LF onto the wire");
	assert(decodeHeaderValue(wire) == evil, "encoded Mcp-Name must round-trip to the URI");
}

unittest  // a benign reserved-character resource URI still survives Mcp-Name encoding
{
	import mcp.protocol.modern : decodeHeaderValue;

	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	c.enableModern();

	// A space is a non-token byte: it must be encoded rather than corrupt the line.
	const uri = "file:///a b";
	Json msg = Json.emptyObject;
	msg["method"] = "resources/read";
	Json params = Json.emptyObject;
	params["uri"] = uri;
	msg["params"] = params;

	auto headers = transport.protocol.headersFor(msg);
	assert(decodeHeaderValue(headers[HttpHeader.name]) == uri);
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

unittest  // connect() auto-detect probes server/discover with draft framing and selects draft
{
	// A stateless/draft server only serves `server/discover` when the probe is
	// itself draft-framed; an undecorated probe would resolve to the server's
	// stable default and be rejected. The probe must carry the draft
	// `_meta.protocolVersion` and the draft `MCP-Protocol-Version` header, and
	// connect() must end up on draft.
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	bool sawModernFramedDiscover;
	transport.responder = (Json message, long expectId) @safe {
		assert(message["method"].get!string == "server/discover");
		// The probe self-advertises draft in the body...
		assert(message["params"]["_meta"][MetaKey.protocolVersion].get!string
				== ProtocolVersion.modern.toWire);
		// ...and in the protocol-derived headers the transport would send.
		auto headers = c.headersFor(message);
		assert(headers[HttpHeader.protocolVersion] == ProtocolVersion.modern.toWire);
		sawModernFramedDiscover = true;
		Json r = Json.emptyObject;
		r["protocolVersions"] = Json.emptyArray;
		r["protocolVersions"] ~= Json(ProtocolVersion.modern.toWire);
		r["capabilities"] = Json.emptyObject;
		Json info = Json.emptyObject;
		info["name"] = "draft-srv";
		info["version"] = "1.0";
		r["serverInfo"] = info;
		return r;
	};
	auto chosen = c.connect();
	assert(sawModernFramedDiscover);
	assert(chosen == ProtocolVersion.modern);
}

unittest  // connect() still falls back to initialize when even a draft-framed probe is methodNotFound
{
	// A genuine legacy server rejects `server/discover` with -32601 regardless of
	// draft framing; connect() must then run the legacy initialize handshake and
	// must not be left in draft mode by the probe.
	auto transport = new RecordingClientTransport();
	auto c = new McpClient(transport);
	transport.responder = (Json message, long expectId) @safe {
		if (message["method"].get!string == "server/discover")
			throw new McpException(ErrorCode.methodNotFound, "Method not found");
		// The legacy initialize handshake.
		Json r = Json.emptyObject;
		r["protocolVersion"] = latestStable.toWire;
		r["capabilities"] = Json.emptyObject;
		Json info = Json.emptyObject;
		info["name"] = "legacy-srv";
		info["version"] = "1.0";
		r["serverInfo"] = info;
		return r;
	};
	auto chosen = c.connect();
	assert(chosen == latestStable);
	assert(!chosen.isModern);
}

unittest  // test-only RPC/notify hooks are guarded behind version(unittest)
{
	// The test seams `onRpcForTest`, `onNotifyForTest`, and
	// `setInitializeRequestIdForTest` must not ship in non-unittest builds and
	// must not add a runtime branch to `rpc`/`notify` in release. Verify each is
	// declared inside a `version (unittest)` block in this source file.
	import std.file : readText;

	const src = readText(__FILE__);

	static struct Hook
	{
		string name;
		string decl;
	}

	immutable Hook[3] hooks = [
		Hook("onRpcForTest", "delegate(string method, Json params) @safe onRpcForTest;"),
		Hook("onNotifyForTest", "delegate(Json message) @safe onNotifyForTest;"),
		Hook("setInitializeRequestIdForTest", "void setInitializeRequestIdForTest("),
	];

	import std.string : indexOf, lastIndexOf;

	foreach (h; hooks)
	{
		const declPos = src.indexOf(h.decl);
		assert(declPos >= 0, "declaration not found for " ~ h.name);
		// The nearest `version (unittest)` before the declaration must be the
		// guard introducing it (same line / immediately preceding).
		const guardPos = src[0 .. declPos].lastIndexOf("version (unittest)");
		assert(guardPos >= 0, h.name ~ " is not behind version (unittest)");
		// No intervening unguarded class member: the guard must sit on the
		// declaration's own line or the line just above it.
		const between = src[guardPos .. declPos];
		import std.algorithm : count;

		assert(between.count('\n') <= 1, h.name ~ " is not directly guarded by version (unittest)");
	}
}
