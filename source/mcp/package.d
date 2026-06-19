/**
 * mcp — a production-grade Model Context Protocol SDK for D.
 *
 * Importing `mcp` re-exports the curated, stable public API:
 *
 *   - the protocol types (`mcp.protocol.*`: versions, errors, JSON-RPC,
 *     capabilities, core types, sampling),
 *   - the server / client entry points (`McpServer`, `McpClient`,
 *     `RequestContext`),
 *   - the declarative UDA / reflection layer (`@tool`, `@resource`,
 *     `@prompt`, `registerModule`, schema generation), and
 *   - the error builders (`McpException`, `ErrorCode`, `toErrorJson`,
 *     `makeErrorResponse`).
 *
 * Transport wiring and auth plumbing are deliberately kept out of the
 * top-level surface to avoid name collisions and to signal stable-public-API
 * vs internal plumbing. Bring them in explicitly when needed:
 *
 *   - `import mcp.transport;` — stdio / Streamable HTTP / SSE / session /
 *     OAuth-proxy mount / modern transport helpers,
 *   - `import mcp.auth;`      — token verifiers / OAuth client / login /
 *     resource-server / OAuth proxy.
 */
module mcp;

// --- Protocol types ---
public import mcp.protocol.versions;
public import mcp.protocol.errors;
public import mcp.protocol.jsonrpc;
public import mcp.protocol.capabilities;
public import mcp.protocol.types;
public import mcp.protocol.tasks;
public import mcp.protocol.sampling;
public import mcp.protocol.schema;
public import mcp.protocol.events;

// --- Server / client entry points ---
public import mcp.server.task_store;
public import mcp.server.task_runtime : TaskOptions, TaskRuntime;
public import mcp.server.task_context : TaskContext, TaskExecutor, TaskDispatcher,
	InProcessTaskDispatcher, SyncTaskDispatcher, TaskSuspended, TaskDetached;
public import mcp.server.event_store;
public import mcp.server.event_context : EventContext, EventResult, Event,
	EventBatch, FetchContext, SubContext;
public import mcp.server.events_runtime : EventsRuntime, EventsOptions,
	EventRegistration, EventHandle,
	EventCheck, EventMatch, EventTransform, EventLifecycle, PushHandle, PushStream;
public import mcp.server.context;
public import mcp.server.server;
public import mcp.server.settings;
public import mcp.client.client;
public import mcp.client.runner;
public import mcp.client.subscription;
public import mcp.client.cache;
public import mcp.client.events : WebhookReceiver, ReceiverResponse, generateWhsecSecret;
public import mcp.client.event_subscription : EventSubscription;

// --- Declarative UDA / reflection API ---
public import mcp.api.attributes;
public import mcp.api.reflection;

// --- MCP Apps extension (interactive UI resources) ---
public import mcp.api.apps;

// --- MCP Skills extension (SEP-2640 Agent Skills over resources) ---
public import mcp.api.skills;
public import mcp.api.skill_dir;

// --- User-facing modern (next-version) result/hint types ---
// `mcp.protocol.modern` holds only user-facing result/hint wire types
// (`DiscoverResult`, `CacheHint`/`CacheScope`, `RequestMeta`, and the cache
// hint codec). They are referenced by members already on the lean public
// surface — `McpServer.setListCacheHint(string, CacheHint)` and
// `McpClient.discover()` returning `DiscoverResult` — so the whole module is
// safe to re-export. The transport/wire plumbing now lives in
// `mcp.protocol.mrtr`, reachable via `import mcp.transport;`.
public import mcp.protocol.modern;

// --- Opt-in MRTR requestState security ---
// Referenced by `McpServer.secureRequestState(RequestStateSecurity)`. The codec
// itself (`RequestStateCodec`) is internal dispatch plumbing and is not
// re-exported.
public import mcp.server.request_state : RequestStateSecurity,
	RequestStateMode, RequestStateBinding;
