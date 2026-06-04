/**
 * MCP Resources example — SERVER (dual transport: stdio AND Streamable HTTP).
 *
 * Demonstrates the server side of MCP Resources, written in the ergonomic
 * UDA style (`@resource` / `@resourceTemplate` / `@tool` annotated methods
 * registered with `registerHandlers`):
 *   - a static `@resource` direct resource (`config://app`) with a draft
 *     `CacheableResult` freshness hint declared via `@cache(ttl, scope)`,
 *   - a `@resourceTemplate` (`note:///{id}`) whose reader receives the matched
 *     `{id}` as a typed argument,
 *   - `subscriptions/listen` + push `notifications/resources/updated` (via
 *     `notifyResourceUpdated`) when a watched resource changes, and
 *   - `notifications/resources/list_changed` when the available set changes.
 *
 * A small `@tool`, `set_note`, mutates a note's body and (a) emits a
 * resource-updated notification for that note's URI and (b) registers a brand
 * new note resource the first time an id is seen, emitting a list-changed
 * notification. This gives the client something concrete to subscribe to and
 * assert on. The tool returns a typed `SetNoteResult` struct directly, so the
 * reflection layer derives both the `outputSchema` and the per-call
 * `structuredContent` — no `structuredContent` Json is hand-built.
 *
 * Transport selection and the getopt/`runStreamableHttp`-vs-`runStdio` wiring
 * are delegated to the shared `examples_common` scaffold's `runServerFromArgs`.
 *
 * One binary, either transport:
 *   stdio (default): dub run -c server
 *   http:            dub run -c server -- --http --port 8349
 */
module server;

import mcp;
import mcp.api.attributes;
import mcp.api.reflection : registerHandlers;

import std.typecons : nullable;
import core.time : seconds;

import examples_common;

/// Default HTTP port (kept from the original HTTP-only example). The client's
/// HTTP mode connects to `http://127.0.0.1:<port>/mcp`.
enum ushort defaultPort = 8349;

/// Typed result of the `set_note` tool. Returning this struct from the `@tool`
/// method keeps the example on the typed APIs: the reflection layer derives the
/// `structuredContent` Json (and the tool's `outputSchema`) from these fields
/// rather than hand-building any Json. The client asserts these exact fields.
struct SetNoteResult
{
	/// The URI of the note that was set (e.g. `note:///e2e`).
	string uri;
	/// True iff this id was seen for the first time (a new resource appeared).
	bool created;
}

/// The annotated resources/tool surface for this example. The class holds the
/// note store and the server reference so the `set_note` tool can push
/// notifications and dynamically register newly-created note resources.
final class ResourcesApi
{
	private McpServer server;
	/// Backing store for note bodies, keyed by id. The template reader and the
	/// `set_note` tool both read/write this.
	private string[string] notes;

	this(McpServer server) @safe
	{
		this.server = server;
		notes["welcome"] = "Hello from the resources example.";
	}

	/// A static (direct) resource with a draft freshness hint. The hint
	/// (ttlMs/cacheScope) is emitted on the draft `resources/read` response so a
	/// draft client can cache the contents.
	@resource("config://app", "App config", "application/json")
	@cache(60.seconds, "public")
	string config() @safe
	{
		return `{"name":"resources-example","featureFlags":["resources","subscribe"]}`;
	}

	/// A resource template: note:///{id}. The reader receives the captured
	/// `{id}` as a typed argument.
	@resourceTemplate("note:///{id}", "Note", "text/plain")
	string note(string id) @safe
	{
		return (id in notes) ? notes[id] : "(no such note)";
	}

	/// A tool that mutates a note and pushes notifications. `set_note` updates
	/// (or creates) a note. On update it emits notifications/resources/updated
	/// for the note's URI (delivered only to subscribers). The first time an id
	/// is created it also registers a direct resource for that note and emits
	/// notifications/resources/list_changed. It returns the typed `SetNoteResult`
	/// struct directly: the reflection layer derives both the tool's
	/// `outputSchema` and the per-call `structuredContent` from the struct fields,
	/// so there is no hand-built result Json anywhere.
	@tool("set_note", "Set a note's body; pushes resources/updated to subscribers.")
	SetNoteResult setNote(string id, string body) @safe
	{
		const uri = "note:///" ~ id;
		const isNew = (id !in notes);
		notes[id] = body;

		if (isNew)
		{
			// A new note resource appeared -> the available set changed.
			auto r = Resource(uri, "Note " ~ id);
			r.mimeType = nullable("text/plain");
			server.registerResource(r, () @safe {
				return ResourceContents.makeText(uri, "text/plain", notes[id]);
			});
			server.notifyResourcesListChanged();
		}
		// The watched resource changed -> tell subscribers.
		server.notifyResourceUpdated(uri);

		return SetNoteResult(uri, isNew);
	}
}

void main(string[] args) @safe
{
	// This example is STATELESS (the default) because its client
	// speaks the draft (inline resources/read cache hints + the draft
	// subscriptions/listen push mechanism), and a stateful server excludes the
	// draft from negotiation. Its push flow (subscriptions/listen + push
	// notifications/resources/updated) correlates more than one HTTP call, so it is
	// available only over STDIO here (a single implicit connection). Over HTTP a
	// stateless server correctly forbids subscriptions/listen, so the client skips
	// the push phase there. (For HTTP resource-update push, use a stateful server
	// with resources/subscribe + the standalone GET SSE stream.)
	auto server = new McpServer("resources-example", "1.0.0");

	registerHandlers(server, new ResourcesApi(server));

	// Advertise the resources subscribe + listChanged capabilities so the
	// client may open a `subscriptions/listen` stream and receive push
	// notifications over either transport.
	server.enableResourceSubscriptions();
	server.enableResourcesListChanged();

	// Transport (stdio default / --http on --port/--host) is handled by the
	// shared scaffold.
	runServerFromArgs(server, args, defaultPort);
}
