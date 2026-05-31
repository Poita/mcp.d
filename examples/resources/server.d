/**
 * MCP Resources example — SERVER (Streamable HTTP).
 *
 * Demonstrates the server side of MCP Resources, written in the ergonomic
 * UDA style (`@resource` / `@resourceTemplate` / `@tool` annotated methods
 * registered with `registerHandlers`):
 *   - a static `@resource` direct resource (`config://app`) with a draft
 *     `CacheableResult` freshness hint declared via `@cache(ttlMs, scope)`,
 *   - a `@resourceTemplate` (`note:///{id}`) whose reader receives the matched
 *     `{id}` as a typed argument,
 *   - `resources/subscribe` + push `notifications/resources/updated` (via
 *     `notifyResourceUpdated`) when a watched resource changes, and
 *   - `notifications/resources/list_changed` when the available set changes.
 *
 * A small `@tool`, `set_note`, mutates a note's body and (a) emits a
 * resource-updated notification for that note's URI and (b) registers a brand
 * new note resource the first time an id is seen, emitting a list-changed
 * notification. This gives the client something concrete to subscribe to and
 * assert on.
 *
 * Run:  dub run -c server      (serves on http://127.0.0.1:8349/mcp)
 */
module server;

import mcp;
import mcp.transport.streamable_http : runStreamableHttp;
import mcp.api.attributes;
import mcp.api.reflection : registerHandlers;

import std.typecons : nullable;
import vibe.data.json : Json;

enum ushort port = 8349;

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
	@cache(60_000, "public")
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
	/// notifications/resources/list_changed.
	@tool("set_note", "Set a note's body; pushes resources/updated to subscribers.")
	CallToolResult setNote(string id, string body) @safe
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

		Json structured = Json.emptyObject;
		structured["uri"] = uri;
		structured["created"] = isNew;
		auto result = CallToolResult([Content.makeText("updated " ~ uri)]);
		result.structuredContent = structured;
		return result;
	}
}

void main() @safe
{
	auto server = new McpServer("resources-example", "1.0.0");

	registerHandlers(server, new ResourcesApi(server));

	// Advertise the resources subscribe + listChanged capabilities so the
	// client may `resources/subscribe` and receive push notifications.
	server.enableResourceSubscriptions();
	server.enableResourcesListChanged();

	runStreamableHttp(server, port);
}
