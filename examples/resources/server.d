/**
 * MCP Resources example — SERVER (Streamable HTTP).
 *
 * Demonstrates the server side of MCP Resources:
 *   - a static `@resource`-style direct resource (`config://app`) with a draft
 *     `CacheableResult` freshness hint (ttlMs + cacheScope),
 *   - a resource template (`note:///{id}`) whose reader receives the matched
 *     `{id}`,
 *   - `resources/subscribe` + push `notifications/resources/updated` (via
 *     `notifyResourceUpdated`) when a watched resource changes, and
 *   - `notifications/resources/list_changed` when the available set changes.
 *
 * A small tool, `set_note`, mutates a note's body and (a) emits a
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
import mcp.protocol.draft : CacheHint, CacheScope;

import std.typecons : nullable, Nullable;
import vibe.data.json : Json;

enum ushort port = 8349;

/// Backing store for note bodies, keyed by id. The template reader and the
/// `set_note` tool both close over this.
string[string] notes;

void main() @safe
{
	auto server = new McpServer("resources-example", "1.0.0");

	// --- a static (direct) resource with a draft freshness hint --------------
	// The hint (ttlMs/cacheScope) is emitted on the draft `resources/read`
	// response so a draft client can cache the contents.
	auto cfg = Resource("config://app", "App config");
	cfg.mimeType = nullable("application/json");
	cfg.description = nullable("Static application configuration.");
	server.registerResource(cfg, () @safe {
		return ResourceContents.makeText("config://app", "application/json",
			`{"name":"resources-example","featureFlags":["resources","subscribe"]}`);
	}, nullable(CacheHint(60_000, CacheScope.public_)));

	// --- a resource template: note:///{id} -----------------------------------
	// The reader receives the concrete URI and the captured `{id}`.
	notes["welcome"] = "Hello from the resources example.";
	auto tmpl = ResourceTemplate("note:///{id}", "Note");
	tmpl.mimeType = nullable("text/plain");
	tmpl.description = nullable("A note addressed by id.");
	server.registerResourceTemplate(tmpl, (string uri, string[string] params) @safe {
		const id = params["id"];
		const body_ = (id in notes) ? notes[id] : "(no such note)";
		return ResourceContents.makeText(uri, "text/plain", body_);
	});

	// Advertise the resources subscribe + listChanged capabilities so the
	// client may `resources/subscribe` and receive push notifications.
	server.enableResourceSubscriptions();
	server.enableResourcesListChanged();

	// --- a tool that mutates a note and pushes notifications ------------------
	// `set_note` updates (or creates) a note. On update it emits
	// notifications/resources/updated for the note's URI (delivered only to
	// subscribers). The first time an id is created it also registers a direct
	// resource for that note and emits notifications/resources/list_changed.
	auto setNote = Tool("set_note", Nullable!string.init,
		nullable("Set a note's body; pushes resources/updated to subscribers."));
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	Json idProp = Json.emptyObject;
	idProp["type"] = "string";
	Json bodyProp = Json.emptyObject;
	bodyProp["type"] = "string";
	props["id"] = idProp;
	props["body"] = bodyProp;
	schema["properties"] = props;
	Json req = Json.emptyArray;
	req ~= Json("id");
	req ~= Json("body");
	schema["required"] = req;
	setNote.inputSchema = schema;

	server.registerDynamicTool(setNote, (Json args) @safe {
		const id = args["id"].get!string;
		const body_ = args["body"].get!string;
		const uri = "note:///" ~ id;
		const isNew = (id !in notes);
		notes[id] = body_;

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
	});

	runStreamableHttp(server, port);
}
