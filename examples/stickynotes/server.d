/**
 * examples/stickynotes — server.d (stateful, dual-transport)
 *
 * A small STATEFUL MCP server that ties together the three feature areas a
 * real server usually combines: tools that mutate state, a resource per piece
 * of state, and a server->client elicitation for confirming a destructive
 * action.
 *
 * The server keeps an in-memory board of sticky notes (id -> text). Each note
 * is exposed as its own direct resource at `note:///{id}`, so the live note set
 * is browsable via `resources/list` and each note is readable via
 * `resources/read`. The set is dynamic: tools register and unregister note
 * resources at runtime and emit `notifications/resources/list_changed` so a
 * connected client knows to re-list.
 *
 * Tools:
 *   - `add_note(text)`     — create a note, register its `note:///{id}` resource,
 *                            announce the list change; returns the new id + uri.
 *   - `remove_note(id)`    — delete one note and unregister its resource.
 *   - `remove_all()`       — delete EVERY note, but first BLOCK on a typed
 *                            server->client elicitation (`ctx.elicit!ConfirmClear`)
 *                            so the user must confirm before anything is removed.
 *                            Declining/cancelling (or unchecking the box) leaves
 *                            the board untouched.
 *
 * Why stateful: a server->client elicitation is a request issued back to the
 * client mid-handler, which over Streamable HTTP needs a session to correlate
 * the reply — so the server runs in `McpServer.stateful` mode (which also works
 * over stdio as a single implicit session).
 *
 * One binary, either transport (selected by the shared `examples_common`
 * scaffold from argv):
 *   stdio (default): dub run -c server
 *   http:            dub run -c server -- --http --port 8537
 */
module stickynotes_server;

import std.conv : to;
import std.typecons : nullable;

import mcp;
import mcp.api.attributes : title;
import mcp.api.reflection : registerHandlers;
import examples_common : runServerFromArgs;

/// The fixed HTTP port this example binds, kept in one place so server.d,
/// client.d and the README agree.
enum ushort defaultPort = 8537;

/// Result of `add_note`: the assigned id and the resource URI now serving it.
/// Returning a struct lets the reflection layer derive the tool's `outputSchema`
/// and per-call `structuredContent` — no hand-built Json.
struct AddNoteResult
{
	string id; /// the new note's id
	string uri; /// the `note:///{id}` resource URI now registered
}

/// Result of `remove_note`: whether a note with that id existed and was removed.
struct RemoveNoteResult
{
	bool removed; /// true iff a note with `id` was present and is now gone
	string id; /// the id that was requested
}

/// Result of `remove_all`: the outcome of the confirmed clear.
struct RemoveAllResult
{
	/// "cleared" (user confirmed), "declined" (user said no / unchecked the box),
	/// "cancelled" (user dismissed the prompt), or "empty" (nothing to clear).
	string status;
	int removed; /// how many notes were deleted (0 unless status == "cleared")
}

/// The elicitation form `remove_all` sends to the client: a single required
/// boolean the user must set to actually proceed. `jsonSchemaOf!ConfirmClear`
/// derives the whole `requestedSchema` (an object with one required boolean and
/// a display title) — no hand-built schema Json.
struct ConfirmClear
{
	/// required: the user must check this for the clear to go ahead.
	@title("Yes, permanently delete every sticky note") bool confirm;
}

/// The annotated tool surface plus the note board. The class holds the server
/// reference so the tools can register/unregister note resources and announce
/// list changes at runtime.
final class StickyNotesApi
{
	private McpServer server;
	/// The board: note id -> note text. The per-note resource readers and the
	/// tools all read/write this.
	private string[string] notes;
	/// Monotonic id source so each note gets a stable, unique `note:///{id}`.
	private int nextId = 1;

	this(McpServer server) @safe
	{
		this.server = server;
	}

	/// The resource URI that serves the note with `id`.
	private static string uriFor(string id) @safe
	{
		return "note:///" ~ id;
	}

	/// `add_note`: store the text under a fresh id, register a direct resource
	/// that reads the note back, and announce the new resource via
	/// `notifications/resources/list_changed`.
	@tool("add_note", "Add a sticky note; registers a note:///{id} resource for it.")
	@describeParam("text", "the note text")
	AddNoteResult addNote(string text) @safe
	{
		const id = (nextId++).to!string;
		const uri = uriFor(id);
		notes[id] = text;

		auto r = Resource(uri, "Sticky note #" ~ id);
		r.mimeType = nullable("text/plain");
		// The reader reads the live board, guarding against a removed id (the
		// resource is unregistered on removal, so this is belt-and-braces).
		server.registerResource(r, () @safe {
			const noteText = (id in notes) ? notes[id] : "(note removed)";
			return ResourceContents.makeText(uri, "text/plain", noteText);
		});
		server.notifyResourcesListChanged();

		return AddNoteResult(id, uri);
	}

	/// `remove_note`: delete one note and unregister its resource, announcing the
	/// list change. Returns `removed:false` (not an error) for an unknown id.
	@tool("remove_note", "Remove one sticky note by id and unregister its resource.")
	@describeParam("id", "the id of the note to remove")
	RemoveNoteResult removeNote(string id) @safe
	{
		if (id !in notes)
			return RemoveNoteResult(false, id);

		notes.remove(id);
		server.removeResource(uriFor(id));
		server.notifyResourcesListChanged();
		return RemoveNoteResult(true, id);
	}

	/// `remove_all`: clear the whole board — but only after the user confirms via
	/// a BLOCKING server->client elicitation. The handler refuses to delete
	/// anything unless the client `accept`s the prompt with `confirm == true`;
	/// decline/cancel/unchecked all leave every note in place.
	@tool("remove_all",
			"Remove ALL sticky notes after confirming via a server->client elicitation.")
	RemoveAllResult removeAll(RequestContext ctx) @safe
	{
		if (notes.length == 0)
			return RemoveAllResult("empty", 0);

		const count = cast(int) notes.length;
		ElicitResult result = ctx.elicit!ConfirmClear(
				"Remove all " ~ count.to!string ~ " sticky note(s)? This cannot be undone.");

		final switch (result.action)
		{
		case ElicitAction.decline:
			return RemoveAllResult("declined", 0);
		case ElicitAction.cancel:
			return RemoveAllResult("cancelled", 0);
		case ElicitAction.accept:
			break;
		}

		// Accepted — but the destructive action still requires the explicit box.
		if (!result.contentAs!ConfirmClear.confirm)
			return RemoveAllResult("declined", 0);

		// Confirmed: drop every note and unregister every note resource, then
		// announce the (now empty) set once.
		foreach (id; notes.keys)
			server.removeResource(uriFor(id));
		notes.clear();
		server.notifyResourcesListChanged();
		return RemoveAllResult("cleared", count);
	}
}

void main(string[] args) @safe
{
	// Stateful so the `remove_all` elicitation (a server->client request) can be
	// correlated over Streamable HTTP; this also works over stdio as a single
	// implicit session.
	auto server = McpServer.stateful("stickynotes-example", "1.0.0",
			nullable("Stateful sticky-notes board: tools + a resource per note + "
				~ "elicitation-confirmed clear (stdio + Streamable HTTP)."));

	registerHandlers(server, new StickyNotesApi(server));

	// The note set changes at runtime, so advertise resources `listChanged` to
	// back the `notifications/resources/list_changed` the tools emit.
	server.enableResourcesListChanged();

	runServerFromArgs(server, args, defaultPort);
}
