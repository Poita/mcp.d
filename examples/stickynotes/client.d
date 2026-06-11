/**
 * examples/stickynotes — client.d (dual-transport, self-verifying e2e test)
 *
 * Drives the stateful sticky-notes server end to end and ASSERTS every step, so
 * CI can run it as a regression test over BOTH stdio and Streamable HTTP. It
 * exercises the full triad the example is about: tools that mutate state, the
 * per-note resources that reflect that state, and the blocking elicitation that
 * guards the destructive `remove_all`.
 *
 * Unlike the elicitation example (independent one-shot scenarios), the sticky
 * board is STATEFUL, so the main flow runs on a SINGLE connection: add notes,
 * list/read their resources, remove one, then attempt `remove_all` while
 * swapping the client's `onElicitation` answer (cancel / unchecked / confirm) to
 * prove the board is only cleared on an explicit confirmation. A final, separate
 * connection checks that a client which does NOT support elicitation makes
 * `remove_all` fail rather than silently deleting everything.
 *
 * Two-step run (see README):
 *   stdio:  dub run -c client                                   # spawns the server
 *   http:   dub run -c server -- --http --port 8537   (term 1)
 *           dub run -c client -- --http http://127.0.0.1:8537/mcp  (term 2)
 *
 * What it verifies, in order, on whichever transport is selected:
 *   A. DISCOVERY — tools add_note/remove_note/remove_all exist (with ctx omitted
 *      from remove_all's schema), and the server advertises resources.listChanged.
 *   B. ADD — two add_note calls return distinct ids/URIs and make resources/list
 *      grow to two note:/// resources; resources/read returns the note text.
 *   C. REMOVE ONE — remove_note drops exactly that note's resource; removing an
 *      unknown id returns removed:false (not an error).
 *   D. CANCEL — remove_all with an onElicitation that cancels leaves the board.
 *   E. UNCHECKED — remove_all accepted but with confirm:false leaves the board.
 *   F. CONFIRM — remove_all accepted with confirm:true clears the board, and
 *      resources/list goes empty; a follow-up remove_all returns status:"empty".
 *   G. UNSUPPORTED — a fresh client with NO onElicitation handler makes
 *      remove_all fail (the server refuses to elicit a non-elicitation client).
 */
module stickynotes_client;

import std.algorithm : canFind, count, map;
import std.array : array;
import std.stdio : writeln;

import vibe.data.json : Json;

import mcp;
import examples_common : check, checkEq, runClient, connectFromArgs;
import mcp.protocol.errors : McpException;

/// Mirrors the server's `AddNoteResult` for typed decoding via structuredContentAs.
struct AddNoteResult
{
	string id;
	string uri;
}

/// Mirrors the server's `RemoveNoteResult`.
struct RemoveNoteResult
{
	bool removed;
	string id;
}

/// Mirrors the server's `RemoveAllResult`.
struct RemoveAllResult
{
	string status;
	int removed;
}

/// The accept form the client submits for the `remove_all` confirmation: its one
/// `confirm` field matches the server's `ConfirmClear` schema.
struct ConfirmForm
{
	bool confirm;
}

int main(string[] args) @safe
{
	return runClient(() @safe {
		McpClient makeClient() @safe
		{
			return connectFromArgs(args, "stickynotes-server");
		}

		return run(&makeClient);
	});
}

/// The count of `note:///` resources currently advertised by the server.
private size_t noteCount(McpClient client) @safe
{
	return client.listResources().resources.count!(r => r.uri.canFind("note:///"));
}

/// True iff a resource with `uri` is currently advertised.
private bool hasResource(McpClient client, string uri) @safe
{
	return client.listResources().resources.map!(r => r.uri).array.canFind(uri);
}

/// `add_note` arguments as a JSON object (`{ "text": text }`).
private Json addArgs(string text) @safe
{
	Json a = Json.emptyObject;
	a["text"] = text;
	return a;
}

/// `remove_note` arguments as a JSON object (`{ "id": id }`).
private Json removeArgs(string id) @safe
{
	Json a = Json.emptyObject;
	a["id"] = id;
	return a;
}

/// The transport-agnostic e2e body. The main flow uses one stateful connection;
/// the unsupported-elicitation check opens its own.
private int run(McpClient delegate() @safe makeClient) @safe
{
	// ---- A. DISCOVERY -----------------------------------------------------
	auto client = makeClient();
	scope (exit)
		client.close();
	// Install an elicitation handler BEFORE connecting so the client advertises
	// the elicitation capability at negotiation time; the per-scenario handlers
	// below reassign this delegate. Without a handler at connect the server would
	// (correctly) refuse to elicit later.
	client.onElicitation = (ElicitParams p) @safe { return ElicitResult.cancel(); };
	client.connect();
	checkEq(client.serverInfo().name, "stickynotes-example", "server name");
	auto serverCaps = client.serverCapabilities();
	check(!serverCaps.resources.isNull && serverCaps.resources.get.listChanged,
			"server should advertise resources.listChanged");

	auto names = client.listTools().tools.map!(t => t.name).array;
	foreach (n; ["add_note", "remove_note", "remove_all"])
		check(names.canFind(n), "tools/list missing '" ~ n ~ "'");

	auto removeAllTool = client.listTools().tools.byName("remove_all");
	check(!removeAllTool.isNull, "remove_all tool must be listed");
	check(("ctx" in removeAllTool.get.inputSchema["properties"]) is null,
			"remove_all.inputSchema must not expose the injected 'ctx'");

	check(noteCount(client) == 0, "a fresh board should have no note resources");

	// ---- B. ADD -----------------------------------------------------------
	auto first = client.callTool("add_note", addArgs("Buy milk"));
	check(!first.isError, "add_note should succeed");
	auto firstNote = first.structuredContentAs!AddNoteResult;
	check(firstNote.uri.canFind("note:///"), "add_note uri should be a note:/// URI");

	auto second = client.callTool("add_note", addArgs("Walk the dog"));
	auto secondNote = second.structuredContentAs!AddNoteResult;
	check(firstNote.id != secondNote.id, "each note should get a distinct id");

	checkEq(noteCount(client), cast(size_t) 2, "two notes should be listed after two adds");
	check(hasResource(client, firstNote.uri), "first note's resource should be listed");

	auto read = client.readResource(firstNote.uri);
	check(read.contents.length && read.contents[0].text == "Buy milk",
			"reading the first note should return its text");

	// ---- C. REMOVE ONE ----------------------------------------------------
	auto removed = client.callTool("remove_note", removeArgs(firstNote.id));
	checkEq(removed.structuredContentAs!RemoveNoteResult.removed, true,
			"remove_note should remove it");
	check(!hasResource(client, firstNote.uri), "removed note's resource should be gone");
	checkEq(noteCount(client), cast(size_t) 1, "one note should remain after removing one");

	auto missing = client.callTool("remove_note", removeArgs("does-not-exist"));
	check(!missing.isError, "removing an unknown id is not an error");
	checkEq(missing.structuredContentAs!RemoveNoteResult.removed, false,
			"removing an unknown id reports removed:false");

	// ---- D. CANCEL (board untouched) --------------------------------------
	client.onElicitation = (ElicitParams p) @safe {
		// The prompt should mention the count and carry the confirm schema.
		check(p.requestedSchema.type == Json.Type.object,
				"remove_all elicitation should send a requestedSchema");
		check(("confirm" in p.requestedSchema["properties"]) !is null,
				"requestedSchema should contain the 'confirm' field");
		return ElicitResult.cancel();
	};
	auto cancelled = client.callTool("remove_all");
	check(!cancelled.isError, "remove_all (cancel) should not be a tool error");
	checkEq(cancelled.structuredContentAs!RemoveAllResult.status, "cancelled", "cancel status");
	checkEq(noteCount(client), cast(size_t) 1, "cancel must leave the board untouched");

	// ---- E. UNCHECKED (accept but confirm:false -> board untouched) -------
	client.onElicitation = (ElicitParams p) @safe {
		return ElicitResult.accept(ConfirmForm(false));
	};
	auto unchecked = client.callTool("remove_all");
	checkEq(unchecked.structuredContentAs!RemoveAllResult.status, "declined",
			"accept with confirm:false should decline the clear");
	checkEq(noteCount(client), cast(size_t) 1, "an unchecked confirm must leave the board");

	// ---- F. CONFIRM (accept + confirm:true -> board cleared) --------------
	client.onElicitation = (ElicitParams p) @safe {
		return ElicitResult.accept(ConfirmForm(true));
	};
	auto cleared = client.callTool("remove_all");
	auto clearedResult = cleared.structuredContentAs!RemoveAllResult;
	checkEq(clearedResult.status, "cleared", "confirmed remove_all should clear");
	checkEq(clearedResult.removed, 1, "one remaining note should have been cleared");
	checkEq(noteCount(client), cast(size_t) 0, "the board should be empty after a confirmed clear");

	auto empty = client.callTool("remove_all");
	checkEq(empty.structuredContentAs!RemoveAllResult.status, "empty",
			"remove_all on an empty board should report 'empty' without eliciting");

	// ---- G. UNSUPPORTED (no onElicitation -> remove_all fails) ------------
	{
		auto plain = makeClient();
		scope (exit)
			plain.close();
		plain.connect();
		// Add a note so remove_all actually tries to elicit (an empty board would
		// short-circuit to "empty" before any elicitation).
		plain.callTool("add_note", addArgs("To be confirmed"));

		bool failed;
		try
			failed = plain.callTool("remove_all").isError;
		catch (McpException)
			failed = true;
		check(failed, "remove_all should fail when the client does not support elicitation");
	}

	writeln("OK: stickynotes example e2e passed — add/remove tools mutate the board, ",
			"a resource per note tracks it via resources/list+read, and remove_all only ",
			"clears after a confirmed ctx.elicit (cancel/unchecked/unsupported all spare the board).");
	return 0;
}
