/**
 * MRTR (Multi Round-Trip Requests, SEP-2322) example server — dual transport.
 *
 * Demonstrates the *stateless* draft input flow: instead of opening a
 * server->client `elicitation/create` or `sampling/createMessage` request (which
 * the draft revision has no channel for), a tool that needs more input simply
 * ENDS the current `tools/call` with `ToolResponse.inputRequired(...)`. The
 * client gathers the answers and resubmits a fresh `tools/call` carrying them in
 * `params.inputResponses`, echoing back the opaque `requestState` the server
 * attached. There is no suspension and no shared session state on the server.
 *
 * This is written in the SDK's ergonomic UDA style: `book_meeting` is a plain
 * annotated method that takes a typed `topic` argument (its input JSON Schema is
 * inferred) and an auto-injected `RequestContext`, and returns a `ToolResponse`
 * so it can answer either `inputRequired` (round 1) or `complete` (round 2).
 * `registerHandlers` wires it onto the server -- no hand-built `Json` args,
 * descriptors, or registration calls.
 *
 * Typed APIs (SEP-2322 builders) replace every hand-built MRTR `Json`:
 *   - the elicitation `InputRequest` is built with `InputRequest.elicitation!T`,
 *     which DERIVES its `requestedSchema` from the flat struct `MeetingDate`;
 *   - the sampling `InputRequest` is built with `InputRequest.sampling(id, req)`
 *     from a typed `CreateMessageRequest` (typed `SamplingMessage` + `Content`);
 *   - on the resubmit round the answers are decoded with `ctx.inputResponseAs!T`
 *     (an `ElicitResult` for the date, a `CreateMessageResult` for the agenda);
 *   - the final content uses `Content.makeText` and the structured result is
 *     serialized from a typed `Booking` struct.
 *
 * The `book_meeting` tool below shows both round-trips in one call:
 *   round 1: client calls `book_meeting {topic}`     -> server asks for input
 *            (an `elicitation` for the date + a `sampling` for an agenda),
 *            stashing `topic` into the opaque `requestState`.
 *   round 2: client resubmits with `inputResponses`  -> server reads the answers
 *            + the echoed `requestState` and returns the final confirmation.
 *
 * One binary, either transport:
 *   stdio (default):  ./mrtr-server
 *   Streamable HTTP:  ./mrtr-server --http --port 8765
 * The client (client.d / README) drives either.
 */
module mrtr_server;

import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable, Nullable;

import vibe.data.json : Json, serializeToJson;

import mcp;
import mcp.protocol.draft : InputRequest;
import mcp.protocol.sampling : CreateMessageRequest, SamplingMessage;
import mcp.transport : StreamableHttpOptions, runStreamableHttp, runStdio;

/// The fixed port the example binds for HTTP, kept in one place so server.d and
/// client.d (and the README) agree.
enum ushort defaultPort = 8765;

void main(string[] args)
{
	bool http;
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args,
			"http", "Serve over Streamable HTTP instead of stdio", &http,
			"port|p", "Port to listen on when --http (default 8765)", &port,
			"host|h", "Address to bind when --http (default 127.0.0.1)", &host);

	auto server = new McpServer("mrtr-example", "0.1.0",
			nullable("MRTR (multi round-trip) demo server."));
	// Register every @tool method of the API class in one call; the tool's input
	// schema and argument marshalling are derived from the method signature.
	registerHandlers(server, new MrtrApi);

	if (http)
	{
		StreamableHttpOptions opts;
		opts.bindAddresses = [host];
		() @trusted {
			stderr.writefln("mrtr-server listening on http://%s:%d/mcp", host, port);
		}();
		runStreamableHttp(server, port, opts);
	}
	else
	{
		// stdio: the client spawns this process and speaks newline-delimited
		// JSON-RPC over the pipe. Keep stdout clean for the protocol.
		runStdio(server);
	}
}

/// A flat struct describing the date elicitation form. `InputRequest.elicitation!T`
/// derives its `requestedSchema` from this via `jsonSchemaOf!T`, and the client's
/// answer decodes back into it through `ElicitResult.contentAs!MeetingDate`.
struct MeetingDate
{
	string date;
}

/// The typed structured result of a completed booking. Serialized into the
/// `CallToolResult.structuredContent` so the structured payload is inferred from
/// a struct rather than hand-built field by field.
struct Booking
{
	string topic;
	string date;
	string agenda;
	int rounds;
}

/// The `book_meeting` MRTR tool, expressed as an annotated typed method: a
/// stateless MRTR handler that asks for a date (elicitation) and an agenda
/// (sampling) before confirming the booking.
final class MrtrApi
{
	// The server-assigned correlation ids for the two input requests. The client
	// echoes these back as the keys of `inputResponses`, so the handler reads its
	// answers by the same ids on the retry.
	private enum dateId = "meeting_date";
	private enum agendaId = "meeting_agenda";

	/// Book a meeting. The `topic` argument is typed (so the tool's inputSchema is
	/// inferred and the value is marshalled for us); `ctx` is auto-injected and
	/// omitted from the schema, used to read `inputResponses` / `requestState`.
	/// Returning a `ToolResponse` lets the method answer either `inputRequired`
	/// (round 1) or `complete` (round 2).
	@tool("book_meeting",
			"Book a meeting; needs a date (elicitation) and an agenda (sampling).")
	ToolResponse bookMeeting(string topic, RequestContext ctx) @safe
	{
		auto answers = ctx.inputResponses();
		const haveAnswers = (dateId in answers) !is null && (agendaId in answers) !is null;

		// Round 1 (no answers yet): ask the client for the date + agenda and stash
		// `topic` into the opaque requestState so we can recover it on the retry.
		if (!haveAnswers)
		{
			// Typed elicitation builder: the `requestedSchema` is derived from the
			// flat `MeetingDate` struct via jsonSchemaOf!T — no hand-built schema.
			auto dateReq = InputRequest.elicitation!MeetingDate(
				dateId, "On what date should we meet?");

			// Typed sampling builder: build a CreateMessageRequest from a typed
			// SamplingMessage + Content, then hand it to InputRequest.sampling.
			CreateMessageRequest sreq;
			sreq.messages = [
				SamplingMessage("user",
					Content.makeText("Draft a one-line agenda for: " ~ topic))
			];
			sreq.maxTokens = Nullable!long(64);
			auto agendaReq = InputRequest.sampling(agendaId, sreq);

			// SEP-2322: the opaque, server-owned requestState. The client echoes it
			// verbatim; we recover `topic` from it on the retry instead of trusting
			// the resubmitted arguments.
			return ToolResponse.inputRequired([dateReq, agendaReq], "topic=" ~ topic);
		}

		// Round 2: the client resubmitted with answers. Read the echoed
		// requestState (server-owned, validated as untrusted input) and the two
		// answers, then return the final confirmation.
		const echoed = ctx.requestState();
		string recoveredTopic = topic;
		if (echoed.length > "topic=".length && echoed[0 .. "topic=".length] == "topic=")
			recoveredTopic = echoed["topic=".length .. $];

		// Decode the elicitation answer as a typed ElicitResult; branch on .action
		// and read the date through the typed MeetingDate view of its content.
		auto elicit = ctx.inputResponseAs!ElicitResult(dateId);
		string date = "unspecified";
		if (elicit.action == ElicitAction.accept)
			date = elicit.contentAs!MeetingDate().date;

		// Decode the sampling answer as a typed CreateMessageResult.
		auto sample = ctx.inputResponseAs!CreateMessageResult(agendaId);
		const agenda = sample.content().text();

		// Build the final result with typed Content + a typed structured struct.
		Booking booking;
		booking.topic = recoveredTopic;
		booking.date = date;
		booking.agenda = agenda;
		booking.rounds = 2;

		CallToolResult r;
		r.content = [
			Content.makeText(
				"Booked '" ~ recoveredTopic ~ "' on " ~ date ~ ". Agenda: " ~ agenda)
		];
		r.structuredContent = () @trusted { return serializeToJson(booking); }();
		return ToolResponse.complete(r);
	}
}
