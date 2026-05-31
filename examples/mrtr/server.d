/**
 * MRTR (Multi Round-Trip Requests, SEP-2322) example server.
 *
 * Demonstrates the *stateless* draft input flow: instead of opening a
 * server->client `elicitation/create` or `sampling/createMessage` request (which
 * the draft revision has no channel for), a tool that needs more input simply
 * ENDS the current `tools/call` with `ToolResponse.inputRequired(...)`. The
 * client gathers the answers and resubmits a fresh `tools/call` carrying them in
 * `params.inputResponses`, echoing back the opaque `requestState` the server
 * attached. There is no suspension and no shared session state on the server.
 *
 * The `book_meeting` tool below shows both round-trips in one call:
 *   round 1: client calls `book_meeting {topic}`     -> server asks for input
 *            (an `elicitation` for the date + a `sampling` for an agenda),
 *            stashing `topic` into the opaque `requestState`.
 *   round 2: client resubmits with `inputResponses`  -> server reads the answers
 *            + the echoed `requestState` and returns the final confirmation.
 *
 * Run it standalone over Streamable HTTP:
 *   dub build -c server
 *   ./mrtr-server --port 8765
 * then point the client at http://127.0.0.1:8765/mcp (see client.d / README).
 */
module mrtr_server;

import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable;

import vibe.data.json : Json;

import mcp;
import mcp.protocol.draft : InputRequest;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

/// The fixed port the example binds, kept in one place so server.d and client.d
/// (and the README) agree.
enum ushort defaultPort = 8765;

void main(string[] args)
{
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on", &port,
			"host|h", "Address to bind", &host);

	auto server = new McpServer("mrtr-example", "0.1.0",
			nullable("MRTR (multi round-trip) demo server."));
	registerBookMeeting(server);

	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	() @trusted {
		stderr.writefln("mrtr-server listening on http://%s:%d/mcp", host, port);
	}();
	runStreamableHttp(server, port, opts);
}

/// Register the `book_meeting` tool: a stateless MRTR handler that asks for a
/// date (elicitation) and an agenda (sampling) before confirming the booking.
void registerBookMeeting(McpServer server) @safe
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["topic"] = Json(["type": Json("string")]);
	schema["properties"] = props;
	schema["required"] = Json([Json("topic")]);

	Tool descriptor = {
		name: "book_meeting",
		description: nullable(
			"Book a meeting; needs a date (elicitation) and an agenda (sampling)."),
		inputSchema: schema
	};

	// The server-assigned correlation ids for the two input requests. The client
	// echoes these back as the keys of `inputResponses`, so the handler reads its
	// answers by the same ids on the retry.
	enum dateId = "meeting_date";
	enum agendaId = "meeting_agenda";

	server.registerDynamicTool(descriptor, (Json args, RequestContext ctx) @safe {
		const topic = ("topic" in args) ? args["topic"].get!string : "";

		auto answers = ctx.inputResponses();
		const haveAnswers = (dateId in answers) !is null && (agendaId in answers) !is null;

		// Round 1 (no answers yet): ask the client for the date + agenda and stash
		// `topic` into the opaque requestState so we can recover it on the retry.
		if (!haveAnswers)
		{
			InputRequest dateReq;
			dateReq.id = dateId;
			dateReq.type = "elicitation";
			Json dateParams = Json.emptyObject;
			dateParams["message"] = Json("On what date should we meet?");
			Json dateSchema = Json.emptyObject;
			dateSchema["type"] = "object";
			Json dateSchemaProps = Json.emptyObject;
			dateSchemaProps["date"] = Json(["type": Json("string")]);
			dateSchema["properties"] = dateSchemaProps;
			dateParams["requestedSchema"] = dateSchema;
			dateReq.params = dateParams;

			InputRequest agendaReq;
			agendaReq.id = agendaId;
			agendaReq.type = "sampling";
			Json agendaParams = Json.emptyObject;
			Json messages = Json.emptyArray;
			Json m = Json.emptyObject;
			m["role"] = Json("user");
			m["content"] = Content.makeText("Draft a one-line agenda for: " ~ topic).toJson();
			messages ~= m;
			agendaParams["messages"] = messages;
			agendaParams["maxTokens"] = Json(64);
			agendaReq.params = agendaParams;

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

		// The elicitation answer is a bare ElicitResult: {action, content:{date}}.
		auto elicit = ElicitResult.fromJson(answers[dateId]);
		string date = "unspecified";
		if (elicit.content.type == Json.Type.object && "date" in elicit.content)
			date = elicit.content["date"].get!string;

		// The sampling answer is a bare CreateMessageResult: {role, content, ...}.
		auto sample = CreateMessageResult.fromJson(answers[agendaId]);
		const agenda = sample.content().text();

		CallToolResult r;
		r.content = [
			Content.makeText(
				"Booked '" ~ recoveredTopic ~ "' on " ~ date ~ ". Agenda: " ~ agenda)
		];
		Json structured = Json.emptyObject;
		structured["topic"] = Json(recoveredTopic);
		structured["date"] = Json(date);
		structured["agenda"] = Json(agenda);
		structured["rounds"] = Json(2);
		r.structuredContent = structured;
		return ToolResponse.complete(r);
	});
}
