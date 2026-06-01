/**
 * examples/sampling — server.d
 *
 * Demonstrates the SERVER side of MCP **Sampling** (issue #354) in the
 * ergonomic UDA style. The server exposes annotated `@tool` methods on a class
 * (registered in one `registerHandlers` call); inside a tool it turns around
 * and asks the *client* for an LLM completion via `RequestContext.sample`
 * (`sampling/createMessage`).
 *
 * This is the inverted MCP direction: normally the client drives the server,
 * but sampling lets a server borrow the client's model. The server never holds
 * an API key — it builds a typed `CreateMessageRequest` (system prompt + a user
 * message), calls `ctx.sample(req)`, and reads the typed `CreateMessageResult`
 * the client returns. The matching `client.d` supplies a deterministic mock
 * model via its `onSampling` handler so the round-trip is fully reproducible.
 *
 * Two tools:
 *
 *   `summarize` — asks the client's model to summarize a block of text. Builds a
 *     `CreateMessageRequest` with a system prompt and one user message, calls
 *     `ctx.sample`, and returns `{summary, model, stopReason}` from the reply.
 *     The structured result lets the client assert the mock value flowed all the
 *     way through the server→client→server hop.
 *
 *   `model_name` — asks the client (via a trivial 1-token sample) which model it
 *     used and returns just `{model}`. Shows that even a tiny request carries the
 *     client's `model` identifier back to the server.
 *
 * DUAL-TRANSPORT: one binary, EITHER transport. The MCP stdio transport is
 * bidirectional, so the server→client sampling hop works over stdio just as it
 * does over Streamable HTTP (the HTTP keep-alive deadlock that used to bite this
 * path was fixed in #377):
 *
 *   dub build -c server
 *   ./sampling-server                      # default: stdio (JSON-RPC on stdin/stdout)
 *   ./sampling-server --http --port 9354   # Streamable HTTP on http://127.0.0.1:9354/mcp
 *
 * The bundled client.d drives this binary over EITHER transport: with no flags
 * it spawns this server over stdio; with `--http <url>` it connects to a running
 * `--http` instance. The same assertions verify the sampling hop both ways.
 */
module sampling_server;

import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;
import mcp.transport.stdio : runStdio;

enum ushort defaultPort = 9354;

void main(string[] args)
{
	bool http;
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args,
			"http", "Serve over Streamable HTTP instead of stdio", &http,
			"port|p", "Port to listen on when --http (default 9354)", &port,
			"host|h", "Address to bind when --http (default 127.0.0.1)", &host);

	auto server = new McpServer("sampling-example", "1.0.0",
			nullable("Server-initiated LLM sampling demo (stdio or Streamable HTTP)."));

	// Register every @tool method on the API object in one call.
	registerHandlers(server, new SamplingApi);

	if (http)
	{
		StreamableHttpOptions opts;
		opts.bindAddresses = [host];
		() @trusted {
			stderr.writefln("sampling-server listening on http://%s:%d/mcp", host, port);
		}();
		runStreamableHttp(server, port, opts);
	}
	else
	{
		// Default: stdio. The matching client.d spawns this very binary and drives
		// it end-to-end over the bidirectional stdio channel.
		runStdio(server);
	}
}

/// `summarize` structured result: the model's `summary`, the `model` identifier
/// the client used, and the `stopReason` it reported. Returned from the `@tool`
/// method, so the SDK infers the output JSON Schema and emits it as
/// `structuredContent`.
struct SummaryResult
{
	string summary;
	string model;
	string stopReason;
}

/// `model_name` structured result: just the model the client used.
struct ModelResult
{
	string model;
}

/// The annotated MCP tool surface for this example. Each tool takes a
/// `RequestContext ctx` so it can call back into the client for sampling.
final class SamplingApi
{
	/// `summarize`: ask the client's model to summarize `text`.
	///
	/// Builds a typed `CreateMessageRequest` (a system prompt steering the model
	/// to be terse + one user message carrying the text via `Content.makeText`),
	/// sends it with `ctx.sample`, and surfaces the reply's first text block as
	/// `summary` alongside the `model`/`stopReason` the client reported.
	@tool("summarize", "Summarize a block of text by asking the client's LLM (sampling/createMessage).")
	SummaryResult summarize(
			@describe("the text to summarize") string text,
			RequestContext ctx) @safe
	{
		CreateMessageRequest req;
		req.systemPrompt = nullable(
				"You are a terse summarizer. Reply with a single short sentence.");
		req.messages = [
			SamplingMessage("user",
				Content.makeText("Summarize the following text:\n\n" ~ text))
		];
		req.maxTokens = nullable(200L);
		req.temperature = nullable(0.0);

		// The bidirectional hop: this blocks until the client's onSampling handler
		// answers. Works over both stdio and Streamable HTTP (#377 fixed the HTTP
		// keep-alive deadlock).
		CreateMessageResult reply = ctx.sample(req);

		return SummaryResult(reply.content.text, reply.model, reply.stopReason);
	}

	/// `model_name`: a minimal sample whose only purpose is to report which model
	/// the client used. Demonstrates that `CreateMessageResult.model` flows back
	/// to the server even for a trivial request.
	@tool("model_name", "Report which model the client used, via a 1-token sampling request.")
	ModelResult modelName(RequestContext ctx) @safe
	{
		CreateMessageRequest req;
		req.messages = [SamplingMessage("user", Content.makeText("ping"))];
		req.maxTokens = nullable(1L);

		CreateMessageResult reply = ctx.sample(req);
		return ModelResult(reply.model);
	}
}
