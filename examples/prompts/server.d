/// Prompts + completion example — SERVER.
///
/// Demonstrates the MCP "prompts" surface of the D SDK from the server side:
///
///   * `@prompt`-annotated methods with *typed*, described arguments (registered
///     via the reflection layer `registerHandlers`), each producing a
///     `GetPromptResult` (or a string the SDK wraps into one).
///   * a prompt message carrying an *embedded resource* content block
///     (`Content.makeEmbeddedText`) alongside ordinary text.
///   * `completion/complete` for prompt-argument autocompletion
///     (`setCompletionRequestHandler`), prefix-matching a known-language list.
///
/// Run shape: STDIO. The client (client.d) spawns this built binary and drives
/// it; see README.md.
module prompts_server;

import std.algorithm : startsWith, filter;
import std.array : array;
import std.string : toLower;

import mcp.server.server : McpServer;
import mcp.transport.stdio : runStdio;
import mcp.api.reflection : registerHandlers;
import mcp.api.attributes : prompt, describe;
import mcp.protocol.types : GetPromptResult, PromptMessage, Content,
	CompleteRequest, CompleteResult;
import vibe.data.json : Json;

/// A representative snippet per language, embedded into the `code_review`
/// prompt as a resource content block.
private string sampleSnippet(string language) @safe
{
	switch (language.toLower)
	{
	case "d":
		return "void main() { int x; }";
	case "python":
		return "def main():\n    x = 0";
	case "rust":
		return "fn main() { let x = 0; }";
	default:
		return "// sample " ~ language ~ " code";
	}
}

private string snippetUri(string language) @safe
{
	switch (language.toLower)
	{
	case "d":
		return "snippet://review.d";
	case "python":
		return "snippet://review.py";
	case "rust":
		return "snippet://review.rs";
	default:
		return "snippet://review.txt";
	}
}

private string mimeFor(string language) @safe
{
	switch (language.toLower)
	{
	case "d":
		return "text/x-dlang";
	case "python":
		return "text/x-python";
	case "rust":
		return "text/x-rust";
	default:
		return "text/plain";
	}
}

/// The application object. Each `@prompt` method becomes an MCP prompt.
final class PromptApp
{
	/// A simple prompt with one typed, described argument. Returns plain text,
	/// which the SDK wraps into a single user `PromptMessage`.
	@prompt("greet", "Greet someone by name", "Greeting")
	string greet(@describe("the person to greet") string name) @safe
	{
		return "Please write a warm, one-line greeting for " ~ name ~ ".";
	}

	/// A richer prompt that embeds a resource content block into the message
	/// list, demonstrating `Content.makeEmbeddedText`. The `language` argument is
	/// completed via the completion handler below.
	@prompt("code_review", "Ask the model to review a code snippet", "Code Review")
	GetPromptResult codeReview(
		@describe("programming language to review a sample of") string language) @safe
	{
		GetPromptResult r;
		r.description = "Review request for a " ~ language ~ " snippet";
		r.messages = [
			PromptMessage("user",
				Content.makeText("Review the following " ~ language
					~ " code and list any bugs:")),
			// Embedded-resource content: the snippet travels as a resource block
			// (uri + mimeType + text), not just inline prose.
			PromptMessage("user",
				Content.makeEmbeddedText(
					snippetUri(language),
					mimeFor(language),
					sampleSnippet(language))),
		];
		return r;
	}
}

/// The set of languages the completion handler offers for the `language`
/// argument of the `code_review` prompt.
private immutable string[] knownLanguages =
	["c", "cpp", "d", "go", "java", "javascript", "python", "rust", "typescript"];

void main()
{
	auto server = new McpServer("prompts-example-server", "1.0.0");

	// Register the @prompt methods (typed dispatch + descriptors) by reflection.
	registerHandlers(server, new PromptApp);

	// Prompt-argument autocompletion. Advertising this handler makes the server
	// declare the `completions` capability. We complete the `language` argument
	// of the `code_review` prompt by prefix-matching the partial value.
	server.setCompletionRequestHandler((CompleteRequest request) @safe {
		CompleteResult result;
		if (request.isPrompt && request.reference.name == "code_review")
		{
			const partial = request.argumentValue.toLower;
			string[] matches;
			foreach (l; knownLanguages)
				if (l.startsWith(partial))
					matches ~= l;
			result.values = matches;
			result.total = matches.length;
			result.hasMore = false;
		}
		return result;
	});

	runStdio(server);
}
