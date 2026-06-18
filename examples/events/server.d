/**
 * MCP Events example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates the SDK's typed event builder for the
 * `io.modelcontextprotocol/events` extension. A client subscribes to a declared
 * event type and receives occurrences over poll, push, or webhook delivery; the
 * model only sees arriving events. `enableEvents()` returns an `EventsRuntime`
 * the author uses to `define!(A, P)(...)` a strongly-typed event type and
 * `publish` typed payloads.
 *
 * One push-source event type plus a tool that raises it:
 *
 *   incident.created — defined with `rt.define!(IncidentArgs, Incident)(...)`. Its
 *   upstream is push-only with no addressable history, so it has no fetch handler:
 *   the SDK serves `events/poll` from an in-memory ring buffer fed by `publish`,
 *   and fans live occurrences out to push streams (and webhook subscribers). A
 *   `match` filter scopes delivery per subscription's `severity` argument.
 *
 *   raise_incident — an ordinary `@tool` that calls the handle's `publish(...)`,
 *   so the client can deterministically trigger an occurrence in the e2e test.
 *
 * Webhook delivery is driven end-to-end too: the spec forbids webhook on
 * unauthenticated servers, so this demo uses a fixed "fake auth" principal
 * (`EventsOptions.assumePrincipal`) — appropriate for a single-tenant/dev server
 * that authenticates outside the SDK — and `allowPrivateCallbackHosts` so a
 * localhost receiver (over plain http) is reachable. The client runs a
 * `WebhookReceiver` HTTP listener, subscribes pointing at it, and the server
 * signs + POSTs occurrences to it (verifying the endpoint first).
 *
 * Transport selection is delegated to `runServerFromArgs`:
 *   stdio (default):  ./events-server
 *   http:             ./events-server --http --port 8646
 */
module events_server;

import mcp;
import examples_common : runServerFromArgs;

/// The fixed HTTP port for this example.
enum ushort defaultPort = 8646;

/// Strongly-typed subscription arguments (the filter) and payload for the
/// `incident.created` event type. `IncidentArgs` derives the inputSchema,
/// `Incident` derives the payloadSchema.
struct IncidentArgs
{
	string severity;
}

struct Incident
{
	string id;
	string severity;
	string title;
}

/// The tool that raises incidents. It holds the typed event handle and `publish`es
/// — `incident.created` is a push source, so it uses the builder, not `@event`
/// (which is for pull/fetch types).
final class EventsApi
{
	private EventHandle!(IncidentArgs, Incident) incidents_;

	this(EventHandle!(IncidentArgs, Incident) incidents) @safe
	{
		incidents_ = incidents;
	}

	/// Raise an incident, publishing a typed `Incident`. The SDK marshals it,
	/// stamps the eventId/timestamp, assigns the cursor, and fans it out to
	/// node-local stream/poll subscribers + the webhook delivery queue.
	@tool("raise_incident", "Raise an incident, emitting an incident.created event.")
	string raiseIncident(string severity) @safe
	{
		incidents_.publish(Incident("INC-" ~ severity, severity, "incident " ~ severity));
		return "raised " ~ severity;
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("events-example", "1.0.0");

	// Enable the Events extension. The in-memory webhook store + emit buffer are
	// fine for a single-node demo. `allowPrivateCallbackHosts` lets a localhost
	// webhook receiver be used here; a real deployment leaves it off so the SSRF
	// guard rejects non-globally-routable callback URLs.
	EventsOptions opts;
	opts.allowPrivateCallbackHosts = true;
	// Fake single-tenant auth: treat every caller as this fixed principal so
	// webhook subscribe is permitted (the spec forbids webhook without one). A
	// real multi-tenant server uses genuine auth so the subscription key isolates
	// tenants.
	opts.assumePrincipal = "events-demo-user";
	auto rt = server.enableEvents(null, opts);

	// Define the strongly-typed event type (a push source -> typed builder +
	// publish). `match` filters delivery per subscription's `severity` argument.
	auto incidents = rt.define!(IncidentArgs, Incident)("incident.created",
			"Fires when a new incident is raised")
		.match((IncidentArgs a, Incident i) @safe => a.severity.length == 0
				|| i.severity == a.severity);

	registerHandlers(server, new EventsApi(incidents));

	runServerFromArgs(server, args, defaultPort);
}
