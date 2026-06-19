/**
 * MCP Events example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `events-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `events-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Exercises the `io.modelcontextprotocol/events` extension end-to-end:
 *
 *   1. server/discover advertises the events extension under `capabilities`.
 *   2. events/list declares `incident.created` with its delivery modes.
 *   3. POLL: bootstrap a cursor, raise an incident via a tool, then `events/poll`
 *      with the cursor drains the occurrence.
 *   4. PUSH: open an `events/stream`, raise an incident, and receive the
 *      occurrence as a `notifications/events/event` (routed by the stream id).
 *   5. WEBHOOK: the client runs a `WebhookReceiver` HTTP listener, subscribes
 *      pointing at it, and the server verifies the endpoint (challenge handshake)
 *      then signs + POSTs the occurrence — driven end-to-end on both transports.
 *      (The server uses a fixed "fake auth" principal so webhook subscribe is
 *      permitted; the spec forbids webhook on unauthenticated servers.)
 *
 * Events is draft-only, so the client switches to the draft protocol
 * (`enableModern`) before negotiation.
 */
module events_client;

import std.stdio : writeln;

import core.time : msecs;
import std.conv : to;
import vibe.core.core : sleep;
import vibe.data.json : Json, parseJsonString;
import vibe.http.server : listenHTTP, HTTPListener, HTTPServerSettings,
	HTTPServerRequest, HTTPServerResponse;
import vibe.stream.operations : readAllUTF8;

import mcp;
import examples_common : check, checkEq, runClient, connectFromArgs;

/// The loopback port the client's webhook receiver listens on.
enum ushort receiverPort = 8647;

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "events-server");
		scope (exit)
			client.close();

		// Events is draft-only: switch to the draft protocol before negotiation.
		client.enableModern();

		// --- 1. server/discover advertises the events extension --------------
		auto disc = client.discover();
		checkEq(disc.serverInfo.name, "events-example", "discover.serverInfo.name");
		auto caps = disc.capabilities.toJson();
		check("extensions" in caps && (eventsExtensionKey in caps["extensions"]) !is null,
			"discover capabilities.extensions should contain the events extension key");

		client.connect();
		check(client.eventsSupported(), "client.eventsSupported() should be true");

		// --- 2. events/list declares incident.created -----------------------
		auto list = client.listEvents();
		check(list.events.length >= 1, "events/list should declare at least one type");
		bool foundIncident;
		foreach (e; list.events)
			if (e.name == "incident.created")
			{
				foundIncident = true;
				check(e.delivery.length >= 1, "incident.created should advertise delivery modes");
			}
		check(foundIncident, "events/list should include incident.created");

		// --- 3. POLL: bootstrap, raise, then drain the occurrence ------------
		{
			auto boot = client.pollEvents("incident.created");
			check(boot.events.length == 0, "bootstrap poll returns no events");
			auto cursor = boot.cursor;

			client.callTool("raise_incident", Json(["severity": Json("P1")]));

			auto polled = client.pollEvents("incident.created", Json.emptyObject, cursor);
			check(polled.events.length >= 1, "poll after raise should drain the incident");
			checkEq(polled.events[0].data["severity"].get!string, "P1",
				"polled incident severity");
		}

		// --- 4. PUSH: stream, raise, receive notifications/events/event ------
		{
			string lastEventSeverity;
			int eventCount;
			// Occurrences and control frames arrive on this stream's own handlers,
			// already typed — no global onNotification, no manual subscriptionId
			// routing.
			auto stream = client.streamEvents("incident.created",
				(EventOccurrence occ) @safe {
					eventCount++;
					if ("severity" in occ.data)
						lastEventSeverity = occ.data["severity"].get!string;
				});
			scope (exit)
				stream.close();

			client.callTool("raise_incident", Json(["severity": Json("P2")]));

			// Wait (bounded) for the pushed occurrence to arrive on the stream.
			foreach (_; 0 .. 200)
			{
				if (eventCount >= 1)
					break;
				sleep(25.msecs);
			}
			check(eventCount >= 1, "push stream should deliver the raised incident");
			checkEq(lastEventSeverity, "P2", "pushed incident severity");
		}

		// --- 5. WEBHOOK: server signs + POSTs the occurrence to our receiver --
		// The webhook delivery channel (server -> the receiver, over loopback
		// http) is independent of the MCP transport, so this works over both
		// stdio and HTTP. The server verifies the endpoint (challenge handshake)
		// before its first delivery; our receiver echoes the nonce, then routes
		// the signed event.
		{
			auto secret = generateWhsecSecret();
			auto rx = new WebhookReceiver();
			bool delivered;
			string deliveredSeverity;

			// Run the receiver as a loopback HTTP listener the server can POST to.
			HTTPListener listener;
			() @trusted {
				auto settings = new HTTPServerSettings;
				settings.port = receiverPort;
				settings.bindAddresses = ["127.0.0.1"];
				listener = listenHTTP(settings, (scope HTTPServerRequest req,
					scope HTTPServerResponse res) {
					// Copy the Standard Webhooks + routing headers the receiver needs.
					string[string] hdrs;
					foreach (name; [
						"webhook-id", "webhook-timestamp", "webhook-signature",
						"X-MCP-Subscription-Id"
					])
					{
						auto v = req.headers.get(name, "");
						if (v.length)
							hdrs[name] = v;
					}
					auto resp = rx.processDelivery(req.bodyReader.readAllUTF8(), hdrs);
					res.statusCode = resp.status;
					res.writeBody(resp.body, "application/json");
				});
			}();
			scope (exit)
				() @trusted { listener.stopListening(); }();

			rx.register("placeholder", secret, (EventOccurrence occ) @safe {
				delivered = true;
				if ("severity" in occ.data)
					deliveredSeverity = occ.data["severity"].get!string;
			});

			// Subscribe, pointing the callback at our receiver. The server returns
			// the derived subscription id (carried in X-MCP-Subscription-Id on every
			// delivery); re-register the receiver under it.
			SubscribeParams sp;
			sp.name = "incident.created";
			sp.arguments = Json(["severity": Json("P3")]);
			sp.delivery = WebhookDelivery("http://127.0.0.1:" ~ to!string(receiverPort) ~ "/hooks",
				secret);
			auto sub = client.subscribeWebhookEvents(sp);
			check(sub.id.length > 0, "events/subscribe should return a subscription id");
			rx.unregister("placeholder");
			rx.register(sub.id, secret, (EventOccurrence occ) @safe {
				delivered = true;
				if ("severity" in occ.data)
					deliveredSeverity = occ.data["severity"].get!string;
			});

			client.callTool("raise_incident", Json(["severity": Json("P3")]));

			// Wait (bounded) for the server's verification + signed delivery.
			foreach (_; 0 .. 400)
			{
				if (delivered)
					break;
				sleep(25.msecs);
			}
			check(delivered, "server should deliver the incident to the webhook receiver");
			checkEq(deliveredSeverity, "P3", "delivered webhook incident severity");

			client.unsubscribeWebhookEvents("incident.created", sp.arguments, sp.delivery.url);
		}

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: events example e2e passed over ", http ? "http" : "stdio",
			" — events extension advertised, incident.created listed,",
			" poll drained the incident (P1), push delivered it (P2),",
			" webhook signed+verified delivery to the receiver (P3).");
		return 0;
	});
}
