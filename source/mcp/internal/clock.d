/// Wall-clock helpers shared by the server runtimes.
module mcp.internal.clock;

@safe:

/// The system clock as an ISO-8601 UTC timestamp, the default for the runtimes'
/// injectable `nowIso` clocks.
string systemNowIso() @safe
{
	import std.datetime.systime : Clock;

	return () @trusted { return Clock.currTime().toUTC().toISOExtString(); }();
}
