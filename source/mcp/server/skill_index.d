module mcp.server.skill_index;

import vibe.data.json : Json;

@safe:

/// Mutable state backing a server's SEP-2640 skills (the
/// `io.modelcontextprotocol/skills` extension). A neutral data holder living in
/// the server package so `McpServer` can own one without depending on the
/// `mcp.api.skills` helper layer; all skills semantics live in `mcp.api.skills`,
/// which appends to `entries` and reads them from the `skill://index.json`
/// resource reader.
///
/// Each entry in `entries` is one already-built discovery-document object
/// (`{name, type, description, url}` for a `skill-md`, or `{type, description,
/// url}` for an `mcp-resource-template`), per the Agent Skills discovery format.
final class SkillIndex
{
	/// Discovery entries, one per registered skill, in registration order.
	Json[] entries;

	/// Whether the `skill://index.json` discovery resource has been registered,
	/// so repeated `enableSkills` / `registerSkill` calls register it at most once.
	bool indexResourceRegistered;
}
