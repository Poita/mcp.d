module mcp.server.skill_index;

import vibe.data.json : Json;

@safe:

/// Mutable state backing a server's skills (the `io.modelcontextprotocol/skills`
/// extension). A neutral data holder living in the server package so
/// `McpServer` can own one without depending on the `mcp.api.skills` helper
/// layer; all skills semantics live in `mcp.api.skills`, which adds entries
/// here, while the server's `skills/list` and `skills/get` handlers read them.
///
/// Each entry is one already-built skill entry per the extension: the
/// `SKILL.md` resource `uri`, a verbatim `frontmatter` object, and either the
/// complete per-file `resources` manifest of `{uri, digest, size}` entries or
/// the string `"dynamic"` for a skill whose content is generated on demand.
final class SkillIndex
{
	/// Skill entries keyed by their `SKILL.md` resource URI — the identity
	/// `skills/get` looks up and duplicate registration checks against.
	Json[string] byUri;

	/// Entry URIs in registration order: the stable order `skills/list` pages
	/// over.
	string[] order;

	/// Whether the skills extension has been enabled on the owning server, so
	/// repeated `enableSkills` / `registerSkill` calls configure it at most once.
	bool enabled;
}
