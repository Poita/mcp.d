/**
 * MCP Skills example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates the SDK's ergonomic `@skill` UDA for SEP-2640 (the
 * `io.modelcontextprotocol/skills` extension). A skill is an Agent Skill — a
 * `SKILL.md` of instructions plus optional supporting files — served over the
 * existing Resources primitive: SEP-2640 adds no new protocol methods. A
 * `@skill` method returns the `SKILL.md` body; `registerHandlers` synthesizes
 * the YAML frontmatter from the UDA's name/description, serves it at
 * `skill://<name>/SKILL.md` as `text/markdown`, advertises the extension, and
 * lists the skill in the well-known `skill://index.json` discovery resource.
 *
 * Two `@skill` methods plus one imperative `registerSkill` (with a supporting
 * file) cover the surface:
 *
 *   git-workflow — a plain skill: its method returns the Markdown instructions.
 *   code-review  — a second plain skill, so the index lists more than one.
 *   pdf-forms    — registered imperatively with a sibling `references/FORMS.md`
 *                  file, showing a multi-file skill (served at
 *                  `skill://pdf-forms/references/FORMS.md`).
 *
 * Transport selection is delegated to `runServerFromArgs`:
 *   stdio (default):  ./skills-server
 *   http:             ./skills-server --http --port 8645
 */
module skills_server;

import mcp;
import examples_common : runServerFromArgs;

/// The fixed HTTP port for this example.
enum ushort defaultPort = 8645;

/// Two skills declared the ergonomic way: each `@skill` method returns the
/// `SKILL.md` instructions body; the frontmatter, the `skill://` resource, the
/// extension advertisement, and the index entry are all derived for you.
final class SkillsApi
{
	@skill("git-workflow", "Follow this team's Git branching and commit conventions")
	string gitWorkflow() @safe
	{
		return "# Git Workflow\n\n"
			~ "1. Branch from `main`: `git switch -c feature/<topic>`.\n"
			~ "2. Commit in small, reviewable steps.\n"
			~ "3. Open a PR; squash-merge once approved.\n";
	}

	@skill("code-review", "Review a change for correctness, clarity, and test coverage")
	string codeReview() @safe
	{
		return "# Code Review\n\n"
			~ "- Confirm the change has a test that fails without it.\n"
			~ "- Check error paths, not just the happy path.\n"
			~ "- Prefer the smallest change that is correct and clear.\n";
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("skills-example", "1.0.0");

	// Register the two @skill methods — no per-skill wiring. The first
	// registration also advertises the skills extension and stands up the
	// skill://index.json discovery resource.
	registerHandlers(server, new SkillsApi);

	// A multi-file skill registered imperatively: the SKILL.md plus a sibling
	// reference document served at skill://pdf-forms/references/FORMS.md.
	Skill pdf = {
		name: "pdf-forms",
		description: "Fill in PDF forms using the field reference",
		instructions: "# PDF Forms\n\nConsult `references/FORMS.md` for field names, "
			~ "then fill each field by its exact label.\n",
		files: [
			SkillFile("references/FORMS.md", "text/markdown",
					"# Form Fields\n\n- `applicant_name`\n- `date_of_birth`\n- `signature`\n")
		]
	};
	registerSkill(server, pdf);

	runServerFromArgs(server, args, defaultPort);
}
