import unittest
from pathlib import Path


class ClaudeSkillsIntegrationTests(unittest.TestCase):
    def test_claude_skill_files_exist(self):
        root = Path("integrations/claude-skills/sbom-security-toolkit")
        self.assertTrue((root / "SKILL.md").exists())
        self.assertTrue((root / "resources/command-reference.md").exists())
        self.assertTrue((root / "resources/safety-rules.md").exists())
        self.assertTrue((root / "resources/workflow-map.md").exists())

    def test_skill_is_review_gated(self):
        text = Path("integrations/claude-skills/sbom-security-toolkit/SKILL.md").read_text()
        self.assertIn("AI suggests; deterministic tooling validates; humans approve", text)
        self.assertIn("Never execute AI-generated code", text)
        self.assertIn("Never decide that a vulnerability is `not_affected`", text)

    def test_agent_prompts_exist(self):
        root = Path("integrations/agent-prompts")
        self.assertTrue((root / "generic-sbom-agent.md").exists())
        self.assertTrue((root / "fuzzing-triage-agent.md").exists())
        self.assertTrue((root / "supplier-intake-agent.md").exists())


if __name__ == "__main__":
    unittest.main()
