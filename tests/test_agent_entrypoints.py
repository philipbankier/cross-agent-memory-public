"""Git-clone agent discovery files, not runtime-container or live-client acceptance."""

from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
pytestmark = pytest.mark.skipif(
    not (ROOT / ".git").exists(), reason="agent entry points belong to the Git checkout"
)


def test_claude_imports_the_shared_agent_instructions() -> None:
    assert (ROOT / "CLAUDE.md").read_text() == "@AGENTS.md\n"
    assert (ROOT / "AGENTS.md").is_file()


@pytest.mark.parametrize("directory", (".agents", ".claude", ".grok"))
def test_agent_skill_adapter_resolves_to_the_canonical_workflow(directory: str) -> None:
    adapter = ROOT / directory / "skills/cross-agent-memory/SKILL.md"
    canonical = ROOT / "skills/cross-agent-memory/SKILL.md"
    target = "../../../skills/cross-agent-memory/SKILL.md"
    assert canonical.is_file()
    assert (adapter.parent / target).resolve() == canonical.resolve()
    assert adapter.read_text() == (
        "---\nname: cross-agent-memory\n"
        "description: Answer questions about earlier assistant conversations with Cross-Agent "
        "Memory, or set up and extend its installation safely.\n---\n\n"
        f"Read `{target}`, relative to this file, in full and follow\n"
        "that canonical workflow.\n"
    )
