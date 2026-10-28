from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import Access, QueryMode, Scope, SourceSystem
from cross_assistant_memory.retrieval import lexical_score
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl


@pytest.mark.parametrize(
    "query",
    ["connect-ssh", "serve-codex-readonly", "memory-client-v2", "memoire-agent"],
)
@pytest.mark.parametrize("prefix", ["Use `", "Run /tools/", "  Use "])
def test_literal_identifier_outranks_disconnected_repeated_tokens(query: str, prefix: str) -> None:
    unrelated = " ".join(token + " " for token in query.split("-")) * 20
    assert lexical_score(query, prefix + query + " once.") > lexical_score(query, unrelated)


@pytest.mark.parametrize("query", ["connect-ssh", "CONNECT-SSH", " connect-ssh "])
def test_identifier_matching_is_case_insensitive_and_trims_query(query: str) -> None:
    assert lexical_score(query, "Use CONNECT-SSH.") > lexical_score(
        query, "connect " * 20 + "ssh " * 20
    )


@pytest.mark.parametrize(
    "content",
    [
        "disconnect-ssh",
        "connect-ssh-extra",
        "extra-connect-ssh",
        "connect-ssh2",
        "connect-ssh_extra",
        "pre_connect-ssh",
        "\u00e9connect-ssh",
        "e\u0301connect-ssh",
        "x\u0301connect-ssh",
        "connect-ssh\u0301",
        "connect-ssh\u093e",
    ],
)
def test_identifier_prefixes_and_suffixes_receive_no_identifier_priority(content: str) -> None:
    assert lexical_score("connect-ssh", content) == _baseline_score("connect-ssh", content)


@pytest.mark.parametrize(
    "query",
    [
        "connect ssh",
        "repair connect-ssh",
        "connect-ssh repair",
        "connect\u2011ssh",
        "ssh",
        "",
        "---",
    ],
)
def test_other_queries_keep_existing_score(query: str) -> None:
    content = "connect-ssh handles connect and ssh, while connect ssh occurs elsewhere."
    assert lexical_score(query, content) == _baseline_score(query, content)


def test_identifier_priority_does_not_consume_tokens_beyond_existing_query_cap() -> None:
    query = "-".join(f"part{index}" for index in range(25))
    assert lexical_score(query, query) == _baseline_score(query, query)


@pytest.mark.parametrize("query", ["\u0130-ssh", "stra\u00dfe-map"])
def test_casefold_expansion_preserves_literal_priority(query: str) -> None:
    unrelated = (" ".join(query.split("-")) + " ") * 20
    assert lexical_score(query, query) > lexical_score(query, unrelated)


def test_invalid_marked_match_does_not_hide_a_later_valid_identifier() -> None:
    content = "e\u0301connect-ssh first, then use connect-ssh."
    assert lexical_score("connect-ssh", content) > _baseline_score("connect-ssh", content)


@pytest.mark.parametrize(
    "parts", [["ssh", "ssh"], ["connect", "ssh"], [f"part{i}" for i in range(24)]]
)
def test_literal_in_long_content_outranks_the_legacy_score_ceiling(parts: list[str]) -> None:
    query = "-".join(parts)
    spam = " ".join(token for token in dict.fromkeys(parts) for _ in range(8))
    content = "unrelated words " * 1000 + query
    ceiling = 9 * len(parts) + 4
    assert lexical_score(query, spam) <= ceiling
    assert lexical_score(query, content) >= ceiling + 1
    assert lexical_score(query, content) > lexical_score(query, spam)


def test_workset_prefers_literal_without_expanding_access_or_matches(tmp_path: Path) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    _ingest(ledger, tmp_path / "literal.jsonl", "Use connect-ssh once.", Scope.USER_GLOBAL)
    _ingest(
        ledger,
        tmp_path / "unrelated.jsonl",
        "connect " * 20 + "ssh " * 20,
        Scope.USER_GLOBAL,
    )
    _ingest(ledger, tmp_path / "hidden.jsonl", "connect-ssh " * 20, Scope.ASSISTANT_PRIVATE)
    _ingest(ledger, tmp_path / "nonmatch.jsonl", "connect only", Scope.USER_GLOBAL)

    workset = ledger.retrieve_workset(
        "connect-ssh",
        mode=QueryMode.FIND_EVIDENCE,
        scopes=(Scope.USER_GLOBAL,),
        accesses=(Access.OWNER,),
        limit=5,
    )

    assert workset["selection"]["candidate_match_count"] == 2
    assert workset["selection"]["candidate_input_count"] == 2
    assert workset["results"][0]["content_text"] == "Use connect-ssh once."
    assert len(workset["results"]) == 2
    assert all(item["scope"] == "user_global" for item in workset["results"])


def _baseline_score(query: str, content: str) -> float:
    query_tokens = [token.casefold() for token in re.findall(r"[^\W]+", query)][:24]
    content_tokens = [token.casefold() for token in re.findall(r"[^\W]+", content)]
    counts = Counter(content_tokens)
    frequency = sum(min(counts[token], 8) for token in query_tokens)
    phrase_bonus = 4 if query_tokens and " ".join(query_tokens) in " ".join(content_tokens) else 0
    return float(phrase_bonus + frequency) + frequency / max(1, len(content_tokens))


def _ingest(ledger: Ledger, path: Path, content: str, scope: Scope) -> None:
    records: list[dict[str, Any]] = [
        {"type": "session_meta", "payload": {"id": path.stem, "source": "vscode"}},
        {
            "timestamp": "2026-08-01T10:00:00Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": content}],
            },
        },
    ]
    source = write_jsonl(path, records)
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account=f"synthetic:{path.stem}",
        scope=scope,
        project_id=None,
    )
