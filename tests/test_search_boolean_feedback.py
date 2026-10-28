from __future__ import annotations

from pathlib import Path

import pytest

from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import (
    ContextFilter,
    ContextKind,
    QueryMode,
    RetrievalCandidate,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    result = Ledger(Settings(tmp_path / "data"))
    source = write_jsonl(
        tmp_path / "source.jsonl",
        [{"type": "session_meta", "payload": {"id": "boolean-feedback", "source": "vscode"}}]
        + [
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                },
            }
            for text in [
                "Synthetic image example.",
                "Synthetic video example.",
                "Synthetic image OR video AND audio NOT draft. First literal example.",
                "Synthetic image OR video AND audio NOT draft. Second literal example.",
            ]
        ],
    )
    result.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    return result


@pytest.mark.parametrize("operator", ["OR", "AND", "NOT"])
def test_boolean_looking_query_explains_literal_matching_without_changing_results(
    ledger: Ledger, operator: str
) -> None:
    result = ledger.retrieve_workset(f"synthetic image {operator} video")
    baseline = ledger.retrieve_workset(f"synthetic image {operator.lower()} video")
    assert result["selection"]["candidate_match_count"] == 2
    diagnostic = result.pop("search_diagnostic")
    assert "literal required words, not Boolean operators" in diagnostic
    assert "separate short keyword searches" in diagnostic
    assert result == baseline


def test_boolean_feedback_preserves_empty_search_and_selected_context_explanations(
    ledger: Ledger,
) -> None:
    result = ledger.retrieve_workset(
        "synthetic image OR video",
        contexts=(ContextFilter(kind=ContextKind.TOPIC, key="unassigned"),),
    )
    assert result["results"] == []
    diagnostic = result["search_diagnostic"]
    assert "No eligible individual message" in diagnostic
    assert "assigned context labels" in diagnostic
    assert "literal required words, not Boolean operators" in diagnostic
    assert "Existing filters still apply" in diagnostic


@pytest.mark.parametrize("query", ["synthetic", "synthetic or", "ORACLE", "ordinary"])
def test_ordinary_words_do_not_get_boolean_feedback(ledger: Ledger, query: str) -> None:
    assert "Boolean" not in ledger.retrieve_workset(query).get("search_diagnostic", "")


def test_boolean_feedback_only_describes_consumed_query_tokens(ledger: Ledger) -> None:
    query = " ".join(["synthetic"] * 24 + ["OR", "missing"])
    result = ledger.retrieve_workset(query)
    assert result["selection"]["candidate_match_count"] == 4
    assert "search_diagnostic" not in result


def test_boolean_feedback_includes_the_last_consumed_token(ledger: Ledger) -> None:
    query = " ".join(["synthetic"] * 23 + ["OR"])
    result = ledger.retrieve_workset(query)
    assert result["selection"]["candidate_match_count"] == 2
    assert "literal required words" in result["search_diagnostic"]


@pytest.mark.parametrize("candidate_id", ["synthetic-projection", "first-party-sqlite-fts5"])
def test_ranked_candidates_do_not_claim_lexical_requirements(
    ledger: Ledger, candidate_id: str
) -> None:
    hit = ledger.retrieve_workset("example")["results"][0]
    result = ledger.retrieve_ranked_workset(
        "nonmatching OR query",
        candidates=(RetrievalCandidate(hit["event_id"], 1.0),),
        candidate_id=candidate_id,
    )
    assert [row["event_id"] for row in result["results"]] == [hit["event_id"]]
    assert "search_diagnostic" not in result


def test_recency_mode_without_lexical_filter_does_not_claim_literal_matching(
    ledger: Ledger,
) -> None:
    result = ledger.retrieve_workset("OR", mode=QueryMode.WHERE_DID_I_LEAVE_OFF)
    assert "search_diagnostic" not in result
