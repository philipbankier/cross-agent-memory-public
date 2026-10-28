from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_incremental_file
from cross_assistant_memory.models import Access, Authority, QueryMode, Scope, SourceSystem
from cross_assistant_memory.storage import Ledger
from tests.conftest import write_jsonl


def _segmented_source(
    ledger: Ledger, path: Path, *, account: str = "synthetic", branch: str | None = "main"
) -> list[str]:
    write_jsonl(
        path, [{"type": "session_meta", "payload": {"id": "stream-thread", "source": "vscode"}}]
    )
    ids: list[str] = []
    for role, text in [
        ("user", "Earlier unrelated request."),
        ("assistant", "Earlier synthetic response."),
        ("assistant", "Synthetic repair proposal."),
        ("user", "Agreed."),
        ("assistant", "Synthetic implementation report."),
        ("user", "Please verify cleanup."),
        ("assistant", "Synthetic cleanup verified."),
    ]:
        row = {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": role,
                "phase": "final_answer" if role == "assistant" else None,
                "content": [{"type": "text", "text": text}],
            },
        }
        with path.open("ab") as handle:
            handle.write((json.dumps(row) + "\n").encode())
        cursor = ledger.source_cursor(
            SourceSystem.CODEX, source_account=account, source_path=str(path.resolve())
        )
        parsed = parse_incremental_file(
            path,
            SourceSystem.CODEX,
            start_byte=cursor.next_byte_offset if cursor else 0,
            start_ordinal=cursor.next_record_ordinal if cursor else 0,
            expected_prefix_digest=cursor.prefix_digest if cursor else None,
        )
        parsed = replace(
            parsed,
            branch_id=branch,
            records=tuple(replace(record, branch_id=branch) for record in parsed.records),
        )
        report = ledger.ingest(
            parsed, source_account=account, scope=Scope.USER_GLOBAL, project_id=None
        )
        assert report.inserted_events == 1
        with sqlite3.connect(ledger.settings.database_path) as connection:
            event = connection.execute(
                "SELECT event_id FROM events JOIN source_records USING(source_record_id) "
                "WHERE source_file_id = ?",
                (report.source_file_id,),
            ).fetchone()
        assert event is not None
        ids.append(str(event[0]))
    return ids


@pytest.mark.parametrize("branch", ["main", None])
def test_native_context_crosses_verified_upload_segments(
    tmp_path: Path, branch: str | None
) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    ids = _segmented_source(ledger, tmp_path / "source.jsonl", branch=branch)
    baseline = ledger.get_evidence(ids[3])
    generation = ledger.generation_digest()
    result = ledger.get_evidence(ids[3], include_context=True)
    context = result.pop("conversation_context")
    assert result == baseline
    assert context["selection"] == "same_source_stream_conversation_branch"
    assert context["history_complete"] is False
    assert [row["event_id"] for row in context["results"]] == [ids[1], ids[2], ids[4], ids[5]]
    assert [row["context_position"] for row in context["results"]] == [
        "preceding",
        "preceding",
        "following",
        "following",
    ]
    search = ledger.retrieve_workset("implementation", limit=1)
    assert search["results"][0]["event_id"] == ids[4]
    previous = search["results"][0]["conversation_context"]["results"]
    assert [row["event_id"] for row in previous] == [ids[3]]
    assert previous[0]["authority"] == "user_assertion"
    assert ledger.generation_digest() == generation


def test_segmented_context_does_not_cross_account_or_physical_file(tmp_path: Path) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    ids = _segmented_source(ledger, tmp_path / "first.jsonl")
    baseline = ledger.get_evidence(ids[3], include_context=True)["conversation_context"]
    _segmented_source(ledger, tmp_path / "second.jsonl")
    _segmented_source(ledger, tmp_path / "third.jsonl", account="other")
    assert ledger.get_evidence(ids[3], include_context=True)["conversation_context"] == baseline


@pytest.mark.parametrize(
    "boundary", ["privacy", "access", "conversation", "branch", "scope", "authority"]
)
def test_segmented_search_context_filters_before_limit(tmp_path: Path, boundary: str) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    ids = _segmented_source(ledger, tmp_path / "source.jsonl")
    arguments: dict[str, Any] = {"accesses": (Access.OWNER,)}
    with sqlite3.connect(ledger.settings.database_path) as connection:
        if boundary == "access":
            connection.execute(
                "UPDATE event_access SET access='assistant_private' WHERE event_id=?", (ids[3],)
            )
        elif boundary == "authority":
            arguments["authorities"] = (Authority.ASSISTANT_OUTPUT,)
        else:
            column, value = {
                "privacy": ("privacy", "no_memory"),
                "conversation": ("conversation_id", "other"),
                "branch": ("branch_id", "other"),
                "scope": ("scope", "session"),
            }[boundary]
            connection.execute(f"UPDATE events SET {column}=? WHERE event_id=?", (value, ids[3]))
    result = ledger.retrieve_workset("implementation", **arguments)
    context = result["results"][0]["conversation_context"]
    assert [row["event_id"] for row in context["results"]] == [ids[2]]
    assert "Agreed." not in str(context)


def test_legacy_source_without_stream_mapping_keeps_file_boundary(tmp_path: Path) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    ids = _segmented_source(ledger, tmp_path / "source.jsonl")
    with sqlite3.connect(ledger.settings.database_path) as connection:
        connection.execute(
            "DELETE FROM source_segments WHERE source_file_id = "
            "(SELECT source_file_id FROM source_records JOIN events USING(source_record_id) "
            "WHERE event_id=?)",
            (ids[3],),
        )
    context = ledger.get_evidence(ids[3], include_context=True)["conversation_context"]
    assert context["selection"] == "same_source_file_conversation_branch"
    assert context["results"] == []


def test_segmented_current_mode_excludes_superseded_predecessor(tmp_path: Path) -> None:
    ledger = Ledger(Settings(tmp_path / "data"))
    ids = _segmented_source(ledger, tmp_path / "source.jsonl")
    with sqlite3.connect(ledger.settings.database_path) as connection:
        connection.execute(
            "INSERT INTO event_relations "
            "(relation_id,from_event_id,to_event_id,relation_type,basis,created_at) "
            "VALUES ('synthetic',?,?,'supersession','synthetic','2026-10-07T00:00:00Z')",
            (ids[3], ids[4]),
        )
    result = ledger.retrieve_workset("implementation", mode=QueryMode.WHAT_IS_CURRENT)
    context = result["results"][0]["conversation_context"]
    assert [row["event_id"] for row in context["results"]] == [ids[2]]
