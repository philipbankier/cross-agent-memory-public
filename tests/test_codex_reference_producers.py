from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory import ingest as ingest_module
from cross_assistant_memory.ingest import parse_incremental_file
from cross_assistant_memory.models import Authority, CollectorProvenance, SourceSystem
from cross_assistant_memory.uploads import build_upload_batch, parse_upload_batch

VERSIONS = (
    "0.155.0-alpha.9.2",
    "0.158.0-alpha.2.1",
    "0.159.0-alpha.12.1",
    "0.160.0",
    "0.160.1",
    "0.162.0-alpha.2",
    "0.162.0-alpha.17.2",
)


def header(version: str, **changes: object) -> dict[str, object]:
    return {
        "type": "session_meta",
        "ordinal": 1000,
        "payload": {
            "id": "synthetic-child",
            "session_id": "synthetic-root",
            "cli_version": version,
            "history_mode": "paginated",
            "source": "cli",
            "history_base": {
                "thread_id": "synthetic-parent-rollout",
                "end_ordinal_exclusive": 1000,
                "end_byte_offset": 2 * 1024**3,
            },
            **changes,
        },
    }


def message(
    ordinal: object = 1001, text: str = "Synthetic child-owned statement."
) -> dict[str, object]:
    return {
        "type": "response_item",
        "ordinal": ordinal,
        "payload": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": text}],
        },
    }


def write_jsonl(path: Path, records: Iterable[Mapping[str, object]]) -> Path:
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    return path


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("fork", ["absent", "null", "parent"])
@pytest.mark.parametrize("source_kind", ["cli", "exec"])
def test_verified_reference_keeps_physical_cursors_and_upload_identity(
    tmp_path: Path, version: str, fork: str, source_kind: str
) -> None:
    metadata = header(version, source=source_kind)
    payload = cast(dict[str, object], metadata["payload"])
    if fork != "absent":
        payload["forked_from_id"] = "synthetic-parent" if fork == "parent" else None
    path = write_jsonl(tmp_path / "synthetic-rollout.jsonl", [metadata, message()])
    raw = path.read_bytes()
    first_line = raw.splitlines(keepends=True)[0]
    first = parse_incremental_file(path, SourceSystem.CODEX, max_increment_bytes=len(first_line))
    assert first.records == ()
    assert first.segment_start_byte == first.segment_start_ordinal == 0
    assert first.segment_end_byte == len(first_line)
    assert first.segment_end_ordinal_exclusive == 1
    assert first.end_prefix_digest == hashlib.sha256(first_line).hexdigest()
    parsed = parse_incremental_file(
        path,
        SourceSystem.CODEX,
        start_byte=first.segment_end_byte,
        start_ordinal=first.segment_end_ordinal_exclusive,
        expected_prefix_digest=first.end_prefix_digest,
    )
    assert parsed.parser_name == "codex-jsonl"
    assert parsed.parser_version == "0.2.3"
    assert parsed.conversation_id == "synthetic-child"
    assert parsed.branch_id == ("synthetic-child" if fork == "parent" else "synthetic-root")
    assert parsed.parent_conversation_id == ("synthetic-parent" if fork == "parent" else None)
    assert parsed.history_base is not None
    assert parsed.history_base.thread_id == "synthetic-parent-rollout"
    assert parsed.history_base.end_byte_offset == 2 * 1024**3
    assert parsed.segment_end_byte == len(raw)
    assert parsed.segment_end_ordinal_exclusive == 2
    assert parsed.end_prefix_digest == hashlib.sha256(raw).hexdigest()
    assert len(parsed.records) == 1
    record = parsed.records[0]
    assert record.record_ordinal == 1
    assert record.byte_start == len(first_line)
    assert record.raw_record == raw[len(first_line) :]
    expected = Authority.USER_ASSERTION if source_kind == "cli" else Authority.TOOL_OBSERVATION
    assert record.authority is expected
    provenance = CollectorProvenance(
        "codex",
        version,
        "native-jsonl-history",
        "cross-memory-native-collector",
        "0.1.0",
        parsed.schema_fingerprint,
    )
    body = build_upload_batch(parsed, source_account_id="synthetic-owner", provenance=provenance)
    batch = parse_upload_batch(body)
    assert batch.parsed.records == parsed.records
    assert batch.parsed.history_base == parsed.history_base
    assert batch.parsed.conversation_id == parsed.conversation_id
    assert batch.parsed.parent_conversation_id == parsed.parent_conversation_id
    assert batch.batch_id == parse_upload_batch(body).batch_id


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("ordinal", [1000, 1002, True, "1001", None])
def test_reference_refuses_noncontiguous_native_ordinal(
    tmp_path: Path, version: str, ordinal: object
) -> None:
    path = write_jsonl(tmp_path / "invalid.jsonl", [header(version), message(ordinal)])
    with pytest.raises(ValueError, match="invalid child ordinal sequence"):
        parse_incremental_file(path, SourceSystem.CODEX)


@pytest.mark.parametrize(
    "version",
    [
        "0.155.0-alpha.9.1",
        "0.155.0-alpha.9.3",
        "0.158.0-alpha.2",
        "0.158.0-alpha.2.2",
        "0.159.0-alpha.12",
        "0.159.0-alpha.12.2",
        "0.160.2",
        "0.160.0-alpha.1",
        "0.162.0-alpha.1",
        "0.162.0-alpha.3",
        "0.162.0-alpha.17.1",
        "0.162.0-alpha.17.3",
        "0.162.0",
    ],
)
def test_adjacent_unverified_producers_stay_refused(tmp_path: Path, version: str) -> None:
    path = write_jsonl(tmp_path / "unverified.jsonl", [header(version), message()])
    with pytest.raises(ValueError, match="explicit replay boundary"):
        parse_incremental_file(path, SourceSystem.CODEX)


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("copy_marker", [2, 1000])
def test_reference_addition_does_not_authorize_copied_history(
    tmp_path: Path, version: str, copy_marker: int
) -> None:
    path = write_jsonl(
        tmp_path / "copied.jsonl",
        [header(version, subagent_history_start_ordinal=copy_marker), message()],
    )
    with pytest.raises(ValueError):
        parse_incremental_file(path, SourceSystem.CODEX)


@pytest.mark.parametrize("version", ["0.160.0", "0.160.1", "0.162.0-alpha.2", "0.162.0-alpha.17.2"])
def test_logical_fork_cutoff_and_creator_do_not_replace_physical_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    path = write_jsonl(
        tmp_path / "new-reference.jsonl",
        [
            header(
                version,
                forked_from_id="synthetic-parent",
                forked_from_ordinal_exclusive=800,
                creator_user_id="synthetic-user",
                creator_account_id="synthetic-account",
                runtime_workspace_roots=["/synthetic/another-account"],
            ),
            message(),
        ],
    )
    original = ingest_module._open_regular_file  # pyright: ignore[reportPrivateUsage]

    def child_only(source: Path) -> int:
        assert source == path
        return original(source)

    monkeypatch.setattr(ingest_module, "_open_regular_file", child_only)
    parsed = parse_incremental_file(path, SourceSystem.CODEX)
    assert parsed.history_base is not None
    assert parsed.history_base.end_ordinal_exclusive == 1000
    assert parsed.parent_conversation_id == "synthetic-parent"
    assert parsed.segment_start_byte == parsed.segment_start_ordinal == 0
    assert parsed.segment_end_ordinal_exclusive == 2
    assert parsed.records[0].record_ordinal == 1
    assert parsed.records[0].authority is Authority.USER_ASSERTION
    assert parsed.records[0].content_text == "Synthetic child-owned statement."


def test_reference_producer_tool_observations_do_not_become_child_messages(tmp_path: Path) -> None:
    source = write_jsonl(
        tmp_path / "transformed-observations.jsonl",
        [
            header("0.162.0-alpha.17.2"),
            {
                "type": "event_msg",
                "ordinal": 1001,
                "payload": {
                    "type": "item_completed",
                    "item": {
                        "type": "command_execution",
                        "aggregated_output": "Synthetic stored output with a truncation marker.",
                    },
                },
            },
            {
                "type": "event_msg",
                "ordinal": 1002,
                "payload": {
                    "type": "item_completed",
                    "item": {
                        "type": "mcp_tool_call",
                        "result": {
                            "content": [
                                {"type": "text", "text": "Synthetic truncated tool result."}
                            ]
                        },
                    },
                },
            },
            message(1003, "The actual child request."),
        ],
    )
    parsed = parse_incremental_file(source, SourceSystem.CODEX)
    assert not parsed.unknown_record_types and not parsed.malformed_records
    assert parsed.segment_end_ordinal_exclusive == 4
    assert len(parsed.records) == 1
    assert parsed.records[0].record_ordinal == 3
    assert parsed.records[0].content_text == "The actual child request."
    assert parsed.records[0].authority is Authority.USER_ASSERTION
