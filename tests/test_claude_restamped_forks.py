from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from cross_assistant_memory.ingest import parse_file, parse_incremental_file
from cross_assistant_memory.models import Authority, SourceSystem
from cross_assistant_memory.uploads import parse_upload_batch
from tests.claude_fork_fixtures import (
    CHILD,
    PARENT,
    _body,  # pyright: ignore[reportPrivateUsage]
    write_jsonl,
)
from tests.test_claude_start_hook_forks import (
    _start_hook_fork,  # pyright: ignore[reportPrivateUsage]
)

FINAL = "33333333-3333-4333-8333-333333333333"


def _rows() -> list[dict[str, object]]:
    return [
        {
            "type": role,
            "sessionId": session,
            "uuid": str(UUID(int=index + 1)),
            "parentUuid": None if parent is None else str(UUID(int=parent)),
            "entrypoint": "claude-desktop",
            "isSidechain": False,
            "version": "2.1.281",
            "timestamp": f"2026-10-12T10:00:0{index}Z",
            "message": {"role": role, "content": f"Synthetic {role} message {index}."},
        }
        for index, (session, role, parent) in enumerate(
            [
                (PARENT, "user", None),
                (PARENT, "assistant", 1),
                (PARENT, "user", 2),
                (CHILD, "assistant", 1),
                (CHILD, "user", 4),
            ]
        )
    ]


@pytest.mark.parametrize("attachment", [False, True])
def test_restamped_assistant_links_unique_earlier_user_without_inherited_evidence(
    tmp_path: Path, attachment: bool
) -> None:
    rows = _rows()
    if attachment:
        rows.insert(
            3,
            {
                "type": "attachment",
                "uuid": str(UUID(int=100)),
                "parentUuid": rows[2]["uuid"],
                "sessionId": PARENT,
                "attachment": {"type": "batching_reminder_sent"},
            },
        )
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    raw = source.read_bytes().splitlines(keepends=True)
    boundary = len(rows) - 2
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.conversation_id == parsed.branch_id == CHILD
    assert parsed.parent_conversation_id == PARENT
    assert [record.record_ordinal for record in parsed.records] == [boundary, boundary + 1]
    assert parsed.records[0].raw_record == raw[boundary]
    assert parsed.records[0].byte_start == sum(map(len, raw[:boundary]))
    assert parsed.records[0].parent_message_id == rows[0]["uuid"]
    assert [record.authority for record in parsed.records] == [
        Authority.ASSISTANT_OUTPUT,
        Authority.USER_ASSERTION,
    ]
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records
    prefix_bytes = sum(map(len, raw[:boundary]))
    prefix = parse_incremental_file(
        source, SourceSystem.CLAUDE_CODE, max_increment_bytes=prefix_bytes
    )
    assert not prefix.records
    assert prefix.end_prefix_digest == hashlib.sha256(b"".join(raw[:boundary])).hexdigest()
    assert not parse_upload_batch(_body(prefix)).parsed.records
    tail = parse_incremental_file(
        source,
        SourceSystem.CLAUDE_CODE,
        start_byte=prefix.segment_end_byte,
        start_ordinal=boundary,
        expected_prefix_digest=prefix.end_prefix_digest,
    )
    assert tail.records == parsed.records
    assert parse_upload_batch(_body(tail)).parsed.records == parsed.records


@pytest.mark.parametrize(
    "mutation",
    [
        "user_transition",
        "other_known_version",
        "future_version",
        "parent_other_version",
        "parent_other_entrypoint",
        "parent_assistant",
        "ambiguous_parent",
        "attachment_parent",
        "foreign_parent",
        "missing_parent",
        "invalid_child_uuid",
        "repeated_child_uuid",
        "self_parent",
        "nonboolean_sidechain",
        "missing_sidechain",
        "wrong_message_role",
        "unknown_prefix",
        "malformed_prefix",
        "wrong_filename",
    ],
)
def test_unqualified_earlier_parent_transition_refuses_before_upload(
    tmp_path: Path, mutation: str
) -> None:
    rows = _rows()
    first = rows[3]
    filename = CHILD
    if mutation == "user_transition":
        first["type"] = "user"
        first["message"] = {"role": "user", "content": "Synthetic user transition."}
    elif mutation == "other_known_version":
        first["version"] = "2.1.280"
    elif mutation == "future_version":
        first["version"] = "future-producer"
    elif mutation == "parent_other_version":
        rows[0]["version"] = "2.1.280"
    elif mutation == "parent_other_entrypoint":
        rows[0]["entrypoint"] = "sdk-cli"
    elif mutation == "parent_assistant":
        first["parentUuid"] = rows[1]["uuid"]
    elif mutation == "ambiguous_parent":
        rows[1]["uuid"] = rows[0]["uuid"]
    elif mutation == "attachment_parent":
        rows.insert(0, {"type": "attachment", "uuid": str(UUID(int=100))})
        first["parentUuid"] = str(UUID(int=100))
    elif mutation == "foreign_parent":
        first["parentUuid"] = str(UUID(int=100))
    elif mutation == "missing_parent":
        del first["parentUuid"]
    elif mutation == "invalid_child_uuid":
        first["uuid"] = "not-a-native-uuid"
    elif mutation == "repeated_child_uuid":
        first["uuid"] = rows[1]["uuid"]
    elif mutation == "self_parent":
        first["uuid"] = rows[0]["uuid"]
    elif mutation == "nonboolean_sidechain":
        first["isSidechain"] = "false"
    elif mutation == "missing_sidechain":
        del first["isSidechain"]
    elif mutation == "wrong_message_role":
        first["message"] = {"role": "user", "content": "Synthetic mismatched role."}
    elif mutation == "unknown_prefix":
        rows.insert(0, {"type": "unknown-record"})
    elif mutation == "malformed_prefix":
        rows.insert(0, {"type": "custom-title", "sessionId": PARENT})
    else:
        filename = PARENT
    source = write_jsonl(tmp_path / f"{filename}.jsonl", rows)
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)


def test_earlier_parent_link_cannot_reach_a_grandparent_session(tmp_path: Path) -> None:
    rows = _rows()
    for row in rows[3:]:
        row["sessionId"] = FINAL
    middle = dict(
        rows[2],
        sessionId=CHILD,
        uuid=str(UUID(int=200)),
        parentUuid=rows[2]["uuid"],
    )
    rows.insert(3, middle)
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", rows)
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)


def test_third_occurrence_cannot_requalify_an_ambiguous_parent(tmp_path: Path) -> None:
    rows = _rows()
    rows[1:1] = [rows[0].copy(), rows[0].copy()]
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)


def test_restamped_assistant_cannot_bypass_a_qualified_child_start_hook(tmp_path: Path) -> None:
    rows = _start_hook_fork()
    earlier = _rows()[0]
    rows.insert(0, earlier)
    first = rows[-2]
    first.update(
        type="assistant",
        uuid=str(UUID(int=200)),
        parentUuid=earlier["uuid"],
        isSidechain=False,
        message={"role": "assistant", "content": "Synthetic restamped assistant."},
    )
    rows[-1]["parentUuid"] = first["uuid"]
    # Removing only the start hook leaves an otherwise qualified earlier-parent link.
    control = write_jsonl(tmp_path / "control" / f"{CHILD}.jsonl", rows[:4] + rows[5:])
    assert parse_file(control, SourceSystem.CLAUDE_CODE).parent_conversation_id == PARENT
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)
