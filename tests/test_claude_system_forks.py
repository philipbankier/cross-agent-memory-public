from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.ingest import parse_file, parse_incremental_file
from cross_assistant_memory.models import Authority, SourceSystem
from cross_assistant_memory.parsers import claude_code
from cross_assistant_memory.parsers.claude_code import MAX_FORK_ATTACHMENT_LINKS
from cross_assistant_memory.uploads import parse_upload_batch
from tests.claude_fork_fixtures import (
    CHILD,
    PARENT,
    _attachment_fork,  # pyright: ignore[reportPrivateUsage]
    _body,  # pyright: ignore[reportPrivateUsage]
    write_jsonl,
)


def _system_fork(count: int = 1, version: str = "2.1.284") -> list[dict[str, object]]:
    rows = _attachment_fork(count)
    for row in rows:
        if row.get("type") in {"user", "assistant", "attachment"}:
            row["version"] = version
    for row in rows[1 : count + 1]:
        del row["attachment"]
        row.update(
            type="system",
            subtype="stop_hook_summary",
            hookCount=1,
            hookInfos=[{"command": "synthetic-only-hook", "durationMs": 1}],
            hookErrors=[],
            hookAdditionalContext=["Inherited hook feedback."],
            preventedContinuation=False,
            hasOutput=True,
            level="info",
        )
    return rows


def test_280_stop_hook_link_matches_qualified_publisher_contract(tmp_path: Path) -> None:
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", _system_fork(version="2.1.280"))
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert [row.record_ordinal for row in parsed.records] == [3, 4]
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records


def test_message_support_does_not_authorize_unverified_stop_hook_links(tmp_path: Path) -> None:
    version = "2.1.237"
    assert version in claude_code.COPIED_FORK_PRODUCERS
    assert version not in claude_code.STOP_HOOK_LINK_PRODUCERS
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", _system_fork(version=version))
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)


@pytest.mark.parametrize("version", ["2.1.271", "2.1.280", "2.1.281", "2.1.289"])
def test_stop_fork_upload_decodes_without_expanded_node_allowlists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", _system_fork(2, version))
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    body = _body(parsed)
    with monkeypatch.context() as patch:
        patch.setattr(
            claude_code, "COPIED_FORK_PRODUCERS", claude_code.COPIED_FORK_PRODUCERS - {version}
        )
        patch.setattr(
            claude_code,
            "STOP_HOOK_LINK_PRODUCERS",
            claude_code.STOP_HOOK_LINK_PRODUCERS - {version},
        )
        decoded = parse_upload_batch(body)
    assert decoded.parsed.records == parsed.records
    assert [row.record_ordinal for row in parsed.records] == [4, 5]
    assert parsed.parser_version == "0.4.2"
    assert decoded.parsed.conversation_id == CHILD
    assert decoded.parsed.parent_conversation_id == PARENT


@pytest.mark.parametrize(
    "version", ["2.1.271", "2.1.280", "2.1.281", "2.1.284", "2.1.286", "2.1.289"]
)
@pytest.mark.parametrize("count", [1, 2, MAX_FORK_ATTACHMENT_LINKS])
def test_stop_hook_link_preserves_only_physical_child_evidence(
    tmp_path: Path, version: str, count: int
) -> None:
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", _system_fork(count, version))
    lines = source.read_bytes().splitlines(keepends=True)
    child_ordinal = count + 2
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.conversation_id == CHILD and parsed.parent_conversation_id == PARENT
    assert parsed.parser_version == "0.4.2"
    assert [row.record_ordinal for row in parsed.records] == [child_ordinal, child_ordinal + 1]
    assert all(row.authority is Authority.USER_ASSERTION for row in parsed.records)
    assert all("Inherited" not in row.content_text for row in parsed.records)
    assert parsed.records[0].raw_record == lines[child_ordinal]
    assert parsed.records[0].byte_start == sum(map(len, lines[:child_ordinal]))
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records
    prefix = parse_incremental_file(
        source, SourceSystem.CLAUDE_CODE, max_increment_bytes=sum(map(len, lines[:child_ordinal]))
    )
    assert not prefix.records
    assert prefix.end_prefix_digest == hashlib.sha256(b"".join(lines[:child_ordinal])).hexdigest()
    assert not parse_upload_batch(_body(prefix)).parsed.records
    tail = parse_incremental_file(
        source,
        SourceSystem.CLAUDE_CODE,
        start_byte=prefix.segment_end_byte,
        start_ordinal=child_ordinal,
        expected_prefix_digest=prefix.end_prefix_digest,
    )
    assert tail.records == parsed.records
    assert parse_upload_batch(_body(tail)).parsed.records == parsed.records


@pytest.mark.parametrize(
    "mutation",
    [
        "parent",
        "session",
        "uuid",
        "cycle",
        "duplicate",
        "sidechain",
        "entrypoint",
        "producer",
        "producer_type",
        "subtype",
        "count_bool",
        "count_negative",
        "infos",
        "command",
        "duration",
        "errors",
        "feedback",
        "prevented",
        "output",
        "level",
        "level_type",
        "reason",
        "tool",
        "label",
        "total_duration",
        "incomplete",
        "interleaved",
        "too_many_links",
    ],
)
def test_unverified_system_link_refuses_before_upload(tmp_path: Path, mutation: str) -> None:
    rows = _system_fork(2)
    row = rows[2]
    if mutation == "parent":
        row["parentUuid"] = "unlinked"
    elif mutation == "session":
        row["sessionId"] = CHILD
    elif mutation == "uuid":
        row["uuid"] = "not-a-uuid"
    elif mutation == "cycle":
        rows = _system_fork(3)
        rows[2]["uuid"] = rows[0]["uuid"]
        rows[3]["parentUuid"] = rows[0]["uuid"]
    elif mutation == "duplicate":
        row["uuid"] = rows[1]["uuid"]
        rows[-2]["parentUuid"] = row["uuid"]
    elif mutation == "sidechain":
        row["isSidechain"] = "false"
    elif mutation == "entrypoint":
        row["entrypoint"] = "sdk-cli"
    elif mutation == "producer":
        row["version"] = "2.1.285"
    elif mutation == "producer_type":
        row["version"] = []
    elif mutation == "subtype":
        row["subtype"] = "future"
    elif mutation == "count_bool":
        row["hookCount"] = True
    elif mutation == "count_negative":
        row["hookCount"] = -1
    elif mutation == "infos":
        row["hookInfos"] = {}
    elif mutation in {"command", "duration"}:
        info = cast(list[dict[str, object]], row["hookInfos"])[0]
        info["command" if mutation == "command" else "durationMs"] = (
            [] if mutation == "command" else True
        )
    elif mutation == "errors":
        row["hookErrors"] = [1]
    elif mutation == "feedback":
        row["hookAdditionalContext"] = [False]
    elif mutation == "prevented":
        row["preventedContinuation"] = "false"
    elif mutation == "output":
        row["hasOutput"] = 1
    elif mutation == "level":
        row["level"] = "unknown"
    elif mutation == "level_type":
        row["level"] = []
    elif mutation in {"reason", "tool", "label", "total_duration"}:
        field = {
            "reason": "stopReason",
            "tool": "toolUseID",
            "label": "hookLabel",
            "total_duration": "totalDurationMs",
        }[mutation]
        row[field] = []
    elif mutation == "incomplete":
        rows = rows[:-2]
    elif mutation == "interleaved":
        rows[-1]["sessionId"] = PARENT
    else:
        rows = _system_fork(MAX_FORK_ATTACHMENT_LINKS + 1)
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)


def test_unused_bad_summary_does_not_change_existing_direct_link(tmp_path: Path) -> None:
    rows = _system_fork()
    rows[1]["hookCount"] = "invalid-unused-summary"
    rows[-2]["parentUuid"] = rows[0]["uuid"]
    for row in rows:
        if row.get("type") == "user":
            row["version"] = "2.1.229"
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.conversation_id == CHILD and parsed.parent_conversation_id == PARENT
    assert len(parsed.records) == 2


def test_non_chain_metadata_does_not_break_stop_hook_link(tmp_path: Path) -> None:
    rows = _system_fork()
    rows[2:2] = [
        {"type": "custom-title", "sessionId": CHILD, "customTitle": "Synthetic title"}
        for _ in range(27)
    ]
    parsed = parse_file(write_jsonl(tmp_path / f"{CHILD}.jsonl", rows), SourceSystem.CLAUDE_CODE)
    assert [record.record_ordinal for record in parsed.records] == [30, 31]
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records


def test_unknown_uuid_system_record_breaks_stop_hook_link(tmp_path: Path) -> None:
    rows = _system_fork()
    rows.insert(2, {"type": "system", "subtype": "future", "uuid": "future-chain-link"})
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)


@pytest.mark.parametrize("count", [2, MAX_FORK_ATTACHMENT_LINKS, MAX_FORK_ATTACHMENT_LINKS + 1])
def test_mixed_links_share_the_existing_suffix_limit(tmp_path: Path, count: int) -> None:
    rows = _system_fork(count)
    attachment = _attachment_fork(count)[2]
    attachment["version"] = "2.1.284"
    rows[2] = attachment
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    if count > MAX_FORK_ATTACHMENT_LINKS:
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse_file(source, SourceSystem.CLAUDE_CODE)
    else:
        parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
        assert [record.record_ordinal for record in parsed.records] == [count + 2, count + 3]
        assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records
