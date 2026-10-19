from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast
from uuid import UUID

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
    _records,  # pyright: ignore[reportPrivateUsage]
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


def _start_hook_fork(stop_count: int = 1) -> list[dict[str, object]]:
    rows = _system_fork(stop_count, version="2.1.280")
    hook_ordinal = stop_count + 2
    hook: dict[str, object] = {
        "type": "attachment",
        "uuid": str(UUID(int=201)),
        "parentUuid": rows[stop_count]["uuid"],
        "sessionId": CHILD,
        "entrypoint": "claude-desktop",
        "version": "2.1.281",
        "isSidechain": False,
        "attachment": {
            "type": "hook_success",
            "hookEvent": "SessionStart",
            "hookName": "synthetic-only-start-hook",
            "toolUseID": "synthetic-start",
            "content": "Inherited runtime hook feedback.",
            "stdout": "Inherited runtime output.",
            "stderr": "",
            "command": "synthetic-only-command",
            "exitCode": 0,
            "durationMs": 1,
        },
    }
    rows.insert(hook_ordinal, hook)
    rows[hook_ordinal + 1].update(parentUuid=hook["uuid"], version="2.1.281", isMeta=True)
    rows[hook_ordinal + 2]["version"] = "2.1.281"
    return rows


@pytest.mark.parametrize("stop_count", [MAX_FORK_ATTACHMENT_LINKS - 1, MAX_FORK_ATTACHMENT_LINKS])
def test_start_hook_does_not_expand_the_existing_total_suffix_bound(
    tmp_path: Path, stop_count: int
) -> None:
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", _start_hook_fork(stop_count))
    if stop_count == MAX_FORK_ATTACHMENT_LINKS:
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse_file(source, SourceSystem.CLAUDE_CODE)
    else:
        parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
        assert [r.record_ordinal for r in parsed.records] == [stop_count + 3, stop_count + 4]


@pytest.mark.parametrize("output", ["content", "stdout", "stderr"])
def test_child_session_start_hook_keeps_only_exact_child_messages(
    tmp_path: Path, output: str
) -> None:
    rows = _start_hook_fork()
    attachment = cast(dict[str, object], rows[3]["attachment"])
    attachment.update(content="", stdout="", stderr="")
    attachment[output] = "Inherited runtime output."
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    lines = source.read_bytes().splitlines(keepends=True)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.parser_version == "0.4.2"
    assert parsed.conversation_id == CHILD and parsed.parent_conversation_id == PARENT
    assert [record.record_ordinal for record in parsed.records] == [4, 5]
    assert parsed.records[0].authority is Authority.TOOL_OBSERVATION
    assert parsed.records[0].actor_kind == "automation"
    assert parsed.records[1].authority is Authority.USER_ASSERTION
    assert all("Inherited" not in record.content_text for record in parsed.records)
    for record in parsed.records:
        assert record.raw_record == lines[record.record_ordinal]
        assert record.byte_start == sum(map(len, lines[: record.record_ordinal]))
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records
    prefix = parse_incremental_file(
        source, SourceSystem.CLAUDE_CODE, max_increment_bytes=sum(map(len, lines[:4]))
    )
    assert not prefix.records
    assert prefix.end_prefix_digest == hashlib.sha256(b"".join(lines[:4])).hexdigest()
    assert not parse_upload_batch(_body(prefix)).parsed.records
    tail = parse_incremental_file(
        source,
        SourceSystem.CLAUDE_CODE,
        start_byte=prefix.segment_end_byte,
        start_ordinal=4,
        expected_prefix_digest=prefix.end_prefix_digest,
    )
    assert tail.records == parsed.records


@pytest.mark.parametrize(
    "mutation",
    [
        "parent",
        "session",
        "producer",
        "event",
        "empty",
        "nonstring_content",
        "nonstring_command",
        "nonstring_hook_name",
        "nonstring_tool_id",
        "exit_bool",
        "duration_bool",
        "sidechain",
        "entrypoint",
        "duplicate",
        "missing_stop",
        "unqualified_stop",
        "second_child_hook",
        "back_to_parent",
        "unlinked_child",
        "different_child_session",
        "earlier_parent",
    ],
)
def test_unverified_child_session_hook_or_earlier_parent_still_refuses(
    tmp_path: Path, mutation: str
) -> None:
    rows = _start_hook_fork()
    hook = rows[3]
    attachment = cast(dict[str, object], hook["attachment"])
    if mutation == "parent":
        hook["parentUuid"] = rows[0]["uuid"]
    elif mutation == "session":
        hook["sessionId"] = PARENT
    elif mutation == "producer":
        hook["version"] = "2.1.289"
    elif mutation == "event":
        attachment["hookEvent"] = "Stop"
    elif mutation == "empty":
        attachment.update(content="", stdout="  ", stderr="\n")
    elif mutation.startswith("nonstring_"):
        key = {
            "content": "content",
            "command": "command",
            "hook_name": "hookName",
            "tool_id": "toolUseID",
        }[mutation.removeprefix("nonstring_")]
        attachment[key] = []
    elif mutation == "exit_bool":
        attachment["exitCode"] = True
    elif mutation == "duration_bool":
        attachment["durationMs"] = True
    elif mutation == "sidechain":
        hook["isSidechain"] = "false"
    elif mutation == "entrypoint":
        hook["entrypoint"] = "sdk-cli"
    elif mutation == "duplicate":
        hook["uuid"] = rows[1]["uuid"]
        rows[4]["parentUuid"] = hook["uuid"]
    elif mutation == "missing_stop":
        del rows[1]
    elif mutation == "unqualified_stop":
        rows[1]["version"] = "2.1.279"
    elif mutation in {"second_child_hook", "back_to_parent"}:
        next_hook = dict(hook, uuid=str(UUID(int=202)), parentUuid=hook["uuid"])
        if mutation == "back_to_parent":
            next_hook.update(sessionId=PARENT, attachment={"type": "total_tokens_reminder"})
        rows.insert(4, next_hook)
        rows[5]["parentUuid"] = next_hook["uuid"]
    elif mutation == "unlinked_child":
        rows[4]["parentUuid"] = "unlinked"
    elif mutation == "different_child_session":
        rows[4]["sessionId"] = str(UUID(int=333))
    elif mutation == "earlier_parent":
        previous = dict(rows[0], uuid=str(UUID(int=300)), parentUuid=rows[0]["uuid"])
        rows.insert(1, previous)
        rows[5]["parentUuid"] = rows[0]["uuid"]
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)


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


def test_289_preserved_parent_version_keeps_only_child_evidence(tmp_path: Path) -> None:
    rows = _system_fork(version="2.1.289")
    rows[0]["version"] = "2.1.275"
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    lines = source.read_bytes().splitlines(keepends=True)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.parent_conversation_id == PARENT
    assert parsed.conversation_id == parsed.branch_id == CHILD
    assert parsed.parser_version == "0.4.2"
    assert [record.record_ordinal for record in parsed.records] == [3, 4]
    assert [record.raw_record for record in parsed.records] == lines[3:]
    assert all(record.authority is Authority.USER_ASSERTION for record in parsed.records)
    assert all("Inherited" not in record.content_text for record in parsed.records)
    assert parse_incremental_file(source, SourceSystem.CLAUDE_CODE).records == parsed.records
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records
    prefix_bytes = sum(map(len, lines[:3]))
    prefix = parse_incremental_file(
        source, SourceSystem.CLAUDE_CODE, max_increment_bytes=prefix_bytes
    )
    assert not prefix.records and prefix.segment_end_ordinal_exclusive == 3
    assert prefix.end_prefix_digest == hashlib.sha256(b"".join(lines[:3])).hexdigest()
    tail = parse_incremental_file(
        source,
        SourceSystem.CLAUDE_CODE,
        start_byte=prefix.segment_end_byte,
        start_ordinal=3,
        expected_prefix_digest=prefix.end_prefix_digest,
    )
    assert tail.records == parsed.records
    assert tail.end_prefix_digest == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.parametrize("ordinal", [1, 3, 4])
@pytest.mark.parametrize("preserved_version", ["2.1.281", None, "2.1.290"])
def test_289_fork_validates_each_preserved_row_version(
    tmp_path: Path, ordinal: int, preserved_version: str | None
) -> None:
    rows = _system_fork(version="2.1.289")
    if preserved_version is None:
        del rows[ordinal]["version"]
    else:
        rows[ordinal]["version"] = preserved_version
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", rows)
    if preserved_version != "2.1.281":
        for parse in (parse_file, parse_incremental_file):
            with pytest.raises(ValueError, match="verified fork boundary"):
                parse(source, SourceSystem.CLAUDE_CODE)
        return
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.parent_conversation_id == PARENT and parsed.conversation_id == CHILD
    assert parsed.parser_version == "0.4.2"
    assert [record.record_ordinal for record in parsed.records] == [3, 4]
    assert [record.raw_record for record in parsed.records] == source.read_bytes().splitlines(
        keepends=True
    )[3:]
    assert parse_incremental_file(source, SourceSystem.CLAUDE_CODE).records == parsed.records
    assert parse_upload_batch(_body(parsed)).parsed.records == parsed.records


@pytest.mark.parametrize("version", sorted(claude_code.COPIED_FORK_PRODUCERS))
def test_copied_fork_keeps_only_child_messages_and_physical_locators(
    tmp_path: Path, version: str
) -> None:
    records = _records()
    for item in records[1:]:
        item["version"] = version
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", records)
    raw = source.read_bytes().splitlines(keepends=True)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.conversation_id == parsed.branch_id == CHILD
    assert parsed.parent_conversation_id == PARENT
    assert [r.record_ordinal for r in parsed.records] == [1, 2]
    assert parsed.records[0].raw_record == raw[1]
    assert parsed.records[0].byte_start == len(raw[0])
    decoded = parse_upload_batch(_body(parsed))
    assert all("Inherited" not in r.content_text for r in decoded.parsed.records)
    assert decoded.parsed.records == parsed.records
    assert decoded.parsed.conversation_id == CHILD
    assert decoded.parsed.parent_conversation_id == PARENT


@pytest.mark.parametrize("version", ["2.1.280", "2.1.289"])
def test_fork_upload_decodes_without_expanded_node_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    records = _records()
    for item in records[1:]:
        item["version"] = version
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", records)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    body = _body(parsed)
    with monkeypatch.context() as patch:
        patch.setattr(
            claude_code, "COPIED_FORK_PRODUCERS", claude_code.COPIED_FORK_PRODUCERS - {version}
        )
        decoded = parse_upload_batch(body)
    assert parsed.parser_version == "0.4.2"
    assert decoded.parsed.records == parsed.records
    assert [row.record_ordinal for row in parsed.records] == [1, 2]
    assert decoded.parsed.conversation_id == CHILD
    assert decoded.parsed.parent_conversation_id == PARENT


@pytest.mark.parametrize("version", ["2.1.282", "2.1.290"])
def test_newer_unqualified_fork_producers_still_refuse(tmp_path: Path, version: str) -> None:
    records = _records()
    for item in records[1:]:
        item["version"] = version
    source = write_jsonl(tmp_path / f"{CHILD}.jsonl", records)
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)
