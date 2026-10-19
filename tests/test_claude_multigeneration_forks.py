from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from cross_assistant_memory.ingest import parse_file, parse_incremental_file
from cross_assistant_memory.models import Authority, SourceSystem
from cross_assistant_memory.parsers import claude_code
from cross_assistant_memory.uploads import parse_upload_batch
from tests.claude_fork_fixtures import (
    CHILD,
    PARENT,
    _body,  # pyright: ignore[reportPrivateUsage]
    _records,  # pyright: ignore[reportPrivateUsage]
    write_jsonl,
)
from tests.test_claude_system_forks import _system_fork  # pyright: ignore[reportPrivateUsage]

FINAL = "33333333-3333-4333-8333-333333333333"


def _three_generations(stop_links: bool = True) -> list[dict[str, object]]:
    rows = _system_fork(version="2.1.281") if stop_links else _records()
    if stop_links:
        link = rows[1].copy()
        link.update(uuid=str(UUID(int=201)), parentUuid=rows[-1]["uuid"], sessionId=CHILD)
        rows.append(link)
    final = rows[0].copy()
    final.update(
        uuid="final-message",
        parentUuid=rows[-1]["uuid"],
        sessionId=FINAL,
        version="2.1.281",
        timestamp="2026-10-08T12:00:00Z",
        message={"role": "user", "content": "Final branch decision."},
    )
    return [*rows, final]


@pytest.mark.parametrize("stop_links", [False, True])
def test_three_generations_keep_only_final_child_and_immediate_parent(
    tmp_path: Path, stop_links: bool
) -> None:
    rows = _three_generations(stop_links)
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", rows)
    lines = source.read_bytes().splitlines(keepends=True)
    final_ordinal = len(rows) - 1
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.conversation_id == parsed.branch_id == FINAL
    assert parsed.parent_conversation_id == CHILD
    assert parsed.captured_at == "2026-10-08T12:00:00Z"
    assert [r.record_ordinal for r in parsed.records] == [final_ordinal]
    assert parsed.records[0].raw_record == lines[-1]
    assert parsed.records[0].byte_start == sum(map(len, lines[:-1]))
    assert parsed.records[0].content_text == "Final branch decision."
    assert parsed.records[0].authority is Authority.USER_ASSERTION
    decoded = parse_upload_batch(_body(parsed))
    assert decoded.parsed.records == parsed.records
    assert decoded.parsed.parent_conversation_id == CHILD
    prefix = parse_incremental_file(
        source, SourceSystem.CLAUDE_CODE, max_increment_bytes=sum(map(len, lines[:-1]))
    )
    assert not prefix.records
    assert prefix.end_prefix_digest == hashlib.sha256(b"".join(lines[:-1])).hexdigest()
    assert not parse_upload_batch(_body(prefix)).parsed.records
    tail = parse_incremental_file(
        source,
        SourceSystem.CLAUDE_CODE,
        start_byte=prefix.segment_end_byte,
        start_ordinal=final_ordinal,
        expected_prefix_digest=prefix.end_prefix_digest,
    )
    assert tail.records == parsed.records
    assert parse_upload_batch(_body(tail)).parsed.records == parsed.records


def test_unused_unqualified_hook_does_not_replace_a_verified_direct_parent(tmp_path: Path) -> None:
    rows = _three_generations()
    rows[1]["version"] = "2.1.272"
    rows[3]["parentUuid"] = rows[0]["uuid"]
    # The older two-run contract also permits this direct link, not the invalid hook.
    parent = write_jsonl(tmp_path / "parent" / f"{CHILD}.jsonl", rows[:-2])
    assert parse_file(parent, SourceSystem.CLAUDE_CODE).parent_conversation_id == PARENT
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", rows)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.parent_conversation_id == CHILD
    assert [r.content_text for r in parsed.records] == ["Final branch decision."]
    rows[3]["parentUuid"] = rows[1]["uuid"]
    source = write_jsonl(source, rows)
    with pytest.raises(ValueError, match="verified fork boundary"):
        parse_file(source, SourceSystem.CLAUDE_CODE)


def test_unqualified_later_final_message_still_refuses(tmp_path: Path) -> None:
    rows = _three_generations()
    later = rows[-1].copy()
    later.update(uuid="later-final-message", parentUuid=rows[-1]["uuid"], version="2.1.272")
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", [*rows, later])
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)


def test_multigeneration_decoder_does_not_reinspect_copied_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", _three_generations())
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    body = _body(parsed)

    def refuse_inspection(*_: object, **__: object) -> claude_code.ClaudeCodeMetadata:
        raise AssertionError("upload decoder must not reinterpret the inherited prefix")

    monkeypatch.setattr(claude_code, "inspect_claude_code_metadata_records", refuse_inspection)
    decoded = parse_upload_batch(body)
    assert decoded.parsed.records == parsed.records
    assert decoded.parsed.parent_conversation_id == CHILD
    assert decoded.parsed.parser_version == "0.4.2"


@pytest.mark.parametrize(
    "mutation",
    [
        "first_link",
        "last_link",
        "early_stop_producer",
        "middle_producer",
        "middle_session_uuid",
        "middle_entrypoint",
        "cycle",
        "four_generations",
        "four_then_repeat_final",
        "filename_is_ancestor",
    ],
)
def test_unverified_multigeneration_history_refuses_before_upload(
    tmp_path: Path, mutation: str
) -> None:
    rows = _three_generations()
    filename = FINAL
    if mutation == "first_link":
        rows[3]["parentUuid"] = "unlinked"
    elif mutation == "last_link":
        rows[-1]["parentUuid"] = "unlinked"
    elif mutation == "early_stop_producer":
        rows[1]["version"] = "2.1.272"
    elif mutation == "middle_producer":
        rows[3]["version"] = "future-producer"
    elif mutation == "middle_session_uuid":
        for row in rows:
            if row.get("sessionId") == CHILD:
                row["sessionId"] = "not-a-native-session-uuid"
    elif mutation == "middle_entrypoint":
        rows[3]["entrypoint"] = "sdk-cli"
    elif mutation == "cycle":
        rows[-1]["sessionId"] = PARENT
        filename = PARENT
    elif mutation in {"four_generations", "four_then_repeat_final"}:
        fourth = rows[-1].copy()
        fourth.update(
            sessionId="44444444-4444-4444-8444-444444444444",
            uuid="fourth-message",
            parentUuid=rows[-1]["uuid"],
        )
        rows.append(fourth)
        if mutation == "four_then_repeat_final":
            repeated = rows[-2].copy()
            repeated.update(uuid="repeated-message", parentUuid=rows[-1]["uuid"])
            rows.append(repeated)
        else:
            filename = str(fourth["sessionId"])
    elif mutation == "filename_is_ancestor":
        filename = CHILD
    source = write_jsonl(tmp_path / f"{filename}.jsonl", rows)
    for parse in (parse_file, parse_incremental_file):
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse(source, SourceSystem.CLAUDE_CODE)


@pytest.mark.parametrize("final_link_version", ["2.1.281", "2.1.284"])
def test_271_ancestor_stop_link_preserves_final_child_and_unchanged_decoder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, final_link_version: str
) -> None:
    rows = _three_generations()
    rows[1]["version"] = "2.1.271"
    rows[-2]["version"] = final_link_version
    source = write_jsonl(tmp_path / f"{FINAL}.jsonl", rows)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    assert parsed.parent_conversation_id == CHILD
    assert parsed.parser_version == "0.4.2"
    assert [row.content_text for row in parsed.records] == ["Final branch decision."]
    assert [row.record_ordinal for row in parsed.records] == [len(rows) - 1]
    body = _body(parsed)
    with monkeypatch.context() as patch:
        patch.setattr(
            claude_code, "COPIED_FORK_PRODUCERS", claude_code.COPIED_FORK_PRODUCERS - {"2.1.271"}
        )
        patch.setattr(
            claude_code,
            "STOP_HOOK_LINK_PRODUCERS",
            claude_code.STOP_HOOK_LINK_PRODUCERS - {"2.1.271"},
        )
        with pytest.raises(ValueError, match="verified fork boundary"):
            parse_file(source, SourceSystem.CLAUDE_CODE)
        decoded = parse_upload_batch(body)
    assert decoded.parsed.records == parsed.records
    assert decoded.parsed.parent_conversation_id == CHILD
