"""Synthetic installed-package coverage, not client, provider, or owner acceptance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, cast
from zipfile import ZipFile

import pytest

from cross_assistant_memory.backup import create_offline_clone, create_snapshot
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import NATIVE_SOURCE_SYSTEMS, parse_file
from cross_assistant_memory.models import Authority, Scope, SourceSystem
from cross_assistant_memory.runtime_provenance import runtime_code_revision
from cross_assistant_memory.storage import Ledger
from cross_assistant_memory.web_export_limits import DEFAULT_WEB_EXPORT_LIMITS
from cross_assistant_memory.web_exports import (
    apply_web_export_plans,
    authorize_web_export_schema,
    extract_web_export_member,
    prepare_web_export_plan,
    verify_web_export_plan,
)

MIB = 1024 * 1024
WEB_SOURCES = (SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB, SourceSystem.GROK_WEB)
LIMITS = replace(DEFAULT_WEB_EXPORT_LIMITS, max_temp_disk_bytes=2 * MIB)
EXCLUSIONS = {"private_marker": 1, "no_memory_marker": 1}


def _write_source(root: Path, source: SourceSystem) -> Path:
    conversation = f"synthetic-{source.value}"
    records: list[dict[str, Any]] = []
    for index, (role, text) in enumerate(
        (
            ("user", f"Roundtripbeacon {source.value} decision."),
            ("assistant", f"Roundtripbeacon {source.value} confirmation."),
            ("user", f"[private] Privatecanary {source.value}."),
            ("user", f"[no-memory] Nomemorycanary {source.value}."),
        )
    ):
        identifier = f"{conversation}-{index}"
        parent = f"{conversation}-{index - 1}" if index else None
        timestamp = f"2026-10-01T12:00:0{index}Z"
        if source is SourceSystem.CODEX:
            record = {
                "timestamp": timestamp,
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": role,
                    "phase": "final_answer" if role == "assistant" else None,
                    "content": [
                        {"type": "input_text" if role == "user" else "output_text", "text": text}
                    ],
                },
            }
        elif source is SourceSystem.CLAUDE_CODE:
            record = {
                "type": role,
                "sessionId": conversation,
                "entrypoint": "claude-desktop",
                "uuid": identifier,
                "parentUuid": parent,
                "timestamp": timestamp,
                "message": {"role": role, "content": [{"type": "text", "text": text}]},
            }
        elif source is SourceSystem.GROK_BUILD:
            record = {
                "timestamp": timestamp,
                "method": "session/update",
                "params": {
                    "sessionId": conversation,
                    "update": {
                        "sessionUpdate": (
                            "user_message_chunk" if role == "user" else "agent_message_chunk"
                        ),
                        "content": {"type": "text", "text": text},
                        "_meta": {"promptIndex": index},
                    },
                },
            }
        elif source is SourceSystem.CHATGPT_WEB:
            record = {
                "parent": parent,
                "message": {
                    "id": identifier,
                    "author": {"role": role},
                    "create_time": timestamp,
                    "content": {"content_type": "text", "parts": [text]},
                },
            }
        elif source is SourceSystem.CLAUDE_WEB:
            record = {
                "uuid": identifier,
                "parent_message_uuid": parent,
                "sender": "human" if role == "user" else "assistant",
                "created_at": timestamp,
                "text": text,
            }
        else:
            assert source is SourceSystem.GROK_WEB
            record = {
                "response": {
                    "_id": identifier,
                    "parent_response_id": parent,
                    "sender": "human" if role == "user" else "assistant",
                    "create_time": timestamp,
                    "message": text,
                }
            }
        records.append(record)

    if source in NATIVE_SOURCE_SYSTEMS:
        if source is SourceSystem.CODEX:
            records.insert(
                0, {"type": "session_meta", "payload": {"id": conversation, "source": "vscode"}}
            )
        path = root / f"{source.value}.jsonl"
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    else:
        document: object
        if source is SourceSystem.CHATGPT_WEB:
            document = [
                {
                    "id": conversation,
                    "mapping": {
                        f"{conversation}-{index}": record for index, record in enumerate(records)
                    },
                }
            ]
        elif source is SourceSystem.CLAUDE_WEB:
            document = [{"uuid": conversation, "chat_messages": records}]
        else:
            document = {
                "conversations": [{"conversation": {"id": conversation}, "responses": records}]
            }
        path = root / f"{source.value}.zip"
        with ZipFile(path, "w") as archive:
            archive.writestr("conversations.json", json.dumps(document))
    path.chmod(0o600)
    return path


def _clone(settings: Settings, output: Path) -> Ledger:
    snapshot = output.with_name(f"{output.name}-snapshot")
    create_snapshot(settings, snapshot, max_bytes=4 * MIB)
    create_offline_clone(snapshot, output)
    return Ledger(Settings(output))


def _plan(
    ledger: Ledger,
    source: SourceSystem,
    account: str,
    archive: Path,
    member: Path,
    output: Path,
    revision: str,
) -> dict[str, Any]:
    plan = prepare_web_export_plan(
        source_system=source,
        source_account=account,
        member_path=member,
        archive_path=archive,
        archive_member="conversations.json",
        output=output,
        scope=Scope.USER_GLOBAL,
        project_id=None,
        expected_ledger_generation=ledger.generation_digest(),
        code_revision=revision,
        limits=LIMITS,
    )
    assert plan["admission_counts"] == {"included": 2, **EXCLUSIONS}
    assert plan["malformed_records"] == 0
    assert plan["unknown_record_type_conversation_counts"] == {}
    return plan


def _assert_evidence(ledger: Ledger, source: SourceSystem, path: Path) -> set[str]:
    parsed = parse_file(path, source)
    assert not parsed.unknown_record_types
    assert parsed.malformed_records == 0
    assert len(parsed.records) == 4
    assert [record.actor_kind for record in parsed.records[:2]] == ["user", "assistant"]
    assert [record.authority for record in parsed.records[:2]] == [
        Authority.USER_ASSERTION,
        Authority.ASSISTANT_OUTPUT,
    ]
    expected = {record.content_text: record for record in parsed.records[:2]}
    results = ledger.search(f"Roundtripbeacon {source.value}", limit=20)
    assert len(results) == 2
    assert {result.content_text for result in results} == set(expected)
    for result in results:
        record = expected[result.content_text]
        evidence = ledger.get_evidence(result.event_id)
        assert result.source_system == evidence["source_system"] == source.value
        assert evidence["conversation_id"] == parsed.conversation_id
        assert evidence["actor_kind"] == record.actor_kind
        assert evidence["authority"] == record.authority.value
        assert evidence["assistant"] == record.assistant
        assert evidence["occurred_at"] == record.occurred_at
        assert evidence["content_text"] == record.content_text
        assert evidence["raw_record_access"] == "exact"
        assert evidence["raw_record"].encode() == record.raw_record
        assert path.read_bytes()[record.byte_start : record.byte_end] == record.raw_record
        assert (evidence["byte_start"], evidence["byte_end"]) == (
            record.byte_start,
            record.byte_end,
        )
        if source in WEB_SOURCES:
            assert evidence["source_account_id"] is not None
            assert evidence["source_device_id"] is not None
            assert evidence["source_locator"] is not None
            assert evidence["web_export"] is not None
    return {result.event_id for result in results}


def test_six_source_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAM_HOME", str(tmp_path / "unused-live-root"))
    revision = runtime_code_revision()
    ledger = Ledger(Settings(tmp_path / "seed"))
    event_ids: set[str] = set()
    for source in SourceSystem:
        if source not in NATIVE_SOURCE_SYSTEMS:
            continue
        path = _write_source(tmp_path, source)
        parsed = parse_file(path, source)
        report = ledger.ingest(
            parsed, source_account="synthetic", scope=Scope.USER_GLOBAL, project_id=None
        )
        assert report.status == "ingested"
        assert report.inserted_events == 2
        assert report.quarantine_reasons == EXCLUSIONS
        event_ids.update(_assert_evidence(ledger, source, path))
        before = ledger.status()
        replay = ledger.ingest(
            parse_file(path, source),
            source_account="synthetic",
            scope=Scope.USER_GLOBAL,
            project_id=None,
        )
        assert replay.status == "already_ingested"
        assert replay.inserted_events == 0
        assert ledger.status() == before

    # Test-only enrollment uses the existing API; no external credentials or accounts.
    now = datetime.now(UTC)
    enrollment = ledger.create_device_enrollment(
        label="synthetic",
        platform="synthetic",
        expires_at=now + timedelta(minutes=10),
        credential_expires_at=now + timedelta(days=1),
        created_by="local:synthetic",
    )
    device = ledger.redeem_device_enrollment(cast(str, enrollment["code"]))["device"]
    for source in WEB_SOURCES:
        account = ledger.register_source_account(
            device_id=cast(str, device["device_id"]),
            source_system=source,
            account_label="synthetic",
            scope=Scope.USER_GLOBAL,
            project_id=None,
            created_by="local:synthetic",
        )["source_account_id"]
        archive = _write_source(tmp_path, source)
        member = tmp_path / f"{source.value}.json"
        extracted = extract_web_export_member(
            archive_path=archive,
            archive_member="conversations.json",
            expected_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            output=member,
            limits=LIMITS,
        )
        assert extracted["status"] == "extracted"
        ledger = _clone(ledger.settings, tmp_path / f"{source.value}-review")
        plan = _plan(
            ledger,
            source,
            account,
            archive,
            member,
            tmp_path / f"{source.value}-schema-plan",
            revision,
        )
        manifest = Path(plan["manifest_path"])
        manifest_sha256 = cast(str, plan["manifest_sha256"])
        assert (
            verify_web_export_plan(
                manifest_path=manifest,
                expected_manifest_sha256=manifest_sha256,
                code_revision=revision,
            )["status"]
            == "verified"
        )
        before_authorization = ledger.status()
        with pytest.raises(PermissionError, match="schema authorization"):
            apply_web_export_plans(
                ledger.settings,
                manifest_paths=[manifest],
                expected_manifest_sha256s=[manifest_sha256],
                code_revision=revision,
                execute=True,
                offline_clone=True,
            )
        assert ledger.status() == before_authorization
        authorized = authorize_web_export_schema(
            ledger.settings,
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha256,
            code_revision=revision,
            authorized_by="local:synthetic",
            execute=True,
            offline_clone=True,
        )
        assert authorized["status"] == "authorized"
        assert authorized["replan_required"] is True
        # Authorization changes the generation; create its real marker, then replan.
        ledger = _clone(ledger.settings, tmp_path / f"{source.value}-admit")
        output = tmp_path / f"{source.value}-import-plan"
        plan = _plan(ledger, source, account, archive, member, output, revision)
        apply = partial(
            apply_web_export_plans,
            ledger.settings,
            manifest_paths=[Path(plan["manifest_path"])],
            expected_manifest_sha256s=[cast(str, plan["manifest_sha256"])],
            code_revision=revision,
            offline_clone=True,
        )
        preview_state = ledger.status()
        preview = apply(execute=False)
        assert preview["status"] == "preview"
        assert preview["accepted_records"] == preview["quarantined_records"] == 2
        assert ledger.status() == preview_state
        applied = apply(execute=True)
        assert applied["status"] == "applied_offline"
        assert applied["replayed"] is False
        assert applied["inserted_events"] == 2
        assert applied["new_quarantined_records"] == 2
        (split,) = (output / "conversations").glob("*.json")
        event_ids.update(_assert_evidence(ledger, source, split))
        before = ledger.status()
        receipt = Path(applied["receipt_path"]).read_bytes()
        replayed = apply(execute=True)
        assert replayed["replayed"] is True
        assert replayed["receipt_sha256"] == applied["receipt_sha256"]
        assert Path(replayed["receipt_path"]).read_bytes() == receipt
        assert ledger.status() == before
        assert (
            sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) < 150 * MIB
        )

    # Reopen the installed ledger and prove native + web attribution in one query.
    ledger = Ledger(ledger.settings, read_only=True)
    results = ledger.search("Roundtripbeacon", limit=20)
    assert len(results) == len(event_ids) == 12
    assert {result.event_id for result in results} == event_ids
    assert {result.source_system for result in results} == {source.value for source in SourceSystem}
    assert {result.authority for result in results} == {
        Authority.USER_ASSERTION.value,
        Authority.ASSISTANT_OUTPUT.value,
    }
    assert ledger.status()["source_files"] == 6
    assert ledger.status()["events"] == ledger.status()["quarantined_records"] == 12
    assert not ledger.search("Privatecanary")
    assert not ledger.search("Nomemorycanary")
    for path in (ledger.settings.database_path, *ledger.settings.object_root.glob("*/*")):
        raw = path.read_bytes().lower()
        assert b"privatecanary" not in raw
        assert b"nomemorycanary" not in raw
