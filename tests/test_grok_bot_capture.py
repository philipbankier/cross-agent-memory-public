from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory import grok_bot_capture as capture
from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CreateDeviceEnrollmentRequest,
    MemoryApplication,
    RegisterSourceAccountRequest,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.models import Authority, Capability, ClientKind, Scope, SourceSystem
from cross_assistant_memory.storage import Ledger
from cross_assistant_memory.uploads import parse_upload_batch

BOT = "abcdef00-0000-4000-8000-000000000001"


def _capture_case(root: Path) -> tuple[MemoryApplication, ApplicationPrincipal, str]:
    application = MemoryApplication(Ledger(Settings(root)))
    admin = ApplicationPrincipal.local_admin("local:synthetic-grok-test")
    now = datetime.now(UTC)
    enrollment = application.create_device_enrollment(
        admin,
        CreateDeviceEnrollmentRequest(
            label="Synthetic Grok cloud",
            platform="Linux",
            expires_at=now + timedelta(minutes=10),
            credential_expires_at=now + timedelta(days=1),
        ),
    )
    redeemed = application.redeem_device_enrollment(cast(str, enrollment["code"]))
    principal = ApplicationPrincipal(
        principal_id=redeemed["client"]["client_id"],
        kind=ClientKind.COLLECTOR,
        capabilities=frozenset({Capability.SOURCE_UPLOAD, Capability.MEMORY_STATUS}),
        device_id=redeemed["device"]["device_id"],
    )
    account = application.register_source_account(
        admin,
        RegisterSourceAccountRequest(
            device_id=redeemed["device"]["device_id"],
            source_system=SourceSystem.GROK_BOT,
            account_label="synthetic-grok-owner",
            scope=Scope.USER_GLOBAL,
            project_id=None,
        ),
    )
    return application, principal, account["source_account_id"]


def _value() -> dict[str, object]:
    return {
        "format_version": 1,
        "bot_id": BOT,
        "surface": "operator_enrolled_personal_app_chat",
        "kind": "reply_request",
        "native_tool_call_id": "call-synthetic-1",
        "content_text": "Synthetic Bot capture beacon.",
        "end_turn": True,
        "delivery": "requested_not_verified",
        "native_conversation_id": None,
        "native_author_id": None,
        "native_occurred_at": None,
    }


def test_capture_keeps_bot_scope_distinct_from_native_conversation_identity() -> None:
    observation = capture.parse_grok_bot_capture_record(json.dumps(_value()).encode())
    assert observation.bot_id == BOT
    assert observation.conversation_id == f"grok-bot-app:{BOT}"
    assert observation.native_conversation_id is None
    assert observation.native_author_id is None
    assert observation.native_occurred_at is None
    assert observation.delivery == "requested_not_verified"
    assert "beacon" not in repr(observation)
    assert json.loads(observation.canonical_bytes()) == _value()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("format_version", True),
        ("bot_id", "display name"),
        ("bot_id", BOT.upper()),
        ("surface", "group"),
        ("kind", "thinking"),
        ("end_turn", 1),
        ("delivery", "delivered"),
        ("native_conversation_id", BOT),
        ("native_author_id", "owner"),
        ("native_occurred_at", "2026-10-30T00:00:00Z"),
        ("content_text", "[private] synthetic"),
        ("content_text", "[no-memory] synthetic"),
        ("content_text", "xai-" + "0" * 32),
        ("native_tool_call_id", "invalid\naddress"),
    ],
)
def test_capture_refuses_unsupported_authority_scope_and_private_content(
    key: str, value: object
) -> None:
    source = _value()
    source[key] = value
    with pytest.raises(ValueError) as error:
        capture.parse_grok_bot_capture_record(json.dumps(source).encode())
    assert "synthetic" not in str(error.value)
    assert "xai-" not in str(error.value)


def test_capture_refuses_duplicate_and_unknown_fields() -> None:
    module = capture
    source = json.dumps(_value()).encode()
    for raw in (
        source.replace(b'"format_version": 1', b'"format_version": 1, "format_version": 1'),
        source[:-1] + b', "thinking": "synthetic secret"}',
        b"x" * (128 * 1024 + 1),
    ):
        with pytest.raises(ValueError):
            module.parse_grok_bot_capture_record(raw)


def test_grok_bot_parser_does_not_turn_a_send_into_execution_or_invent_a_timestamp() -> None:
    module = capture
    source = json.dumps(_value()).encode()
    parsed = module.parse_grok_bot_capture(source, Path("/synthetic/observation.json"))
    assert parsed.source_system is SourceSystem.GROK_BOT
    (record,) = parsed.records
    assert record.raw_record == source
    assert record.authority is Authority.ASSISTANT_OUTPUT
    assert record.event_type == "native_reply_request"
    assert record.actor_kind == "assistant"
    assert record.occurred_at is None
    assert record.message_id == "call-synthetic-1"
    assert record.message_id_kind == "native_tool_call_id"
    assert record.content_text == _value()["content_text"]


def test_capture_roundtrips_through_the_existing_native_upload_protocol() -> None:
    module = capture
    observation = module.parse_grok_bot_capture_record(json.dumps(_value()).encode())
    body = module.build_grok_bot_capture_upload(
        observation, source_account_id="source_account:" + "0" * 64
    )
    batch = parse_upload_batch(body)
    assert batch.parsed.source_system is SourceSystem.GROK_BOT
    assert batch.parsed.records[0].content_text == observation.content_text
    assert batch.parsed.records[0].raw_record == observation.canonical_bytes()
    assert batch.parsed.records[0].message_id_kind == "native_tool_call_id"
    assert batch.parsed.records[0].occurred_at is None
    assert batch.parsed.captured_at is None
    assert body == module.build_grok_bot_capture_upload(
        observation, source_account_id="source_account:" + "0" * 64
    )


def test_grok_bot_capture_is_not_a_grok_build_or_web_record(tmp_path: Path) -> None:
    from cross_assistant_memory.ingest import parse_file

    path = tmp_path / "observation.json"
    path.write_bytes(json.dumps(_value()).encode())
    parsed = parse_file(path, SourceSystem.GROK_BOT)
    assert parsed.parser_name == "grok-bot-native-observation"
    assert parsed.conversation_id.startswith("grok-bot-app:")
    assert parsed.records[0].assistant == "grok_bot"


def test_user_role_text_is_verbatim_observation_not_verified_human_authorship(
    tmp_path: Path,
) -> None:
    text = (
        "<timestamp>2026-10-30T12:00:00Z</timestamp>\n<user_query>\n"
        "[t1u]\n[Sent from machine synthetic-machine]\nSynthetic user text.\n</user_query>"
    )
    observation = capture.GrokBotUserTextObservation(BOT, text)
    raw = observation.canonical_bytes()
    parsed = capture.parse_grok_bot_capture(raw, Path("/synthetic/user.json"))
    (record,) = parsed.records
    assert record.content_text == text
    assert record.actor_kind == "source"
    assert record.authority is Authority.TOOL_OBSERVATION
    assert record.event_type == "native_user_role_text"
    assert record.message_id is None and record.message_id_kind is None
    assert record.occurred_at is None and record.turn_id is None
    assert "Synthetic" not in repr(observation)
    assert capture.parse_grok_bot_capture_record(raw) == observation
    application, principal, account = _capture_case(tmp_path / "node")
    body = capture.build_grok_bot_capture_upload(observation, source_account_id=account)
    assert parse_upload_batch(body).parsed.records[0].raw_record == raw
    assert application.upload_batch(principal, parse_upload_batch(body))["status"] == "applied"
    hit = Ledger(Settings(tmp_path / "node"), read_only=True).search("Synthetic user text")[0]
    assert hit.authority == Authority.TOOL_OBSERVATION.value


@pytest.mark.parametrize(
    "text", ["[private] synthetic", "[no-memory] synthetic", "xai-" + "0" * 32]
)
def test_user_role_observation_uses_the_existing_privacy_checks(text: str) -> None:
    with pytest.raises(ValueError):
        capture.GrokBotUserTextObservation(BOT, text)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("native_author_id", "owner"),
        ("native_tool_call_id", "invented-user-id"),
        ("native_conversation_id", BOT),
        ("native_occurred_at", "2026-10-30T12:00:00Z"),
        ("end_turn", True),
        ("delivery", "delivered"),
        ("surface", "shared_group"),
    ],
)
def test_user_text_envelope_cannot_smuggle_identity_or_delivery(key: str, value: object) -> None:
    raw = capture.GrokBotUserTextObservation(BOT, "Synthetic role observation.").canonical_bytes()
    loaded = json.loads(raw)
    loaded[key] = value
    with pytest.raises(ValueError):
        capture.parse_grok_bot_capture_record(json.dumps(loaded).encode())


def test_grok_bot_admission_replay_exact_evidence_and_restore(tmp_path: Path) -> None:
    from cross_assistant_memory.backup import create_offline_clone, create_snapshot, verify_snapshot

    root = tmp_path / "node"
    application, principal, account = _capture_case(root)
    module = capture
    observation = module.parse_grok_bot_capture_record(json.dumps(_value()).encode())
    body = module.build_grok_bot_capture_upload(observation, source_account_id=account)
    batch = parse_upload_batch(body)
    admitted = application.upload_batch(principal, batch)
    assert admitted["status"] == "applied"
    ledger = Ledger(Settings(root), read_only=True)
    hits = ledger.search("capture beacon")
    assert len(hits) == 1
    assert hits[0].source_system == "grok_bot"
    evidence = ledger.get_evidence(hits[0].event_id)
    assert evidence["raw_record_access"] == "exact"
    assert evidence["raw_record"].encode() == observation.canonical_bytes()
    assert evidence["occurred_at"] is None
    assert evidence["authority"] == Authority.ASSISTANT_OUTPUT.value
    assert evidence["source_account_id"] == account
    before = ledger.generation_digest()
    assert application.upload_batch(principal, batch)["status"] == "already_applied"
    assert Ledger(Settings(root), read_only=True).generation_digest() == before
    snapshot = tmp_path / "snapshot"
    create_snapshot(Settings(root), snapshot, max_bytes=4 * 1024 * 1024)
    assert verify_snapshot(snapshot)["status"] == "verified"
    clone = tmp_path / "restored"
    create_offline_clone(snapshot, clone)
    restored = Ledger(Settings(clone), read_only=True)
    assert restored.get_evidence(hits[0].event_id)["raw_record"] == evidence["raw_record"]
    assert restored.search("capture beacon")[0].event_id == hits[0].event_id


def test_grok_bot_upload_requires_capture_capability_and_correct_device(tmp_path: Path) -> None:
    application, principal, account = _capture_case(tmp_path / "node")
    module = capture
    observation = module.parse_grok_bot_capture_record(json.dumps(_value()).encode())
    batch = parse_upload_batch(
        module.build_grok_bot_capture_upload(observation, source_account_id=account)
    )
    query_only = ApplicationPrincipal(
        principal.principal_id,
        ClientKind.ASSISTANT,
        frozenset(
            {Capability.MEMORY_SEARCH, Capability.MEMORY_EVIDENCE_READ, Capability.MEMORY_STATUS}
        ),
    )
    with pytest.raises(PermissionError):
        application.upload_batch(query_only, batch)
    other = ApplicationPrincipal(
        principal.principal_id,
        ClientKind.COLLECTOR,
        principal.capabilities,
        "device:other-synthetic-device",
    )
    with pytest.raises(PermissionError):
        application.upload_batch(other, batch)


@pytest.mark.parametrize("captured_at", ["invalid", "2026-10-30T12:00:00", True])
def test_capture_time_cannot_be_an_unverified_native_timestamp(captured_at: object) -> None:
    observation = capture.parse_grok_bot_capture_record(json.dumps(_value()).encode())
    with pytest.raises(ValueError):
        capture.build_grok_bot_capture_upload(
            observation,
            source_account_id="synthetic",
            captured_at=cast(str, captured_at),
        )


def test_grok_bot_registered_status_does_not_claim_a_running_routine(tmp_path: Path) -> None:
    application, _principal, _account = _capture_case(tmp_path / "node")
    overview = application.operations_overview(ApplicationPrincipal.local_admin("local:synthetic"))
    source = next(item for item in overview["sources"] if item["source_system"] == "grok_bot")
    assert source["sync"]["state"] == "status_unavailable"
    assert source["sync"]["freshness_guaranteed"] is False
    assert source["sync"]["expected_cadence_minutes"] is None


def test_capture_scope_does_not_include_its_collector_or_unselected_bots() -> None:
    assert hasattr(capture, "GrokBotCaptureScope"), "Grok Bot capture enrollment scope is missing"
    scope = capture.GrokBotCaptureScope(
        "source_account:" + "0" * 64, (BOT,), "00000000-0000-4000-8000-000000000002"
    )
    assert scope.allows(BOT)
    assert not scope.allows(scope.collector_bot_id)
    assert not scope.allows("00000000-0000-4000-8000-000000000003")
    with pytest.raises(ValueError):
        capture.GrokBotCaptureScope("source_account:" + "0" * 64, (BOT,), BOT)


def test_transcript_capture_uses_only_the_encrypted_existing_queue(tmp_path: Path) -> None:
    from cross_assistant_memory.collector import CollectorNodeConfig, CollectorQueueConfig
    from cross_assistant_memory.collector_queue import CollectorQueue, QueueFailureCode
    from cross_assistant_memory.models import UploadReceipt
    from cross_assistant_memory.uploads import validate_upload_receipt

    assert hasattr(capture, "capture_transcript_page"), "Grok Bot queue bridge is missing"
    root = tmp_path / "queue"
    root.mkdir(mode=0o700)
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    config = CollectorQueueConfig(root, secrets / "key.tink", 1024 * 1024, 86400)
    queue = CollectorQueue.initialize(config)
    application, principal, account = _capture_case(tmp_path / "node")
    scope = capture.GrokBotCaptureScope(account, (BOT,), "00000000-0000-4000-8000-000000000002")
    records = [
        {
            "role": "assistant",
            "message": {
                "content": [
                    {"type": "thinking", "thinking": "synthetic excluded reasoning"},
                    {
                        "type": "tool_use",
                        "id": "call-synthetic-1",
                        "name": "SendToUser",
                        "input": {
                            "content": "Synthetic capture recovery beacon.",
                            "end_turn": True,
                        },
                    },
                ]
            },
        },
    ]
    raw = (
        f'<cursor_untrusted_data_1337 source="ReadTranscript">\n\n'
        f'Transcript of agent "Synthetic" ({BOT}), positions 0\u20130 of 1:\n'
        + json.dumps(records[0])
        + "\n\n</cursor_untrusted_data_1337>\n"
    ).encode()
    first = capture.capture_transcript_page(queue, raw, bot_id=BOT, scope=scope, now_epoch=1000)
    assert first.pending_replies == 1
    assert first.already_acknowledged == 0
    again = capture.capture_transcript_page(queue, raw, bot_id=BOT, scope=scope, now_epoch=1001)
    assert again.pending_replies == 1
    assert queue.status(now_epoch=1001).queued_items == 1
    due = queue.due_uploads(now_epoch=1001)
    assert len(due) == 1
    parsed = parse_upload_batch(due[0].body)
    assert parsed.parsed.records[0].content_text == "Synthetic capture recovery beacon."
    assert b"excluded reasoning" not in due[0].body
    stored = queue.database_path.read_bytes()
    assert b"Synthetic capture recovery beacon" not in stored
    assert b"excluded reasoning" not in stored
    reopened = CollectorQueue.open(config)
    assert reopened.due_uploads(now_epoch=1002)[0].body == due[0].body
    with pytest.raises(PermissionError):
        capture.capture_transcript_page(queue, raw, bot_id=scope.collector_bot_id, scope=scope)
    credential = secrets / "credential"
    credential.write_text("synthetic-authentication-fixture")
    credential.chmod(0o600)
    node = CollectorNodeConfig("http://127.0.0.1:8765/upload/batches", credential, 10)
    assert hasattr(capture, "flush_queued_grok_bot_capture"), "Grok Bot queue flush is missing"

    def offline(_node: CollectorNodeConfig, _credential: str, _body: bytes) -> QueueFailureCode:
        return QueueFailureCode.NETWORK_UNREACHABLE

    first_flush = capture.flush_queued_grok_bot_capture(
        reopened,
        node,
        scope=scope,
        transport=offline,
        now_epoch=1002,
    )
    assert first_flush.failed == 1
    assert reopened.status(now_epoch=1003).queued_items == 1

    def send(_node: CollectorNodeConfig, _credential: str, body: bytes) -> None:
        batch = parse_upload_batch(body)
        receipt = application.upload_batch(principal, batch)
        validate_upload_receipt(
            batch,
            UploadReceipt.from_dict(receipt),
            status_code=201 if receipt["status"] == "applied" else 200,
        )

    def interrupted(node: CollectorNodeConfig, credential: str, body: bytes) -> None:
        send(node, credential, body)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        capture.flush_queued_grok_bot_capture(
            reopened,
            node,
            scope=scope,
            transport=interrupted,
            now_epoch=1010,
        )
    after_interrupt = CollectorQueue.open(config)
    assert after_interrupt.due_uploads(now_epoch=1011)[0].body == due[0].body
    resumed = capture.flush_queued_grok_bot_capture(
        after_interrupt,
        node,
        scope=scope,
        transport=send,
        now_epoch=1011,
    )
    assert resumed.uploaded == 1
    assert after_interrupt.status(now_epoch=1011).queued_items == 0
    replay = capture.capture_transcript_page(
        after_interrupt,
        raw,
        bot_id=BOT,
        scope=scope,
        now_epoch=1012,
    )
    assert replay.pending_replies == 0 and replay.already_acknowledged == 1
    assert len(Ledger(Settings(tmp_path / "node"), read_only=True).search("recovery beacon")) == 1
