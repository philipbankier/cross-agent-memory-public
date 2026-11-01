from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CreateDeviceEnrollmentRequest,
    MemoryApplication,
    RegisterSourceAccountRequest,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import FilesystemObjectBackend, RootKey
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.grok_bot_capture import (
    GrokBotStructuredRequestObservation,
    build_grok_bot_capture_upload,
)
from cross_assistant_memory.grok_bot_outward import canonical_outward_request
from cross_assistant_memory.models import Capability, ClientKind, Scope, SourceSystem
from cross_assistant_memory.native_attachments import (
    NativeAttachmentUpload,
    attach_native_artifact,
)
from cross_assistant_memory.publication_work import (
    EvidencePublicationPolicy,
    EvidencePublicationYielded,
)
from cross_assistant_memory.storage import Ledger
from cross_assistant_memory.uploads import UploadBatch, parse_upload_batch

BOT = "abcdef00-0000-4000-8000-000000000001"


def capture_case(root: Path) -> tuple[MemoryApplication, ApplicationPrincipal, str]:
    application = MemoryApplication(Ledger(Settings(root)))
    admin = ApplicationPrincipal.local_admin("local:synthetic-grok-artifacts")
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
            device_id=cast(str, principal.device_id),
            source_system=SourceSystem.GROK_BOT,
            account_label="synthetic-grok-owner",
            scope=Scope.USER_GLOBAL,
            project_id=None,
        ),
    )
    return application, principal, account["source_account_id"]


def reference() -> GrokBotStructuredRequestObservation:
    kind, text = canonical_outward_request(
        {"type": "attachment", "url": "file:///workspace/results/synthetic.md"}
    )
    return GrokBotStructuredRequestObservation(BOT, "synthetic-artifact", text, kind)


def encrypted_case(
    root: Path,
) -> tuple[MemoryApplication, ApplicationPrincipal, str, EncryptedEvidenceReader]:
    _app, principal, account = capture_case(root)
    reader = EncryptedEvidenceReader(
        FilesystemObjectBackend(root.parent / "provider"),
        RootKey.generate(),
        1024 * 1024,
        2 * 1024 * 1024,
    )
    application = MemoryApplication(
        Ledger(
            Settings(root),
            encrypted_evidence_reader=reader,
            evidence_publication_policy=EvidencePublicationPolicy(4 * 1024 * 1024, 100),
        )
    )
    return application, principal, account, reader


def admit(
    app: MemoryApplication, principal: ApplicationPrincipal, batch: UploadBatch
) -> dict[str, object]:
    for _ in range(4):
        try:
            return app.upload_batch(principal, batch)
        except EvidencePublicationYielded:
            continue
    raise AssertionError("bounded publication did not finish")


def test_attachment_transport_preserves_reference_and_legacy_envelope() -> None:
    import hashlib

    ref = reference()
    body = build_grok_bot_capture_upload(ref, source_account_id="source_account:" + "0" * 64)
    attachment = NativeAttachmentUpload(
        0, hashlib.sha256(ref.canonical_bytes()).hexdigest(), "text/markdown", b"Synthetic file.\n"
    )
    combined = attach_native_artifact(body, attachment)
    parsed = parse_upload_batch(combined)
    assert parsed.native_attachments == (attachment,)
    assert parsed.parsed.records[0].raw_record == ref.canonical_bytes()
    assert json.loads(body)["format_version"] == 2
    assert json.loads(combined)["format_version"] == 3
    assert parse_upload_batch(body).native_attachments == ()
    assert combined == attach_native_artifact(body, attachment)
    assert "Synthetic file" not in repr(attachment)


@pytest.mark.parametrize("tamper", ["digest", "size", "base64", "type", "reference", "extra"])
def test_attachment_wire_fields_are_not_trusted(tamper: str) -> None:
    import hashlib

    ref = reference()
    attachment = NativeAttachmentUpload(
        0, hashlib.sha256(ref.canonical_bytes()).hexdigest(), "text/markdown", b"Synthetic file.\n"
    )
    item = attachment.as_dict()
    if tamper == "digest":
        item["content_sha256"] = "0" * 64
    elif tamper == "size":
        item["byte_length"] = 1
    elif tamper == "base64":
        item["data_base64"] = "not base64"
    elif tamper == "type":
        item["record_ordinal"] = True
    elif tamper == "reference":
        item["reference_sha256"] = "wrong"
    else:
        item["extra"] = "private-canary"
    with pytest.raises(ValueError) as caught:
        NativeAttachmentUpload.from_dict(item)
    assert "private-canary" not in str(caught.value)


def test_attachment_upload_cannot_attach_to_a_different_reference() -> None:
    ref = reference()
    body = build_grok_bot_capture_upload(ref, source_account_id="source_account:" + "0" * 64)
    attachment = NativeAttachmentUpload(0, "0" * 64, "text/markdown", b"Synthetic file.\n")
    with pytest.raises(ValueError, match="reference"):
        attach_native_artifact(body, attachment)


def test_attachment_admission_delivery_replay_and_recovery(tmp_path: Path) -> None:
    import hashlib

    from cross_assistant_memory.backup import create_offline_clone, create_snapshot, verify_snapshot
    from cross_assistant_memory.config import Settings
    from cross_assistant_memory.storage import Ledger

    root = tmp_path / "node"
    app, principal, account, reader = encrypted_case(root)
    ref = reference()
    data = b"Unique synthetic file payload must not become another event.\n"
    attachment = NativeAttachmentUpload(
        0, hashlib.sha256(ref.canonical_bytes()).hexdigest(), "text/markdown", data
    )
    body = build_grok_bot_capture_upload(ref, source_account_id=account)
    combined = parse_upload_batch(attach_native_artifact(body, attachment))
    assert app.upload_batch(principal, parse_upload_batch(body))["status"] == "applied"
    ledger = Ledger(Settings(root), read_only=True, encrypted_evidence_reader=reader)
    parent = ledger.search("synthetic.md")[0]
    assert admit(app, principal, combined)["status"] in {"applied", "already_applied"}
    evidence = ledger.get_evidence(parent.event_id)
    manifests = evidence["native_attachments"]["attachment_manifests"]
    assert len(manifests) == 1
    assert manifests[0]["content_sha256"] == hashlib.sha256(data).hexdigest()
    assert manifests[0]["byte_length"] == len(data)
    assert manifests[0]["content_access"] == "metadata_only"
    assert manifests[0]["original_sent_bytes_verified"] is False
    assert "Unique synthetic file payload" not in json.dumps(evidence)
    assert ledger.search("Unique synthetic file payload") == []
    from cross_assistant_memory.models import Access

    with pytest.raises(KeyError):
        ledger.get_evidence(parent.event_id, allowed_accesses=[Access.ASSISTANT_PRIVATE])
    before = ledger.generation_digest()
    assert app.upload_batch(principal, combined)["status"] == "already_applied"
    assert Ledger(Settings(root), read_only=True).generation_digest() == before
    snapshot = tmp_path / "snapshot"
    create_snapshot(
        Settings(root), snapshot, max_bytes=4 * 1024 * 1024, encrypted_evidence_reader=reader
    )
    assert verify_snapshot(snapshot)["status"] == "verified"
    clone = tmp_path / "restored"
    create_offline_clone(snapshot, clone)
    restored = Ledger(Settings(clone), read_only=True).get_evidence(parent.event_id)
    assert restored["native_attachments"] == evidence["native_attachments"]
    digest = hashlib.sha256(data).hexdigest()
    assert (clone / "objects" / "sha256" / digest[:2] / digest).read_bytes() == data


@pytest.mark.parametrize(
    "data", [b"[private] excluded", b"[no-memory] excluded", b"xai-" + b"x" * 25, b"\xff"]
)
def test_excluded_text_cannot_become_opaque_media(data: bytes) -> None:
    with pytest.raises(ValueError, match="admission"):
        NativeAttachmentUpload(0, "0" * 64, "text/markdown", data)


def test_opaque_media_is_encrypted_and_replayed_without_an_idle_plaintext_copy(
    tmp_path: Path,
) -> None:
    from cross_assistant_memory.evidence_locations import read_location

    app, principal, account, reader = encrypted_case(tmp_path / "node")
    settings = Settings(tmp_path / "node")
    kind, text = canonical_outward_request(
        {"type": "attachment", "url": "file:///workspace/results/synthetic.png"}
    )
    ref = GrokBotStructuredRequestObservation(BOT, "synthetic-image", text, kind)
    data = b"\x89PNG\r\n\x1a\n\xff\x00synthetic opaque image"
    batch = parse_upload_batch(
        attach_native_artifact(
            build_grok_bot_capture_upload(ref, source_account_id=account),
            NativeAttachmentUpload(
                0, hashlib.sha256(ref.canonical_bytes()).hexdigest(), "image/png", data
            ),
        )
    )
    for _ in range(4):
        try:
            result = app.upload_batch(principal, batch)
            break
        except EvidencePublicationYielded:
            continue
    else:
        pytest.fail("bounded publication did not finish")
    assert result["status"] in {"applied", "already_applied"}
    digest = hashlib.sha256(data).hexdigest()
    with closing(sqlite3.connect(settings.database_path)) as connection:
        object_id, storage_kind, relative = connection.execute(
            "SELECT object_id, storage_kind, object_path FROM objects WHERE plaintext_digest = ?",
            (digest,),
        ).fetchone()
        assert storage_kind == "encrypted"
        location = read_location(connection, object_id)
        assert location is not None
        assert (
            reader.read(
                location[1],
                object_id=object_id,
                expected_size=len(data),
                backend_identity_sha256=location[0],
            )
            == data
        )
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM evidence_publication_work").fetchone()[0] == 0
        )
    assert not (settings.data_root / relative).exists()
    assert app.upload_batch(principal, batch)["status"] == "already_applied"


def test_parent_erasure_also_removes_local_attachment(tmp_path: Path) -> None:
    from cross_assistant_memory.models import DeletionKind
    from cross_assistant_memory.storage import exclusive_ledger_writer

    app, principal, account, reader = encrypted_case(tmp_path / "node")
    ref = reference()
    data = b"Synthetic erasable artifact.\n"
    batch = parse_upload_batch(
        attach_native_artifact(
            build_grok_bot_capture_upload(ref, source_account_id=account),
            NativeAttachmentUpload(
                0, hashlib.sha256(ref.canonical_bytes()).hexdigest(), "text/markdown", data
            ),
        )
    )
    admit(app, principal, batch)
    from cross_assistant_memory.backup import create_offline_clone, create_snapshot

    snapshot = tmp_path / "snapshot"
    clone = tmp_path / "restored"
    create_snapshot(Settings(tmp_path / "node"), snapshot, encrypted_evidence_reader=reader)
    create_offline_clone(snapshot, clone)
    settings = Settings(clone)
    ledger = Ledger(settings)
    plan = ledger.plan_deletion(
        kind=DeletionKind.SOURCE_ACCOUNT,
        source_system=SourceSystem.GROK_BOT,
        source_account=account,
        conversation_id=None,
    )
    assert plan["target_counts"]["objects_deleted"] == 2
    with exclusive_ledger_writer(settings) as token:
        writer = Ledger(settings, exclusive_writer_token=token)
        writer.apply_deletion(
            kind=DeletionKind.SOURCE_ACCOUNT,
            source_system=SourceSystem.GROK_BOT,
            source_account_digests=plan["source_account_digests"],
            conversation_digest=None,
            expected_generation_digest=plan["expected_generation_digest"],
            expected_target_digest=plan["target_digest"],
            expected_target_counts=plan["target_counts"],
            plan_sha256="a" * 64,
            authorized_by="local:synthetic",
            authorization_scope="synthetic:delete",
            reason="Synthetic attachment erasure test",
        )
    with closing(sqlite3.connect(settings.database_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM native_attachment_objects").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    digest = hashlib.sha256(data).hexdigest()
    assert not (settings.object_root / digest[:2] / digest).exists()


def test_schema24_upgrade_preserves_existing_generation_and_records(tmp_path: Path) -> None:
    app, principal, account = capture_case(tmp_path / "node")
    app.upload_batch(
        principal,
        parse_upload_batch(build_grok_bot_capture_upload(reference(), source_account_id=account)),
    )
    settings = Settings(tmp_path / "node")
    before = Ledger(settings).generation_digest(schema_version=24)
    with closing(sqlite3.connect(settings.database_path)) as connection, connection:
        connection.execute("DROP TABLE native_attachment_objects")
        connection.execute("DELETE FROM schema_migrations WHERE version = 25")
        connection.execute("INSERT INTO schema_migrations VALUES (24, 'synthetic')")
    with pytest.raises(RuntimeError, match="schema"):
        Ledger(settings)
    upgraded = Ledger(settings, allow_schema_upgrade=True)
    assert upgraded.generation_digest(schema_version=24) == before
    assert len(upgraded.search("synthetic.md")) == 1


def test_artifact_queue_reconnect_does_not_rewind_acknowledged_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cross_assistant_memory import grok_bot_artifacts as artifacts
    from cross_assistant_memory.collector import CollectorNodeConfig, CollectorQueueConfig
    from cross_assistant_memory.collector_queue import CollectorQueue, source_key_for
    from cross_assistant_memory.grok_bot_capture import (
        GrokBotCaptureScope,
        flush_queued_grok_bot_capture,
    )
    from cross_assistant_memory.models import UploadReceipt
    from cross_assistant_memory.uploads import validate_upload_receipt

    app, principal, account, _reader = encrypted_case(tmp_path / "node")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    root = tmp_path / "queue"
    root.mkdir(mode=0o700)
    config = CollectorQueueConfig(root, private / "queue.key", 2 * 1024 * 1024, 86400)
    queue = CollectorQueue.initialize(config)
    credential = private / "credential"
    credential.write_text("synthetic-authentication-fixture")
    credential.chmod(0o600)
    node = CollectorNodeConfig("http://127.0.0.1:8765/upload/batches", credential, 10)
    scope = GrokBotCaptureScope(account, (BOT,), "abcdef00-0000-4000-8000-000000000002")
    ref = reference()
    parent_body = build_grok_bot_capture_upload(ref, source_account_id=account)
    parent = parse_upload_batch(parent_body)
    queue.enqueue_upload(parent_body)

    def send(_node: CollectorNodeConfig, _credential: str, body: bytes) -> None:
        batch = parse_upload_batch(body)
        receipt = admit(app, principal, batch)
        validate_upload_receipt(
            batch,
            UploadReceipt.from_dict(receipt),
            status_code=201 if receipt["status"] == "applied" else 200,
        )

    assert flush_queued_grok_bot_capture(queue, node, scope=scope, transport=send).uploaded == 1
    parent_key = source_key_for(SourceSystem.GROK_BOT, account, parent.source_path_hash)
    before = queue.cursor(parent_key)
    workspace = tmp_path / "workspace"
    (workspace / "results").mkdir(parents=True)
    data = b"Synthetic durable encrypted attachment payload.\n"
    (workspace / "results" / "synthetic.md").write_bytes(data)
    monkeypatch.setattr(artifacts, "WORKSPACE_ROOT", workspace)
    assert (
        artifacts.capture_sent_artifact(queue, ref, scope=scope, max_bytes=4096)["status"]
        == "queued_not_admitted"
    )
    assert queue.cursor(parent_key) == before
    assert data not in queue.database_path.read_bytes()
    pending = queue.due_uploads()[0].body

    def lose_receipt(node: CollectorNodeConfig, credential: str, body: bytes) -> None:
        send(node, credential, body)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        flush_queued_grok_bot_capture(
            queue, node, scope=scope, transport=lose_receipt, preserve_sent_artifacts=True
        )
    reopened = CollectorQueue.open(config)
    assert reopened.due_uploads()[0].body == pending
    assert (
        flush_queued_grok_bot_capture(
            reopened, node, scope=scope, transport=send, preserve_sent_artifacts=True
        ).uploaded
        == 1
    )
    assert reopened.status().queued_items == 0
    assert reopened.cursor(parent_key) == before
    assert (
        artifacts.capture_sent_artifact(reopened, ref, scope=scope, max_bytes=4096)["status"]
        == "already_acknowledged"
    )
    with closing(sqlite3.connect(Settings(tmp_path / "node").database_path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM native_attachment_objects").fetchone()[0] == 1
        )


def test_native_attachment_refuses_plaintext_only_node_without_admission(tmp_path: Path) -> None:
    app, principal, account = capture_case(tmp_path / "node")
    ref = reference()
    batch = parse_upload_batch(
        attach_native_artifact(
            build_grok_bot_capture_upload(ref, source_account_id=account),
            NativeAttachmentUpload(
                0,
                hashlib.sha256(ref.canonical_bytes()).hexdigest(),
                "text/markdown",
                b"Synthetic file.",
            ),
        )
    )
    before = Ledger(Settings(tmp_path / "node")).generation_digest()
    with pytest.raises(ValueError, match="encrypted publication"):
        app.upload_batch(principal, batch)
    assert Ledger(Settings(tmp_path / "node")).generation_digest() == before


def test_private_parent_refuses_new_file_version_atomically(tmp_path: Path) -> None:
    from cross_assistant_memory.models import Authority, EventCorrection, Privacy

    app, principal, account, reader = encrypted_case(tmp_path / "node")
    ref = reference()
    body = build_grok_bot_capture_upload(ref, source_account_id=account)

    def version(data: bytes) -> UploadBatch:
        return parse_upload_batch(
            attach_native_artifact(
                body,
                NativeAttachmentUpload(
                    0,
                    hashlib.sha256(ref.canonical_bytes()).hexdigest(),
                    "text/markdown",
                    data,
                ),
            )
        )

    admit(app, principal, version(b"Synthetic first file version."))
    settings = Settings(tmp_path / "node")
    ledger = Ledger(settings, encrypted_evidence_reader=reader)
    event = ledger.search("synthetic.md")[0]
    state, generation = ledger.event_state_with_generation(event.event_id)
    ledger.apply_event_corrections(
        [
            EventCorrection(
                event_id=event.event_id,
                expected_state_digest=state["state_digest"],
                event_type=state["event_type"],
                actor_kind=state["actor_kind"],
                assistant=state["assistant"],
                authority=Authority(state["authority"]),
                scope=Scope(state["scope"]),
                project_id=state["project_id"],
                privacy=Privacy.NO_MEMORY,
                content_text=state["content_text"],
                parser_version=state["parser_version"],
                reason="Synthetic no-memory correction",
            )
        ],
        expected_generation_digest=generation,
        authorized_by="local:synthetic",
        authorization_scope="synthetic:privacy",
        reason="Synthetic privacy test",
    )
    before = ledger.generation_digest()
    with pytest.raises(KeyError):
        ledger.get_evidence(event.event_id)
    with pytest.raises(ValueError, match="included parent"):
        admit(app, principal, version(b"Synthetic second file version."))
    assert ledger.generation_digest() == before
    with closing(sqlite3.connect(settings.database_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM native_attachment_objects").fetchone()[0] == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 2
