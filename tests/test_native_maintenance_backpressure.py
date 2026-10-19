from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from starlette.testclient import TestClient

from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CreateDeviceEnrollmentRequest,
    MemoryApplication,
    RegisterSourceAccountRequest,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    FilesystemObjectBackend,
    OperationalKey,
    RecoverySecret,
    RootKey,
    build_recovery_kit,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import CollectorProvenance, Scope, SourceSystem
from cross_assistant_memory.private_json import write_owner_only_json
from cross_assistant_memory.publication_work import EvidencePublicationPolicy
from cross_assistant_memory.runtime_evidence import (
    MAX_RUNTIME_CONFIG_BYTES,
    runtime_evidence_for_command,
)
from cross_assistant_memory.storage import (
    Ledger,
    exclusive_ledger_writer,
    generate_client_credential_token,
)
from cross_assistant_memory.uploads import build_upload_batch


# The friends-alpha checkout omits the original test-helper modules.
def client(settings: Settings, config: Path) -> TestClient:
    evidence = runtime_evidence_for_command(settings, "serve", config, allow_publication=True)
    server = create_mcp_server(
        settings,
        transport="streamable-http",
        http_auth_url="http://127.0.0.1:8765/mcp",
        encrypted_evidence_reader=evidence.reader,
        evidence_publication_policy=evidence.publication_policy,
    )
    return TestClient(
        server.streamable_http_app(stateless_http=True, json_response=True),
        base_url="http://127.0.0.1:8765",
    )


@dataclass(frozen=True)
class NativeCase:
    settings: Settings
    config: Path
    body: bytes
    token: str

    def inspect(self) -> Ledger:
        evidence = runtime_evidence_for_command(self.settings, "serve", self.config)
        return Ledger(
            self.settings,
            read_only=True,
            require_checkpointed=False,
            encrypted_evidence_reader=evidence.reader,
        )


def _synthetic_source(path: Path, source_system: SourceSystem) -> Path:
    records: list[dict[str, object]]
    if source_system is SourceSystem.CODEX:
        records = [
            {"type": "session_meta", "payload": {"id": "synthetic-codex", "source": "vscode"}},
            *(
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": role,
                        "phase": "final_answer" if role == "assistant" else None,
                        "content": [{"type": content_type, "text": text}],
                    },
                }
                for role, content_type, text in (
                    ("user", "input_text", "Synthetic maintenance request."),
                    ("assistant", "output_text", "Synthetic maintenance response."),
                )
            ),
        ]
    elif source_system is SourceSystem.CLAUDE_CODE:
        records = [
            {
                "type": role,
                "sessionId": "synthetic-claude",
                "leafUuid": "synthetic-claude",
                "entrypoint": "claude-desktop",
                "timestamp": f"2026-08-30T12:00:0{index}Z",
                "uuid": f"synthetic-claude-{index}",
                "message": {"role": role, "content": [{"type": "text", "text": text}]},
            }
            for index, (role, text) in enumerate(
                (
                    ("user", "Synthetic maintenance request."),
                    ("assistant", "Synthetic maintenance response."),
                )
            )
        ]
    else:
        assert source_system is SourceSystem.GROK_BUILD
        records = [
            {
                "timestamp": 1786190400 + index,
                "method": "session/update",
                "params": {
                    "sessionId": "synthetic-grok",
                    "update": {
                        "sessionUpdate": update,
                        "content": {"type": "text", "text": text},
                        "_meta": {"modelId": "synthetic-grok", "promptIndex": 0},
                    },
                },
            }
            for index, (update, text) in enumerate(
                (
                    ("user_message_chunk", "Synthetic maintenance request."),
                    ("agent_message_chunk", "Synthetic maintenance response."),
                )
            )
        ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def prepare(root: Path, source_system: SourceSystem) -> NativeCase:
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings = Settings(root / "node")
    reader = EncryptedEvidenceReader(
        FilesystemObjectBackend(root / "provider"), RootKey.generate(), 1024 * 1024, 2 * 1024 * 1024
    )
    Ledger(
        settings,
        encrypted_evidence_reader=reader,
        evidence_publication_policy=EvidencePublicationPolicy(1024 * 1024, 100),
    )
    application = MemoryApplication(Ledger(settings))
    principal = ApplicationPrincipal.local_admin("local:synthetic")
    now = datetime.now(UTC)
    enrollment = application.create_device_enrollment(
        principal,
        CreateDeviceEnrollmentRequest(
            label="Synthetic Mac",
            platform="macOS arm64",
            expires_at=now + timedelta(minutes=10),
            credential_expires_at=now + timedelta(days=90),
        ),
    )
    redeemed = application.redeem_device_enrollment(cast(str, enrollment["code"]))
    device = cast(dict[str, object], redeemed["device"])
    credential = cast(dict[str, object], redeemed["credential"])
    account = application.register_source_account(
        principal,
        RegisterSourceAccountRequest(
            device_id=cast(str, device["device_id"]),
            source_system=source_system,
            account_label="synthetic-account",
            scope=Scope.PROJECT,
            project_id="synthetic-project",
        ),
    )
    parsed = parse_file(_synthetic_source(root / "synthetic.jsonl", source_system), source_system)
    secret = RecoverySecret.generate()
    key = root / "operational-key"
    OperationalKey.from_recovery_kit(build_recovery_kit(reader.root_key, secret), secret).write(key)
    config = root / "evidence-config.json"
    write_owner_only_json(
        config,
        {
            "format_version": 1,
            "data_root": str(settings.data_root),
            "operational_key": str(key),
            "backend": {"profile": "filesystem-v1", "root": str(root / "provider")},
            "max_plaintext_bytes": 1024 * 1024,
            "max_ciphertext_bytes": 2 * 1024 * 1024,
            "max_snapshot_bytes": 16 * 1024 * 1024,
            "publication": {
                "mode": "remote-primary",
                "max_pending_bytes": 1024 * 1024,
                "max_pending_objects": 16,
            },
        },
        label="synthetic native recovery config",
        max_bytes=MAX_RUNTIME_CONFIG_BYTES,
    )
    provenance = CollectorProvenance(
        source_client={
            SourceSystem.CODEX: "codex",
            SourceSystem.CLAUDE_CODE: "claude-code",
            SourceSystem.GROK_BUILD: "grok-build",
        }[source_system],
        source_client_version="test-client-1.0.0",
        capture_capability="native-jsonl-history",
        adapter_name="cross-memory-native-collector",
        adapter_version="0.1.0",
        schema_fingerprint=parsed.schema_fingerprint,
    )
    body = build_upload_batch(
        parsed, source_account_id=cast(str, account["source_account_id"]), provenance=provenance
    )
    return NativeCase(settings, config, body, cast(str, credential["token"]))


@pytest.mark.parametrize(
    "source_system", [SourceSystem.CODEX, SourceSystem.CLAUDE_CODE, SourceSystem.GROK_BUILD]
)
@pytest.mark.parametrize("remote_primary", [False, True])
def test_native_upload_is_retryable_without_waiting_for_backup(
    tmp_path: Path, source_system: SourceSystem, remote_primary: bool
) -> None:
    case = prepare(tmp_path / "synthetic-maintenance", source_system)
    before = case.inspect().generation_digest()
    if remote_primary:
        http_client = client(case.settings, case.config)
    else:
        server = create_mcp_server(
            case.settings,
            transport="streamable-http",
            http_auth_url="http://127.0.0.1:8765/mcp",
        )
        http_client = TestClient(
            server.streamable_http_app(stateless_http=True, json_response=True),
            base_url="http://127.0.0.1:8765",
        )
    with http_client as http, ThreadPoolExecutor(max_workers=1) as worker:
        with exclusive_ledger_writer(case.settings):
            assert http.get("/health").json() == {"status": "ok"}
            assert case.inspect().generation_digest() == before
            started = time.monotonic()
            request = worker.submit(
                http.post,
                "/upload/batches",
                content=case.body,
                headers={"authorization": "Bearer " + case.token},
            )
            try:
                response = request.result(timeout=1)
            except TimeoutError:
                pytest.fail("native upload waited for the backup writer instead of yielding")
            assert time.monotonic() - started < 1
            assert response.status_code == 503
            assert response.json() == {
                "status": "writer_busy",
                "error": "node writer is busy; retry this batch",
            }
            assert response.headers["retry-after"] == "30"
            assert case.inspect().generation_digest() == before
            assert not (case.settings.data_root / ".object-write-attempt.jsonl").exists()
        response = http.post(
            "/upload/batches", content=case.body, headers={"authorization": "Bearer " + case.token}
        )
        if remote_primary:
            assert response.status_code == 503, response.json()
            assert response.json()["status"] == "publication_pending"
            assert response.json()["completed_objects"] == 1
        else:
            assert response.status_code == 201, response.json()
        replay = http.post(
            "/upload/batches", content=case.body, headers={"authorization": "Bearer " + case.token}
        )
        assert replay.status_code == 200, replay.json()
    assert case.inspect().status()["upload_batches"] == 1


def test_many_busy_uploads_leave_authenticated_reads_available(tmp_path: Path) -> None:
    case = prepare(tmp_path / "synthetic-concurrent-maintenance", SourceSystem.CODEX)
    before = case.inspect().generation_digest()
    with (
        client(case.settings, case.config) as http,
        ThreadPoolExecutor(max_workers=8) as workers,
        exclusive_ledger_writer(case.settings),
    ):
        started = time.monotonic()
        requests = [
            workers.submit(
                http.post,
                "/upload/batches",
                content=case.body,
                headers={"authorization": "Bearer " + case.token},
            )
            for _ in range(40)
        ]
        replies = [request.result(timeout=2) for request in requests]
        assert time.monotonic() - started < 2
        assert all(reply.status_code == 503 for reply in replies)
        assert all(reply.json()["status"] == "writer_busy" for reply in replies)
        denied = http.post(
            "/upload/batches",
            content=case.body,
            headers={"authorization": "Bearer cam1.synthetic.invalid"},
        )
        assert denied.status_code == 401
        status = http.post(
            "/mcp",
            headers={
                "authorization": "Bearer " + case.token,
                "accept": "application/json, text/event-stream",
                "content-type": "application/json",
                "mcp-protocol-version": "2026-07-28",
                "mcp-method": "tools/call",
                "mcp-name": "memory_status",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "memory_status",
                    "arguments": {},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "synthetic-maintenance-test",
                            "version": "1.0.0",
                        },
                    },
                },
            },
        )
        assert status.status_code == 200, status.json()
        assert not status.json()["result"].get("isError", False)
        assert case.inspect().generation_digest() == before
    assert case.inspect().status()["upload_batches"] == 0


def test_enrollment_yields_without_consuming_its_code(tmp_path: Path) -> None:
    case = prepare(tmp_path / "synthetic-enrollment-maintenance", SourceSystem.CODEX)
    app = MemoryApplication(Ledger(case.settings))
    now = datetime.now(UTC)
    enrollment = app.create_device_enrollment(
        ApplicationPrincipal.local_admin("local:synthetic"),
        CreateDeviceEnrollmentRequest(
            label="Synthetic enrollment",
            platform="synthetic",
            expires_at=now + timedelta(minutes=10),
            credential_expires_at=now + timedelta(days=1),
        ),
    )
    body = {
        "code": cast(str, enrollment["code"]),
        "credential_token": generate_client_credential_token(),
    }
    before = case.inspect().generation_digest()
    with client(case.settings, case.config) as http, ThreadPoolExecutor(max_workers=1) as worker:
        with exclusive_ledger_writer(case.settings):
            reply = worker.submit(http.post, "/enroll", json=body).result(timeout=1)
            assert reply.status_code == 503
            assert reply.json() == {
                "status": "writer_busy",
                "error": "node writer is busy; retry later",
            }
            assert case.inspect().generation_digest() == before
        response = http.post("/enroll", json=body)
        assert response.status_code == 201, response.json()
        replay = http.post("/enroll", json=body)
        assert replay.status_code == 200, replay.json()
        assert replay.json() == {**response.json(), "status": "already_enrolled", "replayed": True}
