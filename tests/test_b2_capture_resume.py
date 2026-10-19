from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, cast

import pytest

import cross_assistant_memory.b2_object_store as b2_module
import cross_assistant_memory.recovery as recovery_module
from cross_assistant_memory.b2_object_store import (
    B2S3Profile,
)
from cross_assistant_memory.cli import main
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import (
    Authority,
    Capability,
    ClientKind,
    EventCorrection,
    Privacy,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.recovery import (
    RecoveryQuery,
    b2_backup_staging_path,
    initialize_recovery_material,
)
from cross_assistant_memory.recovery_status import BACKUP_RECEIPT_ROOT, inspect_recovery_status
from cross_assistant_memory.storage import Ledger

SYNTHETIC_SECRET = "synthetic-only-b2-recovery-secret-not-a-real-credential"


class FakeProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(f"synthetic provider error: {code}")
        self.response: dict[str, object] = {"Error": {"Code": code}}


class FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.object_versions: dict[str, str] = {}
        self.versions: dict[str, list[tuple[str, bytes]]] = {}
        self.delete_markers: dict[str, list[str]] = {}
        self.version_order: dict[str, int] = {}
        self.multipart: dict[str, dict[str, object]] = {}
        self.upload_part_calls: list[tuple[str, int, int]] = []
        self.abort_calls: list[tuple[str, str]] = []
        self.complete_calls: list[str] = []
        self.put_calls = 0
        self.fail_put_after_store = False
        self.interrupt_put_after_store = False
        self.fail_upload_part_number: int | None = None
        self.fail_complete_after_store = False
        self.omit_key_delete_marker_flag = False
        self.setting_errors: dict[str, str] = {
            "lifecycle": "NoSuchLifecycleConfiguration",
            "object_lock": "ObjectLockConfigurationNotFoundError",
        }
        self.versioning_response: dict[str, object] = {"Status": "Enabled"}
        self.lifecycle_response: dict[str, object] = {"Rules": []}
        self.object_lock_response: dict[str, object] = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        self._next_upload = 1
        self._next_version = 1

    def head_bucket(self, **kwargs: object) -> dict[str, object]:
        self._raise_setting_error("bucket")
        _required_string(kwargs, "Bucket")
        return {}

    def head_object(self, **kwargs: object) -> dict[str, object]:
        key = _required_string(kwargs, "Key")
        try:
            payload = self.objects[key]
        except KeyError as error:
            raise FakeProviderError("404") from error
        return {
            "ContentLength": len(payload),
            "ETag": f'"{hashlib.md5(payload, usedforsecurity=False).hexdigest()}"',
            "VersionId": self.object_versions[key],
        }

    def get_object(self, **kwargs: object) -> dict[str, object]:
        key = _required_string(kwargs, "Key")
        version_id = kwargs.get("VersionId")
        if version_id is None:
            try:
                payload = self.objects[key]
            except KeyError as error:
                raise FakeProviderError("NoSuchKey") from error
        else:
            if not isinstance(version_id, str) or not version_id:
                raise FakeProviderError("NoSuchVersion")
            payload = next(
                (
                    payload
                    for candidate, payload in self.versions.get(key, [])
                    if candidate == version_id
                ),
                None,
            )
            if payload is None:
                raise FakeProviderError("NoSuchVersion")
        return {"Body": io.BytesIO(payload)}

    def put_object(self, **kwargs: object) -> dict[str, object]:
        key = _required_string(kwargs, "Key")
        body = kwargs.get("Body")
        payload = _read_body(body)
        self._store(key, payload)
        self.put_calls += 1
        if self.interrupt_put_after_store:
            self.interrupt_put_after_store = False
            raise KeyboardInterrupt
        if self.fail_put_after_store:
            self.fail_put_after_store = False
            raise FakeProviderError("RequestTimeout")
        return {"ETag": "synthetic-etag", "VersionId": self.object_versions[key]}

    def create_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        key = _required_string(kwargs, "Key")
        upload_id = f"upload-{self._next_upload}"
        self._next_upload += 1
        self.multipart[upload_id] = {
            "Key": key,
            "UploadId": upload_id,
            "Initiated": datetime.now(UTC),
            "Parts": {},
        }
        return {"UploadId": upload_id}

    def upload_part(self, **kwargs: object) -> dict[str, object]:
        upload_id = _required_string(kwargs, "UploadId")
        part_number = _required_int(kwargs, "PartNumber")
        payload = _read_body(kwargs.get("Body"))
        self.upload_part_calls.append((upload_id, part_number, len(payload)))
        if self.fail_upload_part_number == part_number:
            self.fail_upload_part_number = None
            raise FakeProviderError("SlowDown")
        upload = self.multipart[upload_id]
        parts = cast(dict[int, bytes], upload["Parts"])
        parts[part_number] = payload
        return {"ETag": f"part-{part_number}"}

    def complete_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        upload_id = _required_string(kwargs, "UploadId")
        key = _required_string(kwargs, "Key")
        upload = self.multipart.pop(upload_id)
        parts = cast(dict[int, bytes], upload["Parts"])
        self._store(key, b"".join(payload for _, payload in sorted(parts.items())))
        self.complete_calls.append(upload_id)
        if self.fail_complete_after_store:
            self.fail_complete_after_store = False
            raise FakeProviderError("RequestTimeout")
        return {"ETag": "multipart-etag", "VersionId": self.object_versions[key]}

    def abort_multipart_upload(self, **kwargs: object) -> dict[str, object]:
        upload_id = _required_string(kwargs, "UploadId")
        key = _required_string(kwargs, "Key")
        self.multipart.pop(upload_id, None)
        self.abort_calls.append((key, upload_id))
        return {}

    def list_multipart_uploads(self, **kwargs: object) -> dict[str, object]:
        prefix = _required_string(kwargs, "Prefix")
        uploads = [
            {
                "Key": upload["Key"],
                "UploadId": upload["UploadId"],
                "Initiated": upload["Initiated"],
            }
            for upload in self.multipart.values()
            if isinstance(upload.get("Key"), str) and cast(str, upload["Key"]).startswith(prefix)
        ]
        return {"Uploads": uploads, "IsTruncated": False}

    def list_object_versions(self, **kwargs: object) -> dict[str, object]:
        prefix = _required_string(kwargs, "Prefix")
        versions = [
            {"Key": key, "VersionId": version_id, "Size": len(payload)}
            for key, entries in self.versions.items()
            if key.startswith(prefix)
            for version_id, payload in entries
        ]
        delete_markers = [
            {"Key": key, "VersionId": version_id}
            for key, entries in self.delete_markers.items()
            if key.startswith(prefix)
            for version_id in entries
        ]
        return {"Versions": versions, "DeleteMarkers": delete_markers, "IsTruncated": False}

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        key = _required_string(kwargs, "Key")
        raw_version_id = kwargs.get("VersionId")
        if raw_version_id is None:
            version_id = f"version-{self._next_version}"
            self.delete_markers.setdefault(key, []).append(version_id)
            self.version_order[version_id] = self._next_version
            self._next_version += 1
            self._refresh_current(key)
            response: dict[str, object] = {"VersionId": version_id}
            if not self.omit_key_delete_marker_flag:
                response["DeleteMarker"] = True
            return response
        if not isinstance(raw_version_id, str) or not raw_version_id:
            raise FakeProviderError("NoSuchVersion")
        version_id = raw_version_id
        entries = self.versions.get(key, [])
        remaining = [entry for entry in entries if entry[0] != version_id]
        markers = self.delete_markers.get(key, [])
        remaining_markers = [entry for entry in markers if entry != version_id]
        if len(remaining) == len(entries) and len(remaining_markers) == len(markers):
            raise FakeProviderError("NoSuchVersion")
        if remaining:
            self.versions[key] = remaining
        else:
            self.versions.pop(key, None)
        if remaining_markers:
            self.delete_markers[key] = remaining_markers
        else:
            self.delete_markers.pop(key, None)
        self.version_order.pop(version_id, None)
        self._refresh_current(key)
        return {"VersionId": version_id, "DeleteMarker": version_id in markers}

    def get_bucket_versioning(self, **kwargs: object) -> dict[str, object]:
        self._raise_setting_error("versioning")
        return self.versioning_response

    def get_bucket_lifecycle_configuration(self, **kwargs: object) -> dict[str, object]:
        self._raise_setting_error("lifecycle")
        return self.lifecycle_response

    def get_object_lock_configuration(self, **kwargs: object) -> dict[str, object]:
        self._raise_setting_error("object_lock")
        return self.object_lock_response

    def seed_multipart(self, key: str, upload_id: str, initiated_at: datetime) -> None:
        self.multipart[upload_id] = {
            "Key": key,
            "UploadId": upload_id,
            "Initiated": initiated_at,
            "Parts": {},
        }

    def _store(self, key: str, payload: bytes) -> None:
        version_id = f"version-{self._next_version}"
        self.versions.setdefault(key, []).append((version_id, payload))
        self.version_order[version_id] = self._next_version
        self._next_version += 1
        self._refresh_current(key)

    def _refresh_current(self, key: str) -> None:
        candidates: list[tuple[int, str, bytes | None]] = [
            (self.version_order[version_id], version_id, payload)
            for version_id, payload in self.versions.get(key, [])
        ]
        candidates.extend(
            (self.version_order[version_id], version_id, None)
            for version_id in self.delete_markers.get(key, [])
        )
        if not candidates:
            self.object_versions.pop(key, None)
            self.objects.pop(key, None)
            return
        _order, version_id, payload = max(candidates)
        if payload is None:
            self.object_versions.pop(key, None)
            self.objects.pop(key, None)
            return
        self.object_versions[key] = version_id
        self.objects[key] = payload

    def _raise_setting_error(self, setting: str) -> None:
        code = self.setting_errors.get(setting)
        if code is not None:
            raise FakeProviderError(code)


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"missing synthetic string: {key}")
    return value


def _required_int(values: Mapping[str, object], key: str) -> int:
    value = values.get(key)
    if not isinstance(value, int):
        raise AssertionError(f"missing synthetic integer: {key}")
    return value


def _read_body(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if not callable(getattr(value, "read", None)):
        raise AssertionError("missing synthetic body")
    return cast(BinaryIO, value).read()


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    return path


def _atlas_query() -> RecoveryQuery:
    return RecoveryQuery(
        name="atlas-rollback",
        query="Atlas rollback",
        scopes=(Scope.PROJECT,),
        project_id="atlas",
        limit=10,
    )


def _synthetic_ledger(tmp_path: Path) -> Settings:
    settings = Settings(tmp_path / "source-data")
    ledger = Ledger(settings)
    codex_source = write_jsonl(
        tmp_path / "codex.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "codex-atlas", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": "Keep the Atlas rollback gate before deployment.",
                        }
                    ],
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "The Atlas rollback gate is recorded.",
                        }
                    ],
                },
            },
        ],
    )
    grok_source = write_jsonl(
        tmp_path / "grok-atlas" / "updates.jsonl",
        [
            {
                "timestamp": 1786190400,
                "method": "session/update",
                "params": {
                    "sessionId": "grok-atlas",
                    "update": {
                        "sessionUpdate": "user_message_chunk",
                        "content": {
                            "type": "text",
                            "text": "Atlas rollback needs a verified restore first.",
                        },
                        "_meta": {"modelId": "synthetic-grok", "promptIndex": 0},
                    },
                },
            },
            {
                "timestamp": 1786190401,
                "method": "session/update",
                "params": {
                    "sessionId": "grok-atlas",
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {
                            "type": "text",
                            "text": "The restore should replay the Atlas query.",
                        },
                    },
                },
            },
        ],
    )
    for source, system in (
        (codex_source, SourceSystem.CODEX),
        (grok_source, SourceSystem.GROK_BUILD),
    ):
        ledger.ingest(
            parse_file(source, system),
            source_account="synthetic",
            scope=Scope.PROJECT,
            project_id="atlas",
        )
    return settings


@dataclass
class RecoveryCase:
    settings: Settings
    root_kit: Path
    secret: Path
    package_kit: Path
    query_suite: Path
    output: Path
    client: FakeS3Client = field(default_factory=FakeS3Client)
    profiles: list[B2S3Profile] = field(default_factory=list[B2S3Profile])
    sdk_error: str | None = None

    def arguments(self, command: str, *backend: str) -> list[str]:
        arguments = [
            "--home",
            str(self.settings.data_root),
            command,
            *backend,
            "--package-kit",
            str(self.package_kit),
            "--recovery-secret",
            str(self.secret),
        ]
        if command == "backup":
            return [
                *arguments,
                "--root-kit",
                str(self.root_kit),
                "--query-suite",
                str(self.query_suite),
            ]
        assert command == "restore"
        return [*arguments, "--output", str(self.output), "--verify"]


@pytest.fixture
def recovery_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RecoveryCase:
    case = RecoveryCase(
        settings=_synthetic_ledger(tmp_path),
        root_kit=tmp_path / "offline-kit" / "root-kit.json",
        secret=tmp_path / "offline-secret" / "recovery-secret.tink",
        package_kit=tmp_path / "offline-kit" / "package-kit.json",
        query_suite=tmp_path / "query-suite.json",
        output=tmp_path / "restored-node",
    )
    initialize_recovery_material(case.secret, case.root_kit)
    case.query_suite.write_text(
        json.dumps({"format_version": 1, "queries": [_atlas_query().as_dict()]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CAM_B2_BUCKET", "synthetic-recovery-bucket")
    monkeypatch.setenv("CAM_B2_REGION", "us-east-005")
    monkeypatch.delenv("CAM_B2_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("CAM_B2_BACKUP_MAX_STAGING_BYTES", raising=False)
    monkeypatch.setenv("B2_APPLICATION_KEY_ID", "synthetic-recovery-key-id")
    monkeypatch.setenv("B2_APPLICATION_KEY", SYNTHETIC_SECRET)

    def fake_client_factory(
        profile: B2S3Profile, *, environ: Mapping[str, str] | None = None
    ) -> FakeS3Client:
        assert environ is None
        case.profiles.append(profile)
        if case.sdk_error is not None:
            raise FakeProviderError(case.sdk_error)
        return case.client

    monkeypatch.setattr(b2_module, "create_b2_s3_client", fake_client_factory)
    return case


def _run_cli(capsys: pytest.CaptureFixture[str], arguments: list[str]) -> dict[str, Any]:
    main(arguments)
    captured = capsys.readouterr()
    assert captured.err == ""
    value: object = json.loads(captured.out)
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _cli_error(capsys: pytest.CaptureFixture[str], arguments: list[str]) -> str:
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert SYNTHETIC_SECRET not in captured.err
    value: object = json.loads(captured.err)
    assert isinstance(value, dict)
    result = cast(dict[str, object], value)
    assert result["status"] == "error"
    assert isinstance(result["error"], str)
    return result["error"]


def _assert_no_backup(case: RecoveryCase) -> None:
    assert case.client.put_calls == 0
    assert case.client.objects == {}
    assert case.client.versions == {}
    assert case.client.multipart == {}
    assert not case.package_kit.exists()
    assert not list((case.settings.data_root / BACKUP_RECEIPT_ROOT).glob("*.json"))
    assert inspect_recovery_status(case.settings)["status"] == "not_recorded_by_node"


@pytest.mark.parametrize(
    "backend",
    [[], ["--b2", "--discard-empty-preparation"], ["--b2", "--discard-unpublished-preparation"]],
)
def test_capture_resume_requires_b2_without_cleanup_before_provider_access(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    backend: list[str],
) -> None:
    case = recovery_case
    if not backend:
        backend = ["--backend-root", str(case.output.parent / "filesystem-backend")]
    calls = _forbid_provider_calls(case.client, monkeypatch)
    generation = Ledger(case.settings, read_only=True).generation_digest()
    assert "capture resume requires --b2 and no preparation cleanup" in _cli_error(
        capsys, case.arguments("backup", *backend, "--resume-source-generation", generation)
    )
    assert calls == []
    assert not b2_backup_staging_path(case.settings).exists()
    _assert_no_backup(case)


def _cli_interrupted(capsys: pytest.CaptureFixture[str], arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert SYNTHETIC_SECRET not in captured.err
    assert json.loads(captured.err) == {
        "status": "interrupted",
        "error": (
            "B2 recovery interrupted; success is unconfirmed. "
            "Inspect the package kit before retrying."
        ),
    }


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _forbid_provider_calls(client: FakeS3Client, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    for method in (
        "head_bucket",
        "head_object",
        "get_object",
        "put_object",
        "get_bucket_versioning",
        "get_bucket_lifecycle_configuration",
        "get_object_lock_configuration",
        "create_multipart_upload",
        "upload_part",
        "complete_multipart_upload",
        "abort_multipart_upload",
        "list_multipart_uploads",
        "list_object_versions",
        "delete_object",
    ):

        def reject_call(*, _method: str = method, **_kwargs: object) -> dict[str, object]:
            calls.append(_method)
            raise AssertionError(f"unexpected provider call: {_method}")

        monkeypatch.setattr(client, method, reject_call)
    return calls


def _assert_retained_stage(case: RecoveryCase) -> Path:
    stage = b2_backup_staging_path(case.settings)
    assert stage.is_dir()
    for name in ("staged-kit.json", "request.tink", "upload-intent.tink"):
        assert (stage / name).is_file()
    assert list((stage / "ciphertext" / "objects").iterdir())
    assert not case.package_kit.exists()
    assert not list((case.settings.data_root / BACKUP_RECEIPT_ROOT).glob("*.json"))
    assert inspect_recovery_status(case.settings)["status"] == "not_recorded_by_node"
    return stage


def _empty_failed_preparation(
    case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    def fail_snapshot(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(SYNTHETIC_SECRET)

    with monkeypatch.context() as patch:
        patch.setattr(recovery_module, "create_snapshot", fail_snapshot)
        assert "B2 backup failed" in _cli_error(capsys, case.arguments("backup", "--b2"))
    stage = b2_backup_staging_path(case.settings)
    assert set(_tree_bytes(stage)) == {"request.tink"}
    _assert_no_backup(case)
    return stage


def _advance_backup_source(case: RecoveryCase) -> None:
    source = write_jsonl(
        case.settings.data_root.parent / "later-source.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "later", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Later synthetic evidence."}],
                },
            },
        ],
    )
    ledger = Ledger(case.settings)
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )


@pytest.mark.parametrize("change", ["generation", "privacy", "query_suite", "bucket"])
@pytest.mark.parametrize("capture_resume", [False, True])
def test_b2_cli_staged_resume_refuses_changed_inputs_before_extra_puts(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    capture_resume: bool,
) -> None:
    case = recovery_case
    capture_generation = Ledger(case.settings, read_only=True).generation_digest()
    case.client.interrupt_put_after_store = True
    _cli_interrupted(capsys, case.arguments("backup", "--b2"))
    stage = _assert_retained_stage(case)
    staged_bytes = _tree_bytes(stage)
    objects = dict(case.client.objects)
    versions = {key: list(entries) for key, entries in case.client.versions.items()}
    put_calls = case.client.put_calls

    if change in ("generation", "privacy"):
        ledger = Ledger(case.settings)
        generation = ledger.generation_digest()
        event = ledger.search("Atlas rollback", scopes=[Scope.PROJECT], project_id="atlas")[0]
        state = ledger.event_state(event.event_id)
        ledger.apply_event_corrections(
            [
                EventCorrection(
                    event_id=event.event_id,
                    expected_state_digest=state["state_digest"],
                    event_type=state["event_type"],
                    actor_kind=state["actor_kind"],
                    assistant=state["assistant"],
                    authority=Authority(state["authority"]),
                    scope=Scope.USER_GLOBAL if change == "generation" else Scope(state["scope"]),
                    project_id=None if change == "generation" else state["project_id"],
                    privacy=Privacy.NO_MEMORY if change == "privacy" else Privacy(state["privacy"]),
                    content_text=state["content_text"],
                    parser_version=state["parser_version"],
                    reason="synthetic staged-recovery source change",
                )
            ],
            expected_generation_digest=generation,
            authorized_by="local:test",
            authorization_scope="memory:curate",
            reason="synthetic staged-recovery source change",
        )
        assert ledger.generation_digest() != generation
    elif change == "query_suite":
        case.query_suite.write_text(
            json.dumps(
                {"format_version": 1, "queries": [{**_atlas_query().as_dict(), "limit": 1}]}
            ),
            encoding="utf-8",
        )
    else:
        monkeypatch.setenv("CAM_B2_BUCKET", "synthetic-other-recovery-bucket")

    resume = ["--resume-source-generation", capture_generation] if capture_resume else []
    assert "B2 backup failed" in _cli_error(capsys, case.arguments("backup", "--b2", *resume))

    assert case.client.put_calls == put_calls
    assert case.client.objects == objects
    assert case.client.versions == versions
    assert _assert_retained_stage(case) == stage
    assert _tree_bytes(stage) == staged_bytes


def test_b2_cli_explicit_capture_resume_preserves_frozen_generation(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = recovery_case
    capture_generation = Ledger(case.settings, read_only=True).generation_digest()
    case.client.interrupt_put_after_store = True
    _cli_interrupted(capsys, case.arguments("backup", "--b2"))
    stage = _assert_retained_stage(case)
    staged_kit = (stage / "staged-kit.json").read_bytes()
    ciphertext = _tree_bytes(stage / "ciphertext")
    versions = {key: list(entries) for key, entries in case.client.versions.items()}
    _advance_backup_source(case)
    current_generation = Ledger(case.settings, read_only=True).generation_digest()
    arguments = case.arguments("backup", "--b2", "--resume-source-generation", capture_generation)

    resumed = _run_cli(capsys, arguments)

    assert resumed["status"] == "resumed"
    assert resumed["source_ledger_generation"] == capture_generation != current_generation
    assert resumed["current_ledger_generation"] == current_generation
    assert resumed["capture_is_current"] is False
    assert case.package_kit.read_bytes() == staged_kit
    assert case.client.objects == ciphertext
    assert case.client.put_calls == len(ciphertext)
    assert all(len(entries) == 1 for entries in case.client.versions.values())
    assert all(case.client.versions[key] == entries for key, entries in versions.items())
    assert not stage.exists()
    assert Ledger(case.settings, read_only=True).generation_digest() == current_generation
    receipt = inspect_recovery_status(case.settings)["last_successful_backup"]
    assert isinstance(receipt, dict)
    assert receipt["source_ledger_generation"] == capture_generation
    assert _run_cli(capsys, arguments) == resumed
    assert case.client.put_calls == len(ciphertext)

    restored = _run_cli(capsys, case.arguments("restore", "--b2"))
    assert restored["source_ledger_generation"] == capture_generation
    ledger = Ledger(Settings(case.output), read_only=True)
    assert ledger.generation_digest() == capture_generation
    assert ledger.search("Later synthetic evidence", scopes=[Scope.USER_GLOBAL]) == []


@pytest.mark.parametrize("published", [False, True])
def test_b2_capture_resume_accepts_only_stream_observation_timestamp_changes(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    published: bool,
) -> None:
    case = recovery_case
    capture_generation = Ledger(case.settings, read_only=True).generation_digest()
    if published:
        _run_cli(capsys, case.arguments("backup", "--b2"))
        kit = case.package_kit.read_bytes()
    else:
        case.client.interrupt_put_after_store = True
        _cli_interrupted(capsys, case.arguments("backup", "--b2"))
        kit = (_assert_retained_stage(case) / "staged-kit.json").read_bytes()
    with closing(sqlite3.connect(case.settings.database_path)) as connection:
        assert (
            connection.execute(
                "UPDATE source_streams SET updated_at = '2099-01-01T00:00:00+00:00'"
            ).rowcount
            > 0
        )
        connection.commit()
    assert Ledger(case.settings, read_only=True).generation_digest() == capture_generation
    _advance_backup_source(case)
    current = Ledger(case.settings, read_only=True).generation_digest()
    assert current != capture_generation

    resumed = _run_cli(
        capsys, case.arguments("backup", "--b2", "--resume-source-generation", capture_generation)
    )

    assert resumed["status"] == "resumed"
    assert resumed["source_ledger_generation"] == capture_generation
    assert resumed["current_ledger_generation"] == current
    assert resumed["capture_is_current"] is False
    assert case.package_kit.read_bytes() == kit
    assert all(len(entries) == 1 for entries in case.client.versions.values())
    assert Ledger(case.settings, read_only=True).generation_digest() == current


@pytest.mark.parametrize("generation", ["invalid", "a" * 64])
def test_b2_cli_capture_resume_requires_exact_existing_preparation(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    generation: str,
) -> None:
    case = recovery_case
    calls = _forbid_provider_calls(case.client, monkeypatch)
    _cli_error(
        capsys,
        case.arguments("backup", "--b2", "--resume-source-generation", generation),
    )
    assert calls == []
    assert not b2_backup_staging_path(case.settings).exists()
    _assert_no_backup(case)


def test_b2_cli_capture_resume_never_prepares_an_incomplete_attempt(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = recovery_case
    stage = _empty_failed_preparation(case, capsys, monkeypatch)
    original = _tree_bytes(stage)
    calls = _forbid_provider_calls(case.client, monkeypatch)
    generation = Ledger(case.settings, read_only=True).generation_digest()
    _cli_error(capsys, case.arguments("backup", "--b2", "--resume-source-generation", generation))
    assert _tree_bytes(stage) == original
    assert calls == []
    _assert_no_backup(case)


@pytest.mark.parametrize(
    "change",
    [
        "privacy",
        "correction",
        "access",
        "deleted_event",
        "client_revocation",
        "stream_scope",
        "stream_label",
        "stream_parser",
        "stream_initial_ordinal",
    ],
)
def test_b2_cli_capture_resume_refuses_changed_retained_content_before_provider_access(
    recovery_case: RecoveryCase,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    case = recovery_case
    ledger = Ledger(case.settings)
    client_id = None
    if change == "client_revocation":
        client_id = ledger.register_client(
            label="synthetic reader",
            kind=ClientKind.ASSISTANT,
            capabilities=[Capability.MEMORY_SEARCH],
        )["client_id"]
    capture_generation = ledger.generation_digest()
    case.client.interrupt_put_after_store = True
    _cli_interrupted(capsys, case.arguments("backup", "--b2"))
    stage = _assert_retained_stage(case)
    original = _tree_bytes(stage)
    event = ledger.search("Atlas rollback", scopes=[Scope.PROJECT], project_id="atlas")[0]
    if change in {"privacy", "correction"}:
        state = ledger.event_state(event.event_id)
        ledger.apply_event_corrections(
            [
                EventCorrection(
                    event_id=event.event_id,
                    expected_state_digest=state["state_digest"],
                    event_type=state["event_type"],
                    actor_kind=state["actor_kind"],
                    assistant=state["assistant"],
                    authority=(
                        Authority.TOOL_OBSERVATION
                        if change == "correction"
                        and state["authority"] != Authority.TOOL_OBSERVATION
                        else Authority.EXTERNAL_CONTENT
                        if change == "correction"
                        else Authority(state["authority"])
                    ),
                    scope=Scope(state["scope"]),
                    project_id=state["project_id"],
                    privacy=Privacy.NO_MEMORY if change == "privacy" else Privacy(state["privacy"]),
                    content_text=state["content_text"],
                    parser_version=state["parser_version"],
                    reason="synthetic capture-resume refusal",
                )
            ],
            expected_generation_digest=capture_generation,
            authorized_by="local:test",
            authorization_scope="memory:curate",
            reason="synthetic capture-resume refusal",
        )
    else:
        # Corrupt only this synthetic fixture to exercise the conservative row guard.
        with closing(sqlite3.connect(case.settings.database_path)) as connection:
            if change == "client_revocation":
                connection.execute(
                    "UPDATE clients SET status = 'revoked' WHERE client_id = ?", (client_id,)
                )
            elif change == "access":
                connection.execute(
                    "UPDATE event_access SET access = 'private' WHERE event_id = ?",
                    (event.event_id,),
                )
            elif change.startswith("stream_"):
                column, value = {
                    "stream_scope": ("scope", "user_global"),
                    "stream_label": ("source_label", "changed synthetic provenance"),
                    "stream_parser": ("parser_name", "changed-parser"),
                    "stream_initial_ordinal": ("initial_record_ordinal", 99),
                }[change]
                connection.execute(f"UPDATE source_streams SET {column} = ?", (value,))
            else:
                connection.execute("DELETE FROM events WHERE event_id = ?", (event.event_id,))
            connection.commit()
    calls = _forbid_provider_calls(case.client, monkeypatch)
    _cli_error(
        capsys,
        case.arguments("backup", "--b2", "--resume-source-generation", capture_generation),
    )
    assert calls == []
    assert _tree_bytes(stage) == original
    assert not case.package_kit.exists()
    assert not list((case.settings.data_root / BACKUP_RECEIPT_ROOT).glob("*.json"))
