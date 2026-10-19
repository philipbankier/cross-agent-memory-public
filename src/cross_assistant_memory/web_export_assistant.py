from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.models import Scope, SourceSystem
from cross_assistant_memory.storage import Ledger

ASSISTANT_STATE_VERSION = 1
ASSISTANT_CADENCE_DAYS = 7
MAX_STATE_BYTES = 1024 * 1024
WEB_SOURCE_SYSTEMS = frozenset(
    {SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB, SourceSystem.GROK_WEB}
)


class WebExportAssistEvent(StrEnum):
    REQUEST_CONFIRMED = "request_confirmed"
    PROCESSING_CONFIRMED = "processing_confirmed"
    DOWNLOAD_READY = "download_ready"
    ARCHIVE_VERIFIED = "archive_verified"
    MANIFEST_VERIFIED = "manifest_verified"
    BLOCKED = "blocked"


class WebExportPauseReason(StrEnum):
    LOGIN = "login"
    CAPTCHA = "captcha"
    TWO_FACTOR = "two_factor"
    CHANGED_UI = "changed_ui"
    EXPIRED_LINK = "expired_link"
    MISSING_APPROVAL = "missing_approval"
    LEGAL_OR_ACCOUNT_CONFIRMATION = "legal_or_account_confirmation"


def inspect_assisted_web_exports(
    settings: Settings,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_at = _normalized_time(now or datetime.now(UTC), "inspection time")
    ledger = Ledger(settings, read_only=True, require_checkpointed=False)
    registrations = ledger.registered_web_source_accounts()
    path = _state_path(settings)
    _validate_existing_state_directories(settings, path.parent)
    state = _load_state(path)
    sources = cast(dict[str, object], state["sources"])
    summaries: list[dict[str, object]] = []
    for registration in registrations:
        source_system = SourceSystem(cast(str, registration["source_system"]))
        source_account_id = cast(str, registration["source_account_id"])
        key = _source_key(source_system, source_account_id)
        entry_value = sources.get(key)
        entry = _validated_entry(entry_value) if entry_value is not None else None
        if entry is not None:
            _validate_entry_registration(entry, registration)
        summaries.append(_source_summary(registration, entry, observed_at))
    active_keys = {
        _source_key(
            SourceSystem(cast(str, registration["source_system"])),
            cast(str, registration["source_account_id"]),
        )
        for registration in registrations
    }
    action_required = any(item["next_action"] != "wait" for item in summaries)
    return {
        "status": (
            "blocked" if not registrations else "action_required" if action_required else "ok"
        ),
        "blocking_reason": None if registrations else "no_registered_web_sources",
        "content_opened": False,
        "fully_unattended_browser_automation": False,
        "private_web_api_canonical_input": False,
        "cadence_days": ASSISTANT_CADENCE_DAYS,
        "observed_at": observed_at.isoformat(),
        "registered_source_count": len(registrations),
        "orphaned_state_count": len(set(sources) - active_keys),
        "sources": summaries,
    }


def record_assisted_web_export_event(
    settings: Settings,
    *,
    source_system: SourceSystem,
    source_account_id: str,
    scope: Scope,
    project_id: str | None,
    event: WebExportAssistEvent,
    occurred_at: datetime | None = None,
    pause_reason: WebExportPauseReason | None = None,
    archive_sha256: str | None = None,
    manifest_sha256: str | None = None,
    execute: bool,
) -> dict[str, Any]:
    if source_system not in WEB_SOURCE_SYSTEMS:
        raise ValueError("assisted export events require a web source system")
    source_account_id = _canonical_value(source_account_id, "source account id")
    timestamp = _normalized_time(occurred_at or datetime.now(UTC), "event time")
    ledger = Ledger(settings, read_only=True, require_checkpointed=False)
    registration = ledger.verify_source_account_registration(
        source_account_id=source_account_id,
        source_system=source_system,
        scope=scope,
        project_id=project_id,
    )
    path = _state_path(settings)
    _validate_existing_state_directories(settings, path.parent)
    state = _load_state(path)
    preview = _event_preview(
        state,
        registration=registration,
        source_system=source_system,
        source_account_id=source_account_id,
        scope=scope,
        project_id=project_id,
        event=event,
        occurred_at=timestamp,
        pause_reason=pause_reason,
        archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
    )
    if not execute:
        return {**preview, "status": "preview", "execute": False}

    root = path.parent
    _prepare_private_state_directory(settings, root)
    with _exclusive_state_lock(root):
        ledger = Ledger(settings, read_only=True, require_checkpointed=False)
        registration = ledger.verify_source_account_registration(
            source_account_id=source_account_id,
            source_system=source_system,
            scope=scope,
            project_id=project_id,
        )
        state = _load_state(path)
        applied = _event_preview(
            state,
            registration=registration,
            source_system=source_system,
            source_account_id=source_account_id,
            scope=scope,
            project_id=project_id,
            event=event,
            occurred_at=timestamp,
            pause_reason=pause_reason,
            archive_sha256=archive_sha256,
            manifest_sha256=manifest_sha256,
        )
        sources = cast(dict[str, object], state["sources"])
        sources[cast(str, applied["source_key"])] = applied["next_state"]
        _write_state(path, state)
        state_sha256 = _hash_file(path)
    return {
        **applied,
        "status": "recorded",
        "execute": True,
        "state_sha256": state_sha256,
    }


def _event_preview(
    state: dict[str, object],
    *,
    registration: dict[str, str | None],
    source_system: SourceSystem,
    source_account_id: str,
    scope: Scope,
    project_id: str | None,
    event: WebExportAssistEvent,
    occurred_at: datetime,
    pause_reason: WebExportPauseReason | None,
    archive_sha256: str | None,
    manifest_sha256: str | None,
) -> dict[str, Any]:
    key = _source_key(source_system, source_account_id)
    sources = cast(dict[str, object], state["sources"])
    current_value = sources.get(key)
    current = _validated_entry(current_value) if current_value is not None else None
    if current is not None:
        _validate_entry_registration(current, registration)
    next_state = _transition(
        current,
        registration=registration,
        source_system=source_system,
        source_account_id=source_account_id,
        scope=scope,
        project_id=project_id,
        event=event,
        occurred_at=occurred_at,
        pause_reason=pause_reason,
        archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
    )
    return {
        "source_key": key,
        "source_system": source_system.value,
        "source_account_id": source_account_id,
        "device_id": registration["device_id"],
        "event": event.value,
        "previous_stage": current["stage"] if current is not None else "request_due",
        "next_state": next_state,
    }


def _transition(
    current: dict[str, object] | None,
    *,
    registration: dict[str, str | None],
    source_system: SourceSystem,
    source_account_id: str,
    scope: Scope,
    project_id: str | None,
    event: WebExportAssistEvent,
    occurred_at: datetime,
    pause_reason: WebExportPauseReason | None,
    archive_sha256: str | None,
    manifest_sha256: str | None,
) -> dict[str, object]:
    stage = cast(str, current["stage"]) if current is not None else "request_due"
    if current is not None and occurred_at < _parse_time(
        cast(str, current["updated_at"]), "previous update time"
    ):
        raise ValueError("assisted export events must not move backward in time")
    if archive_sha256 is not None and event not in {
        WebExportAssistEvent.ARCHIVE_VERIFIED,
        WebExportAssistEvent.MANIFEST_VERIFIED,
    }:
        raise ValueError("archive_sha256 is valid only for archive or manifest verification")
    if manifest_sha256 is not None and event is not WebExportAssistEvent.MANIFEST_VERIFIED:
        raise ValueError("manifest_sha256 is valid only for manifest verification")
    if event is WebExportAssistEvent.BLOCKED:
        if pause_reason is None:
            raise ValueError("a blocked assisted export event requires a pause reason")
        return _entry(
            current,
            registration=registration,
            source_system=source_system,
            source_account_id=source_account_id,
            scope=scope,
            project_id=project_id,
            stage=stage,
            blocking_reason=pause_reason.value,
            occurred_at=occurred_at,
        )
    if pause_reason is not None:
        raise ValueError("pause_reason is valid only for a blocked event")

    if event is WebExportAssistEvent.REQUEST_CONFIRMED:
        return _entry(
            None,
            registration=registration,
            source_system=source_system,
            source_account_id=source_account_id,
            scope=scope,
            project_id=project_id,
            stage="requested",
            blocking_reason=None,
            occurred_at=occurred_at,
            last_request_at=occurred_at.isoformat(),
            next_request_due_at=(occurred_at + timedelta(days=ASSISTANT_CADENCE_DAYS)).isoformat(),
        )
    allowed_stages = {
        WebExportAssistEvent.PROCESSING_CONFIRMED: {"requested", "processing"},
        WebExportAssistEvent.DOWNLOAD_READY: {"requested", "processing", "ready"},
        WebExportAssistEvent.ARCHIVE_VERIFIED: {"ready", "downloaded"},
        WebExportAssistEvent.MANIFEST_VERIFIED: {"downloaded", "staged"},
    }
    if stage not in allowed_stages[event]:
        raise ValueError(f"event {event.value} is invalid while the source is {stage}")
    if event is WebExportAssistEvent.ARCHIVE_VERIFIED:
        _validate_digest(archive_sha256, "archive SHA-256")
    if event is WebExportAssistEvent.MANIFEST_VERIFIED:
        _validate_digest(manifest_sha256, "manifest SHA-256")
        if current is None or current.get("archive_sha256") is None:
            raise ValueError("manifest verification requires a previously verified archive")
        if archive_sha256 is not None and archive_sha256 != current["archive_sha256"]:
            raise ValueError("manifest verification archive digest conflicts with workflow state")
    next_stage = {
        WebExportAssistEvent.PROCESSING_CONFIRMED: "processing",
        WebExportAssistEvent.DOWNLOAD_READY: "ready",
        WebExportAssistEvent.ARCHIVE_VERIFIED: "downloaded",
        WebExportAssistEvent.MANIFEST_VERIFIED: "staged",
    }[event]
    return _entry(
        current,
        registration=registration,
        source_system=source_system,
        source_account_id=source_account_id,
        scope=scope,
        project_id=project_id,
        stage=next_stage,
        blocking_reason=None,
        occurred_at=occurred_at,
        archive_sha256=(archive_sha256 if event is WebExportAssistEvent.ARCHIVE_VERIFIED else None),
        manifest_sha256=(
            manifest_sha256 if event is WebExportAssistEvent.MANIFEST_VERIFIED else None
        ),
    )


def _entry(
    current: dict[str, object] | None,
    *,
    registration: dict[str, str | None],
    source_system: SourceSystem,
    source_account_id: str,
    scope: Scope,
    project_id: str | None,
    stage: str,
    blocking_reason: str | None,
    occurred_at: datetime,
    last_request_at: str | None = None,
    next_request_due_at: str | None = None,
    archive_sha256: str | None = None,
    manifest_sha256: str | None = None,
) -> dict[str, object]:
    previous = current or {}
    return {
        "source_system": source_system.value,
        "source_account_id": source_account_id,
        "device_id": registration["device_id"],
        "scope": scope.value,
        "project_id": project_id,
        "stage": stage,
        "blocking_reason": blocking_reason,
        "last_request_at": last_request_at or previous.get("last_request_at"),
        "next_request_due_at": next_request_due_at or previous.get("next_request_due_at"),
        "archive_sha256": archive_sha256 or previous.get("archive_sha256"),
        "manifest_sha256": manifest_sha256 or previous.get("manifest_sha256"),
        "updated_at": occurred_at.isoformat(),
    }


def _source_summary(
    registration: dict[str, str | None],
    entry: dict[str, object] | None,
    observed_at: datetime,
) -> dict[str, object]:
    stage = cast(str, entry["stage"]) if entry is not None else "request_due"
    blocking_reason = entry.get("blocking_reason") if entry is not None else None
    due_at_text = cast(str | None, entry.get("next_request_due_at")) if entry else None
    cadence_overdue = (
        due_at_text is not None and _parse_time(due_at_text, "next request due") <= observed_at
    )
    if blocking_reason is not None:
        next_action = "human_intervention"
    elif stage == "request_due" or (stage == "staged" and cadence_overdue):
        next_action = "request_export"
    else:
        next_action = {
            "requested": "check_export_status",
            "processing": "check_export_status",
            "ready": "download_export",
            "downloaded": "verify_and_stage_plan",
            "staged": "wait",
        }[stage]
    return {
        **registration,
        "stage": stage,
        "blocking_reason": blocking_reason,
        "last_request_at": entry.get("last_request_at") if entry else None,
        "next_request_due_at": due_at_text,
        "cadence_overdue": cadence_overdue,
        "archive_verified": bool(entry and entry.get("archive_sha256")),
        "manifest_verified": bool(entry and entry.get("manifest_sha256")),
        "next_action": next_action,
        "requires_authenticated_ui": next_action
        in {
            "request_export",
            "check_export_status",
            "download_export",
            "human_intervention",
        },
    }


def _validated_entry(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("assisted export source state must be an object")
    entry = cast(dict[str, object], value)
    expected = {
        "source_system",
        "source_account_id",
        "device_id",
        "scope",
        "project_id",
        "stage",
        "blocking_reason",
        "last_request_at",
        "next_request_due_at",
        "archive_sha256",
        "manifest_sha256",
        "updated_at",
    }
    if set(entry) != expected:
        raise ValueError("assisted export source state keys are invalid")
    stage = entry.get("stage")
    if stage not in {"request_due", "requested", "processing", "ready", "downloaded", "staged"}:
        raise ValueError("assisted export source stage is invalid")
    source_system = SourceSystem(_required_string(entry, "source_system"))
    if source_system not in WEB_SOURCE_SYSTEMS:
        raise ValueError("assisted export source state requires a web source system")
    scope = Scope(_required_string(entry, "scope"))
    _canonical_value(_required_string(entry, "source_account_id"), "source account id")
    _canonical_value(_required_string(entry, "device_id"), "device id")
    project_id = entry.get("project_id")
    if project_id is not None:
        if not isinstance(project_id, str):
            raise ValueError("assisted export source state project_id is invalid")
        _canonical_value(project_id, "project id")
    if scope is Scope.PROJECT and project_id is None:
        raise ValueError("project-scoped assisted export state requires project_id")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped assisted export state may carry project_id")
    last_request_value = entry.get("last_request_at")
    next_request_due_value = entry.get("next_request_due_at")
    updated_at = _parse_time(_required_string(entry, "updated_at"), "updated_at")
    if stage == "request_due":
        if last_request_value is not None or next_request_due_value is not None:
            raise ValueError("request-due assisted export state must not carry cadence timestamps")
    else:
        if last_request_value is None or next_request_due_value is None:
            raise ValueError("post-request assisted export state requires cadence timestamps")
        last_request_at = _parse_time(_required_string(entry, "last_request_at"), "last_request_at")
        next_request_due_at = _parse_time(
            _required_string(entry, "next_request_due_at"), "next_request_due_at"
        )
        if next_request_due_at != last_request_at + timedelta(days=ASSISTANT_CADENCE_DAYS):
            raise ValueError("assisted export cadence deadline is invalid")
        if updated_at < last_request_at:
            raise ValueError("assisted export update time precedes its request")
    for key in ("archive_sha256", "manifest_sha256"):
        digest = entry.get(key)
        if digest is not None:
            _validate_digest(_required_string(entry, key), key)
    blocking_reason = entry.get("blocking_reason")
    if blocking_reason is not None:
        WebExportPauseReason(_required_string(entry, "blocking_reason"))
    if entry.get("manifest_sha256") is not None and entry.get("archive_sha256") is None:
        raise ValueError("assisted export manifest state requires an archive digest")
    if stage == "downloaded" and entry.get("archive_sha256") is None:
        raise ValueError("downloaded assisted export state requires an archive digest")
    if stage == "staged" and (
        entry.get("archive_sha256") is None or entry.get("manifest_sha256") is None
    ):
        raise ValueError("staged assisted export state requires archive and manifest digests")
    return entry


def _validate_entry_registration(
    entry: dict[str, object], registration: dict[str, str | None]
) -> None:
    for key in ("source_system", "source_account_id", "device_id", "scope", "project_id"):
        if entry[key] != registration[key]:
            raise ValueError(f"assisted export state conflicts with registered {key}")


def _state_path(settings: Settings) -> Path:
    return settings.run_root / "private" / "web-export-assistant" / "state.json"


def _load_state(path: Path) -> dict[str, object]:
    if not path.exists() and not path.is_symlink():
        return {"version": ASSISTANT_STATE_VERSION, "sources": {}}
    if path.is_symlink() or not path.is_file():
        raise ValueError("assisted export state must be a private regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("assisted export state must be a private regular file")
        if metadata.st_size > MAX_STATE_BYTES:
            raise ValueError("assisted export state exceeds its size limit")
        raw = handle.read(MAX_STATE_BYTES + 1)
    try:
        loaded: object = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("assisted export state is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise ValueError("assisted export state must be an object")
    state = cast(dict[str, object], loaded)
    if set(state) != {"version", "sources"} or state.get("version") != ASSISTANT_STATE_VERSION:
        raise ValueError("assisted export state version or keys are invalid")
    sources = state.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("assisted export sources must be an object")
    for key, entry in cast(dict[str, object], sources).items():
        if len(key) != 64 or any(character not in "0123456789abcdef" for character in key):
            raise ValueError("assisted export source key is invalid")
        validated = _validated_entry(entry)
        expected_key = _source_key(
            SourceSystem(cast(str, validated["source_system"])),
            cast(str, validated["source_account_id"]),
        )
        if key != expected_key:
            raise ValueError("assisted export source key does not match its identity")
    return state


def _write_state(path: Path, state: dict[str, object]) -> None:
    raw = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("assisted export state exceeds its size limit")
    temporary = path.parent / f".state-{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@contextmanager
def _exclusive_state_lock(root: Path) -> Generator[None]:
    lock_path = root / "state.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ValueError("assisted export lock must be a private regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_existing_state_directories(settings: Settings, root: Path) -> None:
    for path in _state_directories(settings, root):
        if not path.exists() and not path.is_symlink():
            continue
        _validate_private_directory(path)


def _prepare_private_state_directory(settings: Settings, root: Path) -> None:
    for path in _state_directories(settings, root):
        if path.is_symlink():
            raise ValueError("assisted export state directory must not be a symlink")
        path.mkdir(mode=0o700, exist_ok=True)
        _validate_private_directory(path)
        path.chmod(0o700)


def _state_directories(settings: Settings, root: Path) -> tuple[Path, ...]:
    expected_root = settings.run_root / "private" / "web-export-assistant"
    if root != expected_root:
        raise ValueError("assisted export state root is invalid")
    return (
        settings.data_root,
        settings.run_root,
        settings.run_root / "private",
        expected_root,
    )


def _validate_private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("assisted export state directory must be a private directory")
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("assisted export state directory must be owned and private")


def _source_key(source_system: SourceSystem, source_account_id: str) -> str:
    return hashlib.sha256(f"{source_system.value}\0{source_account_id}".encode()).hexdigest()


def _normalized_time(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    return _normalized_time(parsed, label)


def _validate_digest(value: str | None, label: str) -> None:
    if (
        value is None
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _canonical_value(value: str, label: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be an exact canonical value")
    return value


def _required_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"assisted export source state {key} is invalid")
    return item


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"assisted export state contains a duplicate key: {key}")
        result[key] = value
    return result


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
