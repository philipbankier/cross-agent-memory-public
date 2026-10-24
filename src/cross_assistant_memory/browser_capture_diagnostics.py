"""Bounded, content-free local capture health, separate from encrypted payloads."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import TypedDict, cast
from uuid import uuid4

from cross_assistant_memory.safe_files import open_directory_no_symlinks

PAGE_STATUSES = frozenset(
    {
        "checking_page",
        "page_not_eligible",
        "identity_not_verified",
        "identity_settling",
        "account_not_authorized",
        "messages_not_ready",
        "snapshot_changed",
        "unchanged",
        "ready_to_queue",
        "queued",
        "already_queued",
        "queue_full",
        "capture_failed",
        "inactive",
    }
)
DELIVERY_STATUSES = frozenset(
    {
        "ready",
        "uploaded",
        "upload_pending",
        "upload_unconfigured",
        "upload_not_authorized",
        "invalid_receipt",
        "capture_failed",
    }
)
MAX_BYTES = 64 * 1024


class DiagnosticPage(TypedDict):
    page_key: str
    provider: str
    status: str
    extension_version: str
    account_binding: str | None
    checked_at: float


def _page(value: object, checked_at: float) -> DiagnosticPage:
    if not isinstance(value, dict):
        raise ValueError("invalid capture diagnostic")
    row = cast(dict[str, object], value)
    if set(row) != {"page_key", "provider", "status", "extension_version", "account_binding"}:
        raise ValueError("invalid capture diagnostic fields")
    for key, pattern in (
        ("page_key", r"[0-9a-f]{64}"),
        ("extension_version", r"[0-9]{1,4}(\.[0-9]{1,4}){2,3}"),
    ):
        if not isinstance(row[key], str) or not re.fullmatch(pattern, cast(str, row[key])):
            raise ValueError("invalid capture diagnostic identity")
    if not isinstance(row["provider"], str) or row["provider"] not in {
        "chatgpt_web",
        "claude_web",
        "grok_web",
    }:
        raise ValueError("invalid capture diagnostic provider")
    if not isinstance(row["status"], str) or row["status"] not in PAGE_STATUSES:
        raise ValueError("invalid capture diagnostic status")
    binding = row["account_binding"]
    if binding is not None and (
        not isinstance(binding, str) or not re.fullmatch(r"source_account:[0-9a-f]{64}", binding)
    ):
        raise ValueError("invalid capture diagnostic binding")
    _timestamp(checked_at)
    return cast(DiagnosticPage, {**row, "checked_at": checked_at})


def _timestamp(value: object) -> None:
    if (
        type(value) not in (float, int)
        or not math.isfinite(cast(float, value))
        or cast(float, value) < 0
    ):
        raise ValueError("invalid diagnostic timestamp")


def _validate_state(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(cast(dict[str, object], value)) != {
        "pages",
        "delivery",
        "last_receipts",
    }:
        raise ValueError("invalid capture diagnostic file")
    state = cast(dict[str, object], value)
    for section, limit in (("pages", 32), ("last_receipts", 64)):
        items = state[section]
        if not isinstance(items, dict) or len(cast(dict[str, object], items)) > limit:
            raise ValueError("invalid diagnostic inventory")
        for key, raw in cast(dict[str, object], items).items():
            if not isinstance(raw, dict):
                raise ValueError("invalid diagnostic record")
            row = cast(dict[str, object], raw)
            _timestamp(row.get("checked_at"))
            if section == "pages":
                checked = _page(
                    {k: v for k, v in row.items() if k != "checked_at"},
                    cast(float, row["checked_at"]),
                )
                if key != checked["page_key"]:
                    raise ValueError("invalid diagnostic page key")
            else:
                if (
                    set(row) != {"batch_sha256", "receipt_created_at", "checked_at"}
                    or not re.fullmatch(r"source_account:[0-9a-f]{64}", key)
                    or not isinstance(row["batch_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", row["batch_sha256"])
                    or not isinstance(row["receipt_created_at"], str)
                ):
                    raise ValueError("invalid diagnostic receipt")
                _receipt_time(row["receipt_created_at"])
    delivery = state["delivery"]
    if delivery is not None:
        if not isinstance(delivery, dict) or set(cast(dict[str, object], delivery)) != {
            "status",
            "checked_at",
        }:
            raise ValueError("invalid delivery diagnostic")
        row = cast(dict[str, object], delivery)
        if not isinstance(row["status"], str) or row["status"] not in DELIVERY_STATUSES:
            raise ValueError("invalid delivery status")
        _timestamp(row["checked_at"])
    return state


def _receipt_time(value: str) -> None:
    if len(value) > 40 or datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("invalid receipt timestamp")


def _validate_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ValueError("unsafe capture diagnostic file")


def _read(directory: int, name: str) -> dict[str, object]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return {"pages": {}, "delivery": None, "last_receipts": {}}
    with os.fdopen(fd, "rb") as handle:
        _validate_file(os.fstat(handle.fileno()))
        body = handle.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("capture diagnostic is too large")
    value: object = json.loads(body)
    return _validate_state(value)


def _state(root: Path, update: tuple[str, str, object] | None) -> dict[str, object]:
    directory = open_directory_no_symlinks(root.parent, "capture diagnostic directory")
    lock: int | None = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("capture diagnostic directory must be private")
        name = root.with_suffix(".diagnostics.json").name
        lock = os.open(
            name + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        _validate_file(os.fstat(lock))
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = _read(directory, name)
        if update is not None:
            section, key, value = update
            if section == "delivery":
                state[section] = value
            else:
                items = cast(dict[str, dict[str, object]], state[section])
                items[key] = cast(dict[str, object], value)
                limit = 32 if section == "pages" else 64
                state[section] = dict(
                    sorted(items.items(), key=lambda pair: cast(float, pair[1]["checked_at"]))[
                        -limit:
                    ]
                )
            body = json.dumps(_validate_state(state), separators=(",", ":")).encode()
            if len(body) > MAX_BYTES:
                raise ValueError("capture diagnostic is too large")
            temporary = name + "." + uuid4().hex + ".tmp"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(body)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=directory)
        return state
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def record_diagnostic(root: Path, report: dict[str, object], *, now: float | None = None) -> None:
    row = _page(report, time.time() if now is None else now)
    _state(root, ("pages", row["page_key"], row))


def record_delivery(root: Path, status: str) -> None:
    if status not in DELIVERY_STATUSES:
        raise ValueError("invalid delivery status")
    _state(root, ("delivery", "", {"status": status, "checked_at": time.time()}))


def record_receipt(root: Path, account: str, batch: str, created_at: str) -> None:
    if not re.fullmatch(r"source_account:[0-9a-f]{64}", account):
        raise ValueError("invalid receipt account")
    _receipt_time(created_at)
    # Persist only opaque receipt identity, never a provider message or URL.
    _state(
        root,
        (
            "last_receipts",
            account,
            {
                "batch_sha256": hashlib.sha256(batch.encode()).hexdigest(),
                "receipt_created_at": created_at,
                "checked_at": time.time(),
            },
        ),
    )


def inspect_diagnostics(root: Path, *, now: float | None = None) -> dict[str, object]:
    state = _state(root, None)
    observed = time.time() if now is None else now
    pages: list[dict[str, object]] = []
    for value in cast(dict[str, dict[str, object]], state["pages"]).values():
        at = cast(float, value["checked_at"])
        checked = _page({k: v for k, v in value.items() if k != "checked_at"}, at)
        age = max(0.0, observed - at)
        pages.append({**checked, "age_seconds": round(age, 3), "stale": age > 120})
    return {"pages": pages, "delivery": state["delivery"], "last_receipts": state["last_receipts"]}
