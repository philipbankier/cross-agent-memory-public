from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.evidence_deletion import (
    EncryptedDeletionTarget,
    EncryptedEvidencePurger,
)
from cross_assistant_memory.models import DeletionKind, ObservationRetirement, SourceSystem
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_file_no_replace,
)
from cross_assistant_memory.storage import Ledger, exclusive_ledger_writer

DELETION_PLAN_FORMAT_VERSION = 3
MAX_DELETION_PLAN_BYTES = 1024 * 1024


def retained_copy_disclosure(
    targets: tuple[EncryptedDeletionTarget, ...] = (), *, performed: bool = False
) -> dict[str, object]:
    disclosure: dict[str, object] = {
        "operation_scope": "local_canonical_state_only",
        "remote_deletion_performed": False,
        "requires_separate_version_aware_deletion": True,
        "copies_outside_operation": [
            "local_snapshots_and_recovery_packages",
            "portable_exports",
            "remote_backup_objects_and_versions",
            "provider_native_histories_and_exports",
        ],
    }
    if targets:
        disclosure.update(
            {
                "operation_scope": "local_canonical_state_and_registered_encrypted_objects",
                "remote_deletion_performed": performed
                and any(item.backend_profile == "backblaze-b2-s3-v1" for item in targets),
                "registered_encrypted_object_count": len(targets),
                "registered_encrypted_cleanup_completed": performed,
            }
        )
    return disclosure


def build_deletion_plan(
    settings: Settings,
    *,
    kind: DeletionKind,
    source_system: SourceSystem,
    source_account: str,
    conversation_id: str | None,
    authorized_by: str,
    authorization_scope: str,
    reason: str,
    output: Path,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
    retirement_pairs: Sequence[ObservationRetirement] = (),
) -> dict[str, Any]:
    planned = create_deletion_plan(
        settings,
        kind=kind,
        source_system=source_system,
        source_account=source_account,
        conversation_id=conversation_id,
        authorized_by=authorized_by,
        authorization_scope=authorization_scope,
        reason=reason,
        encrypted_evidence_purger=encrypted_evidence_purger,
        retirement_pairs=retirement_pairs,
    )
    plan = cast(dict[str, Any], planned["plan"])
    _write_private_plan(output, plan)
    plan_path = output.expanduser()
    return {key: value for key, value in planned.items() if key != "plan"} | {
        "output": str(plan_path)
    }


def create_deletion_plan(
    settings: Settings,
    *,
    kind: DeletionKind,
    source_system: SourceSystem,
    source_account: str,
    conversation_id: str | None,
    authorized_by: str,
    authorization_scope: str,
    reason: str,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
    retirement_pairs: Sequence[ObservationRetirement] = (),
) -> dict[str, Any]:
    authorization = {
        "authorized_by": _bounded_text(authorized_by, "authorized-by"),
        "authorization_scope": _bounded_text(authorization_scope, "authorization-scope"),
        "reason": _bounded_text(reason, "reason"),
    }
    ledger = Ledger(
        settings,
        read_only=True,
        require_checkpointed=False,
        encrypted_evidence_purger=encrypted_evidence_purger,
    )
    target = ledger.plan_deletion(
        kind=kind,
        source_system=source_system,
        source_account=source_account,
        conversation_id=conversation_id,
        retirement_pairs=retirement_pairs,
    )
    plan: dict[str, Any] = {
        "format_version": (
            DELETION_PLAN_FORMAT_VERSION
            if kind is DeletionKind.OBSOLETE_OBSERVATIONS
            else 2
            if target["encrypted_targets"]
            else 1
        ),
        "text_free": True,
        "created_at": _now(),
        "selector": {
            "kind": target["kind"],
            "source_system": target["source_system"],
            "source_account_digests": target["source_account_digests"],
            "conversation_digest": target["conversation_digest"],
        },
        "expected_generation_digest": target["expected_generation_digest"],
        "target_digest": target["target_digest"],
        "target_counts": target["target_counts"],
        "authorization": authorization,
    }
    if target["encrypted_targets"]:
        plan["encrypted_targets"] = target["encrypted_targets"]
    if kind is DeletionKind.OBSOLETE_OBSERVATIONS:
        plan["selector"]["retirement_pairs"] = [
            {"event_id": pair.event_id, "replacement_event_id": pair.replacement_event_id}
            for pair in sorted(retirement_pairs)
        ]
    selector, _, _ = _validate_plan(plan)
    return {
        "status": "planned",
        "plan": plan,
        "plan_sha256": _sha256_bytes(_serialize_plan(plan)),
        "kind": kind.value,
        "source_system": source_system.value,
        "expected_generation_digest": target["expected_generation_digest"],
        "target_digest": target["target_digest"],
        "target_counts": target["target_counts"],
        "retained_copy_disclosure": retained_copy_disclosure(selector["encrypted_targets"]),
        "text_free": True,
    }


def apply_deletion_plan(
    settings: Settings,
    *,
    plan_path: Path,
    expected_plan_sha256: str,
    execute: bool,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
) -> dict[str, Any]:
    _required_digest(expected_plan_sha256, "expected deletion plan")
    plan, actual_plan_sha256 = _load_private_plan(plan_path)
    if actual_plan_sha256 != expected_plan_sha256:
        raise RuntimeError("deletion plan digest does not match the approved plan")
    return _apply_deletion_plan(
        settings,
        plan=plan,
        actual_plan_sha256=actual_plan_sha256,
        execute=execute,
        encrypted_evidence_purger=encrypted_evidence_purger,
    )


def apply_deletion_plan_value(
    settings: Settings,
    *,
    plan: dict[str, Any],
    expected_plan_sha256: str,
    execute: bool,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
) -> dict[str, Any]:
    _required_digest(expected_plan_sha256, "expected deletion plan")
    actual_plan_sha256 = _sha256_bytes(_serialize_plan(plan))
    if actual_plan_sha256 != expected_plan_sha256:
        raise RuntimeError("deletion plan digest does not match the approved plan")
    return _apply_deletion_plan(
        settings,
        plan=plan,
        actual_plan_sha256=actual_plan_sha256,
        execute=execute,
        encrypted_evidence_purger=encrypted_evidence_purger,
    )


def load_deletion_plan(path: Path) -> dict[str, Any]:
    plan, _ = _load_private_plan(path)
    _validate_plan(plan)
    return plan


def write_deletion_plan(path: Path, plan: dict[str, Any]) -> None:
    _validate_plan(plan)
    _write_private_plan(path, plan)


def deletion_plan_authorized_by(plan: dict[str, Any]) -> str:
    _, authorization, _ = _validate_plan(plan)
    return authorization["authorized_by"]


def _apply_deletion_plan(
    settings: Settings,
    *,
    plan: dict[str, Any],
    actual_plan_sha256: str,
    execute: bool,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
) -> dict[str, Any]:
    selector, authorization, target_counts = _validate_plan(plan)
    preview = {
        "status": "preview",
        "execute": execute,
        "plan_sha256": actual_plan_sha256,
        "kind": selector["kind"].value,
        "source_system": selector["source_system"].value,
        "expected_generation_digest": selector["expected_generation_digest"],
        "target_digest": selector["target_digest"],
        "target_counts": target_counts,
        "retained_copy_disclosure": retained_copy_disclosure(selector["encrypted_targets"]),
        "text_free": True,
    }
    if not execute:
        return preview
    if selector["encrypted_targets"] and encrypted_evidence_purger is None:
        raise RuntimeError("encrypted deletion requires its configured purger")
    with exclusive_ledger_writer(settings) as writer_token:
        ledger = Ledger(
            settings,
            exclusive_writer_token=writer_token,
            encrypted_evidence_purger=encrypted_evidence_purger,
        )
        result = ledger.apply_deletion(
            kind=selector["kind"],
            source_system=selector["source_system"],
            source_account_digests=selector["source_account_digests"],
            conversation_digest=selector["conversation_digest"],
            expected_generation_digest=selector["expected_generation_digest"],
            expected_target_digest=selector["target_digest"],
            expected_target_counts=target_counts,
            plan_sha256=actual_plan_sha256,
            authorized_by=authorization["authorized_by"],
            authorization_scope=authorization["authorization_scope"],
            reason=authorization["reason"],
            encrypted_targets=selector["encrypted_targets"],
            retirement_pairs=selector["retirement_pairs"],
        )
    return {
        **preview,
        **result,
        "execute": True,
        "retained_copy_disclosure": retained_copy_disclosure(
            selector["encrypted_targets"], performed=True
        ),
    }


def _validate_plan(
    plan: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str], dict[str, int]]:
    version = plan.get("format_version")
    if type(version) is not int or version not in {1, 2, DELETION_PLAN_FORMAT_VERSION}:
        raise ValueError("unsupported deletion plan version")
    _require_exact_keys(
        plan,
        {
            "format_version",
            "text_free",
            "created_at",
            "selector",
            "expected_generation_digest",
            "target_digest",
            "target_counts",
            "authorization",
        }
        | ({"encrypted_targets"} if version == 2 else set()),
        "deletion plan",
    )
    if plan["text_free"] is not True:
        raise ValueError("deletion plan must be marked text-free")
    _bounded_text(plan["created_at"], "created-at")
    raw_selector = plan["selector"]
    if not isinstance(raw_selector, dict):
        raise ValueError("deletion selector must be an object")
    selector_value = cast(dict[str, Any], raw_selector)
    _require_exact_keys(
        selector_value,
        {"kind", "source_system", "source_account_digests", "conversation_digest"}
        | ({"retirement_pairs"} if version == 3 else set()),
        "deletion selector",
    )
    kind = DeletionKind(_bounded_text(selector_value["kind"], "deletion kind"))
    source_system = SourceSystem(_bounded_text(selector_value["source_system"], "source system"))
    retirement_pairs: tuple[ObservationRetirement, ...] = ()
    if version == 3:
        if kind is not DeletionKind.OBSOLETE_OBSERVATIONS:
            raise ValueError("plan version 3 requires observation retirement")
        raw_pairs = selector_value["retirement_pairs"]
        if not isinstance(raw_pairs, list) or not 0 < len(cast(list[object], raw_pairs)) <= 100:
            raise ValueError("retirement pairs must be a bounded nonempty list")
        pairs: list[ObservationRetirement] = []
        for raw_pair in cast(list[object], raw_pairs):
            if not isinstance(raw_pair, dict):
                raise ValueError("retirement pair must be an object")
            pair = cast(dict[str, Any], raw_pair)
            _require_exact_keys(pair, {"event_id", "replacement_event_id"}, "retirement pair")
            pairs.append(
                ObservationRetirement(
                    event_id=_bounded_text(pair["event_id"], "obsolete event"),
                    replacement_event_id=_bounded_text(
                        pair["replacement_event_id"], "replacement event"
                    ),
                )
            )
        retirement_pairs = tuple(pairs)
        obsolete = {pair.event_id for pair in pairs}
        if (
            tuple(sorted(pairs)) != retirement_pairs
            or len(obsolete) != len(pairs)
            or obsolete.intersection(pair.replacement_event_id for pair in pairs)
        ):
            raise ValueError("retirement pairs must be sorted, unique and disjoint")
    elif kind is DeletionKind.OBSOLETE_OBSERVATIONS:
        raise ValueError("observation retirement requires plan version 3")
    raw_account_digests = selector_value["source_account_digests"]
    if not isinstance(raw_account_digests, list) or not raw_account_digests:
        raise ValueError("deletion selector requires source-account digests")
    account_digest_values = cast(list[object], raw_account_digests)
    account_digests = tuple(
        _required_digest(item, "source-account digest") for item in account_digest_values
    )
    if tuple(sorted(set(account_digests))) != account_digests:
        raise ValueError("source-account digests must be sorted and unique")
    raw_conversation_digest = selector_value["conversation_digest"]
    conversation_digest = (
        None
        if raw_conversation_digest is None
        else _required_digest(raw_conversation_digest, "conversation digest")
    )
    if kind is DeletionKind.CONVERSATION and conversation_digest is None:
        raise ValueError("conversation deletion requires a conversation digest")
    if kind is DeletionKind.OBSOLETE_OBSERVATIONS and (
        conversation_digest is None
        or source_system
        not in {SourceSystem.CODEX, SourceSystem.CLAUDE_CODE, SourceSystem.GROK_BUILD}
    ):
        raise ValueError("observation retirement requires a native source and exact conversation")
    if kind is DeletionKind.SOURCE_ACCOUNT and conversation_digest is not None:
        raise ValueError("source-account deletion cannot include a conversation digest")
    if kind is DeletionKind.WEB_CONTAINERS and conversation_digest is not None:
        raise ValueError("web-container retirement cannot include a conversation digest")
    if kind is DeletionKind.WEB_CONTAINERS and source_system not in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        raise ValueError("web-container retirement requires a web source system")

    raw_authorization = plan["authorization"]
    if not isinstance(raw_authorization, dict):
        raise ValueError("deletion authorization must be an object")
    authorization_value = cast(dict[str, Any], raw_authorization)
    _require_exact_keys(
        authorization_value,
        {"authorized_by", "authorization_scope", "reason"},
        "deletion authorization",
    )
    authorization = {
        key: _bounded_text(authorization_value[key], key.replace("_", "-"))
        for key in ("authorized_by", "authorization_scope", "reason")
    }

    raw_counts = plan["target_counts"]
    if not isinstance(raw_counts, dict):
        raise ValueError("deletion target counts must be an object")
    target_counts: dict[str, int] = {}
    for key, count in cast(dict[object, object], raw_counts).items():
        if not isinstance(key, str):
            raise ValueError("deletion target count names must be strings")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("deletion target counts must be non-negative integers")
        target_counts[key] = count
    selector = {
        "kind": kind,
        "source_system": source_system,
        "source_account_digests": account_digests,
        "conversation_digest": conversation_digest,
        "expected_generation_digest": _required_digest(
            plan["expected_generation_digest"], "expected ledger generation"
        ),
        "target_digest": _required_digest(plan["target_digest"], "deletion target"),
        "encrypted_targets": _encrypted_targets(plan) if version == 2 else (),
        "retirement_pairs": retirement_pairs,
    }
    return selector, authorization, target_counts


def _encrypted_targets(plan: dict[str, Any]) -> tuple[EncryptedDeletionTarget, ...]:
    raw = plan["encrypted_targets"]
    if not isinstance(raw, list) or not raw or len(cast(list[object], raw)) > 10_000:
        raise ValueError("encrypted deletion targets must be a bounded nonempty list")
    targets = tuple(EncryptedDeletionTarget.from_dict(item) for item in cast(list[object], raw))
    identities = tuple(item.object_id for item in targets)
    if identities != tuple(sorted(set(identities))):
        raise ValueError("encrypted deletion targets must be sorted and unique")
    return targets


def _load_private_plan(path: Path) -> tuple[dict[str, Any], str]:
    descriptor, normalized = open_regular_file_no_symlinks(path, "deletion plan")
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
        ):
            raise ValueError("deletion plan must be an owner-only 0400 single-link file")
        if before.st_size > MAX_DELETION_PLAN_BYTES:
            raise ValueError("deletion plan exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_DELETION_PLAN_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != before.st_size or _stat_identity(before) != _stat_identity(after):
        raise RuntimeError(f"deletion plan changed while reading: {normalized}")
    try:
        value: object = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("deletion plan must contain valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("deletion plan must contain an object")
    return cast(dict[str, Any], value), _sha256_bytes(raw)


def _write_private_plan(path: Path, value: dict[str, Any]) -> None:
    target = Path(os.path.abspath(path.expanduser()))
    if target.exists() or target.is_symlink():
        raise ValueError(f"deletion plan output already exists: {target}")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    parent_descriptor = open_directory_no_symlinks(target.parent, "deletion plan parent")
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    temporary = target.parent / temporary_name
    raw = _serialize_plan(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary_name, flags, 0o400, dir_fd=parent_descriptor)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            raise
        publish_file_no_replace(
            temporary,
            target,
            required_mode=0o400,
            label="deletion plan",
        )
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} has an invalid shape")


def _bounded_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized.encode()) > 1024 or "\x00" in normalized:
        raise ValueError(f"{label} must be a non-empty string of at most 1024 bytes")
    return normalized


def _required_digest(value: object, label: str) -> str:
    digest = _bounded_text(value, label)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _serialize_plan(value: dict[str, Any]) -> bytes:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if len(raw) > MAX_DELETION_PLAN_BYTES:
        raise ValueError("deletion plan exceeds its byte limit")
    return raw


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
