from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import stat
from collections.abc import Generator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.human_gates import (
    HumanGate,
    HumanGateKind,
    human_gates_as_dict,
    parse_human_gates,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_directory_no_replace,
    publish_file_no_replace,
)
from cross_assistant_memory.storage import (
    LEGACY_RECOVERY_SCHEMA_VERSIONS,
    SCHEMA_VERSION,
    SQLITE_SIDECAR_SUFFIXES,
    Ledger,
)

SETUP_FORMAT_VERSION = 2
MAX_SETUP_PLAN_BYTES = 64 * 1024
SETUP_PUBLICATION_MARKER = "setup-publication.sha256"
SETUP_STAGING_MARKER = "setup-staging.sha256"
SETUP_PUBLICATION_MARKER_BYTES = 65


class SetupState(StrEnum):
    ABSENT = "absent"
    READY = "ready"
    ACTIVE = "active"
    PARTIAL = "partial"
    LEGACY = "legacy"
    NEWER = "newer"
    INVALID = "invalid"
    UNSAFE = "unsafe"


class SetupAction(StrEnum):
    INITIALIZE = "initialize_fresh_local_ledger"
    VERIFY = "verify_existing_local_ledger"
    PAUSE = "pause_for_operator"


@dataclass(frozen=True)
class SetupInspection:
    data_root: Path
    state: SetupState
    schema_version: int | None
    state_sha256: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "format_version": SETUP_FORMAT_VERSION,
            "status": self.state.value,
            "data_root": str(self.data_root),
            "database_path": str(self.data_root / "ledger.sqlite3"),
            "schema_version": self.schema_version,
            "supported_schema_version": SCHEMA_VERSION,
            "state_sha256": self.state_sha256,
            "reasons": list(self.reasons),
            "mutated": False,
        }


@dataclass(frozen=True)
class SetupPlan:
    data_root: Path
    action: SetupAction
    observed_state: SetupState
    observed_schema_version: int | None
    observed_state_sha256: str
    required_human_gates: tuple[HumanGate, ...]
    side_effects: tuple[str, ...]
    pause_reasons: tuple[str, ...]

    def _digest_surface(self) -> dict[str, object]:
        return {
            "format_version": SETUP_FORMAT_VERSION,
            "operation": "setup",
            "data_root": str(self.data_root),
            "database_path": str(self.data_root / "ledger.sqlite3"),
            "action": self.action.value,
            "observed_state": self.observed_state.value,
            "observed_schema_version": self.observed_schema_version,
            "supported_schema_version": SCHEMA_VERSION,
            "observed_state_sha256": self.observed_state_sha256,
            "required_human_gates": human_gates_as_dict(self.required_human_gates),
            "side_effects": list(self.side_effects),
            "pause_reasons": list(self.pause_reasons),
        }

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._digest_surface())).hexdigest()

    def as_dict(self, *, status: str = "planned") -> dict[str, object]:
        return {
            "status": status,
            **self._digest_surface(),
            "plan_sha256": self.plan_sha256,
            "execute_required": self.action is SetupAction.INITIALIZE,
        }


def inspect_setup(settings: Settings) -> SetupInspection:
    with _setup_inspection_writer_lease(settings) as writer_held:
        return _inspect_setup(settings, writer_held=writer_held)


def _inspect_setup(settings: Settings, *, writer_held: bool) -> SetupInspection:
    root = _absolute(settings.data_root)
    database = root / "ledger.sqlite3"
    sidecars = tuple(Path(f"{database}{suffix}") for suffix in SQLITE_SIDECAR_SUFFIXES)
    writer_lock = root / "runs" / "ledger-writer.lock"
    publication_marker = root / SETUP_PUBLICATION_MARKER
    descendants = (
        root / "objects",
        root / "objects" / "sha256",
        root / "runs",
        database,
        *sidecars,
        writer_lock,
        publication_marker,
    )
    ancestor_reason = _unsafe_existing_ancestor(root)
    if ancestor_reason is not None:
        metadata: list[dict[str, object]] = [{"path": ".", "kind": "unresolved"}]
        return SetupInspection(
            root,
            SetupState.UNSAFE,
            None,
            _state_digest(root, metadata),
            (ancestor_reason,),
        )
    root_entry, root_reason = _inspect_path(root, root)
    metadata = [root_entry]
    if root_reason is not None:
        return SetupInspection(
            root,
            SetupState.UNSAFE,
            None,
            _state_digest(root, metadata),
            (root_reason,),
        )
    if not root.exists():
        return SetupInspection(root, SetupState.ABSENT, None, _state_digest(root, metadata), ())
    if root_entry.get("kind") != "directory":
        return SetupInspection(
            root,
            SetupState.UNSAFE,
            None,
            _state_digest(root, metadata),
            ("data_root_not_directory",),
        )

    unsafe_reasons: list[str] = []
    entries_by_path: dict[Path, dict[str, object]] = {}
    for path in descendants:
        entry, reason = _inspect_path(path, root)
        metadata.append(entry)
        entries_by_path[path] = entry
        if reason is not None:
            unsafe_reasons.append(reason)

    digest = _state_digest(root, metadata)
    if unsafe_reasons:
        return SetupInspection(
            root,
            SetupState.UNSAFE,
            None,
            digest,
            tuple(sorted(set(unsafe_reasons))),
        )
    if not database.exists():
        return SetupInspection(
            root,
            SetupState.PARTIAL,
            None,
            digest,
            ("database_missing",),
        )
    present_sidecars = tuple(
        path.name for path in sidecars if entries_by_path[path].get("kind") != "absent"
    )
    checkpointed_wal = (
        writer_held
        and present_sidecars == (database.name + "-wal", database.name + "-shm")
        and entries_by_path[Path(f"{database}-wal")].get("size") == 0
    )
    if present_sidecars and not checkpointed_wal:
        return SetupInspection(
            root,
            SetupState.ACTIVE,
            None,
            digest,
            ("sqlite_sidecars_present:" + ",".join(present_sidecars),),
        )

    schema_version, schema_error = _read_schema_version(database)
    if checkpointed_wal:
        current_metadata = [_inspect_path(path, root)[0] for path in (root, *descendants)]
        if current_metadata != metadata:
            return SetupInspection(
                root,
                SetupState.ACTIVE,
                None,
                _state_digest(root, current_metadata),
                ("sqlite_state_changed_during_inspection",),
            )
    if schema_error is not None:
        return SetupInspection(
            root,
            SetupState.INVALID,
            None,
            digest,
            (schema_error,),
        )
    if schema_version == SCHEMA_VERSION:
        missing = tuple(
            label
            for label, path, expected_kind in (
                ("object_root_missing", root / "objects" / "sha256", "directory"),
                ("run_root_missing", root / "runs", "directory"),
                ("writer_lock_missing", writer_lock, "file"),
            )
            if entries_by_path[path].get("kind") != expected_kind
        )
        if missing:
            return SetupInspection(root, SetupState.PARTIAL, schema_version, digest, missing)
        return SetupInspection(root, SetupState.READY, schema_version, digest, ())
    if schema_version in LEGACY_RECOVERY_SCHEMA_VERSIONS or (
        schema_version is not None and schema_version < SCHEMA_VERSION
    ):
        return SetupInspection(
            root,
            SetupState.LEGACY,
            schema_version,
            digest,
            ("approved_migration_required",),
        )
    if schema_version is not None and schema_version > SCHEMA_VERSION:
        return SetupInspection(
            root,
            SetupState.NEWER,
            schema_version,
            digest,
            ("newer_runtime_required",),
        )
    return SetupInspection(
        root,
        SetupState.INVALID,
        schema_version,
        digest,
        ("schema_version_unavailable",),
    )


def build_setup_plan(settings: Settings) -> SetupPlan:
    inspection = inspect_setup(settings)
    if inspection.state is SetupState.ABSENT:
        action = SetupAction.INITIALIZE
        gates: tuple[HumanGate, ...] = ()
        effects = (
            "create_private_data_root",
            f"initialize_schema_{SCHEMA_VERSION}",
            "write_setup_publication_marker",
        )
    elif inspection.state is SetupState.READY:
        action = SetupAction.VERIFY
        gates = ()
        effects = ()
    else:
        action = SetupAction.PAUSE
        gates = (
            HumanGate(
                kind=HumanGateKind.OPERATOR_REVIEW,
                action="review_nonfresh_local_setup_state",
                target=str(inspection.data_root),
                target_state_sha256=inspection.state_sha256,
                impact="Setup remains paused and makes no changes to the existing state.",
                rollback="No rollback is needed because the plan cannot mutate this state.",
            ),
        )
        effects = ()
    return SetupPlan(
        data_root=inspection.data_root,
        action=action,
        observed_state=inspection.state,
        observed_schema_version=inspection.schema_version,
        observed_state_sha256=inspection.state_sha256,
        required_human_gates=gates,
        side_effects=effects,
        pause_reasons=inspection.reasons,
    )


def write_setup_plan(plan: SetupPlan, output: Path) -> dict[str, object]:
    destination = _absolute(output)
    if _is_within(destination, plan.data_root):
        raise ValueError("setup plan output must be outside the target data root")
    payload = _canonical_json(plan.as_dict()) + b"\n"
    if len(payload) > MAX_SETUP_PLAN_BYTES:
        raise RuntimeError("setup plan exceeds the supported size")
    parent_descriptor = open_directory_no_symlinks(destination.parent, "setup plan parent")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    created = False
    try:
        descriptor = os.open(destination.name, flags, 0o400, dir_fd=parent_descriptor)
        created = True
        try:
            os.fchmod(descriptor, 0o400)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    except Exception:
        if created:
            with suppress(FileNotFoundError):
                os.unlink(destination.name, dir_fd=parent_descriptor)
        raise
    finally:
        os.close(parent_descriptor)
    return {
        "status": "planned",
        "plan_path": str(destination),
        "plan_sha256": plan.plan_sha256,
        "action": plan.action.value,
        "observed_state": plan.observed_state.value,
        "execute_required": plan.action is SetupAction.INITIALIZE,
        "required_human_gates": human_gates_as_dict(plan.required_human_gates),
        "pause_reasons": list(plan.pause_reasons),
    }


def apply_setup_plan(
    settings: Settings,
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    execute: bool,
) -> dict[str, object]:
    plan = load_setup_plan(plan_path)
    if not hmac.compare_digest(expected_plan_sha256, plan.plan_sha256):
        raise ValueError("setup plan SHA-256 does not match")
    if plan.data_root != _absolute(settings.data_root):
        raise ValueError("setup plan targets a different data root")
    if plan.action is SetupAction.PAUSE:
        raise RuntimeError("setup plan requires operator review before any mutation")
    root = plan.data_root
    if not execute:
        return cast(
            dict[str, object],
            _apply_or_preview_setup_state(settings, plan, execute=False),
        )

    _ensure_private_parent(root.parent)
    with _exclusive_setup_target(plan):
        converged = _apply_or_preview_setup_state(settings, plan, execute=True)
        if converged is not None:
            return converged
        if root.exists() or root.is_symlink():
            raise RuntimeError("fresh setup target is no longer absent")
        staging = _setup_staging_path(plan)
        created_staging = False
        published = False
        if staging.exists() or staging.is_symlink():
            staged = inspect_setup(Settings(staging))
            if staged.state is SetupState.READY:
                try:
                    _verify_setup_publication_marker(plan, data_root=staging)
                except RuntimeError:
                    _discard_incomplete_setup_staging(plan, staging)
                else:
                    staging_marker = staging / SETUP_STAGING_MARKER
                    if staging_marker.exists() or staging_marker.is_symlink():
                        _verify_setup_marker(plan, staging_marker, "setup staging marker")
                        _fsync_setup_tree(staging)
                        _remove_setup_staging_marker(staging)
            else:
                _discard_incomplete_setup_staging(plan, staging)
        if not staging.exists():
            staging.mkdir(mode=0o700)
            staging.chmod(0o700)
            created_staging = True
            try:
                _write_setup_staging_marker(staging, plan)
                Ledger(Settings(staging))
                _write_setup_publication_marker(staging, plan)
                staged = inspect_setup(Settings(staging))
                if staged.state is not SetupState.READY:
                    raise RuntimeError("fresh setup staging root did not verify")
                _fsync_setup_tree(staging)
                _remove_setup_staging_marker(staging)
            except BaseException:
                shutil.rmtree(staging, ignore_errors=True)
                raise
        try:
            publish_directory_no_replace(
                staging,
                root,
                required_mode=0o700,
                label="setup",
            )
            published = True
        finally:
            if created_staging and not published:
                shutil.rmtree(staging, ignore_errors=True)

        verified = verify_setup(Settings(root))
        return {
            **verified,
            "status": "initialized",
            "plan_sha256": plan.plan_sha256,
            "previous_state_sha256": plan.observed_state_sha256,
            "mutated": True,
        }


def _apply_or_preview_setup_state(
    settings: Settings,
    plan: SetupPlan,
    *,
    execute: bool,
) -> dict[str, object] | None:
    current = inspect_setup(settings)
    if plan.action is SetupAction.INITIALIZE and current.state is SetupState.READY:
        _verify_setup_publication_marker(plan)
        verified = verify_setup(settings)
        return {
            **verified,
            "status": "already_configured",
            "plan_sha256": plan.plan_sha256,
            "mutated": False,
        }
    if (
        current.state is not plan.observed_state
        or current.schema_version != plan.observed_schema_version
        or not hmac.compare_digest(current.state_sha256, plan.observed_state_sha256)
    ):
        raise RuntimeError("setup target changed after the plan was created")
    if plan.action is SetupAction.VERIFY:
        verified = verify_setup(settings)
        return {
            **verified,
            "status": "already_configured",
            "plan_sha256": plan.plan_sha256,
            "mutated": False,
        }
    if not execute:
        return plan.as_dict(status="awaiting_execute")
    return None


def verify_setup(settings: Settings) -> dict[str, object]:
    with _setup_inspection_writer_lease(settings) as writer_held:
        return _verify_setup(settings, writer_held=writer_held)


def _verify_setup(settings: Settings, *, writer_held: bool) -> dict[str, object]:
    inspection = _inspect_setup(settings, writer_held=writer_held)
    if inspection.state is not SetupState.READY:
        raise RuntimeError(
            f"setup verification requires ready state; found {inspection.state.value}"
        )
    descriptor, _normalized = open_regular_file_no_symlinks(
        inspection.data_root / "ledger.sqlite3",
        "ledger database",
    )
    try:
        before = os.fstat(descriptor)
        with closing(_connect_sqlite_descriptor(descriptor)) as connection:
            result = cast(str, connection.execute("PRAGMA integrity_check").fetchone()[0])
            schema_version = cast(
                int,
                connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0],
            )
            source_files = cast(
                int,
                connection.execute("SELECT COUNT(*) FROM source_files").fetchone()[0],
            )
            events = cast(int, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            invariant_error = _application_invariant_error(connection)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise RuntimeError("ledger database changed during setup verification")
    finally:
        os.close(descriptor)
    if result != "ok" or schema_version != SCHEMA_VERSION:
        raise RuntimeError("ledger integrity or schema verification failed")
    if invariant_error is not None:
        raise RuntimeError(f"ledger application invariant failed: {invariant_error}")
    final_inspection = _inspect_setup(settings, writer_held=writer_held)
    if final_inspection.state is not SetupState.READY or not hmac.compare_digest(
        final_inspection.state_sha256, inspection.state_sha256
    ):
        raise RuntimeError("setup target changed during verification")
    return {
        "status": "verified",
        "data_root": str(inspection.data_root),
        "schema_version": schema_version,
        "state_sha256": final_inspection.state_sha256,
        "source_files": source_files,
        "events": events,
        "integrity_check": "ok",
        "foreign_key_check": "ok",
        "installation_count": 1,
        "mutated": False,
    }


def load_setup_plan(path: Path) -> SetupPlan:
    descriptor, normalized = open_regular_file_no_symlinks(path, "setup plan")
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o400:
            raise ValueError("setup plan must be owned by the current user with mode 0400")
        if before.st_nlink != 1 or before.st_size > MAX_SETUP_PLAN_BYTES:
            raise ValueError("setup plan must be a singly linked bounded regular file")
        payload = _read_bounded(descriptor, MAX_SETUP_PLAN_BYTES)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise RuntimeError("setup plan changed while it was read")
    finally:
        os.close(descriptor)
    try:
        raw_value: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("setup plan is not valid JSON") from error
    if not isinstance(raw_value, dict):
        raise ValueError("setup plan must be a JSON object")
    raw = cast(dict[str, Any], raw_value)
    expected_keys = {
        "status",
        "format_version",
        "operation",
        "data_root",
        "database_path",
        "action",
        "observed_state",
        "observed_schema_version",
        "supported_schema_version",
        "observed_state_sha256",
        "required_human_gates",
        "side_effects",
        "pause_reasons",
        "plan_sha256",
        "execute_required",
    }
    if set(raw) != expected_keys:
        raise ValueError("setup plan fields do not match format version 2")
    if raw["format_version"] != SETUP_FORMAT_VERSION or raw["operation"] != "setup":
        raise ValueError("unsupported setup plan format")
    data_root = _absolute(Path(_require_string(raw, "data_root")))
    if raw["database_path"] != str(data_root / "ledger.sqlite3"):
        raise ValueError("setup plan database path is inconsistent")
    if raw["supported_schema_version"] != SCHEMA_VERSION:
        raise ValueError("setup plan targets a different schema version")
    try:
        action = SetupAction(_require_string(raw, "action"))
        observed_state = SetupState(_require_string(raw, "observed_state"))
    except ValueError as error:
        raise ValueError("setup plan action or state is invalid") from error
    observed_schema_value: object = raw["observed_schema_version"]
    if observed_schema_value is not None and (
        isinstance(observed_schema_value, bool) or not isinstance(observed_schema_value, int)
    ):
        raise ValueError("setup plan schema version is invalid")
    observed_schema = observed_schema_value
    plan = SetupPlan(
        data_root=data_root,
        action=action,
        observed_state=observed_state,
        observed_schema_version=observed_schema,
        observed_state_sha256=_require_sha256(raw, "observed_state_sha256"),
        required_human_gates=parse_human_gates(raw["required_human_gates"]),
        side_effects=_string_tuple(raw, "side_effects"),
        pause_reasons=_string_tuple(raw, "pause_reasons"),
    )
    _validate_plan_semantics(plan)
    if not hmac.compare_digest(_require_sha256(raw, "plan_sha256"), plan.plan_sha256):
        raise ValueError("setup plan content does not match its SHA-256")
    if raw["execute_required"] is not (plan.action is SetupAction.INITIALIZE):
        raise ValueError("setup plan execute requirement is inconsistent")
    if raw["status"] != "planned":
        raise ValueError("setup plan status is invalid")
    if normalized != _absolute(path):
        raise ValueError("setup plan path normalization changed")
    return plan


def _validate_plan_semantics(plan: SetupPlan) -> None:
    if plan.observed_state is SetupState.ABSENT:
        expected = (
            SetupAction.INITIALIZE,
            None,
            (),
            (
                "create_private_data_root",
                f"initialize_schema_{SCHEMA_VERSION}",
                "write_setup_publication_marker",
            ),
            (),
        )
    elif plan.observed_state is SetupState.READY:
        expected = (SetupAction.VERIFY, SCHEMA_VERSION, (), (), ())
    else:
        if not plan.pause_reasons:
            raise ValueError("paused setup plan must include a reason")
        expected = (
            SetupAction.PAUSE,
            plan.observed_schema_version,
            (
                HumanGate(
                    kind=HumanGateKind.OPERATOR_REVIEW,
                    action="review_nonfresh_local_setup_state",
                    target=str(plan.data_root),
                    target_state_sha256=plan.observed_state_sha256,
                    impact="Setup remains paused and makes no changes to the existing state.",
                    rollback="No rollback is needed because the plan cannot mutate this state.",
                ),
            ),
            (),
            plan.pause_reasons,
        )
    observed = (
        plan.action,
        plan.observed_schema_version,
        plan.required_human_gates,
        plan.side_effects,
        plan.pause_reasons,
    )
    if observed != expected:
        raise ValueError("setup plan action does not match its observed state")


def _read_schema_version(database: Path) -> tuple[int | None, str | None]:
    descriptor, _normalized = open_regular_file_no_symlinks(database, "ledger database")
    try:
        before = os.fstat(descriptor)
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600:
            return None, "database_permissions_invalid"
        if before.st_nlink != 1:
            return None, "database_link_count_invalid"
        try:
            with closing(_connect_sqlite_descriptor(descriptor)) as connection:
                row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
                version = row[0] if row is not None else None
                invariant_error = (
                    _application_invariant_error(connection) if version == SCHEMA_VERSION else None
                )
        except sqlite3.Error:
            return None, "schema_metadata_unavailable"
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            return None, "database_changed_during_inspection"
    finally:
        os.close(descriptor)
    if version is not None and not isinstance(version, int):
        return None, "schema_version_invalid"
    if invariant_error is not None:
        return version, invariant_error
    return version, None


def _connect_sqlite_descriptor(descriptor: int) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:/dev/fd/{descriptor}?mode=ro&immutable=1",
        uri=True,
    )
    connection.execute("PRAGMA query_only = ON")
    return connection


def _application_invariant_error(connection: sqlite3.Connection) -> str | None:
    installation_count = cast(
        int,
        connection.execute("SELECT COUNT(*) FROM installations").fetchone()[0],
    )
    if installation_count != 1:
        return "installation_count_invalid"
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        return "foreign_key_violation"
    return None


def _write_setup_publication_marker(staging: Path, plan: SetupPlan) -> None:
    _write_setup_marker(
        staging,
        SETUP_PUBLICATION_MARKER,
        plan,
        "setup publication marker",
    )


def _write_setup_staging_marker(staging: Path, plan: SetupPlan) -> None:
    _write_setup_marker(staging, SETUP_STAGING_MARKER, plan, "setup staging marker")


def _write_setup_marker(staging: Path, name: str, plan: SetupPlan, label: str) -> None:
    payload = f"{plan.plan_sha256}\n".encode("ascii")
    temporary_name = f"{_setup_marker_temp_prefix(name, plan)}{secrets.token_hex(16)}"
    parent_descriptor = open_directory_no_symlinks(staging, "setup staging directory")
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    try:
        publish_file_no_replace(
            staging / temporary_name,
            staging / name,
            required_mode=0o600,
            label=label,
        )
    except FileExistsError as error:
        raise RuntimeError(f"{label} already exists") from error


def _verify_setup_publication_marker(plan: SetupPlan, *, data_root: Path | None = None) -> None:
    try:
        _verify_setup_marker(
            plan,
            (data_root or plan.data_root) / SETUP_PUBLICATION_MARKER,
            "setup publication marker",
        )
    except RuntimeError as error:
        raise RuntimeError("setup target was not published by this plan") from error


def _verify_setup_marker(plan: SetupPlan, marker: Path, label: str) -> None:
    try:
        descriptor, _normalized = open_regular_file_no_symlinks(
            marker,
            label,
        )
    except (FileNotFoundError, ValueError) as error:
        raise RuntimeError(f"{label} does not belong to this plan") from error
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != SETUP_PUBLICATION_MARKER_BYTES
        ):
            raise RuntimeError(f"{label} does not belong to this plan")
        payload = _read_bounded(descriptor, SETUP_PUBLICATION_MARKER_BYTES)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise RuntimeError("setup publication marker changed while it was read")
    finally:
        os.close(descriptor)
    expected = f"{plan.plan_sha256}\n".encode("ascii")
    if not hmac.compare_digest(payload, expected):
        raise RuntimeError(f"{label} does not belong to this plan")


def _discard_incomplete_setup_staging(plan: SetupPlan, staging: Path) -> None:
    details = staging.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise RuntimeError("setup staging state is incomplete or unsafe")
    entries = tuple(staging.iterdir())
    marker = staging / SETUP_STAGING_MARKER
    if entries:
        try:
            _verify_setup_marker(plan, marker, "setup staging marker")
        except RuntimeError as error:
            if not _only_safe_staging_marker_temps(plan, entries):
                raise RuntimeError("setup staging state is incomplete or unsafe") from error
    shutil.rmtree(staging)
    _fsync_directory(staging.parent)


def _only_safe_staging_marker_temps(plan: SetupPlan, entries: tuple[Path, ...]) -> bool:
    prefix = _setup_marker_temp_prefix(SETUP_STAGING_MARKER, plan)
    for entry in entries:
        if not entry.name.startswith(prefix):
            return False
        details = entry.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
        ):
            return False
    return True


def _setup_marker_temp_prefix(name: str, plan: SetupPlan) -> str:
    return f".{name}.{plan.plan_sha256}.tmp-"


def _remove_setup_staging_marker(staging: Path) -> None:
    parent_descriptor = open_directory_no_symlinks(staging, "setup staging directory")
    try:
        os.unlink(SETUP_STAGING_MARKER, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _setup_staging_path(plan: SetupPlan) -> Path:
    return plan.data_root.with_name(f".{plan.data_root.name}.setup-{plan.plan_sha256}")


@contextmanager
def _exclusive_setup_target(plan: SetupPlan) -> Generator[None]:
    lock = plan.data_root.with_name(f".{plan.data_root.name}.setup.lock")
    parent_descriptor = open_directory_no_symlinks(lock.parent, "setup target parent")
    descriptor: int | None = None
    locked = False
    created = False
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(
                lock.name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(lock.name, flags, dir_fd=parent_descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or (not created and stat.S_IMODE(details.st_mode) != 0o600)
        ):
            raise RuntimeError("setup target lock is unsafe")
        if created:
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        if created:
            os.fsync(parent_descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        if locked and descriptor is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


@contextmanager
def _setup_inspection_writer_lease(settings: Settings) -> Generator[bool]:
    root = _absolute(settings.data_root)
    lock = root / "runs" / "ledger-writer.lock"
    if _unsafe_existing_ancestor(lock) is not None:
        yield False
        return
    entry, reason = _inspect_path(lock, root)
    if reason is not None or entry.get("kind") != "file":
        yield False
        return
    try:
        descriptor, _normalized = open_regular_file_no_symlinks(lock, "ledger writer lock")
    except ValueError:
        yield False
        return
    locked = False
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            yield False
            return
        # A retained empty WAL is checkpointed, but does not prove that a writer is idle.
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        locked = True
        try:
            current = lock.lstat()
        except FileNotFoundError:
            yield False
            return
        yield _stat_identity(before) == _stat_identity(current)
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _inspect_path(path: Path, root: Path) -> tuple[dict[str, object], str | None]:
    relative = "." if path == root else str(path.relative_to(root))
    try:
        details = path.lstat()
    except FileNotFoundError:
        return {"path": relative, "kind": "absent"}, None
    mode = stat.S_IMODE(details.st_mode)
    entry: dict[str, object] = {
        "path": relative,
        "mode": mode,
        "uid": details.st_uid,
        "gid": details.st_gid,
        "device": details.st_dev,
        "inode": details.st_ino,
        "size": details.st_size,
        "mtime_ns": details.st_mtime_ns,
    }
    if stat.S_ISLNK(details.st_mode):
        entry["kind"] = "symlink"
        return entry, f"symlink_not_allowed:{relative}"
    if stat.S_ISDIR(details.st_mode):
        entry["kind"] = "directory"
        if details.st_uid != os.geteuid() or mode != 0o700:
            return entry, f"directory_permissions_invalid:{relative}"
        return entry, None
    if stat.S_ISREG(details.st_mode):
        entry["kind"] = "file"
        if details.st_uid != os.geteuid() or mode != 0o600 or details.st_nlink != 1:
            return entry, f"file_permissions_invalid:{relative}"
        return entry, None
    entry["kind"] = "other"
    return entry, f"unsupported_path_type:{relative}"


def _state_digest(root: Path, metadata: list[dict[str, object]]) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "format_version": SETUP_FORMAT_VERSION,
                "data_root": str(root),
                "paths": metadata,
            }
        )
    ).hexdigest()


def _unsafe_existing_ancestor(path: Path) -> str | None:
    for ancestor in reversed(path.parents):
        try:
            details = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            return "data_root_ancestor_is_symlink"
        if not stat.S_ISDIR(details.st_mode):
            return "data_root_ancestor_not_directory"
    return None


def _ensure_private_parent(parent: Path) -> None:
    ancestor_reason = _unsafe_existing_ancestor(parent)
    if ancestor_reason is not None:
        raise ValueError(ancestor_reason)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = parent.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o022
    ):
        raise ValueError("setup target parent must be owned by the current user and not writable")


def _fsync_setup_tree(root: Path) -> None:
    for path in (
        root / "ledger.sqlite3",
        root / "runs" / "ledger-writer.lock",
        root / SETUP_PUBLICATION_MARKER,
    ):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in (root / "objects" / "sha256", root / "objects", root / "runs", root):
        descriptor = open_directory_no_symlinks(path, "setup staging directory")
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = open_directory_no_symlinks(path, "setup directory")
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ValueError("setup plan exceeds the supported size")
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        written += os.write(descriptor, view[written:])


def _stat_identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _require_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"setup plan {key} is invalid")
    return value


def _require_sha256(raw: dict[str, Any], key: str) -> str:
    value = _require_string(raw, key)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"setup plan {key} is invalid")
    return value


def _string_tuple(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    value: object = raw.get(key)
    if not isinstance(value, list):
        raise ValueError(f"setup plan {key} is invalid")
    values = cast(list[object], value)
    if not all(isinstance(item, str) for item in values):
        raise ValueError(f"setup plan {key} is invalid")
    return tuple(cast(str, item) for item in values)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
