from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CreateDeviceEnrollmentRequest,
    MemoryApplication,
    RegisterSourceAccountRequest,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.human_gates import (
    HumanGate,
    HumanGateKind,
    human_gates_as_dict,
    parse_human_gates,
)
from cross_assistant_memory.models import (
    CLIENT_KIND_CAPABILITIES,
    Capability,
    ClientKind,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
    publish_file_no_replace,
)
from cross_assistant_memory.storage import (
    Ledger,
    generate_client_credential_token,
    generate_device_enrollment_code,
    parse_client_credential_token,
)

IDENTITY_SETUP_PLAN_FORMAT_VERSION = 2
IDENTITY_SETUP_RECEIPT_FORMAT_VERSION = 1
MAX_IDENTITY_SETUP_FILE_BYTES = 64 * 1024
MAX_SECRET_BYTES = 4096


class IdentitySetupOperation(StrEnum):
    CLIENT_REGISTRATION = "client_registration"
    CLIENT_CREDENTIAL = "client_credential"
    DEVICE_ENROLLMENT = "device_enrollment"
    SOURCE_REGISTRATION = "source_registration"


@dataclass(frozen=True)
class IdentitySetupPlan:
    operation: IdentitySetupOperation
    data_root: Path
    installation_id: str
    expected_identity_state_sha256: str
    request: dict[str, object]
    intent: dict[str, object]
    required_human_gates: tuple[HumanGate, ...]
    side_effects: tuple[str, ...]

    def _digest_surface(self) -> dict[str, object]:
        return {
            "format_version": IDENTITY_SETUP_PLAN_FORMAT_VERSION,
            "operation": self.operation.value,
            "data_root": str(self.data_root),
            "installation_id": self.installation_id,
            "expected_identity_state_sha256": self.expected_identity_state_sha256,
            "request": self.request,
            "intent": self.intent,
            "required_human_gates": human_gates_as_dict(self.required_human_gates),
            "side_effects": list(self.side_effects),
        }

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._digest_surface())).hexdigest()

    def as_dict(self, *, status: str = "awaiting_human_gate") -> dict[str, object]:
        return {
            "status": status,
            **self._digest_surface(),
            "plan_sha256": self.plan_sha256,
            "execute_required": True,
            "secret_material_exposed": False,
        }


def plan_client_registration(
    settings: Settings,
    plan_output: Path,
    *,
    label: str,
    kind: ClientKind,
    capabilities: Sequence[Capability],
    intent_key: str,
) -> dict[str, object]:
    normalized_label = _identity_value(label, "client label")
    normalized_intent = _identity_value(intent_key, "client intent key")
    normalized_capabilities = tuple(sorted(set(capabilities), key=lambda item: item.value))
    if not normalized_capabilities:
        raise ValueError("at least one client capability is required")
    disallowed = set(normalized_capabilities) - CLIENT_KIND_CAPABILITIES[kind]
    if disallowed:
        values = ", ".join(sorted(item.value for item in disallowed))
        raise ValueError(f"{kind.value} client cannot receive capabilities: {values}")
    request: dict[str, object] = {
        "label": normalized_label,
        "kind": kind.value,
        "capabilities": [item.value for item in normalized_capabilities],
        "intent_key": normalized_intent,
    }
    existing = _reuse_existing_plan(
        plan_output,
        operation=IdentitySetupOperation.CLIENT_REGISTRATION,
        settings=settings,
        request=request,
    )
    if existing is not None:
        return _plan_result(existing, plan_output, reused=True)
    installation_id, generation = _ledger_identity(settings)
    client_id = _stable_id("client", installation_id, normalized_intent)
    intent = {**request, "client_id": client_id}
    plan = _build_plan(
        operation=IdentitySetupOperation.CLIENT_REGISTRATION,
        settings=settings,
        installation_id=installation_id,
        generation=generation,
        request=request,
        intent=intent,
        gate=HumanGate(
            kind=HumanGateKind.CLIENT_IDENTITY_CHANGE,
            action="register_client_identity",
            target=client_id,
            target_state_sha256=_target_state_digest(
                installation_id,
                generation,
                intent,
            ),
            impact="Creates one client principal with the listed capabilities.",
            rollback="Revoke the client and each credential issued to it.",
        ),
        side_effects=("create_client_identity", "grant_listed_capabilities"),
    )
    return _write_or_reuse_plan(plan, plan_output)


def apply_client_registration(
    settings: Settings,
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    execute: bool,
) -> dict[str, object]:
    plan = _load_expected_plan(
        settings,
        plan_path,
        expected_plan_sha256,
        IdentitySetupOperation.CLIENT_REGISTRATION,
    )
    if not execute:
        return _plan_result(plan, plan_path, reused=True)
    with _exclusive_plan_application(plan_path, plan):
        request = plan.request
        result = MemoryApplication(Ledger(settings)).register_client(
            ApplicationPrincipal.local_admin("local:setup"),
            label=cast(str, request["label"]),
            kind=ClientKind(cast(str, request["kind"])),
            capabilities=tuple(
                Capability(cast(str, item)) for item in cast(list[object], request["capabilities"])
            ),
            intent_key=cast(str, request["intent_key"]),
            expected_identity_state_sha256=plan.expected_identity_state_sha256,
            expected_installation_id=plan.installation_id,
        )
        sanitized = _sanitized_result(result)
        _require_result_identity(plan, sanitized)
        replayed = bool(result["replayed"])
        _store_or_verify_receipt(plan_path, plan, None, sanitized)
        return _application_result(plan_path, plan, sanitized, replayed=replayed)


def plan_client_credential(
    settings: Settings,
    plan_output: Path,
    *,
    client_id: str,
    intent_key: str,
    ttl_hours: int,
    credential_output: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    normalized_client = _identity_value(client_id, "client id")
    normalized_intent = _identity_value(intent_key, "credential intent key")
    if ttl_hours <= 0 or ttl_hours > 24 * 365:
        raise ValueError("credential TTL must be between 1 and 8760 hours")
    output = _absolute(credential_output)
    request: dict[str, object] = {
        "client_id": normalized_client,
        "intent_key": normalized_intent,
        "ttl_hours": ttl_hours,
        "credential_output": str(output),
    }
    existing = _reuse_existing_plan(
        plan_output,
        operation=IdentitySetupOperation.CLIENT_CREDENTIAL,
        settings=settings,
        request=request,
    )
    if existing is not None:
        return _plan_result(existing, plan_output, reused=True)
    _require_new_secret_output(output, "client credential output")
    installation_id, generation = _ledger_identity(settings)
    credential_id = _stable_secret_id(
        "credential_setup", installation_id, normalized_client, normalized_intent
    )
    planned_at = _normalized_now(now)
    expires_at = planned_at + timedelta(hours=ttl_hours)
    intent: dict[str, object] = {
        "client_id": normalized_client,
        "credential_id": credential_id,
        "expires_at": expires_at.isoformat(),
        "credential_output": str(output),
    }
    target_state = _target_state_digest(
        installation_id,
        generation,
        intent,
        secret_output=output,
    )
    plan = _build_plan(
        operation=IdentitySetupOperation.CLIENT_CREDENTIAL,
        settings=settings,
        installation_id=installation_id,
        generation=generation,
        request=request,
        intent=intent,
        gate=HumanGate(
            kind=HumanGateKind.CLIENT_CREDENTIAL_CHANGE,
            action="issue_and_store_client_credential",
            target=f"{credential_id}:{output}",
            target_state_sha256=target_state,
            impact="Creates one expiring bearer credential and writes it to a private file.",
            rollback="Revoke the credential and remove only the named private output file.",
        ),
        side_effects=("create_client_credential", "write_private_credential_file"),
    )
    return _write_or_reuse_plan(plan, plan_output)


def apply_client_credential(
    settings: Settings,
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    execute: bool,
) -> dict[str, object]:
    plan = _load_expected_plan(
        settings,
        plan_path,
        expected_plan_sha256,
        IdentitySetupOperation.CLIENT_CREDENTIAL,
    )
    if not execute:
        return _plan_result(plan, plan_path, reused=True)
    output = Path(cast(str, plan.intent["credential_output"]))
    with _exclusive_plan_application(plan_path, plan):
        token, output_exists = _prepare_or_read_secret(
            plan,
            output,
            generator=lambda: generate_client_credential_token(
                credential_id=cast(str, plan.intent["credential_id"])
            ),
            decoder=_decode_client_token,
            label="client credential",
        )
        result = MemoryApplication(Ledger(settings)).issue_client_credential(
            ApplicationPrincipal.local_admin("local:setup"),
            cast(str, plan.intent["client_id"]),
            expires_at=_parse_timestamp(cast(str, plan.intent["expires_at"])),
            token=token,
            expected_identity_state_sha256=plan.expected_identity_state_sha256,
            expected_installation_id=plan.installation_id,
            require_existing=output_exists,
        )
        sanitized = _sanitized_result(result)
        _require_result_identity(plan, sanitized)
        _store_or_verify_receipt(plan_path, plan, token, sanitized)
        if not output_exists:
            _publish_staged_secret(plan, output, token, "client credential")
        return _application_result(
            plan_path,
            plan,
            sanitized,
            replayed=bool(result["replayed"]),
            secret_output=output,
            secret_written=not output_exists,
        )


def plan_device_enrollment(
    settings: Settings,
    plan_output: Path,
    *,
    label: str,
    platform: str,
    intent_key: str,
    ttl_minutes: int,
    credential_ttl_days: int,
    enrollment_output: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    normalized_label = _identity_value(label, "device label")
    normalized_platform = _identity_value(platform, "device platform")
    normalized_intent = _identity_value(intent_key, "device enrollment intent key")
    if ttl_minutes <= 0 or ttl_minutes > 60:
        raise ValueError("enrollment TTL must be between 1 and 60 minutes")
    if credential_ttl_days <= 0 or credential_ttl_days > 365:
        raise ValueError("device credential TTL must be between 1 and 365 days")
    output = _absolute(enrollment_output)
    request: dict[str, object] = {
        "label": normalized_label,
        "platform": normalized_platform,
        "intent_key": normalized_intent,
        "ttl_minutes": ttl_minutes,
        "credential_ttl_days": credential_ttl_days,
        "enrollment_output": str(output),
    }
    existing = _reuse_existing_plan(
        plan_output,
        operation=IdentitySetupOperation.DEVICE_ENROLLMENT,
        settings=settings,
        request=request,
    )
    if existing is not None:
        return _plan_result(existing, plan_output, reused=True)
    _require_new_secret_output(output, "device enrollment output")
    installation_id, generation = _ledger_identity(settings)
    enrollment_id = _stable_secret_id("enrollment_setup", installation_id, normalized_intent)
    planned_at = _normalized_now(now)
    expires_at = planned_at + timedelta(minutes=ttl_minutes)
    credential_expires_at = planned_at + timedelta(days=credential_ttl_days)
    intent: dict[str, object] = {
        "enrollment_id": enrollment_id,
        "label": normalized_label,
        "platform": normalized_platform,
        "expires_at": expires_at.isoformat(),
        "credential_expires_at": credential_expires_at.isoformat(),
        "enrollment_output": str(output),
    }
    target_state = _target_state_digest(
        installation_id,
        generation,
        intent,
        secret_output=output,
    )
    plan = _build_plan(
        operation=IdentitySetupOperation.DEVICE_ENROLLMENT,
        settings=settings,
        installation_id=installation_id,
        generation=generation,
        request=request,
        intent=intent,
        gate=HumanGate(
            kind=HumanGateKind.DEVICE_ENROLLMENT_CHANGE,
            action="create_and_store_device_enrollment_code",
            target=f"{enrollment_id}:{output}",
            target_state_sha256=target_state,
            impact="Creates one short-lived pairing code and writes it to a private file.",
            rollback=(
                "Do not distribute the code and let it expire; revoke a credential if redeemed."
            ),
        ),
        side_effects=("create_device_enrollment", "write_private_enrollment_file"),
    )
    return _write_or_reuse_plan(plan, plan_output)


def apply_device_enrollment(
    settings: Settings,
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    execute: bool,
) -> dict[str, object]:
    plan = _load_expected_plan(
        settings,
        plan_path,
        expected_plan_sha256,
        IdentitySetupOperation.DEVICE_ENROLLMENT,
    )
    if not execute:
        return _plan_result(plan, plan_path, reused=True)
    output = Path(cast(str, plan.intent["enrollment_output"]))
    with _exclusive_plan_application(plan_path, plan):
        code, output_exists = _prepare_or_read_secret(
            plan,
            output,
            generator=lambda: generate_device_enrollment_code(
                enrollment_id=cast(str, plan.intent["enrollment_id"])
            ),
            decoder=_decode_enrollment_code,
            label="device enrollment code",
        )
        result = MemoryApplication(Ledger(settings)).create_device_enrollment(
            ApplicationPrincipal.local_admin("local:setup"),
            CreateDeviceEnrollmentRequest(
                label=cast(str, plan.intent["label"]),
                platform=cast(str, plan.intent["platform"]),
                expires_at=_parse_timestamp(cast(str, plan.intent["expires_at"])),
                credential_expires_at=_parse_timestamp(
                    cast(str, plan.intent["credential_expires_at"])
                ),
            ),
            code=code,
            expected_identity_state_sha256=plan.expected_identity_state_sha256,
            expected_installation_id=plan.installation_id,
            require_existing=output_exists,
        )
        sanitized = _sanitized_result(result)
        _require_result_identity(plan, sanitized)
        _store_or_verify_receipt(plan_path, plan, code, sanitized)
        if not output_exists:
            _publish_staged_secret(plan, output, code, "device enrollment code")
        return _application_result(
            plan_path,
            plan,
            sanitized,
            replayed=bool(result["replayed"]),
            secret_output=output,
            secret_written=not output_exists,
        )


def plan_source_registration(
    settings: Settings,
    plan_output: Path,
    *,
    device_id: str,
    source_system: SourceSystem,
    account_label: str,
    scope: Scope,
    project_id: str | None,
) -> dict[str, object]:
    normalized_device = _identity_value(device_id, "device id")
    normalized_label = _identity_value(account_label, "source account label")
    if scope is Scope.PROJECT and not project_id:
        raise ValueError("project_id is required for project-scoped source accounts")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped source accounts may carry project_id")
    normalized_project = (
        _identity_value(project_id, "project id") if project_id is not None else None
    )
    request: dict[str, object] = {
        "device_id": normalized_device,
        "source_system": source_system.value,
        "account_label": normalized_label,
        "scope": scope.value,
        "project_id": normalized_project,
    }
    existing = _reuse_existing_plan(
        plan_output,
        operation=IdentitySetupOperation.SOURCE_REGISTRATION,
        settings=settings,
        request=request,
    )
    if existing is not None:
        return _plan_result(existing, plan_output, reused=True)
    installation_id, generation = _ledger_identity(settings)
    source_account_id = _stable_id(
        "source_account",
        installation_id,
        normalized_device,
        source_system.value,
        normalized_label,
    )
    intent = {**request, "source_account_id": source_account_id}
    plan = _build_plan(
        operation=IdentitySetupOperation.SOURCE_REGISTRATION,
        settings=settings,
        installation_id=installation_id,
        generation=generation,
        request=request,
        intent=intent,
        gate=HumanGate(
            kind=HumanGateKind.SOURCE_REGISTRATION,
            action="register_source_account_policy",
            target=source_account_id,
            target_state_sha256=_target_state_digest(
                installation_id,
                generation,
                intent,
            ),
            impact="Creates one source identity with the listed immutable access policy.",
            rollback="Use the separately approved source-account deletion workflow.",
        ),
        side_effects=("create_source_account", "create_immutable_source_policy"),
    )
    return _write_or_reuse_plan(plan, plan_output)


def apply_source_registration(
    settings: Settings,
    plan_path: Path,
    *,
    expected_plan_sha256: str,
    execute: bool,
) -> dict[str, object]:
    plan = _load_expected_plan(
        settings,
        plan_path,
        expected_plan_sha256,
        IdentitySetupOperation.SOURCE_REGISTRATION,
    )
    if not execute:
        return _plan_result(plan, plan_path, reused=True)
    request = plan.request
    with _exclusive_plan_application(plan_path, plan):
        result = MemoryApplication(Ledger(settings)).register_source_account(
            ApplicationPrincipal.local_admin("local:setup"),
            RegisterSourceAccountRequest(
                device_id=cast(str, request["device_id"]),
                source_system=SourceSystem(cast(str, request["source_system"])),
                account_label=cast(str, request["account_label"]),
                scope=Scope(cast(str, request["scope"])),
                project_id=cast(str | None, request["project_id"]),
            ),
            expected_identity_state_sha256=plan.expected_identity_state_sha256,
            expected_installation_id=plan.installation_id,
        )
        sanitized = _sanitized_result(result)
        _require_result_identity(plan, sanitized)
        replayed = bool(result["replayed"])
        _store_or_verify_receipt(plan_path, plan, None, sanitized)
        return _application_result(plan_path, plan, sanitized, replayed=replayed)


def load_identity_setup_plan(path: Path) -> IdentitySetupPlan:
    payload = _read_private_file(
        path,
        required_mode=0o400,
        max_bytes=MAX_IDENTITY_SETUP_FILE_BYTES,
        label="identity setup plan",
    )
    try:
        value: object = json.loads(payload, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("identity setup plan is not valid JSON") from error
    raw = _exact_object(
        value,
        {
            "status",
            "format_version",
            "operation",
            "data_root",
            "installation_id",
            "expected_identity_state_sha256",
            "request",
            "intent",
            "required_human_gates",
            "side_effects",
            "plan_sha256",
            "execute_required",
            "secret_material_exposed",
        },
        "identity setup plan",
    )
    if (
        raw["status"] != "awaiting_human_gate"
        or raw["format_version"] != IDENTITY_SETUP_PLAN_FORMAT_VERSION
        or raw["execute_required"] is not True
        or raw["secret_material_exposed"] is not False
    ):
        raise ValueError("identity setup plan metadata is invalid")
    try:
        operation = IdentitySetupOperation(_require_string(raw, "operation"))
    except ValueError as error:
        raise ValueError("identity setup operation is invalid") from error
    plan = IdentitySetupPlan(
        operation=operation,
        data_root=_absolute(Path(_require_string(raw, "data_root"))),
        installation_id=_require_string(raw, "installation_id"),
        expected_identity_state_sha256=_require_sha256(raw, "expected_identity_state_sha256"),
        request=_string_keyed_object(raw["request"], "identity setup request"),
        intent=_string_keyed_object(raw["intent"], "identity setup intent"),
        required_human_gates=parse_human_gates(raw["required_human_gates"]),
        side_effects=_string_tuple(raw["side_effects"], "identity setup side effects"),
    )
    _validate_plan_semantics(plan)
    if not hmac.compare_digest(_require_sha256(raw, "plan_sha256"), plan.plan_sha256):
        raise ValueError("identity setup plan content does not match its SHA-256")
    return plan


def _build_plan(
    *,
    operation: IdentitySetupOperation,
    settings: Settings,
    installation_id: str,
    generation: str,
    request: dict[str, object],
    intent: dict[str, object],
    gate: HumanGate,
    side_effects: tuple[str, ...],
) -> IdentitySetupPlan:
    return IdentitySetupPlan(
        operation=operation,
        data_root=_absolute(settings.data_root),
        installation_id=installation_id,
        expected_identity_state_sha256=generation,
        request=request,
        intent=intent,
        required_human_gates=(gate,),
        side_effects=side_effects,
    )


def _validate_plan_semantics(plan: IdentitySetupPlan) -> None:
    _identity_value(plan.installation_id, "installation id")
    _validate_sha256(plan.expected_identity_state_sha256, "expected identity state")
    request_keys: dict[IdentitySetupOperation, set[str]] = {
        IdentitySetupOperation.CLIENT_REGISTRATION: {
            "label",
            "kind",
            "capabilities",
            "intent_key",
        },
        IdentitySetupOperation.CLIENT_CREDENTIAL: {
            "client_id",
            "intent_key",
            "ttl_hours",
            "credential_output",
        },
        IdentitySetupOperation.DEVICE_ENROLLMENT: {
            "label",
            "platform",
            "intent_key",
            "ttl_minutes",
            "credential_ttl_days",
            "enrollment_output",
        },
        IdentitySetupOperation.SOURCE_REGISTRATION: {
            "device_id",
            "source_system",
            "account_label",
            "scope",
            "project_id",
        },
    }
    intent_keys: dict[IdentitySetupOperation, set[str]] = {
        IdentitySetupOperation.CLIENT_REGISTRATION: request_keys[
            IdentitySetupOperation.CLIENT_REGISTRATION
        ]
        | {"client_id"},
        IdentitySetupOperation.CLIENT_CREDENTIAL: {
            "client_id",
            "credential_id",
            "expires_at",
            "credential_output",
        },
        IdentitySetupOperation.DEVICE_ENROLLMENT: {
            "enrollment_id",
            "label",
            "platform",
            "expires_at",
            "credential_expires_at",
            "enrollment_output",
        },
        IdentitySetupOperation.SOURCE_REGISTRATION: request_keys[
            IdentitySetupOperation.SOURCE_REGISTRATION
        ]
        | {"source_account_id"},
    }
    if (
        set(plan.request) != request_keys[plan.operation]
        or set(plan.intent) != intent_keys[plan.operation]
    ):
        raise ValueError("identity setup plan fields do not match its operation")
    expected_gate, expected_effects = _expected_gate_and_effects(plan)
    if plan.required_human_gates != (expected_gate,) or plan.side_effects != expected_effects:
        raise ValueError("identity setup gate or side effects do not match its operation")
    _validate_operation_values(plan)


def _validate_operation_values(plan: IdentitySetupPlan) -> None:
    request = plan.request
    intent = plan.intent
    if plan.operation is IdentitySetupOperation.CLIENT_REGISTRATION:
        kind = ClientKind(_require_string(request, "kind"))
        capabilities_value = request["capabilities"]
        if not isinstance(capabilities_value, list):
            raise ValueError("client capabilities must be a list")
        capabilities = tuple(
            Capability(cast(str, item)) for item in cast(list[object], capabilities_value)
        )
        if not capabilities or capabilities != tuple(
            sorted(set(capabilities), key=lambda item: item.value)
        ):
            raise ValueError("client capabilities must be sorted and unique")
        if set(capabilities) - CLIENT_KIND_CAPABILITIES[kind]:
            raise ValueError("client capabilities do not match the client kind")
        expected_id = _stable_id(
            "client",
            plan.installation_id,
            _require_string(request, "intent_key"),
        )
        if intent != {**request, "client_id": expected_id}:
            raise ValueError("client registration intent is invalid")
    elif plan.operation is IdentitySetupOperation.CLIENT_CREDENTIAL:
        ttl = _require_int(request, "ttl_hours")
        if ttl <= 0 or ttl > 24 * 365:
            raise ValueError("credential TTL is invalid")
        output = _absolute(Path(_require_string(request, "credential_output")))
        if intent["credential_output"] != str(output):
            raise ValueError("credential output is inconsistent")
        expected_id = _stable_secret_id(
            "credential_setup",
            plan.installation_id,
            _require_string(request, "client_id"),
            _require_string(request, "intent_key"),
        )
        if intent["credential_id"] != expected_id:
            raise ValueError("credential intent identity is invalid")
        _parse_timestamp(_require_string(intent, "expires_at"))
    elif plan.operation is IdentitySetupOperation.DEVICE_ENROLLMENT:
        ttl = _require_int(request, "ttl_minutes")
        credential_ttl = _require_int(request, "credential_ttl_days")
        if ttl <= 0 or ttl > 60 or credential_ttl <= 0 or credential_ttl > 365:
            raise ValueError("device enrollment TTL is invalid")
        output = _absolute(Path(_require_string(request, "enrollment_output")))
        if intent["enrollment_output"] != str(output):
            raise ValueError("device enrollment output is inconsistent")
        expected_id = _stable_secret_id(
            "enrollment_setup",
            plan.installation_id,
            _require_string(request, "intent_key"),
        )
        if intent["enrollment_id"] != expected_id:
            raise ValueError("device enrollment intent identity is invalid")
        expiry = _parse_timestamp(_require_string(intent, "expires_at"))
        credential_expiry = _parse_timestamp(_require_string(intent, "credential_expires_at"))
        if credential_expiry <= expiry:
            raise ValueError("device credential must outlive enrollment")
    else:
        source = SourceSystem(_require_string(request, "source_system"))
        scope = Scope(_require_string(request, "scope"))
        project_id = request["project_id"]
        if project_id is not None and not isinstance(project_id, str):
            raise ValueError("source project id is invalid")
        if (scope is Scope.PROJECT) != (project_id is not None):
            raise ValueError("source project scope is invalid")
        expected_id = _stable_id(
            "source_account",
            plan.installation_id,
            _require_string(request, "device_id"),
            source.value,
            _require_string(request, "account_label"),
        )
        if intent != {**request, "source_account_id": expected_id}:
            raise ValueError("source registration intent is invalid")


def _expected_gate_and_effects(
    plan: IdentitySetupPlan,
) -> tuple[HumanGate, tuple[str, ...]]:
    intent = plan.intent
    generation = plan.expected_identity_state_sha256
    if plan.operation is IdentitySetupOperation.CLIENT_REGISTRATION:
        target = _require_string(intent, "client_id")
        return (
            HumanGate(
                kind=HumanGateKind.CLIENT_IDENTITY_CHANGE,
                action="register_client_identity",
                target=target,
                target_state_sha256=_target_state_digest(
                    plan.installation_id,
                    generation,
                    intent,
                ),
                impact="Creates one client principal with the listed capabilities.",
                rollback="Revoke the client and each credential issued to it.",
            ),
            ("create_client_identity", "grant_listed_capabilities"),
        )
    if plan.operation is IdentitySetupOperation.CLIENT_CREDENTIAL:
        output = Path(_require_string(intent, "credential_output"))
        return (
            HumanGate(
                kind=HumanGateKind.CLIENT_CREDENTIAL_CHANGE,
                action="issue_and_store_client_credential",
                target=f"{_require_string(intent, 'credential_id')}:{output}",
                target_state_sha256=_target_state_digest(
                    plan.installation_id,
                    generation,
                    intent,
                    secret_output=output,
                ),
                impact="Creates one expiring bearer credential and writes it to a private file.",
                rollback="Revoke the credential and remove only the named private output file.",
            ),
            ("create_client_credential", "write_private_credential_file"),
        )
    if plan.operation is IdentitySetupOperation.DEVICE_ENROLLMENT:
        output = Path(_require_string(intent, "enrollment_output"))
        return (
            HumanGate(
                kind=HumanGateKind.DEVICE_ENROLLMENT_CHANGE,
                action="create_and_store_device_enrollment_code",
                target=f"{_require_string(intent, 'enrollment_id')}:{output}",
                target_state_sha256=_target_state_digest(
                    plan.installation_id,
                    generation,
                    intent,
                    secret_output=output,
                ),
                impact="Creates one short-lived pairing code and writes it to a private file.",
                rollback=(
                    "Do not distribute the code and let it expire; revoke a credential if redeemed."
                ),
            ),
            ("create_device_enrollment", "write_private_enrollment_file"),
        )
    return (
        HumanGate(
            kind=HumanGateKind.SOURCE_REGISTRATION,
            action="register_source_account_policy",
            target=_require_string(intent, "source_account_id"),
            target_state_sha256=_target_state_digest(
                plan.installation_id,
                generation,
                intent,
            ),
            impact="Creates one source identity with the listed immutable access policy.",
            rollback="Use the separately approved source-account deletion workflow.",
        ),
        ("create_source_account", "create_immutable_source_policy"),
    )


def _load_expected_plan(
    settings: Settings,
    plan_path: Path,
    expected_plan_sha256: str,
    operation: IdentitySetupOperation,
) -> IdentitySetupPlan:
    _validate_sha256(expected_plan_sha256, "expected identity setup plan")
    plan = load_identity_setup_plan(plan_path)
    if not hmac.compare_digest(expected_plan_sha256, plan.plan_sha256):
        raise ValueError("identity setup plan SHA-256 does not match")
    if plan.operation is not operation:
        raise ValueError("identity setup plan has the wrong operation")
    if plan.data_root != _absolute(settings.data_root):
        raise ValueError("identity setup plan targets a different data root")
    return plan


def _reuse_existing_plan(
    output: Path,
    *,
    operation: IdentitySetupOperation,
    settings: Settings,
    request: dict[str, object],
) -> IdentitySetupPlan | None:
    normalized = _absolute(output)
    if not normalized.exists() and not normalized.is_symlink():
        return None
    existing = load_identity_setup_plan(normalized)
    if (
        existing.operation is not operation
        or existing.data_root != _absolute(settings.data_root)
        or existing.request != request
    ):
        raise FileExistsError("identity setup plan output conflicts with the requested intent")
    return existing


def _write_or_reuse_plan(plan: IdentitySetupPlan, output: Path) -> dict[str, object]:
    destination = _absolute(output)
    payload = _canonical_json(plan.as_dict()) + b"\n"
    try:
        _write_new_private_file(destination, payload, mode=0o400, label="identity setup plan")
    except FileExistsError:
        existing = _reuse_existing_plan(
            destination,
            operation=plan.operation,
            settings=Settings(plan.data_root),
            request=plan.request,
        )
        if existing is None:
            raise AssertionError("identity setup plan collision disappeared") from None
        return _plan_result(existing, destination, reused=True)
    return _plan_result(plan, destination, reused=False)


def _plan_result(
    plan: IdentitySetupPlan,
    path: Path,
    *,
    reused: bool,
) -> dict[str, object]:
    return {
        **plan.as_dict(),
        "plan_path": str(_absolute(path)),
        "plan_reused": reused,
    }


def _ledger_identity(settings: Settings) -> tuple[str, str]:
    ledger = Ledger(settings, read_only=True, require_checkpointed=False)
    return ledger.identity_snapshot()


def _require_result_identity(plan: IdentitySetupPlan, result: dict[str, object]) -> None:
    key_by_operation = {
        IdentitySetupOperation.CLIENT_REGISTRATION: "client_id",
        IdentitySetupOperation.CLIENT_CREDENTIAL: "credential_id",
        IdentitySetupOperation.DEVICE_ENROLLMENT: "enrollment_id",
        IdentitySetupOperation.SOURCE_REGISTRATION: "source_account_id",
    }
    key = key_by_operation[plan.operation]
    if result.get(key) != plan.intent.get(key):
        raise RuntimeError("identity setup result does not match the approved intent")


def _sanitized_result(result: dict[str, Any]) -> dict[str, object]:
    return {
        key: cast(object, value)
        for key, value in result.items()
        if key not in {"token", "code", "replayed"}
    }


def _application_result(
    plan_path: Path,
    plan: IdentitySetupPlan,
    result: dict[str, object],
    *,
    replayed: bool,
    secret_output: Path | None = None,
    secret_written: bool = False,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "already_configured" if replayed else "configured",
        "operation": plan.operation.value,
        "plan_path": str(_absolute(plan_path)),
        "plan_sha256": plan.plan_sha256,
        "result": result,
        "mutated": not replayed,
        "secret_material_exposed": False,
    }
    if secret_output is not None:
        payload["secret_output"] = str(secret_output)
        payload["secret_written"] = secret_written
    return payload


def _prepare_or_read_secret(
    plan: IdentitySetupPlan,
    output: Path,
    *,
    generator: Callable[[], str],
    decoder: Callable[[bytes], str],
    label: str,
) -> tuple[str, bool]:
    stage = _staged_secret_path(plan, output)
    if output.exists() or output.is_symlink():
        if stage.exists() or stage.is_symlink():
            raise RuntimeError(f"{label} has conflicting published and staged state")
        return (
            decoder(
                _read_private_file(
                    output,
                    required_mode=0o600,
                    max_bytes=MAX_SECRET_BYTES,
                    label=f"published {label}",
                )
            ),
            True,
        )
    if stage.exists() or stage.is_symlink():
        _discard_owned_temps(stage, required_mode=0o600, label=label)
        return (
            decoder(
                _read_private_file(
                    stage,
                    required_mode=0o600,
                    max_bytes=MAX_SECRET_BYTES,
                    label=f"staged {label}",
                )
            ),
            False,
        )
    _discard_owned_temps(stage, required_mode=0o600, label=label)
    secret = generator()
    decoder(f"{secret}\n".encode("ascii"))
    temporary = _new_temporary_path(stage)
    try:
        _write_new_private_file(
            temporary,
            f"{secret}\n".encode("ascii"),
            mode=0o600,
            label=f"temporary {label}",
        )
        publish_file_no_replace(
            temporary,
            stage,
            required_mode=0o600,
            label=f"staged {label}",
        )
    except BaseException:
        _discard_owned_temp(temporary, required_mode=0o600, label=label)
        raise
    return secret, False


def _publish_staged_secret(
    plan: IdentitySetupPlan,
    output: Path,
    secret: str,
    label: str,
) -> None:
    stage = _staged_secret_path(plan, output)
    staged = _read_private_file(
        stage,
        required_mode=0o600,
        max_bytes=MAX_SECRET_BYTES,
        label=f"staged {label}",
    )
    if not hmac.compare_digest(staged, f"{secret}\n".encode("ascii")):
        raise RuntimeError(f"staged {label} changed before publication")
    publish_file_no_replace(stage, output, required_mode=0o600, label=label)


def _staged_secret_path(plan: IdentitySetupPlan, output: Path) -> Path:
    return output.with_name(f".cross-memory-{plan.operation.value}-{plan.plan_sha256}.secret")


def _store_or_verify_receipt(
    plan_path: Path,
    plan: IdentitySetupPlan,
    secret: str | None,
    result: dict[str, object],
) -> None:
    receipt_path = _receipt_path(plan_path, plan)
    expected = {
        "format_version": IDENTITY_SETUP_RECEIPT_FORMAT_VERSION,
        "plan_sha256": plan.plan_sha256,
        "secret_sha256": hashlib.sha256(secret.encode()).hexdigest() if secret else None,
        "result": result,
    }
    if receipt_path.exists() or receipt_path.is_symlink():
        if _load_receipt(receipt_path) != expected:
            raise RuntimeError("identity setup receipt conflicts with the current result")
        _discard_owned_temps(
            receipt_path,
            required_mode=0o400,
            label="identity setup receipt",
        )
        return
    _discard_owned_temps(
        receipt_path,
        required_mode=0o400,
        label="identity setup receipt",
    )
    temporary = _new_temporary_path(receipt_path)
    try:
        _write_new_private_file(
            temporary,
            _canonical_json(expected) + b"\n",
            mode=0o400,
            label="identity setup receipt",
        )
        publish_file_no_replace(
            temporary,
            receipt_path,
            required_mode=0o400,
            label="identity setup receipt",
        )
    except BaseException:
        _discard_owned_temp(
            temporary,
            required_mode=0o400,
            label="identity setup receipt",
        )
        raise


def _load_receipt(path: Path) -> dict[str, object]:
    payload = _read_private_file(
        path,
        required_mode=0o400,
        max_bytes=MAX_IDENTITY_SETUP_FILE_BYTES,
        label="identity setup receipt",
    )
    try:
        value: object = json.loads(payload, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("identity setup receipt is invalid") from error
    return _exact_object(
        value,
        {"format_version", "plan_sha256", "secret_sha256", "result"},
        "identity setup receipt",
    )


def _receipt_path(plan_path: Path, plan: IdentitySetupPlan) -> Path:
    normalized = _absolute(plan_path)
    return normalized.with_name(f".{normalized.name}.{plan.plan_sha256}.receipt.json")


def _new_temporary_path(target: Path) -> Path:
    return target.with_name(f"{target.name}.tmp-{secrets.token_hex(16)}")


def _discard_owned_temps(target: Path, *, required_mode: int, label: str) -> None:
    parent_descriptor = _open_private_parent(target)
    removed = False
    try:
        prefix = f"{target.name}.tmp-"
        for name in os.listdir(parent_descriptor):
            if not name.startswith(prefix):
                continue
            _discard_owned_temp_at(
                parent_descriptor,
                name,
                required_mode=required_mode,
                label=label,
            )
            removed = True
        if removed:
            os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _discard_owned_temp(path: Path, *, required_mode: int, label: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    parent_descriptor = _open_private_parent(path)
    try:
        _discard_owned_temp_at(
            parent_descriptor,
            path.name,
            required_mode=required_mode,
            label=label,
        )
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _discard_owned_temp_at(
    parent_descriptor: int,
    name: str,
    *,
    required_mode: int,
    label: str,
) -> None:
    metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != required_mode
        or metadata.st_nlink != 1
    ):
        raise RuntimeError(f"temporary {label} is unsafe")
    os.unlink(name, dir_fd=parent_descriptor)


@contextmanager
def _exclusive_plan_application(
    plan_path: Path,
    plan: IdentitySetupPlan,
) -> Generator[None]:
    normalized = _absolute(plan_path)
    lock = normalized.with_name(f".{normalized.name}.{plan.plan_sha256}.lock")
    parent_descriptor = _open_private_parent(lock)
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
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or (not created and stat.S_IMODE(metadata.st_mode) != 0o600)
        ):
            raise RuntimeError("identity setup application lock is unsafe")
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


def _write_new_private_file(path: Path, payload: bytes, *, mode: int, label: str) -> None:
    if len(payload) > MAX_IDENTITY_SETUP_FILE_BYTES:
        raise ValueError(f"{label} exceeds the supported size")
    normalized = _absolute(path)
    parent_descriptor = _open_private_parent(normalized)
    descriptor: int | None = None
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(normalized.name, flags, mode, dir_fd=parent_descriptor)
        os.fchmod(descriptor, mode)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(f"{label} is unsafe")
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _read_private_file(
    path: Path,
    *,
    required_mode: int,
    max_bytes: int,
    label: str,
) -> bytes:
    descriptor, _normalized = open_regular_file_no_symlinks(path, label)
    try:
        before = os.fstat(descriptor)
        if (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != required_mode
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise ValueError(f"{label} must be singly linked and mode {required_mode:04o}")
        payload = _read_bounded(descriptor, max_bytes)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise RuntimeError(f"{label} changed while it was read")
        return payload
    finally:
        os.close(descriptor)


def _open_private_parent(path: Path) -> int:
    descriptor = open_directory_no_symlinks(_absolute(path).parent, "identity setup parent")
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 1
    ):
        os.close(descriptor)
        raise ValueError("identity setup parent must be owned by the current user with mode 0700")
    return descriptor


def _require_new_secret_output(path: Path, label: str) -> None:
    descriptor = _open_private_parent(path)
    os.close(descriptor)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"{label} already exists")


def _decode_client_token(payload: bytes) -> str:
    value = _single_ascii_line(payload, "client credential")
    parse_client_credential_token(value)
    return value


def _decode_enrollment_code(payload: bytes) -> str:
    value = _single_ascii_line(payload, "device enrollment code")
    parts = value.split(".")
    if (
        len(parts) != 3
        or parts[0] != "came1"
        or not parts[1].startswith("enrollment_")
        or not parts[2]
    ):
        raise ValueError("device enrollment code is invalid")
    return value


def _single_ascii_line(payload: bytes, label: str) -> str:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise ValueError(f"{label} must contain one line")
    try:
        return payload[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be ASCII") from error


def _target_state_digest(
    installation_id: str,
    generation: str,
    intent: dict[str, object],
    *,
    secret_output: Path | None = None,
) -> str:
    target: dict[str, object] = {
        "installation_id": installation_id,
        "identity_state_sha256": generation,
        "intent": intent,
    }
    if secret_output is not None:
        target["secret_output"] = str(secret_output)
        target["secret_output_state"] = "absent"
    return hashlib.sha256(_canonical_json(target)).hexdigest()


def _stable_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((kind, *parts)).encode()).hexdigest()
    return f"{kind}:{digest}"


def _stable_secret_id(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((kind, *parts)).encode()).hexdigest()
    prefix = "credential_" if kind == "credential_setup" else "enrollment_"
    return f"{prefix}setup_{digest}"


def _identity_value(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    if len(normalized.encode()) > 256:
        raise ValueError(f"{label} exceeds its size limit")
    return normalized


def _normalized_now(value: datetime | None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None:
        raise ValueError("planning time must include a timezone")
    return result.astimezone(UTC)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("identity setup timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("identity setup timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} fields are invalid")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw) or set(raw) != keys:
        raise ValueError(f"{label} fields are invalid")
    return {cast(str, key): item for key, item in raw.items()}


def _string_keyed_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object with string keys")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{label} must be an object with string keys")
    return {cast(str, key): item for key, item in raw.items()}


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a string list")
    items = cast(list[object], value)
    if not all(isinstance(item, str) for item in items):
        raise ValueError(f"{label} must be a string list")
    return tuple(cast(str, item) for item in items)


def _require_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _require_int(value: dict[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{key} must be an integer")
    return item


def _require_sha256(value: dict[str, object], key: str) -> str:
    item = _require_string(value, key)
    _validate_sha256(item, key)
    return item


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("identity setup file write made no progress")
        view = view[written:]


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(16 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > maximum:
        raise ValueError("identity setup file exceeds the supported size")
    return payload


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
