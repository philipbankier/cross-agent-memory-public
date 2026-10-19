from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import queue
import socket
import ssl
import stat
import termios
import threading
import time
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPException, HTTPResponse, HTTPSConnection
from ipaddress import ip_address
from pathlib import Path
from typing import BinaryIO, cast
from urllib.parse import urlsplit

from cross_assistant_memory.human_gates import HumanGate, HumanGateKind, human_gates_as_dict
from cross_assistant_memory.models import Capability, ClientKind
from cross_assistant_memory.safe_files import publish_file_no_replace
from cross_assistant_memory.storage import (
    generate_client_credential_token,
    parse_client_credential_token,
)

COLLECTOR_ENROLLMENT_PLAN_FORMAT_VERSION = 3
COLLECTOR_ENROLLMENT_RECEIPT_FORMAT_VERSION = 1
MAX_ENROLLMENT_CODE_BYTES = 1024
MAX_ENROLLMENT_RESPONSE_BYTES = 64 * 1024
MAX_ENROLLMENT_VALUE_BYTES = 4096
ENROLLMENT_TIMEOUT_SECONDS = 15
ENROLLMENT_READ_CHUNK_BYTES = 16 * 1024


@dataclass(frozen=True)
class EnrollmentHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


EnrollmentTransport = Callable[[str, bytes], EnrollmentHTTPResponse]
SocketAddress = tuple[str, int] | tuple[str, int, int, int]
AddressInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, SocketAddress]


@dataclass(frozen=True)
class CollectorEnrollmentPlan:
    enrollment_url: str
    credential_output: Path
    enrollment_id: str
    device_label: str
    device_platform: str

    @property
    def target_state_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._target_surface())).hexdigest()

    @property
    def required_human_gates(self) -> tuple[HumanGate, ...]:
        return (
            HumanGate(
                kind=HumanGateKind.CLIENT_CREDENTIAL_CHANGE,
                action="redeem_device_enrollment_and_store_collector_credential",
                target=f"{self.enrollment_id}:{self.credential_output}",
                target_state_sha256=self.target_state_sha256,
                impact=(
                    "Redeems one pairing code over the network and writes one device credential."
                ),
                rollback="Revoke the enrolled client credential and remove this credential file.",
            ),
        )

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._digest_surface())).hexdigest()

    def _target_surface(self) -> dict[str, object]:
        return {
            "format_version": COLLECTOR_ENROLLMENT_PLAN_FORMAT_VERSION,
            "enrollment_url": self.enrollment_url,
            "credential_output": str(self.credential_output),
            "enrollment_id": self.enrollment_id,
            "device_label": self.device_label,
            "device_platform": self.device_platform,
        }

    def _digest_surface(self) -> dict[str, object]:
        return {
            **self._target_surface(),
            "required_human_gates": human_gates_as_dict(self.required_human_gates),
        }

    def as_dict(self, *, status: str) -> dict[str, object]:
        return {
            "status": status,
            **self._digest_surface(),
            "plan_sha256": self.plan_sha256,
            "network_used": False,
            "code_read": False,
            "credential_written": False,
            "execute_required": status in {"planned", "credential_verification_required"},
        }


def plan_collector_enrollment(
    enrollment_url: str,
    credential_output: Path,
    *,
    enrollment_id: str,
    device_label: str,
    device_platform: str,
) -> CollectorEnrollmentPlan:
    normalized_url = _validate_enrollment_url(enrollment_url)
    normalized_output = _normalize_credential_output(credential_output)
    normalized_enrollment_id = _validate_enrollment_id(enrollment_id)
    normalized_device_label = _validate_plan_value(device_label, "device label")
    normalized_device_platform = _validate_plan_value(device_platform, "device platform")
    parent_descriptor = _open_private_parent(normalized_output)
    os.close(parent_descriptor)
    if normalized_output.exists() or normalized_output.is_symlink():
        _require_private_file_metadata(
            normalized_output,
            required_mode=0o600,
            max_bytes=MAX_ENROLLMENT_VALUE_BYTES,
            label="collector credential output",
        )
    return CollectorEnrollmentPlan(
        enrollment_url=normalized_url,
        credential_output=normalized_output,
        enrollment_id=normalized_enrollment_id,
        device_label=normalized_device_label,
        device_platform=normalized_device_platform,
    )


def enroll_collector(
    enrollment_url: str,
    credential_output: Path,
    *,
    enrollment_id: str,
    device_label: str,
    device_platform: str,
    execute: bool,
    expected_plan_sha256: str | None,
    code_stream: BinaryIO,
    transport: EnrollmentTransport | None = None,
) -> dict[str, object]:
    plan = plan_collector_enrollment(
        enrollment_url,
        credential_output,
        enrollment_id=enrollment_id,
        device_label=device_label,
        device_platform=device_platform,
    )
    if not execute:
        if expected_plan_sha256 is not None and not hmac.compare_digest(
            expected_plan_sha256, plan.plan_sha256
        ):
            raise ValueError("collector enrollment plan SHA-256 does not match")
        return plan.as_dict(
            status=(
                "credential_verification_required"
                if plan.credential_output.exists() or plan.credential_output.is_symlink()
                else "planned"
            )
        )
    if expected_plan_sha256 is None:
        raise ValueError("collector enrollment requires --expected-plan-sha256")
    if not hmac.compare_digest(expected_plan_sha256, plan.plan_sha256):
        raise ValueError("collector enrollment plan SHA-256 does not match")

    with _exclusive_enrollment(plan):
        state = _active_enrollment_state(plan)
        existing = _resume_completed_enrollment(plan, state)
        if existing is not None:
            return existing

        token = _prepare_staged_token(state)
        receipt = _load_enrollment_receipt(plan, state, token, required=False)
        if receipt is not None:
            _publish_staged_credential(plan, state, token)
            return _collector_enrollment_result(
                plan,
                receipt,
                status="already_enrolled",
                network_used=False,
                code_read=False,
                credential_written=True,
            )

        code = _read_enrollment_code(code_stream)
        if not hmac.compare_digest(code.split(".")[1], plan.enrollment_id):
            raise ValueError("collector enrollment code does not match the approved plan")
        body = _canonical_json({"code": code, "credential_token": token})
        response = (transport or post_enrollment_request)(plan.enrollment_url, body)
        enrolled = _parse_enrollment_response(
            response,
            expected_enrollment_id=plan.enrollment_id,
            expected_device_label=plan.device_label,
            expected_device_platform=plan.device_platform,
            expected_credential_id=parse_client_credential_token(token)[0],
        )
        _store_enrollment_receipt(plan, state, token, response.status_code, enrolled)
        _publish_staged_credential(plan, state, token)
        return _collector_enrollment_result(
            plan,
            enrolled,
            status=cast(str, enrolled["status"]),
            network_used=True,
            code_read=True,
            credential_written=True,
        )


def post_enrollment_request(url: str, body: bytes) -> EnrollmentHTTPResponse:
    normalized_url = _validate_enrollment_url(url)
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("collector enrollment URL is invalid")
    deadline = time.monotonic() + ENROLLMENT_TIMEOUT_SECONDS
    try:
        connection = _open_direct_connection(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            use_tls=parsed.scheme == "https",
            deadline=deadline,
        )
    except (OSError, ValueError) as error:
        raise RuntimeError("collector enrollment transport failed") from error
    try:
        timer_seconds = _remaining_seconds(deadline)
    except TimeoutError as error:
        connection.close()
        raise RuntimeError("collector enrollment transport failed") from error
    response_holder: list[HTTPResponse] = []
    response_lock = threading.Lock()
    deadline_expired = threading.Event()

    def expire_response() -> None:
        deadline_expired.set()
        active_socket = connection.sock
        if active_socket is not None:
            with suppress(OSError):
                active_socket.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                active_socket.close()
        with response_lock:
            if response_holder:
                with suppress(OSError):
                    response_holder[0].close()

    timer = threading.Timer(timer_seconds, expire_response)
    timer.daemon = True
    timer.start()
    response: HTTPResponse | None = None
    try:
        connection.request(
            "POST",
            parsed.path,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        _require_live_deadline(deadline, deadline_expired)
        response = connection.getresponse()
        with response_lock:
            response_holder.append(response)
        _require_live_deadline(deadline, deadline_expired)
        if response.status not in {200, 201}:
            raise RuntimeError("collector enrollment was rejected")
        status_code = response.status
        chunks: list[bytes] = []
        byte_count = 0
        while byte_count <= MAX_ENROLLMENT_RESPONSE_BYTES:
            _require_live_deadline(deadline, deadline_expired)
            chunk = response.read(
                min(
                    ENROLLMENT_READ_CHUNK_BYTES,
                    MAX_ENROLLMENT_RESPONSE_BYTES + 1 - byte_count,
                )
            )
            _require_live_deadline(deadline, deadline_expired)
            if not chunk:
                break
            chunks.append(chunk)
            byte_count += len(chunk)
        response_body = b"".join(chunks)
        headers = {
            "cache-control": response.headers.get("Cache-Control", ""),
            "content-type": response.headers.get("Content-Type", ""),
        }
        _require_live_deadline(deadline, deadline_expired)
    except RuntimeError:
        raise
    except (HTTPException, OSError, ValueError) as error:
        raise RuntimeError("collector enrollment transport failed") from error
    finally:
        timer.cancel()
        with response_lock:
            response_holder.clear()
        if response is not None:
            response.close()
        connection.close()
    if len(response_body) > MAX_ENROLLMENT_RESPONSE_BYTES:
        raise RuntimeError("collector enrollment response exceeded its size limit")
    return EnrollmentHTTPResponse(status_code=status_code, headers=headers, body=response_body)


def _parse_enrollment_response(
    response: EnrollmentHTTPResponse,
    *,
    expected_enrollment_id: str,
    expected_device_label: str,
    expected_device_platform: str,
    expected_credential_id: str,
) -> dict[str, object]:
    cache_control = response.headers.get("cache-control", "")
    content_type = response.headers.get("content-type", "")
    if (
        response.status_code not in {200, 201}
        or "no-store" not in {item.strip().lower() for item in cache_control.split(",")}
        or not _is_json_content_type(content_type)
        or len(response.body) > MAX_ENROLLMENT_RESPONSE_BYTES
    ):
        raise RuntimeError("collector enrollment response was invalid")
    try:
        value: object = json.loads(response.body, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("collector enrollment response was invalid") from error
    return _validate_enrollment_payload(
        value,
        status_code=response.status_code,
        expected_enrollment_id=expected_enrollment_id,
        expected_device_label=expected_device_label,
        expected_device_platform=expected_device_platform,
        expected_credential_id=expected_credential_id,
    )


def _validate_enrollment_payload(
    value: object,
    *,
    status_code: int,
    expected_enrollment_id: str,
    expected_device_label: str,
    expected_device_platform: str,
    expected_credential_id: str,
) -> dict[str, object]:
    root = _exact_object(
        value,
        {"status", "replayed", "enrollment_id", "device", "client", "credential"},
        "collector enrollment response",
    )
    expected_status = "enrolled" if status_code == 201 else "already_enrolled"
    expected_replayed = status_code == 200
    if (
        root["status"] != expected_status
        or root["replayed"] is not expected_replayed
        or root["enrollment_id"] != expected_enrollment_id
    ):
        raise RuntimeError("collector enrollment response was invalid")
    device = _exact_object(
        root["device"],
        {"device_id", "label", "platform", "status"},
        "collector enrollment device",
    )
    if device["label"] != expected_device_label or device["platform"] != expected_device_platform:
        raise RuntimeError("collector enrollment response was invalid")
    client = _exact_object(
        root["client"],
        {"client_id", "label", "kind", "capabilities", "status", "created_at"},
        "collector enrollment client",
    )
    credential = _exact_object(
        root["credential"],
        {"credential_id", "client_id", "expires_at"},
        "collector enrollment credential",
    )
    _validate_enrollment_values(
        device,
        client,
        credential,
        expected_credential_id=expected_credential_id,
    )
    root["device"] = device
    root["client"] = client
    root["credential"] = credential
    return root


def _validate_enrollment_values(
    device: dict[str, object],
    client: dict[str, object],
    credential: dict[str, object],
    *,
    expected_credential_id: str,
) -> None:
    device_id = _bounded_string(device, "device_id")
    if not device_id.startswith("device_") or device["status"] != "active":
        raise RuntimeError("collector enrollment response was invalid")
    _bounded_string(device, "label")
    _bounded_string(device, "platform")

    client_id = _bounded_string(client, "client_id")
    if (
        not client_id.startswith("client_")
        or client["kind"] != ClientKind.COLLECTOR.value
        or client["status"] != "active"
    ):
        raise RuntimeError("collector enrollment response was invalid")
    _bounded_string(client, "label")
    _parse_timestamp(_bounded_string(client, "created_at"))
    capabilities = client["capabilities"]
    expected_capabilities = {Capability.MEMORY_STATUS.value, Capability.SOURCE_UPLOAD.value}
    if (
        not isinstance(capabilities, list)
        or any(not isinstance(item, str) for item in cast(list[object], capabilities))
        or set(cast(list[str], capabilities)) != expected_capabilities
        or len(cast(list[str], capabilities)) != len(expected_capabilities)
    ):
        raise RuntimeError("collector enrollment response was invalid")

    credential_id = _bounded_string(credential, "credential_id")
    if credential_id != expected_credential_id or credential["client_id"] != client_id:
        raise RuntimeError("collector enrollment response was invalid")
    if _parse_timestamp(_bounded_string(credential, "expires_at")) <= datetime.now(UTC):
        raise RuntimeError("collector enrollment response was invalid")


def _read_enrollment_code(stream: BinaryIO) -> str:
    raw = _read_code_line(stream)
    if not raw or len(raw) > MAX_ENROLLMENT_CODE_BYTES:
        raise ValueError("collector enrollment code is invalid")
    try:
        code = raw.decode("ascii").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("collector enrollment code is invalid") from error
    parts = code.split(".")
    if (
        len(parts) != 3
        or parts[0] != "came1"
        or not parts[1].startswith("enrollment_")
        or not parts[2]
        or code.strip() != code
        or any(character.isspace() for character in code)
        or any(not (character.isalnum() or character in "-._~") for character in code)
    ):
        raise ValueError("collector enrollment code is invalid")
    return code


def _read_code_line(stream: BinaryIO) -> bytes:
    if not stream.isatty():
        return stream.readline(MAX_ENROLLMENT_CODE_BYTES + 1)
    try:
        descriptor = stream.fileno()
        original = termios.tcgetattr(descriptor)
        no_echo = original.copy()
        no_echo[3] &= ~termios.ECHO
        termios.tcsetattr(descriptor, termios.TCSANOW, no_echo)
    except (OSError, termios.error) as error:
        raise RuntimeError("could not disable terminal echo for enrollment code") from error
    try:
        return stream.readline(MAX_ENROLLMENT_CODE_BYTES + 1)
    finally:
        try:
            termios.tcsetattr(descriptor, termios.TCSADRAIN, original)
        except (OSError, termios.error) as error:
            raise RuntimeError("could not restore terminal echo after enrollment code") from error


@dataclass(frozen=True)
class _EnrollmentStatePaths:
    lock: Path
    staged_token: Path
    receipt: Path

    @property
    def staged_token_temp(self) -> Path:
        return self.staged_token.with_name(f"{self.staged_token.name}.tmp")

    @property
    def receipt_temp(self) -> Path:
        return self.receipt.with_name(f"{self.receipt.name}.tmp")


@dataclass(frozen=True)
class _EnrollmentState:
    plan_sha256: str
    paths: _EnrollmentStatePaths


def _enrollment_state_paths(
    plan: CollectorEnrollmentPlan,
    plan_sha256: str | None = None,
) -> _EnrollmentStatePaths:
    prefix = f".cross-memory-enrollment-{plan_sha256 or plan.plan_sha256}"
    parent = plan.credential_output.parent
    return _EnrollmentStatePaths(
        lock=parent / f"{prefix}.lock",
        staged_token=parent / f"{prefix}.token",
        receipt=parent / f"{prefix}.receipt.json",
    )


def _enrollment_states(plan: CollectorEnrollmentPlan) -> tuple[_EnrollmentState, ...]:
    current = _EnrollmentState(plan.plan_sha256, _enrollment_state_paths(plan))
    legacy_sha256 = _legacy_v2_plan_sha256(plan)
    if legacy_sha256 == current.plan_sha256:
        return (current,)
    return (
        current,
        _EnrollmentState(
            legacy_sha256,
            _enrollment_state_paths(plan, legacy_sha256),
        ),
    )


def _active_enrollment_state(plan: CollectorEnrollmentPlan) -> _EnrollmentState:
    states = _enrollment_states(plan)
    active = [
        state
        for state in states
        if any(
            _path_present(path)
            for path in (
                state.paths.staged_token,
                state.paths.staged_token_temp,
                state.paths.receipt,
                state.paths.receipt_temp,
            )
        )
    ]
    if len(active) > 1:
        raise RuntimeError("collector enrollment recovery state conflicts across plan versions")
    return active[0] if active else states[0]


def _legacy_v2_plan_sha256(plan: CollectorEnrollmentPlan) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "format_version": 2,
                "enrollment_url": plan.enrollment_url,
                "credential_output": str(plan.credential_output),
                "enrollment_id": plan.enrollment_id,
                "device_label": plan.device_label,
                "device_platform": plan.device_platform,
            }
        )
    ).hexdigest()


@contextmanager
def _exclusive_enrollment(plan: CollectorEnrollmentPlan) -> Generator[None]:
    lock_paths = tuple(sorted({state.paths.lock for state in _enrollment_states(plan)}))
    descriptors: list[int] = []
    parent_descriptor = _open_private_parent(lock_paths[0])
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        for lock_path in lock_paths:
            descriptor = os.open(lock_path.name, flags, 0o600, dir_fd=parent_descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                os.close(descriptor)
                raise RuntimeError("collector enrollment lock is unsafe")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            descriptors.append(descriptor)
        os.fsync(parent_descriptor)
        for descriptor in descriptors:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        for descriptor in reversed(descriptors):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        os.close(parent_descriptor)


def _resume_completed_enrollment(
    plan: CollectorEnrollmentPlan,
    state: _EnrollmentState,
) -> dict[str, object] | None:
    if not _path_present(plan.credential_output):
        return None
    paths = state.paths
    if _path_present(paths.staged_token):
        raise RuntimeError("collector enrollment has conflicting credential state")
    token = _decode_staged_token(
        _read_private_file(
            plan.credential_output,
            required_mode=0o600,
            max_bytes=MAX_ENROLLMENT_VALUE_BYTES,
            label="collector credential output",
        )
    )
    receipt = _load_enrollment_receipt(plan, state, token, required=True)
    if receipt is None:
        raise AssertionError("required collector enrollment receipt was absent")
    return _collector_enrollment_result(
        plan,
        receipt,
        status="already_enrolled",
        network_used=False,
        code_read=False,
        credential_written=False,
    )


def _prepare_staged_token(state: _EnrollmentState) -> str:
    paths = state.paths
    if _path_present(paths.staged_token):
        return _decode_staged_token(
            _read_private_file(
                paths.staged_token,
                required_mode=0o600,
                max_bytes=MAX_ENROLLMENT_VALUE_BYTES,
                label="staged collector credential",
            )
        )
    _discard_safe_temp(paths.staged_token_temp, required_mode=0o600)
    token = generate_client_credential_token()
    _write_new_private_file(
        paths.staged_token_temp,
        f"{token}\n".encode("ascii"),
        mode=0o600,
        label="staged collector credential",
    )
    publish_file_no_replace(
        paths.staged_token_temp,
        paths.staged_token,
        required_mode=0o600,
        label="staged collector credential",
    )
    return token


def _publish_staged_credential(
    plan: CollectorEnrollmentPlan,
    state: _EnrollmentState,
    token: str,
) -> None:
    paths = state.paths
    current_token = _decode_staged_token(
        _read_private_file(
            paths.staged_token,
            required_mode=0o600,
            max_bytes=MAX_ENROLLMENT_VALUE_BYTES,
            label="staged collector credential",
        )
    )
    if not hmac.compare_digest(current_token, token):
        raise RuntimeError("staged collector credential identity changed")
    publish_file_no_replace(
        paths.staged_token,
        plan.credential_output,
        required_mode=0o600,
        label="collector credential",
    )


def _store_enrollment_receipt(
    plan: CollectorEnrollmentPlan,
    state: _EnrollmentState,
    token: str,
    status_code: int,
    enrolled: dict[str, object],
) -> None:
    paths = state.paths
    existing = _load_enrollment_receipt(plan, state, token, required=False)
    if existing is not None:
        if _canonical_json(existing) != _canonical_json(enrolled):
            raise RuntimeError("collector enrollment receipt conflicts with the node response")
        return
    receipt = {
        "format_version": COLLECTOR_ENROLLMENT_RECEIPT_FORMAT_VERSION,
        "plan_sha256": state.plan_sha256,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "status_code": status_code,
        "response": enrolled,
    }
    _discard_safe_temp(paths.receipt_temp, required_mode=0o400)
    _write_new_private_file(
        paths.receipt_temp,
        _canonical_json(receipt) + b"\n",
        mode=0o400,
        label="collector enrollment receipt",
    )
    publish_file_no_replace(
        paths.receipt_temp,
        paths.receipt,
        required_mode=0o400,
        label="collector enrollment receipt",
    )


def _load_enrollment_receipt(
    plan: CollectorEnrollmentPlan,
    state: _EnrollmentState,
    token: str,
    *,
    required: bool,
) -> dict[str, object] | None:
    paths = state.paths
    if not _path_present(paths.receipt) and _path_present(paths.receipt_temp):
        try:
            pending = _decode_enrollment_receipt(plan, state, token, paths.receipt_temp)
        except RuntimeError:
            _discard_safe_temp(paths.receipt_temp, required_mode=0o400)
        else:
            publish_file_no_replace(
                paths.receipt_temp,
                paths.receipt,
                required_mode=0o400,
                label="collector enrollment receipt",
            )
            return pending
    if not _path_present(paths.receipt):
        if required:
            raise RuntimeError("collector enrollment receipt is missing")
        return None
    receipt = _decode_enrollment_receipt(plan, state, token, paths.receipt)
    if _path_present(paths.receipt_temp):
        duplicate = _decode_enrollment_receipt(plan, state, token, paths.receipt_temp)
        if _canonical_json(duplicate) != _canonical_json(receipt):
            raise RuntimeError("collector enrollment receipt staging state conflicts")
        _discard_safe_temp(paths.receipt_temp, required_mode=0o400)
    return receipt


def _decode_enrollment_receipt(
    plan: CollectorEnrollmentPlan,
    state: _EnrollmentState,
    token: str,
    path: Path,
) -> dict[str, object]:
    raw = _read_private_file(
        path,
        required_mode=0o400,
        max_bytes=MAX_ENROLLMENT_RESPONSE_BYTES,
        label="collector enrollment receipt",
    )
    try:
        value: object = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("collector enrollment receipt is invalid") from error
    receipt = _exact_object(
        value,
        {"format_version", "plan_sha256", "token_sha256", "status_code", "response"},
        "collector enrollment receipt",
    )
    status_code = receipt["status_code"]
    if (
        receipt["format_version"] != COLLECTOR_ENROLLMENT_RECEIPT_FORMAT_VERSION
        or receipt["plan_sha256"] != state.plan_sha256
        or receipt["token_sha256"] != hashlib.sha256(token.encode()).hexdigest()
        or type(status_code) is not int
        or status_code not in {200, 201}
    ):
        raise RuntimeError("collector enrollment receipt is invalid")
    return _validate_enrollment_payload(
        receipt["response"],
        status_code=status_code,
        expected_enrollment_id=plan.enrollment_id,
        expected_device_label=plan.device_label,
        expected_device_platform=plan.device_platform,
        expected_credential_id=parse_client_credential_token(token)[0],
    )


def _collector_enrollment_result(
    plan: CollectorEnrollmentPlan,
    enrolled: dict[str, object],
    *,
    status: str,
    network_used: bool,
    code_read: bool,
    credential_written: bool,
) -> dict[str, object]:
    device = cast(dict[str, object], enrolled["device"])
    client = cast(dict[str, object], enrolled["client"])
    credential = cast(dict[str, object], enrolled["credential"])
    return {
        "status": status,
        "device_id": device["device_id"],
        "device_label": device["label"],
        "device_platform": device["platform"],
        "client_id": client["client_id"],
        "credential_id": credential["credential_id"],
        "credential_expires_at": credential["expires_at"],
        "credential_output": str(plan.credential_output),
        "network_used": network_used,
        "code_read": code_read,
        "credential_written": credential_written,
    }


def _decode_staged_token(raw: bytes) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise RuntimeError("staged collector credential is invalid")
    try:
        token = raw[:-1].decode("ascii")
        parse_client_credential_token(token)
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("staged collector credential is invalid") from error
    return token


def _write_new_private_file(path: Path, payload: bytes, *, mode: int, label: str) -> None:
    parent_descriptor = _open_private_parent(path)
    descriptor: int | None = None
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path.name, flags, mode, dir_fd=parent_descriptor)
        os.fchmod(descriptor, mode)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(f"{label} staging file is unsafe")
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
    parent_descriptor = _open_private_parent(path)
    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != required_mode
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > max_bytes
        ):
            raise RuntimeError(f"{label} is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(ENROLLMENT_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise RuntimeError(f"{label} exceeded its size limit")
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _require_private_file_metadata(
    path: Path,
    *,
    required_mode: int,
    max_bytes: int,
    label: str,
) -> None:
    parent_descriptor = _open_private_parent(path)
    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != required_mode
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > max_bytes
        ):
            raise RuntimeError(f"{label} is unsafe")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _discard_safe_temp(path: Path, *, required_mode: int) -> None:
    if not _path_present(path):
        return
    parent_descriptor = _open_private_parent(path)
    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != required_mode
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise RuntimeError("collector enrollment temporary file is unsafe")
        os.unlink(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _open_direct_connection(
    hostname: str,
    port: int,
    *,
    use_tls: bool,
    deadline: float,
) -> HTTPConnection:
    addresses = _resolve_addresses(hostname, port, deadline)
    connected_socket = _connect_to_addresses(addresses, deadline)
    transport_socket: socket.socket | None = None
    try:
        if use_tls:
            context = ssl.create_default_context()
            connected_socket.settimeout(_remaining_seconds(deadline))
            transport_socket = context.wrap_socket(connected_socket, server_hostname=hostname)
            connection: HTTPConnection = HTTPSConnection(
                hostname,
                port=port,
                timeout=_remaining_seconds(deadline),
                context=context,
            )
        else:
            transport_socket = connected_socket
            connection = HTTPConnection(
                hostname,
                port=port,
                timeout=_remaining_seconds(deadline),
            )
        connection.sock = transport_socket
        return connection
    except BaseException:
        (transport_socket or connected_socket).close()
        raise


def _resolve_addresses(hostname: str, port: int, deadline: float) -> list[AddressInfo]:
    results: queue.Queue[tuple[list[AddressInfo] | None, OSError | None]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            addresses = cast(
                list[AddressInfo],
                socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
            )
            results.put((addresses, None))
        except OSError as error:
            results.put((None, error))

    resolver = threading.Thread(target=resolve, daemon=True, name="collector-enrollment-dns")
    resolver.start()
    try:
        addresses, error = results.get(timeout=_remaining_seconds(deadline))
    except queue.Empty as error:
        raise TimeoutError("collector enrollment DNS resolution timed out") from error
    if error is not None:
        raise error
    if not addresses:
        raise OSError("collector enrollment DNS resolution returned no addresses")
    return addresses


def _connect_to_addresses(addresses: list[AddressInfo], deadline: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socket_kind, protocol, _canonical_name, address in addresses:
        candidate = socket.socket(family, socket_kind, protocol)
        try:
            candidate.settimeout(_remaining_seconds(deadline))
            candidate.connect(address)
            return candidate
        except OSError as error:
            last_error = error
            candidate.close()
    if last_error is not None:
        raise last_error
    raise OSError("collector enrollment connection had no usable address")


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("collector enrollment deadline expired")
    return remaining


def _require_live_deadline(deadline: float, expired: threading.Event) -> None:
    if expired.is_set() or time.monotonic() >= deadline:
        raise TimeoutError("collector enrollment deadline expired")


def _is_json_content_type(value: str) -> bool:
    parts = value.split(";")
    if not parts or parts[0].strip().lower() != "application/json":
        return False
    if len(parts) == 1:
        return True
    if len(parts) != 2 or "=" not in parts[1]:
        return False
    name, charset = parts[1].split("=", 1)
    normalized_charset = charset.strip().strip('"').lower()
    return name.strip().lower() == "charset" and normalized_charset in {"utf-8", "utf8"}


def _validate_enrollment_id(value: str) -> str:
    normalized = _validate_plan_value(value, "enrollment ID")
    if not normalized.startswith("enrollment_") or any(
        not character.isascii() or not (character.isalnum() or character in "_-")
        for character in normalized
    ):
        raise ValueError("collector enrollment ID is invalid")
    return normalized


def _validate_plan_value(value: str, label: str) -> str:
    if (
        not value
        or value.strip() != value
        or len(value.encode()) > MAX_ENROLLMENT_VALUE_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"collector enrollment {label} is invalid")
    return value


def _open_private_parent(path: Path) -> int:
    parts = path.parent.parts
    descriptor = os.open(
        parts[0],
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError("collector credential parent must not contain symlinks") from error
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        os.close(descriptor)
        raise ValueError("collector credential parent must be a private current-user directory")
    return descriptor


def _normalize_credential_output(path: Path) -> Path:
    normalized = Path(os.path.abspath(path.expanduser()))
    if not normalized.is_absolute() or any(
        ord(character) < 32 or ord(character) == 127 for character in str(normalized)
    ):
        raise ValueError("collector credential output must be an absolute safe path")
    return normalized


def _validate_enrollment_url(value: str) -> str:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("collector enrollment URL is invalid")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("collector enrollment URL is invalid") from error
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/enroll"
        or parsed.hostname is None
    ):
        raise ValueError("collector enrollment URL is invalid")
    if parsed.scheme == "https":
        return value
    if parsed.scheme != "http":
        raise ValueError("collector enrollment URL must use HTTPS or loopback HTTP")
    if parsed.hostname == "localhost":
        return value
    try:
        address = ip_address(parsed.hostname)
    except ValueError as error:
        raise ValueError("collector enrollment HTTP URL must be loopback") from error
    if not address.is_loopback:
        raise ValueError("collector enrollment HTTP URL must be loopback")
    return value


def _exact_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} was invalid")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw) or set(raw) != fields:
        raise RuntimeError(f"{label} was invalid")
    return cast(dict[str, object], raw)


def _bounded_string(value: dict[str, object], field: str) -> str:
    item = value[field]
    if (
        not isinstance(item, str)
        or not item
        or item.strip() != item
        or len(item.encode()) > MAX_ENROLLMENT_VALUE_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in item)
    ):
        raise RuntimeError("collector enrollment response was invalid")
    return item


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise RuntimeError("collector enrollment response was invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeError("collector enrollment response was invalid")
    return parsed


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object field")
        value[key] = item
    return value


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("collector credential write made no progress")
        written += count


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
