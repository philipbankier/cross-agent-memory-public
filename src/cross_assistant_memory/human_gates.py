from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

HUMAN_GATE_FORMAT_VERSION = 1
MAX_HUMAN_GATE_VALUE_BYTES = 4096


class HumanGateKind(StrEnum):
    OPERATOR_REVIEW = "operator_review"
    CLIENT_IDENTITY_CHANGE = "client_identity_change"
    CLIENT_CREDENTIAL_CHANGE = "client_credential_change"
    DEVICE_ENROLLMENT_CHANGE = "device_enrollment_change"
    SOURCE_REGISTRATION = "source_registration"
    SERVICE_INSTALLATION = "service_installation"


@dataclass(frozen=True)
class HumanGate:
    kind: HumanGateKind
    action: str
    target: str
    target_state_sha256: str
    impact: str
    rollback: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.action, "human gate action"),
            (self.target, "human gate target"),
            (self.impact, "human gate impact"),
            (self.rollback, "human gate rollback"),
        ):
            _validate_value(value, label)
        _validate_sha256(self.target_state_sha256, "human gate target state")

    def _digest_surface(self) -> dict[str, object]:
        return {
            "format_version": HUMAN_GATE_FORMAT_VERSION,
            "kind": self.kind.value,
            "action": self.action,
            "target": self.target,
            "target_state_sha256": self.target_state_sha256,
            "impact": self.impact,
            "rollback": self.rollback,
        }

    @property
    def gate_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._digest_surface())).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {**self._digest_surface(), "gate_sha256": self.gate_sha256}


def parse_human_gates(value: object) -> tuple[HumanGate, ...]:
    if not isinstance(value, list):
        raise ValueError("required_human_gates must be a list")
    gates: list[HumanGate] = []
    for raw in cast(list[object], value):
        if not isinstance(raw, dict):
            raise ValueError("human gate fields are invalid")
        item = cast(dict[str, object], raw)
        if set(item) != {
            "format_version",
            "kind",
            "action",
            "target",
            "target_state_sha256",
            "impact",
            "rollback",
            "gate_sha256",
        }:
            raise ValueError("human gate fields are invalid")
        if item["format_version"] != HUMAN_GATE_FORMAT_VERSION:
            raise ValueError("human gate format is unsupported")
        try:
            gate = HumanGate(
                kind=HumanGateKind(_require_string(item, "kind")),
                action=_require_string(item, "action"),
                target=_require_string(item, "target"),
                target_state_sha256=_require_string(item, "target_state_sha256"),
                impact=_require_string(item, "impact"),
                rollback=_require_string(item, "rollback"),
            )
        except ValueError as error:
            raise ValueError("human gate is invalid") from error
        digest = _require_string(item, "gate_sha256")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("human gate SHA-256 is invalid")
        if not hmac.compare_digest(digest, gate.gate_sha256):
            raise ValueError("human gate content does not match its SHA-256")
        gates.append(gate)
    return tuple(gates)


def human_gates_as_dict(gates: tuple[HumanGate, ...]) -> list[dict[str, object]]:
    return [gate.as_dict() for gate in gates]


def _require_string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _validate_value(value: str, label: str) -> None:
    if not value or value.strip() != value:
        raise ValueError(f"{label} is required")
    if len(value.encode()) > MAX_HUMAN_GATE_VALUE_BYTES:
        raise ValueError(f"{label} exceeds the supported size")


def _validate_sha256(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
