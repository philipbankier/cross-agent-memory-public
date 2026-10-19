from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.b2_object_store import B2S3Profile, create_b2_s3_bindings
from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    MAX_OPERATIONAL_KEY_BYTES,
    FilesystemObjectBackend,
    OperationalKey,
)
from cross_assistant_memory.evidence_deletion import EncryptedEvidencePurger
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.evidence_rotation import (
    capture_file,
    check_rotation_access,
    require_file,
)
from cross_assistant_memory.object_store import PurgeableObjectBackend
from cross_assistant_memory.private_json import load_owner_only_json
from cross_assistant_memory.publication_work import EvidencePublicationPolicy

MAX_RUNTIME_CONFIG_BYTES = 16 * 1024
EVIDENCE_COMMANDS = frozenset(
    {
        "ingest",
        "web-export-apply",
        "evidence-publish",
        "search",
        "evidence",
        "propose",
        "candidate-review",
        "snapshot",
        "backup",
        "portable-export",
        "deletion-plan",
        "deletion-apply",
        "serve",
        "panel",
    }
)


@dataclass(frozen=True, repr=False)
class RuntimeEvidence:
    reader: EncryptedEvidenceReader | None = None
    purger: EncryptedEvidencePurger | None = None
    max_snapshot_bytes: int | None = None
    publication_policy: EvidencePublicationPolicy | None = None

    def __repr__(self) -> str:
        return f"RuntimeEvidence(configured={self.reader is not None})"


@dataclass(frozen=True, repr=False)
class EvidenceConfig:
    data_root: Path
    operational_key: Path
    backend: Path | B2S3Profile
    max_plaintext_bytes: int
    max_ciphertext_bytes: int
    max_snapshot_bytes: int
    publication_policy: EvidencePublicationPolicy | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EvidenceConfig:
        if (
            set(raw) - {"publication"}
            != {
                "format_version",
                "data_root",
                "operational_key",
                "backend",
                "max_plaintext_bytes",
                "max_ciphertext_bytes",
                "max_snapshot_bytes",
            }
            or type(raw["format_version"]) is not int
            or raw["format_version"] != 1
        ):
            raise ValueError("invalid evidence configuration fields or version")
        data_root = _absolute_path(raw["data_root"])
        key = _absolute_path(raw["operational_key"])
        if key.is_relative_to(data_root):
            raise ValueError("operational key must be outside the data root")
        backend_value = raw["backend"]
        if not isinstance(backend_value, dict):
            raise ValueError("invalid evidence backend")
        backend = cast(dict[str, Any], backend_value)
        profile: Path | B2S3Profile
        if set(backend) == {"profile", "root"} and backend["profile"] == "filesystem-v1":
            profile = _absolute_path(backend["root"])
            if profile.is_relative_to(data_root) or data_root.is_relative_to(profile):
                raise ValueError("evidence backend and data root must be separate")
        elif (
            set(backend)
            == {"profile", "bucket", "region", "application_key_id_env", "application_key_env"}
            and backend["profile"] == "backblaze-b2-s3-v1"
        ):
            if any(type(value) is not str for value in backend.values()):
                raise ValueError("invalid B2 configuration")
            profile = B2S3Profile(
                bucket=backend["bucket"],
                region=backend["region"],
                endpoint_url=f"https://s3.{backend['region']}.backblazeb2.com",
                application_key_id_env=backend["application_key_id_env"],
                application_key_env=backend["application_key_env"],
            )
        else:
            raise ValueError("invalid evidence backend fields or profile")
        return cls(
            data_root,
            key,
            profile,
            _byte_limit(raw["max_plaintext_bytes"]),
            _byte_limit(raw["max_ciphertext_bytes"]),
            _byte_limit(raw["max_snapshot_bytes"]),
            _publication_policy(raw["publication"]) if "publication" in raw else None,
        )


def runtime_evidence_for_command(
    settings: Settings,
    command: str,
    config_path: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    allow_publication: bool = False,
) -> RuntimeEvidence:
    environment = os.environ if environ is None else environ
    if command not in EVIDENCE_COMMANDS:
        if config_path is not None:
            raise ValueError("--evidence-config is not supported by this command")
        # Restore, verification, setup and collectors never inherit a source backend.
        return RuntimeEvidence()
    selected = config_path
    if selected is None and "CAM_EVIDENCE_CONFIG" in environment:
        selected = Path(environment["CAM_EVIDENCE_CONFIG"])
    if selected is None:
        return RuntimeEvidence()
    check_rotation_access(settings)
    try:
        config_binding, _ = capture_file(selected, MAX_RUNTIME_CONFIG_BYTES)
        config = EvidenceConfig.from_dict(
            load_owner_only_json(
                selected, label="evidence configuration", max_bytes=MAX_RUNTIME_CONFIG_BYTES
            )
        )
        if settings.data_root.resolve(strict=True) != config.data_root:
            raise ValueError("evidence configuration belongs to a different data root")
        key_binding, _ = capture_file(config.operational_key, MAX_OPERATIONAL_KEY_BYTES)
        key = OperationalKey.load(config.operational_key)

        def guard() -> None:
            check_rotation_access(settings, reader)
            require_file(config_binding, MAX_RUNTIME_CONFIG_BYTES)
            require_file(key_binding, MAX_OPERATIONAL_KEY_BYTES)

        backend: PurgeableObjectBackend
        if isinstance(config.backend, Path):
            backend = FilesystemObjectBackend(
                config.backend, create=False, purge_max_bytes=config.max_ciphertext_bytes
            )
        else:
            backend = create_b2_s3_bindings(config.backend, environ=environment).backend
        reader = EncryptedEvidenceReader(
            backend,
            key.root_key,
            config.max_plaintext_bytes,
            config.max_ciphertext_bytes,
            runtime_guard=guard,
        )
        guard()
        return RuntimeEvidence(
            reader=reader,
            purger=EncryptedEvidencePurger(
                backend, key.root_key, config.max_plaintext_bytes, config.max_ciphertext_bytes
            ),
            max_snapshot_bytes=config.max_snapshot_bytes,
            publication_policy=(
                config.publication_policy
                if allow_publication
                and command in {"ingest", "web-export-apply", "evidence-publish", "serve", "panel"}
                else None
            ),
        )
    except Exception:
        raise ValueError(
            "evidence configuration unavailable: check its schema, owner-only permissions, "
            "data-root binding, operational key and credential environment"
        ) from None


def _publication_policy(value: object) -> EvidencePublicationPolicy:
    if not isinstance(value, dict):
        raise ValueError("invalid evidence publication configuration")
    publication = cast(dict[str, Any], value)
    if (
        set(publication) != {"mode", "max_pending_bytes", "max_pending_objects"}
        or publication["mode"] != "remote-primary"
    ):
        raise ValueError("invalid evidence publication configuration")
    return EvidencePublicationPolicy(
        max_pending_bytes=publication["max_pending_bytes"],
        max_pending_objects=publication["max_pending_objects"],
    )


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("evidence configuration requires absolute paths")
    path = Path(value)
    if path != path.resolve(strict=True):
        raise ValueError("evidence configuration requires physical paths without symlinks")
    return path


def _byte_limit(value: object) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("evidence configuration requires positive integer byte limits")
    return value
