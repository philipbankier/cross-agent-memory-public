from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from cross_assistant_memory.encrypted_objects import (
    MAX_MANIFEST_BYTES,
    EncryptedObjectManifest,
    ObjectState,
    RootKey,
    read_verified_object,
    validate_authenticated_manifest,
)
from cross_assistant_memory.object_store import IdentifiedObjectBackend

ENCRYPTED_LOCATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS encrypted_object_locations (
  object_id TEXT PRIMARY KEY REFERENCES objects(object_id),
  source_object_id TEXT NOT NULL UNIQUE,
  storage_object_id TEXT NOT NULL UNIQUE,
  backend_profile TEXT NOT NULL,
  backend_identity_sha256 TEXT NOT NULL CHECK (length(backend_identity_sha256) = 64),
  manifest_json TEXT NOT NULL CHECK (length(manifest_json) <= 1048576)
);
"""


@dataclass(frozen=True)
class EncryptedEvidenceReader:
    backend: IdentifiedObjectBackend
    root_key: RootKey
    max_plaintext_bytes: int
    max_ciphertext_bytes: int
    runtime_guard: Callable[[], None] | None = field(default=None, repr=False, compare=False)

    def require_current_runtime(self) -> None:
        if self.runtime_guard is not None:
            self.runtime_guard()

    def __post_init__(self) -> None:
        if (
            type(self.max_plaintext_bytes) is not int
            or type(self.max_ciphertext_bytes) is not int
            or min(self.max_plaintext_bytes, self.max_ciphertext_bytes) <= 0
        ):
            raise ValueError("encrypted evidence reader requires positive integer byte limits")
        if re.fullmatch(r"[0-9a-f]{64}", self.backend.identity_sha256) is None:
            raise ValueError("encrypted evidence backend identity is invalid")

    def read(
        self,
        manifest: EncryptedObjectManifest,
        *,
        object_id: str,
        expected_size: int,
        backend_identity_sha256: str,
    ) -> bytes:
        self.require_current_runtime()
        self._validate_binding(
            manifest,
            object_id=object_id,
            expected_size=expected_size,
            backend_identity_sha256=backend_identity_sha256,
        )
        result = read_verified_object(
            self.backend,
            self.root_key,
            manifest,
            max_plaintext_bytes=self.max_plaintext_bytes,
            max_ciphertext_bytes=self.max_ciphertext_bytes,
        )
        self.require_current_runtime()
        return result

    def validate_location(
        self,
        manifest: EncryptedObjectManifest,
        *,
        object_id: str,
        expected_size: int,
        backend_identity_sha256: str,
        allowed_states: tuple[str, ...] = (ObjectState.VERIFIED,),
    ) -> None:
        """Authenticate a registered location without provider access or plaintext recovery."""
        self.require_current_runtime()
        self._validate_binding(
            manifest,
            object_id=object_id,
            expected_size=expected_size,
            backend_identity_sha256=backend_identity_sha256,
        )
        try:
            validate_authenticated_manifest(
                self.root_key,
                manifest,
                backend_profile=self.backend.profile,
                max_plaintext_bytes=self.max_plaintext_bytes,
                max_ciphertext_bytes=self.max_ciphertext_bytes,
                allowed_states=allowed_states,
            )
        except Exception:
            raise RuntimeError("encrypted evidence location authentication failed") from None

    def _validate_binding(
        self,
        manifest: EncryptedObjectManifest,
        *,
        object_id: str,
        expected_size: int,
        backend_identity_sha256: str,
    ) -> None:
        if (
            backend_identity_sha256 != self.backend.identity_sha256
            or manifest.legacy_source_object_id != object_id
            or object_id != f"sha256:{manifest.plaintext_sha256}"
            or type(expected_size) is not int
            or manifest.plaintext_byte_length != expected_size
        ):
            raise RuntimeError("encrypted evidence location does not match the ledger or backend")


def read_location(
    connection: sqlite3.Connection, object_id: str
) -> tuple[str, EncryptedObjectManifest] | None:
    row = connection.execute(
        "SELECT source_object_id, storage_object_id, backend_profile, "
        "backend_identity_sha256, manifest_json FROM encrypted_object_locations "
        "WHERE object_id = ?",
        (object_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        raw = cast(str, row[4])
        if len(raw) > MAX_MANIFEST_BYTES or len(raw.encode()) > MAX_MANIFEST_BYTES:
            raise ValueError("manifest size")
        manifest = EncryptedObjectManifest.from_dict(json.loads(raw))
        if (manifest.source_object_id, manifest.storage_object_id, manifest.backend_profile) != (
            row[0],
            row[1],
            row[2],
        ):
            raise ValueError("manifest identity")
        return cast(str, row[3]), manifest
    except Exception:
        raise RuntimeError("encrypted evidence location is invalid") from None


def require_local_object_operations(connection: sqlite3.Connection) -> None:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'encrypted_object_locations'"
    ).fetchone()
    columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)")}
    encrypted = (
        "storage_kind" in columns
        and connection.execute(
            "SELECT 1 FROM objects WHERE storage_kind != 'local' LIMIT 1"
        ).fetchone()
    )
    if encrypted or (
        exists and connection.execute("SELECT 1 FROM encrypted_object_locations LIMIT 1").fetchone()
    ):
        raise RuntimeError(
            "encrypted evidence mappings require snapshot and deletion integration; "
            "this local-only operation is unavailable"
        )
