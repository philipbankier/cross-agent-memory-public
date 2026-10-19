from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import cast

from cross_assistant_memory.encrypted_objects import ObjectState
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader, read_location
from cross_assistant_memory.evidence_publication import require_mapping_state

MAX_UPLOAD_PUBLICATION_OBJECTS = 4

PUBLICATION_WORK_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_publication_work (
  object_id TEXT PRIMARY KEY REFERENCES objects(object_id) ON DELETE CASCADE,
  backend_identity_sha256 TEXT NOT NULL CHECK (length(backend_identity_sha256) = 64),
  root_key_sha256 TEXT NOT NULL CHECK (length(root_key_sha256) = 64),
  retire_plaintext INTEGER NOT NULL CHECK (retire_plaintext IN (0, 1)),
  plaintext_identity_sha256 TEXT,
  CHECK ((retire_plaintext = 0 AND plaintext_identity_sha256 IS NULL) OR
         (retire_plaintext = 1 AND plaintext_identity_sha256 IS NOT NULL AND
          length(plaintext_identity_sha256) = 64))
);
"""


class EvidencePublicationPending(RuntimeError):
    """Publication is incomplete; retained work must drain before retrying admission."""


class EvidencePublicationYielded(EvidencePublicationPending):
    """The request completed its bounded work without encountering a publication failure."""

    def __init__(self, completed_objects: int) -> None:
        super().__init__("publication work yielded; retry the same batch")
        self.completed_objects = completed_objects


@dataclass(frozen=True)
class EvidencePublicationPolicy:
    max_pending_bytes: int
    max_pending_objects: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 0 < value <= 2**63 - 1
            for value in (self.max_pending_bytes, self.max_pending_objects)
        ):
            raise ValueError("publication work limits require positive signed 64-bit integers")


def publication_key_sha256(reader: EncryptedEvidenceReader) -> str:
    """Bind the bounded root key ID and key material without retaining cleartext keys."""
    keyset_digest = hashlib.sha256(reader.root_key.serialize_cleartext_keyset()).hexdigest()
    binding = json.dumps(
        [reader.root_key.key_id, keyset_digest], ensure_ascii=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(binding).hexdigest()


def enqueue_publication_work(
    connection: sqlite3.Connection,
    reader: EncryptedEvidenceReader,
    policy: EvidencePublicationPolicy,
    *,
    object_id: str,
    retire_plaintext: bool,
    plaintext_identity_sha256: str | None = None,
) -> None:
    """Register bounded work in the caller's transaction, without provider access."""
    if not connection.in_transaction:
        raise RuntimeError("publication work requires an active SQL transaction")
    if type(retire_plaintext) is not bool:
        raise ValueError("publication work retirement flag must be a boolean")
    registered = connection.execute(
        "SELECT byte_length, storage_kind FROM objects WHERE object_id = ?", (object_id,)
    ).fetchone()
    if registered is None:
        raise RuntimeError("publication work requires a registered object")
    byte_length, storage_kind = cast(tuple[int, str], tuple(registered))
    if type(byte_length) is not int or not 0 <= byte_length <= reader.max_plaintext_bytes:
        raise RuntimeError("publication work object exceeds the reader plaintext byte limit")

    location = read_location(connection, object_id)
    require_mapping_state(storage_kind, location)
    if location is not None:
        reader.validate_location(
            location[1],
            object_id=object_id,
            expected_size=byte_length,
            backend_identity_sha256=location[0],
            allowed_states=(ObjectState.PENDING, ObjectState.VERIFIED),
        )
    existing = connection.execute(
        "SELECT backend_identity_sha256, root_key_sha256 FROM evidence_publication_work "
        "WHERE object_id = ?",
        (object_id,),
    ).fetchone()
    if existing is None and storage_kind == "encrypted":
        return

    backend_identity = reader.backend.identity_sha256
    key_digest = publication_key_sha256(reader)
    if existing is not None:
        if tuple(existing) != (backend_identity, key_digest):
            raise RuntimeError("publication work does not match the reader backend or root key")
        # Retries retain the original retirement decision, even after budgets are lowered.
        return

    if retire_plaintext:
        if (
            not isinstance(plaintext_identity_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", plaintext_identity_sha256) is None
        ):
            raise ValueError("plaintext retirement requires its original file identity")
    elif plaintext_identity_sha256 is not None:
        raise ValueError("preserved plaintext must not carry a retirement identity")

    try:
        pending_count, pending_bytes = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(objects.byte_length), 0) "
            "FROM evidence_publication_work JOIN objects USING (object_id)"
        ).fetchone()
    except sqlite3.OperationalError as error:
        if str(error) != "integer overflow":
            raise
        raise EvidencePublicationPending("publication work pending byte budget exceeded") from None
    if pending_count + 1 > policy.max_pending_objects:
        raise EvidencePublicationPending("publication work pending object budget exceeded")
    if pending_bytes + byte_length > policy.max_pending_bytes:
        raise EvidencePublicationPending("publication work pending byte budget exceeded")
    connection.execute(
        "INSERT INTO evidence_publication_work "
        "(object_id, backend_identity_sha256, root_key_sha256, retire_plaintext, "
        "plaintext_identity_sha256) VALUES (?, ?, ?, ?, ?)",
        (object_id, backend_identity, key_digest, int(retire_plaintext), plaintext_identity_sha256),
    )
