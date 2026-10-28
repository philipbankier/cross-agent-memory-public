from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cross_assistant_memory.config import Settings
from cross_assistant_memory.encrypted_objects import (
    DeterministicFakeBackend,
    EncryptedObjectManifest,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    RootKey,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import Scope, SourceSystem
from cross_assistant_memory.object_store import IdentifiedObjectBackend
from cross_assistant_memory.storage import Ledger, exclusive_ledger_writer
from tests.conftest import write_jsonl


@dataclass(frozen=True)
class Case:
    settings: Settings
    event_id: str
    local_object: Path
    reader: EncryptedEvidenceReader
    manifest: EncryptedObjectManifest
    expected_raw: str


def _case(
    root: Path,
    profile: str = "fake",
    *,
    text: str = "Synthetic durable context violet decision.",
) -> Case:
    settings = Settings(root / "ledger")
    ledger = Ledger(settings)
    source = write_jsonl(
        root / "native.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "synthetic-storage", "source": "vscode"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": text}],
                },
            },
        ],
    )
    ledger.ingest(
        parse_file(source, SourceSystem.CODEX),
        source_account="synthetic",
        scope=Scope.USER_GLOBAL,
        project_id=None,
    )
    with closing(sqlite3.connect(settings.database_path)) as connection:
        event_id = cast(str, connection.execute("SELECT event_id FROM events").fetchone()[0])
        relative, object_id = connection.execute(
            "SELECT object_path, object_id FROM objects"
        ).fetchone()
    local_object = settings.data_root / relative
    backend: IdentifiedObjectBackend
    if profile == "filesystem":
        backend = FilesystemObjectBackend(root / "encrypted-backend")
    else:
        backend = DeterministicFakeBackend()
    key = RootKey.generate()
    manifest = EncryptedObjectStore(root / "encrypted-metadata", backend, key).put_file(
        local_object, media_type="application/jsonl", legacy_source_object_id=object_id
    )
    reader = EncryptedEvidenceReader(backend, key, 1024 * 1024, 2 * 1024 * 1024)
    return Case(settings, event_id, local_object, reader, manifest, local_object.read_text())


def _bind(
    case: Case, manifest: EncryptedObjectManifest | None = None, generation: str | None = None
) -> dict[str, str]:
    with exclusive_ledger_writer(case.settings) as token:
        ledger = Ledger(
            case.settings, exclusive_writer_token=token, encrypted_evidence_reader=case.reader
        )
        return ledger.bind_encrypted_evidence(
            case.event_id,
            manifest or case.manifest,
            expected_generation_digest=generation or ledger.generation_digest(),
            authorized_by="local:synthetic",
            authorization_scope="synthetic:binding",
            reason="synthetic mapping test",
        )
