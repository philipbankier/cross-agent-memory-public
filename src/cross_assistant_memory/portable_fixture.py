from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import shutil
import sys
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import cast

from cross_assistant_memory.encrypted_objects import (
    CHUNK_BYTES,
    ENCRYPTION_PROFILE,
    EncryptedObjectStore,
    FilesystemObjectBackend,
    RootKey,
)
from cross_assistant_memory.tink_crypto import Keyset

FIXTURE_FORMAT_VERSION = 1
FIXTURE_NAME = "portable-encryption-v1"
PLAINTEXT_RECIPE = "repeat-ascii-pattern-v1"
PLAINTEXT_LENGTH = CHUNK_BYTES + 65_537
PLAINTEXT_PATTERN = b"cross-agent-memory portable ciphertext fixture v1\n"
NOTICE = (
    b"PUBLIC TEST MATERIAL ONLY.\n"
    b"The keyset and ciphertext in this directory protect synthetic bytes and are not secrets.\n"
    b"Never reuse this keyset for user data, credentials, backups, or production tests.\n"
)
MAX_INDEX_BYTES = 1024 * 1024

_ROOT_KEY_ID = re.compile(r"root_[0-9a-f]{32}")
_SOURCE_OBJECT_ID = re.compile(r"source_[0-9a-f]{32}")
_STORAGE_OBJECT_ID = re.compile(r"storage_[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def generate_portable_fixture(output: Path) -> dict[str, object]:
    output = output.expanduser()
    if output.exists() or output.is_symlink():
        raise ValueError(f"fixture output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ValueError(f"fixture output parent is invalid: {output.parent}")

    with tempfile.TemporaryDirectory(prefix="portable-fixture-", dir=output.parent) as raw_temp:
        temporary = Path(raw_temp)
        package = temporary / "package"
        package.mkdir()
        source = temporary / "synthetic-source.bin"
        plaintext = _synthetic_plaintext()
        source.write_bytes(plaintext)

        root_keyset = Keyset.generate_aead()
        root_key = RootKey(f"root_{uuid.uuid4().hex}", root_keyset)
        backend = FilesystemObjectBackend(package / "backend")
        store = EncryptedObjectStore(package / "metadata", backend, root_key)
        manifest = store.put_file(source, media_type="application/octet-stream")

        root_key_path = package / "root-key.test-only.tink"
        root_key_path.write_bytes(root_keyset.serialize_cleartext())
        root_key_path.chmod(0o644)
        notice_path = package / "NOTICE.txt"
        notice_path.write_bytes(NOTICE)
        notice_path.chmod(0o644)

        relative_files = (
            "NOTICE.txt",
            "root-key.test-only.tink",
            f"metadata/manifests/{manifest.source_object_id}.json",
            f"backend/objects/{manifest.storage_object_id}",
        )
        entries = {relative: _file_entry(package / relative) for relative in sorted(relative_files)}
        package_sha256 = _package_digest(entries)
        index = {
            "fixture_format_version": FIXTURE_FORMAT_VERSION,
            "fixture_name": FIXTURE_NAME,
            "notice": "PUBLIC TEST KEY MATERIAL; NEVER USE FOR REAL DATA",
            "generated_with": {
                "python": platform.python_version(),
                "tink": importlib.metadata.version("tink"),
            },
            "encryption_profile": ENCRYPTION_PROFILE,
            "root_key_id": root_key.key_id,
            "source_object_id": manifest.source_object_id,
            "storage_object_id": manifest.storage_object_id,
            "plaintext": {
                "recipe": PLAINTEXT_RECIPE,
                "byte_length": len(plaintext),
                "sha256": hashlib.sha256(plaintext).hexdigest(),
            },
            "files": entries,
            "package_sha256": package_sha256,
        }
        index_path = package / "fixture.json"
        index_path.write_text(_canonical_json(index) + "\n", encoding="ascii")
        index_path.chmod(0o644)
        shutil.copytree(package, output)

    return {
        "fixture_name": FIXTURE_NAME,
        "output": str(output),
        "package_sha256": package_sha256,
        "result": "generated",
    }


def verify_portable_fixture(fixture_root: Path) -> dict[str, object]:
    fixture_root = fixture_root.expanduser()
    index_path = fixture_root / "fixture.json"
    index = _load_index(index_path)
    fixture_index_sha256 = cast(str, _file_entry(index_path)["sha256"])
    root_key_id = _required_identifier(index, "root_key_id", _ROOT_KEY_ID)
    source_object_id = _required_identifier(index, "source_object_id", _SOURCE_OBJECT_ID)
    storage_object_id = _required_identifier(index, "storage_object_id", _STORAGE_OBJECT_ID)
    if index.get("fixture_format_version") != FIXTURE_FORMAT_VERSION:
        raise ValueError("portable fixture format version is unsupported")
    if index.get("fixture_name") != FIXTURE_NAME:
        raise ValueError("portable fixture name is invalid")
    if index.get("notice") != "PUBLIC TEST KEY MATERIAL; NEVER USE FOR REAL DATA":
        raise ValueError("portable fixture test-only notice is missing")
    if index.get("encryption_profile") != ENCRYPTION_PROFILE:
        raise ValueError("portable fixture encryption profile is invalid")

    plaintext = _synthetic_plaintext()
    plaintext_entry = index.get("plaintext")
    if not isinstance(plaintext_entry, dict):
        raise ValueError("portable fixture plaintext entry is invalid")
    plaintext_fields = cast(dict[object, object], plaintext_entry)
    if set(plaintext_fields) != {"recipe", "byte_length", "sha256"}:
        raise ValueError("portable fixture plaintext fields are invalid")
    if plaintext_fields["recipe"] != PLAINTEXT_RECIPE:
        raise ValueError("portable fixture plaintext recipe is invalid")
    if plaintext_fields["byte_length"] != len(plaintext):
        raise ValueError("portable fixture plaintext length is invalid")
    if plaintext_fields["sha256"] != hashlib.sha256(plaintext).hexdigest():
        raise ValueError("portable fixture plaintext digest is invalid")

    expected_paths = {
        "NOTICE.txt",
        "root-key.test-only.tink",
        f"metadata/manifests/{source_object_id}.json",
        f"backend/objects/{storage_object_id}",
    }
    entries = _validate_file_entries(fixture_root, index.get("files"), expected_paths)
    package_sha256 = _required_sha256(index, "package_sha256")
    if _package_digest(entries) != package_sha256:
        raise ValueError("portable fixture package digest is invalid")
    if (fixture_root / "NOTICE.txt").read_bytes() != NOTICE:
        raise ValueError("portable fixture notice content is invalid")

    keyset_path = fixture_root / "root-key.test-only.tink"
    root_key = RootKey(root_key_id, Keyset.read_cleartext(keyset_path.read_bytes()))
    with tempfile.TemporaryDirectory(prefix="portable-fixture-verify-") as raw_temp:
        temporary = Path(raw_temp)
        metadata = temporary / "metadata"
        backend_root = temporary / "backend"
        shutil.copytree(fixture_root / "metadata", metadata)
        shutil.copytree(fixture_root / "backend", backend_root)
        store = EncryptedObjectStore(
            metadata,
            FilesystemObjectBackend(backend_root),
            root_key,
        )
        restored = temporary / "restored.bin"
        manifest = store.restore_file(source_object_id, restored)
        if manifest.storage_object_id != storage_object_id:
            raise ValueError("portable fixture manifest object identity is invalid")
        if restored.read_bytes() != plaintext:
            raise ValueError("portable fixture restored plaintext is invalid")

    return {
        "fixture_name": FIXTURE_NAME,
        "fixture_index_sha256": fixture_index_sha256,
        "package_sha256": package_sha256,
        "encryption_profile": ENCRYPTION_PROFILE,
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "python_version": platform.python_version(),
        "tink_version": importlib.metadata.version("tink"),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "ciphertext_sha256": cast(
            dict[str, object], entries[f"backend/objects/{storage_object_id}"]
        )["sha256"],
        "result": "verified",
    }


def _synthetic_plaintext() -> bytes:
    repeats, remainder = divmod(PLAINTEXT_LENGTH, len(PLAINTEXT_PATTERN))
    return PLAINTEXT_PATTERN * repeats + PLAINTEXT_PATTERN[:remainder]


def _load_index(path: Path) -> dict[object, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INDEX_BYTES:
        raise ValueError("portable fixture index is invalid")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("portable fixture index is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("portable fixture index must be an object")
    fields = cast(dict[object, object], value)
    expected = {
        "fixture_format_version",
        "fixture_name",
        "notice",
        "generated_with",
        "encryption_profile",
        "root_key_id",
        "source_object_id",
        "storage_object_id",
        "plaintext",
        "files",
        "package_sha256",
    }
    if set(fields) != expected:
        raise ValueError("portable fixture index fields are invalid")
    return fields


def _validate_file_entries(
    fixture_root: Path,
    raw_entries: object,
    expected_paths: set[str],
) -> dict[str, object]:
    if not isinstance(raw_entries, dict):
        raise ValueError("portable fixture file entries are invalid")
    entries = cast(dict[object, object], raw_entries)
    if set(entries) != expected_paths:
        raise ValueError("portable fixture file set is invalid")
    validated: dict[str, object] = {}
    for raw_relative, raw_entry in entries.items():
        if not isinstance(raw_relative, str) or not isinstance(raw_entry, dict):
            raise ValueError("portable fixture file entry is invalid")
        relative = PurePosixPath(raw_relative)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("portable fixture file path is unsafe")
        entry = cast(dict[object, object], raw_entry)
        if set(entry) != {"byte_length", "sha256"}:
            raise ValueError("portable fixture file metadata is invalid")
        byte_length = entry["byte_length"]
        sha256 = entry["sha256"]
        if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length < 0:
            raise ValueError("portable fixture file length is invalid")
        if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
            raise ValueError("portable fixture file digest is invalid")
        path = fixture_root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise ValueError("portable fixture file is missing or unsafe")
        actual = _file_entry(path)
        if actual != {"byte_length": byte_length, "sha256": sha256}:
            raise ValueError(f"portable fixture file failed verification: {raw_relative}")
        validated[raw_relative] = actual
    return validated


def _file_entry(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    byte_length = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_BYTES):
            digest.update(chunk)
            byte_length += len(chunk)
    return {"byte_length": byte_length, "sha256": digest.hexdigest()}


def _package_digest(entries: Mapping[str, object]) -> str:
    payload = b"cross-agent-memory:portable-fixture:v1\0" + _canonical_json(entries).encode()
    return hashlib.sha256(payload).hexdigest()


def _required_identifier(fields: dict[object, object], key: str, pattern: re.Pattern[str]) -> str:
    value = fields.get(key)
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"portable fixture {key} is invalid")
    return value


def _required_sha256(fields: dict[object, object], key: str) -> str:
    value = fields.get(key)
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"portable fixture {key} is invalid")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify the public encryption fixture")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument(
        "path", nargs="?", type=Path, default=Path("tests/fixtures/portable-encryption-v1")
    )
    verify = commands.add_parser("verify")
    verify.add_argument(
        "path", nargs="?", type=Path, default=Path("tests/fixtures/portable-encryption-v1")
    )
    arguments = parser.parse_args(argv)
    if arguments.command == "generate":
        receipt = generate_portable_fixture(arguments.path)
    else:
        receipt = verify_portable_fixture(arguments.path)
    sys.stdout.write(_canonical_json(receipt) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
