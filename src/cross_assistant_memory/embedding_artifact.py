from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

from cross_assistant_memory.safe_files import open_regular_file_no_symlinks

EMBEDDING_ARTIFACT_FORMAT_VERSION = 1
DEFAULT_EMBEDDING_MODEL_ID = "snowflake-arctic-embed-s-int8"
MAX_ARTIFACT_MANIFEST_BYTES = 1024 * 1024
_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 120
_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 1


@dataclass(frozen=True)
class EmbeddingArtifactFile:
    path: str
    bytes: int
    source_digest_algorithm: str
    source_digest: str


@dataclass(frozen=True)
class EmbeddingModelSpec:
    model_id: str
    repository: str
    revision: str
    license_spdx: str
    license_reviewed_at: str
    adapter_id: str
    dimensions: int
    max_tokens: int
    batch_size: int
    query_prefix: str
    document_prefix: str
    model_path: str
    tokenizer_path: str
    runtime_versions: dict[str, str]
    files: tuple[EmbeddingArtifactFile, ...]

    @property
    def total_bytes(self) -> int:
        return sum(item.bytes for item in self.files)


FROZEN_EMBEDDING_MODELS: dict[str, EmbeddingModelSpec] = {
    DEFAULT_EMBEDDING_MODEL_ID: EmbeddingModelSpec(
        model_id=DEFAULT_EMBEDDING_MODEL_ID,
        repository="Snowflake/snowflake-arctic-embed-s",
        revision="e596f507467533e48a2e17c007f0e1dacc837b33",
        license_spdx="Apache-2.0",
        license_reviewed_at="2026-09-02",
        adapter_id="bert-cls-onnx-v1",
        dimensions=384,
        max_tokens=512,
        batch_size=32,
        query_prefix="Represent this sentence for searching relevant passages: ",
        document_prefix="",
        model_path="onnx/model_int8.onnx",
        tokenizer_path="tokenizer.json",
        runtime_versions={
            "numpy": "2.4.4",
            "onnxruntime": "1.24.4",
            "python": "3.12.8",
            "tokenizers": "0.22.2",
        },
        files=(
            EmbeddingArtifactFile(
                path="README.md",
                bytes=85_025,
                source_digest_algorithm="git-blob-sha1",
                source_digest="36b307ef43ce930daa529eb151763835268482dc",
            ),
            EmbeddingArtifactFile(
                path="config.json",
                bytes=703,
                source_digest_algorithm="git-blob-sha1",
                source_digest="44dc4d3c660fd87dd1147355d74614615ce0ea8f",
            ),
            EmbeddingArtifactFile(
                path="onnx/model_int8.onnx",
                bytes=34_015_111,
                source_digest_algorithm="sha256",
                source_digest="f93ff225320628d2e88baf2a395cae791b0e3b27edf5c70bf7b312a4d3260c14",
            ),
            EmbeddingArtifactFile(
                path="tokenizer.json",
                bytes=711_649,
                source_digest_algorithm="git-blob-sha1",
                source_digest="3c0e6344ec45a9a6e5a621d6711baf109c2d9f87",
            ),
        ),
    )
}


def plan_embedding_artifact(model_id: str, output: Path) -> dict[str, Any]:
    spec = _model_spec(model_id)
    target = _absolute(output)
    return {
        "status": "preview",
        "execute": False,
        "network_required_on_execute": True,
        "model_id": spec.model_id,
        "repository": spec.repository,
        "revision": spec.revision,
        "license": spec.license_spdx,
        "artifact_bytes": spec.total_bytes,
        "artifact_file_count": len(spec.files),
        "output": str(target),
        "trust_remote_code": False,
        "inference_network_required": False,
    }


def install_embedding_artifact(
    model_id: str,
    output: Path,
    *,
    execute: bool,
) -> dict[str, Any]:
    preview = plan_embedding_artifact(model_id, output)
    if not execute:
        return preview

    spec = _model_spec(model_id)
    target = _prepare_new_artifact_target(output)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    building = Path(tempfile.mkdtemp(prefix=f".{target.name}.building-", dir=target.parent))
    try:
        for item in spec.files:
            destination = building / item.path
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _download_file(spec, item, destination)
            _verify_source_file(destination, item)
        files = _artifact_file_entries(building, spec)
        manifest = {
            "format_version": EMBEDDING_ARTIFACT_FORMAT_VERSION,
            "installed_at": datetime.now(UTC).isoformat(),
            **_static_manifest(spec),
            "files": files,
            "artifact_tree_sha256": _artifact_tree_digest(files),
        }
        _write_json(building / "artifact.json", manifest)
        _set_read_only_tree(building)
        verified = verify_embedding_artifact(building, model_id=spec.model_id)
        _publish_directory_no_replace(building, target)
        published = verify_embedding_artifact(target, model_id=spec.model_id)
        if _without_artifact_root(published) != _without_artifact_root(verified):
            raise RuntimeError(
                "published embedding artifact differs from the verified staging tree"
            )
        return {
            **preview,
            **published,
            "status": "installed",
            "execute": True,
            "artifact_root": str(target),
        }
    except Exception:
        if building.exists():
            _make_writable(building)
            shutil.rmtree(building, ignore_errors=True)
        raise


def stage_verified_embedding_artifact(
    source: Path,
    destination: Path,
    *,
    expected_model_id: str,
    expected_manifest_sha256: str,
    expected_tree_sha256: str,
) -> dict[str, Any]:
    source_attestation = verify_embedding_artifact(source, model_id=expected_model_id)
    if (
        source_attestation["manifest_sha256"] != expected_manifest_sha256
        or source_attestation["artifact_tree_sha256"] != expected_tree_sha256
    ):
        raise RuntimeError("embedding artifact attestation changed before sandbox staging")
    target = _absolute(destination)
    if target.exists() or target.is_symlink():
        raise ValueError(f"embedding artifact staging target already exists: {target}")
    target.mkdir(mode=0o700)
    spec = _model_spec(expected_model_id)
    try:
        for relative in ("artifact.json", *(item.path for item in spec.files)):
            output = target / relative
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _copy_regular_file_no_symlinks(_absolute(source) / relative, output)
        _set_read_only_tree(target)
        staged = verify_embedding_artifact(target, model_id=expected_model_id)
        if (
            staged["manifest_sha256"] != expected_manifest_sha256
            or staged["artifact_tree_sha256"] != expected_tree_sha256
            or _without_artifact_root(staged) != _without_artifact_root(source_attestation)
        ):
            raise RuntimeError("sandboxed embedding artifact differs from its verified source")
        return staged
    except Exception:
        if target.exists():
            _make_writable(target)
            shutil.rmtree(target, ignore_errors=True)
        raise


def verify_embedding_artifact(
    root: Path,
    *,
    model_id: str | None = None,
) -> dict[str, Any]:
    artifact_root = _absolute(root)
    if (
        artifact_root.is_symlink()
        or not artifact_root.is_dir()
        or artifact_root.resolve() != artifact_root
        or _is_within(artifact_root, Path.home().resolve())
    ):
        raise RuntimeError(f"embedding artifact root is missing or unsafe: {artifact_root}")
    manifest_path = artifact_root / "artifact.json"
    manifest = _load_json_object(manifest_path)
    manifest_model_id = _required_string(manifest, "model_id")
    if model_id is not None and manifest_model_id != model_id:
        raise RuntimeError("embedding artifact model id mismatch")
    spec = _model_spec(manifest_model_id)
    for key, expected in _static_manifest(spec).items():
        if manifest.get(key) != expected:
            raise RuntimeError(f"embedding artifact manifest {key} mismatch")
    if manifest.get("format_version") != EMBEDDING_ARTIFACT_FORMAT_VERSION:
        raise RuntimeError("unsupported embedding artifact format")
    if not isinstance(manifest.get("installed_at"), str) or not manifest["installed_at"]:
        raise RuntimeError("embedding artifact installed_at is invalid")

    _validate_artifact_tree(artifact_root, spec)
    files = _artifact_file_entries(artifact_root, spec)
    if manifest.get("files") != files:
        raise RuntimeError("embedding artifact file inventory mismatch")
    if manifest.get("artifact_tree_sha256") != _artifact_tree_digest(files):
        raise RuntimeError("embedding artifact tree digest mismatch")
    files_by_path = {cast(str, item["path"]): item for item in files}
    if set(files_by_path) != {item.path for item in spec.files}:
        raise RuntimeError("embedding artifact file set mismatch")
    for item in spec.files:
        path = artifact_root / item.path
        observed = files_by_path[item.path]
        if observed["bytes"] != item.bytes:
            raise RuntimeError(f"embedding artifact file size mismatch: {item.path}")
        _verify_source_file(path, item)

    manifest_sha256 = _sha256_file(manifest_path)
    return {
        "status": "verified",
        "model_id": spec.model_id,
        "repository": spec.repository,
        "revision": spec.revision,
        "license": spec.license_spdx,
        "license_reviewed_at": spec.license_reviewed_at,
        "artifact_root": str(artifact_root),
        "artifact_bytes": spec.total_bytes,
        "artifact_file_count": len(spec.files),
        "artifact_tree_sha256": manifest["artifact_tree_sha256"],
        "manifest_sha256": manifest_sha256,
        "adapter": manifest["adapter"],
        "runtime_versions": manifest["runtime_versions"],
        "trust_remote_code": False,
        "inference_network_required": False,
    }


def _static_manifest(spec: EmbeddingModelSpec) -> dict[str, Any]:
    return {
        "model_id": spec.model_id,
        "repository": spec.repository,
        "revision": spec.revision,
        "license": {
            "spdx": spec.license_spdx,
            "reviewed_at": spec.license_reviewed_at,
            "source": (f"https://huggingface.co/{spec.repository}/blob/{spec.revision}/README.md"),
        },
        "adapter": {
            "id": spec.adapter_id,
            "model_path": spec.model_path,
            "tokenizer_path": spec.tokenizer_path,
            "dimensions": spec.dimensions,
            "max_tokens": spec.max_tokens,
            "batch_size": spec.batch_size,
            "pooling": "cls",
            "normalization": "l2",
            "query_prefix": spec.query_prefix,
            "document_prefix": spec.document_prefix,
            "long_input_policy": "truncate",
            "trust_remote_code": False,
            "network_required": False,
        },
        "runtime_versions": dict(sorted(spec.runtime_versions.items())),
        "source_files": [
            {
                "path": item.path,
                "bytes": item.bytes,
                "digest_algorithm": item.source_digest_algorithm,
                "digest": item.source_digest,
            }
            for item in spec.files
        ],
    }


def _download_file(
    spec: EmbeddingModelSpec,
    item: EmbeddingArtifactFile,
    destination: Path,
) -> None:
    encoded_path = quote(item.path, safe="/")
    url = (
        f"https://huggingface.co/{spec.repository}/resolve/{spec.revision}/"
        f"{encoded_path}?download=true"
    )
    curl = shutil.which("curl")
    if curl is None:
        raise RuntimeError("curl is required for bounded embedding artifact downloads")
    command = [
        curl,
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "20",
        "--max-time",
        str(_DOWNLOAD_TIMEOUT_SECONDS),
        "--max-filesize",
        str(item.bytes),
        "--user-agent",
        "cross-agent-memory/0.1",
        "--output",
        "-",
        url,
    ]
    try:
        with destination.open("xb") as output:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                text=False,
                timeout=_DOWNLOAD_TIMEOUT_SECONDS + 5,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"embedding artifact download exceeded deadline: {item.path}") from exc
    if completed.returncode:
        raise RuntimeError(
            "embedding artifact download failed with curl status "
            f"{completed.returncode}: {item.path}"
        )
    destination.chmod(0o600)
    if destination.stat().st_size != item.bytes:
        raise RuntimeError(f"embedding artifact download size mismatch: {item.path}")


def _verify_source_file(path: Path, spec: EmbeddingArtifactFile) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != spec.bytes:
        raise RuntimeError(f"embedding artifact source file mismatch: {spec.path}")
    if spec.source_digest_algorithm == "sha256":
        observed = _sha256_file(path)
    elif spec.source_digest_algorithm == "git-blob-sha1":
        observed = _git_blob_sha1(path)
    else:
        raise RuntimeError(f"unsupported embedding artifact source digest: {spec.path}")
    if observed != spec.source_digest:
        raise RuntimeError(f"embedding artifact source digest mismatch: {spec.path}")


def _artifact_file_entries(
    root: Path,
    spec: EmbeddingModelSpec,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in sorted(spec.files, key=lambda value: value.path):
        path = root / item.path
        entries.append(
            {
                "path": item.path,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries


def _validate_artifact_tree(root: Path, spec: EmbeddingModelSpec) -> None:
    expected_files: dict[str, int | None] = {item.path: item.bytes for item in spec.files}
    expected_files["artifact.json"] = None
    expected_directories: set[str] = set()
    for relative in expected_files:
        member = Path(relative)
        if member.is_absolute() or ".." in member.parts or member.as_posix() != relative:
            raise RuntimeError("embedding artifact specification contains an unsafe path")
        expected_directories.update(
            parent.as_posix() for parent in member.parents if parent != Path(".")
        )

    if stat.S_IMODE(root.stat().st_mode) != 0o500:
        raise RuntimeError("embedding artifact root permissions are not read-only")
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    entry_limit = len(expected_files) + len(expected_directories)
    entry_count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > entry_limit:
                    raise RuntimeError("embedding artifact contains unexpected entries")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if entry.is_symlink():
                    raise RuntimeError("embedding artifact contains a symlink")
                mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                if entry.is_dir(follow_symlinks=False):
                    if relative not in expected_directories or mode != 0o500:
                        raise RuntimeError(
                            "embedding artifact directory set or permissions mismatch"
                        )
                    seen_directories.add(relative)
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False) or relative not in expected_files:
                    raise RuntimeError("embedding artifact contains an unexpected file")
                expected_size = expected_files[relative]
                observed_size = entry.stat(follow_symlinks=False).st_size
                if (
                    mode != 0o400
                    or (
                        expected_size is None
                        and not 0 < observed_size <= MAX_ARTIFACT_MANIFEST_BYTES
                    )
                    or (expected_size is not None and observed_size != expected_size)
                ):
                    raise RuntimeError("embedding artifact file size or permissions mismatch")
                seen_files.add(relative)
    if seen_files != set(expected_files) or seen_directories != expected_directories:
        raise RuntimeError("embedding artifact file or directory set mismatch")


def _artifact_tree_digest(files: list[dict[str, Any]]) -> str:
    payload = "".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n" for item in files
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _prepare_new_artifact_target(path: Path) -> Path:
    target = _absolute(path)
    if target.exists() or target.is_symlink():
        raise ValueError(f"embedding artifact output already exists: {target}")
    if _is_within(target, Path.home().resolve()):
        raise ValueError("embedding artifact output must be outside the host user's home")
    for ancestor in target.parents:
        if ancestor.exists() and ancestor.is_symlink():
            raise ValueError("embedding artifact output parents must not be symlinks")
    return target


def _publish_directory_no_replace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if source.parent != target.parent:
        raise ValueError("embedding artifact publication must stay within one parent directory")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_descriptor = os.open(source.parent, directory_flags)
    source_descriptor = os.open(source.name, directory_flags, dir_fd=parent_descriptor)
    source_mode = stat.S_IMODE(os.fstat(source_descriptor).st_mode)
    try:
        source_identity = os.fstat(source_descriptor)
        if source_mode != 0o500:
            raise RuntimeError("embedding artifact staging root is not sealed")
        # macOS refuses to rename a write-disabled directory, even within one parent.
        # Keep the directory identity open, restore its sealed mode in all paths, and
        # verify the published identity and contents before returning.
        os.fchmod(source_descriptor, 0o700)
        source_bytes = os.fsencode(source.name)
        target_bytes = os.fsencode(target.name)
        try:
            if sys.platform == "darwin":
                rename = libc.renameatx_np
                rename.argtypes = [
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_uint,
                ]
                rename.restype = ctypes.c_int
                result = rename(
                    parent_descriptor,
                    source_bytes,
                    parent_descriptor,
                    target_bytes,
                    _RENAME_EXCL,
                )
            elif sys.platform.startswith("linux"):
                rename = getattr(libc, "renameat2", None)
                if rename is None:
                    raise RuntimeError(
                        "atomic no-replace publication is unavailable on this platform"
                    )
                rename.argtypes = [
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_uint,
                ]
                rename.restype = ctypes.c_int
                result = rename(
                    parent_descriptor,
                    source_bytes,
                    parent_descriptor,
                    target_bytes,
                    _RENAME_NOREPLACE,
                )
            else:
                raise RuntimeError("atomic no-replace publication is unavailable on this platform")
        finally:
            os.fchmod(source_descriptor, source_mode)
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise ValueError(f"embedding artifact output already exists: {target}")
            raise OSError(error_number, os.strerror(error_number), target)
        published_identity = os.stat(
            target.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            published_identity.st_dev != source_identity.st_dev
            or published_identity.st_ino != source_identity.st_ino
            or not stat.S_ISDIR(published_identity.st_mode)
            or stat.S_IMODE(published_identity.st_mode) != 0o500
        ):
            raise RuntimeError("published embedding artifact identity changed")
        os.fsync(parent_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(parent_descriptor)


def _model_spec(model_id: str) -> EmbeddingModelSpec:
    spec = FROZEN_EMBEDDING_MODELS.get(model_id)
    if spec is None:
        raise ValueError(f"unknown frozen embedding model: {model_id}")
    return spec


def _load_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected a regular artifact manifest: {path}")
    if path.stat().st_size > MAX_ARTIFACT_MANIFEST_BYTES:
        raise RuntimeError("embedding artifact manifest exceeds its size limit")
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("embedding artifact manifest must be an object")
    return cast(dict[str, Any], value)


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise RuntimeError(f"embedding artifact {key} must be a non-empty string")
    return item


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _copy_regular_file_no_symlinks(source: Path, destination: Path) -> None:
    source_descriptor, _normalized = open_regular_file_no_symlinks(
        source,
        "embedding artifact member",
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("embedding artifact member must be a singly linked regular file")
        destination_descriptor = os.open(destination, flags, 0o400)
        copied = 0
        while block := os.read(source_descriptor, _DOWNLOAD_CHUNK_BYTES):
            copied += len(block)
            written = 0
            while written < len(block):
                written += os.write(destination_descriptor, block[written:])
        after = os.fstat(source_descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if copied != before.st_size or after_identity != before_identity:
            raise RuntimeError("embedding artifact member changed while it was staged")
        os.fchmod(destination_descriptor, 0o400)
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _without_artifact_root(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"artifact_root", "status"}}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_DOWNLOAD_CHUNK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_blob_sha1(path: Path) -> str:
    payload = path.read_bytes()
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(payload)}\0".encode())
    digest.update(payload)
    return digest.hexdigest()


def _set_read_only_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    root.chmod(0o500)


def _make_writable(root: Path) -> None:
    root.chmod(0o700)
    for path in root.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
