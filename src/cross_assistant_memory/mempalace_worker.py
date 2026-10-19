from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import platform
import resource
import stat
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Any, Protocol, cast

MAX_WORKER_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_WORKER_OUTPUT_NODES = 50_000
MAX_WORKER_CONTAINER_ITEMS = 4_096
MAX_WORKER_STRING_CHARACTERS = 65_536


class _Hit(Protocol):
    id: str
    score: float
    metadata: dict[str, Any]


class _LexicalResult(Protocol):
    hits: list[_Hit]


class _GetResult(Protocol):
    ids: list[str]


class _QueryResult(Protocol):
    ids: list[list[str]]
    metadatas: list[list[dict[str, Any]]]
    distances: list[list[float]]


class _Collection(Protocol):
    def add(
        self,
        *,
        ids: list[str],
        documents: list[str],
        metadatas: list[dict[str, str]],
        embeddings: list[list[float]],
    ) -> object: ...

    def lexical_search(
        self,
        *,
        query: str,
        n_results: int,
        where: dict[str, Any],
    ) -> _LexicalResult: ...

    def query(
        self,
        *,
        query_embeddings: list[list[float]],
        n_results: int,
        where: dict[str, Any],
        include: list[str],
    ) -> _QueryResult: ...

    def delete(self, *, ids: list[str]) -> object: ...

    def count(self) -> int: ...

    def get(self, *, ids: list[str]) -> _GetResult: ...


class _Backend(Protocol):
    def create_collection(self, palace_path: str, collection_name: str) -> _Collection: ...

    def get_collection(
        self,
        palace_path: str,
        collection_name: str,
        *,
        options: dict[str, bool] | None = None,
    ) -> _Collection: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class _EmbeddingConfig:
    root: Path
    manifest_sha256: str
    artifact_tree_sha256: str
    model_id: str
    adapter: dict[str, Any]
    runtime_versions: dict[str, str]


class _OnnxEmbedder:
    def __init__(self, config: _EmbeddingConfig) -> None:
        np = importlib.import_module("numpy")
        ort = importlib.import_module("onnxruntime")
        tokenizers = importlib.import_module("tokenizers")
        observed_versions = {
            "numpy": str(np.__version__),
            "onnxruntime": str(ort.__version__),
            "python": platform.python_version(),
            "tokenizers": str(tokenizers.__version__),
        }
        if observed_versions != config.runtime_versions:
            raise RuntimeError("embedding runtime versions do not match the artifact manifest")

        adapter = config.adapter
        tokenizer_path = _artifact_member(config.root, _string(adapter, "tokenizer_path"))
        model_path = _artifact_member(config.root, _string(adapter, "model_path"))
        tokenizer_type = tokenizers.Tokenizer
        tokenizer = tokenizer_type.from_file(str(tokenizer_path))
        tokenizer.enable_truncation(max_length=_integer(adapter, "max_tokens"))
        pad_id = tokenizer.token_to_id("[PAD]")
        if not isinstance(pad_id, int) or pad_id < 0:
            raise RuntimeError("embedding tokenizer does not define a valid [PAD] token")
        tokenizer.enable_padding(pad_id=pad_id, pad_token="[PAD]")

        options = ort.SessionOptions()
        options.intra_op_num_threads = 2
        options.inter_op_num_threads = 1
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        session = ort.InferenceSession(
            str(model_path),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
        input_names = {str(item.name) for item in session.get_inputs()}
        if not {"input_ids", "attention_mask"}.issubset(input_names):
            raise RuntimeError("embedding ONNX inputs omit required BERT tensors")
        if input_names - {"input_ids", "attention_mask", "token_type_ids"}:
            raise RuntimeError("embedding ONNX inputs contain unsupported tensors")
        outputs = session.get_outputs()
        if not outputs:
            raise RuntimeError("embedding ONNX model does not define an output")

        self._np = np
        self._tokenizer = tokenizer
        self._session = session
        self._input_names = input_names
        self._output_name = str(outputs[0].name)
        self._dimensions = _integer(adapter, "dimensions")
        self._batch_size = _integer(adapter, "batch_size")
        self._query_prefix = _string(adapter, "query_prefix")
        self._document_prefix = _string_allow_empty(adapter, "document_prefix")
        self.runtime_receipt = {
            "versions": observed_versions,
            "provider": "CPUExecutionProvider",
            "intra_op_threads": 2,
            "inter_op_threads": 1,
        }

    @property
    def batch_size(self) -> int:
        return self._batch_size

    def embed(self, texts: list[str], *, role: str) -> list[list[float]]:
        if not texts:
            return []
        if len(texts) > self._batch_size:
            raise ValueError("embedding batch exceeds the configured bound")
        if role == "query":
            prefix = self._query_prefix
        elif role == "document":
            prefix = self._document_prefix
        else:
            raise ValueError("embedding role must be query or document")
        encodings = self._tokenizer.encode_batch([prefix + text for text in texts])
        inputs: dict[str, Any] = {
            "input_ids": self._np.asarray([item.ids for item in encodings], dtype="int64"),
            "attention_mask": self._np.asarray(
                [item.attention_mask for item in encodings], dtype="int64"
            ),
        }
        if "token_type_ids" in self._input_names:
            inputs["token_type_ids"] = self._np.asarray(
                [item.type_ids for item in encodings], dtype="int64"
            )
        hidden = self._session.run([self._output_name], inputs)[0]
        if len(hidden.shape) != 3 or int(hidden.shape[0]) != len(texts):
            raise RuntimeError("embedding ONNX output has an unexpected shape")
        vectors = hidden[:, 0, :]
        if int(vectors.shape[1]) != self._dimensions:
            raise RuntimeError("embedding ONNX output dimension does not match its manifest")
        norms = self._np.linalg.norm(vectors, axis=1, keepdims=True)
        if bool(self._np.any(norms <= 0)):
            raise RuntimeError("embedding ONNX model returned a zero vector")
        normalized = vectors / norms
        result = normalized.astype(float).tolist()
        if any(
            len(vector) != self._dimensions
            or any(not math.isfinite(float(value)) for value in vector)
            for vector in result
        ):
            raise RuntimeError("embedding ONNX model returned an invalid vector")
        return cast(list[list[float]], result)


def main() -> None:
    args = _parser().parse_args()
    checkout = Path(args.checkout).resolve()
    sys.path.insert(0, str(checkout))
    module = importlib.import_module("mempalace.backends.sqlite_exact")
    backend_factory = cast(Callable[[], _Backend], module.SQLiteExactBackend)
    backend = backend_factory()
    try:
        command = str(args.command)
        if command == "build":
            result = _build(backend, args)
        elif command == "search":
            result = _search(backend, args)
        elif command == "delete":
            result = _delete(backend, args)
        elif command == "inspect":
            result = _inspect(backend, args)
        else:
            raise ValueError(f"unknown worker command: {command}")
    finally:
        backend.close()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    peak_rss = int(usage.ru_maxrss)
    result["resource_usage"] = {
        "cpu_ms": round((usage.ru_utime + usage.ru_stime) * 1000),
        "peak_rss_bytes": peak_rss if platform.system() == "Darwin" else peak_rss * 1024,
    }
    _limit_output_file_size()
    _write_json(Path(args.output), result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--palace", required=True)
    parser.add_argument("--collection", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--embedding-artifact")
    parser.add_argument("--embedding-manifest-sha256")
    parser.add_argument("--embedding-tree-sha256")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--input", required=True)

    search = subparsers.add_parser("search")
    search.add_argument("--request", required=True)

    delete = subparsers.add_parser("delete")
    delete.add_argument("--event-id", required=True)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--event-id", required=True)
    return parser


def _build(backend: _Backend, args: argparse.Namespace) -> dict[str, Any]:
    embedding_config = _load_embedding_config(args)
    embedder = _OnnxEmbedder(embedding_config) if embedding_config is not None else None
    collection = backend.create_collection(str(args.palace), str(args.collection))
    batch_size = embedder.batch_size if embedder is not None else 128
    document_count = 0
    batch_count = 0
    for documents in _read_jsonl_batches(Path(args.input), batch_size=batch_size):
        vectors = (
            embedder.embed(
                [_string(item, "content_text") for item in documents],
                role="document",
            )
            if embedder is not None
            else [[1.0] for _ in documents]
        )
        collection.add(
            ids=[_string(item, "event_id") for item in documents],
            documents=[_string(item, "content_text") for item in documents],
            metadatas=[projection_metadata(item) for item in documents],
            embeddings=vectors,
        )
        document_count += len(documents)
        batch_count += 1
    if collection.count() != document_count:
        raise RuntimeError("projection collection count does not match worker input")
    return {
        "status": "built",
        "document_count": document_count,
        "batch_count": batch_count,
        "retrieval_mode": "semantic" if embedder is not None else "lexical",
        "embedding": (
            _embedding_receipt(embedding_config, embedder)
            if embedding_config is not None and embedder is not None
            else None
        ),
    }


def _search(backend: _Backend, args: argparse.Namespace) -> dict[str, Any]:
    request = _read_json_object(Path(args.request))
    embedding_config = _load_embedding_config(args)
    embedder = _OnnxEmbedder(embedding_config) if embedding_config is not None else None
    collection = backend.get_collection(
        str(args.palace),
        str(args.collection),
        options={"read_only": True},
    )
    hits: list[dict[str, Any]] = []
    source_systems = _string_list(request, "source_systems")
    if not source_systems or len(set(source_systems)) != len(source_systems):
        raise ValueError("source systems must be a non-empty unique list")
    if embedder is None:
        for source_system in source_systems:
            lexical = collection.lexical_search(
                query=_string(request, "query"),
                n_results=_integer(request, "limit"),
                where=projection_where({**request, "source_systems": [source_system]}),
            )
            for hit in lexical.hits:
                score = float(hit.score)
                if not math.isfinite(score):
                    raise ValueError("candidate returned a non-finite score")
                hits.append({"event_id": hit.id, "score": score, "metadata": hit.metadata})
    else:
        query_vector = embedder.embed([_string(request, "query")], role="query")
        for source_system in source_systems:
            semantic = collection.query(
                query_embeddings=query_vector,
                n_results=_integer(request, "limit"),
                where=projection_where({**request, "source_systems": [source_system]}),
                include=["metadatas", "distances"],
            )
            ids = semantic.ids[0] if semantic.ids else []
            metadatas = semantic.metadatas[0] if semantic.metadatas else []
            distances = semantic.distances[0] if semantic.distances else []
            if not (len(ids) == len(metadatas) == len(distances)):
                raise RuntimeError("semantic query returned misaligned result fields")
            for event_id, metadata, distance in zip(ids, metadatas, distances, strict=True):
                score = 1.0 - float(distance)
                if not math.isfinite(score):
                    raise ValueError("candidate returned a non-finite score")
                hits.append({"event_id": event_id, "score": score, "metadata": metadata})
    return {
        "status": "ok",
        "retrieval_mode": "semantic" if embedder is not None else "lexical",
        "embedding": (
            _embedding_receipt(embedding_config, embedder)
            if embedding_config is not None and embedder is not None
            else None
        ),
        "hits": hits,
    }


def _delete(backend: _Backend, args: argparse.Namespace) -> dict[str, Any]:
    collection = backend.get_collection(str(args.palace), str(args.collection))
    before = collection.count()
    event_id = str(args.event_id)
    collection.delete(ids=[event_id])
    after = collection.count()
    return {
        "status": "deleted",
        "event_id": event_id,
        "count_before": before,
        "count_after": after,
    }


def _inspect(backend: _Backend, args: argparse.Namespace) -> dict[str, Any]:
    collection = backend.get_collection(
        str(args.palace),
        str(args.collection),
        options={"read_only": True},
    )
    event_id = str(args.event_id)
    return {
        "status": "inspected",
        "event_id": event_id,
        "document_count": collection.count(),
        "present": event_id in collection.get(ids=[event_id]).ids,
    }


def projection_metadata(document: dict[str, Any]) -> dict[str, str]:
    contexts = _contexts(document)
    metadata = {
        "event_id": _string(document, "event_id"),
        "content_digest": _string(document, "content_digest"),
        "source_system": _string(document, "source_system"),
        "scope": _string(document, "scope"),
        "project_id": _optional_string(document, "project_id") or "",
        "authority": _string(document, "authority"),
        "access": _string(document, "access"),
        "context_state_sha256": _context_state_digest(contexts),
    }
    for context in contexts:
        metadata[context_metadata_key(context["kind"], context["key"])] = "1"
    return metadata


def projection_where(request: dict[str, Any]) -> dict[str, Any]:
    scopes = _string_list(request, "scopes")
    if not scopes:
        raise ValueError("at least one scope is required")
    clauses: list[dict[str, Any]] = [{"scope": {"$in": scopes}}]
    authorities = _string_list(request, "authorities")
    if authorities:
        clauses.append({"authority": {"$in": authorities}})
    accesses = _string_list(request, "accesses")
    if not accesses:
        raise ValueError("at least one access class is required")
    clauses.append({"access": {"$in": accesses}})
    source_systems = _string_list(request, "source_systems")
    if not source_systems:
        raise ValueError("at least one source system is required")
    clauses.append({"source_system": {"$in": source_systems}})
    for context in _contexts(request):
        clauses.append({context_metadata_key(context["kind"], context["key"]): {"$eq": "1"}})
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


def _contexts(value: dict[str, Any]) -> list[dict[str, str]]:
    raw_contexts = value.get("contexts")
    if not isinstance(raw_contexts, list):
        raise ValueError("contexts must be a list")
    contexts: list[dict[str, str]] = []
    for raw in cast(list[object], raw_contexts):
        if not isinstance(raw, dict):
            raise ValueError("contexts must contain objects")
        item = cast(dict[str, Any], raw)
        context = {"kind": _string(item, "kind"), "key": _string(item, "key")}
        if item != context:
            raise ValueError("context contains unexpected fields")
        contexts.append(context)
    contexts.sort(key=lambda item: (item["kind"], item["key"]))
    if len({(item["kind"], item["key"]) for item in contexts}) != len(contexts):
        raise ValueError("contexts contain duplicates")
    return contexts


def context_metadata_key(kind: str, key: str) -> str:
    digest = hashlib.sha256(f"{kind}\x00{key}".encode()).hexdigest()
    return f"context_{digest}"


def _context_state_digest(contexts: list[dict[str, str]]) -> str:
    payload = json.dumps(contexts, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _load_embedding_config(args: argparse.Namespace) -> _EmbeddingConfig | None:
    raw_values = (
        args.embedding_artifact,
        args.embedding_manifest_sha256,
        args.embedding_tree_sha256,
    )
    if all(value is None for value in raw_values):
        return None
    if any(value is None for value in raw_values):
        raise ValueError("embedding artifact arguments must be provided together")

    provided_root = Path(str(args.embedding_artifact))
    if provided_root.is_symlink():
        raise RuntimeError("embedding artifact root is unsafe")
    try:
        root = provided_root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("embedding artifact root cannot be resolved") from exc
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("embedding artifact root is unsafe")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise RuntimeError("embedding artifact contains a symlink")

    manifest_path = root / "artifact.json"
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.stat().st_size > 1024 * 1024
    ):
        raise RuntimeError("embedding artifact manifest is missing or unsafe")
    manifest_sha256 = _sha256_file(manifest_path)
    if manifest_sha256 != str(args.embedding_manifest_sha256):
        raise RuntimeError("embedding artifact manifest digest changed before inference")
    manifest = _read_json_object(manifest_path)
    if manifest.get("format_version") != 1:
        raise RuntimeError("unsupported embedding artifact format")
    model_id = _string(manifest, "model_id")
    adapter_raw = manifest.get("adapter")
    if not isinstance(adapter_raw, dict):
        raise RuntimeError("embedding artifact adapter is invalid")
    adapter = cast(dict[str, Any], adapter_raw)
    expected_adapter_values: dict[str, object] = {
        "id": "bert-cls-onnx-v1",
        "pooling": "cls",
        "normalization": "l2",
        "long_input_policy": "truncate",
        "trust_remote_code": False,
        "network_required": False,
    }
    for key, expected in expected_adapter_values.items():
        if adapter.get(key) != expected:
            raise RuntimeError(f"embedding artifact adapter {key} is unsupported")
    _integer(adapter, "dimensions")
    _integer(adapter, "max_tokens")
    _integer(adapter, "batch_size")
    _string(adapter, "model_path")
    _string(adapter, "tokenizer_path")
    _string(adapter, "query_prefix")
    _string_allow_empty(adapter, "document_prefix")

    versions_raw = manifest.get("runtime_versions")
    if not isinstance(versions_raw, dict):
        raise RuntimeError("embedding artifact runtime versions are invalid")
    versions_object = cast(dict[object, object], versions_raw)
    if set(versions_object) != {"numpy", "onnxruntime", "python", "tokenizers"} or any(
        not isinstance(key, str) or not isinstance(value, str) or not value
        for key, value in versions_object.items()
    ):
        raise RuntimeError("embedding artifact runtime versions are invalid")
    runtime_versions = cast(dict[str, str], versions_raw)

    expected_files = _manifest_artifact_files(manifest)
    _validate_artifact_tree(root, expected_files)
    files = _artifact_file_entries(root, expected_files)
    if manifest.get("files") != files:
        raise RuntimeError("embedding artifact file inventory changed before inference")
    artifact_tree_sha256 = _artifact_tree_digest(files)
    if manifest.get("artifact_tree_sha256") != artifact_tree_sha256 or artifact_tree_sha256 != str(
        args.embedding_tree_sha256
    ):
        raise RuntimeError("embedding artifact tree digest changed before inference")
    _artifact_member(root, _string(adapter, "model_path"))
    _artifact_member(root, _string(adapter, "tokenizer_path"))
    return _EmbeddingConfig(
        root=root,
        manifest_sha256=manifest_sha256,
        artifact_tree_sha256=artifact_tree_sha256,
        model_id=model_id,
        adapter=adapter,
        runtime_versions=dict(runtime_versions),
    )


def _embedding_receipt(
    config: _EmbeddingConfig,
    embedder: _OnnxEmbedder,
) -> dict[str, Any]:
    return {
        "model_id": config.model_id,
        "manifest_sha256": config.manifest_sha256,
        "artifact_tree_sha256": config.artifact_tree_sha256,
        "adapter_id": _string(config.adapter, "id"),
        "dimensions": _integer(config.adapter, "dimensions"),
        "max_tokens": _integer(config.adapter, "max_tokens"),
        "batch_size": embedder.batch_size,
        "pooling": _string(config.adapter, "pooling"),
        "normalization": _string(config.adapter, "normalization"),
        "long_input_policy": _string(config.adapter, "long_input_policy"),
        "runtime": embedder.runtime_receipt,
        "trust_remote_code": False,
        "network_required": False,
    }


def _manifest_artifact_files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise RuntimeError("embedding artifact file inventory is invalid")
    raw_file_list = cast(list[object], raw_files)
    if not 1 <= len(raw_file_list) <= 16:
        raise RuntimeError("embedding artifact file inventory is invalid")
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for raw in raw_file_list:
        if not isinstance(raw, dict):
            raise RuntimeError("embedding artifact file inventory is invalid")
        item = cast(dict[str, Any], raw)
        relative = _string(item, "path")
        path = Path(relative)
        byte_length = _integer(item, "bytes")
        digest = _string(item, "sha256")
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != relative
            or relative == "artifact.json"
            or relative in seen
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RuntimeError("embedding artifact file inventory is invalid")
        total_bytes += byte_length
        if total_bytes > 512 * 1024 * 1024:
            raise RuntimeError("embedding artifact file inventory exceeds its byte limit")
        seen.add(relative)
        files.append({"path": relative, "bytes": byte_length, "sha256": digest})
    files.sort(key=lambda item: cast(str, item["path"]))
    if raw_file_list != files:
        raise RuntimeError("embedding artifact file inventory is not canonical")
    return files


def _validate_artifact_tree(root: Path, expected_files: list[dict[str, Any]]) -> None:
    expected_sizes = {cast(str, item["path"]): cast(int, item["bytes"]) for item in expected_files}
    expected_sizes["artifact.json"] = -1
    expected_directories: set[str] = set()
    for relative in expected_sizes:
        member = Path(relative)
        expected_directories.update(
            parent.as_posix() for parent in member.parents if parent != Path(".")
        )
    if stat.S_IMODE(root.stat().st_mode) != 0o500:
        raise RuntimeError("embedding artifact root permissions changed before inference")
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    entry_limit = len(expected_sizes) + len(expected_directories)
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
                            "embedding artifact directory set or permissions changed"
                        )
                    seen_directories.add(relative)
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False) or relative not in expected_sizes:
                    raise RuntimeError("embedding artifact contains an unexpected file")
                expected_size = expected_sizes[relative]
                observed_size = entry.stat(follow_symlinks=False).st_size
                if (
                    mode != 0o400
                    or (expected_size == -1 and not 0 < observed_size <= 1024 * 1024)
                    or (expected_size != -1 and observed_size != expected_size)
                ):
                    raise RuntimeError("embedding artifact file size or permissions changed")
                seen_files.add(relative)
    if seen_files != set(expected_sizes) or seen_directories != expected_directories:
        raise RuntimeError("embedding artifact file or directory set changed before inference")


def _artifact_file_entries(
    root: Path,
    expected_files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for expected in expected_files:
        relative = cast(str, expected["path"])
        path = root / relative
        entries.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries


def _artifact_tree_digest(files: list[dict[str, Any]]) -> str:
    payload = "".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n" for item in files
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _artifact_member(root: Path, relative: str) -> Path:
    member = root / relative
    try:
        resolved = member.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise RuntimeError("embedding artifact member path is unsafe") from exc
    if member.is_symlink() or not member.is_file() or resolved != member:
        raise RuntimeError("embedding artifact member path is unsafe")
    return member


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_jsonl_batches(path: Path, *, batch_size: int) -> Iterator[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            value: object = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("worker input rows must be JSON objects")
            batch.append(cast(dict[str, Any], value))
            if len(batch) == batch_size:
                yield batch
                batch = []
    if batch:
        yield batch


def _read_json_object(path: Path) -> dict[str, Any]:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("worker request must be a JSON object")
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _validate_output_shape(value)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    total = 0
    try:
        encoder = json.JSONEncoder(separators=(",", ":"), sort_keys=True)
        for text in chain(encoder.iterencode(value), ("\n",)):
            payload = text.encode("utf-8")
            total += len(payload)
            if total > MAX_WORKER_OUTPUT_BYTES:
                raise RuntimeError("worker output exceeds its byte limit")
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count == 0:
                    raise OSError("worker output made no write progress")
                written += count
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _limit_output_file_size() -> None:
    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = (
        MAX_WORKER_OUTPUT_BYTES
        if hard == resource.RLIM_INFINITY
        else min(int(hard), MAX_WORKER_OUTPUT_BYTES)
    )
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _validate_output_shape(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    node_count = 0
    string_bytes = 0
    while pending:
        item, depth = pending.pop()
        node_count += 1
        if node_count > MAX_WORKER_OUTPUT_NODES or depth > 12:
            raise RuntimeError("worker output exceeds its shape limit")
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if abs(item) > 2**63 - 1:
                raise RuntimeError("worker output integer is out of range")
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise RuntimeError("worker output contains a non-finite number")
            continue
        if isinstance(item, str):
            if len(item) > MAX_WORKER_STRING_CHARACTERS:
                raise RuntimeError("worker output string exceeds its character limit")
            string_bytes += len(item.encode("utf-8"))
            if string_bytes > MAX_WORKER_OUTPUT_BYTES:
                raise RuntimeError("worker output strings exceed the byte limit")
            continue
        if isinstance(item, list):
            children = cast(list[object], item)
            if len(children) > MAX_WORKER_CONTAINER_ITEMS:
                raise RuntimeError("worker output list exceeds its item limit")
            pending.extend((child, depth + 1) for child in children)
            continue
        if isinstance(item, dict):
            mapping = cast(dict[object, object], item)
            if len(mapping) > MAX_WORKER_CONTAINER_ITEMS:
                raise RuntimeError("worker output object exceeds its item limit")
            for key, child in mapping.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise RuntimeError("worker output object key is invalid")
                string_bytes += len(key.encode("utf-8"))
                if string_bytes > MAX_WORKER_OUTPUT_BYTES:
                    raise RuntimeError("worker output strings exceed the byte limit")
                pending.append((child, depth + 1))
            continue
        raise RuntimeError("worker output contains an unsupported value")


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a non-empty string")
    return item


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be null or a non-empty string")
    return item


def _string_allow_empty(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ValueError(f"{key} must be a string")
    return item


def _integer(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int) or item < 1:
        raise ValueError(f"{key} must be a positive integer")
    return item


def _string_list(value: dict[str, Any], key: str) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list):
        raise ValueError(f"{key} must be a string list")
    values = cast(list[object], item)
    if any(not isinstance(entry, str) or not entry for entry in values):
        raise ValueError(f"{key} must be a string list")
    return cast(list[str], values)


if __name__ == "__main__":
    main()
