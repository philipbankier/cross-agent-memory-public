from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import os
import platform
import resource
import shutil
import sqlite3
import stat
import statistics
import subprocess
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO, cast

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import DEFAULT_MAX_FILE_BYTES, parse_file
from cross_assistant_memory.models import (
    Access,
    Authority,
    ContextFilter,
    ContextKind,
    QueryMode,
    RetrievalControl,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.retrieval import MAX_EVIDENCE_PREVIEW_CHARACTERS
from cross_assistant_memory.safe_files import (
    open_regular_file_no_symlinks,
    publish_directory_no_replace,
    publish_file_no_replace,
)
from cross_assistant_memory.storage import DEFAULT_MAX_RECORD_BYTES, FTS_TOKEN, Ledger

EVALUATION_FORMAT_VERSION = 1
FROZEN_BASELINE_REVISION = "9c483a66563e8edea90f128bb53d4c15d9b7917c"
FROZEN_WORKSET_REVISION = "8ea5e23f5da69bfbbedf4c9e7a40f0b91047fd33"
PRIVATE_SPLITS = ("calibration", "development", "held_out")
QUERY_SPLITS = (*PRIVATE_SPLITS, "regression")
QUERY_SUITES = (
    "exact_evidence",
    "attribution_and_authority",
    "current_and_historical_state",
    "work_continuity",
    "preference_and_persona",
    "deletion_and_recovery",
    "security",
)
BASELINE_PATHS = (
    "src/cross_assistant_memory/admission.py",
    "src/cross_assistant_memory/config.py",
    "src/cross_assistant_memory/ingest.py",
    "src/cross_assistant_memory/models.py",
    "src/cross_assistant_memory/parsers",
    "src/cross_assistant_memory/storage.py",
)
WORKSET_BASELINE_PATHS = (
    *BASELINE_PATHS,
    "src/cross_assistant_memory/retrieval.py",
)
WORKSET_HARNESS_PATHS = (
    "src/cross_assistant_memory/evaluation.py",
    "src/cross_assistant_memory/safe_files.py",
)
SEMANTIC_PROJECTION_PATHS = (
    *WORKSET_BASELINE_PATHS,
    "src/cross_assistant_memory/candidates.py",
    "src/cross_assistant_memory/embedding_artifact.py",
    "src/cross_assistant_memory/mempalace_worker.py",
    "src/cross_assistant_memory/projection.py",
)
EVIDENCE_RELATION_TYPES = frozenset(
    {"source_variant", "contradiction", "correction", "supersession"}
)


class EvaluationIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    source_system: SourceSystem
    path: Path
    source_account: str
    scope: Scope
    project_id: str | None
    expected_sha256: str
    max_file_bytes: int


@dataclass(frozen=True)
class EvaluationQuery:
    query_id: str
    split: str
    suite: str
    query: str
    mode: QueryMode
    project_id: str | None
    scopes: tuple[Scope, ...]
    authorities: tuple[Authority, ...]
    contexts: tuple[ContextFilter, ...]
    limit: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "split": self.split,
            "suite": self.suite,
            "query": self.query,
            "mode": self.mode.value,
            "project_id": self.project_id,
            "scopes": [item.value for item in self.scopes],
            "authorities": [item.value for item in self.authorities],
            "contexts": [item.as_dict() for item in self.contexts],
            "limit": self.limit,
        }


@dataclass(frozen=True)
class AnswerSelector:
    source_id: str
    record_ordinal: int
    gain: int


@dataclass(frozen=True)
class EvaluationAnswer:
    query_id: str
    relevant: tuple[AnswerSelector, ...]
    forbidden: tuple[AnswerSelector, ...]
    distractors: tuple[AnswerSelector, ...]
    expect_empty: bool
    required_authorities: tuple[Authority, ...]
    review_note: str | None


@dataclass(frozen=True)
class RelationSpec:
    from_source_id: str
    from_record_ordinal: int
    to_source_id: str
    to_record_ordinal: int
    relation_type: str
    basis: str


@dataclass(frozen=True)
class SemanticProjectionEvaluationConfig:
    runtime: Path
    checkout: Path
    embedding_artifact: Path


def _new_result_rows() -> list[dict[str, Any]]:
    return []


def _new_source_counter() -> Counter[str]:
    return Counter()


@dataclass
class _WorksetTrack:
    retrieval_results: list[dict[str, Any]] = field(default_factory=_new_result_rows)
    security_results: list[dict[str, Any]] = field(default_factory=_new_result_rows)
    latencies: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    cpu_times: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    workset_bytes: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    word_proxies: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    citation_failures: int = 0
    evidence_failures: int = 0
    stale_current_returns: int = 0
    open_thread_role_failures: int = 0
    unjustified_duplicate_returns: int = 0
    source_counts: Counter[str] = field(default_factory=_new_source_counter)


@dataclass(frozen=True)
class _WorksetObservation:
    serialized_bytes: int
    content_word_proxy: int
    results: list[dict[str, Any]]
    selection: dict[str, Any]
    contract: dict[str, Any]
    citation_failures: int
    evidence_failures: int
    stale_current_returns: int
    open_thread_role_failures: int
    unjustified_duplicate_returns: int
    source_counts: Counter[str]


def freeze_evaluation_bundle(
    *,
    source_plan_path: Path,
    queries_path: Path,
    answers_path: Path,
    output: Path,
    answer_key_output: Path | None = None,
    gpg_recipient: str | None = None,
    require_split_ratio: bool = True,
) -> dict[str, Any]:
    """Create one immutable corpus bundle and optionally encrypt its answer key."""
    output = output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise ValueError(f"evaluation output already exists: {output}")
    if (answer_key_output is None) != (gpg_recipient is None):
        raise ValueError("answer_key_output and gpg_recipient must be provided together")
    if answer_key_output is not None:
        answer_key_output = answer_key_output.expanduser().resolve()
        if answer_key_output.exists() or answer_key_output.is_symlink():
            raise ValueError(f"answer key output already exists: {answer_key_output}")
        if _is_within(answer_key_output, output):
            raise ValueError("the encrypted answer key must be outside the corpus bundle")

    sources = _load_source_plan(source_plan_path)
    relation_specs = _load_relation_specs(source_plan_path)
    queries = _load_queries(queries_path)
    answers = _load_answers(answers_path)
    _validate_query_answers(queries, answers, require_split_ratio=require_split_ratio)

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.building-", dir=output.parent))
    answer_temporary: Path | None = None
    try:
        raw_root = temporary / "raw" / "sources"
        candidate_root = temporary / "candidate"
        evidence_root = candidate_root / "evidence" / "sha256"
        build_root = temporary / ".build"
        for directory in (raw_root, candidate_root, evidence_root, build_root):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        ledger = Ledger(Settings(build_root / "ledger"))
        source_entries: list[dict[str, Any]] = []
        documents: list[dict[str, Any]] = []
        selector_to_document: dict[tuple[str, int], str] = {}
        included_documents: set[str] = set()
        exclusion_counts: Counter[str] = Counter()

        for source in sources:
            suffix = source.path.suffix if source.path.suffix else ".jsonl"
            raw_relative = Path("raw") / "sources" / f"{source.source_id}{suffix}"
            copied = temporary / raw_relative
            copied_digest = _copy_regular_file(source.path, copied)
            if copied_digest != source.expected_sha256:
                raise ValueError(
                    f"source hash mismatch for {source.source_id}: "
                    f"expected {source.expected_sha256}, got {copied_digest}"
                )
            parsed = parse_file(
                copied,
                source.source_system,
                max_file_bytes=source.max_file_bytes,
            )
            canonical_path = f"/evaluation/sources/{source.source_id}{suffix}"
            report = ledger.ingest(
                parsed,
                source_account=source.source_account,
                scope=source.scope,
                project_id=source.project_id,
                source_path=canonical_path,
            )
            rows = _event_rows(ledger.settings.database_path, report.source_file_id)
            row_by_ordinal = {cast(int, row["record_ordinal"]): row for row in rows}
            per_source_exclusions: Counter[str] = Counter()

            for record in parsed.records:
                document_id = _document_id(
                    source.source_id, record.record_ordinal, record.raw_record
                )
                selector_to_document[(source.source_id, record.record_ordinal)] = document_id
                decision = classify_record(
                    source.source_system,
                    record.content_text,
                    record.raw_record,
                    max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                )
                if not decision.accepted:
                    exclusion_counts[decision.reason] += 1
                    per_source_exclusions[decision.reason] += 1
                    continue
                row = row_by_ordinal.get(record.record_ordinal)
                if row is None:
                    raise RuntimeError(
                        f"accepted record missing from shadow ledger: "
                        f"{source.source_id}:{record.record_ordinal}"
                    )
                object_id = cast(str, row["object_id"])
                object_digest = object_id.removeprefix("sha256:")
                evidence_relative = Path("evidence") / "sha256" / object_digest[:2] / object_digest
                source_object = ledger.settings.data_root / cast(str, row["object_path"])
                candidate_object = candidate_root / evidence_relative
                if not candidate_object.exists():
                    candidate_object.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    copied_object_digest = _copy_regular_file(source_object, candidate_object)
                    if copied_object_digest != object_digest:
                        raise RuntimeError(f"evidence copy hash mismatch: {object_id}")
                included_documents.add(document_id)
                documents.append(
                    {
                        "document_id": document_id,
                        "event_id": cast(str, row["event_id"]),
                        "source_id": source.source_id,
                        "source_system": source.source_system.value,
                        "conversation_id": cast(str, row["conversation_id"]),
                        "branch_id": cast(str | None, row["branch_id"]),
                        "record_ordinal": record.record_ordinal,
                        "actor_kind": cast(str, row["actor_kind"]),
                        "assistant": cast(str | None, row["assistant"]),
                        "authority": cast(str, row["authority"]),
                        "scope": source.scope.value,
                        "project_id": source.project_id,
                        "privacy": "included",
                        "occurred_at": cast(str | None, row["occurred_at"]),
                        "content_digest": cast(str, row["content_digest"]),
                        "content_text": cast(str, row["content_text"]),
                        "source_object_id": object_id,
                        "evidence_path": str(evidence_relative),
                        "byte_start": cast(int, row["byte_start"]),
                        "byte_end": cast(int, row["byte_end"]),
                    }
                )

            source_entries.append(
                {
                    "source_id": source.source_id,
                    "source_system": source.source_system.value,
                    "source_account": source.source_account,
                    "scope": source.scope.value,
                    "project_id": source.project_id,
                    "raw_path": str(raw_relative),
                    "canonical_source_path": canonical_path,
                    "origin_path_sha256": _sha256_text(str(source.path.resolve())),
                    "file_sha256": parsed.file_digest,
                    "file_size": parsed.file_size,
                    "max_file_bytes": source.max_file_bytes,
                    "parser_name": parsed.parser_name,
                    "parser_version": parsed.parser_version,
                    "conversation_id_digest": _sha256_text(parsed.conversation_id),
                    "record_count": len(parsed.records),
                    "included_count": len(rows),
                    "exclusions": dict(sorted(per_source_exclusions.items())),
                    "malformed_records": parsed.malformed_records,
                    "unknown_record_types": list(parsed.unknown_record_types),
                }
            )

        documents.sort(
            key=lambda item: (
                cast(str, item["source_id"]),
                cast(int, item["record_ordinal"]),
            )
        )
        _write_jsonl(candidate_root / "documents.jsonl", documents)
        _write_jsonl(candidate_root / "queries.jsonl", [item.as_dict() for item in queries])
        resolved_relations = _resolve_relations(
            relation_specs,
            selector_to_document,
            included_documents,
        )
        if resolved_relations:
            _write_jsonl(candidate_root / "relations.jsonl", resolved_relations)

        resolved_answers = _resolve_answers(
            queries,
            answers,
            selector_to_document,
            included_documents,
        )
        answer_key_bytes = _jsonl_bytes(resolved_answers)
        answer_key_sha256 = hashlib.sha256(answer_key_bytes).hexdigest()

        candidate_manifest = {
            "format_version": EVALUATION_FORMAT_VERSION,
            "corpus_kind": "admitted_normalized_events",
            "document_count": len(documents),
            "query_count": len(queries),
            "relation_count": len(resolved_relations),
            "source_systems": dict(
                sorted(Counter(item["source_system"] for item in documents).items())
            ),
            "exclusions": dict(sorted(exclusion_counts.items())),
            "files": _file_entries(candidate_root, exclude={"manifest.json"}),
        }
        _write_json(candidate_root / "manifest.json", candidate_manifest)

        shutil.rmtree(build_root)
        split_counts = Counter(item.split for item in queries)
        manifest = {
            "format_version": EVALUATION_FORMAT_VERSION,
            "created_at": _now(),
            "status": "frozen",
            "source_count": len(source_entries),
            "document_count": len(documents),
            "query_count": len(queries),
            "relation_count": len(resolved_relations),
            "split_counts": {
                name: split_counts[name] for name in QUERY_SPLITS if split_counts.get(name, 0)
            },
            "answer_key_plaintext_sha256": answer_key_sha256,
            "answer_key_storage": "separate_gpg" if answer_key_output else "not_written",
            "sources": source_entries,
            "files": _file_entries(temporary, exclude={"manifest.json"}),
        }
        _write_json(temporary / "manifest.json", manifest)

        if answer_key_output is not None and gpg_recipient is not None:
            answer_key_output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{answer_key_output.name}.",
                dir=answer_key_output.parent,
            )
            os.close(descriptor)
            answer_temporary = Path(temporary_name)
            answer_temporary.unlink()
            _encrypt_gpg(answer_key_bytes, answer_temporary, gpg_recipient)
            answer_temporary.chmod(0o400)

        _set_read_only_tree(temporary)
        result = verify_evaluation_bundle(temporary)
        if answer_temporary is not None and answer_key_output is not None:
            publish_file_no_replace(
                answer_temporary,
                answer_key_output,
                required_mode=0o400,
                label="encrypted evaluation answer key",
            )
            answer_temporary = None
        publish_directory_no_replace(
            temporary,
            output,
            required_mode=0o500,
            label="evaluation bundle",
        )

        result["bundle"] = str(output)
        result.update(
            {
                "answer_key_plaintext_sha256": answer_key_sha256,
                "answer_key_output": str(answer_key_output) if answer_key_output else None,
            }
        )
        return result
    except Exception:
        if temporary.exists():
            _make_writable(temporary)
            shutil.rmtree(temporary, ignore_errors=True)
        if answer_temporary is not None and answer_temporary.exists():
            answer_temporary.chmod(0o600)
            answer_temporary.unlink()
        raise


def verify_evaluation_bundle(bundle: Path) -> dict[str, Any]:
    supplied_bundle = bundle.expanduser()
    if supplied_bundle.is_symlink():
        raise ValueError(f"evaluation bundle must not be a symlink: {supplied_bundle}")
    bundle = supplied_bundle.resolve()
    manifest = _load_json_object(bundle / "manifest.json")
    if manifest.get("format_version") != EVALUATION_FORMAT_VERSION:
        raise ValueError("unsupported evaluation bundle format")
    _verify_file_entries(bundle, _require_list(manifest, "files"), excluded={"manifest.json"})
    candidate = bundle / "candidate"
    candidate_manifest = _load_json_object(candidate / "manifest.json")
    if candidate_manifest.get("format_version") != EVALUATION_FORMAT_VERSION:
        raise ValueError("unsupported candidate evaluation format")
    _verify_file_entries(
        candidate,
        _require_list(candidate_manifest, "files"),
        excluded={"manifest.json"},
    )
    relation_count = _optional_nonnegative_int(manifest, "relation_count")
    candidate_relation_count = _optional_nonnegative_int(candidate_manifest, "relation_count")
    relations_path = candidate / "relations.jsonl"
    observed_relation_count = len(_read_jsonl(relations_path)) if relations_path.exists() else 0
    if relation_count != candidate_relation_count or relation_count != observed_relation_count:
        raise ValueError("evaluation relation counts do not match")
    for path in (bundle, *bundle.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"evaluation bundle contains a symlink: {path}")
        if path.stat().st_mode & 0o222:
            raise ValueError(f"evaluation bundle is writable: {path}")
    if (candidate / "answers.jsonl").exists() or (candidate / "answer-key.jsonl").exists():
        raise ValueError("candidate directory contains an answer key")
    return {
        "status": "verified",
        "bundle": str(bundle),
        "manifest_sha256": _sha256_file(bundle / "manifest.json"),
        "candidate_manifest_sha256": _sha256_file(candidate / "manifest.json"),
        "source_count": _require_int(manifest, "source_count"),
        "document_count": _require_int(manifest, "document_count"),
        "query_count": _require_int(manifest, "query_count"),
        "relation_count": relation_count,
        "answer_key_plaintext_sha256": _require_str(manifest, "answer_key_plaintext_sha256"),
    }


def run_first_party_baseline(
    *,
    bundle: Path,
    output: Path,
    revision: str = FROZEN_BASELINE_REVISION,
) -> dict[str, Any]:
    bundle = bundle.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise ValueError(f"run output already exists: {output}")
    bundle_verification = verify_evaluation_bundle(bundle)
    repository = Path(__file__).resolve().parents[2]
    resolved_revision = _resolve_commit_revision(repository, revision, label="baseline")
    baseline_hashes = _verify_baseline_revision(repository, resolved_revision)
    publication_id = str(uuid.uuid4())

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.running-", dir=output.parent))
    try:
        for directory in (temporary / "config", temporary / "logs", temporary / "receipts"):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        manifest = _load_json_object(bundle / "manifest.json")
        sources = _require_list(manifest, "sources")
        queries = _load_queries(bundle / "candidate" / "queries.jsonl")
        documents = _read_jsonl(bundle / "candidate" / "documents.jsonl")
        document_by_event = {
            _require_str(item, "event_id"): _require_str(item, "document_id") for item in documents
        }

        settings = Settings(temporary / "index")
        ledger = Ledger(settings)
        ingestion_started = time.perf_counter()
        ingestion_log: list[dict[str, Any]] = []
        for raw_source in sources:
            source_system = SourceSystem(_require_str(raw_source, "source_system"))
            raw_path = _verified_bundle_source(bundle, manifest, raw_source)
            parsed = parse_file(
                raw_path,
                source_system,
                max_file_bytes=_require_int(raw_source, "max_file_bytes"),
            )
            report = ledger.ingest(
                parsed,
                source_account=_require_str(raw_source, "source_account"),
                scope=Scope(_require_str(raw_source, "scope")),
                project_id=_optional_str(raw_source.get("project_id")),
                source_path=_require_str(raw_source, "canonical_source_path"),
            )
            ingestion_log.append(
                {
                    "source_id": _require_str(raw_source, "source_id"),
                    "status": report.status,
                    "inserted_events": report.inserted_events,
                    "quarantined_records": report.quarantined_records,
                    "quarantine_reasons": report.quarantine_reasons,
                }
            )
        ingestion_seconds = time.perf_counter() - ingestion_started
        _write_jsonl(temporary / "logs" / "ingestion.jsonl", ingestion_log)

        retrieval_results: list[dict[str, Any]] = []
        latencies: dict[str, list[float]] = defaultdict(list)
        for trial, phase in enumerate(("cold", "warm"), start=1):
            for query in queries:
                started = time.perf_counter()
                try:
                    search_results = ledger.search(
                        query.query,
                        mode=query.mode,
                        scopes=query.scopes,
                        project_id=query.project_id,
                        authorities=query.authorities or None,
                        limit=query.limit,
                        principal="evaluation:first-party",
                    )
                    latency_ms = (time.perf_counter() - started) * 1000
                    normalized_results: list[dict[str, Any]] = []
                    for rank, item in enumerate(search_results, start=1):
                        document_id = document_by_event.get(item.event_id)
                        if document_id is None:
                            raise RuntimeError(
                                "baseline returned an event outside the frozen corpus: "
                                f"{item.event_id}"
                            )
                        evidence = ledger.get_evidence(item.event_id)
                        raw_record = _require_str(evidence, "raw_record").encode()
                        evidence_verified = (
                            f"sha256:{hashlib.sha256(raw_record).hexdigest()}"
                            == item.source_object_id
                        )
                        normalized_results.append(
                            {
                                "rank": rank,
                                "document_id": document_id,
                                "event_id": item.event_id,
                                "authority": item.authority,
                                "scope": item.scope,
                                "project_id": item.project_id,
                                "source_object_id": item.source_object_id,
                                "record_ordinal": item.record_ordinal,
                                "evidence_verified": evidence_verified,
                            }
                        )
                    status = "ok"
                    error = None
                except ValueError as exc:
                    latency_ms = (time.perf_counter() - started) * 1000
                    normalized_results = []
                    status = "unsupported" if "not implemented" in str(exc) else "error"
                    error = str(exc)
                latencies[phase].append(latency_ms)
                retrieval_results.append(
                    {
                        "query_id": query.query_id,
                        "split": query.split,
                        "suite": query.suite,
                        "trial": trial,
                        "phase": phase,
                        "status": status,
                        "error": error,
                        "latency_ms": round(latency_ms, 6),
                        "results": normalized_results,
                    }
                )

        _write_jsonl(temporary / "retrieval-results.jsonl", retrieval_results)
        _write_jsonl(temporary / "answer-results.jsonl", [])
        _write_jsonl(temporary / "security-results.jsonl", [])
        _checkpoint_evaluation_database(settings.database_path)
        config = {
            "candidate": "first-party-sqlite-fts5",
            "candidate_revision": resolved_revision,
            "baseline_paths": baseline_hashes,
            "query_trials": 2,
            "phases": ["cold", "warm"],
            "answer_generation": False,
            "internet_used_during_retrieval": False,
        }
        _write_json(temporary / "config" / "baseline.json", config)
        environment = {
            "captured_at": _now(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "pid": os.getpid(),
        }
        _write_json(temporary / "environment.json", environment)
        metrics = {
            "status": "retrieval_only_unscored",
            "ingestion_seconds": round(ingestion_seconds, 6),
            "source_count": len(sources),
            "document_count": len(documents),
            "query_count": len(queries),
            "cold_latency_ms": _latency_summary(latencies["cold"]),
            "warm_latency_ms": _latency_summary(latencies["warm"]),
            "peak_rss_bytes": _peak_rss_bytes(),
            "index_bytes": _directory_bytes(settings.data_root),
            "unsupported_results": sum(
                1 for item in retrieval_results if item["status"] == "unsupported"
            ),
        }
        _write_json(temporary / "metrics.json", metrics)
        (temporary / "report.md").write_text(
            "# First-Party Retrieval Run\n\n"
            "Status: retrieval-only, unscored\n\n"
            "This run rebuilt an empty shadow ledger from the frozen raw corpus, "
            "executed cold and warm retrieval passes, and verified every returned "
            "evidence object. The answer key was not available to this process.\n",
            encoding="utf-8",
        )
        run_manifest = {
            "format_version": EVALUATION_FORMAT_VERSION,
            "run_id": output.name,
            "created_at": _now(),
            "publication_id": publication_id,
            "candidate": "first-party-sqlite-fts5",
            "candidate_revision": resolved_revision,
            "corpus_manifest_sha256": bundle_verification["manifest_sha256"],
            "candidate_manifest_sha256": bundle_verification["candidate_manifest_sha256"],
            "answer_key_plaintext_sha256": bundle_verification["answer_key_plaintext_sha256"],
            "config_sha256": _sha256_file(temporary / "config" / "baseline.json"),
            "files": _file_entries(temporary, exclude={"manifest.json"}),
        }
        _write_json(temporary / "manifest.json", run_manifest)
        _publish_evaluation_output(temporary, output)
        return {
            "status": "completed_unscored",
            "run": str(output),
            "manifest_sha256": _sha256_file(output / "manifest.json"),
            "metrics": metrics,
        }
    except Exception:
        if temporary.exists():
            _make_writable(temporary)
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def run_first_party_workset_evaluation(
    *,
    bundle: Path,
    output: Path,
    revision: str = FROZEN_WORKSET_REVISION,
    harness_revision: str | None = None,
) -> dict[str, Any]:
    return _run_workset_evaluation(
        bundle=bundle,
        output=output,
        revision=revision,
        harness_revision=harness_revision,
        semantic_projection=None,
    )


def run_semantic_workset_evaluation(
    *,
    bundle: Path,
    output: Path,
    runtime: Path,
    checkout: Path,
    embedding_artifact: Path,
    revision: str,
    harness_revision: str | None = None,
) -> dict[str, Any]:
    return _run_workset_evaluation(
        bundle=bundle,
        output=output,
        revision=revision,
        harness_revision=harness_revision,
        semantic_projection=SemanticProjectionEvaluationConfig(
            runtime=runtime,
            checkout=checkout,
            embedding_artifact=embedding_artifact,
        ),
    )


def _run_workset_evaluation(
    *,
    bundle: Path,
    output: Path,
    revision: str,
    harness_revision: str | None,
    semantic_projection: SemanticProjectionEvaluationConfig | None,
) -> dict[str, Any]:
    bundle = bundle.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise ValueError(f"run output already exists: {output}")
    bundle_verification = verify_evaluation_bundle(bundle)
    repository = Path(__file__).resolve().parents[2]
    resolved_revision = _resolve_commit_revision(repository, revision, label="baseline")
    baseline_hashes = _verify_baseline_revision(
        repository,
        resolved_revision,
        paths=(
            SEMANTIC_PROJECTION_PATHS if semantic_projection is not None else WORKSET_BASELINE_PATHS
        ),
    )
    requested_harness_revision = harness_revision or _repository_head(repository)
    resolved_harness_revision = _resolve_commit_revision(
        repository,
        requested_harness_revision,
        label="evaluation harness",
    )
    harness_hashes = _verify_baseline_revision(
        repository,
        resolved_harness_revision,
        paths=WORKSET_HARNESS_PATHS,
        label="evaluation harness",
    )
    publication_id = str(uuid.uuid4())
    projection_scratch: Path | None = None

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.running-", dir=output.parent))
    try:
        for directory in (temporary / "config", temporary / "logs", temporary / "receipts"):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        manifest = _load_json_object(bundle / "manifest.json")
        sources = _require_list(manifest, "sources")
        queries = _load_queries(bundle / "candidate" / "queries.jsonl")
        documents = _read_jsonl(bundle / "candidate" / "documents.jsonl")
        frozen_document_by_id = {_require_str(item, "document_id"): item for item in documents}
        if len(frozen_document_by_id) != len(documents):
            raise ValueError("frozen corpus contains duplicate document ids")
        document_by_selector = {
            (_require_str(item, "source_id"), _require_int(item, "record_ordinal")): _require_str(
                item, "document_id"
            )
            for item in documents
        }
        if len(document_by_selector) != len(documents):
            raise ValueError("frozen corpus contains duplicate source record selectors")
        document_by_event: dict[str, str] = {}
        event_by_document: dict[str, str] = {}

        settings = Settings(temporary / "index")
        ledger = Ledger(settings)
        ingestion_started = time.perf_counter()
        ingestion_cpu_started = time.process_time()
        ingestion_log: list[dict[str, Any]] = []
        for raw_source in sources:
            source_system = SourceSystem(_require_str(raw_source, "source_system"))
            raw_path = _verified_bundle_source(bundle, manifest, raw_source)
            parsed = parse_file(
                raw_path,
                source_system,
                max_file_bytes=_require_int(raw_source, "max_file_bytes"),
            )
            report = ledger.ingest(
                parsed,
                source_account=_require_str(raw_source, "source_account"),
                scope=Scope(_require_str(raw_source, "scope")),
                project_id=_optional_str(raw_source.get("project_id")),
                source_path=_require_str(raw_source, "canonical_source_path"),
            )
            source_id = _require_str(raw_source, "source_id")
            for row in _event_rows(settings.database_path, report.source_file_id):
                selector = (source_id, cast(int, row["record_ordinal"]))
                document_id = document_by_selector.get(selector)
                if document_id is None:
                    raise RuntimeError(
                        "rebuilt ledger returned an event outside the frozen corpus: "
                        f"{source_id}:{selector[1]}"
                    )
                event_id = cast(str, row["event_id"])
                frozen_document = frozen_document_by_id[document_id]
                if event_id != _require_str(frozen_document, "event_id"):
                    raise RuntimeError(
                        f"rebuilt ledger changed a stable evidence id: {source_id}:{selector[1]}"
                    )
                document_by_event[event_id] = document_id
                event_by_document[document_id] = event_id
            ingestion_log.append(
                {
                    "source_id": _require_str(raw_source, "source_id"),
                    "status": report.status,
                    "inserted_events": report.inserted_events,
                    "quarantined_records": report.quarantined_records,
                    "quarantine_reasons": report.quarantine_reasons,
                }
            )
        if len(document_by_event) != len(documents) or len(event_by_document) != len(documents):
            raise RuntimeError("rebuilt ledger does not match the frozen candidate documents")
        ingestion_seconds = time.perf_counter() - ingestion_started
        ingestion_cpu_seconds = time.process_time() - ingestion_cpu_started
        _write_jsonl(temporary / "logs" / "ingestion.jsonl", ingestion_log)
        relations_path = bundle / "candidate" / "relations.jsonl"
        relation_count = _install_frozen_relations(
            database_path=settings.database_path,
            relations_path=relations_path,
            event_by_document=event_by_document,
        )
        frozen_relation_rows = _read_jsonl(relations_path) if relations_path.exists() else []
        frozen_superseded_ids = {
            event_by_document[_require_str(relation, "from_document_id")]
            for relation in frozen_relation_rows
            if _require_str(relation, "relation_type") in {"correction", "supersession"}
        }
        if semantic_projection is not None:
            _checkpoint_evaluation_database(settings.database_path)

        baseline_track = _WorksetTrack()
        semantic_track = _WorksetTrack() if semantic_projection is not None else None
        projection_root: Path | None = None
        projection_summary: dict[str, Any] | None = None
        if semantic_projection is not None:
            from cross_assistant_memory.projection import (
                build_shadow_projection,
                verify_shadow_projection,
            )

            projection_scratch = Path(
                tempfile.mkdtemp(prefix="cam-evaluation-projection-", dir="/private/tmp")
            )
            projection_root = projection_scratch / "projection"
            built = build_shadow_projection(
                settings,
                runtime=semantic_projection.runtime,
                checkout=semantic_projection.checkout,
                projection_root=projection_root,
                execute=True,
                embedding_artifact=semantic_projection.embedding_artifact,
            )
            verified = verify_shadow_projection(
                settings,
                runtime=semantic_projection.runtime,
                checkout=semantic_projection.checkout,
                projection_root=projection_root,
                embedding_artifact=semantic_projection.embedding_artifact,
            )
            if built["manifest_sha256"] != verified["manifest_sha256"]:
                raise EvaluationIntegrityError("semantic projection build verification changed")
            projection_summary = {
                "candidate": verified["candidate"],
                "candidate_revision": verified["candidate_revision"],
                "candidate_attestation": verified["candidate_attestation"],
                "retrieval_mode": verified["retrieval_mode"],
                "manifest_sha256": verified["manifest_sha256"],
                "ledger_generation_digest": verified["ledger_generation_digest"],
                "document_count": verified["document_count"],
                "embedding_artifact": _without_local_artifact_path(
                    _require_object(verified, "embedding_artifact")
                ),
                "embedding_runtime": verified["embedding_runtime"],
                "worker_sha256": verified["worker_sha256"],
                "sandbox": verified["sandbox"],
                "files": verified["files"],
                "build_seconds": built["build_seconds"],
            }
            generation_path = Path(_require_str(verified, "generation_path"))
            verified_projection_files = {
                _require_str(item, "path"): _require_str(item, "sha256")
                for item in _require_list(verified, "files")
            }
            preserved_projection_files: dict[str, str] = {}
            for source_relative, output_name in (
                ("manifest.json", "projection-manifest.json"),
                ("receipts/build.json", "projection-build.json"),
                ("receipts/sandbox.json", "projection-sandbox.json"),
            ):
                output_path = temporary / "receipts" / output_name
                expected_digest = (
                    _require_str(verified, "manifest_sha256")
                    if source_relative == "manifest.json"
                    else verified_projection_files.get(source_relative)
                )
                if expected_digest is None:
                    raise EvaluationIntegrityError(
                        f"verified projection omitted receipt: {source_relative}"
                    )
                preserved_projection_files[output_name] = _copy_regular_file(
                    generation_path / source_relative,
                    output_path,
                    expected_sha256=expected_digest,
                )
            projection_summary["preserved_receipts"] = preserved_projection_files
            _write_json(temporary / "receipts" / "projection.json", projection_summary)

        for trial, phase in enumerate(("cold", "warm"), start=1):
            for query in queries:
                baseline_workset = _record_workset_attempt(
                    track=baseline_track,
                    ledger=ledger,
                    query=query,
                    trial=trial,
                    phase=phase,
                    candidate_kind="raw_fts_baseline",
                    load_workset=lambda query=query: (
                        ledger.retrieve_workset(
                            query.query,
                            mode=query.mode,
                            scopes=query.scopes,
                            contexts=query.contexts,
                            project_id=query.project_id,
                            authorities=query.authorities or None,
                            accesses=(Access.OWNER,),
                            limit=query.limit,
                            control=RetrievalControl.FORCE,
                            principal="evaluation:raw-fts-workset",
                        ),
                        {"candidate_id": "first-party-sqlite-fts5"},
                    ),
                    document_by_event=document_by_event,
                    frozen_document_by_id=frozen_document_by_id,
                    frozen_superseded_ids=frozen_superseded_ids,
                )
                if semantic_projection is not None:
                    if semantic_track is None or projection_root is None:
                        raise AssertionError("semantic evaluation state is incomplete")

                    def load_semantic_workset(
                        query: EvaluationQuery = query,
                        baseline_workset: dict[str, Any] | None = baseline_workset,
                    ) -> tuple[dict[str, Any], dict[str, Any]]:
                        from cross_assistant_memory.projection import search_shadow_projection

                        comparison = search_shadow_projection(
                            settings,
                            query.query,
                            runtime=semantic_projection.runtime,
                            checkout=semantic_projection.checkout,
                            projection_root=projection_root,
                            mode=query.mode,
                            scopes=list(query.scopes),
                            contexts=query.contexts,
                            project_id=query.project_id,
                            authorities=list(query.authorities) or None,
                            accesses=[Access.OWNER],
                            limit=query.limit,
                            control=RetrievalControl.FORCE,
                            principal="evaluation:semantic-shadow-workset",
                            embedding_artifact=semantic_projection.embedding_artifact,
                        )
                        compared_baseline = _require_object(
                            _require_object(comparison, "baseline"), "workset"
                        )
                        if baseline_workset is None or compared_baseline != baseline_workset:
                            raise EvaluationIntegrityError(
                                "semantic comparison embedded raw FTS workset differed from the "
                                "direct raw FTS workset"
                            )
                        candidate = _require_object(comparison, "candidate")
                        candidate_workset = _require_object(candidate, "workset")
                        return candidate_workset, {
                            "candidate_id": _require_str(candidate, "id"),
                            "candidate_status": _require_str(comparison, "status"),
                            "retrieval_mode": _require_str(candidate, "retrieval_mode"),
                            "raw_hit_count": _require_int(candidate, "raw_hit_count"),
                            "abstention": _require_object(comparison, "abstention"),
                            "raw_fts_baseline_verified": True,
                            "comparison_timing_ms": _require_object(comparison, "timing_ms"),
                            "worker_resource_usage": _require_object(
                                candidate, "worker_resource_usage"
                            ),
                        }

                    _record_workset_attempt(
                        track=semantic_track,
                        ledger=ledger,
                        query=query,
                        trial=trial,
                        phase=phase,
                        candidate_kind="optional_semantic_projection",
                        load_workset=load_semantic_workset,
                        document_by_event=document_by_event,
                        frozen_document_by_id=frozen_document_by_id,
                        frozen_superseded_ids=frozen_superseded_ids,
                    )

        retrieval_results = (
            semantic_track.retrieval_results
            if semantic_track is not None
            else baseline_track.retrieval_results
        )
        security_results = (
            semantic_track.security_results
            if semantic_track is not None
            else baseline_track.security_results
        )

        _write_jsonl(temporary / "retrieval-results.jsonl", retrieval_results)
        _write_jsonl(temporary / "answer-results.jsonl", [])
        _write_jsonl(temporary / "security-results.jsonl", security_results)
        if semantic_track is not None:
            _write_jsonl(
                temporary / "baseline-results.jsonl",
                baseline_track.retrieval_results,
            )
            _write_jsonl(
                temporary / "baseline-security-results.jsonl",
                baseline_track.security_results,
            )
        receipts = _read_query_receipts(settings.database_path)
        _write_jsonl(temporary / "receipts" / "query-receipts.jsonl", receipts)
        projection_bytes = 0
        if projection_root is not None:
            projection_bytes = _directory_bytes(projection_root)
            _make_writable(projection_root)
            shutil.rmtree(projection_root)
        if projection_scratch is not None:
            projection_scratch.rmdir()
            projection_scratch = None
        _checkpoint_evaluation_database(settings.database_path)
        index_bytes = _directory_bytes(settings.data_root)
        shutil.rmtree(settings.data_root)
        candidate_name = (
            "first-party-source-aware-semantic-shadow-workset"
            if semantic_track is not None
            else "first-party-source-aware-fts5-workset"
        )
        config = {
            "candidate": candidate_name,
            "candidate_revision": resolved_revision,
            "baseline_paths": baseline_hashes,
            "evaluation_harness_revision": resolved_harness_revision,
            "evaluation_harness_paths": harness_hashes,
            "query_trials": 2,
            "phases": ["cold", "warm"],
            "access": [Access.OWNER.value],
            "retrieval_control": RetrievalControl.FORCE.value,
            "answer_generation": False,
            "internet_used_during_retrieval": False,
            "candidate_generation": (
                "mempalace_local_onnx_embeddings"
                if semantic_track is not None
                else "sqlite_fts5_match"
            ),
            "candidate_ranking": (
                "cosine_similarity" if semantic_track is not None else "content_local_lexical_score"
            ),
            "optional_projection": projection_summary or "disabled",
        }
        _write_json(temporary / "config" / "workset.json", config)
        environment = {
            "captured_at": _now(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "pid": os.getpid(),
        }
        _write_json(temporary / "environment.json", environment)
        primary_track = semantic_track or baseline_track
        primary_error_count = _track_error_count(primary_track)
        baseline_error_count = _track_error_count(baseline_track)
        comparison_failed = primary_error_count > 0 or baseline_error_count > 0
        run_status = "failed_unscored" if comparison_failed else "completed_unscored"
        metrics: dict[str, Any] = {
            "status": ("retrieval_only_failed" if comparison_failed else "retrieval_only_unscored"),
            "ingestion_seconds": round(ingestion_seconds, 6),
            "ingestion_cpu_seconds": round(ingestion_cpu_seconds, 6),
            "source_count": len(sources),
            "document_count": len(documents),
            "relation_count": relation_count,
            "query_count": len(queries),
            "peak_parent_rss_bytes": _peak_rss_bytes(resource.RUSAGE_SELF),
            "peak_child_rss_bytes": _peak_rss_bytes(resource.RUSAGE_CHILDREN),
            "index_bytes": index_bytes,
            "projection_bytes": projection_bytes,
            "query_receipt_count": len(receipts),
            **_workset_track_metrics(primary_track),
        }
        if semantic_track is not None:
            metrics["raw_fts_baseline"] = _workset_track_metrics(baseline_track)
            metrics["optional_semantic_projection"] = _workset_track_metrics(semantic_track)
        _write_json(temporary / "metrics.json", metrics)
        if semantic_track is not None and not comparison_failed:
            projection_report = (
                "The optional local semantic projection ran in shadow mode. Every query also "
                "returned a raw SQLite FTS workset, and that embedded FTS workset exactly matched "
                "an independently executed raw FTS request. The semantic arm remains "
                "uncalibrated and cannot be accepted for normal retrieval from this run alone. "
            )
        elif semantic_track is not None:
            projection_report = (
                "The optional semantic comparison recorded one or more failed attempts. It is a "
                "failed run and does not establish raw FTS parity or candidate quality. "
            )
        else:
            projection_report = "Raw SQLite FTS was the only retrieval candidate. "
        (temporary / "report.md").write_text(
            "# First-Party Evidence Workset Run\n\n"
            f"Status: {run_status.replace('_', '-')}\n\n"
            "This run rebuilt an empty ledger from the frozen corpus, installed only "
            "candidate-visible evidence relations, and executed cold and warm source-aware "
            "worksets. Persisted result rows contain no transcript text. Each returned citation "
            "and exact source object was verified. "
            + projection_report
            + "No answer model ran. The word count is a labeled transport "
            "proxy, not a model-token claim.\n\n"
            "The legacy metric `unjustified_same_source_duplicate_returns_all_trials` counts "
            "returns after the first occurrence of each event ID within each workset, summed "
            "across trials. Distinct events with equal text are not duplicates; relation "
            "endpoints are not exempt from repeated-event detection.\n\n"
            "The hostile-text case checks only the retrieval output contract. No answer model "
            "ran, so instruction execution was not exercised.\n",
            encoding="utf-8",
        )
        run_manifest = {
            "format_version": EVALUATION_FORMAT_VERSION,
            "run_id": output.name,
            "created_at": _now(),
            "publication_id": publication_id,
            "candidate": candidate_name,
            "result_kind": (
                "evidence_workset_comparison" if semantic_track is not None else "evidence_workset"
            ),
            "candidate_revision": resolved_revision,
            "evaluation_harness_revision": resolved_harness_revision,
            "evaluation_harness_paths": harness_hashes,
            "corpus_manifest_sha256": bundle_verification["manifest_sha256"],
            "candidate_manifest_sha256": bundle_verification["candidate_manifest_sha256"],
            "answer_key_plaintext_sha256": bundle_verification["answer_key_plaintext_sha256"],
            "config_sha256": _sha256_file(temporary / "config" / "workset.json"),
            "files": _file_entries(temporary, exclude={"manifest.json"}),
        }
        _write_json(temporary / "manifest.json", run_manifest)
        _publish_evaluation_output(temporary, output)
        return {
            "status": run_status,
            "run": str(output),
            "manifest_sha256": _sha256_file(output / "manifest.json"),
            "metrics": metrics,
        }
    except Exception:
        if projection_scratch is not None and projection_scratch.exists():
            _make_writable(projection_scratch)
            shutil.rmtree(projection_scratch, ignore_errors=True)
        if temporary.exists():
            _make_writable(temporary)
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def _record_workset_attempt(
    *,
    track: _WorksetTrack,
    ledger: Ledger,
    query: EvaluationQuery,
    trial: int,
    phase: str,
    candidate_kind: str,
    load_workset: Callable[[], tuple[dict[str, Any], dict[str, Any]]],
    document_by_event: dict[str, str],
    frozen_document_by_id: dict[str, dict[str, Any]],
    frozen_superseded_ids: set[str],
) -> dict[str, Any] | None:
    started = time.perf_counter()
    cpu_started = _cpu_seconds(include_children=True)
    workset: dict[str, Any] | None = None
    metadata: dict[str, Any] = {}
    try:
        workset, metadata = load_workset()
        observation = _evaluate_workset_output(
            ledger=ledger,
            query=query,
            workset=workset,
            document_by_event=document_by_event,
            frozen_document_by_id=frozen_document_by_id,
            frozen_superseded_ids=frozen_superseded_ids,
        )
        status = "ok"
        error = None
    except EvaluationIntegrityError:
        raise
    except (KeyError, RuntimeError, ValueError) as exc:
        observation = _WorksetObservation(
            serialized_bytes=0,
            content_word_proxy=0,
            results=[],
            selection={},
            contract={},
            citation_failures=0,
            evidence_failures=0,
            stale_current_returns=0,
            open_thread_role_failures=0,
            unjustified_duplicate_returns=0,
            source_counts=Counter(),
        )
        status = "error"
        error = str(exc)
        workset = None
        metadata = {}
    latency_ms = (time.perf_counter() - started) * 1000
    cpu_ms = (_cpu_seconds(include_children=True) - cpu_started) * 1000
    track.latencies[phase].append(latency_ms)
    track.cpu_times[phase].append(cpu_ms)
    track.workset_bytes[phase].append(float(observation.serialized_bytes))
    track.word_proxies[phase].append(float(observation.content_word_proxy))
    track.citation_failures += observation.citation_failures
    track.evidence_failures += observation.evidence_failures
    track.stale_current_returns += observation.stale_current_returns
    track.open_thread_role_failures += observation.open_thread_role_failures
    track.unjustified_duplicate_returns += observation.unjustified_duplicate_returns
    track.source_counts.update(observation.source_counts)
    track.retrieval_results.append(
        {
            "query_id": query.query_id,
            "split": query.split,
            "suite": query.suite,
            "query_mode": query.mode.value,
            "trial": trial,
            "phase": phase,
            "candidate_kind": candidate_kind,
            "status": status,
            "error": error,
            "latency_ms": round(latency_ms, 6),
            "cpu_ms": round(cpu_ms, 6),
            "serialized_workset_utf8_bytes": observation.serialized_bytes,
            "content_word_token_proxy": observation.content_word_proxy,
            "workset_contract": observation.contract,
            "selection": observation.selection,
            "results": observation.results,
            **metadata,
        }
    )
    if query.suite == "security":
        boundary_ok = observation.contract == {
            "answer_generation": False,
            "content_boundary": "retrieved_content_is_untrusted_data",
        }
        track.security_results.append(
            {
                "query_id": query.query_id,
                "trial": trial,
                "phase": phase,
                "candidate_kind": candidate_kind,
                "status": (
                    "contract_shape_pass"
                    if status == "ok" and boundary_ok
                    else "contract_shape_fail"
                ),
                "answer_generation": observation.contract.get("answer_generation"),
                "content_boundary": observation.contract.get("content_boundary"),
            }
        )
    return workset


def _evaluate_workset_output(
    *,
    ledger: Ledger,
    query: EvaluationQuery,
    workset: dict[str, Any],
    document_by_event: dict[str, str],
    frozen_document_by_id: dict[str, dict[str, Any]],
    frozen_superseded_ids: set[str],
) -> _WorksetObservation:
    serialized_bytes = len(json.dumps(workset, separators=(",", ":"), sort_keys=True).encode())
    content_word_proxy = sum(
        len(_require_str(item, "content_text").split())
        for item in _require_object_list(workset, "results")
    )
    normalized_results: list[dict[str, Any]] = []
    returned_event_ids: set[str] = set()
    citation_failures = 0
    evidence_failures = 0
    stale_current_returns = 0
    open_thread_role_failures = 0
    unjustified_duplicate_returns = 0
    source_counts: Counter[str] = Counter()
    for rank, item in enumerate(_require_object_list(workset, "results"), start=1):
        event_id = _require_str(item, "event_id")
        document_id = document_by_event.get(event_id)
        if document_id is None:
            raise EvaluationIntegrityError(
                f"workset returned an event outside the frozen corpus: {event_id}"
            )
        evidence = ledger.get_evidence(event_id)
        raw_record = _require_str(evidence, "raw_record").encode()
        frozen_document = frozen_document_by_id[document_id]
        expected_source_object_id = _require_str(frozen_document, "source_object_id")
        evidence_verified = (
            f"sha256:{hashlib.sha256(raw_record).hexdigest()}" == expected_source_object_id
        )
        expected_citation = {
            "evidence_id": _require_str(frozen_document, "event_id"),
            "source": _require_str(frozen_document, "source_system"),
            "conversation": _require_str(frozen_document, "conversation_id"),
            "date": frozen_document.get("occurred_at"),
        }
        citation = _require_object(item, "citation")
        citation_verified = citation == expected_citation
        _verify_workset_item_metadata(
            item,
            frozen_document=frozen_document,
            expected_source_object_id=expected_source_object_id,
            query=query.query,
        )
        roles = _require_string_list(item, "workset_roles")
        relations = _require_object_list(item, "relations")
        if not citation_verified:
            raise EvaluationIntegrityError(
                f"workset citation differs from frozen evidence: {document_id}"
            )
        if not evidence_verified:
            raise EvaluationIntegrityError(
                f"workset evidence hash differs from frozen evidence: {document_id}"
            )
        citation_failures += int(not citation_verified)
        evidence_failures += int(not evidence_verified)
        source_counts[_require_str(item, "source_system")] += 1
        stale_current_returns += int(
            _is_stale_current_return(query.mode, event_id, frozen_superseded_ids)
        )
        if query.mode is QueryMode.OPEN_THREADS:
            expected_role = _expected_open_thread_role(frozen_document)
            open_thread_role_failures += int(
                set(roles) & {"user_statement", "assistant_suggestion", "tool_observation"}
                != {expected_role}
            )
        if _is_unjustified_duplicate_return(event_id, returned_event_ids):
            unjustified_duplicate_returns += 1
        returned_event_ids.add(event_id)
        candidate_score = item.get("rank")
        if (
            isinstance(candidate_score, bool)
            or not isinstance(candidate_score, (int, float))
            or not math.isfinite(candidate_score)
        ):
            raise EvaluationIntegrityError("workset candidate score is not finite")
        normalized_results.append(
            {
                "rank": rank,
                "candidate_score": float(candidate_score),
                "document_id": document_id,
                "event_id": event_id,
                "source_system": _require_str(item, "source_system"),
                "actor_kind": _require_str(item, "actor_kind"),
                "assistant": item.get("assistant"),
                "authority": _require_str(item, "authority"),
                "scope": _require_str(item, "scope"),
                "project_id": item.get("project_id"),
                "source_object_id": _require_str(item, "source_object_id"),
                "record_ordinal": _require_int(item, "record_ordinal"),
                "candidate_rank": item.get("candidate_rank"),
                "selection_origin": _require_str(item, "selection_origin"),
                "workset_roles": roles,
                "citation": citation,
                "relations": relations,
                "citation_verified": citation_verified,
                "evidence_verified": evidence_verified,
            }
        )
    return _WorksetObservation(
        serialized_bytes=serialized_bytes,
        content_word_proxy=content_word_proxy,
        results=normalized_results,
        selection=_require_object(workset, "selection"),
        contract={
            "answer_generation": workset.get("answer_generation"),
            "content_boundary": workset.get("content_boundary"),
        },
        citation_failures=citation_failures,
        evidence_failures=evidence_failures,
        stale_current_returns=stale_current_returns,
        open_thread_role_failures=open_thread_role_failures,
        unjustified_duplicate_returns=unjustified_duplicate_returns,
        source_counts=source_counts,
    )


def _workset_track_metrics(track: _WorksetTrack) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "cold_latency_ms": _latency_summary(track.latencies["cold"]),
        "warm_latency_ms": _latency_summary(track.latencies["warm"]),
        "cold_cpu_ms": _latency_summary(track.cpu_times["cold"]),
        "warm_cpu_ms": _latency_summary(track.cpu_times["warm"]),
        "error_results": _track_error_count(track),
        "citation_failures": track.citation_failures,
        "evidence_hash_failures": track.evidence_failures,
        "stale_current_returns": track.stale_current_returns,
        "open_thread_role_failures": track.open_thread_role_failures,
        # Legacy key: repeated event IDs within each workset, not equal source text.
        "unjustified_same_source_duplicate_returns_all_trials": (
            track.unjustified_duplicate_returns
        ),
        "returned_items_by_source_all_trials": dict(sorted(track.source_counts.items())),
        "serialized_workset_utf8_bytes": {
            "cold": _latency_summary(track.workset_bytes["cold"]),
            "warm": _latency_summary(track.workset_bytes["warm"]),
        },
        "content_word_token_proxy": {
            "status": "proxy_only_model_tokenizer_not_selected",
            "cold": _latency_summary(track.word_proxies["cold"]),
            "warm": _latency_summary(track.word_proxies["warm"]),
        },
        "security_contract_shape_failures": sum(
            1 for item in track.security_results if item["status"] != "contract_shape_pass"
        ),
    }
    comparison_timings = [
        cast(dict[str, Any], item["comparison_timing_ms"])
        for item in track.retrieval_results
        if isinstance(item.get("comparison_timing_ms"), dict)
    ]
    if comparison_timings:
        metrics["comparison_timing_ms"] = {
            key: _latency_summary(
                [
                    float(value)
                    for item in comparison_timings
                    if isinstance((value := item.get(key)), (int, float))
                    and not isinstance(value, bool)
                    and math.isfinite(float(value))
                ]
            )
            for key in (
                "raw_fts_baseline",
                "projection_verification",
                "candidate_execution",
                "total",
            )
        }
        metrics["raw_fts_baseline_parity_failures"] = sum(
            1
            for item in track.retrieval_results
            if item.get("status") != "ok" or item.get("raw_fts_baseline_verified") is not True
        )
    worker_usage = [
        cast(dict[str, Any], item["worker_resource_usage"])
        for item in track.retrieval_results
        if isinstance(item.get("worker_resource_usage"), dict)
    ]
    if worker_usage:
        metrics["worker_resource_usage"] = {
            "cpu_ms": _latency_summary(
                [float(_require_int(item, "cpu_ms")) for item in worker_usage]
            ),
            "peak_rss_bytes": _latency_summary(
                [float(_require_int(item, "peak_rss_bytes")) for item in worker_usage]
            ),
        }
    return metrics


def _track_error_count(track: _WorksetTrack) -> int:
    return sum(1 for item in track.retrieval_results if item.get("status") != "ok")


def _without_local_artifact_path(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"artifact_root", "status"}}


def score_retrieval_run(*, run: Path, answer_key: TextIO) -> dict[str, Any]:
    supplied_run = run.expanduser()
    if supplied_run.is_symlink():
        raise ValueError(f"evaluation run must not be a symlink: {supplied_run}")
    run = supplied_run.resolve()
    manifest = _load_json_object(run / "manifest.json")
    if manifest.get("format_version") != EVALUATION_FORMAT_VERSION:
        raise ValueError("unsupported evaluation run format")
    _verify_file_entries(run, _require_list(manifest, "files"), excluded={"manifest.json"})
    for path in (run, *run.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"evaluation run contains a symlink: {path}")
        if path.stat().st_mode & 0o222:
            raise ValueError(f"evaluation run is writable: {path}")
    result_kind = manifest.get("result_kind")
    config_name = (
        "workset.json"
        if result_kind
        in {
            "evidence_workset",
            "evidence_workset_comparison",
        }
        else "baseline.json"
    )
    config = _load_json_object(run / "config" / config_name)
    phases = tuple(_require_string_list(config, "phases"))
    if (
        not phases
        or len(phases) != len(set(phases))
        or _require_int(config, "query_trials") != len(phases)
    ):
        raise ValueError("evaluation run phase configuration is invalid")
    if result_kind == "evidence_workset_comparison":
        answer_key_payload = answer_key.read()
        candidate = score_retrieval_results(
            results_path=run / "retrieval-results.jsonl",
            answer_key=io.StringIO(answer_key_payload),
            expected_answer_key_sha256=_require_str(manifest, "answer_key_plaintext_sha256"),
            require_citations=True,
            expected_phases=phases,
        )
        baseline = score_retrieval_results(
            results_path=run / "baseline-results.jsonl",
            answer_key=io.StringIO(answer_key_payload),
            expected_answer_key_sha256=_require_str(manifest, "answer_key_plaintext_sha256"),
            require_citations=True,
            expected_phases=phases,
        )
        hard_gates = dict(_require_object(candidate, "hard_gates"))
        baseline_retrieval_gate = dict(
            _require_object(_require_object(baseline, "hard_gates"), "retrieval_failure")
        )
        hard_gates["raw_fts_baseline_retrieval_failure"] = baseline_retrieval_gate
        comparison_failed = (
            _require_int(_require_object(candidate, "aggregate"), "retrieval_failure_count") > 0
            or _require_int(_require_object(baseline, "aggregate"), "retrieval_failure_count") > 0
        )
        return {
            "status": (
                "retrieval_comparison_failed"
                if comparison_failed
                else "retrieval_comparison_scored"
            ),
            "answer_key_plaintext_sha256": candidate["answer_key_plaintext_sha256"],
            "query_count": candidate["query_count"],
            "aggregate": candidate["aggregate"],
            "candidate": candidate,
            "raw_fts_baseline": baseline,
            "aggregate_delta_vs_raw_fts": _aggregate_score_delta(
                _require_object(candidate, "aggregate"),
                _require_object(baseline, "aggregate"),
            ),
            "hard_gates": hard_gates,
        }
    return score_retrieval_results(
        results_path=run / "retrieval-results.jsonl",
        answer_key=answer_key,
        expected_answer_key_sha256=_require_str(manifest, "answer_key_plaintext_sha256"),
        require_citations=(result_kind == "evidence_workset"),
        expected_phases=phases,
    )


def _aggregate_score_delta(
    candidate: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, float | int | None]:
    delta: dict[str, float | int | None] = {}
    for key in (
        "recall_at_5",
        "mrr",
        "ndcg_at_10",
        "forbidden_hit_count",
        "distractor_hit_count",
        "authority_accuracy",
    ):
        candidate_value = candidate.get(key)
        baseline_value = baseline.get(key)
        if isinstance(candidate_value, bool) or isinstance(baseline_value, bool):
            delta[key] = None
        elif isinstance(candidate_value, (int, float)) and isinstance(baseline_value, (int, float)):
            delta[key] = round(candidate_value - baseline_value, 6)
        else:
            delta[key] = None
    return delta


def score_retrieval_results(
    *,
    results_path: Path,
    answer_key: TextIO,
    expected_answer_key_sha256: str,
    require_citations: bool = False,
    expected_phases: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    results = _read_jsonl(results_path)
    answers = _read_jsonl_handle(answer_key)
    answer_key_sha256 = hashlib.sha256(_jsonl_bytes(answers)).hexdigest()
    if not _is_sha256(expected_answer_key_sha256):
        raise ValueError("expected answer-key digest is invalid")
    if answer_key_sha256 != expected_answer_key_sha256:
        raise ValueError("answer key does not match the frozen run manifest")

    answer_ids = [_require_str(item, "query_id") for item in answers]
    if len(answer_ids) != len(set(answer_ids)):
        raise ValueError("answer key contains duplicate query ids")

    results_by_query: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        results_by_query[_require_str(item, "query_id")].append(item)
    if set(results_by_query) != set(answer_ids):
        raise ValueError(
            "retrieval result and answer ids differ: "
            f"missing_results={sorted(set(answer_ids) - set(results_by_query))}, "
            f"extra_results={sorted(set(results_by_query) - set(answer_ids))}"
        )

    ordered_results_by_query: dict[str, list[dict[str, Any]]] = {}
    for query_id, query_results in results_by_query.items():
        if expected_phases is not None:
            observed_attempts = sorted(
                (_require_int(item, "trial"), _require_str(item, "phase")) for item in query_results
            )
            expected_attempts = [
                (trial, phase) for trial, phase in enumerate(expected_phases, start=1)
            ]
            if observed_attempts != expected_attempts:
                raise ValueError(
                    f"retrieval attempts differ for query {query_id}: "
                    f"expected={expected_attempts}, observed={observed_attempts}"
                )
            order = {phase: index for index, phase in enumerate(expected_phases)}
            query_results = sorted(
                query_results,
                key=lambda item: order[_require_str(item, "phase")],
            )
        elif len(query_results) > 1:
            observed_phases = [_require_str(item, "phase") for item in query_results]
            if len(observed_phases) != len(set(observed_phases)):
                raise ValueError(f"ambiguous retrieval results for query: {query_id}")
        statuses = [_require_str(item, "status") for item in query_results]
        if any(status not in {"ok", "unsupported", "error"} for status in statuses):
            raise ValueError(f"invalid retrieval status for query: {query_id}")
        splits = {_require_str(item, "split") for item in query_results}
        suites = {_require_str(item, "suite") for item in query_results}
        if len(splits) != 1 or len(suites) != 1:
            raise ValueError(f"retrieval attempt metadata differs for query: {query_id}")
        ordered_results_by_query[query_id] = query_results

    per_query: list[dict[str, Any]] = []
    per_attempt: list[dict[str, Any]] = []
    for answer in answers:
        query_id = _require_str(answer, "query_id")
        relevant_items = _require_list(answer, "relevant")
        gains = {
            _require_str(item, "document_id"): _require_int(item, "gain") for item in relevant_items
        }
        forbidden = {
            _require_str(item, "document_id") for item in _require_list(answer, "forbidden")
        }
        distractors = {
            _require_str(item, "document_id")
            for item in _optional_object_list(answer, "distractors")
        }
        required_authorities = {
            str(value) for value in cast(list[object], answer.get("required_authorities", []))
        }
        query_attempts: list[dict[str, Any]] = []
        all_returned_ids: set[str] = set()
        query_evidence_failures = 0
        query_citation_failures = 0
        query_retrieval_failures = 0
        statuses: list[str] = []
        for result in ordered_results_by_query[query_id]:
            status = _require_str(result, "status")
            statuses.append(status)
            successful = status == "ok"
            if not successful:
                query_retrieval_failures += 1
            returned_items = _require_list(result, "results")
            returned_ids = [_require_str(item, "document_id") for item in returned_items]
            all_returned_ids.update(returned_ids)
            top_five = returned_ids[:5]
            if not successful:
                recall_at_five = 0.0
                reciprocal_rank = 0.0
                ndcg_at_ten = 0.0
            elif gains:
                recall_at_five = len(set(top_five) & gains.keys()) / len(gains)
                reciprocal_rank = next(
                    (
                        1.0 / rank
                        for rank, item in enumerate(returned_ids, start=1)
                        if item in gains
                    ),
                    0.0,
                )
                ndcg_at_ten = _ndcg_at_ten(returned_ids, gains)
            else:
                expect_empty = answer.get("expect_empty")
                if not isinstance(expect_empty, bool) or not expect_empty:
                    raise ValueError(
                        f"answer without relevant documents is not expect_empty: {query_id}"
                    )
                empty_score = 1.0 if not returned_ids else 0.0
                recall_at_five = empty_score
                reciprocal_rank = empty_score
                ndcg_at_ten = empty_score
            attempt_evidence_failures = sum(
                1 for item in returned_items if item.get("evidence_verified") is not True
            )
            query_evidence_failures += attempt_evidence_failures
            attempt_citation_failures = (
                sum(1 for item in returned_items if item.get("citation_verified") is not True)
                if require_citations
                else 0
            )
            query_citation_failures += attempt_citation_failures
            authority_checks = [
                _require_str(item, "authority") in required_authorities
                for item in returned_items
                if _require_str(item, "document_id") in gains and required_authorities
            ]
            if required_authorities:
                authority_accuracy = (
                    sum(authority_checks) / len(authority_checks)
                    if successful and authority_checks
                    else 0.0
                )
            else:
                authority_accuracy = None
            attempt_score = {
                "query_id": query_id,
                "split": _require_str(result, "split"),
                "suite": _require_str(result, "suite"),
                "phase": _require_str(result, "phase"),
                "status": status,
                "recall_at_5": round(recall_at_five, 6),
                "mrr": round(reciprocal_rank, 6),
                "ndcg_at_10": round(ndcg_at_ten, 6),
                "forbidden_hit_count": len(set(returned_ids) & forbidden),
                "distractor_hit_count": len(set(returned_ids) & distractors),
                "evidence_failure_count": attempt_evidence_failures,
                "citation_failure_count": attempt_citation_failures,
                "retrieval_failure_count": 0 if successful else 1,
                "authority_accuracy": (
                    round(authority_accuracy, 6) if authority_accuracy is not None else None
                ),
            }
            if "trial" in result:
                attempt_score["trial"] = _require_int(result, "trial")
            query_attempts.append(attempt_score)
            per_attempt.append(attempt_score)

        attempt_aggregate = _aggregate_scores(query_attempts)
        query_status = (
            "error" if "error" in statuses else "unsupported" if "unsupported" in statuses else "ok"
        )
        per_query.append(
            {
                "query_id": query_id,
                "split": query_attempts[0]["split"],
                "suite": query_attempts[0]["suite"],
                "status": query_status,
                "attempt_count": len(query_attempts),
                "recall_at_5": attempt_aggregate["recall_at_5"],
                "mrr": attempt_aggregate["mrr"],
                "ndcg_at_10": attempt_aggregate["ndcg_at_10"],
                "forbidden_hit_count": len(all_returned_ids & forbidden),
                "distractor_hit_count": len(all_returned_ids & distractors),
                "evidence_failure_count": query_evidence_failures,
                "citation_failure_count": query_citation_failures,
                "retrieval_failure_count": query_retrieval_failures,
                "authority_accuracy": attempt_aggregate["authority_accuracy"],
            }
        )

    aggregate = _aggregate_scores(per_query)
    forbidden_hits = _require_int(aggregate, "forbidden_hit_count")
    evidence_failures = _require_int(aggregate, "evidence_failure_count")
    citation_failures = _require_int(aggregate, "citation_failure_count")
    retrieval_failures = _require_int(aggregate, "retrieval_failure_count")
    return {
        "status": ("retrieval_failed_scored" if retrieval_failures else "retrieval_only_scored"),
        "answer_key_plaintext_sha256": answer_key_sha256,
        "query_count": len(per_query),
        "attempt_count": len(per_attempt),
        "aggregate": aggregate,
        "per_suite": {
            suite: _aggregate_scores([item for item in per_query if item["suite"] == suite])
            for suite in sorted({cast(str, item["suite"]) for item in per_query})
        },
        "per_phase": {
            phase: _aggregate_scores([item for item in per_attempt if item["phase"] == phase])
            for phase in sorted({cast(str, item["phase"]) for item in per_attempt})
        },
        "hard_gates": {
            "forbidden_document_returned": {
                "status": "pass" if forbidden_hits == 0 else "fail",
                "count": forbidden_hits,
            },
            "evidence_hash_mismatch": {
                "status": "pass" if evidence_failures == 0 else "fail",
                "count": evidence_failures,
            },
            "citation_mismatch": {
                "status": (
                    "pass"
                    if require_citations and citation_failures == 0
                    else "fail"
                    if require_citations
                    else "not_applicable"
                ),
                "count": citation_failures,
            },
            "retrieval_failure": {
                "status": "pass" if retrieval_failures == 0 else "fail",
                "count": retrieval_failures,
            },
            "instruction_execution": {"status": "not_exercised"},
            "deletion_rebuild": {"status": "not_exercised"},
            "oauth_and_origin_bypass": {"status": "not_exercised"},
        },
        "per_query": per_query,
        "per_attempt": per_attempt,
    }


def _load_source_plan(path: Path) -> tuple[SourceSpec, ...]:
    payload = _load_json_object(path)
    if payload.get("format_version") != EVALUATION_FORMAT_VERSION:
        raise ValueError("unsupported source plan format")
    base = path.expanduser().resolve().parent
    sources: list[SourceSpec] = []
    seen: set[str] = set()
    for raw in _require_list(payload, "sources"):
        source_id = _require_identifier(raw, "source_id")
        if source_id in seen:
            raise ValueError(f"duplicate source_id: {source_id}")
        seen.add(source_id)
        raw_path = Path(_require_str(raw, "path")).expanduser()
        source_path = raw_path if raw_path.is_absolute() else base / raw_path
        source_path = source_path.resolve()
        scope = Scope(_require_str(raw, "scope"))
        project_id = _optional_str(raw.get("project_id"))
        if scope is Scope.PROJECT and not project_id:
            raise ValueError(f"project_id is required for project source: {source_id}")
        expected_sha256 = _require_str(raw, "sha256")
        if not _is_sha256(expected_sha256):
            raise ValueError(f"invalid source sha256 for {source_id}")
        max_file_bytes_value = raw.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        if (
            isinstance(max_file_bytes_value, bool)
            or not isinstance(max_file_bytes_value, int)
            or max_file_bytes_value < 1
        ):
            raise ValueError(f"invalid max_file_bytes for {source_id}")
        max_file_bytes = max_file_bytes_value
        sources.append(
            SourceSpec(
                source_id=source_id,
                source_system=SourceSystem(_require_str(raw, "source_system")),
                path=source_path,
                source_account=_require_str(raw, "source_account"),
                scope=scope,
                project_id=project_id,
                expected_sha256=expected_sha256,
                max_file_bytes=max_file_bytes,
            )
        )
    if not sources:
        raise ValueError("source plan must contain at least one source")
    return tuple(sources)


def _load_relation_specs(path: Path) -> tuple[RelationSpec, ...]:
    payload = _load_json_object(path)
    if payload.get("format_version") != EVALUATION_FORMAT_VERSION:
        raise ValueError("unsupported source plan format")
    relations: list[RelationSpec] = []
    seen: set[tuple[str, int, str, int, str]] = set()
    for raw in _optional_object_list(payload, "relations"):
        from_selector = _require_object(raw, "from")
        to_selector = _require_object(raw, "to")
        from_source_id = _require_identifier(from_selector, "source_id")
        to_source_id = _require_identifier(to_selector, "source_id")
        from_record_ordinal = _require_int(from_selector, "record_ordinal")
        to_record_ordinal = _require_int(to_selector, "record_ordinal")
        if from_record_ordinal < 0 or to_record_ordinal < 0:
            raise ValueError("relation record ordinals must be non-negative")
        relation_type = _require_str(raw, "relation_type")
        if relation_type not in EVIDENCE_RELATION_TYPES:
            raise ValueError(f"invalid evidence relation type: {relation_type}")
        basis = _require_str(raw, "basis").strip()
        if not basis:
            raise ValueError("relation basis must contain non-whitespace text")
        if len(basis.encode("utf-8")) > 1000:
            raise ValueError("relation basis exceeds 1000 bytes")
        identity = (
            from_source_id,
            from_record_ordinal,
            to_source_id,
            to_record_ordinal,
            relation_type,
        )
        if identity in seen:
            raise ValueError("source plan contains a duplicate evidence relation")
        if identity[:2] == identity[2:4]:
            raise ValueError("evidence relation cannot point to itself")
        seen.add(identity)
        relations.append(
            RelationSpec(
                from_source_id=from_source_id,
                from_record_ordinal=from_record_ordinal,
                to_source_id=to_source_id,
                to_record_ordinal=to_record_ordinal,
                relation_type=relation_type,
                basis=basis,
            )
        )
    return tuple(relations)


def _load_queries(path: Path) -> tuple[EvaluationQuery, ...]:
    queries: list[EvaluationQuery] = []
    seen: set[str] = set()
    for raw in _read_jsonl(path):
        query_id = _require_identifier(raw, "query_id")
        if query_id in seen:
            raise ValueError(f"duplicate query_id: {query_id}")
        seen.add(query_id)
        split = _require_str(raw, "split")
        suite = _require_str(raw, "suite")
        if split not in QUERY_SPLITS:
            raise ValueError(f"invalid query split: {split}")
        if suite not in QUERY_SUITES:
            raise ValueError(f"invalid query suite: {suite}")
        query_text = _require_str(raw, "query")
        if not query_text.strip():
            raise ValueError(f"query must contain non-whitespace text: {query_id}")
        scopes = tuple(Scope(item) for item in _require_string_list(raw, "scopes"))
        if not scopes or len(scopes) != len(set(scopes)):
            raise ValueError(f"query scopes must be non-empty and unique: {query_id}")
        project_id = _optional_str(raw.get("project_id"))
        if Scope.PROJECT in scopes and project_id is None:
            raise ValueError(f"project_id is required for project query: {query_id}")
        authorities = tuple(Authority(item) for item in _optional_string_list(raw, "authorities"))
        if len(authorities) != len(set(authorities)):
            raise ValueError(f"query authorities must be unique: {query_id}")
        contexts = tuple(
            ContextFilter(
                kind=ContextKind(_require_str(item, "kind")),
                key=_require_str(item, "key"),
            )
            for item in _optional_object_list(raw, "contexts")
        )
        if len(contexts) != len(set(contexts)):
            raise ValueError(f"query contexts must be unique: {query_id}")
        limit_value = raw.get("limit", 5)
        if (
            isinstance(limit_value, bool)
            or not isinstance(limit_value, int)
            or not 1 <= limit_value <= 20
        ):
            raise ValueError(f"invalid query limit for {query_id}")
        limit = limit_value
        queries.append(
            EvaluationQuery(
                query_id=query_id,
                split=split,
                suite=suite,
                query=query_text,
                mode=QueryMode(_require_str(raw, "mode")),
                project_id=project_id,
                scopes=scopes,
                authorities=authorities,
                contexts=contexts,
                limit=limit,
            )
        )
    if not queries:
        raise ValueError("query file must contain at least one query")
    return tuple(queries)


def _load_answers(path: Path) -> tuple[EvaluationAnswer, ...]:
    answers: list[EvaluationAnswer] = []
    seen: set[str] = set()
    for raw in _read_jsonl(path):
        query_id = _require_identifier(raw, "query_id")
        if query_id in seen:
            raise ValueError(f"duplicate answer query_id: {query_id}")
        seen.add(query_id)
        expect_empty = raw.get("expect_empty", False)
        if not isinstance(expect_empty, bool):
            raise ValueError(f"expect_empty must be a boolean: {query_id}")
        answers.append(
            EvaluationAnswer(
                query_id=query_id,
                relevant=tuple(
                    _answer_selector(item, require_gain=True)
                    for item in _require_object_list(raw, "relevant")
                ),
                forbidden=tuple(
                    _answer_selector(item, require_gain=False)
                    for item in _optional_object_list(raw, "forbidden")
                ),
                distractors=tuple(
                    _answer_selector(item, require_gain=False)
                    for item in _optional_object_list(raw, "distractors")
                ),
                expect_empty=expect_empty,
                required_authorities=tuple(
                    Authority(item) for item in _optional_string_list(raw, "required_authorities")
                ),
                review_note=_optional_str(raw.get("review_note")),
            )
        )
    return tuple(answers)


def _answer_selector(raw: dict[str, Any], *, require_gain: bool) -> AnswerSelector:
    ordinal = _require_int(raw, "record_ordinal")
    gain = _require_int(raw, "gain") if require_gain else 0
    if ordinal < 0 or (require_gain and not 1 <= gain <= 3):
        raise ValueError("answer selector ordinal or gain is invalid")
    return AnswerSelector(_require_identifier(raw, "source_id"), ordinal, gain)


def _validate_query_answers(
    queries: tuple[EvaluationQuery, ...],
    answers: tuple[EvaluationAnswer, ...],
    *,
    require_split_ratio: bool,
) -> None:
    query_ids = {item.query_id for item in queries}
    answer_ids = {item.query_id for item in answers}
    if query_ids != answer_ids:
        raise ValueError(
            "query and answer ids differ: "
            f"missing_answers={sorted(query_ids - answer_ids)}, "
            f"extra_answers={sorted(answer_ids - query_ids)}"
        )
    for answer in answers:
        relevant = {(item.source_id, item.record_ordinal) for item in answer.relevant}
        forbidden = {(item.source_id, item.record_ordinal) for item in answer.forbidden}
        distractors = {(item.source_id, item.record_ordinal) for item in answer.distractors}
        if (
            len(relevant) != len(answer.relevant)
            or len(forbidden) != len(answer.forbidden)
            or len(distractors) != len(answer.distractors)
        ):
            raise ValueError(f"answer contains duplicate selectors: {answer.query_id}")
        if relevant & forbidden or relevant & distractors or forbidden & distractors:
            raise ValueError(f"answer selector has conflicting labels: {answer.query_id}")
        if answer.expect_empty and relevant:
            raise ValueError(f"expect_empty answer has relevant records: {answer.query_id}")
        if not answer.expect_empty and not relevant:
            raise ValueError(
                f"answer must have relevant records or expect_empty: {answer.query_id}"
            )
        if len(answer.required_authorities) != len(set(answer.required_authorities)):
            raise ValueError(f"answer authorities must be unique: {answer.query_id}")
    if require_split_ratio:
        if len(queries) < 10 or len(queries) % 10:
            raise ValueError("a frozen private query set must be a multiple of 10")
        unit = len(queries) // 10
        expected = {"calibration": unit * 3, "development": unit * 3, "held_out": unit * 4}
        actual = Counter(item.split for item in queries)
        unexpected = sorted(set(actual) - set(PRIVATE_SPLITS))
        if unexpected:
            raise ValueError(f"private frozen query set contains non-private splits: {unexpected}")
        if any(actual.get(name, 0) != count for name, count in expected.items()):
            raise ValueError(
                f"query split must be 30/30/40: expected {expected}, got {dict(actual)}"
            )


def _resolve_answers(
    queries: tuple[EvaluationQuery, ...],
    answers: tuple[EvaluationAnswer, ...],
    selector_to_document: dict[tuple[str, int], str],
    included_documents: set[str],
) -> list[dict[str, Any]]:
    answer_by_query = {item.query_id: item for item in answers}
    resolved: list[dict[str, Any]] = []
    for query in queries:
        answer = answer_by_query[query.query_id]
        relevant: list[dict[str, Any]] = []
        for selector in answer.relevant:
            document_id = _resolve_selector(selector, selector_to_document)
            if document_id not in included_documents:
                raise ValueError(f"relevant answer points to an excluded record: {query.query_id}")
            relevant.append({"document_id": document_id, "gain": selector.gain})
        forbidden = [
            {"document_id": _resolve_selector(item, selector_to_document)}
            for item in answer.forbidden
        ]
        distractors = [
            {"document_id": _resolve_selector(item, selector_to_document)}
            for item in answer.distractors
        ]
        if answer.expect_empty and relevant:
            raise ValueError(f"expect_empty answer has relevant records: {query.query_id}")
        resolved.append(
            {
                "query_id": query.query_id,
                "relevant": relevant,
                "forbidden": forbidden,
                "distractors": distractors,
                "expect_empty": answer.expect_empty,
                "required_authorities": [item.value for item in answer.required_authorities],
                "review_note": answer.review_note,
            }
        )
    return resolved


def _resolve_relations(
    relations: tuple[RelationSpec, ...],
    selector_to_document: dict[tuple[str, int], str],
    included_documents: set[str],
) -> list[dict[str, str]]:
    resolved: list[dict[str, str]] = []
    for relation in relations:
        try:
            from_document_id = selector_to_document[
                (relation.from_source_id, relation.from_record_ordinal)
            ]
            to_document_id = selector_to_document[
                (relation.to_source_id, relation.to_record_ordinal)
            ]
        except KeyError as error:
            source_id, ordinal = cast(tuple[str, int], error.args[0])
            raise ValueError(f"relation selector not found: {source_id}:{ordinal}") from error
        if from_document_id not in included_documents or to_document_id not in included_documents:
            raise ValueError("evidence relation points to an excluded record")
        resolved.append(
            {
                "from_document_id": from_document_id,
                "to_document_id": to_document_id,
                "relation_type": relation.relation_type,
                "basis": relation.basis,
            }
        )
    return resolved


def _resolve_selector(
    selector: AnswerSelector, selector_to_document: dict[tuple[str, int], str]
) -> str:
    try:
        return selector_to_document[(selector.source_id, selector.record_ordinal)]
    except KeyError as exc:
        raise ValueError(
            f"answer selector not found: {selector.source_id}:{selector.record_ordinal}"
        ) from exc


def _event_rows(database_path: Path, source_file_id: str) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            """
            SELECT
              sr.record_ordinal, sr.object_id, sr.byte_start, sr.byte_end,
              o.object_path, e.event_id, e.conversation_id, e.branch_id,
              e.actor_kind, e.assistant, e.authority, e.occurred_at,
              e.content_digest, e.content_text
            FROM source_records sr
            JOIN objects o ON o.object_id = sr.object_id
            JOIN events e ON e.source_record_id = sr.source_record_id
            WHERE sr.source_file_id = ?
            ORDER BY sr.record_ordinal
            """,
            (source_file_id,),
        ).fetchall()


def _verified_bundle_source(
    bundle: Path,
    manifest: dict[str, Any],
    source: dict[str, Any],
) -> Path:
    relative_text = _require_str(source, "raw_path")
    relative = Path(relative_text)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) < 3
        or relative.parts[:2] != ("raw", "sources")
    ):
        raise ValueError(f"invalid evaluation source path: {relative_text}")
    manifested_paths = {
        _require_str(cast(dict[str, Any], item), "path")
        for item in _require_list(manifest, "files")
        if isinstance(item, dict)
    }
    if relative_text not in manifested_paths:
        raise ValueError(f"evaluation source path is absent from the manifest: {relative_text}")
    resolved = (bundle / relative).resolve()
    if not _is_within(resolved, bundle) or resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f"evaluation source path is unsafe: {relative_text}")
    expected_digest = _require_str(source, "file_sha256")
    expected_size = _require_int(source, "file_size")
    if resolved.stat().st_size != expected_size or _sha256_file(resolved) != expected_digest:
        raise ValueError(f"evaluation source does not match its source entry: {relative_text}")
    return resolved


def _verify_workset_item_metadata(
    item: dict[str, Any],
    *,
    frozen_document: dict[str, Any],
    expected_source_object_id: str,
    query: str = "",
) -> None:
    for key in (
        "event_id",
        "actor_kind",
        "assistant",
        "authority",
        "scope",
        "project_id",
        "conversation_id",
        "branch_id",
        "occurred_at",
        "source_system",
        "record_ordinal",
    ):
        if item.get(key) != frozen_document.get(key):
            raise EvaluationIntegrityError(
                f"workset result metadata differs from frozen evidence: {key}"
            )
    content = _require_str(frozen_document, "content_text")
    expected_content = content[:4000]
    if "content_preview" in item:
        # Reconstruct from frozen text, never the candidate's index or returned excerpt.
        with closing(sqlite3.connect(":memory:")) as probe:
            prefix, text_length = probe.execute(
                "SELECT substr(?, 1, ?), length(?)",
                (content, MAX_EVIDENCE_PREVIEW_CHARACTERS, content),
            ).fetchone()
            expected_content = cast(str, prefix)
            truncated = len(expected_content.encode()) < len(content.encode())
            strategy = "prefix" if truncated else "complete"
            tokens = [match.group(0) for match in FTS_TOKEN.finditer(query)][:24]
            if tokens and text_length > MAX_EVIDENCE_PREVIEW_CHARACTERS:
                probe.execute(
                    "CREATE VIRTUAL TABLE frozen USING fts5("
                    "content, tokenize='unicode61 remove_diacritics 2')"
                )
                probe.execute("INSERT INTO frozen(content) VALUES (?)", (content,))
                match_query = " AND ".join('"' + token.replace('"', "") + '"' for token in tokens)
                row = probe.execute(
                    "SELECT substr(snippet(frozen, 0, '', '', ' ... ', 64), 1, ?) "
                    "FROM frozen WHERE frozen MATCH ?",
                    (MAX_EVIDENCE_PREVIEW_CHARACTERS, match_query),
                ).fetchone()
                if row is not None:
                    expected_content = cast(str, row[0])
                    strategy = "query_snippet"
        expected_preview = {
            "strategy": strategy,
            "truncated": truncated,
            "total_utf8_bytes": len(content.encode()),
        }
        if item["content_preview"] != expected_preview:
            raise EvaluationIntegrityError("workset content_preview differs from frozen evidence")
    if item.get("content_text") != expected_content:
        raise EvaluationIntegrityError(
            "workset result metadata differs from frozen evidence: content_text"
        )
    if item.get("source_object_id") != expected_source_object_id:
        raise EvaluationIntegrityError("workset result source object differs from frozen evidence")


def _expected_open_thread_role(frozen_document: dict[str, Any]) -> str:
    actor_kind = _require_str(frozen_document, "actor_kind")
    authority = _require_str(frozen_document, "authority")
    if actor_kind == "user" or authority == Authority.USER_ASSERTION.value:
        return "user_statement"
    if actor_kind == "assistant" or authority == Authority.ASSISTANT_OUTPUT.value:
        return "assistant_suggestion"
    return "tool_observation"


def _is_stale_current_return(
    mode: QueryMode,
    event_id: str,
    frozen_superseded_ids: set[str],
) -> bool:
    return mode is QueryMode.WHAT_IS_CURRENT and event_id in frozen_superseded_ids


def _is_unjustified_duplicate_return(
    event_id: str,
    seen_event_ids: set[str],
) -> bool:
    return event_id in seen_event_ids


def _install_frozen_relations(
    *,
    database_path: Path,
    relations_path: Path,
    event_by_document: dict[str, str],
) -> int:
    if not relations_path.exists():
        return 0
    relations = _read_jsonl(relations_path)
    with closing(sqlite3.connect(database_path)) as connection, connection:
        for relation in relations:
            from_document_id = _require_str(relation, "from_document_id")
            to_document_id = _require_str(relation, "to_document_id")
            try:
                from_event_id = event_by_document[from_document_id]
                to_event_id = event_by_document[to_document_id]
            except KeyError as error:
                raise ValueError(
                    f"frozen relation references an unknown document: {error.args[0]}"
                ) from error
            relation_type = _require_str(relation, "relation_type")
            if relation_type not in EVIDENCE_RELATION_TYPES:
                raise ValueError(f"invalid frozen relation type: {relation_type}")
            basis = _require_str(relation, "basis")
            relation_digest = _sha256_text(
                "\x00".join((from_event_id, to_event_id, relation_type, basis))
            )
            connection.execute(
                """
                INSERT INTO event_relations(
                  relation_id, from_event_id, to_event_id, relation_type, basis, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"evaluation:{relation_digest}",
                    from_event_id,
                    to_event_id,
                    relation_type,
                    basis,
                    _now(),
                ),
            )
    return len(relations)


def _read_query_receipts(database_path: Path) -> list[dict[str, Any]]:
    with closing(sqlite3.connect(database_path)) as connection:
        rows = connection.execute(
            """
            SELECT query_id, query_mode, query_digest, principal, filters_json,
                   result_event_ids_json, omitted_counts_json, latency_ms, created_at
            FROM query_receipts
            ORDER BY created_at, query_id
            """
        ).fetchall()
    return [
        {
            "receipt_id": cast(str, row[0]),
            "query_mode": cast(str, row[1]),
            "query_digest": cast(str, row[2]),
            "principal": cast(str, row[3]),
            "filters": json.loads(cast(str, row[4])),
            "result_event_ids": json.loads(cast(str, row[5])),
            "omitted_counts": json.loads(cast(str, row[6])),
            "latency_ms": cast(float, row[7]),
            "created_at": cast(str, row[8]),
        }
        for row in rows
    ]


def _checkpoint_evaluation_database(database_path: Path) -> None:
    with closing(sqlite3.connect(database_path, isolation_level=None)) as connection:
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or checkpoint[0] != 0:
            raise RuntimeError("evaluation database WAL checkpoint did not complete")
    sidecars = [
        database_path.with_name(f"{database_path.name}{suffix}") for suffix in ("-wal", "-shm")
    ]
    existing = [str(path) for path in sidecars if path.exists()]
    if existing:
        raise RuntimeError(f"evaluation database retains SQLite sidecars: {existing}")


def _publish_evaluation_output(temporary: Path, output: Path) -> None:
    _set_read_only_tree(temporary)
    publish_directory_no_replace(
        temporary,
        output,
        required_mode=0o500,
        label="evaluation run",
    )


def _resolve_commit_revision(repository: Path, revision: str, *, label: str) -> str:
    if not revision or "\x00" in revision:
        raise RuntimeError(f"{label} revision is unavailable: {revision}")
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    resolved = completed.stdout.strip()
    if completed.returncode or not _is_git_object_id(resolved):
        raise RuntimeError(f"{label} revision is unavailable: {revision}")
    return resolved


def _verify_baseline_revision(
    repository: Path,
    revision: str,
    *,
    paths: tuple[str, ...] = BASELINE_PATHS,
    label: str = "baseline",
) -> dict[str, str]:
    if not _is_git_object_id(revision):
        raise RuntimeError(f"{label} revision is unavailable: {revision}")
    diff = subprocess.run(
        ["git", "diff", "--quiet", revision, "--", *paths],
        cwd=repository,
        check=False,
    )
    if diff.returncode:
        raise RuntimeError(f"{label} code differs from the frozen revision")
    hashes: dict[str, str] = {}
    for relative in paths:
        path = repository / relative
        if path.is_dir():
            for child in sorted(item for item in path.rglob("*.py") if item.is_file()):
                hashes[str(child.relative_to(repository))] = _sha256_file(child)
        else:
            hashes[relative] = _sha256_file(path)
    return hashes


def _repository_head(repository: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    revision = completed.stdout.strip()
    if completed.returncode or not _is_git_object_id(revision):
        raise RuntimeError("could not resolve the evaluation harness revision")
    return revision


def _encrypt_gpg(payload: bytes, output: Path, recipient: str) -> None:
    executable = shutil.which("gpg")
    if executable is None:
        raise RuntimeError("gpg is required to encrypt the answer key")
    completed = subprocess.run(
        [
            executable,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--recipient",
            recipient,
            "--output",
            str(output),
            "--encrypt",
        ],
        input=payload,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        error = completed.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"gpg answer-key encryption failed: {error}")


def _aggregate_scores(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        return {"query_count": 0}
    authority_values = [
        cast(float, item["authority_accuracy"])
        for item in items
        if item.get("authority_accuracy") is not None
    ]
    return {
        "query_count": len(items),
        "recall_at_5": round(
            statistics.fmean(cast(float, item["recall_at_5"]) for item in items), 6
        ),
        "mrr": round(statistics.fmean(cast(float, item["mrr"]) for item in items), 6),
        "ndcg_at_10": round(statistics.fmean(cast(float, item["ndcg_at_10"]) for item in items), 6),
        "forbidden_hit_count": sum(cast(int, item["forbidden_hit_count"]) for item in items),
        "distractor_hit_count": sum(
            cast(int, item.get("distractor_hit_count", 0)) for item in items
        ),
        "evidence_failure_count": sum(cast(int, item["evidence_failure_count"]) for item in items),
        "citation_failure_count": sum(
            cast(int, item.get("citation_failure_count", 0)) for item in items
        ),
        "retrieval_failure_count": sum(
            cast(int, item.get("retrieval_failure_count", 0)) for item in items
        ),
        "authority_accuracy": (
            round(statistics.fmean(authority_values), 6) if authority_values else None
        ),
        "unsupported_query_count": sum(1 for item in items if item["status"] == "unsupported"),
        "error_query_count": sum(1 for item in items if item["status"] == "error"),
    }


def _ndcg_at_ten(returned_ids: list[str], gains: dict[str, int]) -> float:
    if not gains:
        return 1.0 if not returned_ids else 0.0
    dcg = sum(
        (2 ** gains.get(document_id, 0) - 1) / math.log2(rank + 1)
        for rank, document_id in enumerate(returned_ids[:10], start=1)
    )
    ideal = sum(
        (2**gain - 1) / math.log2(rank + 1)
        for rank, gain in enumerate(sorted(gains.values(), reverse=True)[:10], start=1)
    )
    return dcg / ideal if ideal else 0.0


def _latency_summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    if not ordered:
        return {"p50": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "p50": round(statistics.median(ordered), 6),
        "p95": round(ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], 6),
        "max": round(ordered[-1], 6),
    }


def _cpu_seconds(*, include_children: bool = False) -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    total = usage.ru_utime + usage.ru_stime
    if include_children:
        child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        total += child_usage.ru_utime + child_usage.ru_stime
    return total


def _peak_rss_bytes(who: int = resource.RUSAGE_SELF) -> int:
    value = int(resource.getrusage(who).ru_maxrss)
    return value if platform.system() == "Darwin" else value * 1024


def _directory_bytes(root: Path) -> int:
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file())


def _copy_regular_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str | None = None,
) -> str:
    if expected_sha256 is not None and not _is_sha256(expected_sha256):
        raise ValueError("expected source SHA-256 is invalid")
    source_descriptor, _normalized = open_regular_file_no_symlinks(
        source,
        "evaluation copy source",
    )
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_descriptor = os.open(
        destination.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
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
        destination_descriptor = os.open(
            destination.name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        digest = hashlib.sha256()
        copied_bytes = 0
        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            copied_bytes += len(block)
            view = memoryview(block)
            written = 0
            while written < len(view):
                count = os.write(destination_descriptor, view[written:])
                if count == 0:
                    raise OSError("evaluation copy made no write progress")
                written += count
        after = os.fstat(source_descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or copied_bytes != before.st_size:
            raise RuntimeError("evaluation copy source changed while it was read")
        copied_digest = digest.hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(
            copied_digest,
            expected_sha256,
        ):
            raise EvaluationIntegrityError("evaluation copy did not match its verified digest")
        os.fchmod(destination_descriptor, 0o600)
        os.fsync(destination_descriptor)
        created = os.fstat(destination_descriptor)
        published = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            created.st_dev != published.st_dev
            or created.st_ino != published.st_ino
            or created.st_nlink != 1
            or not stat.S_ISREG(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o600
        ):
            raise RuntimeError("evaluation copy destination identity changed")
        os.fsync(parent_descriptor)
        return copied_digest
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(parent_descriptor)
        os.close(source_descriptor)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_jsonl(path: Path, payloads: list[dict[str, Any]]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(_jsonl_bytes(payloads))
    path.chmod(0o600)


def _jsonl_bytes(payloads: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n" for item in payloads
    ).encode()


def _load_json_object(path: Path) -> dict[str, Any]:
    raw: object = json.loads(path.expanduser().read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return cast(dict[str, Any], raw)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.expanduser().open(encoding="utf-8") as handle:
        return _read_jsonl_handle(handle)


def _read_jsonl_handle(handle: TextIO) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        raw: object = json.loads(line)
        if not isinstance(raw, dict):
            raise ValueError(f"JSONL row {line_number} is not an object")
        rows.append(cast(dict[str, Any], raw))
    return rows


def _file_entries(root: Path, *, exclude: set[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = str(path.relative_to(root))
        if relative in exclude:
            continue
        entries.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries


def _verify_file_entries(root: Path, raw_entries: list[object], *, excluded: set[str]) -> None:
    entries: dict[str, tuple[int, str]] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise ValueError("file manifest entry is not an object")
        entry = cast(dict[str, Any], raw)
        relative = _require_str(entry, "path")
        if relative in entries or relative.startswith("/") or ".." in Path(relative).parts:
            raise ValueError(f"invalid file manifest path: {relative}")
        entries[relative] = (_require_int(entry, "bytes"), _require_str(entry, "sha256"))
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and str(path.relative_to(root)) not in excluded
    }
    if actual != entries.keys():
        raise ValueError(
            f"evaluation file set mismatch: missing={sorted(entries.keys() - actual)}, "
            f"unexpected={sorted(actual - entries.keys())}"
        )
    for relative, (expected_size, expected_digest) in entries.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"evaluation file is not regular: {relative}")
        if path.stat().st_size != expected_size or _sha256_file(path) != expected_digest:
            raise ValueError(f"evaluation file failed verification: {relative}")


def _set_read_only_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    root.chmod(0o500)


def _make_writable(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o700)
    for path in root.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)


def _document_id(source_id: str, ordinal: int, raw_record: bytes) -> str:
    raw_digest = hashlib.sha256(raw_record).hexdigest()
    identity = "\0".join((source_id, str(ordinal), raw_digest))
    return f"doc:{_sha256_text(identity)}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


# Shared by the isolated third-party runner so bundle and run serialization
# stays identical across every candidate.
directory_bytes = _directory_bytes
file_entries = _file_entries
latency_summary = _latency_summary
load_json_object = _load_json_object
now = _now
read_jsonl = _read_jsonl
set_read_only_tree = _set_read_only_tree
sha256_file = _sha256_file
write_json = _write_json
write_jsonl = _write_jsonl


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _is_git_object_id(value: str) -> bool:
    return len(value) in (40, 64) and all(character in "0123456789abcdef" for character in value)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_identifier(payload: dict[str, Any], key: str) -> str:
    value = _require_str(payload, key)
    if (
        not value
        or len(value) > 96
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in value
        )
    ):
        raise ValueError(f"invalid identifier for {key}: {value!r}")
    return value


def _require_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("optional string value is invalid")
    return value


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _optional_nonnegative_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def _require_list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return cast(list[Any], value)


def _require_string_list(payload: dict[str, Any], key: str) -> list[str]:
    values = _require_list(payload, key)
    if any(not isinstance(item, str) or not item for item in values):
        raise ValueError(f"{key} must contain only non-empty strings")
    return cast(list[str], values)


def _optional_string_list(payload: dict[str, Any], key: str) -> list[str]:
    if key not in payload:
        return []
    return _require_string_list(payload, key)


def _require_object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return cast(dict[str, Any], value)


def _require_object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = _require_list(payload, key)
    if any(not isinstance(item, dict) for item in values):
        raise ValueError(f"{key} must contain only objects")
    return cast(list[dict[str, Any]], values)


def _optional_object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    if key not in payload:
        return []
    return _require_object_list(payload, key)
