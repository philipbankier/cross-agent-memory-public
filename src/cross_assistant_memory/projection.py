from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.candidates import (
    FROZEN_CANDIDATES,
    candidate_environment,
    candidate_preflight,
    probe_sandbox,
    sandbox_profile,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.embedding_artifact import (
    stage_verified_embedding_artifact,
    verify_embedding_artifact,
)
from cross_assistant_memory.evaluation import (
    file_entries,
    set_read_only_tree,
    sha256_file,
    write_json,
    write_jsonl,
)
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.models import (
    Access,
    Authority,
    ContextFilter,
    QueryMode,
    RetrievalCandidate,
    RetrievalControl,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.retrieval import (
    MAX_WORKSET_CANDIDATES,
    effective_context_filters,
    suppressed_workset,
)
from cross_assistant_memory.storage import (
    FTS_WORKSET_CANDIDATE_ID,
    MAX_QUERY_RESULTS,
    MAX_WORKSET_CONTEXT_FILTERS,
    Ledger,
    exclusive_ledger_writer,
)

SHADOW_FORMAT_VERSION = 4
SHADOW_LEXICAL_CANDIDATE_ID = "mempalace-sqlite-exact"
SHADOW_SEMANTIC_CANDIDATE_ID = "mempalace-sqlite-exact-semantic"
SHADOW_CANDIDATE_ID = SHADOW_LEXICAL_CANDIDATE_ID
SHADOW_COLLECTION = "cross_assistant_memory"
MIN_MATCHED_QUERY_TOKENS = 2
MIN_QUERY_TOKEN_COVERAGE = 0.25
TOKEN_PATTERN = re.compile(r"[^\W]+", re.UNICODE)
STOP_TOKENS = frozenset(
    {
        "a",
        "about",
        "an",
        "and",
        "are",
        "did",
        "do",
        "for",
        "i",
        "in",
        "is",
        "it",
        "my",
        "of",
        "on",
        "or",
        "our",
        "say",
        "that",
        "the",
        "this",
        "to",
        "was",
        "we",
        "what",
    }
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_WORKER_OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class ActiveProjection:
    root: Path
    generation_path: Path
    palace_path: Path
    manifest: dict[str, Any]
    manifest_sha256: str


def build_shadow_projection(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    execute: bool,
    embedding_artifact: Path | None = None,
) -> dict[str, Any]:
    if not execute:
        return _build_shadow_projection_locked(
            settings,
            runtime=runtime,
            checkout=checkout,
            projection_root=projection_root,
            execute=False,
            embedding_artifact=embedding_artifact,
        )
    root = _prepare_projection_root(projection_root)
    with _exclusive_projection_operation(root):
        return _build_shadow_projection_locked(
            settings,
            runtime=runtime,
            checkout=checkout,
            projection_root=root,
            execute=True,
            embedding_artifact=embedding_artifact,
        )


def _build_shadow_projection_locked(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    execute: bool,
    embedding_artifact: Path | None = None,
    ledger_writer_locked: bool = False,
) -> dict[str, Any]:
    ledger = Ledger(settings, read_only=True)
    generation_digest = ledger.generation_digest()
    documents = ledger.projection_documents()
    attestation = _candidate_attestation(runtime, checkout)
    embedding_attestation = _embedding_attestation(embedding_artifact)
    retrieval_mode = "semantic" if embedding_attestation is not None else "lexical"
    candidate_id = (
        SHADOW_SEMANTIC_CANDIDATE_ID
        if embedding_attestation is not None
        else SHADOW_LEXICAL_CANDIDATE_ID
    )
    abstention_policy = _abstention_policy(retrieval_mode=retrieval_mode)
    build_timeout_seconds = 1800 if retrieval_mode == "semantic" else 300
    preview = {
        "status": "preview",
        "shadow_only": True,
        "execute": execute,
        "candidate": candidate_id,
        "candidate_revision": attestation["candidate_revision"],
        "retrieval_mode": retrieval_mode,
        "embedding_artifact": embedding_attestation,
        "abstention_policy": abstention_policy,
        "build_timeout_seconds": build_timeout_seconds,
        "ledger_generation_digest": generation_digest,
        "document_count": len(documents),
        "projection_root": str(_absolute(projection_root)),
    }
    if not execute:
        return preview

    root = _absolute(projection_root)
    generations = root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    generations.chmod(0o700)
    building = generations / f".building-{uuid.uuid4()}"
    building.mkdir(mode=0o700)
    worker_source = Path(__file__).with_name("mempalace_worker.py")
    worker_sha256 = sha256_file(worker_source)
    started = time.perf_counter()
    published_generation: Path | None = None
    try:
        for directory in (
            building / "adapter",
            building / "input",
            building / "receipts",
            building / "work" / "home",
            building / "work" / "tmp",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker_copy = building / "adapter" / "mempalace_worker.py"
        shutil.copy2(worker_source, worker_copy, follow_symlinks=False)
        worker_copy.chmod(0o500)
        worker_embedding_attestation = _stage_worker_embedding_artifact(
            embedding_attestation,
            building / "input" / "embedding-artifact",
        )
        input_path = building / "input" / "documents.jsonl"
        write_jsonl(input_path, documents)
        output_path = building / "work" / "build-result.json"
        palace_work = building / "work" / "palace"
        profile = sandbox_profile(Path.home(), building / "work")
        sandbox_receipt = probe_sandbox(
            profile=profile,
            denied_read=worker_source,
            sandbox_root=building,
        )
        write_json(building / "receipts" / "sandbox.json", sandbox_receipt)
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker_copy,
            palace=palace_work,
            output=output_path,
            command="build",
            command_arguments=["--input", str(input_path)],
            sandbox_root=building,
            timeout_seconds=build_timeout_seconds,
            embedding_attestation=worker_embedding_attestation,
        )
        worker_result = _load_worker_output(output_path)
        if (
            worker_result.get("status") != "built"
            or worker_result.get("document_count") != len(documents)
            or worker_result.get("retrieval_mode") != retrieval_mode
            or worker_result.get("embedding")
            != _expected_worker_embedding_receipt(embedding_attestation)
        ):
            raise RuntimeError("MemPalace build receipt did not match the canonical document set")
        palace = building / "palace"
        os.replace(palace_work, palace)
        os.replace(output_path, building / "receipts" / "build.json")
        _make_writable(building / "input")
        shutil.rmtree(building / "input")
        shutil.rmtree(building / "adapter")
        shutil.rmtree(building / "work")

        document_states = _document_states(documents)
        manifest: dict[str, Any] = {
            "format_version": SHADOW_FORMAT_VERSION,
            "created_at": _now(),
            "shadow_only": True,
            "answer_generation": False,
            "candidate": candidate_id,
            "candidate_revision": attestation["candidate_revision"],
            "candidate_attestation": attestation,
            "retrieval_mode": retrieval_mode,
            "embedding_artifact": embedding_attestation,
            "embedding_runtime": worker_result.get("embedding"),
            "worker_sha256": worker_sha256,
            "ledger_generation_digest": generation_digest,
            "document_count": len(documents),
            "document_state_sha256": _document_state_digest(document_states),
            "documents": document_states,
            "collection": SHADOW_COLLECTION,
            "abstention_policy": abstention_policy,
            "build_timeout_seconds": build_timeout_seconds,
            "sandbox": {
                "engine": "macos-sandbox-exec",
                "network": "deny-default",
                "home_read": "denied",
                "writes": "isolated-build-work-directory-only",
            },
            "build_seconds": round(time.perf_counter() - started, 6),
            "files": file_entries(building, exclude={"manifest.json"}),
        }
        write_json(building / "manifest.json", manifest)
        manifest_sha256 = sha256_file(building / "manifest.json")

        def publish_generation() -> tuple[str, Path]:
            nonlocal published_generation
            if Ledger(settings, read_only=True).generation_digest() != generation_digest:
                raise RuntimeError("ledger changed while the shadow projection was built")
            generation_name = f"{generation_digest[:16]}-{uuid.uuid4().hex[:12]}"
            generation_path = generations / generation_name
            os.replace(building, generation_path)
            published_generation = generation_path
            set_read_only_tree(generation_path)
            _write_active_pointer(
                root,
                generation=generation_name,
                manifest_sha256=manifest_sha256,
                ledger_generation_digest=generation_digest,
            )
            return generation_name, generation_path

        if ledger_writer_locked:
            generation_name, generation_path = publish_generation()
        else:
            with exclusive_ledger_writer(settings):
                generation_name, generation_path = publish_generation()
        return {
            **preview,
            "status": "built",
            "execute": True,
            "generation": generation_name,
            "generation_path": str(generation_path),
            "manifest_sha256": manifest_sha256,
            "build_seconds": manifest["build_seconds"],
        }
    except Exception:
        if building.exists():
            _make_writable(building)
            shutil.rmtree(building, ignore_errors=True)
        if published_generation is not None and published_generation.exists():
            _make_writable(published_generation)
            shutil.rmtree(published_generation, ignore_errors=True)
        raise


def verify_shadow_projection(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    embedding_artifact: Path | None = None,
) -> dict[str, Any]:
    active = _load_active_projection(
        Ledger(settings, read_only=True),
        runtime=runtime,
        checkout=checkout,
        projection_root=projection_root,
        embedding_artifact=embedding_artifact,
    )
    return {
        "status": "verified",
        "shadow_only": True,
        "generation": active.generation_path.name,
        "generation_path": str(active.generation_path),
        "manifest_sha256": active.manifest_sha256,
        "candidate": active.manifest["candidate"],
        "candidate_revision": active.manifest["candidate_revision"],
        "candidate_attestation": active.manifest["candidate_attestation"],
        "retrieval_mode": active.manifest["retrieval_mode"],
        "embedding_artifact": active.manifest["embedding_artifact"],
        "embedding_runtime": active.manifest["embedding_runtime"],
        "worker_sha256": active.manifest["worker_sha256"],
        "sandbox": active.manifest["sandbox"],
        "files": active.manifest["files"],
        "ledger_generation_digest": active.manifest["ledger_generation_digest"],
        "document_count": active.manifest["document_count"],
    }


def search_shadow_projection(
    settings: Settings,
    query: str,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    mode: QueryMode,
    scopes: list[Scope],
    contexts: tuple[ContextFilter, ...] = (),
    project_id: str | None,
    authorities: list[Authority] | None,
    accesses: list[Access] | None = None,
    limit: int,
    control: RetrievalControl = RetrievalControl.AUTO,
    principal: str = "local:shadow-comparison",
    embedding_artifact: Path | None = None,
    require_checkpointed: bool = True,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
) -> dict[str, Any]:
    overall_started = time.perf_counter()
    context_filters = effective_context_filters(contexts, project_id)
    if control is RetrievalControl.SUPPRESS:
        return suppressed_workset(mode=mode, contexts=context_filters)
    if len(context_filters) > MAX_WORKSET_CONTEXT_FILTERS:
        raise ValueError(
            f"context filter count exceeds the bounded limit of {MAX_WORKSET_CONTEXT_FILTERS}"
        )
    if not scopes:
        raise ValueError("at least one scope is required")
    if not _tokens(query):
        raise ValueError("query must contain at least one meaningful searchable token")
    limit = max(1, min(limit, MAX_QUERY_RESULTS))
    effective_authorities = list(authorities or ())
    if mode in (QueryMode.WHAT_DID_I_SAY, QueryMode.WHAT_DID_I_THINK):
        effective_authorities = [Authority.USER_ASSERTION]
    effective_accesses = list(Access if accesses is None else accesses)
    if not effective_accesses:
        raise ValueError("at least one access classification is required")
    ledger = Ledger(
        settings,
        read_only=True,
        require_checkpointed=require_checkpointed,
        encrypted_evidence_reader=encrypted_evidence_reader,
    )
    baseline_started = time.perf_counter()
    baseline = ledger.retrieve_workset(
        query,
        mode=mode,
        scopes=scopes,
        contexts=context_filters,
        project_id=None,
        authorities=effective_authorities,
        accesses=effective_accesses,
        limit=limit,
        control=control,
        principal=principal,
    )
    baseline_ms = (time.perf_counter() - baseline_started) * 1000
    verification_started = time.perf_counter()
    try:
        active = _load_active_projection(
            ledger,
            runtime=runtime,
            checkout=checkout,
            projection_root=projection_root,
            embedding_artifact=embedding_artifact,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        verification_ms = (time.perf_counter() - verification_started) * 1000
        return _unavailable_shadow_result(
            ledger=ledger,
            baseline=baseline,
            embedding_artifact=embedding_artifact,
            failure_stage="projection_verification",
            exc=exc,
            timing_ms=_shadow_timing(
                overall_started=overall_started,
                baseline_ms=baseline_ms,
                projection_verification_ms=verification_ms,
                candidate_execution_ms=None,
            ),
        )
    verification_ms = (time.perf_counter() - verification_started) * 1000
    request_base = {
        "query": query,
        "mode": mode.value,
        "scopes": [item.value for item in scopes],
        "contexts": [item.as_dict() for item in context_filters],
        "authorities": [item.value for item in effective_authorities],
        "accesses": [item.value for item in effective_accesses],
        "limit": MAX_WORKSET_CANDIDATES,
        "source_systems": [item.value for item in SourceSystem],
    }
    candidate_started = time.perf_counter()
    try:
        manifest_states = _manifest_document_states(active.manifest)
        worker_result = _query_worker(
            runtime=runtime,
            checkout=checkout,
            palace=active.palace_path,
            request=request_base,
            embedding_attestation=cast(
                dict[str, Any] | None,
                active.manifest["embedding_artifact"],
            ),
        )
        hits = _worker_hits(
            worker_result,
            retrieval_mode=cast(str, active.manifest["retrieval_mode"]),
            embedding_attestation=cast(
                dict[str, Any] | None,
                active.manifest["embedding_artifact"],
            ),
        )
        hits_by_source: dict[str, list[dict[str, Any]]] = {
            source_system.value: [] for source_system in SourceSystem
        }
        seen_event_ids: set[str] = set()
        for hit in hits:
            event_id = cast(str, hit["event_id"])
            if event_id in seen_event_ids:
                raise RuntimeError(f"projection returned a duplicate event: {event_id}")
            expected_state = manifest_states.get(event_id)
            if expected_state is None:
                raise RuntimeError(
                    f"projection returned an event absent from its manifest: {event_id}"
                )
            metadata = cast(dict[str, Any], hit["metadata"])
            observed_state = {
                "event_id": metadata.get("event_id"),
                "content_digest": metadata.get("content_digest"),
                "source_system": metadata.get("source_system"),
                "scope": metadata.get("scope"),
                "project_id": metadata.get("project_id") or None,
                "authority": metadata.get("authority"),
                "access": metadata.get("access"),
                "context_state_sha256": metadata.get("context_state_sha256"),
            }
            source_system = metadata.get("source_system")
            if observed_state != expected_state or source_system not in hits_by_source:
                raise RuntimeError(f"projection returned mismatched event metadata: {event_id}")
            seen_event_ids.add(event_id)
            hits_by_source[cast(str, source_system)].append(hit)
        for source_hits in hits_by_source.values():
            if len(source_hits) > MAX_WORKSET_CANDIDATES:
                raise RuntimeError("MemPalace returned more per-source hits than requested")
            if any(
                cast(float, source_hits[index]["score"])
                < cast(float, source_hits[index + 1]["score"])
                for index in range(len(source_hits) - 1)
            ):
                raise RuntimeError("MemPalace returned hits outside descending score order")
        hits.sort(key=lambda item: (-cast(float, item["score"]), cast(str, item["event_id"])))
        ranked_candidates = [
            RetrievalCandidate(event_id=cast(str, hit["event_id"]), score=cast(float, hit["score"]))
            for hit in hits
        ]
        candidate_workset = ledger.retrieve_ranked_workset(
            query,
            candidates=ranked_candidates,
            candidate_id=cast(str, active.manifest["candidate"]),
            mode=mode,
            scopes=scopes,
            contexts=context_filters,
            project_id=None,
            authorities=effective_authorities,
            accesses=effective_accesses,
            limit=limit,
            control=control,
            principal=principal,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        candidate_ms = (time.perf_counter() - candidate_started) * 1000
        return _unavailable_shadow_result(
            ledger=ledger,
            baseline=baseline,
            embedding_artifact=embedding_artifact,
            failure_stage="candidate_execution",
            exc=exc,
            timing_ms=_shadow_timing(
                overall_started=overall_started,
                baseline_ms=baseline_ms,
                projection_verification_ms=verification_ms,
                candidate_execution_ms=candidate_ms,
            ),
        )
    candidate_ms = (time.perf_counter() - candidate_started) * 1000
    candidate_results = cast(list[dict[str, Any]], candidate_workset["results"])
    abstention = _evaluate_active_abstention(
        query=query,
        candidate_results=candidate_results,
        policy=cast(dict[str, Any], active.manifest["abstention_policy"]),
    )
    accepted = cast(bool, abstention["accepted"])
    return {
        "status": (
            "shadow_result"
            if accepted
            else (
                "uncalibrated"
                if active.manifest["abstention_policy"].get("status") == "uncalibrated"
                else "abstained"
            )
        ),
        "shadow_only": True,
        "answer_generation": False,
        "generation": active.generation_path.name,
        "ledger_generation_digest": active.manifest["ledger_generation_digest"],
        "candidate": {
            "id": active.manifest["candidate"],
            "revision": active.manifest["candidate_revision"],
            "retrieval_mode": active.manifest["retrieval_mode"],
            "embedding_artifact": active.manifest["embedding_artifact"],
            "raw_hit_count": len(hits),
            "workset": candidate_workset,
            "worker_resource_usage": _worker_resource_usage(worker_result),
        },
        "baseline": {
            "id": FTS_WORKSET_CANDIDATE_ID,
            "workset": baseline,
        },
        "abstention": abstention,
        "timing_ms": _shadow_timing(
            overall_started=overall_started,
            baseline_ms=baseline_ms,
            projection_verification_ms=verification_ms,
            candidate_execution_ms=candidate_ms,
        ),
    }


def _unavailable_shadow_result(
    *,
    ledger: Ledger,
    baseline: dict[str, Any],
    embedding_artifact: Path | None,
    failure_stage: str,
    exc: Exception,
    timing_ms: dict[str, float | None],
) -> dict[str, Any]:
    retrieval_mode = "semantic" if embedding_artifact is not None else "lexical"
    candidate_id = (
        SHADOW_SEMANTIC_CANDIDATE_ID
        if embedding_artifact is not None
        else SHADOW_LEXICAL_CANDIDATE_ID
    )
    reason = f"optional {retrieval_mode} candidate is unavailable"
    return {
        "status": "candidate_unavailable",
        "shadow_only": True,
        "answer_generation": False,
        "generation": None,
        "ledger_generation_digest": ledger.generation_digest(),
        "candidate": {
            "id": candidate_id,
            "retrieval_mode": retrieval_mode,
            "status": "unavailable",
            "raw_hit_count": 0,
            "workset": None,
        },
        "baseline": {
            "id": FTS_WORKSET_CANDIDATE_ID,
            "workset": baseline,
        },
        "abstention": {
            "accepted": False,
            "status": "unavailable",
            "reason": reason,
        },
        "failure": {
            "stage": failure_stage,
            "class": type(exc).__name__,
            "detail_exposed": False,
        },
        "timing_ms": timing_ms,
    }


def run_shadow_deletion_rebuild_drill(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    event_id: str,
    execute: bool,
    embedding_artifact: Path | None = None,
) -> dict[str, Any]:
    ledger = Ledger(settings, read_only=True)
    active = _load_active_projection(
        ledger,
        runtime=runtime,
        checkout=checkout,
        projection_root=projection_root,
        embedding_artifact=embedding_artifact,
    )
    documents = _manifest_document_digests(active.manifest)
    if event_id not in documents:
        raise KeyError(f"event is absent from the active projection: {event_id}")
    preview = {
        "status": "preview",
        "execute": execute,
        "shadow_only": True,
        "event_id": event_id,
        "source_generation": active.generation_path.name,
        "expected_document_count": len(documents),
    }
    if not execute:
        return preview

    sandbox_root = Path(tempfile.mkdtemp(prefix="cam-shadow-delete-", dir="/private/tmp"))
    try:
        for directory in (
            sandbox_root / "adapter",
            sandbox_root / "work" / "home",
            sandbox_root / "work" / "tmp",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker = sandbox_root / "adapter" / "mempalace_worker.py"
        shutil.copy2(Path(__file__).with_name("mempalace_worker.py"), worker, follow_symlinks=False)
        worker.chmod(0o500)
        palace = sandbox_root / "work" / "palace"
        shutil.copytree(active.palace_path, palace, symlinks=False)
        _make_writable(palace)
        before_path = sandbox_root / "work" / "before.json"
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker,
            palace=palace,
            output=before_path,
            command="inspect",
            command_arguments=["--event-id", event_id],
            sandbox_root=sandbox_root,
            timeout_seconds=60,
        )
        before = _load_worker_output(before_path)
        delete_path = sandbox_root / "work" / "delete.json"
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker,
            palace=palace,
            output=delete_path,
            command="delete",
            command_arguments=["--event-id", event_id],
            sandbox_root=sandbox_root,
            timeout_seconds=60,
        )
        deletion = _load_worker_output(delete_path)
        after_path = sandbox_root / "work" / "after.json"
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker,
            palace=palace,
            output=after_path,
            command="inspect",
            command_arguments=["--event-id", event_id],
            sandbox_root=sandbox_root,
            timeout_seconds=60,
        )
        after = _load_worker_output(after_path)
        expected_count = len(documents)
        if (
            before.get("document_count") != expected_count
            or before.get("present") is not True
            or deletion.get("count_before") != expected_count
            or deletion.get("count_after") != expected_count - 1
            or after.get("document_count") != expected_count - 1
            or after.get("present") is not False
        ):
            raise RuntimeError("MemPalace deletion drill did not prove exact event removal")
    finally:
        if sandbox_root.exists():
            _make_writable(sandbox_root)
            shutil.rmtree(sandbox_root, ignore_errors=True)

    rebuilt = build_shadow_projection(
        settings,
        runtime=runtime,
        checkout=checkout,
        projection_root=projection_root,
        execute=True,
        embedding_artifact=embedding_artifact,
    )
    verified = _load_active_projection(
        ledger,
        runtime=runtime,
        checkout=checkout,
        projection_root=projection_root,
        embedding_artifact=embedding_artifact,
    )
    if event_id not in _manifest_document_digests(verified.manifest):
        raise RuntimeError("rebuilt projection did not restore the deleted canonical event")
    rebuilt_inspection = _inspect_worker(
        runtime=runtime,
        checkout=checkout,
        palace=verified.palace_path,
        event_id=event_id,
    )
    if (
        rebuilt_inspection.get("document_count") != len(documents)
        or rebuilt_inspection.get("present") is not True
    ):
        raise RuntimeError("rebuilt MemPalace data did not restore the deleted canonical event")
    receipt = {
        "format_version": SHADOW_FORMAT_VERSION,
        "created_at": _now(),
        "status": "passed",
        "event_id": event_id,
        "source_generation": active.generation_path.name,
        "source_manifest_sha256": active.manifest_sha256,
        "canonical_document_count": len(documents),
        "deleted_copy_document_count": len(documents) - 1,
        "rebuilt_generation": rebuilt["generation"],
        "rebuilt_manifest_sha256": rebuilt["manifest_sha256"],
        "ledger_generation_digest": ledger.generation_digest(),
    }
    receipt_path = _write_drill_receipt(active.root, receipt)
    return {
        **preview,
        "status": "passed",
        "execute": True,
        "rebuilt_generation": rebuilt["generation"],
        "receipt": str(receipt_path),
        "receipt_sha256": sha256_file(receipt_path),
    }


def rebuild_shadow_projection_after_deletion(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    operation_id: str,
    execute: bool,
    embedding_artifact: Path | None = None,
) -> dict[str, Any]:
    root = _absolute(projection_root)
    if _is_within(root, Path.home().resolve()):
        raise ValueError("projection root must be outside the host user's home")
    if root.exists() or root.is_symlink():
        _validate_existing_projection_root(root)
    if not execute or not root.exists():
        return _rebuild_shadow_projection_after_deletion_locked(
            settings,
            runtime=runtime,
            checkout=checkout,
            projection_root=root,
            operation_id=operation_id,
            execute=execute,
            embedding_artifact=embedding_artifact,
            ledger_writer_locked=False,
        )
    with _exclusive_projection_operation(root), exclusive_ledger_writer(settings):
        return _rebuild_shadow_projection_after_deletion_locked(
            settings,
            runtime=runtime,
            checkout=checkout,
            projection_root=root,
            operation_id=operation_id,
            execute=True,
            embedding_artifact=embedding_artifact,
            ledger_writer_locked=True,
        )


def _rebuild_shadow_projection_after_deletion_locked(
    settings: Settings,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    operation_id: str,
    execute: bool,
    embedding_artifact: Path | None,
    ledger_writer_locked: bool,
) -> dict[str, Any]:
    ledger = Ledger(settings, read_only=True)
    deletion = ledger.completed_deletion_operation(operation_id)
    current_generation = ledger.generation_digest()
    if current_generation != deletion["new_generation_digest"]:
        raise RuntimeError("ledger changed after the completed deletion operation")

    root = projection_root
    if not root.exists():
        return {
            "status": "not_required",
            "execute": execute,
            "shadow_only": True,
            "deletion_operation_id": operation_id,
            "ledger_generation_digest": current_generation,
            "reason": "projection root is absent",
        }

    source_active = _load_optional_active_projection(root)
    source_generation_digest = (
        _required_string(source_active.manifest, "ledger_generation_digest")
        if source_active is not None
        else None
    )
    generation_paths = _projection_generation_paths_if_present(root)
    preview = {
        "status": "preview",
        "execute": execute,
        "shadow_only": True,
        "deletion_operation_id": operation_id,
        "deletion_plan_sha256": deletion["plan_sha256"],
        "previous_ledger_generation_digest": deletion["previous_generation_digest"],
        "ledger_generation_digest": current_generation,
        "source_projection_status": "active" if source_active is not None else "absent",
        "source_projection_generation": (
            source_active.generation_path.name if source_active is not None else None
        ),
        "source_projection_generation_digest": source_generation_digest,
        "source_manifest_sha256": (
            source_active.manifest_sha256 if source_active is not None else None
        ),
        "source_generation_count": len(generation_paths),
        "inactive_generation_count": len(generation_paths) - int(source_active is not None),
        "deleted_event_count": deletion["target_counts"]["events"],
    }
    if not execute:
        return preview

    rebuilt = _build_shadow_projection_locked(
        settings,
        runtime=runtime,
        checkout=checkout,
        projection_root=root,
        execute=True,
        embedding_artifact=embedding_artifact,
        ledger_writer_locked=ledger_writer_locked,
    )
    if Ledger(settings, read_only=True).generation_digest() != current_generation:
        raise RuntimeError("ledger changed while the post-deletion projection was rebuilt")
    verified = _load_active_projection(
        ledger,
        runtime=runtime,
        checkout=checkout,
        projection_root=root,
        embedding_artifact=embedding_artifact,
    )
    if verified.manifest["ledger_generation_digest"] != current_generation:
        raise RuntimeError("rebuilt projection is not bound to the post-deletion ledger")
    purged_generations = _purge_inactive_projection_generations(
        root,
        active_generation=verified.generation_path.name,
    )
    remaining_generations = _projection_generation_paths(root)
    if remaining_generations != [verified.generation_path]:
        raise RuntimeError("inactive projection generation purge is incomplete")

    purged_names = [path.name for path in purged_generations]
    receipt = {
        "format_version": SHADOW_FORMAT_VERSION,
        "created_at": _now(),
        "status": "passed",
        "shadow_only": True,
        "deletion_operation_id": operation_id,
        "deletion_plan_sha256": deletion["plan_sha256"],
        "deletion_target_digest": deletion["target_digest"],
        "previous_ledger_generation_digest": deletion["previous_generation_digest"],
        "ledger_generation_digest": current_generation,
        "deleted_event_count": deletion["target_counts"]["events"],
        "source_projection_status": preview["source_projection_status"],
        "source_projection_generation": preview["source_projection_generation"],
        "source_projection_generation_digest": source_generation_digest,
        "source_manifest_sha256": (
            source_active.manifest_sha256 if source_active is not None else None
        ),
        "rebuilt_generation": rebuilt["generation"],
        "rebuilt_manifest_sha256": verified.manifest_sha256,
        "purged_inactive_generation_count": len(purged_names),
        "purged_generation_names_sha256": _string_list_digest(purged_names),
        "remaining_generation_count": 1,
    }
    receipt_path = _write_deletion_projection_receipt(root, receipt)
    return {
        **preview,
        "status": "passed",
        "execute": True,
        "rebuilt_generation": rebuilt["generation"],
        "rebuilt_manifest_sha256": verified.manifest_sha256,
        "purged_inactive_generation_count": len(purged_names),
        "remaining_generation_count": 1,
        "receipt": str(receipt_path),
        "receipt_sha256": sha256_file(receipt_path),
    }


def evaluate_shadow_abstention(query: str, content_text: str) -> dict[str, Any]:
    query_tokens = _tokens(query)
    matched = sorted(query_tokens & _tokens(content_text))
    coverage = len(matched) / len(query_tokens) if query_tokens else 0.0
    return {
        "matched_query_tokens": matched,
        "matched_query_token_count": len(matched),
        "query_token_coverage": round(coverage, 6),
        "passes_abstention_policy": (
            len(matched) >= MIN_MATCHED_QUERY_TOKENS and coverage >= MIN_QUERY_TOKEN_COVERAGE
        ),
    }


def _load_active_projection(
    ledger: Ledger,
    *,
    runtime: Path,
    checkout: Path,
    projection_root: Path,
    embedding_artifact: Path | None,
) -> ActiveProjection:
    active_projection = _load_active_projection_artifact(projection_root)
    manifest = active_projection.manifest
    embedding_attestation = _embedding_attestation(embedding_artifact)
    expected_candidate = (
        SHADOW_SEMANTIC_CANDIDATE_ID
        if embedding_attestation is not None
        else SHADOW_LEXICAL_CANDIDATE_ID
    )
    expected_mode = "semantic" if embedding_attestation is not None else "lexical"
    if manifest.get("candidate") != expected_candidate:
        raise RuntimeError("projection manifest candidate mismatch")
    if manifest.get("retrieval_mode") != expected_mode:
        raise RuntimeError("projection manifest retrieval mode mismatch")
    if manifest.get("embedding_artifact") != embedding_attestation:
        raise RuntimeError("projection embedding artifact attestation is stale")
    if manifest.get("embedding_runtime") != _expected_worker_embedding_receipt(
        embedding_attestation
    ):
        raise RuntimeError("projection embedding runtime attestation is stale")
    _validate_manifest_abstention_policy(manifest, retrieval_mode=expected_mode)
    if manifest.get("collection") != SHADOW_COLLECTION:
        raise RuntimeError("projection manifest collection mismatch")
    attestation = _candidate_attestation(runtime, checkout)
    if manifest.get("candidate_attestation") != attestation:
        raise RuntimeError("projection candidate attestation is stale")
    worker_sha256 = sha256_file(Path(__file__).with_name("mempalace_worker.py"))
    if manifest.get("worker_sha256") != worker_sha256:
        raise RuntimeError("projection worker changed after the generation was built")
    current_documents = ledger.projection_documents()
    current_states = _document_states(current_documents)
    if manifest.get("document_count") != len(current_states):
        raise RuntimeError("projection document count is stale")
    if manifest.get("document_state_sha256") != _document_state_digest(current_states):
        raise RuntimeError("projection document state is stale")
    if manifest.get("documents") != current_states:
        raise RuntimeError("projection document map is stale")
    generation_digest = ledger.generation_digest()
    if manifest.get("ledger_generation_digest") != generation_digest:
        raise RuntimeError("projection ledger generation is stale")
    active = _load_private_json(active_projection.root / "active.json", MAX_MANIFEST_BYTES)
    if active.get("ledger_generation_digest") != generation_digest:
        raise RuntimeError("active projection pointer is stale")
    return active_projection


def _load_active_projection_artifact(projection_root: Path) -> ActiveProjection:
    root = _absolute(projection_root)
    if (
        root.is_symlink()
        or not root.is_dir()
        or root.resolve() != root
        or _is_within(root, Path.home().resolve())
    ):
        raise RuntimeError(f"projection root is missing or unsafe: {root}")
    active_path = root / "active.json"
    active = _load_private_json(active_path, MAX_MANIFEST_BYTES)
    generation = _required_string(active, "generation")
    if Path(generation).name != generation or generation in {".", ".."}:
        raise RuntimeError("active projection generation path is invalid")
    generation_path = root / "generations" / generation
    if (
        generation_path.is_symlink()
        or not generation_path.is_dir()
        or generation_path.resolve() != generation_path
    ):
        raise RuntimeError("active projection generation is missing or unsafe")
    if any(path.is_symlink() for path in generation_path.rglob("*")):
        raise RuntimeError("active projection generation contains a symlink")
    manifest_path = generation_path / "manifest.json"
    manifest = _load_private_json(manifest_path, MAX_MANIFEST_BYTES)
    manifest_sha256 = sha256_file(manifest_path)
    if manifest_sha256 != _required_string(active, "manifest_sha256"):
        raise RuntimeError("active projection manifest digest mismatch")
    if manifest.get("format_version") != SHADOW_FORMAT_VERSION:
        raise RuntimeError("unsupported shadow projection format")
    if manifest.get("shadow_only") is not True or manifest.get("answer_generation") is not False:
        raise RuntimeError("projection manifest does not preserve the shadow-only boundary")
    expected_files = manifest.get("files")
    if not isinstance(expected_files, list):
        raise RuntimeError("projection manifest file list is invalid")
    if file_entries(generation_path, exclude={"manifest.json"}) != expected_files:
        raise RuntimeError("projection generation file verification failed")
    manifest_generation = _required_string(manifest, "ledger_generation_digest")
    if active.get("ledger_generation_digest") != manifest_generation:
        raise RuntimeError("active projection pointer generation mismatch")
    palace = generation_path / "palace"
    if palace.is_symlink() or not palace.is_dir():
        raise RuntimeError("active MemPalace data directory is missing or unsafe")
    return ActiveProjection(
        root=root,
        generation_path=generation_path,
        palace_path=palace,
        manifest=manifest,
        manifest_sha256=manifest_sha256,
    )


def _query_worker(
    *,
    runtime: Path,
    checkout: Path,
    palace: Path,
    request: dict[str, Any],
    embedding_attestation: dict[str, Any] | None,
) -> dict[str, Any]:
    sandbox_root = Path(tempfile.mkdtemp(prefix="cam-shadow-query-", dir="/private/tmp"))
    try:
        for directory in (
            sandbox_root / "adapter",
            sandbox_root / "input",
            sandbox_root / "work" / "home",
            sandbox_root / "work" / "tmp",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker = sandbox_root / "adapter" / "mempalace_worker.py"
        shutil.copy2(Path(__file__).with_name("mempalace_worker.py"), worker, follow_symlinks=False)
        worker.chmod(0o500)
        worker_embedding_attestation = _stage_worker_embedding_artifact(
            embedding_attestation,
            sandbox_root / "input" / "embedding-artifact",
        )
        request_path = sandbox_root / "input" / "request.json"
        write_json(request_path, request)
        output = sandbox_root / "work" / "result.json"
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker,
            palace=palace,
            output=output,
            command="search",
            command_arguments=["--request", str(request_path)],
            sandbox_root=sandbox_root,
            timeout_seconds=60,
            embedding_attestation=worker_embedding_attestation,
        )
        return _load_worker_output(output)
    finally:
        if sandbox_root.exists():
            _make_writable(sandbox_root)
            shutil.rmtree(sandbox_root, ignore_errors=True)


def _inspect_worker(
    *,
    runtime: Path,
    checkout: Path,
    palace: Path,
    event_id: str,
) -> dict[str, Any]:
    sandbox_root = Path(tempfile.mkdtemp(prefix="cam-shadow-inspect-", dir="/private/tmp"))
    try:
        for directory in (
            sandbox_root / "adapter",
            sandbox_root / "work" / "home",
            sandbox_root / "work" / "tmp",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker = sandbox_root / "adapter" / "mempalace_worker.py"
        shutil.copy2(Path(__file__).with_name("mempalace_worker.py"), worker, follow_symlinks=False)
        worker.chmod(0o500)
        output = sandbox_root / "work" / "result.json"
        _run_worker(
            runtime=runtime,
            checkout=checkout,
            worker=worker,
            palace=palace,
            output=output,
            command="inspect",
            command_arguments=["--event-id", event_id],
            sandbox_root=sandbox_root,
            timeout_seconds=60,
        )
        return _load_worker_output(output)
    finally:
        if sandbox_root.exists():
            _make_writable(sandbox_root)
            shutil.rmtree(sandbox_root, ignore_errors=True)


def _run_worker(
    *,
    runtime: Path,
    checkout: Path,
    worker: Path,
    palace: Path,
    output: Path,
    command: str,
    command_arguments: list[str],
    sandbox_root: Path,
    timeout_seconds: int,
    embedding_attestation: dict[str, Any] | None = None,
) -> None:
    command_line = [
        str(runtime),
        str(worker),
        "--checkout",
        str(checkout),
        "--palace",
        str(palace),
        "--collection",
        SHADOW_COLLECTION,
        "--output",
        str(output),
    ]
    if embedding_attestation is not None:
        command_line.extend(
            [
                "--embedding-artifact",
                _required_string(embedding_attestation, "artifact_root"),
                "--embedding-manifest-sha256",
                _required_string(embedding_attestation, "manifest_sha256"),
                "--embedding-tree-sha256",
                _required_string(embedding_attestation, "artifact_tree_sha256"),
            ]
        )
    command_line.extend([command, *command_arguments])
    profile = sandbox_profile(Path.home(), sandbox_root / "work")
    environment = candidate_environment(
        runtime=runtime,
        sandbox_root=sandbox_root,
        runtime_kind="python",
    )
    try:
        completed = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", profile, *command_line],
            cwd=sandbox_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"MemPalace worker exceeded {timeout_seconds} seconds") from exc
    if completed.returncode:
        raise RuntimeError(f"MemPalace worker exited with status {completed.returncode}")


def _worker_hits(
    result: dict[str, Any],
    *,
    retrieval_mode: str,
    embedding_attestation: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if result.get("status") != "ok":
        raise RuntimeError("MemPalace query did not return an ok status")
    if result.get("retrieval_mode") != retrieval_mode:
        raise RuntimeError("MemPalace query retrieval mode mismatch")
    if result.get("embedding") != _expected_worker_embedding_receipt(embedding_attestation):
        raise RuntimeError("MemPalace query embedding attestation mismatch")
    raw_hits = result.get("hits")
    if not isinstance(raw_hits, list):
        raise RuntimeError("MemPalace query returned an invalid hit list")
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in cast(list[object], raw_hits):
        if not isinstance(raw, dict):
            raise RuntimeError("MemPalace query returned a non-object hit")
        hit = cast(dict[str, Any], raw)
        event_id = _required_string(hit, "event_id")
        score = hit.get("score")
        metadata = hit.get("metadata")
        if event_id in seen:
            raise RuntimeError(f"MemPalace query returned a duplicate event: {event_id}")
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(float(score))
            or (retrieval_mode == "semantic" and not -1.000001 <= float(score) <= 1.000001)
        ):
            raise RuntimeError(f"MemPalace query returned an invalid score: {event_id}")
        if not isinstance(metadata, dict):
            raise RuntimeError(f"MemPalace query returned invalid metadata: {event_id}")
        seen.add(event_id)
        hits.append(
            {
                "event_id": event_id,
                "score": round(float(score), 8),
                "metadata": cast(dict[str, Any], metadata),
            }
        )
    return hits


def _embedding_attestation(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return verify_embedding_artifact(path)


def _stage_worker_embedding_artifact(
    attestation: dict[str, Any] | None,
    destination: Path,
) -> dict[str, Any] | None:
    if attestation is None:
        return None
    staged = stage_verified_embedding_artifact(
        Path(_required_string(attestation, "artifact_root")),
        destination,
        expected_model_id=_required_string(attestation, "model_id"),
        expected_manifest_sha256=_required_string(attestation, "manifest_sha256"),
        expected_tree_sha256=_required_string(attestation, "artifact_tree_sha256"),
    )
    expected = {
        key: value for key, value in attestation.items() if key not in {"artifact_root", "status"}
    }
    observed = {
        key: value for key, value in staged.items() if key not in {"artifact_root", "status"}
    }
    if observed != expected:
        raise RuntimeError("sandboxed embedding artifact attestation changed")
    return staged


def _worker_resource_usage(result: dict[str, Any]) -> dict[str, int]:
    raw = result.get("resource_usage")
    if not isinstance(raw, dict):
        raise RuntimeError("MemPalace worker resource usage is missing")
    usage = cast(dict[str, Any], raw)
    expected: dict[str, int] = {}
    for key in ("cpu_ms", "peak_rss_bytes"):
        value = usage.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError("MemPalace worker resource usage is invalid")
        expected[key] = value
    if usage != expected:
        raise RuntimeError("MemPalace worker resource usage contains unexpected fields")
    return expected


def _shadow_timing(
    *,
    overall_started: float,
    baseline_ms: float,
    projection_verification_ms: float,
    candidate_execution_ms: float | None,
) -> dict[str, float | None]:
    return {
        "raw_fts_baseline": round(baseline_ms, 6),
        "projection_verification": round(projection_verification_ms, 6),
        "candidate_execution": (
            round(candidate_execution_ms, 6) if candidate_execution_ms is not None else None
        ),
        "total": round((time.perf_counter() - overall_started) * 1000, 6),
    }


def _expected_worker_embedding_receipt(
    attestation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if attestation is None:
        return None
    adapter_raw = attestation.get("adapter")
    versions_raw = attestation.get("runtime_versions")
    if not isinstance(adapter_raw, dict) or not isinstance(versions_raw, dict):
        raise RuntimeError("embedding artifact attestation is incomplete")
    adapter = cast(dict[str, Any], adapter_raw)
    versions = cast(dict[str, Any], versions_raw)
    return {
        "model_id": _required_string(attestation, "model_id"),
        "manifest_sha256": _required_string(attestation, "manifest_sha256"),
        "artifact_tree_sha256": _required_string(attestation, "artifact_tree_sha256"),
        "adapter_id": _required_string(adapter, "id"),
        "dimensions": _positive_integer(adapter, "dimensions"),
        "max_tokens": _positive_integer(adapter, "max_tokens"),
        "batch_size": _positive_integer(adapter, "batch_size"),
        "pooling": _required_string(adapter, "pooling"),
        "normalization": _required_string(adapter, "normalization"),
        "long_input_policy": _required_string(adapter, "long_input_policy"),
        "runtime": {
            "versions": versions,
            "provider": "CPUExecutionProvider",
            "intra_op_threads": 2,
            "inter_op_threads": 1,
        },
        "trust_remote_code": False,
        "network_required": False,
    }


def _abstention_policy(
    *,
    retrieval_mode: str,
) -> dict[str, Any]:
    if retrieval_mode == "lexical":
        return {
            "kind": "lexical_overlap",
            "status": "calibrated",
            "minimum_matched_query_tokens": MIN_MATCHED_QUERY_TOKENS,
            "minimum_query_token_coverage": MIN_QUERY_TOKEN_COVERAGE,
        }
    if retrieval_mode != "semantic":
        raise ValueError(f"unsupported shadow retrieval mode: {retrieval_mode}")
    return {
        "kind": "cosine_similarity",
        "status": "uncalibrated",
        "minimum_similarity": None,
    }


def _validate_manifest_abstention_policy(
    manifest: dict[str, Any],
    *,
    retrieval_mode: str,
) -> None:
    raw = manifest.get("abstention_policy")
    if not isinstance(raw, dict):
        raise RuntimeError("projection abstention policy is invalid")
    policy = cast(dict[str, Any], raw)
    try:
        expected = _abstention_policy(retrieval_mode=retrieval_mode)
    except ValueError as exc:
        raise RuntimeError("projection abstention policy is invalid") from exc
    if policy != expected:
        raise RuntimeError("projection abstention policy is invalid")


def _evaluate_active_abstention(
    *,
    query: str,
    candidate_results: list[dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    if policy.get("kind") == "lexical_overlap":
        top = (
            evaluate_shadow_abstention(
                query,
                _required_string(candidate_results[0], "content_text"),
            )
            if candidate_results
            else None
        )
        accepted = bool(top and top["passes_abstention_policy"])
        return {
            "accepted": accepted,
            "status": "calibrated",
            "reason": (None if accepted else "no top hit met both lexical overlap thresholds"),
            "minimum_matched_query_tokens": MIN_MATCHED_QUERY_TOKENS,
            "minimum_query_token_coverage": MIN_QUERY_TOKEN_COVERAGE,
            "top_hit": top,
        }
    if policy.get("kind") != "cosine_similarity":
        raise RuntimeError("projection abstention policy kind is unsupported")
    top_similarity: float | None = None
    if candidate_results:
        rank = candidate_results[0].get("rank")
        if isinstance(rank, bool) or not isinstance(rank, (int, float)) or not math.isfinite(rank):
            raise RuntimeError("semantic candidate top score is invalid")
        top_similarity = float(rank)
    minimum = policy.get("minimum_similarity")
    accepted = (
        top_similarity is not None
        and isinstance(minimum, (int, float))
        and not isinstance(minimum, bool)
        and top_similarity >= float(minimum)
    )
    if policy.get("status") == "uncalibrated":
        reason = "semantic projection has not been calibrated on the development split"
    elif top_similarity is None:
        reason = "semantic projection returned no policy-valid hit"
    elif not accepted:
        reason = "top semantic hit was below the calibrated similarity threshold"
    else:
        reason = None
    return {
        "accepted": accepted,
        "status": policy.get("status"),
        "reason": reason,
        "minimum_similarity": minimum,
        "top_similarity": top_similarity,
    }


def _candidate_attestation(runtime: Path, checkout: Path) -> dict[str, str]:
    spec = FROZEN_CANDIDATES[SHADOW_CANDIDATE_ID]
    preflight = candidate_preflight(spec, runtime=runtime, checkout=checkout)
    return {
        "candidate_revision": spec.revision,
        "candidate_tree": preflight["candidate_tree"],
        "candidate_lockfile": spec.lockfile,
        "candidate_lockfile_sha256": preflight["candidate_lockfile_sha256"],
        "candidate_required_path": spec.required_path,
        "candidate_required_path_sha256": preflight["candidate_required_path_sha256"],
        "candidate_build_tree_sha256": preflight["candidate_build_tree_sha256"],
        "runtime_path": str(runtime),
        "runtime_resolved_path": preflight["runtime_resolved_path"],
        "runtime_sha256": sha256_file(runtime),
        "runtime_version": preflight["runtime_version"],
    }


def _document_states(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    states = [
        {
            "event_id": _required_string(document, "event_id"),
            "content_digest": _required_string(document, "content_digest"),
            "source_system": _required_string(document, "source_system"),
            "scope": _required_string(document, "scope"),
            "project_id": _optional_manifest_string(document, "project_id"),
            "authority": _required_string(document, "authority"),
            "access": _required_string(document, "access"),
            "context_state_sha256": _context_state_digest(document),
        }
        for document in documents
    ]
    states.sort(key=lambda item: cast(str, item["event_id"]))
    if len({item["event_id"] for item in states}) != len(states):
        raise RuntimeError("canonical projection documents contain duplicate event ids")
    return states


def _document_state_digest(states: list[dict[str, Any]]) -> str:
    payload = "".join(
        json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n" for item in states
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _manifest_document_digests(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        event_id: _required_string(state, "content_digest")
        for event_id, state in _manifest_document_states(manifest).items()
    }


def _manifest_document_states(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_documents = manifest.get("documents")
    if not isinstance(raw_documents, list):
        raise RuntimeError("projection manifest document map is invalid")
    documents: dict[str, dict[str, Any]] = {}
    for raw in cast(list[object], raw_documents):
        if not isinstance(raw, dict):
            raise RuntimeError("projection manifest document entry is invalid")
        entry = cast(dict[str, Any], raw)
        event_id = _required_string(entry, "event_id")
        if event_id in documents:
            raise RuntimeError(f"projection manifest repeats an event: {event_id}")
        state = {
            "event_id": event_id,
            "content_digest": _required_string(entry, "content_digest"),
            "source_system": _required_string(entry, "source_system"),
            "scope": _required_string(entry, "scope"),
            "project_id": _optional_manifest_string(entry, "project_id"),
            "authority": _required_string(entry, "authority"),
            "access": _required_string(entry, "access"),
            "context_state_sha256": _required_string(entry, "context_state_sha256"),
        }
        if entry != state:
            raise RuntimeError(f"projection manifest has an invalid event state: {event_id}")
        documents[event_id] = state
    return documents


def _context_state_digest(document: dict[str, Any]) -> str:
    raw_contexts = document.get("contexts")
    if not isinstance(raw_contexts, list):
        raise RuntimeError("projection document contexts must be a list")
    contexts: list[dict[str, str]] = []
    for raw in cast(list[object], raw_contexts):
        if not isinstance(raw, dict):
            raise RuntimeError("projection document context must be an object")
        value = cast(dict[str, Any], raw)
        context = {
            "kind": _required_string(value, "kind"),
            "key": _required_string(value, "key"),
        }
        if value != context:
            raise RuntimeError("projection document context has unexpected fields")
        contexts.append(context)
    contexts.sort(key=lambda item: (item["kind"], item["key"]))
    if len({(item["kind"], item["key"]) for item in contexts}) != len(contexts):
        raise RuntimeError("projection document contexts contain duplicates")
    payload = json.dumps(contexts, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _write_active_pointer(
    root: Path,
    *,
    generation: str,
    manifest_sha256: str,
    ledger_generation_digest: str,
) -> None:
    active = root / "active.json"
    if active.is_symlink():
        raise RuntimeError("active projection pointer must not be a symlink")
    temporary = root / f".active-{uuid.uuid4()}.json"
    write_json(
        temporary,
        {
            "format_version": SHADOW_FORMAT_VERSION,
            "updated_at": _now(),
            "generation": generation,
            "manifest_sha256": manifest_sha256,
            "ledger_generation_digest": ledger_generation_digest,
        },
    )
    os.replace(temporary, active)
    active.chmod(0o600)


def _write_drill_receipt(root: Path, receipt: dict[str, Any]) -> Path:
    receipts = root / "drills"
    receipts.mkdir(mode=0o700, exist_ok=True)
    receipts.chmod(0o700)
    path = receipts / f"deletion-rebuild-{uuid.uuid4()}.json"
    write_json(path, receipt)
    path.chmod(0o400)
    return path


def _write_deletion_projection_receipt(root: Path, receipt: dict[str, Any]) -> Path:
    receipts = root / "deletion-rebuilds"
    if receipts.is_symlink() or (receipts.exists() and not receipts.is_dir()):
        raise RuntimeError("projection deletion receipt directory is unsafe")
    receipts.mkdir(mode=0o700, exist_ok=True)
    receipts.chmod(0o700)
    path = receipts / f"deletion-rebuild-{uuid.uuid4()}.json"
    write_json(path, receipt)
    path.chmod(0o400)
    return path


def _projection_generation_paths(root: Path) -> list[Path]:
    generations = root / "generations"
    if generations.is_symlink() or not generations.is_dir() or generations.resolve() != generations:
        raise RuntimeError("projection generations directory is missing or unsafe")
    paths = sorted(generations.iterdir(), key=lambda path: path.name)
    for path in paths:
        if path.is_symlink() or not path.is_dir() or path.resolve() != path:
            raise RuntimeError("projection generations directory contains an unsafe entry")
        _validate_generation_tree_for_purge(path)
    return paths


def _projection_generation_paths_if_present(root: Path) -> list[Path]:
    generations = root / "generations"
    if not generations.exists() and not generations.is_symlink():
        return []
    return _projection_generation_paths(root)


def _load_optional_active_projection(root: Path) -> ActiveProjection | None:
    active = root / "active.json"
    if not active.exists() and not active.is_symlink():
        return None
    return _load_active_projection_artifact(root)


def _validate_generation_tree_for_purge(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("projection generation contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1:
            raise RuntimeError("projection generation contains an unsafe file")


def _purge_inactive_projection_generations(
    root: Path,
    *,
    active_generation: str,
) -> list[Path]:
    paths = _projection_generation_paths(root)
    active_path = root / "generations" / active_generation
    if active_path not in paths:
        raise RuntimeError("active projection generation is absent from its generation directory")
    inactive = [path for path in paths if path != active_path]
    for path in inactive:
        _validate_generation_tree_for_purge(path)
        _make_writable(path)
        shutil.rmtree(path)
        if path.exists() or path.is_symlink():
            raise RuntimeError("inactive projection generation purge is incomplete")
    return inactive


def _string_list_digest(values: list[str]) -> str:
    payload = json.dumps(sorted(values), separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _prepare_projection_root(path: Path) -> Path:
    root = _absolute(path)
    if root.is_symlink() or root.resolve() != root:
        raise ValueError("projection root and its parents must not be symlinks")
    if _is_within(root, Path.home().resolve()):
        raise ValueError("projection root must be outside the host user's home")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _validate_existing_projection_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise RuntimeError(f"projection root is missing or unsafe: {root}")


@contextmanager
def _exclusive_projection_operation(root: Path) -> Generator[None]:
    lock_path = root / "operation.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_uid != os.getuid()
        ):
            raise ValueError("projection operation lock must be an owner-private regular file")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _load_worker_output(path: Path) -> dict[str, Any]:
    return _load_private_json(path, MAX_WORKER_OUTPUT_BYTES)


def _load_private_json(path: Path, max_bytes: int) -> dict[str, Any]:
    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected a regular JSON file: {path}")
    if path.stat().st_size > max_bytes:
        raise RuntimeError(f"JSON file exceeds its size limit: {path}")
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"expected a JSON object: {path}")
    return cast(dict[str, Any], raw)


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise RuntimeError(f"{key} must be a non-empty string")
    return item


def _positive_integer(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int) or item < 1:
        raise RuntimeError(f"{key} must be a positive integer")
    return item


def _optional_manifest_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise RuntimeError(f"{key} must be null or a non-empty string")
    return item


def _tokens(value: str) -> set[str]:
    return {
        token.casefold()
        for token in TOKEN_PATTERN.findall(value)
        if len(token) >= 2 and token.casefold() not in STOP_TOKENS
    }


def _make_writable(root: Path) -> None:
    if not root.exists():
        return
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


def _now() -> str:
    return datetime.now(UTC).isoformat()
