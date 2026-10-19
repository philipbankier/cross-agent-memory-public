from __future__ import annotations

import hashlib
import math
import os
import platform
import resource
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.evaluation import (
    EVALUATION_FORMAT_VERSION,
    directory_bytes,
    file_entries,
    latency_summary,
    load_json_object,
    now,
    read_jsonl,
    set_read_only_tree,
    sha256_file,
    verify_evaluation_bundle,
    write_json,
    write_jsonl,
)


@dataclass(frozen=True)
class CandidateSpec:
    candidate_id: str
    revision: str
    adapter: str
    runtime_kind: str
    lockfile: str
    required_path: str


FROZEN_CANDIDATES = {
    "memorix-fast": CandidateSpec(
        candidate_id="memorix-fast",
        revision="1d4fff784ab5e12ad1890a5f3528f61ea0bfc1d4",
        adapter="memorix_fast.mjs",
        runtime_kind="node",
        lockfile="package-lock.json",
        required_path="dist/sdk.js",
    ),
    "mempalace-sqlite-exact": CandidateSpec(
        candidate_id="mempalace-sqlite-exact",
        revision="759b1273d3fc92721596938a57168b1314e77f41",
        adapter="mempalace_sqlite_exact.py",
        runtime_kind="python",
        lockfile="uv.lock",
        required_path="mempalace/backends/sqlite_exact.py",
    ),
}


def run_sandboxed_candidate(
    *,
    bundle: Path,
    output: Path,
    candidate_id: str,
    runtime: Path,
    checkout: Path,
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    spec = FROZEN_CANDIDATES.get(candidate_id)
    if spec is None:
        raise ValueError(f"unknown frozen candidate: {candidate_id}")
    if timeout_seconds < 1 or timeout_seconds > 7200:
        raise ValueError("candidate timeout must be between 1 and 7200 seconds")

    bundle = bundle.expanduser().resolve()
    output = output.expanduser().resolve()
    runtime = Path(os.path.abspath(runtime.expanduser()))
    checkout = checkout.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise ValueError(f"run output already exists: {output}")
    bundle_verification = verify_evaluation_bundle(bundle)
    preflight = candidate_preflight(spec, runtime=runtime, checkout=checkout)

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_output = Path(tempfile.mkdtemp(prefix=f".{output.name}.running-", dir=output.parent))
    sandbox_root = Path(tempfile.mkdtemp(prefix=f"cam-eval-{candidate_id}-", dir="/private/tmp"))
    run_initialized = False
    started_at = now()
    run_started = time.perf_counter()
    try:
        for directory in (
            temporary_output / "config",
            temporary_output / "logs",
            temporary_output / "receipts",
            sandbox_root / "work" / "home",
            sandbox_root / "work" / "tmp",
            sandbox_root / "work" / "data",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        run_initialized = True

        candidate_input = sandbox_root / "input"
        shutil.copytree(bundle / "candidate", candidate_input, symlinks=False)
        adapter_source = (
            Path(__file__).resolve().parents[2] / "evaluation" / "adapters" / spec.adapter
        )
        adapter_copy = sandbox_root / "adapter" / spec.adapter
        adapter_copy.parent.mkdir(mode=0o700, parents=True)
        shutil.copy2(adapter_source, adapter_copy, follow_symlinks=False)
        adapter_copy.chmod(0o500)

        raw_results = sandbox_root / "work" / "adapter-results.jsonl"
        adapter_receipt = sandbox_root / "work" / "adapter-receipt.json"
        command = [
            str(runtime),
            str(adapter_copy),
            "--candidate-dir",
            str(candidate_input),
            "--work-dir",
            str(sandbox_root / "work" / "data"),
            "--output",
            str(raw_results),
            "--receipt",
            str(adapter_receipt),
            "--checkout",
            str(checkout),
            "--candidate-revision",
            spec.revision,
        ]
        sandbox_profile_value = sandbox_profile(Path.home(), sandbox_root / "work")
        sandbox_receipt = probe_sandbox(
            profile=sandbox_profile_value,
            denied_read=bundle / "candidate" / "manifest.json",
            sandbox_root=sandbox_root,
        )
        write_json(temporary_output / "receipts" / "sandbox.json", sandbox_receipt)
        environment = candidate_environment(
            runtime=runtime,
            sandbox_root=sandbox_root,
            runtime_kind=spec.runtime_kind,
        )
        before_children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        try:
            completed = subprocess.run(
                ["/usr/bin/sandbox-exec", "-p", sandbox_profile_value, *command],
                cwd=sandbox_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            (temporary_output / "logs" / "stdout.log").write_text(
                _timeout_text(exc.stdout), encoding="utf-8"
            )
            (temporary_output / "logs" / "stderr.log").write_text(
                _timeout_text(exc.stderr), encoding="utf-8"
            )
            raise RuntimeError(
                f"candidate adapter exceeded {timeout_seconds} second timeout"
            ) from exc
        after_children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        (temporary_output / "logs" / "stdout.log").write_text(completed.stdout, encoding="utf-8")
        (temporary_output / "logs" / "stderr.log").write_text(completed.stderr, encoding="utf-8")
        if completed.returncode:
            raise RuntimeError(f"candidate adapter exited with status {completed.returncode}")
        if (
            not raw_results.is_file()
            or raw_results.is_symlink()
            or raw_results.stat().st_size > 10 * 1024 * 1024
            or not adapter_receipt.is_file()
            or adapter_receipt.is_symlink()
            or adapter_receipt.stat().st_size > 1024 * 1024
        ):
            raise RuntimeError("candidate adapter did not produce its required outputs")

        receipt = load_json_object(adapter_receipt)
        _validate_adapter_receipt(receipt, spec, bundle_verification)
        raw_rows = read_jsonl(raw_results)
        standardized, security_rows = standardize_candidate_results(
            candidate_dir=candidate_input,
            raw_results=raw_rows,
        )
        write_jsonl(temporary_output / "retrieval-results.jsonl", standardized)
        write_jsonl(temporary_output / "answer-results.jsonl", [])
        write_jsonl(temporary_output / "security-results.jsonl", security_rows)
        shutil.copy2(raw_results, temporary_output / "logs" / "adapter-results.jsonl")
        shutil.copy2(adapter_receipt, temporary_output / "receipts" / "adapter.json")

        config = {
            "candidate": spec.candidate_id,
            "candidate_revision": spec.revision,
            "candidate_tree": preflight["candidate_tree"],
            "candidate_lockfile": spec.lockfile,
            "candidate_lockfile_sha256": preflight["candidate_lockfile_sha256"],
            "candidate_required_path": spec.required_path,
            "candidate_required_path_sha256": preflight["candidate_required_path_sha256"],
            "candidate_build_tree_sha256": preflight["candidate_build_tree_sha256"],
            "adapter": spec.adapter,
            "adapter_sha256": sha256_file(adapter_source),
            "runtime_kind": spec.runtime_kind,
            "runtime_path": str(runtime),
            "runtime_resolved_path": preflight["runtime_resolved_path"],
            "runtime_sha256": sha256_file(runtime),
            "runtime_version": preflight["runtime_version"],
            "query_trials": 2,
            "phases": ["cold", "warm"],
            "answer_generation": False,
            "internet_used_during_retrieval": False,
            "sandbox": {
                "engine": "macos-sandbox-exec",
                "network": "deny-default",
                "home_read": "denied",
                "writes": "isolated-work-directory-only",
            },
        }
        write_json(temporary_output / "config" / "candidate.json", config)
        write_json(
            temporary_output / "environment.json",
            {
                "captured_at": now(),
                "hostname": platform.node(),
                "platform": platform.platform(),
                "pid": os.getpid(),
            },
        )
        latencies: dict[str, list[float]] = {"cold": [], "warm": []}
        for row in standardized:
            latencies[cast(str, row["phase"])].append(cast(float, row["latency_ms"]))
        metrics = {
            "status": "retrieval_only_unscored",
            "ingestion_seconds": _nonnegative_number(receipt, "ingestion_seconds"),
            "source_count": bundle_verification["source_count"],
            "document_count": bundle_verification["document_count"],
            "query_count": bundle_verification["query_count"],
            "cold_latency_ms": latency_summary(latencies["cold"]),
            "warm_latency_ms": latency_summary(latencies["warm"]),
            "peak_child_rss_bytes": _rss_bytes(max(before_children, after_children)),
            "index_bytes": directory_bytes(sandbox_root / "work"),
            "unsupported_results": sum(
                1 for item in standardized if item["status"] == "unsupported"
            ),
            "security_violation_count": sum(
                cast(int, row.get("count", 0)) for row in security_rows if row["status"] == "fail"
            ),
            "wall_seconds": round(time.perf_counter() - run_started, 6),
        }
        write_json(temporary_output / "metrics.json", metrics)
        (temporary_output / "report.md").write_text(
            f"# {spec.candidate_id} Retrieval Run\n\n"
            "Status: retrieval-only, unscored\n\n"
            "The candidate received only the normalized candidate corpus. macOS sandbox policy "
            "denied network access, denied reads from the host user's home directory, and limited "
            "writes to the isolated run workspace. The answer key was not present on this host.\n",
            encoding="utf-8",
        )
        run_manifest = {
            "format_version": EVALUATION_FORMAT_VERSION,
            "run_id": output.name,
            "created_at": started_at,
            "candidate": spec.candidate_id,
            "candidate_revision": spec.revision,
            "corpus_manifest_sha256": bundle_verification["manifest_sha256"],
            "candidate_manifest_sha256": bundle_verification["candidate_manifest_sha256"],
            "answer_key_plaintext_sha256": bundle_verification["answer_key_plaintext_sha256"],
            "config_sha256": sha256_file(temporary_output / "config" / "candidate.json"),
            "files": file_entries(temporary_output, exclude={"manifest.json"}),
        }
        write_json(temporary_output / "manifest.json", run_manifest)
        os.replace(temporary_output, output)
        set_read_only_tree(output)
        return {
            "status": "completed_unscored",
            "run": str(output),
            "manifest_sha256": sha256_file(output / "manifest.json"),
            "metrics": metrics,
        }
    except Exception as exc:
        if run_initialized:
            _preserve_failed_run(
                temporary_output=temporary_output,
                output=output,
                spec=spec,
                started_at=started_at,
                bundle_verification=bundle_verification,
                error=str(exc),
                elapsed=time.perf_counter() - run_started,
            )
            raise RuntimeError(
                f"candidate run failed; artifacts preserved at {output}: {exc}"
            ) from exc
        if temporary_output.exists():
            shutil.rmtree(temporary_output, ignore_errors=True)
        raise
    finally:
        if sandbox_root.exists():
            shutil.rmtree(sandbox_root, ignore_errors=True)


def candidate_preflight(
    spec: CandidateSpec,
    *,
    runtime: Path,
    checkout: Path,
) -> dict[str, str]:
    if shutil.which("sandbox-exec") != "/usr/bin/sandbox-exec":
        raise RuntimeError("/usr/bin/sandbox-exec is required for candidate isolation")
    home = Path.home().resolve()
    try:
        runtime_target = runtime.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"candidate runtime cannot be resolved: {runtime}") from exc
    if _is_within(runtime, home) or _is_within(runtime_target, home) or _is_within(checkout, home):
        raise ValueError("candidate runtime and checkout must be outside the host user's home")
    if not runtime.is_file() or not os.access(runtime, os.X_OK):
        raise ValueError(f"candidate runtime is not executable: {runtime}")
    if not checkout.is_dir() or not (checkout / ".git").exists():
        raise ValueError(f"candidate checkout is not a Git repository: {checkout}")
    lockfile = checkout / spec.lockfile
    if not lockfile.is_file():
        raise ValueError(f"candidate lockfile is missing: {lockfile}")
    required_path = checkout / spec.required_path
    if not required_path.exists():
        raise ValueError(f"candidate build/source artifact is missing: {required_path}")
    revision = _git(checkout, "rev-parse", "HEAD")
    if revision != spec.revision:
        raise ValueError(f"candidate revision mismatch: expected {spec.revision}, got {revision}")
    tracked_status = _git(checkout, "status", "--porcelain", "--untracked-files=no")
    if tracked_status:
        raise ValueError("candidate checkout has tracked modifications")
    runtime_probe = subprocess.run(
        [str(runtime), "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    if runtime_probe.returncode:
        raise RuntimeError(f"candidate runtime version probe failed: {runtime}")
    return {
        "candidate_tree": _git(checkout, "rev-parse", "HEAD^{tree}"),
        "candidate_lockfile_sha256": sha256_file(lockfile),
        "candidate_required_path_sha256": sha256_file(required_path),
        "candidate_build_tree_sha256": _tree_digest(
            checkout / "dist" if spec.runtime_kind == "node" else required_path
        ),
        "runtime_resolved_path": str(runtime_target),
        "runtime_version": (runtime_probe.stdout or runtime_probe.stderr).strip(),
    }


def standardize_candidate_results(
    *, candidate_dir: Path, raw_results: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    queries = read_jsonl(candidate_dir / "queries.jsonl")
    documents = read_jsonl(candidate_dir / "documents.jsonl")
    document_by_id = {_required_string(item, "document_id"): item for item in documents}
    query_by_id = {_required_string(item, "query_id"): item for item in queries}
    if len(query_by_id) != len(queries):
        raise ValueError("candidate query file contains duplicate query ids")

    expected = {(query_id, phase) for query_id in query_by_id for phase in ("cold", "warm")}
    actual: set[tuple[str, str]] = set()
    standardized: list[dict[str, Any]] = []
    violations: list[dict[str, str]] = []
    evidence_cache: dict[str, bool] = {}
    for raw in raw_results:
        query_id = _required_string(raw, "query_id")
        phase = _required_string(raw, "phase")
        key = (query_id, phase)
        if key in actual:
            raise ValueError(f"duplicate candidate result: {query_id}/{phase}")
        if key not in expected:
            raise ValueError(f"unexpected candidate result: {query_id}/{phase}")
        actual.add(key)
        query = query_by_id[query_id]
        status = _required_string(raw, "status")
        if status not in {"ok", "unsupported", "error"}:
            raise ValueError(f"invalid candidate result status: {status}")
        latency_ms = raw.get("latency_ms")
        if (
            isinstance(latency_ms, bool)
            or not isinstance(latency_ms, (int, float))
            or not math.isfinite(latency_ms)
            or latency_ms < 0
        ):
            raise ValueError(f"invalid candidate latency: {query_id}/{phase}")
        error = raw.get("error")
        if error is not None and not isinstance(error, str):
            raise ValueError(f"invalid candidate error: {query_id}/{phase}")
        if status == "ok" and error is not None:
            raise ValueError(f"successful candidate result contains an error: {query_id}/{phase}")
        if status != "ok" and not error:
            raise ValueError(f"failed candidate result omits its error: {query_id}/{phase}")
        raw_document_ids = raw.get("document_ids")
        if not isinstance(raw_document_ids, list):
            raise ValueError(f"invalid candidate document ids: {query_id}/{phase}")
        untyped_document_ids = cast(list[object], raw_document_ids)
        if any(not isinstance(item, str) or not item for item in untyped_document_ids):
            raise ValueError(f"invalid candidate document ids: {query_id}/{phase}")
        document_ids = cast(list[str], raw_document_ids)
        if len(document_ids) != len(set(document_ids)):
            raise ValueError(f"duplicate candidate document id: {query_id}/{phase}")
        limit = query.get("limit", 5)
        if isinstance(limit, bool) or not isinstance(limit, int) or len(document_ids) > limit:
            raise ValueError(f"candidate result exceeds query limit: {query_id}/{phase}")
        if status != "ok" and document_ids:
            raise ValueError(f"non-ok candidate result returned documents: {query_id}/{phase}")

        normalized_results: list[dict[str, Any]] = []
        for rank, document_id in enumerate(document_ids, start=1):
            document = document_by_id.get(document_id)
            if document is None:
                raise ValueError(f"candidate returned an unknown document id: {document_id}")
            evidence_verified = evidence_cache.get(document_id)
            if evidence_verified is None:
                evidence_verified = _verify_candidate_evidence(candidate_dir, document)
                evidence_cache[document_id] = evidence_verified
            reasons = _result_policy_violations(query, document)
            for reason in reasons:
                violations.append(
                    {
                        "query_id": query_id,
                        "phase": phase,
                        "document_id": document_id,
                        "reason": reason,
                    }
                )
            normalized_results.append(
                {
                    "rank": rank,
                    "document_id": document_id,
                    "event_id": _required_string(document, "event_id"),
                    "authority": _required_string(document, "authority"),
                    "scope": _required_string(document, "scope"),
                    "project_id": document.get("project_id"),
                    "source_object_id": _required_string(document, "source_object_id"),
                    "record_ordinal": _required_int(document, "record_ordinal"),
                    "evidence_verified": evidence_verified,
                }
            )
        standardized.append(
            {
                "query_id": query_id,
                "split": _required_string(query, "split"),
                "suite": _required_string(query, "suite"),
                "trial": 1 if phase == "cold" else 2,
                "phase": phase,
                "status": status,
                "error": error,
                "latency_ms": round(float(latency_ms), 6),
                "results": normalized_results,
            }
        )
    if actual != expected:
        raise ValueError(f"candidate result set is incomplete: missing={sorted(expected - actual)}")
    standardized.sort(
        key=lambda item: (
            next(
                index
                for index, query in enumerate(queries)
                if query["query_id"] == item["query_id"]
            ),
            0 if item["phase"] == "cold" else 1,
        )
    )
    evidence_failures = sum(
        1
        for item in standardized
        for result in cast(list[dict[str, Any]], item["results"])
        if result["evidence_verified"] is not True
    )
    security_rows = [
        {
            "check": "scope_and_authority_filters",
            "status": "pass" if not violations else "fail",
            "count": len(violations),
            "violations": violations,
        },
        {
            "check": "evidence_hashes",
            "status": "pass" if evidence_failures == 0 else "fail",
            "count": evidence_failures,
        },
        {
            "check": "network_access",
            "status": "pass",
            "count": 0,
            "enforcement": "macos sandbox default-deny",
        },
        {
            "check": "write_boundary",
            "status": "pass",
            "count": 0,
            "enforcement": "macos sandbox isolated work directory",
        },
        {"check": "instruction_execution", "status": "not_exercised", "count": 0},
        {"check": "deletion_rebuild", "status": "not_exercised", "count": 0},
        {"check": "oauth_and_origin_bypass", "status": "not_exercised", "count": 0},
    ]
    return standardized, security_rows


def _result_policy_violations(query: dict[str, Any], document: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    scopes = query.get("scopes")
    if not isinstance(scopes, list) or document.get("scope") not in scopes:
        violations.append("scope")
    if document.get("scope") == "project" and document.get("project_id") != query.get("project_id"):
        violations.append("project")
    authorities = query.get("authorities")
    if not isinstance(authorities, list):
        raise ValueError("query authorities must be a list")
    if query.get("mode") in {"what_did_i_say", "what_did_i_think"}:
        authorities = ["user_assertion"]
    if authorities and document.get("authority") not in authorities:
        violations.append("authority")
    return violations


def _verify_candidate_evidence(candidate_dir: Path, document: dict[str, Any]) -> bool:
    relative = Path(_required_string(document, "evidence_path"))
    evidence = (candidate_dir / relative).resolve()
    if not _is_within(evidence, candidate_dir.resolve()) or evidence.is_symlink():
        return False
    object_id = _required_string(document, "source_object_id")
    if not object_id.startswith("sha256:"):
        return False
    return evidence.is_file() and sha256_file(evidence) == object_id.removeprefix("sha256:")


def _validate_adapter_receipt(
    receipt: dict[str, Any], spec: CandidateSpec, bundle: dict[str, Any]
) -> None:
    if receipt.get("candidate") != spec.candidate_id:
        raise ValueError("adapter receipt candidate mismatch")
    if receipt.get("candidate_revision") != spec.revision:
        raise ValueError("adapter receipt revision mismatch")
    if receipt.get("document_count") != bundle["document_count"]:
        raise ValueError("adapter receipt document count mismatch")
    if receipt.get("query_count") != bundle["query_count"]:
        raise ValueError("adapter receipt query count mismatch")
    _nonnegative_number(receipt, "ingestion_seconds")


def candidate_environment(
    *, runtime: Path, sandbox_root: Path, runtime_kind: str
) -> dict[str, str]:
    environment = {
        "PATH": f"{runtime.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(sandbox_root / "work" / "home"),
        "TMPDIR": str(sandbox_root / "work" / "tmp"),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "MEMORIX_EMBEDDING": "off",
        "MEMPALACE_BACKEND": "sqlite_exact",
    }
    if runtime_kind == "node":
        environment["NODE_NO_WARNINGS"] = "1"
    return environment


def probe_sandbox(*, profile: str, denied_read: Path, sandbox_root: Path) -> dict[str, Any]:
    home = Path.home().resolve()
    denied_read = denied_read.resolve()
    if not _is_within(denied_read, home) or not denied_read.is_file():
        raise RuntimeError("sandbox home-read probe requires a real file inside the host home")
    if not os.access(denied_read, os.R_OK):
        raise RuntimeError("sandbox home-read probe file is not readable outside the sandbox")

    writable_root = sandbox_root / "work"
    allowed_write = writable_root / "sandbox-write-canary"
    denied_write = sandbox_root / "sandbox-write-escape"
    read_probe = _run_sandbox_probe(profile, ["/bin/cat", str(denied_read)])
    write_probe = _run_sandbox_probe(profile, ["/usr/bin/touch", str(denied_write)])
    allowed_probe = _run_sandbox_probe(profile, ["/usr/bin/touch", str(allowed_write)])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        network_probe = _run_sandbox_probe(
            profile,
            ["/usr/bin/nc", "-G", "1", "-z", "127.0.0.1", str(port)],
        )

    checks = {
        "home_read_denied": read_probe["returncode"] != 0,
        "outside_write_denied": write_probe["returncode"] != 0 and not denied_write.exists(),
        "inside_write_allowed": allowed_probe["returncode"] == 0 and allowed_write.is_file(),
        "loopback_network_denied": network_probe["returncode"] != 0,
    }
    allowed_write.unlink(missing_ok=True)
    denied_write.unlink(missing_ok=True)
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise RuntimeError(f"candidate sandbox probe failed: {', '.join(failed)}")
    return {
        "status": "passed",
        "checks": checks,
        "probes": {
            "home_read": read_probe,
            "outside_write": write_probe,
            "inside_write": allowed_probe,
            "loopback_network": network_probe,
        },
    }


def _run_sandbox_probe(profile: str, command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        ["/usr/bin/sandbox-exec", "-p", profile, *command],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
    )
    return {
        "executable": command[0],
        "returncode": completed.returncode,
        "stderr": completed.stderr[-500:],
    }


def sandbox_profile(home: Path, writable_root: Path) -> str:
    return " ".join(
        (
            "(version 1)",
            "(deny default)",
            "(allow process*)",
            "(allow signal)",
            "(allow sysctl-read)",
            "(allow mach*)",
            "(allow ipc-posix*)",
            "(allow file-read*)",
            f'(deny file-read* (subpath "{_sandbox_escape(str(home.resolve()))}"))',
            f'(allow file-write* (subpath "{_sandbox_escape(str(writable_root.resolve()))}"))',
            '(allow file-write* (literal "/dev/null"))',
        )
    )


def _preserve_failed_run(
    *,
    temporary_output: Path,
    output: Path,
    spec: CandidateSpec,
    started_at: str,
    bundle_verification: dict[str, Any],
    error: str,
    elapsed: float,
) -> None:
    if not temporary_output.exists() or output.exists():
        return
    write_json(
        temporary_output / "metrics.json",
        {"status": "failed", "wall_seconds": round(elapsed, 6), "error": error[:1000]},
    )
    (temporary_output / "report.md").write_text(
        f"# {spec.candidate_id} Failed Run\n\nStatus: failed\n\n{error[:1000]}\n",
        encoding="utf-8",
    )
    manifest = {
        "format_version": EVALUATION_FORMAT_VERSION,
        "run_id": output.name,
        "created_at": started_at,
        "candidate": spec.candidate_id,
        "candidate_revision": spec.revision,
        "status": "failed",
        "corpus_manifest_sha256": bundle_verification["manifest_sha256"],
        "candidate_manifest_sha256": bundle_verification["candidate_manifest_sha256"],
        "answer_key_plaintext_sha256": bundle_verification["answer_key_plaintext_sha256"],
        "files": file_entries(temporary_output, exclude={"manifest.json"}),
    }
    write_json(temporary_output / "manifest.json", manifest)
    os.replace(temporary_output, output)
    set_read_only_tree(output)


def _git(checkout: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode:
        raise RuntimeError(f"candidate Git preflight failed: {' '.join(args)}")
    return completed.stdout.strip()


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _nonnegative_number(payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{key} must be a nonnegative number")
    return round(float(value), 6)


def _tree_digest(root: Path) -> str:
    if root.is_file():
        return sha256_file(root)
    if not root.is_dir():
        raise ValueError(f"candidate build tree is missing: {root}")
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise ValueError(f"candidate build tree is empty: {root}")
    for path in files:
        if path.is_symlink():
            raise ValueError(f"candidate build tree contains a symlink: {path}")
        relative = str(path.relative_to(root)).encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def _rss_bytes(value: int | float) -> int:
    amount = int(value)
    return amount if platform.system() == "Darwin" else amount * 1024


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _sandbox_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
