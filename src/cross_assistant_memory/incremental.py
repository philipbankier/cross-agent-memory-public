from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import DEFAULT_MAX_FILE_BYTES, parse_incremental_file
from cross_assistant_memory.models import ParseResult, Scope, SourceSystem
from cross_assistant_memory.storage import DEFAULT_MAX_RECORD_BYTES, Ledger

INGESTION_PLAN_FORMAT_VERSION = 1
MAX_PLAN_BYTES = 1024 * 1024


def build_incremental_ingestion_plan(
    *,
    path: Path,
    output: Path,
    source_account: str,
    source_path: str,
    scope: Scope,
    project_id: str | None,
    start_record_ordinal: int,
    start_byte_offset: int,
    expected_prefix_digest: str | None,
    legacy_fork_replay_source_file_id: str | None = None,
    max_increment_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> dict[str, Any]:
    if scope is Scope.PROJECT and not project_id:
        raise ValueError("project_id is required for project-scoped ingestion")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped ingestion may carry project_id")
    if not source_account:
        raise ValueError("source_account must be a non-empty string")
    if not Path(source_path).is_absolute():
        raise ValueError("source_path must be absolute")
    if legacy_fork_replay_source_file_id == "":
        raise ValueError("legacy fork replay source file id must be non-empty")
    parsed = parse_incremental_file(
        path,
        SourceSystem.CODEX,
        start_ordinal=start_record_ordinal,
        start_byte=start_byte_offset,
        expected_prefix_digest=expected_prefix_digest,
        max_increment_bytes=max_increment_bytes,
    )
    if legacy_fork_replay_source_file_id is not None:
        if parsed.parent_conversation_id is None:
            raise ValueError("legacy fork replay requires fork metadata")
        if parsed.segment_start_ordinal == 0 or parsed.segment_start_byte == 0:
            raise ValueError("legacy fork replay requires a non-zero replay boundary")
    if parsed.segment_end_ordinal_exclusive == parsed.segment_start_ordinal:
        raise ValueError("incremental source has no new complete JSONL records")
    summary = _admission_summary(parsed, max_record_bytes=max_record_bytes)
    plan = {
        "format_version": INGESTION_PLAN_FORMAT_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "source_system": SourceSystem.CODEX.value,
        "source_account": source_account,
        "path": str(path.expanduser().resolve()),
        "source_path": source_path,
        "source_path_hash": _sha256_text(source_path),
        "scope": scope.value,
        "project_id": project_id,
        "parser_name": parsed.parser_name,
        "parser_version": parsed.parser_version,
        "conversation_id": parsed.conversation_id,
        "branch_id": parsed.branch_id,
        "parent_conversation_id": parsed.parent_conversation_id,
        "source_kind": parsed.source_kind.value,
        "source_label": parsed.source_label,
        "legacy_fork_replay_source_file_id": legacy_fork_replay_source_file_id,
        "start_record_ordinal": parsed.segment_start_ordinal,
        "start_byte_offset": parsed.segment_start_byte,
        "start_prefix_digest": parsed.start_prefix_digest,
        "end_record_ordinal": parsed.segment_end_ordinal_exclusive,
        "end_byte_offset": parsed.segment_end_byte,
        "end_prefix_digest": parsed.end_prefix_digest,
        "observed_file_size": parsed.observed_file_size,
        "max_increment_bytes": max_increment_bytes,
        "max_record_bytes": max_record_bytes,
        **summary,
    }
    _write_private_json(output, plan)
    return {
        "status": "planned",
        "output": str(output.expanduser()),
        "plan_sha256": _sha256_file(output.expanduser()),
        **_public_summary(plan),
    }


def apply_incremental_ingestion_plan(
    settings: Settings,
    plan_path: Path,
    *,
    execute: bool,
) -> dict[str, Any]:
    plan = _load_json_object(plan_path, max_bytes=MAX_PLAN_BYTES)
    if plan.get("format_version") != INGESTION_PLAN_FORMAT_VERSION:
        raise ValueError("unsupported incremental ingestion plan version")
    if _required_string(plan, "source_system") != SourceSystem.CODEX.value:
        raise ValueError("incremental ingestion currently supports Codex JSONL only")
    path = Path(_required_string(plan, "path"))
    source_path = _required_string(plan, "source_path")
    legacy_fork_replay_source_file_id = _optional_string(
        plan.get("legacy_fork_replay_source_file_id")
    )
    if _sha256_text(source_path) != _required_digest(plan, "source_path_hash"):
        raise RuntimeError("incremental plan source path hash mismatch")
    start_byte = _required_int(plan, "start_byte_offset")
    end_byte = _required_int(plan, "end_byte_offset")
    if end_byte < start_byte:
        raise ValueError("incremental plan byte boundaries are invalid")
    parsed = parse_incremental_file(
        path,
        SourceSystem.CODEX,
        start_ordinal=_required_int(plan, "start_record_ordinal"),
        start_byte=start_byte,
        expected_prefix_digest=_required_digest(plan, "start_prefix_digest"),
        max_increment_bytes=end_byte - start_byte,
    )
    _verify_parse_matches_plan(parsed, plan)
    current_summary = _admission_summary(
        parsed,
        max_record_bytes=_required_int(plan, "max_record_bytes"),
    )
    for key, value in current_summary.items():
        if plan.get(key) != value:
            raise RuntimeError(f"incremental plan admission summary changed: {key}")

    preview = {
        "status": "preview",
        "plan_sha256": _sha256_file(plan_path.expanduser()),
        "execute": execute,
        **_public_summary(plan),
    }
    if not execute:
        return preview
    ledger = Ledger(settings)
    report = ledger.ingest(
        parsed,
        source_account=_required_string(plan, "source_account"),
        scope=Scope(_required_string(plan, "scope")),
        project_id=_optional_string(plan.get("project_id")),
        source_path=source_path,
        max_record_bytes=_required_int(plan, "max_record_bytes"),
        legacy_fork_replay_source_file_id=legacy_fork_replay_source_file_id,
    )
    return {
        **preview,
        "status": report.status,
        "execute": True,
        "source_file_id": report.source_file_id,
        "inserted_events": report.inserted_events,
        "existing_events": report.existing_events,
        "quarantined_records": report.quarantined_records,
        "quarantine_reasons": report.quarantine_reasons,
        "ledger_generation_digest": ledger.generation_digest(),
    }


def _verify_parse_matches_plan(parsed: ParseResult, plan: dict[str, Any]) -> None:
    expected: dict[str, object] = {
        "parser_name": parsed.parser_name,
        "parser_version": parsed.parser_version,
        "conversation_id": parsed.conversation_id,
        "branch_id": parsed.branch_id,
        "parent_conversation_id": parsed.parent_conversation_id,
        "source_kind": parsed.source_kind.value,
        "source_label": parsed.source_label,
        "start_record_ordinal": parsed.segment_start_ordinal,
        "start_byte_offset": parsed.segment_start_byte,
        "start_prefix_digest": parsed.start_prefix_digest,
        "end_record_ordinal": parsed.segment_end_ordinal_exclusive,
        "end_byte_offset": parsed.segment_end_byte,
        "end_prefix_digest": parsed.end_prefix_digest,
    }
    for key, actual in expected.items():
        if plan.get(key) != actual:
            raise RuntimeError(f"incremental source changed after planning: {key}")


def _admission_summary(parsed: ParseResult, *, max_record_bytes: int) -> dict[str, Any]:
    authorities: Counter[str] = Counter()
    quarantine_reasons: Counter[str] = Counter()
    accepted = 0
    for record in parsed.records:
        decision = classify_record(
            parsed.source_system,
            record.content_text,
            record.raw_record,
            max_record_bytes=max_record_bytes,
        )
        if decision.accepted:
            accepted += 1
            authorities[record.authority.value] += 1
        else:
            quarantine_reasons[decision.reason] += 1
    return {
        "parsed_records": len(parsed.records),
        "accepted_records": accepted,
        "quarantined_records": sum(quarantine_reasons.values()),
        "authority_counts": dict(sorted(authorities.items())),
        "quarantine_reasons": dict(sorted(quarantine_reasons.items())),
        "malformed_records": parsed.malformed_records,
        "unknown_record_types": list(parsed.unknown_record_types),
    }


def _public_summary(plan: dict[str, Any]) -> dict[str, Any]:
    summary = {
        key: plan[key]
        for key in (
            "conversation_id",
            "source_kind",
            "scope",
            "project_id",
            "start_record_ordinal",
            "start_byte_offset",
            "end_record_ordinal",
            "end_byte_offset",
            "end_prefix_digest",
            "observed_file_size",
            "parsed_records",
            "accepted_records",
            "quarantined_records",
            "authority_counts",
            "quarantine_reasons",
        )
    }
    summary["legacy_fork_replay_source_file_id"] = plan.get("legacy_fork_replay_source_file_id")
    return summary


def _load_json_object(path: Path, *, max_bytes: int) -> dict[str, Any]:
    expanded = path.expanduser()
    if expanded.is_symlink() or not expanded.is_file():
        raise ValueError(f"JSON input must be a regular file: {expanded}")
    if expanded.stat().st_size > max_bytes:
        raise ValueError(f"JSON input exceeds the {max_bytes}-byte limit: {expanded}")
    value: object = json.loads(expanded.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON input must contain an object")
    return cast(dict[str, Any], value)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    expanded = path.expanduser()
    if expanded.exists() or expanded.is_symlink():
        raise ValueError(f"output already exists: {expanded}")
    expanded.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    expanded.parent.chmod(0o700)
    expanded.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expanded.chmod(0o400)


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a non-empty string")
    return item


def _required_digest(value: dict[str, Any], key: str) -> str:
    item = _required_string(value, key)
    if len(item) != 64 or any(character not in "0123456789abcdef" for character in item):
        raise ValueError(f"{key} must be a lowercase SHA-256 digest")
    return item


def _required_int(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool) or item < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return item


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("optional string value must be non-empty or null")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
