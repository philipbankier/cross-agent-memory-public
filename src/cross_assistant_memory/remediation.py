from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.admission import classify_record
from cross_assistant_memory.application import (
    ApplicationPrincipal,
    ApplyEventCorrectionsRequest,
    MemoryApplication,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file, parse_incremental_file
from cross_assistant_memory.models import (
    Authority,
    EventCorrection,
    ParsedRecord,
    ParseResult,
    Privacy,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.storage import DEFAULT_MAX_RECORD_BYTES, Ledger, event_state_digest

REMEDIATION_FORMAT_VERSION = 1
MAX_SPEC_BYTES = 1024 * 1024


def build_remediation_plan(settings: Settings, spec_path: Path, output: Path) -> dict[str, Any]:
    spec = _load_json_object(spec_path, max_bytes=MAX_SPEC_BYTES)
    if spec.get("format_version") != REMEDIATION_FORMAT_VERSION:
        raise ValueError("unsupported remediation specification version")
    authorized_by = _required_string(spec, "authorized_by")
    authorization_scope = _required_string(spec, "authorization_scope")
    reason = _required_string(spec, "reason")
    sources = spec.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("remediation specification requires a non-empty sources list")
    source_values = cast(list[object], sources)

    ledger = Ledger(settings)
    expected_generation = ledger.generation_digest()
    corrections: list[EventCorrection] = []
    source_receipts: list[dict[str, Any]] = []
    seen_source_ids: set[str] = set()
    for raw_source in source_values:
        if not isinstance(raw_source, dict):
            raise ValueError("remediation source entries must be objects")
        source = cast(dict[str, Any], raw_source)
        source_file_id = _required_string(source, "source_file_id")
        if source_file_id in seen_source_ids:
            raise ValueError(f"duplicate remediation source: {source_file_id}")
        seen_source_ids.add(source_file_id)
        source_metadata = ledger.source_file(source_file_id)
        states = ledger.source_event_states(source_file_id)
        target_scope = Scope(source["scope"]) if "scope" in source else None
        target_project = source.get("project_id") if "project_id" in source else None
        if (
            "project_id" in source
            and target_project is not None
            and not isinstance(target_project, str)
        ):
            raise ValueError("project_id must be a string or null")
        if target_scope is not None:
            _validate_scope_project(target_scope, target_project)
        elif "project_id" in source:
            raise ValueError("source-wide project_id requires source-wide scope")
        event_overrides = _event_overrides(source, states)

        parsed: ParseResult | None = None
        parsed_by_ordinal: dict[int, ParsedRecord] | None = None
        reparse_receipt: dict[str, Any] | None = None
        reparse_value = source.get("reparse_path")
        if reparse_value is not None:
            if not isinstance(reparse_value, str) or not reparse_value:
                raise ValueError("reparse_path must be a non-empty string")
            reparse_path = Path(reparse_value).expanduser()
            source_system = SourceSystem(source_metadata["source_system"])
            reparse_end_value = source.get("reparse_end_byte")
            if reparse_end_value is None:
                parsed = parse_file(reparse_path, source_system)
            else:
                if source_system is not SourceSystem.CODEX:
                    raise ValueError("bounded-prefix reparsing currently supports Codex only")
                reparse_end = _non_negative_int(reparse_end_value, "reparse_end_byte")
                reparse_start = _non_negative_int(
                    source.get("reparse_start_byte", 0), "reparse_start_byte"
                )
                reparse_ordinal = _non_negative_int(
                    source.get("reparse_start_ordinal", 0), "reparse_start_ordinal"
                )
                if reparse_end <= reparse_start:
                    raise ValueError("bounded reparse end must be after its start")
                prefix_digest = source.get("reparse_start_prefix_digest")
                if prefix_digest is not None and not isinstance(prefix_digest, str):
                    raise ValueError("reparse_start_prefix_digest must be a string")
                parsed = parse_incremental_file(
                    reparse_path,
                    source_system,
                    start_ordinal=reparse_ordinal,
                    start_byte=reparse_start,
                    expected_prefix_digest=prefix_digest,
                    max_increment_bytes=reparse_end - reparse_start,
                )
                if parsed.segment_end_byte != reparse_end:
                    raise RuntimeError(f"bounded reparse end mismatch: {source_file_id}")
            expected_digest = source.get("expected_file_digest", source_metadata["file_digest"])
            if not isinstance(expected_digest, str) or parsed.file_digest != expected_digest:
                raise RuntimeError(f"reparse source digest mismatch: {source_file_id}")
            if parsed.file_digest != source_metadata["file_digest"]:
                raise RuntimeError(
                    f"reparse source does not match the admitted source: {source_file_id}"
                )
            parsed_by_ordinal = {record.record_ordinal: record for record in parsed.records}
            if len(parsed_by_ordinal) != len(parsed.records):
                raise RuntimeError(
                    f"reparse source has duplicate record ordinals: {source_file_id}"
                )
            reparse_receipt = {
                "path_hash": _sha256_text(str(reparse_path.resolve())),
                "file_digest": parsed.file_digest,
                "parser_name": parsed.parser_name,
                "parser_version": parsed.parser_version,
                "parsed_records": len(parsed.records),
                "conversation_id": parsed.conversation_id,
                "source_kind": parsed.source_kind.value,
                "segment_start_ordinal": parsed.segment_start_ordinal,
                "segment_start_byte": parsed.segment_start_byte,
                "segment_end_ordinal": parsed.segment_end_ordinal_exclusive,
                "segment_end_byte": parsed.segment_end_byte,
            }

        source_corrections = 0
        remaining_ordinals = set(parsed_by_ordinal or {})
        for state in states:
            target = {
                key: state[key]
                for key in (
                    "event_type",
                    "actor_kind",
                    "assistant",
                    "authority",
                    "scope",
                    "project_id",
                    "privacy",
                    "content_digest",
                    "content_text",
                    "parser_version",
                )
            }
            if target_scope is not None:
                target["scope"] = target_scope.value
                target["project_id"] = target_project
            correction_reasons: list[str] = []
            if target_scope is not None and (
                state["scope"] != target_scope.value or state["project_id"] != target_project
            ):
                correction_reasons.append("source scope mapping corrected")

            if parsed_by_ordinal is not None:
                ordinal = cast(int, state["record_ordinal"])
                parsed_record = parsed_by_ordinal.get(ordinal)
                if parsed_record is None:
                    if parsed is None:
                        raise RuntimeError("reparse state is unavailable")
                    target["privacy"] = Privacy.NO_MEMORY.value
                    target["parser_version"] = parsed.parser_version
                    correction_reasons.append("observer control wrapper excluded by current parser")
                else:
                    if parsed is None:
                        raise RuntimeError("reparse state is unavailable")
                    remaining_ordinals.discard(ordinal)
                    raw_digest = hashlib.sha256(parsed_record.raw_record).hexdigest()
                    expected_object_id = f"sha256:{raw_digest}"
                    if expected_object_id != state["source_object_id"]:
                        raise RuntimeError(
                            f"reparse record does not match admitted evidence: {state['event_id']}"
                        )
                    decision = classify_record(
                        parsed.source_system,
                        parsed_record.content_text,
                        parsed_record.raw_record,
                        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
                    )
                    if not decision.accepted:
                        target["privacy"] = decision.privacy.value
                        correction_reasons.append(
                            f"current admission policy excluded record: {decision.reason}"
                        )
                    else:
                        target.update(
                            {
                                "event_type": parsed_record.event_type,
                                "actor_kind": parsed_record.actor_kind,
                                "assistant": parsed_record.assistant,
                                "authority": parsed_record.authority.value,
                                "privacy": decision.privacy.value,
                                "content_digest": _sha256_text(parsed_record.content_text),
                                "content_text": parsed_record.content_text,
                                "parser_version": parsed.parser_version,
                            }
                        )
                        if any(
                            target[key] != state[key]
                            for key in (
                                "event_type",
                                "actor_kind",
                                "assistant",
                                "authority",
                                "privacy",
                                "content_text",
                                "parser_version",
                            )
                        ):
                            correction_reasons.append("record reclassified by current parser")

            override = event_overrides.get(cast(str, state["event_id"]))
            if override is not None:
                _apply_event_override(target, override)
                correction_reasons.append(_required_string(override, "reason"))

            if target["privacy"] == Privacy.NO_MEMORY.value:
                target["content_text"] = ""
                target["content_digest"] = hashlib.sha256(b"").hexdigest()
            if event_state_digest(target) == state["state_digest"]:
                continue
            corrections.append(
                EventCorrection(
                    event_id=cast(str, state["event_id"]),
                    expected_state_digest=cast(str, state["state_digest"]),
                    event_type=cast(str, target["event_type"]),
                    actor_kind=cast(str, target["actor_kind"]),
                    assistant=cast(str | None, target["assistant"]),
                    authority=Authority(cast(str, target["authority"])),
                    scope=Scope(cast(str, target["scope"])),
                    project_id=target["project_id"],
                    privacy=Privacy(cast(str, target["privacy"])),
                    content_text=cast(str, target["content_text"]),
                    parser_version=cast(str, target["parser_version"]),
                    reason="; ".join(correction_reasons) or _required_string(source, "reason"),
                )
            )
            source_corrections += 1

        if remaining_ordinals:
            raise RuntimeError(
                f"current parser produced records absent from the admitted source: {source_file_id}"
            )
        source_receipts.append(
            {
                "source_file_id": source_file_id,
                "source_system": source_metadata["source_system"],
                "source_path_hash": _sha256_text(source_metadata["source_path"]),
                "file_digest": source_metadata["file_digest"],
                "previous_parser_version": source_metadata["parser_version"],
                "target_scope": target_scope.value if target_scope is not None else None,
                "target_project_id": target_project,
                "event_count": len(states),
                "event_override_count": len(event_overrides),
                "correction_count": source_corrections,
                "reparse": reparse_receipt,
            }
        )

    if not corrections:
        raise ValueError("remediation specification produced no corrections")
    plan = {
        "format_version": REMEDIATION_FORMAT_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "expected_generation_digest": expected_generation,
        "authorized_by": authorized_by,
        "authorization_scope": authorization_scope,
        "reason": reason,
        "sources": source_receipts,
        "corrections": [_correction_dict(item) for item in corrections],
    }
    _write_private_json(output, plan)
    return {
        "status": "planned",
        "output": str(output.expanduser()),
        "plan_sha256": _sha256_file(output.expanduser()),
        "expected_generation_digest": expected_generation,
        "source_count": len(source_receipts),
        "correction_count": len(corrections),
    }


def apply_remediation_plan(settings: Settings, plan_path: Path, *, execute: bool) -> dict[str, Any]:
    plan = _load_json_object(plan_path, max_bytes=16 * 1024 * 1024)
    if plan.get("format_version") != REMEDIATION_FORMAT_VERSION:
        raise ValueError("unsupported remediation plan version")
    corrections_value = plan.get("corrections")
    if not isinstance(corrections_value, list) or not corrections_value:
        raise ValueError("remediation plan requires corrections")
    correction_values = cast(list[object], corrections_value)
    corrections = [_load_correction(value) for value in correction_values]
    expected_generation = _required_string(plan, "expected_generation_digest")
    authorized_by = _required_string(plan, "authorized_by")
    authorization_scope = _required_string(plan, "authorization_scope")
    plan_sources = plan.get("sources", [])
    if not isinstance(plan_sources, list):
        raise ValueError("remediation plan sources must be a list")
    plan_source_values = cast(list[object], plan_sources)
    preview: dict[str, Any] = {
        "status": "preview",
        "plan_sha256": _sha256_file(plan_path.expanduser()),
        "expected_generation_digest": expected_generation,
        "source_count": len(plan_source_values),
        "correction_count": len(corrections),
        "authorized_by": authorized_by,
        "authorization_scope": authorization_scope,
        "execute": execute,
    }
    if not execute:
        return preview
    result = MemoryApplication(Ledger(settings)).apply_event_corrections(
        ApplicationPrincipal.local_admin(authorized_by),
        ApplyEventCorrectionsRequest(
            corrections=tuple(corrections),
            expected_generation_digest=expected_generation,
            authorization_scope=authorization_scope,
            reason=_required_string(plan, "reason"),
        ),
    )
    return {**preview, **result, "execute": True}


def _load_correction(value: object) -> EventCorrection:
    if not isinstance(value, dict):
        raise ValueError("correction entries must be objects")
    item = cast(dict[str, Any], value)
    assistant = item.get("assistant")
    project_id = item.get("project_id")
    if assistant is not None and not isinstance(assistant, str):
        raise ValueError("correction assistant must be a string or null")
    if project_id is not None and not isinstance(project_id, str):
        raise ValueError("correction project_id must be a string or null")
    privacy = Privacy(_required_string(item, "privacy"))
    content_text = item.get("content_text")
    if not isinstance(content_text, str) or (not content_text and privacy is not Privacy.NO_MEMORY):
        raise ValueError("correction content_text must be a string, empty only for no_memory")
    return EventCorrection(
        event_id=_required_string(item, "event_id"),
        expected_state_digest=_required_digest(item, "expected_state_digest"),
        event_type=_required_string(item, "event_type"),
        actor_kind=_required_string(item, "actor_kind"),
        assistant=assistant,
        authority=Authority(_required_string(item, "authority")),
        scope=Scope(_required_string(item, "scope")),
        project_id=project_id,
        privacy=privacy,
        content_text="" if privacy is Privacy.NO_MEMORY else content_text,
        parser_version=_required_string(item, "parser_version"),
        reason=_required_string(item, "reason"),
    )


def _correction_dict(correction: EventCorrection) -> dict[str, Any]:
    return {
        "event_id": correction.event_id,
        "expected_state_digest": correction.expected_state_digest,
        "event_type": correction.event_type,
        "actor_kind": correction.actor_kind,
        "assistant": correction.assistant,
        "authority": correction.authority.value,
        "scope": correction.scope.value,
        "project_id": correction.project_id,
        "privacy": correction.privacy.value,
        "content_text": "" if correction.privacy is Privacy.NO_MEMORY else correction.content_text,
        "parser_version": correction.parser_version,
        "reason": correction.reason,
    }


def _event_overrides(
    source: dict[str, Any], states: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    value = source.get("event_overrides", [])
    if not isinstance(value, list):
        raise ValueError("event_overrides must be a list")
    known_event_ids = {cast(str, state["event_id"]) for state in states}
    overrides: dict[str, dict[str, Any]] = {}
    allowed_keys = {
        "event_id",
        "reason",
        "event_type",
        "actor_kind",
        "assistant",
        "authority",
        "scope",
        "project_id",
        "privacy",
    }
    for raw_override in cast(list[object], value):
        if not isinstance(raw_override, dict):
            raise ValueError("event override entries must be objects")
        override = cast(dict[str, Any], raw_override)
        unexpected = set(override) - allowed_keys
        if unexpected:
            raise ValueError(f"unsupported event override fields: {sorted(unexpected)}")
        event_id = _required_string(override, "event_id")
        _required_string(override, "reason")
        if event_id not in known_event_ids:
            raise ValueError(f"event override does not belong to the source: {event_id}")
        if event_id in overrides:
            raise ValueError(f"duplicate event override: {event_id}")
        overrides[event_id] = override
    return overrides


def _apply_event_override(target: dict[str, Any], override: dict[str, Any]) -> None:
    for key in ("event_type", "actor_kind"):
        if key in override:
            target[key] = _required_string(override, key)
    if "assistant" in override:
        assistant = override["assistant"]
        if assistant is not None and (not isinstance(assistant, str) or not assistant):
            raise ValueError("override assistant must be a non-empty string or null")
        target["assistant"] = assistant
    if "authority" in override:
        target["authority"] = Authority(_required_string(override, "authority")).value
    if "privacy" in override:
        target["privacy"] = Privacy(_required_string(override, "privacy")).value

    target_scope = (
        Scope(_required_string(override, "scope"))
        if "scope" in override
        else Scope(cast(str, target["scope"]))
    )
    if "project_id" in override:
        target_project = override["project_id"]
        if target_project is not None and (
            not isinstance(target_project, str) or not target_project
        ):
            raise ValueError("override project_id must be a non-empty string or null")
    elif target_scope is Scope.PROJECT:
        target_project = target["project_id"]
    else:
        target_project = None
    _validate_scope_project(target_scope, target_project)
    target["scope"] = target_scope.value
    target["project_id"] = target_project


def _validate_scope_project(scope: Scope, project_id: object) -> None:
    if scope is Scope.PROJECT and (not isinstance(project_id, str) or not project_id):
        raise ValueError("project-scoped remediation requires project_id")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("only project-scoped remediation may carry project_id")


def _non_negative_int(value: object, key: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
