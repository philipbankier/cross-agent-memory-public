from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.collector import CollectorConfig
from cross_assistant_memory.collector_queue import (
    CollectorQueue,
    exclusive_collector_sync,
    source_key_for,
)
from cross_assistant_memory.grok_bot_capture import (
    MAX_CAPTURE_BYTES,
    capture_transcript_page,
    grok_bot_observation_path,
    transcript_page_uploads,
)
from cross_assistant_memory.grok_bot_collector import (
    GrokBotCollectorPolicy,
    load_grok_bot_configuration,
    read_transcript_page,
)
from cross_assistant_memory.models import SourceCursor, SourceKind, SourceSystem
from cross_assistant_memory.private_json import load_owner_only_json, write_owner_only_json
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
)
from cross_assistant_memory.uploads import parse_upload_batch

MAX_PROGRESS_BYTES = 256 * 1024
MAX_PAGE_OBSERVATIONS = 512
_SHA = re.compile(r"[0-9a-f]{64}")


def _binding(
    config: CollectorConfig, policy: GrokBotCollectorPolicy, bot_id: str
) -> dict[str, str]:
    if not policy.enabled or not policy.scope.allows(bot_id):
        raise PermissionError("Grok Bot backfill is disabled or its target is not enrolled")
    descriptor, _ = open_regular_file_no_symlinks(config.queue.key_file, "queue key")
    with os.fdopen(descriptor, "rb") as stream:
        key = stream.read(32769)
    if not key or len(key) > 32768:
        raise ValueError("Grok Bot backfill queue key is invalid")
    return {
        "source_account_id": policy.scope.source_account_id,
        "bot_id": bot_id,
        "collector_bot_id": policy.scope.collector_bot_id,
        "queue_root_sha256": hashlib.sha256(str(config.queue.root.resolve()).encode()).hexdigest(),
        "queue_key_sha256": hashlib.sha256(key).hexdigest(),
    }


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _load(path: Path, binding: dict[str, str]) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    state = load_owner_only_json(
        path, label="Grok Bot backfill progress", max_bytes=MAX_PROGRESS_BYTES
    )
    if (
        state.keys()
        != set(binding)
        | {
            "format_version",
            "frontier_before",
            "exhausted",
            "validated_pages",
            "last_page_sha256",
            "pending",
        }
        or type(state["format_version"]) is not int
        or state["format_version"] != 1
        or any(state[key] != value for key, value in binding.items())
        or type(state["exhausted"]) is not bool
        or not _integer(state["validated_pages"])
        or (
            state["frontier_before"] is not None
            and (not _integer(state["frontier_before"]) or state["frontier_before"] == 0)
        )
        or (
            state["last_page_sha256"] is not None
            and (
                type(state["last_page_sha256"]) is not str
                or _SHA.fullmatch(state["last_page_sha256"]) is None
            )
        )
    ):
        raise ValueError("Grok Bot backfill progress identity or shape is invalid")
    pending_value = state["pending"]
    if pending_value is not None:
        if not isinstance(pending_value, dict):
            raise ValueError("Grok Bot backfill pending page is invalid")
        pending = cast(dict[str, Any], pending_value)
        if (
            pending.keys()
            != {
                "source_sha256",
                "source_bytes",
                "transcript",
                "start",
                "end",
                "total",
                "before",
                "observations",
            }
            or type(pending["source_sha256"]) is not str
            or _SHA.fullmatch(pending["source_sha256"]) is None
            or not _integer(pending["source_bytes"])
            or not 0 < pending["source_bytes"] <= 1024 * 1024
            or type(pending["transcript"]) is not str
            or len(pending["transcript"]) > 4096
            or not Path(pending["transcript"]).is_absolute()
            or not all(_integer(pending[key]) for key in ("start", "end", "total"))
            or not 0 <= pending["start"] <= pending["end"] < pending["total"]
            or (pending["before"] is not None and not _integer(pending["before"]))
            or pending["before"] != (pending["start"] or None)
            or type(pending["observations"]) is not list
            or len(cast(list[object], pending["observations"])) > MAX_PAGE_OBSERVATIONS
        ):
            raise ValueError("Grok Bot backfill pending page is invalid")
        for observation_value in cast(list[object], pending["observations"]):
            if not isinstance(observation_value, dict):
                raise ValueError("Grok Bot backfill pending observation is invalid")
            observation = cast(dict[str, Any], observation_value)
            if (
                observation.keys() != {"sha256", "byte_length"}
                or type(observation["sha256"]) is not str
                or _SHA.fullmatch(observation["sha256"]) is None
                or type(observation["byte_length"]) is not int
                or not 0 < observation["byte_length"] <= MAX_CAPTURE_BYTES
            ):
                raise ValueError("Grok Bot backfill pending observation is invalid")
    if state["validated_pages"] == 0:
        valid = (
            not state["exhausted"]
            and state["frontier_before"] is None
            and pending_value is not None
        )
    else:
        valid = state["exhausted"] == (state["frontier_before"] is None)
        valid = valid and (not state["exhausted"] or pending_value is None)
    if not valid:
        raise ValueError("Grok Bot backfill progress transition is invalid")
    return state


def _save(path: Path, previous: dict[str, Any] | None, state: dict[str, Any]) -> None:
    if previous is None:
        write_owner_only_json(
            path, state, label="Grok Bot backfill progress", max_bytes=MAX_PROGRESS_BYTES
        )
        return
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    write_owner_only_json(
        temporary, state, label="Grok Bot backfill progress", max_bytes=MAX_PROGRESS_BYTES
    )
    parent = open_directory_no_symlinks(path.parent, "backfill progress parent")
    try:
        current = load_owner_only_json(
            path, label="Grok Bot backfill progress", max_bytes=MAX_PROGRESS_BYTES
        )
        if current != previous:
            raise RuntimeError("Grok Bot backfill progress changed during its transition")
        os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        temporary.unlink(missing_ok=True)
        os.close(parent)


def _acknowledged(
    queue: CollectorQueue, binding: dict[str, str], observation: dict[str, Any]
) -> bool:
    digest, length = observation["sha256"], observation["byte_length"]
    path_hash = hashlib.sha256(str(grok_bot_observation_path(digest)).encode()).hexdigest()
    key = source_key_for(SourceSystem.GROK_BOT, binding["source_account_id"], path_hash)
    return queue.cursor(key) == SourceCursor(
        key, f"grok-bot-app:{binding['bot_id']}", SourceKind.UNKNOWN, 1, length, digest
    )


def _settle(
    path: Path, queue: CollectorQueue, state: dict[str, Any] | None, binding: dict[str, str]
) -> dict[str, Any] | None:
    if state is None or state["pending"] is None:
        return state
    pending = state["pending"]
    if not all(_acknowledged(queue, binding, item) for item in pending["observations"]):
        return state
    changed = {
        **state,
        "frontier_before": pending["before"],
        "exhausted": pending["before"] is None,
        "validated_pages": state["validated_pages"] + 1,
        "last_page_sha256": pending["source_sha256"],
        "pending": None,
    }
    _save(path, state, changed)
    return changed


def next_grok_bot_backfill_page(
    config_path: Path, policy_path: Path, progress_path: Path, *, bot_id: str, limit: int = 20
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("Grok Bot native page limit is invalid")
    config, policy = load_grok_bot_configuration(config_path, policy_path)
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.open(config.queue)
        binding = _binding(config, policy, bot_id)
        state = _settle(progress_path, queue, _load(progress_path, binding), binding)
        status = queue.status()
        result = {
            "text_free": True,
            "source_system": "grok_bot",
            "bot_id": bot_id,
            "validated_pages": state["validated_pages"] if state else 0,
            "conversation_completeness_verified": False,
        }
        if status.blocked_items or status.schema_holds:
            return {
                **result,
                "action": "attention",
                "blocked_items": status.blocked_items,
                "schema_holds": status.schema_holds,
            }
        if state and state["exhausted"]:
            return {**result, "action": "native_pagination_exhausted"}
        if status.queued_items:
            return {**result, "action": "flush", "queued_items": status.queued_items}
        if state and state["pending"]:
            pending = state["pending"]
            return {
                **result,
                "action": "replay_page",
                "transcript": pending["transcript"],
                "source_sha256": pending["source_sha256"],
            }
        return {
            **result,
            "action": "read_page",
            "request": {
                "in": bot_id,
                "limit": limit,
                "before": state["frontier_before"] if state else None,
            },
        }


def queue_grok_bot_backfill_page(
    config_path: Path, policy_path: Path, progress_path: Path, transcript_path: Path, *, bot_id: str
) -> dict[str, Any]:
    config, policy = load_grok_bot_configuration(config_path, policy_path)
    data = read_transcript_page(transcript_path)
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.open(config.queue)
        binding = _binding(config, policy, bot_id)
        projection, _excluded_users, bodies = transcript_page_uploads(
            data, bot_id=bot_id, scope=policy.scope
        )
        if len(bodies) > MAX_PAGE_OBSERVATIONS:
            raise ValueError("Grok Bot backfill page exceeds its observation bound")
        state = _load(progress_path, binding)
        if state and state["last_page_sha256"] == projection.source_sha256:
            return {"text_free": True, "status": "already_traversed"}
        pending = state["pending"] if state else None
        if pending is not None:
            if pending["source_sha256"] != projection.source_sha256:
                raise ValueError("Grok Bot backfill must finish its exact pending page")
        else:
            inspection = projection.inspection
            expected_end = (
                inspection.total - 1
                if state is None
                else state["frontier_before"] - 1
                if not state["exhausted"]
                else -1
            )
            if inspection.page_end != expected_end:
                raise ValueError("Grok Bot backfill page skips or changes its native boundary")
            observations: list[dict[str, object]] = []
            for body, _reply in bodies:
                parsed = parse_upload_batch(body).parsed
                observations.append(
                    {"sha256": parsed.end_prefix_digest, "byte_length": parsed.segment_end_byte}
                )
            pending = {
                "source_sha256": projection.source_sha256,
                "source_bytes": len(data),
                "transcript": str(transcript_path.resolve(strict=True)),
                "start": inspection.page_start,
                "end": inspection.page_end,
                "total": inspection.total,
                "before": inspection.before,
                "observations": observations,
            }
            changed = {
                **(
                    state
                    or {
                        **binding,
                        "format_version": 1,
                        "frontier_before": None,
                        "exhausted": False,
                        "validated_pages": 0,
                        "last_page_sha256": None,
                    }
                ),
                "pending": pending,
            }
            # A crash before or between queue writes must retain the complete page intent.
            _save(progress_path, state, changed)
        captured = capture_transcript_page(queue, data, bot_id=bot_id, scope=policy.scope)
        return {"text_free": True, "status": "queued_not_admitted", **asdict(captured)}
