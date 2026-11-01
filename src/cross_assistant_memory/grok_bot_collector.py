from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from cross_assistant_memory.collector import CollectorConfig, load_collector_config
from cross_assistant_memory.collector_queue import CollectorQueue, exclusive_collector_sync
from cross_assistant_memory.grok_bot_capture import (
    GrokBotCaptureScope,
    capture_transcript_page,
    flush_queued_grok_bot_capture,
)
from cross_assistant_memory.grok_bot_transcript import MAX_PAGE_BYTES
from cross_assistant_memory.private_json import load_owner_only_json
from cross_assistant_memory.safe_files import open_regular_file_no_symlinks


@dataclass(frozen=True)
class GrokBotCollectorPolicy:
    enabled: bool
    scope: GrokBotCaptureScope
    preserve_sent_artifacts: bool = False


def load_grok_bot_policy(path: Path) -> GrokBotCollectorPolicy:
    value = load_owner_only_json(path, label="Grok Bot capture policy", max_bytes=32 * 1024)
    artifact_policy = type(value.get("format_version")) is int and value.get("format_version") == 2
    if (
        value.keys()
        != (
            {
                "format_version",
                "enabled",
                "source_account_id",
                "bot_ids",
                "collector_bot_id",
                "excluded_bot_ids",
            }
            | ({"preserve_sent_artifacts"} if artifact_policy else set())
        )
        or type(value["format_version"]) is not int
        or value["format_version"] not in (1, 2)
        or (artifact_policy and type(value["preserve_sent_artifacts"]) is not bool)
        or type(value["enabled"]) is not bool
        or type(value["bot_ids"]) is not list
        or type(value["excluded_bot_ids"]) is not list
    ):
        raise ValueError("Grok Bot capture policy is invalid")
    return GrokBotCollectorPolicy(
        value["enabled"],
        GrokBotCaptureScope(
            cast(str, value["source_account_id"]),
            tuple(cast(list[str], value["bot_ids"])),
            cast(str, value["collector_bot_id"]),
            tuple(cast(list[str], value["excluded_bot_ids"])),
        ),
        cast(bool, value["preserve_sent_artifacts"]) if artifact_policy else False,
    )


def load_grok_bot_configuration(
    config_path: Path, policy_path: Path
) -> tuple[CollectorConfig, GrokBotCollectorPolicy]:
    config = load_collector_config(config_path)
    if config.sources:
        raise ValueError("Grok Bot capture requires a dedicated queue without file-source opt-ins")
    return config, load_grok_bot_policy(policy_path)


def grok_bot_capture_status(config_path: Path, policy_path: Path) -> dict[str, object]:
    config, policy = load_grok_bot_configuration(config_path, policy_path)
    # Status must not create, migrate, expire or flush a queue.
    queue = CollectorQueue.open(config.queue)
    return {
        "text_free": True,
        "enabled": policy.enabled,
        "source_system": "grok_bot",
        "enrolled_bot_count": len(policy.scope.bot_ids),
        "excluded_bot_count": len(policy.scope.excluded_bot_ids),
        "coverage": "user_text_and_outward_requests",
        "attachment_contents_captured": None if policy.preserve_sent_artifacts else False,
        "sent_artifact_retention_enabled": policy.preserve_sent_artifacts,
        "question_answers_attested": False,
        "native_conversation_identity_verified": False,
        "freshness_guaranteed": False,
        "queue": queue.status().as_dict(),
    }


def queue_grok_bot_page(
    config_path: Path, policy_path: Path, transcript_path: Path, *, bot_id: str
) -> dict[str, object]:
    config, policy = load_grok_bot_configuration(config_path, policy_path)
    if not policy.enabled or not policy.scope.allows(bot_id):
        raise PermissionError("Grok Bot capture is disabled or its target is not enrolled")
    data = read_transcript_page(transcript_path)
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.initialize(config.queue)
        result = capture_transcript_page(queue, data, bot_id=bot_id, scope=policy.scope)
    return {"text_free": True, "status": "queued_not_admitted", **asdict(result)}


def queue_grok_bot_artifact(
    config_path: Path,
    policy_path: Path,
    transcript_path: Path,
    *,
    bot_id: str,
    native_tool_call_id: str,
    max_bytes: int,
) -> dict[str, object]:
    from cross_assistant_memory.grok_bot_artifacts import (
        capture_sent_artifact,
        select_sent_attachment,
    )

    config, policy = load_grok_bot_configuration(config_path, policy_path)
    if not policy.enabled or not policy.preserve_sent_artifacts or not policy.scope.allows(bot_id):
        raise PermissionError("Grok Bot sent artifact retention is not enabled for this target")
    references = select_sent_attachment(
        read_transcript_page(transcript_path), bot_id=bot_id, scope=policy.scope
    )
    selected = [item for item in references if item.native_tool_call_id == native_tool_call_id]
    if len(selected) != 1:
        raise ValueError("Grok Bot sent artifact reference is missing or ambiguous")
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.initialize(config.queue)
        return {
            "text_free": True,
            **capture_sent_artifact(
                queue,
                selected[0],
                scope=policy.scope,
                max_bytes=max_bytes,
            ),
        }


def read_transcript_page(transcript_path: Path) -> bytes:
    descriptor, _ = open_regular_file_no_symlinks(transcript_path, "native transcript page")
    try:
        before = os.fstat(descriptor)
        if not 0 < before.st_size <= MAX_PAGE_BYTES:
            raise ValueError("Grok Bot transcript exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_PAGE_BYTES + 1)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(data) != before.st_size:
            raise RuntimeError("Grok Bot transcript changed during its bounded read")
    finally:
        os.close(descriptor)
    return data


def flush_grok_bot_capture(
    config_path: Path, policy_path: Path, *, limit: int = 4
) -> dict[str, object]:
    if type(limit) is not int or not 1 <= limit <= 4:
        raise ValueError("Grok Bot capture flush limit must be between one and four")
    config, policy = load_grok_bot_configuration(config_path, policy_path)
    if not policy.enabled:
        raise PermissionError("Grok Bot capture is disabled")
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.initialize(config.queue)
        queue.expire()
        result = flush_queued_grok_bot_capture(
            queue,
            config.node,
            scope=policy.scope,
            limit=limit,
            preserve_sent_artifacts=policy.preserve_sent_artifacts,
        )
        pending = queue.status()
    return {
        "text_free": True,
        "status": "pending" if pending.queued_items or result.failed else "ready",
        "coverage": "user_text_and_outward_requests",
        **asdict(result),
        "queued_items": pending.queued_items,
        "blocked_items": pending.blocked_items,
    }
