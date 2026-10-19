from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cross_assistant_memory.models import Authority, ParsedRecord, SourceKind
from cross_assistant_memory.parsers.common import content_text, optional_text

PARSER_NAME = "claude-code-jsonl"
PARSER_VERSION = "0.4.2"
COPIED_FORK_PRODUCERS = frozenset(
    {
        "2.1.219",
        "2.1.221",
        "2.1.227",
        "2.1.229",
        "2.1.237",
        "2.1.246",
        "2.1.258",
        "2.1.271",
        "2.1.280",
        "2.1.281",
        "2.1.284",
        "2.1.286",
        "2.1.289",
    }
)
STOP_HOOK_LINK_PRODUCERS = frozenset(
    {"2.1.271", "2.1.280", "2.1.281", "2.1.284", "2.1.286", "2.1.289"}
)
FORK_ATTACHMENT_TYPES = frozenset(
    {
        "deferred_tools_delta",
        "edited_text_file",
        "skill_listing",
        "auto_mode",
        "total_tokens_reminder",
    }
)
MAX_FORK_ATTACHMENT_LINKS = 64
INTERACTIVE_ENTRYPOINTS = {"claude-desktop"}
AUTOMATION_ENTRYPOINTS = {"sdk-cli"}
SESSION_METADATA_FIELDS: dict[
    str, tuple[dict[str, type | tuple[type, ...]], dict[str, type | tuple[type, ...]]]
] = {
    "custom-title": ({"sessionId": str, "customTitle": str}, {}),
    "agent-name": ({"sessionId": str, "agentName": str}, {}),
    "mode": ({"sessionId": str, "mode": str}, {}),
    "permission-mode": ({"sessionId": str, "permissionMode": str}, {}),
    "atis-latch": ({"sessionId": str, "atis": str}, {}),
    "bridge-session": (
        {"sessionId": str, "bridgeSessionId": str, "lastSequenceNum": int},
        {"ownerAccountUuid": str, "ownerOrganizationUuid": str},
    ),
    "pr-link": (
        {"sessionId": str, "prNumber": int, "prUrl": str, "prRepository": str, "timestamp": str},
        {},
    ),
    "frame-link": (
        {"sessionId": str, "timestamp": str},
        {"path": str, "frameUrl": str, "title": str, "artifactCount": int},
    ),
    "artifact-comment-monitor": ({"sessionId": str, "v": int, "artifacts": dict}, {}),
    "artifact-autoreact-ledger": (
        {"sessionId": str, "v": int, "accountUuid": str, "artifacts": dict},
        {},
    ),
    "file-history-delta": (
        {
            "messageId": str,
            "snapshotMessageId": str,
            "trackingPath": str,
            "backup": dict,
            "timestamp": str,
        },
        {},
    ),
    "cost-state": (
        {
            "sessionId": str,
            "totalCostUSD": (int, float),
            "totalAPIDuration": (int, float),
            "totalAPIDurationWithoutRetries": (int, float),
            "totalToolDuration": (int, float),
            "totalLinesAdded": (int, float),
            "totalLinesRemoved": (int, float),
            "totalDuration": (int, float),
            "startTime": (int, float),
            "modelUsage": dict,
        },
        {"hasUnknownModelCost": bool},
    ),
}
KNOWN_RECORD_TYPES = {
    "ai-title",
    "assistant",
    "attachment",
    "file-history-snapshot",
    "last-prompt",
    "queue-operation",
    "summary",
    "system",
    "user",
} | SESSION_METADATA_FIELDS.keys()


def _valid_session_metadata(item: dict[str, Any], record_type: str) -> bool:
    required, optional = SESSION_METADATA_FIELDS[record_type]
    if (
        not required.keys() <= item.keys()
        or item.keys() - {"type"} - required.keys() - optional.keys()
    ):
        return False
    fields = required | optional
    for key, value in item.items():
        if key == "type":
            continue
        expected = fields[key]
        allowed = expected if isinstance(expected, tuple) else (expected,)
        if type(value) not in allowed:
            return False
    if record_type != "cost-state":
        return True
    if any(
        not _valid_cost_number(value)
        for key, value in item.items()
        if isinstance(fields.get(key), tuple)
    ):
        return False
    usage_fields = {
        "inputTokens",
        "outputTokens",
        "cacheReadInputTokens",
        "cacheCreationInputTokens",
        "webSearchRequests",
        "costUSD",
    }
    for model, usage in item["modelUsage"].items():
        if (
            not isinstance(model, str)
            or not model
            or any(unicodedata.category(char) in {"Cc", "Cf"} for char in model)
            or not isinstance(usage, dict)
            or not usage_fields <= usage.keys()
            or usage.keys() - usage_fields - {"thinkingTokens"}
            or not all(
                _valid_cost_number(value) for value in cast(dict[str, object], usage).values()
            )
        ):
            return False
    return True


def _valid_cost_number(value: object) -> bool:
    if type(value) not in (int, float) or not isinstance(value, (int, float)):
        return False
    try:
        return value >= 0 and math.isfinite(value)
    except OverflowError:
        return False


def _valid_stop_hook_link(item: dict[str, Any]) -> bool:
    if (
        item.get("subtype") != "stop_hook_summary"
        or optional_text(item.get("version")) not in STOP_HOOK_LINK_PRODUCERS
        or type(item.get("hookCount")) is not int
        or item["hookCount"] < 0
        or type(item.get("preventedContinuation")) is not bool
        or type(item.get("hasOutput")) is not bool
        or optional_text(item.get("level")) not in {"info", "notice", "suggestion", "warning"}
        or not isinstance(item.get("hookInfos"), list)
        or not isinstance(item.get("hookErrors"), list)
    ):
        return False
    for value in cast(list[object], item["hookInfos"]):
        if not isinstance(value, dict):
            return False
        info = cast(dict[str, object], value)
        if (
            not isinstance(info.get("command"), str)
            or ("promptText" in info and not isinstance(info["promptText"], str))
            or ("durationMs" in info and not _valid_cost_number(info["durationMs"]))
        ):
            return False
    if not all(isinstance(value, str) for value in item["hookErrors"]):
        return False
    if "hookAdditionalContext" in item and (
        not isinstance(item["hookAdditionalContext"], list)
        or not all(
            isinstance(value, str) for value in cast(list[object], item["hookAdditionalContext"])
        )
    ):
        return False
    return all(
        key not in item or isinstance(item[key], str)
        for key in ("stopReason", "toolUseID", "hookLabel")
    ) and ("totalDurationMs" not in item or _valid_cost_number(item["totalDurationMs"]))


def _valid_session_start_hook_link(item: dict[str, Any]) -> bool:
    loaded = item.get("attachment")
    if not isinstance(loaded, dict):
        return False
    attachment = cast(dict[str, Any], loaded)
    if (
        item.get("version") != "2.1.281"
        or attachment.get("type") != "hook_success"
        or attachment.get("hookEvent") != "SessionStart"
        or not all(
            isinstance(attachment.get(key), str)
            for key in ("hookName", "toolUseID", "content", "stdout", "stderr", "command")
        )
        or type(attachment.get("exitCode")) is not int
        or ("durationMs" in attachment and not _valid_cost_number(attachment["durationMs"]))
    ):
        return False
    return bool(
        attachment["content"] or attachment["stdout"].strip() or attachment["stderr"].strip()
    )


@dataclass(frozen=True)
class ClaudeCodeMetadata:
    conversation_id: str
    branch_id: str
    parent_conversation_id: str | None
    captured_at: str | None
    source_kind: SourceKind
    source_label: str
    inherited_prefix_records: int = 0


def inspect_claude_code_metadata(data: bytes, path: Path) -> ClaudeCodeMetadata:
    return inspect_claude_code_metadata_records(data.splitlines(keepends=True), path)


def inspect_claude_code_metadata_records(
    records: Iterable[bytes],
    path: Path,
) -> ClaudeCodeMetadata:
    fallback = path.stem
    session_id: str | None = None
    agent_id: str | None = None
    captured_at: str | None = None
    entrypoint: str | None = None
    sidechain_marker = "subagents" in path.parts
    observer_marker = "claude-mem-observer-sessions" in str(path)
    observer_wrapper = False
    observer_intro = False
    message_session: str | None = None
    last_message_id: str | None = None
    transitions: list[tuple[int, str, str | None, str | None, str | None]] = []
    fork_shape_valid = True
    fork_links_valid = True
    child_versions_valid = True
    last_link_id: str | None = None
    child_hook_session: str | None = None
    attachment_ids: set[str] = set()
    system_link_used = False
    session_message_ids: dict[str, bool] = {}

    for ordinal, raw in enumerate(records):
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            fork_shape_valid = False
            continue
        if not isinstance(loaded, dict):
            fork_shape_valid = False
            continue
        item = cast(dict[str, Any], loaded)
        kind = item.get("type")
        if (
            not isinstance(kind, str)
            or kind not in KNOWN_RECORD_TYPES
            or (kind in SESSION_METADATA_FIELDS and not _valid_session_metadata(item, kind))
        ):
            fork_shape_valid = False
        if kind == "cost-state":
            # Accounting strings cannot establish identity or observer-message authority.
            continue
        observer_wrapper = observer_wrapper or b"<observed_from_primary_session>" in raw
        observer_intro = observer_intro or (
            b"Hello memory agent, you are continuing to observe" in raw
        )
        if kind in ("user", "assistant"):
            native_session = optional_text(item.get("sessionId"))
            native_id = optional_text(item.get("uuid"))
            if native_session is None or native_id is None:
                fork_shape_valid = False
            elif native_session != message_session:
                parent_id = optional_text(item.get("parentUuid"))
                if message_session is not None:
                    # 2.1.281 restamps assistant DTOs without replacing their explicit parent.
                    restamped_assistant_link = (
                        kind == "assistant"
                        and item.get("version") == "2.1.281"
                        and item.get("isSidechain") is False
                        and _session_uuid(native_id)
                        and native_id not in session_message_ids
                        and parent_id is not None
                        and session_message_ids.get(parent_id, False)
                        and child_hook_session is None
                        and isinstance(item.get("message"), dict)
                        and item["message"].get("role") == "assistant"
                    )
                    fork_links_valid &= (
                        parent_id is not None
                        and (
                            restamped_assistant_link
                            or (
                                parent_id in (last_message_id, last_link_id)
                                and (
                                    parent_id == last_message_id
                                    or child_hook_session is None
                                    or native_session == child_hook_session
                                )
                            )
                        )
                        and optional_text(item.get("entrypoint")) in INTERACTIVE_ENTRYPOINTS
                    )
                session_message_ids = {}
                if len(transitions) < 3:
                    transitions.append(
                        (
                            ordinal,
                            native_session,
                            parent_id,
                            optional_text(item.get("entrypoint")),
                            optional_text(item.get("timestamp")),
                        )
                    )
                else:
                    fork_shape_valid = False
                message_session = native_session
            if len(transitions) >= 2:
                child_versions_valid &= optional_text(item.get("version")) in COPIED_FORK_PRODUCERS
            last_message_id = native_id
            last_link_id = native_id
            child_hook_session = None
            attachment_ids = {native_id} if native_id is not None else set()
            system_link_used = False
        elif (
            kind == "attachment"
            or (kind == "system" and item.get("subtype") == "stop_hook_summary")
        ) and message_session is not None:
            native_id = optional_text(item.get("uuid"))
            attachment = item.get("attachment")
            session_start_link = (
                kind == "attachment"
                and child_hook_session is None
                and system_link_used
                and item.get("sessionId") == fallback
                and fallback != message_session
                and _session_uuid(fallback)
                and _valid_session_start_hook_link(item)
            )
            # Desktop's persisted UUID chain also includes verified stop-hook summaries.
            # Follow only the observed linear suffix; never open attachment paths.
            if (
                last_link_id is None
                or native_id is None
                or not _session_uuid(native_id)
                or native_id in attachment_ids
                or len(attachment_ids) > MAX_FORK_ATTACHMENT_LINKS
                or item.get("parentUuid") != last_link_id
                or (item.get("sessionId") != message_session and not session_start_link)
                or child_hook_session is not None
                or item.get("isSidechain") is not False
                or optional_text(item.get("entrypoint")) not in INTERACTIVE_ENTRYPOINTS
                or optional_text(item.get("version")) not in COPIED_FORK_PRODUCERS
                or not (
                    session_start_link
                    or (
                        isinstance(attachment, dict)
                        and optional_text(cast(dict[str, Any], attachment).get("type"))
                        in FORK_ATTACHMENT_TYPES
                    )
                    if kind == "attachment"
                    else _valid_stop_hook_link(item)
                )
            ):
                last_link_id = None
            else:
                attachment_ids.add(native_id)
                last_link_id = native_id
                if session_start_link:
                    child_hook_session = fallback
                system_link_used |= kind == "system"
        elif kind == "system" and "uuid" in item and system_link_used:
            last_link_id = None
        native_uuid = optional_text(item.get("uuid"))
        if native_uuid is not None and _session_uuid(native_uuid):
            session_message_ids[native_uuid] = (
                native_uuid not in session_message_ids
                and kind == "user"
                and item.get("sessionId") == message_session
                and item.get("version") == "2.1.281"
                and item.get("isSidechain") is False
                and optional_text(item.get("entrypoint")) in INTERACTIVE_ENTRYPOINTS
                and isinstance(item.get("message"), dict)
                and item["message"].get("role") == "user"
            )
        session_id = session_id or optional_text(item.get("sessionId"))
        agent_id = agent_id or optional_text(item.get("agentId"))
        captured_at = captured_at or optional_text(item.get("timestamp"))
        entrypoint = entrypoint or optional_text(item.get("entrypoint"))
        if item.get("isSidechain") is True or agent_id is not None:
            sidechain_marker = True

    observer_session = observer_marker or (observer_wrapper and observer_intro)
    if observer_session:
        conversation_id = session_id or fallback
        return ClaudeCodeMetadata(
            conversation_id=conversation_id,
            branch_id=conversation_id,
            parent_conversation_id=None,
            captured_at=captured_at,
            source_kind=SourceKind.AUTOMATION,
            source_label="claude_mem_observer",
        )
    if sidechain_marker:
        conversation_id = agent_id or fallback
        return ClaudeCodeMetadata(
            conversation_id=conversation_id,
            branch_id=conversation_id,
            parent_conversation_id=session_id,
            captured_at=captured_at,
            source_kind=SourceKind.SUBAGENT,
            source_label="claude_code_subagent",
        )

    if entrypoint in INTERACTIVE_ENTRYPOINTS:
        source_kind = SourceKind.INTERACTIVE
    elif entrypoint in AUTOMATION_ENTRYPOINTS:
        source_kind = SourceKind.AUTOMATION
    else:
        source_kind = SourceKind.UNKNOWN
    # Native Desktop forks retain parent session IDs in their copied prefix. Never turn
    # those inherited messages into child evidence or guess at an unverified transition.
    if len(transitions) > 1 or (
        _session_uuid(fallback) and session_id is not None and session_id != fallback
    ):
        if (
            source_kind is not SourceKind.INTERACTIVE
            or not fork_shape_valid
            or not fork_links_valid
            or not child_versions_valid
            or len(transitions) not in (2, 3)
            or not _session_uuid(fallback)
            or not all(_session_uuid(transition[1]) for transition in transitions)
            or len({transition[1] for transition in transitions}) != len(transitions)
            or transitions[-1][1] != fallback
            or transitions[-1][3] not in INTERACTIVE_ENTRYPOINTS
        ):
            raise ValueError("Claude Code copied history requires a verified fork boundary")
        return ClaudeCodeMetadata(
            conversation_id=fallback,
            branch_id=fallback,
            parent_conversation_id=transitions[-2][1],
            captured_at=transitions[-1][4],
            source_kind=source_kind,
            source_label=transitions[-1][3],
            inherited_prefix_records=transitions[-1][0],
        )
    conversation_id = session_id or fallback
    return ClaudeCodeMetadata(
        conversation_id=conversation_id,
        branch_id=conversation_id,
        parent_conversation_id=None,
        captured_at=captured_at,
        source_kind=source_kind,
        source_label=entrypoint or "claude_code",
    )


def _session_uuid(value: str) -> bool:
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def parse_claude_code_records(
    data: bytes,
    path: Path,
    *,
    metadata: ClaudeCodeMetadata | None = None,
    ordinal_base: int = 0,
    byte_base: int = 0,
    parser_version: str = PARSER_VERSION,
) -> tuple[
    str,
    str | None,
    str | None,
    tuple[ParsedRecord, ...],
    tuple[str, ...],
    int,
]:
    if parser_version not in {"0.4.0", "0.4.1", PARSER_VERSION}:
        raise ValueError("unsupported Claude Code parser version")
    source_metadata = metadata or inspect_claude_code_metadata(data, path)
    conversation_id = source_metadata.conversation_id
    branch_id: str | None = source_metadata.branch_id
    captured_at: str | None = source_metadata.captured_at
    records: list[ParsedRecord] = []
    unknown_types: set[str] = set()
    malformed = 0
    if ordinal_base < 0 or byte_base < 0:
        raise ValueError("Claude Code parser bases must be non-negative")
    offset = byte_base
    observer_session = source_metadata.source_label == "claude_mem_observer"

    for relative_ordinal, raw in enumerate(data.splitlines(keepends=True)):
        ordinal = ordinal_base + relative_ordinal
        start = offset
        offset += len(raw)
        try:
            loaded: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(loaded, dict):
            malformed += 1
            continue
        item = cast(dict[str, Any], loaded)
        record_type = item.get("type")
        if not isinstance(record_type, str):
            malformed += 1
            continue
        if record_type not in KNOWN_RECORD_TYPES:
            unknown_types.add(record_type)
            continue
        if record_type in SESSION_METADATA_FIELDS:
            # UI/control metadata is not message evidence, account proof, or user authority.
            if not _valid_session_metadata(item, record_type):
                malformed += 1
            continue
        if ordinal < source_metadata.inherited_prefix_records:
            continue
        item_session = optional_text(item.get("sessionId"))
        if item_session and source_metadata.source_kind is not SourceKind.SUBAGENT:
            conversation_id = item_session
        item_branch = optional_text(item.get("leafUuid"))
        if item_branch:
            branch_id = item_branch
        timestamp = optional_text(item.get("timestamp"))
        captured_at = captured_at or timestamp
        if record_type not in ("user", "assistant"):
            continue
        if (
            parser_version == PARSER_VERSION
            and "isMeta" in item
            and type(item["isMeta"]) is not bool
        ):
            malformed += 1
            continue
        is_meta = (
            parser_version == PARSER_VERSION
            and source_metadata.source_kind is SourceKind.INTERACTIVE
            and item.get("isMeta") is True
        )
        message_value = item.get("message")
        if not isinstance(message_value, dict):
            continue
        message = cast(dict[str, Any], message_value)
        role = message.get("role")
        text = content_text(message.get("content"))
        if not text:
            text = content_text(item.get("content"))
        if not text:
            continue
        if observer_session and (role == "user" or record_type == "user"):
            observer_record = _observer_user_record(
                text=text,
                raw=raw,
                ordinal=ordinal,
                start=start,
                end=offset,
                timestamp=timestamp,
                message_id=optional_text(item.get("uuid")),
                parent_message_id=optional_text(item.get("parentUuid")),
                branch_id=item_branch or branch_id or conversation_id,
            )
            if observer_record is not None:
                records.append(observer_record)
            continue
        if role == "user" or record_type == "user":
            # Runtime-provided context is not evidence that the human said it.
            actor_kind, assistant, authority = _prompt_authority(
                SourceKind.AUTOMATION if is_meta else source_metadata.source_kind
            )
        elif role == "assistant" or record_type == "assistant":
            if observer_session and text.startswith("Failed to authenticate. API Error:"):
                actor_kind = "tool"
                assistant = "claude_mem"
                authority = Authority.TOOL_OBSERVATION
            else:
                actor_kind = "assistant"
                assistant = "claude_mem" if observer_session else "claude_code"
                authority = Authority.ASSISTANT_OUTPUT
        else:
            continue
        records.append(
            ParsedRecord(
                raw_record=raw,
                record_ordinal=ordinal,
                byte_start=start,
                byte_end=offset,
                event_type="tool_observation" if actor_kind == "tool" else "message",
                actor_kind=actor_kind,
                assistant=assistant,
                authority=authority,
                content_text=text,
                occurred_at=timestamp,
                message_id=optional_text(item.get("uuid")),
                parent_message_id=optional_text(item.get("parentUuid")),
                branch_id=item_branch or branch_id or conversation_id,
            )
        )

    return (
        conversation_id,
        source_metadata.branch_id,
        captured_at,
        tuple(records),
        tuple(sorted(unknown_types)),
        malformed,
    )


def _prompt_authority(source_kind: SourceKind) -> tuple[str, str | None, Authority]:
    if source_kind is SourceKind.INTERACTIVE:
        return "user", None, Authority.USER_ASSERTION
    if source_kind is SourceKind.SUBAGENT:
        return "assistant", "claude_code", Authority.ASSISTANT_OUTPUT
    if source_kind is SourceKind.AUTOMATION:
        return "automation", "claude_code", Authority.TOOL_OBSERVATION
    return "source", "claude_code", Authority.TOOL_OBSERVATION


def _observer_user_record(
    *,
    text: str,
    raw: bytes,
    ordinal: int,
    start: int,
    end: int,
    timestamp: str | None,
    message_id: str | None,
    parent_message_id: str | None,
    branch_id: str,
) -> ParsedRecord | None:
    user_request = _tag_value(text, "user_request")
    if user_request:
        return ParsedRecord(
            raw_record=raw,
            record_ordinal=ordinal,
            byte_start=start,
            byte_end=end,
            event_type="message",
            actor_kind="user",
            assistant=None,
            authority=Authority.USER_ASSERTION,
            content_text=user_request,
            occurred_at=_tag_value(text, "requested_at") or timestamp,
            message_id=message_id,
            parent_message_id=parent_message_id,
            branch_id=branch_id,
        )
    if "<observed_from_primary_session>" in text and "<what_happened>" in text:
        fragment = _tag_fragment(text, "observed_from_primary_session")
        if not fragment:
            return None
        return ParsedRecord(
            raw_record=raw,
            record_ordinal=ordinal,
            byte_start=start,
            byte_end=end,
            event_type="tool_observation",
            actor_kind="tool",
            assistant="claude_mem",
            authority=Authority.TOOL_OBSERVATION,
            content_text=fragment,
            occurred_at=_tag_value(text, "occurred_at") or timestamp,
            message_id=message_id,
            parent_message_id=parent_message_id,
            branch_id=branch_id,
        )
    return None


def _tag_value(text: str, tag: str) -> str | None:
    opening = f"<{tag}>"
    closing = f"</{tag}>"
    start = text.find(opening)
    if start < 0:
        return None
    start += len(opening)
    end = text.find(closing, start)
    if end < 0:
        return None
    value = text[start:end].strip()
    return value or None


def _tag_fragment(text: str, tag: str) -> str | None:
    opening = f"<{tag}>"
    closing = f"</{tag}>"
    start = text.find(opening)
    if start < 0:
        return None
    end = text.find(closing, start)
    if end < 0:
        return None
    return text[start : end + len(closing)].strip()
