from __future__ import annotations

import json
import re
from typing import cast

from cross_assistant_memory.models import AdmissionDecision, Privacy, SourceSystem

NO_MEMORY_MARKERS = (
    "<no-memory>",
    "</no-memory>",
    "[no-memory]",
    "# no-memory",
)
PRIVATE_MARKERS = (
    "<private>",
    "</private>",
    "[private]",
    "# private",
)
PLACEHOLDER_MARKERS = (
    '"sessionid":"placeholder"',
    "session transcript unavailable.",
)
PLATFORM_CONTEXT_PREFIXES = (
    "# agents.md instructions for ",
    "<app-context>",
    "<apps_instructions>",
    "<collaboration_mode>",
    "<environment_context>",
    "<permissions instructions>",
    "<plugins_instructions>",
    "<recommended_plugins>",
    "<skills_instructions>",
    "<turn_aborted>",
    "<user_instructions>",
)
TEXT_ATTACHMENT_MEDIA_TYPES = frozenset(
    {"application/json", "text/csv", "text/markdown", "text/plain"}
)
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}\b")),
    ("hex_service_key", re.compile(r"\bsk_[A-Fa-f0-9]{48}\b")),
    (
        "covalent_key",
        re.compile(
            r"(?<!\w)(_{1,2})?(?:ckey(?:\\)?_[a-f0-9]{27}|"
            r"cqt(?:\\)?_(?:wF|rQ)[bcdfghjkmpqrtvwxyBCDFGHJKMPQRTVWXY346789]{26})"
            r"(?(1)\1)(?!\w)"
        ),
    ),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
)
ADMISSION_EXCLUSION_REASONS = frozenset(
    {
        "oversized_record",
        "uninspectable_record",
        "platform_context_wrapper",
        "no_memory_marker",
        "private_marker",
        "synthetic_placeholder",
        *(f"secret:{name}" for name, _pattern in SECRET_PATTERNS),
    }
)


def is_admission_exclusion_reason(value: str) -> bool:
    return value in ADMISSION_EXCLUSION_REASONS


def raw_record_has_uninspected_attachment(raw_record: bytes) -> bool:
    """Withhold attachment-bearing raw JSON; this does not inspect or alter its bytes."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        item = dict(pairs)
        if len(item) != len(pairs):
            raise ValueError("ambiguous raw evidence object")
        return item

    try:
        loaded: object = json.loads(raw_record, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False  # Native adapters may supply ordinary plain-text evidence.
    except (RecursionError, ValueError):
        return True
    pending = [loaded]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            item = cast(dict[str, object], value)
            for key, child in item.items():
                if key in {"attachment", "attachments", "file_attachments", "files"} and child:
                    return True
                if key in {"content", "parts"} and isinstance(child, list):
                    for block in cast(list[object], child):
                        if isinstance(block, dict):
                            block_type = cast(dict[str, object], block).get("type")
                            if block_type not in ("text", "input_text", "output_text"):
                                return True
                pending.append(cast(object, child))
            if item.get("type") in ("image", "input_image", "document", "input_file", "base64"):
                return True
        elif isinstance(value, list):
            pending.extend(cast(list[object], value))
    return False


def classify_record(
    source_system: SourceSystem,
    content_text: str,
    raw_record: bytes,
    *,
    max_record_bytes: int,
) -> AdmissionDecision:
    if len(raw_record) > max_record_bytes:
        return AdmissionDecision(False, Privacy.NO_MEMORY, "oversized_record")

    lowered = content_text.lower()
    context_text = lowered.lstrip()
    context_heading, _, context_body = context_text.partition("\n")
    if source_system is SourceSystem.CODEX and (
        context_text.startswith(PLATFORM_CONTEXT_PREFIXES)
        or (
            context_heading.rstrip() == "# agents.md instructions"
            and context_body.lstrip().startswith("<instructions>")
        )
    ):
        return AdmissionDecision(False, Privacy.NO_MEMORY, "platform_context_wrapper")
    raw_text = raw_record.decode("utf-8", errors="replace")
    texts = [content_text, raw_text]
    try:
        loaded: object = json.loads(raw_record, object_pairs_hook=list)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass  # Native adapters may supply plain-text evidence rather than JSON.
    except (RecursionError, ValueError):
        return AdmissionDecision(False, Privacy.NO_MEMORY, "uninspectable_record")
    else:
        # Raw evidence retains metadata too, including JSON-escaped keys and values.
        pending = [(loaded, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 128:
                return AdmissionDecision(False, Privacy.NO_MEMORY, "uninspectable_record")
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, (list, tuple)):
                pending.extend(
                    (item, depth + 1) for item in cast(list[object] | tuple[object, ...], value)
                )
    lowered_texts = [text.lower() for text in texts]
    if any(marker in text for text in lowered_texts for marker in NO_MEMORY_MARKERS):
        return AdmissionDecision(False, Privacy.NO_MEMORY, "no_memory_marker")
    if any(marker in text for text in lowered_texts for marker in PRIVATE_MARKERS):
        return AdmissionDecision(False, Privacy.PRIVATE, "private_marker")
    if source_system is SourceSystem.CLAUDE_CODE and any(
        marker in text for text in lowered_texts for marker in PLACEHOLDER_MARKERS
    ):
        return AdmissionDecision(False, Privacy.NO_MEMORY, "synthetic_placeholder")
    for name, pattern in SECRET_PATTERNS:
        # Preserve legacy case folding without weakening Covalent's format restrictions.
        candidates = texts if name == "covalent_key" else (*texts, lowered)
        if any(pattern.search(text) for text in candidates):
            return AdmissionDecision(False, Privacy.NO_MEMORY, f"secret:{name}")
    return AdmissionDecision(True, Privacy.INCLUDED, "included")


def classify_attachment(
    source_system: SourceSystem,
    media_type: str,
    raw_record: bytes,
    *,
    max_record_bytes: int,
) -> AdmissionDecision:
    if media_type not in TEXT_ATTACHMENT_MEDIA_TYPES:
        return AdmissionDecision(False, Privacy.NO_MEMORY, "attachment_content_not_inspectable")
    if len(raw_record) > max_record_bytes:
        return AdmissionDecision(False, Privacy.NO_MEMORY, "oversized_record")
    try:
        text = raw_record.decode("utf-8-sig")
    except UnicodeDecodeError:
        return AdmissionDecision(False, Privacy.NO_MEMORY, "attachment_content_not_inspectable")
    if "\x00" in text or raw_record.startswith((b"%PDF-", b"PK\x03\x04", b"\x1f\x8b")):
        return AdmissionDecision(False, Privacy.NO_MEMORY, "attachment_content_not_inspectable")
    return classify_record(source_system, text, raw_record, max_record_bytes=max_record_bytes)
