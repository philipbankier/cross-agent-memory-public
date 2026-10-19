from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from uuid import UUID

from cross_assistant_memory.models import CollectorProvenance, ParseResult
from cross_assistant_memory.uploads import build_upload_batch

PARENT = "11111111-1111-4111-8111-111111111111"
CHILD = "22222222-2222-4222-8222-222222222222"


def write_jsonl(path: Path, records: Iterable[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    return path


def _body(parsed: ParseResult) -> bytes:
    provenance = CollectorProvenance(
        "claude-code",
        "2.1.281",
        "native-jsonl-history",
        "cross-memory-native-collector",
        "0.1.0",
        parsed.schema_fingerprint,
    )
    return build_upload_batch(parsed, source_account_id="synthetic", provenance=provenance)


def _records() -> list[dict[str, object]]:
    return [
        {
            "type": "user",
            "sessionId": session,
            "uuid": f"message-{index}",
            "parentUuid": None if index == 0 else f"message-{index - 1}",
            "entrypoint": "claude-desktop",
            "version": "2.1.221",
            "message": {"role": "user", "content": text},
        }
        for index, (session, text) in enumerate(
            [(PARENT, "Inherited request."), (CHILD, "Child decision."), (CHILD, "Child detail.")]
        )
    ]


def _attachment_fork(count: int, kind: str = "total_tokens_reminder") -> list[dict[str, object]]:
    messages = _records()
    messages[0]["uuid"] = str(UUID(int=100))
    links: list[dict[str, object]] = [
        {
            "type": "attachment",
            "uuid": str(UUID(int=101 + index)),
            "parentUuid": str(UUID(int=100 + index)),
            "sessionId": PARENT,
            "entrypoint": "claude-desktop",
            "version": "2.1.229",
            "isSidechain": False,
            "attachment": {"type": kind},
        }
        for index in range(count)
    ]
    messages[1]["parentUuid"] = links[-1]["uuid"]
    messages[1]["version"] = "2.1.229"
    return [
        messages[0],
        *links,
        {"type": "custom-title", "sessionId": CHILD, "customTitle": "Synthetic fork"},
        *messages[1:],
    ]
