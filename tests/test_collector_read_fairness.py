from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import cross_assistant_memory.collector_runtime as runtime
import cross_assistant_memory.ingest as ingest
from cross_assistant_memory.collector import (
    NATIVE_ADAPTERS,
    CollectorNodeConfig,
    InitialSourceCursor,
    NativeSourceOptIn,
    load_collector_config,
)
from cross_assistant_memory.collector_queue import CollectorQueue, QueueFailureCode, source_key_for
from cross_assistant_memory.models import SourceCursor, SourceSystem
from cross_assistant_memory.uploads import parse_upload_batch


def write_jsonl(path: Path, records: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    return path


def _write_config(tmp_path: Path, sources: list[tuple[str, Path, str]]) -> Path:
    credential = tmp_path / "collector.token"
    credential.write_text("cam1.synthetic.token\n", encoding="ascii")
    credential.chmod(0o600)
    config = tmp_path / "collector.json"
    config.write_text(
        json.dumps(
            {
                "format_version": 2,
                "node": {
                    "upload_url": "http://127.0.0.1:8765/upload/batches",
                    "credential_file": str(credential.resolve()),
                    "timeout_seconds": 5,
                },
                "queue": {
                    "root": str((tmp_path / "queue").resolve()),
                    "key_file": str((tmp_path / "secrets" / "queue-key.tink").resolve()),
                    "max_bytes": 8 * 1024 * 1024,
                    "max_age_seconds": 24 * 60 * 60,
                },
                "sources": [
                    {
                        "source_system": system,
                        "source_account_id": account,
                        "root": str(root.resolve()),
                        "source_client_version": "synthetic-client-1.0.0",
                    }
                    for system, root, account in sources
                ],
            }
        ),
        encoding="utf-8",
    )
    return config


def _codex_message(text: str) -> dict[str, object]:
    return {
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": text}],
        },
    }


@pytest.mark.parametrize("priority", [True, False])
def test_small_source_uses_remaining_budget_without_losing_deferred_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, priority: bool
) -> None:
    now = 2_000_000_000
    root = tmp_path / "codex"
    paths = [
        write_jsonl(
            root / f"source-{index}.jsonl",
            [
                {"type": "session_meta", "payload": {"id": f"source-{index}", "source": "cli"}},
                _codex_message("Synthetic request." + "x" * index),
            ],
        )
        for index in range(3)
    ]
    paths.sort(
        key=lambda p: source_key_for(
            SourceSystem.CODEX, "source_account:codex", hashlib.sha256(str(p).encode()).hexdigest()
        )
    )
    for path in paths:
        modified = now if priority else now - 3600
        os.utime(path, (modified, modified))
    config = _write_config(tmp_path, [("codex", root, "source_account:codex")])
    costs = {paths[0].stat().st_size: 60, paths[1].stat().st_size: 60}
    monkeypatch.setattr(runtime, "MAX_SOURCE_READ_BYTES_PER_SYNC", 100)

    def reservation(
        _system: SourceSystem,
        size: int,
        _cursor: SourceCursor | InitialSourceCursor | None,
        _limit: int | None,
    ) -> int:
        return costs.get(size, 10)

    monkeypatch.setattr(runtime, "_segment_read_reservation", reservation)
    sent: list[str] = []

    def transport(_node: CollectorNodeConfig, _credential: str, body: bytes) -> None:
        sent.append(parse_upload_batch(body).parsed.conversation_id)

    first = runtime.sync_collector(config, transport=transport, now_epoch=now)
    assert len(sent) == 2
    assert f"source-{paths[2].stem.rsplit('-', 1)[1]}" in sent
    assert first["status"] == "pending"
    assert cast(dict[str, object], first["scan_work"])["source_read_bytes_reserved"] == 70
    queue = CollectorQueue.open(load_collector_config(config).queue)
    assert queue.scan_after(priority=priority) == source_key_for(
        SourceSystem.CODEX,
        "source_account:codex",
        hashlib.sha256(str(paths[0]).encode()).hexdigest(),
    )
    assert queue.next_scan_is_priority() is priority
    sent.clear()
    second = runtime.sync_collector(config, transport=transport, now_epoch=now + 1)
    assert sent == [f"source-{paths[1].stem.rsplit('-', 1)[1]}"]
    assert second["status"] == "ok"
    assert queue.status(now_epoch=now + 1).queued_items == 0


@pytest.mark.parametrize("priorities", [(True,), (False,), (True, False)])
def test_initial_deferred_lanes_keep_their_first_unfinished_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, priorities: tuple[bool, ...]
) -> None:
    now = 2_000_000_000
    root = tmp_path / "codex"
    lanes: dict[bool, list[Path]] = {}
    for priority in priorities:
        paths = [
            write_jsonl(
                root / f"{priority}-{index}.jsonl",
                [
                    {"type": "session_meta", "payload": {"id": f"{priority}-{index}"}},
                    _codex_message("Unfinished synthetic source."),
                ],
            )
            for index in range(3)
        ]
        modified = now if priority else now - 3600
        for path in paths:
            os.utime(path, (modified, modified))
        lanes[priority] = sorted(
            paths,
            key=lambda p: source_key_for(
                SourceSystem.CODEX,
                "source_account:codex",
                hashlib.sha256(str(p).encode()).hexdigest(),
            ),
        )
    config = _write_config(tmp_path, [("codex", root, "source_account:codex")])
    attempts: list[Path] = []
    monkeypatch.setattr(runtime, "MAX_SOURCES_PER_SYNC", 2 * len(priorities))

    def unfinished_scan(
        queue: CollectorQueue,
        source: NativeSourceOptIn,
        path: Path,
        *,
        now: int,
        budget: runtime._ScanBudget,  # pyright: ignore[reportPrivateUsage]
        priority: bool = False,
    ) -> runtime.SourceSyncResult:
        attempts.append(path)
        path_hash = hashlib.sha256(str(path).encode()).hexdigest()
        queue.record_scan_attempt(
            source_key_for(source.source_system, source.source_account_id, path_hash),
            priority=priority,
        )
        return runtime.SourceSyncResult(source.source_system, path_hash, "work_limit", 0)

    monkeypatch.setattr(runtime, "_scan_source", unfinished_scan)
    runtime.sync_collector(config, now_epoch=now)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    for priority in priorities:
        assert [path for path in attempts if path in lanes[priority]] == lanes[priority][:2]
        expected = (
            None
            if priority
            else source_key_for(
                SourceSystem.CODEX,
                "source_account:codex",
                hashlib.sha256(str(lanes[priority][-1]).encode()).hexdigest(),
            )
        )
        assert queue.scan_after(priority=priority) == expected
    attempts.clear()
    runtime.sync_collector(config, now_epoch=now + 1)
    for priority in priorities:
        assert [path for path in attempts if path in lanes[priority]] == lanes[priority][:2]


@pytest.mark.parametrize("denial", [None, "remaining_work", "absolute_limit"])
def test_large_frame_reserves_its_measured_length_before_verified_reparse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, denial: str | None
) -> None:
    source = write_jsonl(
        tmp_path / "codex" / "session.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "framing", "source": "cli"}},
            _codex_message("Before the frame."),
        ],
    )
    config = _write_config(tmp_path, [("codex", source.parent, "source_account:codex")])

    def transport(_node: CollectorNodeConfig, _credential: str, _body: bytes) -> None:
        return None

    runtime.sync_collector(config, transport=transport, now_epoch=100)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    key = source_key_for(
        SourceSystem.CODEX, "source_account:codex", hashlib.sha256(str(source).encode()).hexdigest()
    )
    cursor = queue.cursor(key)
    assert cursor is not None
    raw = (json.dumps({"type": "compacted", "payload": {"message": "x" * 600}}) + "\n").encode()
    following = (json.dumps(_codex_message("After the frame.")) + "\n").encode()
    with source.open("ab") as stream:
        stream.write(raw + following)
    monkeypatch.setattr(runtime, "MAX_COLLECTOR_SEGMENT_BYTES", 256)
    monkeypatch.setattr(runtime, "MAX_SINGLE_RECORD_BYTES", 4096)
    reserve = runtime._segment_read_reservation  # pyright: ignore[reportPrivateUsage]
    size = source.stat().st_size
    probe_limit = size - cursor.next_byte_offset
    required = (
        reserve(SourceSystem.CODEX, size, cursor, None)
        + probe_limit
        + 1
        + reserve(SourceSystem.CODEX, size, cursor, len(raw))
    )
    monkeypatch.setattr(
        runtime, "MAX_SOURCE_READ_BYTES_PER_SYNC", required - int(denial == "remaining_work")
    )
    if denial == "absolute_limit":

        def oversized_reservation(
            system: SourceSystem,
            size: int,
            cursor: SourceCursor | InitialSourceCursor | None,
            limit: int | None,
        ) -> int:
            return required + 1 if limit == len(raw) else reserve(system, size, cursor, limit)

        monkeypatch.setattr(runtime, "_segment_read_reservation", oversized_reservation)
    result = runtime.sync_collector(config, transport=transport, now_epoch=101)
    if denial is not None:
        assert result["segments_enqueued"] == 0
        assert result["status"] == (
            "attention_required" if denial == "absolute_limit" else "pending"
        )
        if denial == "absolute_limit":
            attention = cast(list[dict[str, object]], result["source_attention"])
            assert [item["state"] for item in attention] == ["source_read_limit"]
        assert queue.cursor(key) == cursor
        assert queue.status(now_epoch=101).queued_items == 0
        monkeypatch.setattr(runtime, "MAX_SOURCE_READ_BYTES_PER_SYNC", required)
        monkeypatch.setattr(runtime, "_segment_read_reservation", reserve)
        result = runtime.sync_collector(config, transport=transport, now_epoch=101)
    advanced = queue.cursor(key)
    assert advanced is not None
    assert advanced.next_byte_offset == cursor.next_byte_offset + len(raw)
    assert advanced.next_record_ordinal == cursor.next_record_ordinal + 1
    assert (
        advanced.prefix_digest
        == hashlib.sha256(source.read_bytes()[: advanced.next_byte_offset]).hexdigest()
    )
    assert result["segments_enqueued"] == 1
    assert result["status"] == "pending"
    assert cast(dict[str, object], result["scan_work"])["source_read_bytes_reserved"] == required
    completed = runtime.sync_collector(config, transport=transport, now_epoch=102)
    assert completed["status"] == "ok"
    final_cursor = queue.cursor(key)
    assert final_cursor is not None and final_cursor.next_byte_offset == size
    assert (
        runtime.sync_collector(config, transport=transport, now_epoch=103)["uploaded_batches"] == 0
    )


def test_denied_large_reparse_preserves_an_already_enqueued_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_jsonl(
        tmp_path / "codex" / "session.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "partial-framing", "source": "cli"}},
            _codex_message("Before the frame."),
        ],
    )
    config = _write_config(tmp_path, [("codex", source.parent, "source_account:codex")])

    def transport(_node: CollectorNodeConfig, _credential: str, _body: bytes) -> None:
        return None

    runtime.sync_collector(config, transport=transport, now_epoch=100)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    key = source_key_for(
        SourceSystem.CODEX, "source_account:codex", hashlib.sha256(str(source).encode()).hexdigest()
    )
    cursor = queue.cursor(key)
    assert cursor is not None
    first = (json.dumps(_codex_message("Admit this prefix.")) + "\n").encode()
    raw = (json.dumps({"type": "compacted", "payload": {"message": "x" * 600}}) + "\n").encode()
    following = (json.dumps(_codex_message("After the frame.")) + "\n").encode()
    with source.open("ab") as stream:
        stream.write(first + raw + following)
    monkeypatch.setattr(runtime, "MAX_COLLECTOR_SEGMENT_BYTES", len(first))
    monkeypatch.setattr(runtime, "MAX_SINGLE_RECORD_BYTES", 4096)
    prefix_cursor = replace(
        cursor,
        next_byte_offset=cursor.next_byte_offset + len(first),
        next_record_ordinal=cursor.next_record_ordinal + 1,
        prefix_digest=hashlib.sha256(
            source.read_bytes()[: cursor.next_byte_offset] + first
        ).hexdigest(),
    )
    reserve = runtime._segment_read_reservation  # pyright: ignore[reportPrivateUsage]
    size = source.stat().st_size
    probe_limit = size - prefix_cursor.next_byte_offset
    required = (
        reserve(SourceSystem.CODEX, size, cursor, None)
        + reserve(SourceSystem.CODEX, size, prefix_cursor, None)
        + probe_limit
        + 1
    )
    monkeypatch.setattr(runtime, "MAX_SOURCE_READ_BYTES_PER_SYNC", required)
    result = runtime.sync_collector(config, transport=transport, now_epoch=101)
    assert result["segments_enqueued"] == 1
    assert result["status"] == "pending"
    assert queue.cursor(key) == prefix_cursor
    assert queue.status(now_epoch=101).queued_items == 0
    monkeypatch.setattr(runtime, "MAX_SOURCE_READ_BYTES_PER_SYNC", 2 * required)
    completed = runtime.sync_collector(config, transport=transport, now_epoch=102)
    assert completed["status"] == "ok", completed
    final = queue.cursor(key)
    assert final is not None and final.next_byte_offset == size
    assert (
        runtime.sync_collector(config, transport=transport, now_epoch=103)["uploaded_batches"] == 0
    )


@pytest.mark.parametrize("retry_at", [106, 100_000], ids=["retained", "expired"])
def test_parser_upgrade_replays_old_bytes_before_current_parser_appends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_at: int
) -> None:
    source = write_jsonl(
        tmp_path / "codex" / "session.jsonl",
        [
            {"type": "session_meta", "payload": {"id": "upgrade", "source": "cli"}},
            _codex_message("Synthetic request before the parser upgrade."),
        ],
    )
    config = _write_config(tmp_path, [("codex", source.parent, "source_account:codex")])
    current_version = ingest.CODEX_PARSER_VERSION
    attempted: list[bytes] = []

    def unavailable(_node: CollectorNodeConfig, _credential: str, body: bytes) -> QueueFailureCode:
        attempted.append(body)
        return QueueFailureCode.NETWORK_UNREACHABLE

    with monkeypatch.context() as previous:
        previous.setattr(ingest, "CODEX_PARSER_VERSION", "0.2.0")
        previous.setitem(
            NATIVE_ADAPTERS,
            SourceSystem.CODEX,
            replace(NATIVE_ADAPTERS[SourceSystem.CODEX], parser_version="0.2.0"),
        )
        runtime.sync_collector(config, transport=unavailable, now_epoch=100)
    assert parse_upload_batch(attempted[0]).parsed.parser_version == "0.2.0"
    with source.open("ab") as handle:
        handle.write(
            (json.dumps(_codex_message("Synthetic request after the upgrade.")) + "\n").encode()
        )
    uploaded: list[bytes] = []
    result = runtime.sync_collector(
        config,
        transport=lambda _node, _credential, body: uploaded.append(body),
        now_epoch=retry_at,
    )
    assert result["status"] == "ok"
    assert result["uploaded_batches"] == 2
    assert uploaded[0] == attempted[0]
    assert parse_upload_batch(uploaded[1]).parsed.parser_version == current_version
    assert runtime.sync_collector(config, now_epoch=retry_at + 1)["uploaded_batches"] == 0
