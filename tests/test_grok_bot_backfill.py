from __future__ import annotations

import json
from pathlib import Path

import pytest

from cross_assistant_memory import grok_bot_backfill as backfill
from cross_assistant_memory.cli import main
from cross_assistant_memory.collector import load_collector_config
from cross_assistant_memory.collector_queue import MAX_DUE_UPLOADS, CollectorQueue
from cross_assistant_memory.grok_bot_capture import capture_transcript_page
from cross_assistant_memory.grok_bot_collector import load_grok_bot_policy

BOT = "abcdef00-0000-4000-8000-000000000001"
COLLECTOR = "abcdef00-0000-4000-8000-000000000002"


def case(root: Path) -> tuple[Path, Path, Path]:
    private = root / "private"
    private.mkdir(mode=0o700)
    queue = root / "queue"
    queue.mkdir(mode=0o700)
    config = root / "collector.json"
    config.write_text(
        json.dumps(
            {
                "format_version": 2,
                "node": {
                    "upload_url": "https://example.invalid:443/upload/batches",
                    "credential_file": str(private / "token"),
                    "timeout_seconds": 5,
                },
                "queue": {
                    "root": str(queue),
                    "key_file": str(private / "key.tink"),
                    "max_bytes": 1024 * 1024,
                    "max_age_seconds": 86400,
                },
                "sources": [],
            }
        )
    )
    policy = private / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "format_version": 1,
                "enabled": True,
                "source_account_id": "source_account:" + "0" * 64,
                "bot_ids": [BOT],
                "collector_bot_id": COLLECTOR,
                "excluded_bot_ids": [],
            }
        )
    )
    policy.chmod(0o400)
    CollectorQueue.initialize(load_collector_config(config).queue)
    return config, policy, private / "progress.json"


def page(root: Path, start: int, end: int, total: int, *, internal_only: bool = False) -> Path:
    records = [
        {
            "role": "assistant",
            "message": {
                "content": [{"type": "thinking", "thinking": "Excluded synthetic thought."}]
            },
        }
    ]
    if not internal_only:
        records = [
            {
                "role": "user",
                "message": {"content": [{"type": "text", "text": f"Synthetic statement {start}."}]},
            },
            {
                "role": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": f"call_{start}",
                            "name": "SendToUser",
                            "input": {"content": f"Synthetic response {start}."},
                        }
                    ]
                },
            },
        ]
    value = (
        '<cursor_untrusted_data_123 source="ReadTranscript">\n\n'
        f'Transcript of agent "Synthetic" ({BOT}), positions {start}\u2013{end} of {total}:\n'
        + "\n".join(json.dumps(item) for item in records)
        + "\n"
    )
    if start:
        value += (
            "Older messages remain: call ReadTranscript again with the same in "
            f"and before={start}.\n"
        )
    target = root / f"page-{start}.txt"
    target.write_text(value + "\n</cursor_untrusted_data_123>\n")
    return target


def acknowledge(config: Path, count: int = MAX_DUE_UPLOADS) -> None:
    queue = CollectorQueue.open(load_collector_config(config).queue)
    for item in queue.due_uploads(limit=count):
        queue.mark_success(item.item_id)


def test_next_before_initialization_is_read_only(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    result = backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert result["action"] == "read_page"
    assert result["request"] == {"in": BOT, "before": None, "limit": 20}
    assert not progress.exists()


def test_frontier_advances_only_after_all_real_queue_cursors_acknowledge(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    source = page(tmp_path, 8, 11, 12)
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    initial = progress.read_bytes()
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["action"]
        == "flush"
    )
    acknowledge(config, 1)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["action"]
        == "flush"
    )
    assert progress.read_bytes() == initial
    acknowledge(config)
    result = backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert result["request"]["before"] == 8
    assert result["validated_pages"] == 1
    assert progress.stat().st_mode & 0o777 == 0o400
    assert b"Synthetic statement" not in progress.read_bytes()


def test_sequential_pages_exhaust_native_pagination_not_complete_conversation(
    tmp_path: Path,
) -> None:
    config, policy, progress = case(tmp_path)
    for start, end in ((8, 11), (4, 7), (0, 3)):
        source = page(tmp_path, start, end, 12)
        backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
        acknowledge(config)
        result = backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert result["action"] == "native_pagination_exhausted"
    assert result["validated_pages"] == 3
    assert result["conversation_completeness_verified"] is False
    before = progress.read_bytes()
    replay = backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    assert replay["status"] == "already_traversed"
    assert progress.read_bytes() == before


def test_skipped_or_changed_page_refuses_without_advancing(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    backfill.queue_grok_bot_backfill_page(
        config, policy, progress, page(tmp_path, 8, 11, 12), bot_id=BOT
    )
    before = progress.read_bytes()
    with pytest.raises(ValueError):
        backfill.queue_grok_bot_backfill_page(
            config, policy, progress, page(tmp_path, 4, 7, 12), bot_id=BOT
        )
    assert progress.read_bytes() == before
    acknowledge(config)
    backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    with pytest.raises(ValueError):
        backfill.queue_grok_bot_backfill_page(
            config, policy, progress, page(tmp_path, 0, 3, 12), bot_id=BOT
        )


def test_empty_expired_queue_is_not_acknowledgement_and_original_page_replays(
    tmp_path: Path,
) -> None:
    config, policy, progress = case(tmp_path)
    source = page(tmp_path, 8, 11, 12)
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    assert queue.expire(now_epoch=queue.due_uploads()[0].expires_at_epoch + 1) == 2
    assert queue.status().queued_items == 0
    result = backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert result["action"] == "replay_page"
    assert result["transcript"] == str(source)
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    assert queue.status().queued_items == 2
    acknowledge(config)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["request"][
            "before"
        ]
        == 8
    )


def test_pending_intent_survives_process_failure_before_enqueue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, policy, progress = case(tmp_path)
    source = page(tmp_path, 8, 11, 12)

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as scoped:
        scoped.setattr(backfill, "capture_transcript_page", interrupt)
        with pytest.raises(KeyboardInterrupt):
            backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    assert progress.exists()
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["action"]
        == "replay_page"
    )
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    acknowledge(config)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["request"][
            "before"
        ]
        == 8
    )


def test_internal_only_page_records_traversal_without_ingestion(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    backfill.queue_grok_bot_backfill_page(
        config, policy, progress, page(tmp_path, 0, 3, 4, internal_only=True), bot_id=BOT
    )
    result = backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert result["action"] == "native_pagination_exhausted"
    assert CollectorQueue.open(load_collector_config(config).queue).status().queued_items == 0


@pytest.mark.parametrize("tamper", ["bot", "account", "mode", "symlink", "unknown"])
def test_progress_refuses_scope_or_file_tampering(tmp_path: Path, tamper: str) -> None:
    config, policy, progress = case(tmp_path)
    backfill.queue_grok_bot_backfill_page(
        config, policy, progress, page(tmp_path, 8, 11, 12), bot_id=BOT
    )
    if tamper == "mode":
        progress.chmod(0o644)
    elif tamper == "symlink":
        original = progress.with_name("original.json")
        progress.rename(original)
        progress.symlink_to(original)
    else:
        value = json.loads(progress.read_bytes())
        if tamper == "bot":
            value["bot_id"] = COLLECTOR
        elif tamper == "account":
            value["source_account_id"] = "source_account:" + "f" * 64
        else:
            value["unknown"] = "untrusted"
        progress.chmod(0o600)
        progress.write_text(json.dumps(value))
        progress.chmod(0o400)
    with pytest.raises((ValueError, PermissionError)):
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)


def test_head_refresh_does_not_reset_older_frontier(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    backfill.queue_grok_bot_backfill_page(
        config, policy, progress, page(tmp_path, 8, 11, 12), bot_id=BOT
    )
    acknowledge(config)
    backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    before = progress.read_bytes()
    queue = CollectorQueue.open(load_collector_config(config).queue)
    capture_transcript_page(
        queue,
        page(tmp_path, 12, 15, 16).read_bytes(),
        bot_id=BOT,
        scope=load_grok_bot_policy(policy).scope,
    )
    assert progress.read_bytes() == before


def test_cli_next_page_and_reconnect_preserve_the_existing_interface(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, policy, progress = case(tmp_path)
    common = [
        "--config",
        str(config),
        "--policy",
        str(policy),
        "--progress",
        str(progress),
        "--bot-id",
        BOT,
    ]
    main(["grok-bot-capture-next", *common, "--limit", "100"])
    assert json.loads(capsys.readouterr().out)["request"]["limit"] == 100
    source = page(tmp_path, 8, 11, 12)
    main(["grok-bot-capture-page", *common, "--transcript", str(source)])
    assert json.loads(capsys.readouterr().out)["pending_user_texts"] == 1
    acknowledge(config)
    main(["grok-bot-capture-next", *common])
    assert json.loads(capsys.readouterr().out)["request"]["before"] == 8


def test_disabled_or_unenrolled_backfill_never_creates_progress(tmp_path: Path) -> None:
    config, policy, progress = case(tmp_path)
    for bot_id in (COLLECTOR, "abcdef00-0000-4000-8000-000000000003"):
        with pytest.raises(PermissionError):
            backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=bot_id)
    value = json.loads(policy.read_bytes())
    value["enabled"] = False
    policy.chmod(0o600)
    policy.write_text(json.dumps(value))
    policy.chmod(0o400)
    with pytest.raises(PermissionError):
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)
    assert not progress.exists()


def test_partial_queue_crash_flushes_then_replays_missing_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, policy, progress = case(tmp_path)
    source = page(tmp_path, 8, 11, 12)
    original = CollectorQueue.enqueue_upload
    calls = 0

    def interrupt(self: CollectorQueue, body: bytes, *, now_epoch: int | None = None) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        return original(self, body, now_epoch=now_epoch)

    with monkeypatch.context() as scoped:
        scoped.setattr(CollectorQueue, "enqueue_upload", interrupt)
        with pytest.raises(KeyboardInterrupt):
            backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["action"]
        == "flush"
    )
    acknowledge(config)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["action"]
        == "replay_page"
    )
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    assert queue.status().queued_items == 1
    acknowledge(config)
    assert (
        backfill.next_grok_bot_backfill_page(config, policy, progress, bot_id=BOT)["request"][
            "before"
        ]
        == 8
    )


def test_changed_original_page_and_cli_errors_keep_pending_progress_private(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, policy, progress = case(tmp_path)
    source = page(tmp_path, 8, 11, 12)
    backfill.queue_grok_bot_backfill_page(config, policy, progress, source, bot_id=BOT)
    before = progress.read_bytes()
    source.write_text(
        source.read_text().replace("Synthetic statement", "Untrusted private statement")
    )
    with pytest.raises(SystemExit) as error:
        main(
            [
                "grok-bot-capture-page",
                "--config",
                str(config),
                "--policy",
                str(policy),
                "--progress",
                str(progress),
                "--bot-id",
                BOT,
                "--transcript",
                str(source),
            ]
        )
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "Untrusted" not in captured.err and str(source) not in captured.err
    assert progress.read_bytes() == before
