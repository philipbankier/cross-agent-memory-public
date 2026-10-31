from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.cli import main
from cross_assistant_memory.collector import COLLECTOR_CONFIG_FORMAT_VERSION, load_collector_config
from cross_assistant_memory.collector_queue import CollectorQueue
from cross_assistant_memory.grok_bot_collector import (
    flush_grok_bot_capture,
    grok_bot_capture_status,
    load_grok_bot_policy,
    queue_grok_bot_page,
)

BOT = "abcdef00-0000-4000-8000-000000000001"
COLLECTOR = "abcdef00-0000-4000-8000-000000000002"


def _case(root: Path) -> tuple[Path, Path, Path]:
    secret = root / "private"
    secret.mkdir(mode=0o700)
    queue = root / "queue"
    queue.mkdir(mode=0o700)
    config = root / "collector.json"
    config.write_text(
        json.dumps(
            {
                "format_version": COLLECTOR_CONFIG_FORMAT_VERSION,
                "node": {
                    "upload_url": "https://example.invalid:443/upload/batches",
                    "credential_file": str(secret / "collector.token"),
                    "timeout_seconds": 5,
                },
                "queue": {
                    "root": str(queue),
                    "key_file": str(secret / "key.tink"),
                    "max_bytes": 1024 * 1024,
                    "max_age_seconds": 86400,
                },
                "sources": [],
            }
        )
    )
    policy = secret / "policy.json"
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
    page = root / "upstream-page.txt"
    record = {
        "role": "assistant",
        "message": {
            "content": [
                {"type": "thinking", "thinking": "Synthetic excluded thought."},
                {
                    "type": "tool_use",
                    "id": "synthetic-call-1",
                    "name": "SendToUser",
                    "input": {"content": "Synthetic outward reply."},
                },
            ]
        },
    }
    page.write_text(
        '<cursor_untrusted_data_1337 source="ReadTranscript">\n\n'
        f'Transcript of agent "Synthetic" ({BOT}), positions 0\u20130 of 1:\n'
        + json.dumps(record)
        + "\n\n</cursor_untrusted_data_1337>\n"
    )
    return config, policy, page


def test_capture_cli_queues_without_network_and_status_is_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, policy, page = _case(tmp_path)
    main(
        [
            "grok-bot-capture-page",
            "--config",
            str(config),
            "--policy",
            str(policy),
            "--transcript",
            str(page),
            "--bot-id",
            BOT,
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "queued_not_admitted"
    assert result["pending_replies"] == 1
    assert "outward" not in json.dumps(result)
    queue = CollectorQueue.open(load_collector_config(config).queue)
    before = hashlib.sha256(queue.database_path.read_bytes()).hexdigest()
    status = grok_bot_capture_status(config, policy)
    assert status["coverage"] == "reply_requests_only"
    assert status["native_conversation_identity_verified"] is False
    assert status["freshness_guaranteed"] is False
    assert cast(dict[str, object], status["queue"])["queued_items"] == 1
    assert hashlib.sha256(queue.database_path.read_bytes()).hexdigest() == before
    assert b"outward reply" not in queue.database_path.read_bytes()
    assert b"excluded thought" not in queue.database_path.read_bytes()
    replay = queue_grok_bot_page(config, policy, page, bot_id=BOT)
    assert replay["pending_replies"] == 1
    assert queue.status().queued_items == 1


def test_disabled_policy_refuses_page_and_network_without_changing_queue(tmp_path: Path) -> None:
    config, policy, page = _case(tmp_path)
    queue_grok_bot_page(config, policy, page, bot_id=BOT)
    policy.chmod(0o600)
    policy.write_text(policy.read_text().replace('"enabled": true', '"enabled": false'))
    policy.chmod(0o400)
    assert load_grok_bot_policy(policy).enabled is False
    queue = CollectorQueue.open(load_collector_config(config).queue)
    before = queue.database_path.read_bytes()
    with pytest.raises(PermissionError):
        queue_grok_bot_page(config, policy, page, bot_id=BOT)
    with pytest.raises(PermissionError):
        flush_grok_bot_capture(config, policy)
    assert queue.database_path.read_bytes() == before
    assert queue.status().queued_items == 1
    assert grok_bot_capture_status(config, policy)["enabled"] is False


def test_status_refuses_an_uninitialized_queue_without_creating_one(tmp_path: Path) -> None:
    config, policy, _ = _case(tmp_path)
    with pytest.raises((ValueError, FileNotFoundError)):
        grok_bot_capture_status(config, policy)
    assert not (tmp_path / "queue" / "queue.sqlite3").exists()


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_policy_requires_immutable_owner_only_permissions(tmp_path: Path, mode: int) -> None:
    _, policy, _ = _case(tmp_path)
    policy.chmod(mode)
    with pytest.raises(ValueError):
        load_grok_bot_policy(policy)


def test_policy_refuses_unknown_fields_and_self_capture(tmp_path: Path) -> None:
    _, policy, _ = _case(tmp_path)
    for updated in (
        policy.read_text().replace(BOT, COLLECTOR),
        policy.read_text().replace('"enabled": true', '"enabled": true, "unknown": "secret"'),
        policy.read_text().replace('"format_version": 1', '"format_version": true'),
    ):
        policy.chmod(0o600)
        policy.write_text(updated)
        policy.chmod(0o400)
        with pytest.raises(ValueError):
            load_grok_bot_policy(policy)


def test_cli_refusal_does_not_print_untrusted_paths_or_payloads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, policy, page = _case(tmp_path)
    with pytest.raises(SystemExit) as error:
        main(
            [
                "grok-bot-capture-page",
                "--config",
                str(config),
                "--policy",
                str(policy),
                "--transcript",
                str(page),
                "--bot-id",
                "synthetic-untrusted-identity",
            ]
        )
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "status": "refused",
        "text_free": True,
        "error_type": "PermissionError",
    }
    assert str(tmp_path) not in output.err
    assert "synthetic" not in output.err


@pytest.mark.parametrize("limit", [0, 5, True])
def test_flush_bounds_are_checked_before_queue_or_network(tmp_path: Path, limit: int) -> None:
    config, policy, _ = _case(tmp_path)
    with pytest.raises(ValueError):
        flush_grok_bot_capture(config, policy, limit=limit)
    assert not (tmp_path / "queue" / "queue.sqlite3").exists()
