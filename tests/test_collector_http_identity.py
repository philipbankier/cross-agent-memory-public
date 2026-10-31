from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

from cross_assistant_memory import collector_runtime
from cross_assistant_memory.collector import CollectorNodeConfig
from cross_assistant_memory.collector_queue import QueueFailureCode
from cross_assistant_memory.grok_bot_capture import (
    GrokBotUserTextObservation,
    build_grok_bot_capture_upload,
)


def test_native_upload_identifies_the_actual_collector_without_changing_auth_or_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = build_grok_bot_capture_upload(
        GrokBotUserTextObservation(
            "00000000-0000-4000-8000-000000000001", "Synthetic identity check."
        ),
        source_account_id="source_account:" + "0" * 64,
    )
    node = CollectorNodeConfig(
        "https://example.invalid:443/upload/batches", tmp_path / "credential", 17
    )
    opener = Mock()
    opener.open.side_effect = OSError("synthetic offline transport")
    factory = Mock(return_value=opener)
    monkeypatch.setattr(collector_runtime, "build_opener", factory)
    result = collector_runtime.post_upload_batch(node, "synthetic-test-token", body)
    assert result is QueueFailureCode.NETWORK_UNREACHABLE
    request = opener.open.call_args.args[0]
    assert request.get_header("User-agent") == "cross-memory-native-collector/0.1.0"
    assert request.get_header("Authorization") == "Bearer synthetic-test-token"
    assert request.get_header("Content-type") == "application/json"
    assert request.data == body and request.full_url == node.upload_url
    assert request.get_method() == "POST"
    assert opener.open.call_args.kwargs == {"timeout": 17}
    assert len(factory.call_args.args) == 1
    assert isinstance(
        factory.call_args.args[0],
        collector_runtime._RejectRedirects,  # pyright: ignore[reportPrivateUsage]
    )
