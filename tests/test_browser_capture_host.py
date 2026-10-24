from __future__ import annotations

import io
import json
import struct
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.browser_capture_host import (
    CaptureHostConfig,
    handle_capture_request,
    load_capture_host_config,
    serve_once,
)

ORIGIN = "chrome-extension://" + "a" * 32 + "/"
BINDING = "source_account:" + "b" * 64


@pytest.fixture
def host_config(tmp_path: Path) -> CaptureHostConfig:
    return CaptureHostConfig(
        ORIGIN,
        tmp_path / "spool",
        tmp_path / "key",
        {("chatgpt_web", "owner@example.test"): BINDING},
    )


def test_account_authorization_is_exact(host_config: CaptureHostConfig) -> None:
    def authorize(provider: str, email: str) -> dict[str, str]:
        return handle_capture_request(
            json.dumps(
                {"operation": "authorize", "provider": provider, "account_email": email}
            ).encode(),
            host_config,
            ORIGIN,
        )

    assert authorize("chatgpt_web", "owner@example.test") == {"status": "ready"}
    assert authorize("grok_web", "owner@example.test") == {"status": "account_not_authorized"}
    assert authorize("chatgpt_web", "other@example.test") == {"status": "account_not_authorized"}


def test_extension_identity_is_required(host_config: CaptureHostConfig) -> None:
    assert handle_capture_request(
        b'{"operation":"status"}', host_config, "chrome-extension://" + "b" * 32 + "/"
    ) == {"status": "capture_failed"}


@pytest.mark.parametrize(
    "body", [b"{}", b"[]", b"\xff", b'{"operation":"status","operation":"observe"}']
)
def test_bad_requests_are_sanitized(host_config: CaptureHostConfig, body: bytes) -> None:
    assert handle_capture_request(body, host_config, ORIGIN) == {"status": "schema_rejected"}


def test_unknown_account_is_rejected_before_text_parsing(host_config: CaptureHostConfig) -> None:
    request = {
        "operation": "observe",
        "account_email": "other@example.test",
        "observation": {"provider": "chatgpt_web", "text": "not inspected"},
    }
    assert handle_capture_request(json.dumps(request).encode(), host_config, ORIGIN) == {
        "status": "account_not_authorized"
    }


def test_browser_cannot_choose_its_own_binding(host_config: CaptureHostConfig) -> None:
    request = {
        "operation": "observe",
        "account_email": "owner@example.test",
        "observation": {"provider": "chatgpt_web", "account_binding": BINDING},
    }
    assert handle_capture_request(json.dumps(request).encode(), host_config, ORIGIN) == {
        "status": "schema_rejected"
    }


@pytest.mark.parametrize(
    "frame", [b"", b"\x01", struct.pack("=I", 300000), struct.pack("=I", 10) + b"{}"]
)
def test_short_and_oversize_frames_return_one_reply(
    host_config: CaptureHostConfig, frame: bytes
) -> None:
    out = io.BytesIO()
    serve_once(io.BytesIO(frame), out, host_config, ORIGIN)
    data = out.getvalue()
    assert struct.unpack("=I", data[:4])[0] == len(data) - 4
    assert json.loads(data[4:]) == {"status": "schema_rejected"}


def test_configuration_is_private_and_does_not_create_files(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    value = {
        "format_version": 1,
        "extension_origin": ORIGIN,
        "spool_root": str(tmp_path / "spool"),
        "key_file": str(tmp_path / "key"),
        "bindings": [
            {"provider": "chatgpt_web", "email": "owner@example.test", "account_binding": BINDING}
        ],
    }
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    result = load_capture_host_config(path)
    assert result.bindings[("chatgpt_web", "owner@example.test")] == BINDING
    assert not result.spool_root.exists()
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        load_capture_host_config(path)


def test_page_diagnostics_keep_only_authorized_opaque_identity(
    host_config: CaptureHostConfig,
) -> None:
    from cross_assistant_memory.browser_capture_diagnostics import inspect_diagnostics

    request = {
        "operation": "diagnostic",
        "page_key": "c" * 64,
        "provider": "chatgpt_web",
        "status": "ready_to_queue",
        "extension_version": "0.2.0",
        "account_email": "owner@example.test",
    }
    assert handle_capture_request(json.dumps(request).encode(), host_config, ORIGIN) == {
        "status": "ready"
    }
    health = inspect_diagnostics(host_config.spool_root)
    assert cast(list[dict[str, object]], health["pages"])[0]["account_binding"] == BINDING
    assert "owner@example.test" not in json.dumps(health)
    assert handle_capture_request(
        json.dumps({**request, "account_email": "other@example.test"}).encode(), host_config, ORIGIN
    ) == {"status": "account_not_authorized"}
    assert handle_capture_request(
        json.dumps({**request, "text": "PRIVATE"}).encode(), host_config, ORIGIN
    ) == {"status": "schema_rejected"}
