"""Opt-in real Chromium/native-host qualification; synthetic accounts and isolated node only."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from starlette.testclient import TestClient

from cross_assistant_memory.browser_capture_host import (
    load_capture_host_config,
    local_capture_operation,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import SourceSystem
from cross_assistant_memory.storage import Ledger
from cross_assistant_memory.tink_crypto import Keyset
from tests.test_browser_capture_admission import (
    _enrolled_collector,  # pyright: ignore[reportPrivateUsage]
    _register_account,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.skipif(
    os.environ.get("CAM_BROWSER_E2E") != "1", reason="run script/test-browser-capture"
)
def test_real_browser_capture_and_browser_closed_recovery(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    root = tmp_path.resolve() / "capture-e2e"
    root.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    (private / "spool").mkdir(mode=0o700)
    key = private / "fixture.key"
    key.write_bytes(Keyset.generate_aead().serialize_cleartext())
    key.chmod(0o400)
    app, _, enrolled = _enrolled_collector(root / "node", "Synthetic browser E2E")
    specs = [
        ("chatgpt_web", "first@example.test"),
        ("chatgpt_web", "second@example.test"),
        ("claude_web", "claude@example.test"),
        ("grok_web", "grok@example.test"),
    ]
    bindings = [
        {
            "provider": provider,
            "email": email,
            "account_binding": _register_account(
                app,
                enrolled["device_id"],
                source_system=SourceSystem(provider),
                label=email,
            )["source_account_id"],
        }
        for provider, email in specs
    ]
    token_file = private / "fixture.credential"
    token_file.write_text(enrolled["token"])
    token_file.chmod(0o400)
    config_path = private / "config.json"
    outage = threading.Event()
    errors: list[str] = []
    real = create_mcp_server(
        Settings(root / "node"), transport="streamable-http", http_auth_url="http://127.0.0.1:28765"
    )
    with TestClient(real.streamable_http_app()) as client:

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def reply(self, status: int, value: object) -> None:
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path != "/state":
                    self.reply(404, {})
                    return
                config = load_capture_host_config(config_path)
                health = local_capture_operation(config, flush=False)
                ledger = Ledger(Settings(root / "node"))
                matches = ledger.search("SYNTHETICCAPTURE", limit=20)
                self.reply(200, {"health": health, "events": len(matches)})

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path in {"/offline", "/online"}:
                    outage.set() if self.path == "/offline" else outage.clear()
                    self.reply(200, {"ok": True})
                    return
                if self.path != "/upload/browser-observations":
                    self.reply(404, {})
                    return
                if outage.is_set():
                    self.reply(503, {"error": "synthetic outage"})
                    return
                try:
                    response = client.post(
                        self.path,
                        content=body,
                        headers={
                            "authorization": self.headers.get("Authorization", ""),
                            "content-type": "application/json",
                        },
                    )
                    self.reply(response.status_code, response.json())
                except Exception as error:
                    errors.append(type(error).__name__)
                    self.reply(500, {"error": "test server failure"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        config_path.write_text(
            json.dumps(
                {
                    "format_version": 1,
                    "extension_origin": "chrome-extension://" + "a" * 32 + "/",
                    "spool_root": str(private / "spool"),
                    "key_file": str(key),
                    "bindings": bindings,
                    "upload_endpoint": f"http://127.0.0.1:{server.server_port}/upload/browser-observations",
                    "credential_file": str(token_file),
                }
            )
        )
        config_path.chmod(0o600)
        host = private / "host"
        host.write_text(
            f"#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(repo / 'src')!r})\n"
            "from cross_assistant_memory.browser_capture_host import main\n"
            f"sys.argv[1:1] = ['--config', {str(config_path)!r}]\nmain()\n"
        )
        host.chmod(0o700)
        try:
            result = subprocess.run(
                [
                    "node",
                    str(repo / "browser/capture/e2e.mjs"),
                    str(root),
                    str(config_path),
                    str(host),
                    str(server.server_port),
                ],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            proof = json.loads(result.stdout)
            assert proof["browser_closed_recovery"] is True
            assert proof["replayed_without_duplicates"] is True
            assert proof["captured_accounts"] == 4
            assert not errors
            ledger = Ledger(Settings(root / "node"))
            matches = ledger.search("SYNTHETICCAPTURE", limit=20)
            assert len(matches) == 4
            evidence = [ledger.get_evidence(match.event_id) for match in matches]
            assert {row["source_account_id"] for row in evidence} == {
                row["account_binding"] for row in bindings
            }
            assert {row["content_text"] for row in evidence} == {
                "SYNTHETICCAPTURE " + email for _, email in specs
            }
            config = load_capture_host_config(config_path)
            assert (
                cast(dict[str, int], local_capture_operation(config, flush=False)["queue"])[
                    "queued_observations"
                ]
                == 0
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            assert not thread.is_alive()
            # This test owns every byte here, including synthetic keys and the browser profile.
            shutil.rmtree(root)
