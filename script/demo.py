"""Run the real panel against disposable invented history, never the owner's node."""

from __future__ import annotations

import json
import signal
import sys
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import uvicorn

from cross_assistant_memory.config import Settings
from cross_assistant_memory.control_panel import (
    create_control_panel_app,
    reserve_control_panel_listener,
)
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import CLIENT_KIND_CAPABILITIES, ClientKind, Scope, SourceSystem
from cross_assistant_memory.storage import Ledger


def seed_demo(root: Path) -> tuple[Settings, str]:
    settings = Settings(root / "node")
    ledger = Ledger(settings)
    samples = (
        (
            SourceSystem.CODEX,
            "Run Atlas on the office Mac.",
            "Atlas will use the office Mac. The earlier cloud VM idea is parked.",
        ),
        (
            SourceSystem.CLAUDE_CODE,
            "What did we decide for Atlas?",
            "The office Mac is the chosen host for Atlas, according to the user decision.",
        ),
        (
            SourceSystem.GROK_BUILD,
            "What remains for Atlas?",
            "Atlas deployment is reported complete. A live health check is still needed.",
        ),
    )
    for source, question, answer in samples:
        records: list[dict[str, Any]] = []
        if source is SourceSystem.CODEX:
            records.append(
                {"type": "session_meta", "payload": {"id": "demo-atlas", "source": "vscode"}}
            )
        for index, (role, text) in enumerate((("user", question), ("assistant", answer))):
            timestamp = f"2026-01-03T12:00:0{index}Z"
            if source is SourceSystem.CODEX:
                record = {
                    "timestamp": timestamp,
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": role,
                        "phase": "final_answer" if index else None,
                        "content": [
                            {"type": "output_text" if index else "input_text", "text": text}
                        ],
                    },
                }
            elif source is SourceSystem.CLAUDE_CODE:
                record = {
                    "type": role,
                    "sessionId": "demo-atlas",
                    "entrypoint": "claude-desktop",
                    "uuid": f"demo-{index}",
                    "parentUuid": "demo-0" if index else None,
                    "timestamp": timestamp,
                    "message": {"role": role, "content": [{"type": "text", "text": text}]},
                }
            else:
                record = {
                    "timestamp": timestamp,
                    "method": "session/update",
                    "params": {
                        "sessionId": "demo-atlas",
                        "update": {
                            "sessionUpdate": "agent_message_chunk"
                            if index
                            else "user_message_chunk",
                            "content": {"type": "text", "text": text},
                            "_meta": {"promptIndex": index},
                        },
                    },
                }
            records.append(record)
        path = root / f"{source.value}.jsonl"
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        path.chmod(0o600)
        result = ledger.ingest(
            parse_file(path, source),
            source_account="synthetic-demo",
            scope=Scope.USER_GLOBAL,
            project_id=None,
        )
        if result.inserted_events != 2:
            raise RuntimeError("synthetic demo import did not produce two events")
    client = ledger.register_client(
        label="Disposable demo admin",
        kind=ClientKind.LOCAL_ADMIN,
        capabilities=tuple(CLIENT_KIND_CAPABILITIES[ClientKind.LOCAL_ADMIN]),
    )
    credential = ledger.issue_client_credential(
        client["client_id"], expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    return settings, str(credential["token"])


@contextmanager
def demo_node() -> Generator[tuple[Settings, str]]:
    with tempfile.TemporaryDirectory(prefix="cam-demo-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        yield seed_demo(root)


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("usage: script/demo (no paths, accounts or configuration accepted)")
    with demo_node() as (settings, token):
        listener, port = reserve_control_panel_listener()
        try:
            app = create_control_panel_app(settings, host="127.0.0.1", port=port)
            print(f"Synthetic demo only: http://127.0.0.1:{port}", flush=True)
            print(f"Disposable demo unlock credential: {token}", flush=True)
            print(
                "Search for Atlas. No accounts connected. "
                "Ctrl-C removes this demo's temporary data.",
                flush=True,
            )
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host="127.0.0.1",
                    port=port,
                    access_log=False,
                    log_level="warning",
                    proxy_headers=False,
                    server_header=False,
                )
            )
            server.run(sockets=[listener])
        finally:
            listener.close()


if __name__ == "__main__":

    def terminate(_signal: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    main()
