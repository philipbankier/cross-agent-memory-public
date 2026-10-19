from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from cross_assistant_memory.storage import SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("refusal", ["dirty_checkout", "existing_project"])
def test_preflight_refusal_does_not_clean_unowned_resources(tmp_path: Path, refusal: str) -> None:
    tools = tmp_path / "bin"
    tools.mkdir()
    log = tmp_path / "docker.log"
    (tools / "git").write_text(
        '#!/bin/sh\nif [ "$1" = status ] && [ "$REFUSAL" = dirty_checkout ]; then\n'
        '  printf " M README.md\\n"\nfi\n',
        encoding="utf-8",
    )
    (tools / "docker").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
        'case "$*" in\n'
        '  "info --format {{.OSType}}") printf "linux\\n" ;;\n'
        '  "info --format {{.Architecture}}") printf "aarch64\\n" ;;\n'
        '  ps*|"volume ls"*|"network ls"*) printf "unowned-resource\\n" ;;\n'
        "  *) exit 23 ;;\nesac\n",
        encoding="utf-8",
    )
    for tool in tools.iterdir():
        tool.chmod(0o700)
    result = subprocess.run(
        ["sh", str(ROOT / "script/verify-container")],
        env={
            "PATH": f"{tools}:/usr/bin:/bin",
            "PYTHON": sys.executable,
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "REFUSAL": refusal,
            "DOCKER_LOG": str(log),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    expected = (
        "clean tracked worktree" if refusal == "dirty_checkout" else "resources already exist"
    )
    assert expected in result.stdout + result.stderr
    commands = log.read_text() if log.exists() else ""
    assert "down" not in commands
    assert "image rm" not in commands
    assert not list(tmp_path.glob("cam-container.*"))


@pytest.mark.parametrize("stage,clients", [("BEFORE", 0), ("AFTER", 1)])
@pytest.mark.parametrize("expected_schema", [SCHEMA_VERSION, SCHEMA_VERSION + 1])
def test_doctor_gate_uses_the_installed_schema(
    stage: str, clients: int, expected_schema: int
) -> None:
    import json

    source = (ROOT / "script/verify-container").read_text()
    start = source.index(f"printf '%s' \"$DOCTOR_{stage}\"")
    command = source[start : source.index("\n\n", start)]
    result = subprocess.run(
        ["sh", "-c", command],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHON": sys.executable,
            "EXPECTED_SCHEMA": str(expected_schema),
            f"DOCTOR_{stage}": json.dumps(
                {
                    "status": "ready",
                    "ledger": {"schema_version": expected_schema, "clients": clients},
                }
            ),
        },
        timeout=5,
    )
    assert result.returncode == 0, result.stderr

    wrong_schema = json.dumps(
        {
            "status": "ready",
            "ledger": {"schema_version": expected_schema - 1, "clients": clients},
        }
    )
    result = subprocess.run(
        ["sh", "-c", command],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHON": sys.executable,
            "EXPECTED_SCHEMA": str(expected_schema),
            f"DOCTOR_{stage}": wrong_schema,
        },
        timeout=5,
    )
    assert result.returncode != 0


def test_docker_loopback_probe_keeps_stdin_and_requires_execution() -> None:
    source = (ROOT / "script/verify-container").read_text()
    start = source.index("docker run")
    command = source[start : source.index("<<'PY'", start)].replace("\\\n", " ")
    assert "-i" in shlex.split(command)
    assert 'print("cam-loopback-ok")' in source
    assert '[ "$HOST_LOOPBACK_RESULT" != "cam-loopback-ok" ]' in source


def test_fresh_volume_is_not_reported_as_a_migration() -> None:
    source = (ROOT / "script/verify-container").read_text()
    assert '"fresh_schema": "passed"' in source
    assert '"migration": "passed"' not in source


def test_standalone_runtime_notices_are_pinned_and_verified() -> None:
    digest = "e43fb936c6655d7996dba480d7ebdea492d6040ec388eb8ed9d1000f72de8cab"
    upstream = "9e40cba825ca0997a01cab9f60a0b15ffb976af2/python-licenses.rst"
    container = (ROOT / "Containerfile").read_text()
    verifier = (ROOT / "script/verify-container").read_text()
    assert "ADD --checksum=sha256:" + digest in container
    assert "chmod 0755 /usr/share/doc/cross-agent-memory" in container
    assert "chmod 0444 /usr/share/doc/cross-agent-memory/python-runtime-licenses.rst" in container
    assert upstream in container
    assert digest in verifier
    assert '"runtime_notices": "passed"' in verifier
    for source in (container, verifier):
        assert "/usr/share/doc/cross-agent-memory/python-runtime-licenses.rst" in source


@pytest.mark.parametrize(
    "version,ca_count,accepted",
    [
        ((3, 40, 1), 1, False),
        ((3, 51, 0), 1, False),
        ((3, 51, 3), 1, True),
        ((3, 53, 1), 1, True),
        ((3, 53, 1), 0, False),
    ],
)
def test_runtime_probe_refuses_sqlite_before_the_wal_fix(
    version: tuple[int, int, int], ca_count: int, accepted: bool
) -> None:
    source = (ROOT / "script/verify-container").read_text()
    marker = "RUNTIME_CHECK=$(docker exec -i \"$CONTAINER_ID\" python - <<'PY'\n"
    start = source.index(marker) + len(marker)
    probe = source[start : source.index("\nPY", start)]
    command = (
        "import sqlite3, ssl, types;\n"
        f"sqlite3.sqlite_version_info = {version!r};\n"
        "ssl.create_default_context = lambda: types.SimpleNamespace("
        f"cert_store_stats=lambda: {{'x509_ca': {ca_count}}});\n" + probe
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", command],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is accepted, result.stderr
    if not accepted:
        expected = (
            "TLS trust store is required" if ca_count == 0 else "SQLite WAL-reset fix is required"
        )
        assert expected in result.stderr
