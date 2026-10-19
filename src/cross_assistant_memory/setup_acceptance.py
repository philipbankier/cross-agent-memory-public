from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.request
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.storage import SCHEMA_VERSION

GATE_FIELDS = {
    "format_version",
    "kind",
    "action",
    "target",
    "target_state_sha256",
    "impact",
    "rollback",
    "gate_sha256",
}


def main() -> None:
    cli = _cli_path()
    revision = _revision()
    with tempfile.TemporaryDirectory(prefix="cam-agent-setup-") as temporary:
        receipt = _run_acceptance(Path(temporary).resolve(), cli, revision)
    print(json.dumps(receipt, indent=2, sort_keys=True))


def _run_acceptance(base: Path, cli: Path, revision: str) -> dict[str, object]:
    _chmod(base, 0o700)
    node = _private_directory(base / "node-parent") / "memory"
    private = _private_directory(base / "private")
    collector_private = _private_directory(base / "collector-private")
    synthetic_home = _private_directory(base / "home")
    source_root = _private_directory(base / "synthetic-source")
    environment = {**os.environ, "HOME": str(synthetic_home), "PYTHONDONTWRITEBYTECODE": "1"}
    outputs: list[dict[str, Any]] = []
    plan_hashes: dict[str, str] = {}
    gate_hashes: dict[str, str] = {}

    setup_plan_path = private / "local-ledger.plan.json"
    setup_plan = _run_json(
        cli,
        ["--home", node, "setup-plan", "--output", setup_plan_path],
        environment,
    )
    outputs.append(setup_plan)
    setup_sha = _sha256_field(setup_plan, "plan_sha256")
    plan_hashes["local_ledger"] = setup_sha
    assert setup_plan["required_human_gates"] == []
    setup_preview = _run_json(
        cli,
        [
            "--home",
            node,
            "setup-apply",
            "--plan",
            setup_plan_path,
            "--expected-plan-sha256",
            setup_sha,
        ],
        environment,
    )
    outputs.append(setup_preview)
    _require_status(setup_preview, "awaiting_execute")
    setup_first = _run_json(
        cli,
        [
            "--home",
            node,
            "setup-apply",
            "--plan",
            setup_plan_path,
            "--expected-plan-sha256",
            setup_sha,
            "--execute",
        ],
        environment,
    )
    outputs.append(setup_first)
    _require_status(setup_first, "initialized")

    client_plan_path = private / "assistant-client.plan.json"
    client_plan_args: list[str | Path] = [
        "--home",
        node,
        "client-registration-plan",
        "--output",
        client_plan_path,
        "--label",
        "Synthetic Codex",
        "--kind",
        "assistant",
        "--intent-key",
        "assistant:synthetic:codex",
        "--capability",
        "memory:search",
        "--capability",
        "memory:evidence-read",
        "--capability",
        "memory:status",
    ]
    client_plan = _run_json(cli, client_plan_args, environment)
    outputs.append(client_plan)
    client_sha = _sha256_field(client_plan, "plan_sha256")
    plan_hashes["assistant_client"] = client_sha
    gate_hashes["assistant_client"] = _require_gate(client_plan, "client_identity_change")
    client_preview = _apply_identity(
        cli,
        node,
        "client-registration-apply",
        client_plan_path,
        client_sha,
        environment,
        execute=False,
    )
    outputs.append(client_preview)
    _require_status(client_preview, "awaiting_human_gate")
    client_first = _apply_identity(
        cli,
        node,
        "client-registration-apply",
        client_plan_path,
        client_sha,
        environment,
        execute=True,
    )
    outputs.append(client_first)
    _require_status(client_first, "configured")
    client_id = _nested_string(client_first, "result", "client_id")

    credential_plan_path = private / "assistant-credential.plan.json"
    credential_output = private / "assistant.token"
    credential_plan_args: list[str | Path] = [
        "--home",
        node,
        "client-credential-plan",
        "--output",
        credential_plan_path,
        "--client-id",
        client_id,
        "--intent-key",
        "primary",
        "--ttl-hours",
        "24",
        "--credential-output",
        credential_output,
    ]
    credential_plan = _run_json(cli, credential_plan_args, environment)
    outputs.append(credential_plan)
    credential_sha = _sha256_field(credential_plan, "plan_sha256")
    plan_hashes["assistant_credential"] = credential_sha
    gate_hashes["assistant_credential"] = _require_gate(credential_plan, "client_credential_change")
    credential_preview = _apply_identity(
        cli,
        node,
        "client-credential-apply",
        credential_plan_path,
        credential_sha,
        environment,
        execute=False,
    )
    outputs.append(credential_preview)
    _require_status(credential_preview, "awaiting_human_gate")
    credential_first = _apply_identity(
        cli,
        node,
        "client-credential-apply",
        credential_plan_path,
        credential_sha,
        environment,
        execute=True,
    )
    outputs.append(credential_first)
    _require_status(credential_first, "configured")

    enrollment_plan_path = private / "device-enrollment.plan.json"
    enrollment_output = private / "device-enrollment.code"
    enrollment_plan_args: list[str | Path] = [
        "--home",
        node,
        "device-enrollment-plan",
        "--output",
        enrollment_plan_path,
        "--label",
        "Synthetic collector",
        "--platform",
        f"{platform.system()} {platform.machine()}",
        "--intent-key",
        "device:synthetic:collector",
        "--ttl-minutes",
        "10",
        "--credential-ttl-days",
        "1",
        "--enrollment-output",
        enrollment_output,
    ]
    enrollment_plan = _run_json(cli, enrollment_plan_args, environment)
    outputs.append(enrollment_plan)
    enrollment_sha = _sha256_field(enrollment_plan, "plan_sha256")
    plan_hashes["device_enrollment"] = enrollment_sha
    gate_hashes["device_enrollment"] = _require_gate(enrollment_plan, "device_enrollment_change")
    enrollment_preview = _apply_identity(
        cli,
        node,
        "device-enrollment-apply",
        enrollment_plan_path,
        enrollment_sha,
        environment,
        execute=False,
    )
    outputs.append(enrollment_preview)
    _require_status(enrollment_preview, "awaiting_human_gate")
    enrollment_first = _apply_identity(
        cli,
        node,
        "device-enrollment-apply",
        enrollment_plan_path,
        enrollment_sha,
        environment,
        execute=True,
    )
    outputs.append(enrollment_first)
    _require_status(enrollment_first, "configured")
    enrollment_id = _nested_string(enrollment_first, "result", "enrollment_id")
    device_platform = f"{platform.system()} {platform.machine()}"

    port = _free_port()
    enrollment_url = f"http://127.0.0.1:{port}/enroll"
    collector_output = collector_private / "collector.token"
    collector_args: list[str | Path] = [
        "collector-enroll",
        "--url",
        enrollment_url,
        "--credential-output",
        collector_output,
        "--enrollment-id",
        enrollment_id,
        "--device-label",
        "Synthetic collector",
        "--device-platform",
        device_platform,
    ]
    collector_preview = _run_json(cli, collector_args, environment)
    outputs.append(collector_preview)
    collector_sha = _sha256_field(collector_preview, "plan_sha256")
    plan_hashes["collector_pairing"] = collector_sha
    gate_hashes["collector_pairing"] = _require_gate(collector_preview, "client_credential_change")
    server_log = private / "loopback-server.log"
    with _loopback_server(cli, node, port, server_log, environment):
        enrollment_code = _read_secret(enrollment_output)
        collector_first = _run_json(
            cli,
            [*collector_args, "--expected-plan-sha256", collector_sha, "--execute"],
            environment,
            input_text=f"{enrollment_code}\n",
        )
    outputs.append(collector_first)
    _require_status(collector_first, "enrolled")
    device_id = _string_field(collector_first, "device_id")

    source_plan_path = private / "source-account.plan.json"
    source_plan_args: list[str | Path] = [
        "--home",
        node,
        "source-registration-plan",
        "--output",
        source_plan_path,
        "--device-id",
        device_id,
        "--source-system",
        "codex",
        "--account-label",
        "synthetic-codex-primary",
        "--scope",
        "user_global",
    ]
    source_plan = _run_json(cli, source_plan_args, environment)
    outputs.append(source_plan)
    source_sha = _sha256_field(source_plan, "plan_sha256")
    plan_hashes["source_account"] = source_sha
    gate_hashes["source_account"] = _require_gate(source_plan, "source_registration")
    source_preview = _apply_identity(
        cli,
        node,
        "source-registration-apply",
        source_plan_path,
        source_sha,
        environment,
        execute=False,
    )
    outputs.append(source_preview)
    _require_status(source_preview, "awaiting_human_gate")
    source_first = _apply_identity(
        cli,
        node,
        "source-registration-apply",
        source_plan_path,
        source_sha,
        environment,
        execute=True,
    )
    outputs.append(source_first)
    _require_status(source_first, "configured")
    source_account_id = _nested_string(source_first, "result", "source_account_id")

    config = private / "collector.json"
    _write_private_json(
        config,
        {
            "format_version": 2,
            "node": {
                "upload_url": f"http://127.0.0.1:{port}/upload/batches",
                "credential_file": str(collector_output),
                "timeout_seconds": 5,
            },
            "queue": {
                "root": str(base / "queue"),
                "key_file": str(collector_private / "queue-key.tink"),
                "max_bytes": 1024 * 1024,
                "max_age_seconds": 3600,
            },
            "sources": [
                {
                    "source_system": "codex",
                    "source_account_id": source_account_id,
                    "root": str(source_root),
                    "source_client_version": "synthetic-acceptance",
                }
            ],
        },
    )
    config_result = _run_json(cli, ["collector-config-validate", "--config", config], environment)
    outputs.append(config_result)
    _require_status(config_result, "valid")
    if config_result.get("source_count") != 1:
        raise RuntimeError("collector config did not preserve the exact source count")

    service_platform = "launchd" if platform.system() == "Darwin" else "systemd"
    service_args: list[str | Path] = [
        "collector-service-install",
        "--platform",
        service_platform,
        "--config",
        config,
        "--executable",
        cli,
    ]
    service_first = _run_json(cli, service_args, environment)
    service_second = _run_json(cli, service_args, environment)
    outputs.extend((service_first, service_second))
    service_sha = _sha256_field(service_first, "plan_sha256")
    if _sha256_field(service_second, "plan_sha256") != service_sha:
        raise RuntimeError("collector service preview was not deterministic")
    plan_hashes["collector_service"] = service_sha
    gate_hashes["collector_service"] = _require_gate(service_first, "service_installation")
    _require_gate(service_second, "service_installation")

    second_pass = [
        _run_json(
            cli,
            [
                "--home",
                node,
                "setup-apply",
                "--plan",
                setup_plan_path,
                "--expected-plan-sha256",
                setup_sha,
                "--execute",
            ],
            environment,
        ),
        _run_json(cli, client_plan_args, environment),
        _apply_identity(
            cli,
            node,
            "client-registration-apply",
            client_plan_path,
            client_sha,
            environment,
            execute=True,
        ),
        _run_json(cli, credential_plan_args, environment),
        _apply_identity(
            cli,
            node,
            "client-credential-apply",
            credential_plan_path,
            credential_sha,
            environment,
            execute=True,
        ),
        _run_json(cli, enrollment_plan_args, environment),
        _apply_identity(
            cli,
            node,
            "device-enrollment-apply",
            enrollment_plan_path,
            enrollment_sha,
            environment,
            execute=True,
        ),
        _run_json(
            cli,
            [*collector_args, "--expected-plan-sha256", collector_sha, "--execute"],
            environment,
            input_text="",
        ),
        _run_json(cli, source_plan_args, environment),
        _apply_identity(
            cli,
            node,
            "source-registration-apply",
            source_plan_path,
            source_sha,
            environment,
            execute=True,
        ),
    ]
    outputs.extend(second_pass)
    _require_status(second_pass[0], "already_configured")
    for result in (second_pass[1], second_pass[3], second_pass[5], second_pass[8]):
        if result.get("plan_reused") is not True:
            raise RuntimeError("second-pass plan did not reuse the exact sealed intent")
    for result in (second_pass[2], second_pass[4], second_pass[6], second_pass[9]):
        _require_status(result, "already_configured")
    _require_status(second_pass[7], "already_enrolled")
    if any(
        second_pass[7].get(field) is not False
        for field in ("network_used", "code_read", "credential_written")
    ):
        raise RuntimeError("completed collector enrollment replay performed work")

    verified = _run_json(cli, ["--home", node, "setup-verify"], environment)
    doctor = _run_json(cli, ["--home", node, "doctor"], environment)
    outputs.extend((verified, doctor))
    _require_status(verified, "verified")
    _require_status(doctor, "ready")
    if verified.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("unexpected schema version after setup")

    counts = _identity_counts(node / "ledger.sqlite3")
    expected_counts = {
        "clients": 2,
        "client_credentials": 2,
        "devices": 1,
        "device_enrollments": 1,
        "source_accounts": 1,
        "source_account_policies": 1,
    }
    if counts != expected_counts:
        raise RuntimeError("identity resources were duplicated or omitted")

    secret_files = {credential_output, enrollment_output, collector_output}
    secret_values = {_read_secret(path) for path in secret_files}
    _assert_no_secret_in_outputs(outputs, secret_values)
    _assert_secret_locations(base, secret_files, secret_values)
    _assert_modes(
        plan_paths={
            setup_plan_path,
            client_plan_path,
            credential_plan_path,
            enrollment_plan_path,
            source_plan_path,
        },
        secret_paths=secret_files,
        config=config,
    )

    receipt: dict[str, object] = {
        "format_version": 1,
        "kind": "agent_guided_setup_acceptance",
        "revision": revision,
        "platform": platform.system().lower(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "schema_version": SCHEMA_VERSION,
        "synthetic_only": True,
        "network_scope": "loopback_only",
        "live_service_changed": False,
        "source_content_opened": False,
        "checks": {
            "cli_sequence": "passed",
            "typed_human_gates": "passed",
            "exact_plan_reuse": "passed",
            "second_pass_noop": "passed",
            "loopback_pairing": "passed",
            "identity_counts": "passed",
            "secret_locations": "passed",
            "service_preview": "passed",
            "setup_verify": "passed",
            "doctor": "passed",
        },
        "identity_counts": counts,
        "plan_sha256": plan_hashes,
        "gate_sha256": gate_hashes,
        "cli_sha256": _file_sha256(cli),
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical_json(receipt)).hexdigest()
    return receipt


def _apply_identity(
    cli: Path,
    node: Path,
    command: str,
    plan: Path,
    digest: str,
    environment: dict[str, str],
    *,
    execute: bool,
) -> dict[str, Any]:
    arguments: list[str | Path] = [
        "--home",
        node,
        command,
        "--plan",
        plan,
        "--expected-plan-sha256",
        digest,
    ]
    if execute:
        arguments.append("--execute")
    return _run_json(cli, arguments, environment)


def _run_json(
    cli: Path,
    arguments: Sequence[str | Path],
    environment: dict[str, str],
    *,
    input_text: str | None = None,
) -> dict[str, Any]:
    command = [str(cli), *(str(argument) for argument in arguments)]
    completed = subprocess.run(
        command,
        input=input_text,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        operation = str(arguments[2] if arguments and arguments[0] == "--home" else arguments[0])
        raise RuntimeError(
            f"cross-memory operation {operation!r} failed with exit {completed.returncode}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("cross-memory returned non-JSON output") from error
    if not isinstance(value, dict):
        raise RuntimeError("cross-memory returned a non-object result")
    return cast(dict[str, Any], value)


@contextmanager
def _loopback_server(
    cli: Path,
    node: Path,
    port: int,
    log_path: Path,
    environment: dict[str, str],
) -> Generator[None]:
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    log = os.fdopen(descriptor, "wb")
    process = subprocess.Popen(
        [
            str(cli),
            "--home",
            str(node),
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    try:
        _wait_for_health(process, port)
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()


def _wait_for_health(process: subprocess.Popen[bytes], port: int) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("loopback node exited before enrollment")
        try:
            with opener.open(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                if response.status == 200 and json.load(response) == {"status": "ok"}:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise RuntimeError("loopback node did not become ready")


def _require_gate(result: dict[str, Any], expected_kind: str) -> str:
    gates = result.get("required_human_gates")
    if not isinstance(gates, list):
        raise RuntimeError("operation did not expose exactly one typed human gate")
    items = cast(list[object], gates)
    if len(items) != 1 or not isinstance(items[0], dict):
        raise RuntimeError("operation did not expose exactly one typed human gate")
    gate = cast(dict[str, Any], items[0])
    if set(gate) != GATE_FIELDS or gate.get("format_version") != 1:
        raise RuntimeError("human gate fields do not match format version 1")
    if gate.get("kind") != expected_kind:
        raise RuntimeError("operation exposed the wrong human gate kind")
    digest = _sha256_field(gate, "gate_sha256")
    expected = hashlib.sha256(
        _canonical_json({key: value for key, value in gate.items() if key != "gate_sha256"})
    ).hexdigest()
    if digest != expected:
        raise RuntimeError("human gate SHA-256 does not bind its content")
    _sha256_field(gate, "target_state_sha256")
    for field in ("action", "target", "impact", "rollback"):
        _string_field(gate, field)
    return digest


def _assert_no_secret_in_outputs(
    outputs: Sequence[dict[str, Any]],
    secrets: set[str],
) -> None:
    rendered = json.dumps(outputs, sort_keys=True)
    if any(secret in rendered for secret in secrets):
        raise RuntimeError("secret material appeared in command output")


def _assert_secret_locations(base: Path, expected: set[Path], secrets: set[str]) -> None:
    locations: set[Path] = set()
    encoded = {secret.encode("ascii") for secret in secrets}
    for path in base.rglob("*"):
        if path.is_file() and not path.is_symlink():
            content = path.read_bytes()
            if any(secret in content for secret in encoded):
                locations.add(path)
    if locations != expected:
        raise RuntimeError("secret material appeared outside the three approved private files")


def _assert_modes(*, plan_paths: set[Path], secret_paths: set[Path], config: Path) -> None:
    if any(stat.S_IMODE(path.stat().st_mode) != 0o400 for path in plan_paths):
        raise RuntimeError("one or more sealed plans has the wrong mode")
    if any(stat.S_IMODE(path.stat().st_mode) != 0o600 for path in secret_paths | {config}):
        raise RuntimeError("one or more private secret or config files has the wrong mode")
    receipts = set(next(iter(plan_paths)).parent.glob(".*.receipt.json"))
    if len(receipts) != 4 or any(stat.S_IMODE(path.stat().st_mode) != 0o400 for path in receipts):
        raise RuntimeError("identity setup receipts are missing or not sealed")


def _identity_counts(database: Path) -> dict[str, int]:
    tables = (
        "clients",
        "client_credentials",
        "devices",
        "device_enrollments",
        "source_accounts",
        "source_account_policies",
    )
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as connection:
        return {
            table: cast(int, connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        }


def _write_private_json(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private JSON write did not make progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    _chmod(path, 0o700)
    return path


def _chmod(path: Path, mode: int) -> None:
    path.chmod(mode)
    if stat.S_IMODE(path.stat().st_mode) != mode:
        raise RuntimeError("private path mode could not be established")


def _read_secret(path: Path) -> str:
    value = path.read_text(encoding="ascii")
    if not value.endswith("\n") or value.count("\n") != 1:
        raise RuntimeError("private secret file has an invalid envelope")
    return value[:-1]


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast(int, listener.getsockname()[1])


def _require_status(result: dict[str, Any], expected: str) -> None:
    if result.get("status") != expected:
        raise RuntimeError(f"expected status {expected!r}")


def _nested_string(result: dict[str, Any], parent: str, field: str) -> str:
    nested = result.get(parent)
    if not isinstance(nested, dict):
        raise RuntimeError(f"result field {parent!r} is not an object")
    return _string_field(cast(dict[str, Any], nested), field)


def _string_field(result: dict[str, Any], field: str) -> str:
    value = result.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"result field {field!r} is not a string")
    return value


def _sha256_field(result: dict[str, Any], field: str) -> str:
    value = _string_field(result, field)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError(f"result field {field!r} is not a lowercase SHA-256")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _cli_path() -> Path:
    configured = os.environ.get("CAM_CLI")
    candidate = Path(configured) if configured else None
    if candidate is None:
        found = shutil.which("cross-memory")
        candidate = Path(found) if found else None
    if candidate is None:
        raise RuntimeError("cross-memory executable is unavailable")
    resolved = candidate.expanduser().resolve()
    details = resolved.stat()
    if not stat.S_ISREG(details.st_mode) or not os.access(resolved, os.X_OK):
        raise RuntimeError("cross-memory executable is not a regular executable")
    return resolved


def _revision() -> str:
    configured = os.environ.get("CAM_BUILD_REVISION")
    if configured is not None:
        return _validated_revision(configured)
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("CAM_BUILD_REVISION is required outside a Git checkout")
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        capture_output=True,
        text=True,
    )
    if dirty.returncode != 0 or dirty.stdout:
        raise RuntimeError("agent-guided setup acceptance requires a clean tracked checkout")
    return _validated_revision(completed.stdout.strip())


def _validated_revision(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("build revision must be a lowercase 40-character Git SHA-1")
    return value


if __name__ == "__main__":
    main()
