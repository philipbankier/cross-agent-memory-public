from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cross_assistant_memory.collector import MAX_COLLECTOR_CONFIG_BYTES, load_collector_config
from cross_assistant_memory.human_gates import HumanGate, HumanGateKind, human_gates_as_dict
from cross_assistant_memory.safe_files import (
    open_regular_file_no_symlinks,
    publish_file_no_replace,
)

COLLECTOR_SERVICE_PLAN_FORMAT_VERSION = 3
COLLECTOR_SERVICE_SCHEDULE_SECONDS = 15 * 60
COLLECTOR_SERVICE_BASENAME = "cross-assistant-memory-collector"
LAUNCHD_LABEL = "cross-assistant-memory.collector"
SYSTEMD_SERVICE_NAME = f"{COLLECTOR_SERVICE_BASENAME}.service"
SYSTEMD_TIMER_NAME = f"{COLLECTOR_SERVICE_BASENAME}.timer"
MAX_SERVICE_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_MANAGER_PROBE_BYTES = 256 * 1024

CommandRunner = Callable[[tuple[str, ...]], None]


class CollectorServicePlatform(StrEnum):
    LAUNCHD = "launchd"
    SYSTEMD = "systemd"


@dataclass(frozen=True)
class CollectorServiceFile:
    path: Path
    content: bytes
    mode: int = 0o600
    mutable_after_create: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def manifest_entry(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "mode": f"{self.mode:04o}",
            "mutable_after_create": self.mutable_after_create,
        }


@dataclass(frozen=True)
class CollectorServicePlan:
    platform: CollectorServicePlatform
    user_home: Path
    config_path: Path
    config_sha256: str
    executable_path: Path
    executable_sha256: str
    files: tuple[CollectorServiceFile, ...]

    @property
    def target_state_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._target_surface())).hexdigest()

    @property
    def required_human_gates(self) -> tuple[HumanGate, ...]:
        return (
            HumanGate(
                kind=HumanGateKind.SERVICE_INSTALLATION,
                action="install_and_enable_recurring_collector_service",
                target=f"{self.platform.value}:{self.user_home}",
                target_state_sha256=self.target_state_sha256,
                impact="Creates user service files and enables a recurring collector job.",
                rollback="Disable the user service and remove only the files listed in this plan.",
            ),
        )

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self._digest_surface())).hexdigest()

    def _target_surface(self) -> dict[str, object]:
        return {
            "format_version": COLLECTOR_SERVICE_PLAN_FORMAT_VERSION,
            "platform": self.platform.value,
            "scope": "user",
            "schedule_seconds": COLLECTOR_SERVICE_SCHEDULE_SECONDS,
            "config_path": str(self.config_path),
            "config_sha256": self.config_sha256,
            "executable_path": str(self.executable_path),
            "executable_sha256": self.executable_sha256,
            "files": [item.manifest_entry() for item in self.files],
        }

    def _digest_surface(self) -> dict[str, object]:
        return {
            **self._target_surface(),
            "required_human_gates": human_gates_as_dict(self.required_human_gates),
        }

    def as_dict(self, *, status: str) -> dict[str, object]:
        return {
            "status": status,
            **self._digest_surface(),
            "plan_sha256": self.plan_sha256,
            "source_content_opened": False,
            "secrets_embedded": False,
            "execute_required": status == "planned",
        }


class CollectorServiceFileState(StrEnum):
    ABSENT = "absent"
    EXACT = "exact"
    MUTATED = "mutated"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class CollectorServiceManagerState:
    loaded: bool
    enabled: bool
    active: bool
    conflict: bool = False
    reload_required: bool = False

    def ready_for(self, platform: CollectorServicePlatform) -> bool:
        if self.conflict or self.reload_required or not self.loaded or not self.enabled:
            return False
        return platform is CollectorServicePlatform.LAUNCHD or self.active


ManagerStateProbe = Callable[[CollectorServicePlan, Path, int], CollectorServiceManagerState]


def plan_collector_service(
    platform: CollectorServicePlatform,
    config_path: Path,
    executable_path: Path,
    *,
    user_home: Path | None = None,
) -> CollectorServicePlan:
    normalized_home = _normalize_service_path(user_home or Path.home(), "user home")
    normalized_config = _normalize_service_path(config_path, "collector config")
    normalized_executable = _normalize_service_path(executable_path, "collector executable")

    config_sha256_before = _hash_regular_file(
        normalized_config,
        "collector config",
        max_bytes=MAX_COLLECTOR_CONFIG_BYTES,
    )
    load_collector_config(normalized_config)
    config_sha256_after = _hash_regular_file(
        normalized_config,
        "collector config",
        max_bytes=MAX_COLLECTOR_CONFIG_BYTES,
    )
    if config_sha256_before != config_sha256_after:
        raise RuntimeError("collector config changed while the service plan was built")

    executable_sha256 = _hash_executable(normalized_executable)
    arguments = (
        str(normalized_executable),
        "collector-sync",
        "--config",
        str(normalized_config),
        "--quiet",
    )
    files = (
        _launchd_service_file(normalized_home, arguments)
        if platform is CollectorServicePlatform.LAUNCHD
        else _systemd_service_files(normalized_home, arguments)
    )
    return CollectorServicePlan(
        platform=platform,
        user_home=normalized_home,
        config_path=normalized_config,
        config_sha256=config_sha256_after,
        executable_path=normalized_executable,
        executable_sha256=executable_sha256,
        files=files,
    )


def install_collector_service(
    platform: CollectorServicePlatform,
    config_path: Path,
    executable_path: Path,
    *,
    execute: bool,
    expected_plan_sha256: str | None,
) -> dict[str, object]:
    plan = plan_collector_service(platform, config_path, executable_path)
    if not execute:
        if expected_plan_sha256 is not None and not hmac.compare_digest(
            expected_plan_sha256, plan.plan_sha256
        ):
            raise ValueError("collector service plan SHA-256 does not match")
        return plan.as_dict(status="planned")
    if expected_plan_sha256 is None:
        raise ValueError("collector service installation requires --expected-plan-sha256")
    if not hmac.compare_digest(expected_plan_sha256, plan.plan_sha256):
        raise ValueError("collector service plan SHA-256 does not match")
    if os.geteuid() == 0:
        raise PermissionError("collector service installation must run as the target user")
    if platform is CollectorServicePlatform.LAUNCHD:
        if sys.platform != "darwin":
            raise RuntimeError("launchd collector installation requires macOS")
        manager = Path("/bin/launchctl")
    else:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("systemd collector installation requires Linux")
        systemctl = shutil.which("systemctl")
        if systemctl is None:
            raise RuntimeError("systemctl is unavailable")
        manager = Path(systemctl)
    status = _apply_collector_service_plan(
        plan,
        runner=_run_service_command,
        probe=_probe_manager_state,
        manager=manager,
        uid=os.getuid(),
    )
    return plan.as_dict(status=status)


def _launchd_service_file(
    user_home: Path,
    arguments: tuple[str, ...],
) -> tuple[CollectorServiceFile, CollectorServiceFile, CollectorServiceFile]:
    log_directory = user_home / "Library" / "Logs" / "cross-assistant-memory"
    target = user_home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    content = plistlib.dumps(
        {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": list(arguments),
            "RunAtLoad": True,
            "StartInterval": COLLECTOR_SERVICE_SCHEDULE_SECONDS,
            "ProcessType": "Background",
            "LowPriorityIO": True,
            "ThrottleInterval": 60,
            "Umask": 0o077,
            "StandardOutPath": str(log_directory / "collector.out.log"),
            "StandardErrorPath": str(log_directory / "collector.err.log"),
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    return (
        CollectorServiceFile(path=target, content=content),
        CollectorServiceFile(
            path=log_directory / "collector.out.log",
            content=b"",
            mutable_after_create=True,
        ),
        CollectorServiceFile(
            path=log_directory / "collector.err.log",
            content=b"",
            mutable_after_create=True,
        ),
    )


def _systemd_service_files(
    user_home: Path,
    arguments: tuple[str, ...],
) -> tuple[CollectorServiceFile, CollectorServiceFile]:
    unit_directory = user_home / ".config" / "systemd" / "user"
    exec_start = " ".join(_systemd_quote(argument) for argument in arguments)
    service = (
        "[Unit]\n"
        "Description=Cross-Agent Memory native collector\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={exec_start}\n"
        "UMask=0077\n"
        "Nice=10\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n"
    ).encode()
    timer = (
        "[Unit]\n"
        "Description=Run the Cross-Agent Memory native collector every 15 minutes\n"
        "\n"
        "[Timer]\n"
        "OnStartupSec=1min\n"
        "OnUnitActiveSec=15min\n"
        "AccuracySec=1min\n"
        "Persistent=false\n"
        f"Unit={SYSTEMD_SERVICE_NAME}\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    ).encode()
    return (
        CollectorServiceFile(path=unit_directory / SYSTEMD_SERVICE_NAME, content=service),
        CollectorServiceFile(path=unit_directory / SYSTEMD_TIMER_NAME, content=timer),
    )


def _apply_collector_service_plan(
    plan: CollectorServicePlan,
    *,
    runner: CommandRunner,
    probe: ManagerStateProbe,
    manager: Path,
    uid: int,
) -> str:
    with _exclusive_service_install(plan):
        _require_service_plan_inputs_unchanged(plan)
        for item in plan.files:
            if not item.path.is_relative_to(plan.user_home):
                raise ValueError("collector service target must stay within the target user home")
        home_descriptor = _open_directory_no_symlinks(plan.user_home, "target user home")
        try:
            _validate_private_service_directory(os.fstat(home_descriptor), "target user home")
        finally:
            os.close(home_descriptor)

        file_states = tuple(_inspect_service_file(item, plan.user_home) for item in plan.files)
        manager_state = probe(plan, manager, uid)
        _require_nonconflicting_service_state(plan, file_states, manager_state)
        if all(_service_file_state_is_accepted(state) for state in file_states) and (
            manager_state.ready_for(plan.platform)
        ):
            _require_service_plan_files_unchanged(plan)
            if not probe(plan, manager, uid).ready_for(plan.platform):
                raise RuntimeError("collector service manager changed during verification")
            return "already_installed"

        files_created = False
        for item, state in zip(plan.files, file_states, strict=True):
            if _service_file_state_is_accepted(state):
                continue
            try:
                _create_service_file(item, plan.user_home, plan.plan_sha256)
            except FileExistsError:
                state_after_race = _inspect_service_file(item, plan.user_home)
                if state_after_race is not CollectorServiceFileState.EXACT:
                    raise
            files_created = True
        final_file_states = tuple(
            _inspect_service_file(item, plan.user_home) for item in plan.files
        )
        if any(not _service_file_state_is_accepted(state) for state in final_file_states):
            raise RuntimeError("collector service files did not converge")

        manager_state = probe(plan, manager, uid)
        if manager_state.conflict:
            raise RuntimeError("collector service manager state conflicts with the plan")
        if plan.platform is CollectorServicePlatform.LAUNCHD:
            domain = f"gui/{uid}"
            service = f"{domain}/{LAUNCHD_LABEL}"
            if not manager_state.enabled:
                manager_state = _run_manager_step(
                    plan,
                    runner=runner,
                    probe=probe,
                    manager=manager,
                    uid=uid,
                    arguments=(str(manager), "enable", service),
                    satisfied=lambda state: state.enabled,
                )
            if not manager_state.loaded:
                manager_state = _run_manager_step(
                    plan,
                    runner=runner,
                    probe=probe,
                    manager=manager,
                    uid=uid,
                    arguments=(str(manager), "bootstrap", domain, str(plan.files[0].path)),
                    satisfied=lambda state: state.loaded,
                )
        else:
            if files_created or not manager_state.loaded or manager_state.reload_required:
                manager_state = _run_manager_step(
                    plan,
                    runner=runner,
                    probe=probe,
                    manager=manager,
                    uid=uid,
                    arguments=(str(manager), "--user", "daemon-reload"),
                    satisfied=lambda state: state.loaded and not state.reload_required,
                )
            if not manager_state.enabled:
                manager_state = _run_manager_step(
                    plan,
                    runner=runner,
                    probe=probe,
                    manager=manager,
                    uid=uid,
                    arguments=(str(manager), "--user", "enable", SYSTEMD_TIMER_NAME),
                    satisfied=lambda state: state.enabled,
                )
            if not manager_state.active:
                manager_state = _run_manager_step(
                    plan,
                    runner=runner,
                    probe=probe,
                    manager=manager,
                    uid=uid,
                    arguments=(str(manager), "--user", "start", SYSTEMD_TIMER_NAME),
                    satisfied=lambda state: state.active,
                )
        manager_state = probe(plan, manager, uid)
        if not manager_state.ready_for(plan.platform):
            raise RuntimeError("collector service manager did not converge")
        _require_service_plan_files_unchanged(plan)
        return "installed"


def _run_manager_step(
    plan: CollectorServicePlan,
    *,
    runner: CommandRunner,
    probe: ManagerStateProbe,
    manager: Path,
    uid: int,
    arguments: tuple[str, ...],
    satisfied: Callable[[CollectorServiceManagerState], bool],
) -> CollectorServiceManagerState:
    _require_service_plan_files_unchanged(plan)
    command_error: Exception | None = None
    try:
        runner(arguments)
    except Exception as error:
        command_error = error
    state = probe(plan, manager, uid)
    if state.conflict or not satisfied(state):
        if command_error is not None:
            raise command_error
        raise RuntimeError("collector service manager command did not reach its required state")
    return state


def _require_nonconflicting_service_state(
    plan: CollectorServicePlan,
    file_states: tuple[CollectorServiceFileState, ...],
    manager_state: CollectorServiceManagerState,
) -> None:
    if any(state is CollectorServiceFileState.CONFLICT for state in file_states):
        raise FileExistsError("collector service file conflicts with the approved plan")
    if manager_state.conflict:
        raise RuntimeError("collector service manager state conflicts with the approved plan")
    definition_files_exact = all(
        state is CollectorServiceFileState.EXACT
        for item, state in zip(plan.files, file_states, strict=True)
        if not item.mutable_after_create
    )
    if not definition_files_exact and any(
        state is CollectorServiceFileState.MUTATED for state in file_states
    ):
        raise FileExistsError("collector service mutable file has no exact service definition")
    manager_precedes_files = manager_state.loaded or (
        plan.platform is CollectorServicePlatform.SYSTEMD and manager_state.enabled
    )
    if manager_precedes_files and not definition_files_exact:
        raise RuntimeError("collector service manager state cannot precede exact service files")


def _service_file_state_is_accepted(state: CollectorServiceFileState) -> bool:
    return state in {CollectorServiceFileState.EXACT, CollectorServiceFileState.MUTATED}


def _require_service_plan_files_unchanged(plan: CollectorServicePlan) -> None:
    _require_service_plan_inputs_unchanged(plan)
    states = tuple(_inspect_service_file(item, plan.user_home) for item in plan.files)
    if any(not _service_file_state_is_accepted(state) for state in states):
        raise RuntimeError("collector service plan files changed before manager activation")


def _require_service_plan_inputs_unchanged(plan: CollectorServicePlan) -> None:
    config_sha256 = _hash_regular_file(
        plan.config_path,
        "collector config",
        max_bytes=MAX_COLLECTOR_CONFIG_BYTES,
    )
    executable_sha256 = _hash_executable(plan.executable_path)
    if not hmac.compare_digest(config_sha256, plan.config_sha256) or not hmac.compare_digest(
        executable_sha256,
        plan.executable_sha256,
    ):
        raise RuntimeError("collector service plan inputs changed before manager activation")


def _probe_manager_state(
    plan: CollectorServicePlan,
    manager: Path,
    uid: int,
) -> CollectorServiceManagerState:
    if plan.platform is CollectorServicePlatform.LAUNCHD:
        return _probe_launchd_state(plan, manager, uid)
    return _probe_systemd_state(plan, manager)


@contextmanager
def _exclusive_service_install(plan: CollectorServicePlan) -> Generator[None]:
    parent_descriptor = _open_directory_no_symlinks(plan.user_home, "target user home")
    descriptor: int | None = None
    locked = False
    created = False
    lock_name = f".{COLLECTOR_SERVICE_BASENAME}.install.lock"
    open_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        _validate_private_service_directory(os.fstat(parent_descriptor), "target user home")
        try:
            descriptor = os.open(
                lock_name,
                open_flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(lock_name, open_flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or (not created and stat.S_IMODE(metadata.st_mode) != 0o600)
        ):
            raise RuntimeError("collector service installation lock is unsafe")
        if created:
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        if created:
            os.fsync(parent_descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        path_metadata = os.stat(lock_name, dir_fd=parent_descriptor, follow_symlinks=False)
        locked_metadata = os.fstat(descriptor)
        if (
            path_metadata.st_dev != locked_metadata.st_dev
            or path_metadata.st_ino != locked_metadata.st_ino
            or locked_metadata.st_nlink != 1
        ):
            raise RuntimeError("collector service installation lock changed during acquisition")
        yield
    finally:
        if locked and descriptor is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _inspect_service_file(
    item: CollectorServiceFile,
    user_home: Path,
) -> CollectorServiceFileState:
    relative = item.path.relative_to(user_home)
    try:
        parent_descriptor = _open_or_create_descendant_directory(
            user_home,
            relative.parts[:-1],
            create=False,
        )
    except FileNotFoundError:
        return CollectorServiceFileState.ABSENT
    descriptor: int | None = None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(relative.name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return CollectorServiceFileState.ABSENT
        except OSError:
            return CollectorServiceFileState.CONFLICT
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != item.mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            return CollectorServiceFileState.CONFLICT
        if metadata.st_size != len(item.content):
            return (
                CollectorServiceFileState.MUTATED
                if item.mutable_after_create
                else CollectorServiceFileState.CONFLICT
            )
        payload = bytearray()
        while len(payload) <= len(item.content):
            chunk = os.read(descriptor, len(item.content) + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        if bytes(payload) != item.content:
            return (
                CollectorServiceFileState.MUTATED
                if item.mutable_after_create
                else CollectorServiceFileState.CONFLICT
            )
        return CollectorServiceFileState.EXACT
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _probe_launchd_state(
    plan: CollectorServicePlan,
    manager: Path,
    uid: int,
) -> CollectorServiceManagerState:
    domain = f"gui/{uid}"
    result = _run_probe_command((str(manager), "print", f"{domain}/{LAUNCHD_LABEL}"))
    conflict = False
    if result.returncode == 0:
        output = _decode_manager_probe(result.stdout, "launchd service")
        loaded = True
        conflict = not _launchd_definition_matches(plan, output)
    elif result.returncode == 113:
        loaded = False
    else:
        raise RuntimeError("launchd collector service identity probe failed")

    disabled_result = _run_probe_command((str(manager), "print-disabled", domain))
    if disabled_result.returncode != 0:
        raise RuntimeError("launchd collector disabled-state probe failed")
    disabled_output = _decode_manager_probe(disabled_result.stdout, "launchd disabled state")
    expression = re.compile(rf'"{re.escape(LAUNCHD_LABEL)}"\s*=>\s*(enabled|disabled|true|false)')
    values = [
        match.group(1)
        for line in disabled_output.splitlines()
        if (match := expression.fullmatch(line.strip())) is not None
    ]
    if len(values) > 1:
        raise RuntimeError("launchd collector disabled-state probe was invalid")
    enabled = not values or values[0] in {"enabled", "false"}
    return CollectorServiceManagerState(
        loaded=loaded,
        enabled=enabled,
        active=loaded,
        conflict=conflict,
    )


def _launchd_definition_matches(plan: CollectorServicePlan, output: str) -> bool:
    definition = plistlib.loads(plan.files[0].content)
    expected_arguments = tuple(str(value) for value in definition["ProgramArguments"])
    properties = set(_launchd_scalar(output, "properties").split(" | "))
    return (
        _launchd_scalar(output, "path") == str(plan.files[0].path)
        and _launchd_scalar(output, "program") == expected_arguments[0]
        and _launchd_arguments(output) == expected_arguments
        and _launchd_scalar(output, "stdout path") == str(definition["StandardOutPath"])
        and _launchd_scalar(output, "stderr path") == str(definition["StandardErrorPath"])
        and _launchd_scalar(output, "run interval") == f"{definition['StartInterval']} seconds"
        and _launchd_scalar(output, "minimum runtime") == str(definition["ThrottleInterval"])
        and _launchd_scalar(output, "spawn type").startswith(str(definition["ProcessType"]).lower())
        and {"runatload", "low priority i/o"}.issubset(properties)
    )


def _launchd_scalar(output: str, key: str) -> str:
    prefix = f"{key} = "
    values = [
        line.strip().removeprefix(prefix)
        for line in output.splitlines()
        if line.strip().startswith(prefix)
    ]
    if len(values) != 1:
        raise RuntimeError("launchd collector service probe was invalid")
    return values[0]


def _launchd_arguments(output: str) -> tuple[str, ...]:
    lines = output.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == "arguments = {"]
    if len(starts) != 1:
        raise RuntimeError("launchd collector service probe was invalid")
    arguments: list[str] = []
    for line in lines[starts[0] + 1 :]:
        value = line.strip()
        if value == "}":
            return tuple(arguments)
        if not value or "{" in value:
            raise RuntimeError("launchd collector service probe was invalid")
        arguments.append(value)
    raise RuntimeError("launchd collector service probe was invalid")


def _probe_systemd_state(
    plan: CollectorServicePlan,
    manager: Path,
) -> CollectorServiceManagerState:
    service = _systemd_unit_properties(manager, SYSTEMD_SERVICE_NAME)
    timer = _systemd_unit_properties(manager, SYSTEMD_TIMER_NAME)
    expected_paths = (str(plan.files[0].path), str(plan.files[1].path))
    properties = (service, timer)
    conflict = False
    loaded_units: list[bool] = []
    reload_required: list[bool] = []
    for unit, expected_path in zip(properties, expected_paths, strict=True):
        load_state = unit["LoadState"]
        fragment_path = unit["FragmentPath"]
        need_daemon_reload = unit["NeedDaemonReload"]
        if load_state not in {"loaded", "not-found"}:
            conflict = True
        loaded = load_state == "loaded"
        if loaded and fragment_path != expected_path:
            conflict = True
        if not loaded and fragment_path:
            conflict = True
        if unit["UnitFileState"] in {"masked", "masked-runtime"}:
            conflict = True
        if need_daemon_reload not in {"yes", "no"} or unit["DropInPaths"]:
            conflict = True
        loaded_units.append(loaded)
        reload_required.append(need_daemon_reload == "yes")
    return CollectorServiceManagerState(
        loaded=all(loaded_units),
        enabled=timer["UnitFileState"] == "enabled",
        active=timer["ActiveState"] == "active",
        conflict=conflict,
        reload_required=any(reload_required),
    )


def _systemd_unit_properties(manager: Path, unit: str) -> dict[str, str]:
    expected = {
        "LoadState",
        "UnitFileState",
        "ActiveState",
        "FragmentPath",
        "NeedDaemonReload",
        "DropInPaths",
    }
    result = _run_probe_command(
        (
            str(manager),
            "--user",
            "show",
            unit,
            "--property=LoadState",
            "--property=UnitFileState",
            "--property=ActiveState",
            "--property=FragmentPath",
            "--property=NeedDaemonReload",
            "--property=DropInPaths",
            "--no-pager",
        )
    )
    if result.returncode != 0:
        raise RuntimeError("systemd collector service state probe failed")
    output = _decode_manager_probe(result.stdout, "systemd service state")
    properties: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator != "=" or key not in expected or key in properties:
            raise RuntimeError("systemd collector service state probe was invalid")
        properties[key] = value
    if set(properties) != expected:
        raise RuntimeError("systemd collector service state probe was invalid")
    return properties


def _decode_manager_probe(payload: bytes, label: str) -> str:
    if len(payload) > MAX_MANAGER_PROBE_BYTES:
        raise RuntimeError(f"{label} exceeded its size limit")
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} was invalid") from error
    if any(_is_control(character) and character not in "\n\r\t" for character in value):
        raise RuntimeError(f"{label} was invalid")
    return value


def _create_service_file(
    item: CollectorServiceFile,
    user_home: Path,
    plan_sha256: str,
) -> None:
    relative = item.path.relative_to(user_home)
    parent_descriptor = _open_or_create_descendant_directory(
        user_home,
        relative.parts[:-1],
    )
    temporary_prefix = f".{relative.name}.cross-memory-{plan_sha256}.tmp-"
    temporary_name = f"{temporary_prefix}{secrets.token_hex(16)}"
    temporary_path = item.path.with_name(temporary_name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    created = False
    try:
        _discard_service_temps(
            parent_descriptor,
            temporary_prefix,
            required_mode=item.mode,
        )
        descriptor = os.open(temporary_name, flags, item.mode, dir_fd=parent_descriptor)
        created = True
        try:
            os.fchmod(descriptor, item.mode)
            view = memoryview(item.content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("collector service file write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
        publish_file_no_replace(
            temporary_path,
            item.path,
            required_mode=item.mode,
            label="collector service file",
        )
    except Exception:
        if created:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def _discard_service_temps(
    parent_descriptor: int,
    prefix: str,
    *,
    required_mode: int,
) -> None:
    removed = False
    for name in os.listdir(parent_descriptor):
        if not name.startswith(prefix):
            continue
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != required_mode
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("collector service temporary file is unsafe")
        os.unlink(name, dir_fd=parent_descriptor)
        removed = True
    if removed:
        os.fsync(parent_descriptor)


def _open_or_create_descendant_directory(
    user_home: Path,
    components: tuple[str, ...],
    *,
    create: bool = True,
) -> int:
    descriptor = _open_directory_no_symlinks(user_home, "target user home")
    try:
        _validate_private_service_directory(os.fstat(descriptor), "target user home")
        for component in components:
            try:
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise ValueError(f"collector service directory is unsafe: {component}") from error
            try:
                _validate_private_service_directory(
                    os.fstat(next_descriptor),
                    f"collector service directory {component}",
                )
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_directory_no_symlinks(path: Path, label: str) -> int:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    descriptor = os.open(path.anchor, _directory_open_flags())
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError(f"{label} must be a directory without symlink components") from error


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _validate_private_service_directory(metadata: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError(f"{label} must be a private directory owned by the current user")


def _run_service_command(arguments: tuple[str, ...]) -> None:
    try:
        subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("collector service manager command failed") from error


def _run_probe_command(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError("collector service manager probe failed") from error


def _hash_executable(path: Path) -> str:
    descriptor, _normalized = open_regular_file_no_symlinks(path, "collector executable")
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > MAX_SERVICE_EXECUTABLE_BYTES:
            raise ValueError("collector executable exceeds its size limit")
        if not _mode_is_executable_by_current_user(metadata):
            raise ValueError("collector executable is not executable")
        if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError("collector executable must not use set-user-ID or set-group-ID")
        _validate_service_input_owner(metadata, "collector executable")
        return _hash_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _hash_regular_file(path: Path, label: str, *, max_bytes: int) -> str:
    descriptor, _normalized = open_regular_file_no_symlinks(path, label)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds its size limit")
        _validate_service_input_owner(metadata, label)
        return _hash_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _normalize_service_path(path: Path, label: str) -> Path:
    normalized = Path(os.path.abspath(path.expanduser()))
    value = str(normalized)
    if not normalized.is_absolute() or any(_is_control(character) for character in value):
        raise ValueError(f"{label} must be an absolute path without control characters")
    return normalized


def _systemd_quote(value: str) -> str:
    if any(_is_control(character) for character in value):
        raise ValueError("systemd argument contains a control character")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{escaped}"'


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _validate_service_input_owner(metadata: os.stat_result, label: str) -> None:
    if metadata.st_uid not in {0, os.getuid()} or metadata.st_mode & 0o022:
        raise ValueError(
            f"{label} must be owned by the current user or root and not broadly writable"
        )


def _mode_is_executable_by_current_user(metadata: os.stat_result) -> bool:
    if metadata.st_uid == os.geteuid():
        return bool(metadata.st_mode & stat.S_IXUSR)
    groups = {os.getegid(), *os.getgroups()}
    if metadata.st_gid in groups:
        return bool(metadata.st_mode & stat.S_IXGRP)
    return bool(metadata.st_mode & stat.S_IXOTH)


def _is_control(character: str) -> bool:
    return ord(character) < 32 or ord(character) == 127
