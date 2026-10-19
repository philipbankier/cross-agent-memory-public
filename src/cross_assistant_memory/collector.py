from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from cross_assistant_memory.models import CollectorProvenance, ParseResult, SourceSystem
from cross_assistant_memory.parsers.claude_code import PARSER_NAME as CLAUDE_PARSER_NAME
from cross_assistant_memory.parsers.claude_code import PARSER_VERSION as CLAUDE_PARSER_VERSION
from cross_assistant_memory.parsers.codex import LEGACY_PARSER_NAME, LEGACY_PARSER_VERSION
from cross_assistant_memory.parsers.codex import PARSER_NAME as CODEX_PARSER_NAME
from cross_assistant_memory.parsers.codex import PARSER_VERSION as CODEX_PARSER_VERSION
from cross_assistant_memory.parsers.grok_build import PARSER_NAME as GROK_PARSER_NAME
from cross_assistant_memory.parsers.grok_build import PARSER_VERSION as GROK_PARSER_VERSION

COLLECTOR_SOURCE_CONFIG_FORMAT_VERSION = 1
COLLECTOR_CONFIG_FORMAT_VERSION = 2
COLLECTOR_ADAPTER_NAME = "cross-memory-native-collector"
COLLECTOR_ADAPTER_VERSION = "0.1.0"
MAX_COLLECTOR_CONFIG_BYTES = 256 * 1024
MAX_CONFIG_VALUE_BYTES = 1024
MAX_NATIVE_SOURCE_OPT_INS = 64
MAX_EXCLUDED_NATIVE_FILES = 256
MIN_QUEUE_BYTES = 1024 * 1024
MAX_QUEUE_BYTES = 1024 * 1024 * 1024
MIN_QUEUE_AGE_SECONDS = 60 * 60
MAX_QUEUE_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_HTTP_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class NativeAdapter:
    source_system: SourceSystem
    source_client: str
    root_relative_to_home: Path
    version_binary: str
    capture_capability: str
    parser_name: str
    parser_version: str
    required_filename: str | None = None


NATIVE_ADAPTERS = {
    SourceSystem.CODEX: NativeAdapter(
        source_system=SourceSystem.CODEX,
        source_client="codex",
        root_relative_to_home=Path(".codex/sessions"),
        version_binary="codex",
        capture_capability="native-jsonl-history",
        parser_name=CODEX_PARSER_NAME,
        parser_version=CODEX_PARSER_VERSION,
    ),
    SourceSystem.CLAUDE_CODE: NativeAdapter(
        source_system=SourceSystem.CLAUDE_CODE,
        source_client="claude-code",
        root_relative_to_home=Path(".claude/projects"),
        version_binary="claude",
        capture_capability="native-jsonl-history",
        parser_name=CLAUDE_PARSER_NAME,
        parser_version=CLAUDE_PARSER_VERSION,
    ),
    SourceSystem.GROK_BUILD: NativeAdapter(
        source_system=SourceSystem.GROK_BUILD,
        source_client="grok-build",
        root_relative_to_home=Path(".grok/sessions"),
        version_binary="grok",
        capture_capability="native-jsonl-history",
        parser_name=GROK_PARSER_NAME,
        parser_version=GROK_PARSER_VERSION,
        required_filename="updates.jsonl",
    ),
}


@dataclass(frozen=True)
class SourcePreview:
    source_system: SourceSystem
    source_client: str
    root: Path
    capture_capability: str
    client_version: str | None
    candidate_files: int
    state: str

    def as_dict(self) -> dict[str, object]:
        return {
            "source_system": self.source_system.value,
            "source_client": self.source_client,
            "root": str(self.root),
            "capture_capability": self.capture_capability,
            "client_version": self.client_version,
            "candidate_files": self.candidate_files,
            "state": self.state,
        }


@dataclass(frozen=True)
class InitialSourceCursor:
    next_record_ordinal: int
    next_byte_offset: int
    prefix_digest: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 0 < value <= 2**63 - 1
            for value in (self.next_record_ordinal, self.next_byte_offset)
        ):
            raise ValueError("initial source cursor requires positive signed 64-bit integers")
        if self.next_record_ordinal > self.next_byte_offset:
            raise ValueError("initial source cursor ordinal exceeds its byte offset")
        if (
            type(self.prefix_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.prefix_digest) is None
            or self.prefix_digest == hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError("initial source cursor requires a nonempty prefix SHA-256 digest")


@dataclass(frozen=True)
class NativeSourceSelection:
    path: Path
    cursor: InitialSourceCursor


@dataclass(frozen=True)
class NativeSourceOptIn:
    source_system: SourceSystem
    source_account_id: str
    root: Path
    source_client_version: str
    excluded_files: tuple[Path, ...] = ()
    initial_selections: tuple[NativeSourceSelection, ...] = ()

    def initial_cursor_for(self, path: Path) -> InitialSourceCursor | None:
        return next(
            (selection.cursor for selection in self.initial_selections if selection.path == path),
            None,
        )

    @property
    def adapter(self) -> NativeAdapter:
        return NATIVE_ADAPTERS[self.source_system]

    def provenance(self, parsed: ParseResult) -> CollectorProvenance:
        if parsed.source_system is not self.source_system:
            raise ValueError("parsed source does not match the configured source system")
        adapter = self.adapter
        if (parsed.parser_name, parsed.parser_version) != (
            adapter.parser_name,
            adapter.parser_version,
        ) and not (
            self.source_system is SourceSystem.CODEX
            and (parsed.parser_name, parsed.parser_version)
            == (LEGACY_PARSER_NAME, LEGACY_PARSER_VERSION)
        ):
            raise ValueError("parsed source does not match the configured native adapter")
        if not parsed.schema_fingerprint:
            raise ValueError("parsed native source is missing its schema fingerprint")
        return CollectorProvenance(
            source_client=adapter.source_client,
            source_client_version=self.source_client_version,
            capture_capability=adapter.capture_capability,
            adapter_name=COLLECTOR_ADAPTER_NAME,
            adapter_version=COLLECTOR_ADAPTER_VERSION,
            schema_fingerprint=parsed.schema_fingerprint,
        )


@dataclass(frozen=True)
class CollectorNodeConfig:
    upload_url: str
    credential_file: Path
    timeout_seconds: int


@dataclass(frozen=True)
class CollectorQueueConfig:
    root: Path
    key_file: Path
    max_bytes: int
    max_age_seconds: int


@dataclass(frozen=True)
class CollectorConfig:
    node: CollectorNodeConfig
    queue: CollectorQueueConfig
    sources: tuple[NativeSourceOptIn, ...]


def discover_native_sources(
    user_home: Path,
    *,
    version_resolver: Callable[[str], str | None] | None = None,
) -> tuple[SourcePreview, ...]:
    home = user_home.expanduser().resolve()
    resolve_version = version_resolver or detect_client_version
    previews: list[SourcePreview] = []
    for source_system in (
        SourceSystem.CODEX,
        SourceSystem.CLAUDE_CODE,
        SourceSystem.GROK_BUILD,
    ):
        adapter = NATIVE_ADAPTERS[source_system]
        root = home / adapter.root_relative_to_home
        if root.is_symlink():
            state = "unsafe_symlink"
            candidate_files = 0
        elif root.is_dir():
            state = "available"
            candidate_files = len(iter_native_source_files(root, adapter))
        else:
            state = "missing"
            candidate_files = 0
        previews.append(
            SourcePreview(
                source_system=source_system,
                source_client=adapter.source_client,
                root=root,
                capture_capability=adapter.capture_capability,
                client_version=resolve_version(adapter.version_binary),
                candidate_files=candidate_files,
                state=state,
            )
        )
    return tuple(previews)


def detect_client_version(binary: str) -> str | None:
    executable = shutil.which(binary)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    first_line = result.stdout.splitlines()[0].strip() if result.stdout.splitlines() else ""
    if (
        not first_line
        or len(first_line.encode()) > 256
        or any(ord(char) < 32 for char in first_line)
    ):
        return None
    return first_line


def load_collector_config(path: Path) -> CollectorConfig:
    root = _load_collector_config_object(path)
    return _collector_config_from_object(root)


def load_native_source_opt_ins(path: Path) -> tuple[NativeSourceOptIn, ...]:
    root = _load_collector_config_object(path)
    version = root.get("format_version")
    if version == COLLECTOR_SOURCE_CONFIG_FORMAT_VERSION:
        source_config = _exact_object(
            root,
            {"format_version", "sources"},
            "collector config",
        )
        return _parse_native_source_opt_ins(source_config["sources"])
    if version == COLLECTOR_CONFIG_FORMAT_VERSION:
        return _collector_config_from_object(root).sources
    raise ValueError("collector config format version is unsupported")


def _load_collector_config_object(path: Path) -> dict[str, object]:
    expanded = Path(os.path.abspath(path.expanduser()))
    _reject_symlink_components(expanded, "collector config")
    descriptor = os.open(expanded, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_COLLECTOR_CONFIG_BYTES:
            raise ValueError("collector config must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_COLLECTOR_CONFIG_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_COLLECTOR_CONFIG_BYTES:
        raise ValueError("collector config exceeds its size limit")
    try:
        loaded: object = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("collector config must be valid JSON") from error
    if not isinstance(loaded, dict):
        raise ValueError("collector config must be an object")
    return cast(dict[str, object], loaded)


def _collector_config_from_object(loaded: dict[str, object]) -> CollectorConfig:
    root = _exact_object(
        loaded,
        {"format_version", "node", "queue", "sources"},
        "collector config",
    )
    if root["format_version"] != COLLECTOR_CONFIG_FORMAT_VERSION:
        raise ValueError("collector config format version is unsupported")
    node_value = _exact_object(
        root["node"],
        {"upload_url", "credential_file", "timeout_seconds"},
        "collector node config",
    )
    upload_url = _validate_upload_url(_required_string(node_value, "upload_url"))
    credential_file = _absolute_path(node_value, "credential_file")
    timeout_seconds = _required_int(node_value, "timeout_seconds")
    if timeout_seconds <= 0 or timeout_seconds > MAX_HTTP_TIMEOUT_SECONDS:
        raise ValueError("collector HTTP timeout is invalid")
    queue_value = _exact_object(
        root["queue"],
        {"root", "key_file", "max_bytes", "max_age_seconds"},
        "collector queue config",
    )
    queue_root = _absolute_path(queue_value, "root")
    queue_key_file = _absolute_path(queue_value, "key_file")
    if queue_key_file == queue_root or queue_key_file.is_relative_to(queue_root):
        raise ValueError("collector queue key must be outside the queue root")
    if queue_key_file == credential_file:
        raise ValueError("collector queue key and transport credential must be separate files")
    max_bytes = _required_int(queue_value, "max_bytes")
    if max_bytes < MIN_QUEUE_BYTES or max_bytes > MAX_QUEUE_BYTES:
        raise ValueError("collector queue byte limit is invalid")
    max_age_seconds = _required_int(queue_value, "max_age_seconds")
    if max_age_seconds < MIN_QUEUE_AGE_SECONDS or max_age_seconds > MAX_QUEUE_AGE_SECONDS:
        raise ValueError("collector queue age limit is invalid")
    sources = _parse_native_source_opt_ins(root["sources"])
    return CollectorConfig(
        node=CollectorNodeConfig(
            upload_url=upload_url,
            credential_file=credential_file,
            timeout_seconds=timeout_seconds,
        ),
        queue=CollectorQueueConfig(
            root=queue_root,
            key_file=queue_key_file,
            max_bytes=max_bytes,
            max_age_seconds=max_age_seconds,
        ),
        sources=sources,
    )


def _parse_native_source_opt_ins(source_values: object) -> tuple[NativeSourceOptIn, ...]:
    if not isinstance(source_values, list):
        raise ValueError("collector config sources must be a list")
    typed_source_values = cast(list[object], source_values)
    if len(typed_source_values) > MAX_NATIVE_SOURCE_OPT_INS:
        raise ValueError("collector config has too many source opt-ins")
    sources: list[NativeSourceOptIn] = []
    root_identities: set[tuple[SourceSystem, Path]] = set()
    for value in typed_source_values:
        fields = {"source_system", "source_account_id", "root", "source_client_version"}
        if isinstance(value, dict) and "excluded_files" in value:
            fields.add("excluded_files")
        if isinstance(value, dict) and "initial_selections" in value:
            fields.add("initial_selections")
        item = _exact_object(
            cast(object, value),
            fields,
            "collector source opt-in",
        )
        try:
            source_system = SourceSystem(_required_string(item, "source_system"))
        except ValueError as error:
            raise ValueError("collector source system is unsupported") from error
        if source_system not in NATIVE_ADAPTERS:
            raise ValueError("collector source system is not a native source")
        if "initial_selections" in item and source_system is not SourceSystem.CODEX:
            raise ValueError("collector initial selections are only supported for Codex")
        source_root = _absolute_path(item, "root")
        excluded_values = item.get("excluded_files", [])
        if not isinstance(excluded_values, list):
            raise ValueError("collector excluded files must be a bounded list")
        typed_excluded_values = cast(list[object], excluded_values)
        if len(typed_excluded_values) > MAX_EXCLUDED_NATIVE_FILES:
            raise ValueError("collector excluded files must be a bounded list")
        excluded_files: list[Path] = []
        for excluded_value in typed_excluded_values:
            excluded = _absolute_path({"path": excluded_value}, "path")
            if (
                excluded == source_root
                or not excluded.is_relative_to(source_root)
                or excluded in excluded_files
                or excluded.is_dir()
            ):
                raise ValueError(
                    "collector excluded files must be unique files under the source root"
                )
            excluded_files.append(excluded)
        selection_values = item.get("initial_selections", [])
        if not isinstance(selection_values, list):
            raise ValueError("collector initial selections must be a bounded list")
        typed_selection_values = cast(list[object], selection_values)
        if len(typed_selection_values) > MAX_EXCLUDED_NATIVE_FILES:
            raise ValueError("collector initial selections must be a bounded list")
        initial_selections: list[NativeSourceSelection] = []
        selected_paths: set[Path] = set()
        for selection_value in typed_selection_values:
            selection = _exact_object(
                selection_value,
                {"path", "start_record_ordinal", "start_byte_offset", "start_prefix_sha256"},
                "collector initial selection",
            )
            selected_path = _absolute_path(selection, "path")
            if (
                selected_path == source_root
                or not selected_path.is_relative_to(source_root)
                or selected_path.suffix != ".jsonl"
                or selected_path.is_dir()
                or selected_path in selected_paths
            ):
                raise ValueError(
                    "collector initial selections must be unique JSONL files under the source root"
                )
            if selected_path in excluded_files:
                raise ValueError("collector initial selections conflict with excluded files")
            initial_selections.append(
                NativeSourceSelection(
                    path=selected_path,
                    cursor=InitialSourceCursor(
                        next_record_ordinal=_required_int(selection, "start_record_ordinal"),
                        next_byte_offset=_required_int(selection, "start_byte_offset"),
                        prefix_digest=_required_string(selection, "start_prefix_sha256"),
                    ),
                )
            )
            selected_paths.add(selected_path)
        source = NativeSourceOptIn(
            source_system=source_system,
            source_account_id=_required_string(item, "source_account_id"),
            root=source_root,
            source_client_version=_required_string(item, "source_client_version"),
            excluded_files=tuple(excluded_files),
            initial_selections=tuple(initial_selections),
        )
        root_identity = (source.source_system, source.root)
        if root_identity in root_identities:
            raise ValueError("collector source root is duplicated")
        root_identities.add(root_identity)
        sources.append(source)
    for source in sources:
        for selection in source.initial_selections:
            for other in sources:
                if (
                    other.source_system is source.source_system
                    and other.source_account_id == source.source_account_id
                    and selection.path.is_relative_to(other.root)
                    and (
                        selection.path in other.excluded_files
                        or other.initial_cursor_for(selection.path) != selection.cursor
                    )
                ):
                    raise ValueError("overlapping collector roots disagree on an initial selection")
    return tuple(sources)


def iter_native_source_files(
    root: Path, adapter: NativeAdapter, *, excluded_files: tuple[Path, ...] = ()
) -> tuple[Path, ...]:
    expanded = root.expanduser()
    if expanded.is_symlink() or not expanded.is_dir():
        return ()
    files: list[Path] = []
    for current, directory_names, file_names in os.walk(expanded, followlinks=False):
        current_path = Path(current)
        directory_names[:] = [
            name for name in directory_names if not (current_path / name).is_symlink()
        ]
        for name in file_names:
            if not name.endswith(".jsonl"):
                continue
            if adapter.required_filename is not None and name != adapter.required_filename:
                continue
            if (
                adapter.source_system is SourceSystem.CLAUDE_CODE
                and name == "journal.jsonl"
                and current_path.parent.name == "workflows"
                and current_path.parent.parent.name == "subagents"
                and current_path.name.startswith("wf_")
            ):
                continue
            candidate = current_path / name
            if candidate in excluded_files:
                continue
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode):
                files.append(candidate)
    return tuple(sorted(files))


def _exact_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw) or set(raw) != fields:
        raise ValueError(f"{label} fields are invalid")
    return cast(dict[str, object], raw)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object field")
        value[key] = item
    return value


def _required_string(value: dict[str, object], field: str) -> str:
    item = value[field]
    if (
        not isinstance(item, str)
        or not item
        or item.strip() != item
        or len(item.encode()) > MAX_CONFIG_VALUE_BYTES
    ):
        raise ValueError(f"{field} is invalid")
    return item


def _required_int(value: dict[str, object], field: str) -> int:
    item = value[field]
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{field} is invalid")
    return item


def _absolute_path(value: dict[str, object], field: str) -> Path:
    path = Path(_required_string(value, field)).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{field} must be absolute")
    normalized = Path(os.path.abspath(path))
    _reject_symlink_components(normalized, field)
    return normalized


def _reject_symlink_components(path: Path, field: str) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError(f"{field} must not contain symlinks")


def _validate_upload_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("collector upload URL is invalid") from error
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/upload/batches"
        or parsed.hostname is None
        or port is None
    ):
        raise ValueError("collector upload URL is invalid")
    if parsed.scheme == "https":
        return value
    if parsed.scheme != "http":
        raise ValueError("collector upload URL must use HTTPS or loopback HTTP")
    if parsed.hostname == "localhost":
        return value
    try:
        address = ip_address(parsed.hostname)
    except ValueError as error:
        raise ValueError("collector HTTP upload URL must be loopback") from error
    if not address.is_loopback:
        raise ValueError("collector HTTP upload URL must be loopback")
    return value
