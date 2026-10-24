from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import BinaryIO, cast

from cross_assistant_memory.browser_observation import (
    MAX_ENVELOPE_BYTES,
    parse_browser_observation,
)
from cross_assistant_memory.safe_files import open_regular_file_no_symlinks

MAX_CONFIG_BYTES = 32 * 1024
_PROVIDERS = frozenset({"chatgpt_web", "claude_web", "grok_web"})
_BINDING = re.compile(r"source_account:[0-9a-f]{64}")
_EXTENSION_ORIGIN = re.compile(r"chrome-extension://[a-p]{32}/")


@dataclass(frozen=True)
class CaptureHostConfig:
    extension_origin: str
    spool_root: Path
    key_file: Path
    bindings: dict[tuple[str, str], str]
    upload_endpoint: str | None = None
    credential_file: Path | None = None


def load_capture_host_config(path: Path) -> CaptureHostConfig:
    descriptor, _ = open_regular_file_no_symlinks(path, "browser capture configuration")
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("browser capture configuration must be owner-only")
        body = handle.read(MAX_CONFIG_BYTES + 1)
    if len(body) > MAX_CONFIG_BYTES:
        raise ValueError("browser capture configuration is too large")
    value = _object(body)
    required = {"format_version", "extension_origin", "spool_root", "key_file", "bindings"}
    if set(value) not in (required, required | {"upload_endpoint", "credential_file"}):
        raise ValueError("browser capture configuration fields are invalid")
    if type(value["format_version"]) is not int or value["format_version"] != 1:
        raise ValueError("browser capture configuration version is invalid")
    origin = value["extension_origin"]
    if not isinstance(origin, str) or not _EXTENSION_ORIGIN.fullmatch(origin):
        raise ValueError("browser capture extension origin is invalid")
    paths: list[Path] = []
    for name in ("spool_root", "key_file"):
        raw = value[name]
        if not isinstance(raw, str) or not Path(raw).is_absolute():
            raise ValueError("browser capture paths must be absolute")
        paths.append(Path(raw))
    raw_bindings = value["bindings"]
    if not isinstance(raw_bindings, list):
        raise ValueError("browser capture bindings are invalid")
    binding_items = cast(list[object], raw_bindings)
    if not 1 <= len(binding_items) <= 64:
        raise ValueError("browser capture bindings are invalid")
    bindings: dict[tuple[str, str], str] = {}
    used: set[str] = set()
    for item in binding_items:
        if not isinstance(item, dict):
            raise ValueError("browser capture binding fields are invalid")
        row = cast(dict[str, object], item)
        if set(row) != {"provider", "email", "account_binding"}:
            raise ValueError("browser capture binding fields are invalid")
        provider, email, binding = row["provider"], row["email"], row["account_binding"]
        if (
            not isinstance(provider, str)
            or provider not in _PROVIDERS
            or not isinstance(email, str)
            or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
            or len(email) > 254
            or not isinstance(binding, str)
            or not _BINDING.fullmatch(binding)
            or binding in used
            or (provider, email) in bindings
        ):
            raise ValueError("browser capture binding is invalid or ambiguous")
        bindings[(provider, email)] = binding
        used.add(binding)
    endpoint: str | None = None
    credential_file: Path | None = None
    if "upload_endpoint" in value:
        from cross_assistant_memory.browser_capture_transport import validate_capture_endpoint

        raw_endpoint, raw_credential = value["upload_endpoint"], value["credential_file"]
        if not isinstance(raw_endpoint, str) or not isinstance(raw_credential, str):
            raise ValueError("browser capture upload configuration is invalid")
        validate_capture_endpoint(raw_endpoint)
        credential_file = Path(raw_credential)
        if not credential_file.is_absolute():
            raise ValueError("browser capture credential path must be absolute")
        endpoint = raw_endpoint
    return CaptureHostConfig(origin, paths[0], paths[1], bindings, endpoint, credential_file)


def handle_capture_request(
    body: bytes, config: CaptureHostConfig, caller_origin: str
) -> dict[str, str]:
    if caller_origin != config.extension_origin:
        return {"status": "capture_failed"}
    from cross_assistant_memory.browser_capture_spool import (
        BrowserCaptureSpool,
        BrowserCaptureSpoolFull,
    )

    try:
        request = _object(body)
        operation = request.get("operation")
        if operation == "diagnostic" and set(request) == {
            "operation",
            "page_key",
            "provider",
            "status",
            "extension_version",
            "account_email",
        }:
            from cross_assistant_memory.browser_capture_diagnostics import record_diagnostic

            email, provider = request["account_email"], request["provider"]
            if not isinstance(provider, str) or (email is not None and not isinstance(email, str)):
                return {"status": "schema_rejected"}
            binding = config.bindings.get((provider, email)) if isinstance(email, str) else None
            if email is not None and binding is None:
                return {"status": "account_not_authorized"}
            record_diagnostic(
                config.spool_root,
                {
                    key: request[key]
                    for key in ("page_key", "provider", "status", "extension_version")
                }
                | {"account_binding": binding},
            )
            return {"status": "ready"}
        if operation == "status" and set(request) == {"operation"}:
            # This means the local capture sink, never the remote index, is ready.
            BrowserCaptureSpool(config.spool_root, config.key_file).status()
            return {"status": "ready"}
        if operation == "flush" and set(request) == {"operation"}:
            if config.upload_endpoint is None or config.credential_file is None:
                return {"status": "upload_unconfigured"}
            from cross_assistant_memory.browser_capture_transport import flush_browser_capture

            return flush_browser_capture(
                BrowserCaptureSpool(config.spool_root, config.key_file),
                config.upload_endpoint,
                config.credential_file,
            )
        if operation == "authorize" and set(request) == {"operation", "provider", "account_email"}:
            provider, email = request["provider"], request["account_email"]
            allowed = (
                isinstance(provider, str)
                and isinstance(email, str)
                and (provider, email) in config.bindings
            )
            return {"status": "ready" if allowed else "account_not_authorized"}
        if operation != "observe" or set(request) != {"operation", "account_email", "observation"}:
            return {"status": "schema_rejected"}
        value = request["observation"]
        email = request["account_email"]
        if not isinstance(value, dict) or not isinstance(email, str):
            return {"status": "schema_rejected"}
        observation = cast(dict[str, object], value)
        provider = observation.get("provider")
        if not isinstance(provider, str) or (provider, email) not in config.bindings:
            return {"status": "account_not_authorized"}
        if "account_binding" in observation:
            return {"status": "schema_rejected"}
        observation = {**observation, "account_binding": config.bindings[(provider, email)]}
        parsed = parse_browser_observation(
            json.dumps(observation, ensure_ascii=False, separators=(",", ":")).encode()
        )
        spool = BrowserCaptureSpool(config.spool_root, config.key_file)
        outcomes = [spool.put(replace(parsed, messages=(message,))) for message in parsed.messages]
        return {"status": "queued" if "queued" in outcomes else "already_queued"}
    except BrowserCaptureSpoolFull:
        return {"status": "queue_full"}
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return {"status": "schema_rejected"}
    except Exception:
        return {"status": "capture_failed"}


def serve_once(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    config: CaptureHostConfig,
    caller_origin: str,
) -> None:
    reply = {"status": "schema_rejected"}
    header = _read_exact(input_stream, 4)
    if len(header) == 4:
        length = struct.unpack("=I", header)[0]
        if 0 < length <= MAX_ENVELOPE_BYTES:
            body = _read_exact(input_stream, length)
            if len(body) == length:
                reply = handle_capture_request(body, config, caller_origin)
    _reply(output_stream, reply)


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    parts: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _reply(stream: BinaryIO, reply: dict[str, str]) -> None:
    encoded = json.dumps(reply, separators=(",", ":")).encode()
    stream.write(struct.pack("=I", len(encoded)) + encoded)
    stream.flush()


def _object(body: bytes) -> dict[str, object]:
    if not 0 < len(body) <= MAX_ENVELOPE_BYTES:
        raise ValueError("browser capture request size is invalid")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("browser capture JSON contains duplicate fields")
            result[key] = value
        return result

    result: object = json.loads(body, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("browser capture request must be an object")
    return cast(dict[str, object], result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--inspect", action="store_true")
    modes.add_argument("--flush", action="store_true")
    parser.add_argument("caller_origin", nargs="?")
    args = parser.parse_args()
    if args.caller_origin is None and not (args.inspect or args.flush):
        parser.error("caller origin or an explicit local operation is required")
    if args.caller_origin is not None and (args.inspect or args.flush):
        parser.error("local operations do not accept a browser caller")
    try:
        config = load_capture_host_config(cast(Path, args.config))
    except Exception:
        if args.inspect or args.flush:
            print(json.dumps({"text_free": True, "status": "unconfigured"}))
            raise SystemExit(1) from None
        _reply(sys.stdout.buffer, {"status": "unconfigured"})
        return
    if args.inspect or args.flush:

        def deadline(_signum: int, _frame: object) -> None:
            raise TimeoutError("capture delivery deadline")

        previous = signal.signal(signal.SIGALRM, deadline)
        signal.alarm(60)
        try:
            result = local_capture_operation(config, flush=bool(args.flush))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["status"] in {"ready", "uploaded"} else 1)
    serve_once(sys.stdin.buffer, sys.stdout.buffer, config, cast(str, args.caller_origin))


def local_capture_operation(config: CaptureHostConfig, *, flush: bool) -> dict[str, object]:
    from cross_assistant_memory.browser_capture_diagnostics import inspect_diagnostics
    from cross_assistant_memory.browser_capture_spool import BrowserCaptureSpool
    from cross_assistant_memory.browser_capture_transport import flush_browser_capture

    try:
        spool = BrowserCaptureSpool(config.spool_root, config.key_file)
        status = "ready"
        if flush:
            if config.upload_endpoint is None or config.credential_file is None:
                status = "upload_unconfigured"
            else:
                # One bounded pass; the existing collector schedule supplies the next attempt.
                status = flush_browser_capture(
                    spool, config.upload_endpoint, config.credential_file, limit=10
                )["status"]
        return {
            "text_free": True,
            "status": status,
            "queue": spool.status(),
            **inspect_diagnostics(config.spool_root),
        }
    except Exception:
        return {"text_free": True, "status": "capture_failed"}


if __name__ == "__main__":
    main()
