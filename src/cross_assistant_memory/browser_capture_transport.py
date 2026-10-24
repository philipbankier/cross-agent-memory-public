from __future__ import annotations

import fcntl
import json
import os
import stat
from http.client import HTTPException, IncompleteRead
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cross_assistant_memory.browser_capture_diagnostics import record_delivery, record_receipt
from cross_assistant_memory.browser_capture_spool import BrowserCaptureSpool
from cross_assistant_memory.safe_files import (
    open_directory_no_symlinks,
    open_regular_file_no_symlinks,
)

MAX_RESPONSE_BYTES = 16 * 1024


def _receipt_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("invalid receipt number")


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def validate_capture_endpoint(endpoint: str) -> None:
    value = urlsplit(endpoint)
    if (
        value.scheme != "http"
        or value.hostname != "127.0.0.1"
        or value.username is not None
        or value.password is not None
        or value.port is None
        or value.path != "/upload/browser-observations"
        or value.query
        or value.fragment
    ):
        raise ValueError("browser capture requires the configured loopback collection tunnel")


def flush_browser_capture(
    spool: BrowserCaptureSpool, endpoint: str, credential_file: Path, *, limit: int = 2
) -> dict[str, str]:
    if type(limit) is not int or not 1 <= limit <= 10:
        raise ValueError("invalid capture delivery limit")
    directory = open_directory_no_symlinks(spool.root.parent, "capture delivery directory")
    lock: int | None = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("capture delivery directory must be private")
        lock = os.open(
            spool.root.name + ".delivery.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=directory,
        )
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size
        ):
            raise ValueError("invalid capture delivery lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "upload_pending"}
        result = _flush(spool, endpoint, credential_file, limit=limit)
        record_delivery(spool.root, result["status"])
        return result
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def _flush(
    spool: BrowserCaptureSpool, endpoint: str, credential_file: Path, *, limit: int
) -> dict[str, str]:
    validate_capture_endpoint(endpoint)
    descriptor, _ = open_regular_file_no_symlinks(credential_file, "browser upload credential")
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
            raise ValueError("browser capture upload credential must be owner-only")
        credential = handle.read(4097).decode("ascii").strip()
    if not credential or len(credential) > 4096 or any(c.isspace() for c in credential):
        raise ValueError("browser capture upload credential is invalid")
    pending = spool.pending(limit=limit)
    if not pending:
        return {"status": "ready"}
    for digest in pending:
        observation = spool.read(digest)
        request = Request(
            endpoint,
            data=observation.canonical_bytes(),
            headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with build_opener(ProxyHandler({}), _RejectRedirects()).open(
                request, timeout=5
            ) as response:
                status_code = response.status
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) <= MAX_RESPONSE_BYTES and response.length not in {None, 0}:
                    raise IncompleteRead(body)
        except HTTPError as error:
            status = "upload_not_authorized" if error.code in {401, 403} else "upload_pending"
            error.close()
            return {"status": status}
        except (HTTPException, URLError, TimeoutError, OSError):
            return {"status": "upload_pending"}
        if status_code not in {200, 201} or len(body) > MAX_RESPONSE_BYTES:
            return {"status": "invalid_receipt"}
        try:
            receipt: object = json.loads(
                body, object_pairs_hook=_receipt_object, parse_constant=_reject_constant
            )
            if not isinstance(receipt, dict):
                raise ValueError("invalid receipt")
            spool.acknowledge(digest, cast(dict[str, object], receipt), status_code)
        except (ValueError, RuntimeError):
            return {"status": "invalid_receipt"}
        checked_receipt = cast(dict[str, object], receipt)
        record_receipt(
            spool.root,
            observation.account_binding,
            cast(str, checked_receipt["batch_id"]),
            cast(str, checked_receipt["created_at"]),
        )
    return {"status": "uploaded"}
