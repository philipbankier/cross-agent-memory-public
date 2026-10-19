"""Verify indexed public source archives without extracting or retaining them."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, BinaryIO, cast
from urllib.parse import urlsplit

Fetch = Callable[[str, float], AbstractContextManager[BinaryIO]]
MAX_BYTES = 512 * 1024**2
DEADLINE_SECONDS = 600
MAX_UI_BYTES = 16 * 1024**2


def validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc
        not in {"snapshot.debian.org", "files.pythonhosted.org", "registry.npmjs.org"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Source URL is outside the permitted public origins")


def verify_sources(manifest: dict[str, Any], *, fetch: Fetch) -> dict[str, Any]:
    if type(manifest.get("format_version")) is not int or manifest["format_version"] != 1:
        raise ValueError("Unsupported source-index format")
    artifacts: dict[str, tuple[int | None, str, str]] = {}

    def add(url: str, size: int | None, digest: str, algorithm: str = "sha256") -> None:
        binding = (size, digest, algorithm)
        if url in artifacts and artifacts[url] != binding:
            raise ValueError("Conflicting source URL bindings")
        artifacts[url] = binding

    for source in manifest["debian"]["source_releases"]:
        for item in source["files"]:
            if "dsc_declared_sha256" in item:
                add(item["url"], item["bytes"], item["dsc_declared_sha256"])
    for package in manifest["python_packages"]:
        if not package["source_distributions"] and "source_wheel" not in package:
            raise ValueError("Python package has no indexed source form")
        for item in package["source_distributions"]:
            add(item["url"], item["bytes"], item["pypi_declared_sha256"])
        if "source_wheel" in package:
            item = package["source_wheel"]
            add(item["url"], item["bytes"], item["sha256"])
    for item in manifest["bundled_ui_packages"]:
        prefix, separator, value = item["lock_integrity"].partition("-")
        if prefix != "sha512" or not separator:
            raise ValueError("Unsupported UI integrity algorithm")
        digest = base64.b64decode(value, validate=True)
        if len(digest) != 64:
            raise ValueError("Invalid UI integrity hash")
        add(item["package_archive"], None, digest.hex(), "sha512")
    if not artifacts:
        raise ValueError("Source index contains no archives")
    for url, (size, digest, algorithm) in artifacts.items():
        validate_url(url)
        if size is not None and (type(size) is not int or size <= 0):
            raise ValueError("Invalid source size")
        if not re.fullmatch(r"[a-f0-9]{" + str(128 if algorithm == "sha512" else 64) + "}", digest):
            raise ValueError("Invalid source size or SHA-256")
    if (
        sum(size if size is not None else MAX_UI_BYTES for size, _, _ in artifacts.values())
        > MAX_BYTES
    ):
        raise ValueError("Source transfer exceeds the fixed budget")
    started = time.monotonic()
    transferred = 0
    verified: list[dict[str, Any]] = []
    for url, (size, expected, algorithm) in artifacts.items():
        remaining = DEADLINE_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("Source verification deadline exceeded")
        digest = hashlib.new(algorithm)
        received = 0
        limit = size if size is not None else MAX_UI_BYTES
        with fetch(url, min(20, remaining)) as source:
            while chunk := source.read(min(128 * 1024, limit - received + 1)):
                received += len(chunk)
                transferred += len(chunk)
                if received > limit or transferred > MAX_BYTES:
                    raise ValueError("Source archive exceeds its declared size")
                if time.monotonic() - started >= DEADLINE_SECONDS:
                    raise TimeoutError("Source verification deadline exceeded")
                digest.update(chunk)
        if (size is not None and received != size) or digest.hexdigest() != expected:
            raise ValueError("Source archive size or SHA-256 mismatch")
        verified.append({"url": url, "bytes": received, "algorithm": algorithm, "digest": expected})
    return {
        "status": "passed",
        "scope": (
            "Indexed Debian/Python/UI archives, not runtime sources, source closure or publication"
        ),
        "verified_archives": len(verified),
        "downloaded_bytes": transferred,
        "archive_bytes_retained": 0,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "archives": verified,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def https_fetch() -> Fetch:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )

    def fetch(url: str, timeout: float) -> AbstractContextManager[BinaryIO]:
        validate_url(url)
        return cast(AbstractContextManager[BinaryIO], opener.open(url, timeout=timeout))

    return fetch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    arguments = parser.parse_args()
    try:
        with Path(arguments.manifest).open("rb") as source:
            data = source.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError("Source index is too large")
        manifest = json.loads(data)
        if not isinstance(manifest, dict):
            raise ValueError("Invalid source index")
        result = verify_sources(cast(dict[str, Any], manifest), fetch=https_fetch())
        result["input_manifest_sha256"] = hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        print(json.dumps({"status": "not_passed", "error_type": type(error).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
