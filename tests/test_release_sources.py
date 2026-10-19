from __future__ import annotations

import base64
import hashlib
import io
import json
import runpy
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from contextlib import closing
from http.client import HTTPMessage
from pathlib import Path
from typing import Any

import pytest


def release_api() -> dict[str, Any]:
    return runpy.run_path(str(Path(__file__).resolve().parents[1] / "script/release_sources.py"))


def source_manifest(data: bytes) -> dict[str, Any]:
    return {
        "format_version": 1,
        "debian": {
            "source_releases": [
                {
                    "files": [
                        {
                            "url": "https://snapshot.debian.org/file/" + "a" * 40,
                            "bytes": len(data),
                            "dsc_declared_sha256": hashlib.sha256(data).hexdigest(),
                        }
                    ]
                }
            ]
        },
        "python_packages": [],
        "bundled_ui_packages": [],
    }


def source_fetch(data: bytes) -> Callable[[str, float], closing[io.BytesIO]]:
    def fetch(_url: str, _timeout: float) -> closing[io.BytesIO]:
        return closing(io.BytesIO(data))

    return fetch


def forbidden_fetch(_url: str, _timeout: float) -> closing[io.BytesIO]:
    pytest.fail("Source metadata must refuse before download")


def test_release_sources_verifies_complete_archive_without_retaining_it() -> None:
    api = release_api()
    data = b"complete source archive"
    manifest = source_manifest(data)
    requests: list[str] = []

    def fetch(url: str, timeout: float) -> closing[io.BytesIO]:
        assert 0 < timeout <= 20
        requests.append(url)
        return closing(io.BytesIO(data))

    result = api["verify_sources"](manifest, fetch=fetch)
    assert result["status"] == "passed"
    assert result["verified_archives"] == 1
    assert result["downloaded_bytes"] == len(data)
    assert result["archive_bytes_retained"] == 0
    assert requests == [manifest["debian"]["source_releases"][0]["files"][0]["url"]]


@pytest.mark.parametrize("received", [b"wrong", b"sou", b"source plus extra bytes"])
def test_release_sources_refuses_wrong_hash_truncation_and_extra_bytes(received: bytes) -> None:
    with pytest.raises(ValueError, match=r"size|SHA-256"):
        release_api()["verify_sources"](source_manifest(b"source"), fetch=source_fetch(received))


def test_conflicting_url_bindings_refuse_before_network() -> None:
    manifest = source_manifest(b"source")
    first = manifest["debian"]["source_releases"][0]["files"][0]
    manifest["debian"]["source_releases"][0]["files"].append(
        {**first, "dsc_declared_sha256": "b" * 64}
    )

    def forbidden(_url: str, _timeout: float) -> closing[io.BytesIO]:
        pytest.fail("Conflicting metadata must refuse before network access")

    with pytest.raises(ValueError, match="Conflicting"):
        release_api()["verify_sources"](manifest, fetch=forbidden)


def test_bundled_ui_archive_uses_complete_lockfile_integrity() -> None:
    data = b"bundled UI source"
    manifest = source_manifest(data)
    manifest["debian"]["source_releases"] = []
    manifest["bundled_ui_packages"] = [
        {
            "package_archive": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
            "lock_integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
        }
    ]
    result = release_api()["verify_sources"](manifest, fetch=source_fetch(data))
    assert result["verified_archives"] == 1
    assert result["archives"][0]["algorithm"] == "sha512"


def test_cli_refuses_bad_source_metadata_without_echoing_it(tmp_path: Path) -> None:
    manifest = source_manifest(b"source")
    manifest["debian"]["source_releases"][0]["files"][0]["url"] = (
        "https://files.pythonhosted.org/source?SHOULD_NOT_APPEAR"
    )
    path = tmp_path / "source-index.json"
    path.write_text(json.dumps(manifest))
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve().parents[1] / "script/release_sources.py"),
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "not_passed"
    assert "SHOULD_NOT_APPEAR" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "url",
    [
        "http://snapshot.debian.org/file/source",
        "https://127.0.0.1/source",
        "https://example.org/source",
        "https://user:password@files.pythonhosted.org/source",
        "https://files.pythonhosted.org:443/source",
        "https://files.pythonhosted.org/source?token=synthetic",
        "https://files.pythonhosted.org/source#fragment",
        "file:///private/source",
    ],
)
def test_disallowed_sources_refuse_before_any_download(url: str) -> None:
    manifest = source_manifest(b"source")
    manifest["debian"]["source_releases"][0]["files"][0]["url"] = url

    def forbidden(_url: str, _timeout: float) -> closing[io.BytesIO]:
        pytest.fail("Unsafe source metadata must refuse before network access")

    with pytest.raises(ValueError, match="origins"):
        release_api()["verify_sources"](manifest, fetch=forbidden)


@pytest.mark.parametrize(
    "field,value",
    [
        ("bytes", True),
        ("bytes", 0),
        ("bytes", 512 * 1024**2 + 1),
        ("dsc_declared_sha256", "invalid"),
    ],
)
def test_invalid_sizes_hashes_and_budget_refuse_before_network(field: str, value: object) -> None:
    manifest = source_manifest(b"source")
    manifest["debian"]["source_releases"][0]["files"][0][field] = value

    def forbidden(_url: str, _timeout: float) -> closing[io.BytesIO]:
        pytest.fail("Invalid source bindings must refuse before network access")

    with pytest.raises(ValueError):
        release_api()["verify_sources"](manifest, fetch=forbidden)


def test_identical_url_binding_is_downloaded_once() -> None:
    data = b"source"
    manifest = source_manifest(data)
    files = manifest["debian"]["source_releases"][0]["files"]
    files.append(dict(files[0]))
    requests: list[str] = []

    def fetch(url: str, _timeout: float) -> closing[io.BytesIO]:
        requests.append(url)
        return closing(io.BytesIO(data))

    assert release_api()["verify_sources"](manifest, fetch=fetch)["verified_archives"] == 1
    assert len(requests) == 1


def test_interrupted_download_closes_stream_without_retry() -> None:
    class Interrupted(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise OSError("synthetic interrupted read")

    stream = Interrupted(b"source")
    requests: list[str] = []

    def fetch(url: str, _timeout: float) -> closing[io.BytesIO]:
        requests.append(url)
        return closing(stream)

    with pytest.raises(OSError):
        release_api()["verify_sources"](source_manifest(b"source"), fetch=fetch)
    assert stream.closed
    assert len(requests) == 1


def test_missing_python_source_form_refuses_before_network() -> None:
    manifest = source_manifest(b"source")
    manifest["python_packages"] = [{"source_distributions": []}]
    with pytest.raises(ValueError, match="source form"):
        release_api()["verify_sources"](manifest, fetch=forbidden_fetch)


def test_expired_deadline_does_not_start_download(monkeypatch: pytest.MonkeyPatch) -> None:
    api = release_api()
    times = iter([0.0, 601.0])
    monkeypatch.setattr(api["time"], "monotonic", lambda: next(times, 601.0))
    with pytest.raises(TimeoutError):
        api["verify_sources"](source_manifest(b"source"), fetch=forbidden_fetch)


def test_https_transport_disables_proxies_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    api = release_api()
    captured: list[object] = []

    def build(*handlers: object) -> urllib.request.OpenerDirector:
        captured.extend(handlers)
        return urllib.request.OpenerDirector()

    monkeypatch.setattr(urllib.request, "build_opener", build)
    api["https_fetch"]()
    proxies = [item for item in captured if isinstance(item, urllib.request.ProxyHandler)]
    assert len(proxies) == 1 and vars(proxies[0])["proxies"] == {}
    redirects = [item for item in captured if isinstance(item, urllib.request.HTTPRedirectHandler)]
    assert len(redirects) == 1
    with io.BytesIO() as source:
        result = redirects[0].redirect_request(
            urllib.request.Request("https://snapshot.debian.org/file/source"),
            source,
            302,
            "Found",
            HTTPMessage(),
            "http://127.0.0.1/private",
        )
    assert result is None


@pytest.mark.parametrize("version", [True, 0, 2, None])
def test_unknown_index_format_is_not_silently_adopted(version: object) -> None:
    manifest = source_manifest(b"source")
    manifest["format_version"] = version
    with pytest.raises(ValueError, match="format"):
        release_api()["verify_sources"](manifest, fetch=forbidden_fetch)
