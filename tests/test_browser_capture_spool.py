from __future__ import annotations

import json
import multiprocessing
import os
import stat
import time
import traceback
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from cross_assistant_memory import browser_capture_spool
from cross_assistant_memory.browser_capture_spool import (
    BrowserCaptureSpool,
    BrowserCaptureSpoolError,
    BrowserCaptureSpoolFull,
)
from cross_assistant_memory.browser_observation import (
    BrowserObservation,
    parse_browser_observation,
)
from cross_assistant_memory.tink_crypto import Keyset


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    root = private / "spool"
    root.mkdir(mode=0o700)
    key = private / "fixture.key"
    key.write_bytes(Keyset.generate_aead().serialize_cleartext())
    key.chmod(0o400)
    return root, key


def _observation(account: str = "a") -> BrowserObservation:
    conversation = "11111111-2222-4333-8444-555555555555"
    value = {
        "format_version": 1,
        "provider": "claude_web",
        "account_binding": "source_account:" + account * 64,
        "conversation_id": conversation,
        "canonical_url": "https://claude.ai/chat/" + conversation,
        "observed_at": "2026-10-20T12:00:00Z",
        "capture_kind": "rendered_browser_observation",
        "completeness": "visible_messages_only",
        "messages": [
            {
                "locator": "0",
                "locator_kind": "rendered_position",
                "role": "user",
                "text": "SYNTHETIC_BROWSER_CAPTURE_PLAINTEXT",
            }
        ],
    }
    return parse_browser_observation(json.dumps(value).encode())


def _ciphertext(root: Path, observation: BrowserObservation) -> Path:
    return root / f"observation.{observation.content_digest}"


def test_put_read_status_and_no_plaintext(paths: tuple[Path, Path]) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    assert spool.status() == {
        "queued_observations": 0,
        "ciphertext_bytes": 0,
        "max_bytes": 32 * 1024 * 1024,
        "available_bytes": 32 * 1024 * 1024,
    }
    observation = _observation()
    assert spool.put(observation) == "queued"
    stored = _ciphertext(root, observation)
    ciphertext = stored.read_bytes()
    assert observation.messages[0].text.encode() not in ciphertext
    assert observation.account_binding.encode() not in ciphertext
    assert observation.observed_at.encode() not in ciphertext
    assert stat.S_IMODE(stored.stat().st_mode) == 0o400
    assert spool.read(observation.content_digest) == observation
    assert spool.status()["queued_observations"] == 1
    assert spool.status()["ciphertext_bytes"] == len(ciphertext)
    assert sorted(path.name for path in root.iterdir()) == [
        ".browser-capture.lock",
        stored.name,
    ]


def test_replay_preserves_first_time_ciphertext_and_file(paths: tuple[Path, Path]) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    original = _observation()
    assert spool.put(original) == "queued"
    stored = _ciphertext(root, original)
    ciphertext = stored.read_bytes()
    before = stored.stat()
    assert spool.put(original) == "already_queued"
    later = replace(original, observed_at="2026-10-21T00:00:00Z")
    assert spool.put(later) == "already_queued"
    assert stored.read_bytes() == ciphertext
    after = stored.stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert spool.read(original.content_digest).observed_at == original.observed_at


def test_accounts_and_restarts_are_isolated(paths: tuple[Path, Path]) -> None:
    root, key = paths
    first, second = _observation("a"), _observation("b")
    spool = BrowserCaptureSpool(root, key)
    assert spool.put(first) == "queued"
    assert spool.put(second) == "queued"
    reopened = BrowserCaptureSpool(root, key)
    assert reopened.status()["queued_observations"] == 2
    assert reopened.read(first.content_digest).account_binding == first.account_binding
    assert reopened.read(second.content_digest).account_binding == second.account_binding
    assert reopened.put(first) == "already_queued"


def test_full_spool_preserves_every_file_and_allows_replay(paths: tuple[Path, Path]) -> None:
    root, key = paths
    first = _observation()
    assert BrowserCaptureSpool(root, key).put(first) == "queued"
    used = _ciphertext(root, first).stat().st_size
    spool = BrowserCaptureSpool(root, key, max_bytes=used)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(BrowserCaptureSpoolFull):
        spool.put(_observation("b"))
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
    assert spool.status()["available_bytes"] == 0
    assert spool.put(first) == "already_queued"
    assert spool.read(first.content_digest) == first
    reduced_cap = BrowserCaptureSpool(root, key, max_bytes=1)
    assert reduced_cap.status()["ciphertext_bytes"] == used
    assert reduced_cap.put(first) == "already_queued"
    with pytest.raises(BrowserCaptureSpoolFull):
        reduced_cap.put(_observation("b"))


@pytest.mark.parametrize("operation", ["read", "put", "status"])
def test_tamper_fails_closed_without_removal(paths: tuple[Path, Path], operation: str) -> None:
    root, key = paths
    observation = _observation()
    spool = BrowserCaptureSpool(root, key)
    spool.put(observation)
    stored = _ciphertext(root, observation)
    corrupt = bytearray(stored.read_bytes())
    corrupt[-1] ^= 1
    stored.chmod(0o600)
    stored.write_bytes(corrupt)
    stored.chmod(0o400)
    with pytest.raises(BrowserCaptureSpoolError):
        if operation == "read":
            spool.read(observation.content_digest)
        elif operation == "put":
            spool.put(observation)
        else:
            spool.status()
    assert stored.read_bytes() == corrupt


def test_digest_filename_is_authenticated(paths: tuple[Path, Path]) -> None:
    root, key = paths
    original, other = _observation(), _observation("b")
    spool = BrowserCaptureSpool(root, key)
    spool.put(original)
    _ciphertext(root, original).rename(_ciphertext(root, other))
    with pytest.raises(BrowserCaptureSpoolError):
        spool.read(other.content_digest)


def test_associated_data_binds_format_and_digest(paths: tuple[Path, Path]) -> None:
    root, key = paths
    observation = _observation()
    spool = BrowserCaptureSpool(root, key)
    spool.put(observation)
    primitive = Keyset.read_cleartext(key.read_bytes()).aead()
    stored = _ciphertext(root, observation)
    for version, digest in [(2, observation.content_digest), (1, "f" * 64)]:
        aad = json.dumps(
            {"format_version": version, "kind": "browser_capture_spool", "content_digest": digest},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        stored.chmod(0o600)
        stored.write_bytes(primitive.encrypt(observation.canonical_bytes(), aad))
        stored.chmod(0o400)
        with pytest.raises(BrowserCaptureSpoolError):
            spool.read(observation.content_digest)


def test_key_is_never_created_or_replaced(paths: tuple[Path, Path]) -> None:
    root, key = paths
    missing = key.parent / "missing.key"
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(root, missing)
    assert not missing.exists()
    assert list(root.iterdir()) == []
    invalid = key.parent / "invalid.key"
    invalid.write_bytes(b"SYNTHETIC_INVALID_KEY")
    invalid.chmod(0o400)
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(root, invalid)
    assert invalid.read_bytes() == b"SYNTHETIC_INVALID_KEY"


def test_key_drift_and_wrong_key_refuse(paths: tuple[Path, Path]) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    spool.put(_observation())
    key.chmod(0o600)
    key.write_bytes(Keyset.generate_aead().serialize_cleartext())
    key.chmod(0o400)
    with pytest.raises(BrowserCaptureSpoolError):
        spool.status()
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(root, key).status()


def test_owner_writable_supplied_key_is_supported(paths: tuple[Path, Path]) -> None:
    root, key = paths
    key.chmod(0o600)
    assert BrowserCaptureSpool(root, key).put(_observation()) == "queued"


def test_key_may_be_inside_private_root(paths: tuple[Path, Path]) -> None:
    root, key = paths
    inside = root / "fixture.key"
    key.rename(inside)
    spool = BrowserCaptureSpool(root, inside)
    assert spool.put(_observation()) == "queued"
    assert spool.status()["queued_observations"] == 1


@pytest.mark.parametrize("target", ["root", "key_parent", "key", "ciphertext", "lock"])
def test_public_permissions_refuse(paths: tuple[Path, Path], target: str) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    spool.put(_observation())
    targets = {
        "root": root,
        "key_parent": key.parent,
        "key": key,
        "ciphertext": _ciphertext(root, _observation()),
        "lock": root / ".browser-capture.lock",
    }
    path = targets[target]
    path.chmod(0o755 if path.is_dir() else 0o644)
    with pytest.raises(BrowserCaptureSpoolError):
        spool.status()
    assert stat.S_IMODE(path.stat().st_mode) in {0o755, 0o644}


@pytest.mark.parametrize("target", ["root", "key_parent", "key", "ciphertext", "lock"])
def test_symlinks_refuse(paths: tuple[Path, Path], target: str) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    spool.put(_observation())
    targets = {
        "root": root,
        "key_parent": key.parent,
        "key": key,
        "ciphertext": _ciphertext(root, _observation()),
        "lock": root / ".browser-capture.lock",
    }
    path = targets[target]
    moved = path.with_name(path.name + "-moved")
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=moved.is_dir())
    with pytest.raises(BrowserCaptureSpoolError):
        spool.status()
    assert path.is_symlink()


@pytest.mark.parametrize("target", ["key", "ciphertext", "lock"])
def test_hardlinks_refuse(paths: tuple[Path, Path], target: str) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    spool.put(_observation())
    paths_by_target = {
        "key": key,
        "ciphertext": _ciphertext(root, _observation()),
        "lock": root / ".browser-capture.lock",
    }
    path = paths_by_target[target]
    os.link(path, key.parent / "extra-link")
    with pytest.raises(BrowserCaptureSpoolError):
        spool.status()
    assert path.stat().st_nlink == 2


@pytest.mark.parametrize("target", ["root", "key_parent", "key", "ciphertext", "lock"])
def test_nonowner_metadata_refuses(
    paths: tuple[Path, Path], target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    spool.put(_observation())
    targets = {
        "root": root,
        "key_parent": key.parent,
        "key": key,
        "ciphertext": _ciphertext(root, _observation()),
        "lock": root / ".browser-capture.lock",
    }
    wrong_inode = targets[target].stat().st_ino
    original = os.fstat

    def changed_owner(descriptor: int) -> os.stat_result:
        metadata = original(descriptor)
        if metadata.st_ino == wrong_inode:
            values = list(metadata)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(os, "fstat", changed_owner)
    with pytest.raises(BrowserCaptureSpoolError):
        spool.status()


def test_replaced_root_refuses(paths: tuple[Path, Path]) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    root.rename(root.with_name("old-spool"))
    root.mkdir(mode=0o700)
    with pytest.raises(BrowserCaptureSpoolError):
        spool.put(_observation())
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("name", [".interrupted.pending", "unexpected-file"])
def test_unrecognized_entries_are_retained_and_block_writes(
    paths: tuple[Path, Path], name: str
) -> None:
    root, key = paths
    fragment = root / name
    fragment.write_bytes(b"synthetic-opaque-fragment")
    fragment.chmod(0o400)
    spool = BrowserCaptureSpool(root, key)
    with pytest.raises(BrowserCaptureSpoolError):
        spool.put(_observation())
    assert fragment.read_bytes() == b"synthetic-opaque-fragment"


def test_interrupted_publication_retains_only_ciphertext(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, key = paths
    spool = BrowserCaptureSpool(root, key)
    sentinel = "SYNTHETIC_FAILURE_MUST_NOT_ESCAPE"

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError(sentinel)

    monkeypatch.setattr(browser_capture_spool, "publish_file_no_replace_at", fail)
    with pytest.raises(BrowserCaptureSpoolError) as caught:
        spool.put(_observation())
    assert sentinel not in "".join(traceback.format_exception(caught.value))
    staged = list(root.glob("*.pending"))
    assert len(staged) == 1
    assert _observation().messages[0].text.encode() not in staged[0].read_bytes()
    before = staged[0].read_bytes()
    with pytest.raises(BrowserCaptureSpoolError):
        spool.put(_observation())
    assert staged[0].read_bytes() == before


@pytest.mark.parametrize("digest", ["../fixture.key", "F" * 64, "", "short"])
def test_invalid_read_identifiers_refuse(paths: tuple[Path, Path], digest: str) -> None:
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(*paths).read(digest)


def test_missing_observation_and_root_do_not_create_data(paths: tuple[Path, Path]) -> None:
    root, key = paths
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(root, key).read("f" * 64)
    missing = root.parent / "absent-spool"
    with pytest.raises(BrowserCaptureSpoolError):
        BrowserCaptureSpool(missing, key)
    assert not missing.exists()


def _concurrent_put(root: str, key: str, cap: int, body: bytes) -> str:
    spool = BrowserCaptureSpool(Path(root), Path(key), max_bytes=cap)
    original_lock = browser_capture_spool.fcntl.flock

    def hold_lock(descriptor: int, operation: int) -> None:
        original_lock(descriptor, operation)
        time.sleep(0.03)

    try:
        with patch.object(browser_capture_spool.fcntl, "flock", hold_lock):
            return spool.put(parse_browser_observation(body))
    except BrowserCaptureSpoolFull:
        return "full"


@pytest.mark.parametrize("duplicates", [False, True])
def test_process_concurrency_preserves_capacity_and_replay(
    paths: tuple[Path, Path], duplicates: bool
) -> None:
    root, key = paths
    probe = root.parent / "probe"
    probe.mkdir(mode=0o700)
    probe_spool = BrowserCaptureSpool(probe, key)
    probe_spool.put(_observation())
    cap = probe_spool.status()["ciphertext_bytes"] * 2
    observations = [_observation("a" if duplicates else account) for account in "abcdef"]
    with ProcessPoolExecutor(
        max_workers=4, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        futures = [
            pool.submit(_concurrent_put, str(root), str(key), cap, item.canonical_bytes())
            for item in observations
        ]
        results = [future.result(timeout=30) for future in futures]
    spool = BrowserCaptureSpool(root, key, max_bytes=cap)
    state = spool.status()
    assert state["ciphertext_bytes"] <= cap
    if duplicates:
        assert results.count("queued") == 1
        assert results.count("already_queued") == 5
        assert state["queued_observations"] == 1
    else:
        assert results.count("queued") == 2
        assert results.count("full") == 4
        assert state["queued_observations"] == 2
