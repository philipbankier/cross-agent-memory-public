from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import NoReturn

import pytest

from cross_assistant_memory import grok_bot_artifacts as artifacts
from cross_assistant_memory.grok_bot_capture import (
    GrokBotCaptureScope,
    GrokBotStructuredRequestObservation,
)

BOT = "abcdef00-0000-4000-8000-000000000001"
COLLECTOR = "abcdef00-0000-4000-8000-000000000002"
URI = "file:///workspace/results/sent.md"
Case = tuple[Path, GrokBotCaptureScope, GrokBotStructuredRequestObservation]


def page(uri: str = URI, bot: str = BOT) -> bytes:
    record = {
        "role": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": "synthetic-sent-file",
                    "name": "SendToUser",
                    "input": {"type": "attachment", "url": uri},
                }
            ]
        },
    }
    return (
        '<cursor_untrusted_data_artifact source="ReadTranscript">\n\n'
        f'Transcript of agent "Synthetic" ({bot}), positions 0\u20130 of 1:\n'
        + json.dumps(record)
        + "\n\n</cursor_untrusted_data_artifact>\n"
    ).encode()


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Case:
    workspace = tmp_path / "workspace"
    (workspace / "results").mkdir(parents=True)
    monkeypatch.setattr(artifacts, "WORKSPACE_ROOT", workspace)
    scope = GrokBotCaptureScope("source_account:" + "0" * 64, (BOT,), COLLECTOR)
    reference = artifacts.select_sent_attachment(page(), bot_id=BOT, scope=scope)[0]
    return workspace, scope, reference


def test_reader_preserves_exact_bytes_and_separate_snapshot_manifest(case: Case) -> None:
    workspace, scope, reference = case
    data = b"# Synthetic artifact\nA bounded result.\n"
    (workspace / "results/sent.md").write_bytes(data)
    captured = artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)
    assert captured.data == data
    assert captured.content_text == data.decode()
    manifest = captured.manifest()
    assert manifest["content_sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["byte_length"] == len(data)
    assert manifest["reference_sha256"] == hashlib.sha256(reference.canonical_bytes()).hexdigest()
    assert manifest["inspection_status"] == "inspected_text"
    assert manifest["native_version_verified"] is False
    assert manifest["original_sent_bytes_verified"] is False
    assert manifest["media_type_hint"] == "text/markdown"
    assert manifest["native_author_id"] is None
    assert "Bounded result" not in repr(captured)
    assert data.decode() not in json.dumps(manifest)


def test_unknown_media_is_payload_opaque_and_metadata_only(case: Case) -> None:
    workspace, scope, _reference = case
    png_reference = artifacts.select_sent_attachment(
        page("file:///workspace/results/sent.png"), bot_id=BOT, scope=scope
    )[0]
    data = b"\x89PNG\r\n\x1a\nopaque-synthetic-media\x00"
    (workspace / "results/sent.png").write_bytes(data)
    captured = artifacts.read_sent_artifact(png_reference, scope=scope, max_bytes=4096)
    assert captured.data == data and captured.content_text is None
    assert captured.manifest()["content_access"] == "metadata_only"
    assert captured.manifest()["inspection_status"] == "not_inspected"
    assert "opaque-synthetic-media" not in repr(captured)
    assert "opaque-synthetic-media" not in json.dumps(captured.manifest())


@pytest.mark.parametrize("marker", [b"[private]", b"[no-memory]", b"xai-" + b"0" * 32])
def test_known_exclusions_prevent_artifact_retention(case: Case, marker: bytes) -> None:
    workspace, scope, reference = case
    (workspace / "results/sent.md").write_bytes(marker)
    with pytest.raises(artifacts.SentArtifactError) as caught:
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)
    assert caught.value.code.startswith("excluded:")
    assert marker.decode() not in str(caught.value)


def test_media_metadata_still_cannot_hide_known_secret_bytes(case: Case) -> None:
    workspace, scope, _ = case
    reference = artifacts.select_sent_attachment(
        page("file:///workspace/results/sent.png"), bot_id=BOT, scope=scope
    )[0]
    (workspace / "results/sent.png").write_bytes(b"\x89PNG\x00xai-" + b"0" * 32)
    with pytest.raises(artifacts.SentArtifactError, match="excluded:"):
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)


def test_only_the_enrolled_bot_can_select_or_read_artifacts(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, reference = case
    other_scope = GrokBotCaptureScope(
        "source_account:" + "0" * 64, (COLLECTOR,), "abcdef00-0000-4000-8000-000000000003"
    )

    def no_open(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("scope must be checked before file access")

    monkeypatch.setattr(artifacts, "open_regular_file_no_symlinks", no_open)
    with pytest.raises(artifacts.SentArtifactError, match="source_not_enrolled"):
        artifacts.read_sent_artifact(reference, scope=other_scope, max_bytes=4096)
    with pytest.raises(artifacts.SentArtifactError, match="source_not_enrolled"):
        artifacts.select_sent_attachment(page(), bot_id=BOT, scope=other_scope)


@pytest.mark.parametrize(
    "uri",
    [
        "file:///workspace/.ssh/key",
        "file:///workspace/results/.env",
        "file:///workspace/secrets/config.json",
        "file:///workspace/results/key.pem",
        "file:///workspace/cam-integration-probe/capture/secrets/collector.token",
    ],
)
def test_credential_and_collector_paths_refuse_before_open(
    case: Case, uri: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, scope, _ = case
    reference = artifacts.select_sent_attachment(page(uri), bot_id=BOT, scope=scope)[0]

    def no_open(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("sensitive paths must be rejected before open")

    monkeypatch.setattr(artifacts, "open_regular_file_no_symlinks", no_open)
    with pytest.raises(artifacts.SentArtifactError, match="unsafe_reference") as caught:
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)
    assert uri not in str(caught.value)


@pytest.mark.parametrize("parent", [False, True])
def test_symlinks_are_not_followed(case: Case, tmp_path: Path, parent: bool) -> None:
    workspace, scope, reference = case
    target = tmp_path / "unrelated-file"
    target.write_bytes(b"do not read")
    if parent:
        (workspace / "results").rmdir()
        (workspace / "results").symlink_to(tmp_path, target_is_directory=True)
    else:
        (workspace / "results/sent.md").symlink_to(target)
    with pytest.raises(artifacts.SentArtifactError, match="unavailable_or_unsafe"):
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)


def test_oversize_is_refused_before_payload_read(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, scope, reference = case
    (workspace / "results/sent.md").write_bytes(b"x" * 33)

    def no_read(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("oversized payload must not be read")

    monkeypatch.setattr(artifacts.os, "read", no_read)
    with pytest.raises(artifacts.SentArtifactError, match="over_limit"):
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=32)


def test_changed_file_or_replaced_directory_entry_refuses(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, scope, reference = case
    path = workspace / "results/sent.md"
    path.write_bytes(b"synthetic bytes")
    original = os.read
    changed = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        result = original(descriptor, size)
        if not changed:
            replacement = path.with_suffix(".new")
            replacement.write_bytes(b"different bytes")
            replacement.replace(path)
            changed = True
        return result

    monkeypatch.setattr(artifacts.os, "read", replace_after_read)
    with pytest.raises(artifacts.SentArtifactError, match="source_changed"):
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)


def test_hard_links_are_not_eligible(case: Case) -> None:
    workspace, scope, reference = case
    path = workspace / "results/sent.md"
    path.write_bytes(b"synthetic bytes")
    os.link(path, workspace / "results/also.md")
    with pytest.raises(artifacts.SentArtifactError, match="unavailable_or_unsafe"):
        artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)


def test_touch_does_not_manufacture_an_artifact_content_version(case: Case) -> None:
    workspace, scope, reference = case
    path = workspace / "results/sent.md"
    path.write_bytes(b"synthetic bytes")
    first = artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
    second = artifacts.read_sent_artifact(reference, scope=scope, max_bytes=4096)
    assert first.manifest() == second.manifest()
    assert first.observed_mtime_ns != second.observed_mtime_ns
