from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.browser_capture_diagnostics import (
    inspect_diagnostics,
    record_diagnostic,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return private / "spool"


def report(key: str = "a") -> dict[str, object]:
    return {
        "page_key": key * 64,
        "provider": "chatgpt_web",
        "status": "identity_not_verified",
        "extension_version": "0.2.0",
        "account_binding": None,
    }


def test_reports_are_separate_bounded_and_age_explicit(root: Path) -> None:
    for i in range(40):
        record_diagnostic(root, {**report(), "page_key": f"{i:064x}"}, now=100 + i)
    result = inspect_diagnostics(root, now=400)
    pages = cast(list[dict[str, object]], result["pages"])
    assert len(pages) == 32
    assert all(page["stale"] for page in pages)
    assert pages[-1]["age_seconds"] == 261


@pytest.mark.parametrize(
    "change",
    [
        {"text": "PRIVATE"},
        {"status": "PRIVATE"},
        {"account_binding": "owner@example.test"},
        {"page_key": "https://private.test"},
    ],
)
def test_diagnostics_refuse_free_text(root: Path, change: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        record_diagnostic(root, {**report(), **change})
    assert not root.with_suffix(".diagnostics.json").exists()


def test_latest_page_state_does_not_retain_previous_account(root: Path) -> None:
    binding = "source_account:" + "b" * 64
    record_diagnostic(root, {**report(), "account_binding": binding}, now=100)
    record_diagnostic(root, report(), now=101)
    result = inspect_diagnostics(root, now=102)
    pages = cast(list[dict[str, object]], result["pages"])
    assert pages[0]["account_binding"] is None
    assert pages[0]["age_seconds"] == 1
    assert pages[0]["stale"] is False
    assert "owner@" not in json.dumps(result)


def test_unsafe_diagnostic_file_is_not_followed(root: Path) -> None:
    target = root.parent / "unrelated"
    target.write_text("untouched")
    root.with_suffix(".diagnostics.json").symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        record_diagnostic(root, report())
    assert target.read_text() == "untouched"


@pytest.mark.parametrize(
    "change",
    [
        {"delivery": {"status": "PRIVATE", "checked_at": 1}},
        {"pages": {"a" * 64: {**report(), "checked_at": float("nan")}}},
        {"last_receipts": {"owner@example.test": {"private": "body"}}},
    ],
)
def test_inspection_refuses_untrusted_file_content(root: Path, change: dict[str, object]) -> None:
    file = root.with_suffix(".diagnostics.json")
    file.write_text(json.dumps({"pages": {}, "delivery": None, "last_receipts": {}, **change}))
    file.chmod(0o600)
    with pytest.raises(ValueError):
        inspect_diagnostics(root)
