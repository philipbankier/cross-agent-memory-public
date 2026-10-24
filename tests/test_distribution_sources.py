from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from cross_assistant_memory.runtime_provenance import source_provenance


def _prepare_context(output: Path) -> None:
    source = Path(__file__).parents[1] / "src/cross_assistant_memory/runtime_provenance.py"
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(source), "--prepare-container", str(output)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_verified_build_context_includes_the_distribution_companion(tmp_path: Path) -> None:
    context = tmp_path / "context"
    _prepare_context(context)
    for name in ("README.md", "notices.txt", "source-index.json"):
        assert (context / "docs/third-party" / name).is_file()
    for name in ("manifest.json", "observe.js", "background.js", "popup.html"):
        assert (context / "browser/capture" / name).is_file()


@pytest.mark.parametrize("name", ["manifest.json", "observe.js"])
def test_changed_browser_capture_refuses_source_provenance(tmp_path: Path, name: str) -> None:
    context = tmp_path / "context"
    _prepare_context(context)
    target = context / "browser/capture" / name
    target.write_bytes(target.read_bytes() + b"\nchanged\n")
    with pytest.raises(RuntimeError, match="source distribution differs"):
        source_provenance(context)


@pytest.mark.parametrize("name", ["README.md", "notices.txt", "source-index.json"])
def test_changed_companion_refuses_git_free_source_provenance(tmp_path: Path, name: str) -> None:
    context = tmp_path / "context"
    _prepare_context(context)
    target = context / "docs/third-party" / name
    assert target.is_file()
    target.write_bytes(target.read_bytes() + b"\nchanged\n")
    with pytest.raises(RuntimeError, match="source distribution differs"):
        source_provenance(context)


@pytest.mark.parametrize("name", ["docs", "docs/third-party"])
def test_source_companion_parent_symlinks_are_refused(tmp_path: Path, name: str) -> None:
    context = tmp_path / "context"
    _prepare_context(context)
    parent = context / name
    parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    parent.rename(outside)
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="refuses symbolic links"):
        source_provenance(context)


@pytest.mark.parametrize("tamper", [None, "missing", "changed", "extra", "symlink", "writable"])
def test_installed_companion_probe_checks_bytes_membership_and_permissions(
    tmp_path: Path, tamper: str | None
) -> None:
    source = (Path(__file__).parents[1] / "script/verify-container").read_text()
    marker = 'SOURCE_COMPANION_CHECK=$(docker exec -i "$CONTAINER_ID"'
    assert marker in source
    start = source.index("<<'PY'\n", source.index(marker)) + len("<<'PY'\n")
    probe = source[start : source.index("\nPY", start)]
    root = tmp_path / "companion"
    root.mkdir(mode=0o755)
    data = b"source companion fixture\n"
    expected = {}
    for name in ("README.md", "notices.txt", "source-index.json"):
        target = root / name
        target.write_bytes(data)
        target.chmod(0o444)
        expected[name] = hashlib.sha256(data).hexdigest()
    target = root / "notices.txt"
    if tamper == "missing":
        target.unlink()
    elif tamper == "changed":
        target.chmod(0o600)
        target.write_bytes(b"changed")
        target.chmod(0o444)
    elif tamper == "extra":
        (root / "unreviewed.txt").write_bytes(data)
    elif tamper == "symlink":
        outside = tmp_path / "outside.txt"
        outside.write_bytes(data)
        outside.chmod(0o444)
        target.unlink()
        target.symlink_to(outside)
    elif tamper == "writable":
        target.chmod(0o644)
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe, str(root), json.dumps(expected)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (tamper is None), result.stderr


def test_source_archive_contains_the_exact_protected_companion(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys,setuptools.build_meta as build; build.build_sdist(sys.argv[1])",
            str(tmp_path),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    archives = list(tmp_path.glob("*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0]) as archive:
        members = {
            Path(item.name).as_posix().split("/", 1)[1]: item
            for item in archive.getmembers()
            if item.isfile()
        }
        for name in ("README.md", "notices.txt", "source-index.json"):
            relative = "docs/third-party/" + name
            assert relative in members
            content = archive.extractfile(members[relative])
            assert content is not None
            assert content.read() == (root / relative).read_bytes()
        for path in (root / "browser/capture").iterdir():
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            assert relative in members
            content = archive.extractfile(members[relative])
            assert content is not None and content.read() == path.read_bytes()
