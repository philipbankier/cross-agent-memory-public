"""Bind protected operations to verified source bytes, not a supplied version label."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import marshal
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import CodeType
from typing import TypedDict, cast

PACKAGE = "cross_assistant_memory"
MANIFEST = "_build_provenance.json"
EGG_INFO_FILES = frozenset(
    {
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "entry_points.txt",
        "requires.txt",
        "top_level.txt",
    }
)
BUILD_INPUTS = (
    "pyproject.toml",
    "LICENSE",
    "README.md",
    "requirements.lock",
    "requirements-bootstrap.lock",
    "cam_build.py",
    "MANIFEST.in",
    "Containerfile",
    ".dockerignore",
    "compose.yaml",
    "docs/third-party/README.md",
    "docs/third-party/notices.txt",
    "docs/third-party/source-index.json",
    "ui/memory-app/package.json",
    "ui/memory-app/package-lock.json",
    "ui/memory-app/tsconfig.json",
    "ui/memory-app/build.mjs",
)
BUILD_DIRECTORIES = ("script", "ui/memory-app/src", "ui/memory-app/test")


class BuildProvenance(TypedDict):
    format_version: int
    code_revision: str
    package_files: dict[str, str]
    build_inputs: dict[str, str]


def _validate_revision(revision: str) -> None:
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is None:
        raise ValueError("code revision must be a full lowercase Git object ID")


def _files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("runtime provenance requires a regular source directory")
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("runtime provenance refuses symbolic links")
        if path.is_dir():
            continue
        relative = path.relative_to(root)
        if relative == Path(MANIFEST):
            continue
        if "__pycache__" in relative.parts and path.suffix == ".pyc":
            _verify_bytecode(path)
            continue
        if not path.is_file():
            raise RuntimeError("runtime provenance requires regular files")
        result[relative.as_posix()] = path.read_bytes()
    return result


def _verify_bytecode(path: Path) -> None:
    try:
        source = Path(importlib.util.source_from_cache(str(path)))
        if source.is_symlink() or not source.is_file():
            raise ValueError("bytecode has no regular source")
        current = {
            Path(importlib.util.cache_from_source(str(source), optimization=level)): level
            for level in ("", "1", "2")
        }
        if path not in current:
            # Other interpreter tags cannot be loaded by this interpreter.
            return
        data = path.read_bytes()
        if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
            raise ValueError("invalid bytecode header")
        if int.from_bytes(data[4:8], "little") not in {0, 1, 3}:
            raise ValueError("invalid bytecode flags")
        stream = io.BytesIO(data[16:])
        code = marshal.load(stream)
        expected = compile(
            source.read_bytes(),
            str(source),
            "exec",
            dont_inherit=True,
            optimize=int(current[path] or "0"),
        )
        if not isinstance(code, CodeType) or not _same_code(code, expected) or stream.read(1):
            raise ValueError("bytecode does not match source")
    except (OSError, ValueError, EOFError, TypeError, SyntaxError) as exc:
        raise RuntimeError("runtime bytecode differs from verified source") from exc


def _same_code(actual: CodeType, expected: CodeType) -> bool:
    # Code equality permits relocated filenames, but omits stack size and qualified names.
    if (
        actual != expected
        or actual.co_stacksize != expected.co_stacksize
        or actual.co_qualname != expected.co_qualname
    ):
        return False
    return all(
        _same_code(left, right)
        for left, right in zip(actual.co_consts, expected.co_consts, strict=True)
        if isinstance(left, CodeType) and isinstance(right, CodeType)
    )


def _source_files(root: Path) -> dict[str, bytes]:
    if any(
        (root / name).is_symlink()
        for name in ("src", "ui", "ui/memory-app", "docs", "docs/third-party")
    ):
        raise RuntimeError("runtime provenance refuses symbolic links")
    if any(
        (root / name).exists() or (root / name).is_symlink() for name in ("setup.py", "setup.cfg")
    ):
        raise RuntimeError("runtime provenance refuses legacy build overrides")
    for path in (root / "src").iterdir():
        if path.name == ".DS_Store" and path.is_file() and not path.is_symlink():
            continue
        if path.name != PACKAGE and not (
            path.is_dir() and not path.is_symlink() and path.name == f"{PACKAGE}.egg-info"
        ):
            raise RuntimeError("runtime provenance refuses unexpected source modules")
        if path.name == f"{PACKAGE}.egg-info":
            verify_metadata_directory(path, EGG_INFO_FILES)
    result = {
        f"src/{PACKAGE}/{name}": data for name, data in _files(root / "src" / PACKAGE).items()
    }
    for directory in BUILD_DIRECTORIES:
        result.update(
            {f"{directory}/{name}": data for name, data in _files(root / directory).items()}
        )
    for name in BUILD_INPUTS:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("runtime provenance is missing a regular build input")
        result[name] = path.read_bytes()
    return result


def verify_metadata_directory(path: Path, allowed: frozenset[str]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise RuntimeError("build metadata must be a regular directory")
    if not path.exists():
        return
    directories = {
        parent.as_posix()
        for name in allowed
        for parent in PurePosixPath(name).parents
        if parent != PurePosixPath(".")
    }
    for item in path.rglob("*"):
        name = item.relative_to(path).as_posix()
        allowed_entry = name in directories if item.is_dir() else name in allowed and item.is_file()
        if item.is_symlink() or not allowed_entry:
            raise RuntimeError("build metadata contains an unverified file")


def _hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def _git(root: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("web export operations require verifiable runtime provenance") from exc


def _git_provenance(root: Path) -> BuildProvenance:
    if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root.resolve():
        raise RuntimeError("runtime provenance does not belong to this checkout")
    revision = _git(root, "rev-parse", "--verify", "HEAD")
    _validate_revision(revision)
    paths = (f"src/{PACKAGE}", *BUILD_DIRECTORIES, *BUILD_INPUTS)
    if _git(root, "status", "--porcelain=v1", "--untracked-files=no", "--", *paths):
        raise RuntimeError("runtime code differs from the committed code revision")
    files = _source_files(root)
    entries = _git(root, "ls-tree", "-rz", "HEAD", "--", *paths).split("\0")
    tracked: set[str] = set()
    for entry in filter(None, entries):
        metadata, name = entry.split("\t", 1)
        mode, kind, digest = metadata.split()
        if mode not in {"100644", "100755"} or kind != "blob" or name not in files:
            raise RuntimeError("runtime files differ from the committed inventory")
        data = files[name]
        blob = f"blob {len(data)}\0".encode() + data
        actual = hashlib.new("sha1" if len(revision) == 40 else "sha256", blob).hexdigest()
        if actual != digest:
            raise RuntimeError("runtime code differs from the committed code revision")
        tracked.add(name)
    if tracked != files.keys():
        raise RuntimeError("runtime has untracked or ignored build inputs")
    prefix = f"src/{PACKAGE}/"
    hashes = _hashes(files)
    return {
        "format_version": 1,
        "code_revision": revision,
        "package_files": {
            name.removeprefix(prefix): value
            for name, value in hashes.items()
            if name.startswith(prefix)
        },
        "build_inputs": {
            name: value for name, value in hashes.items() if not name.startswith(prefix)
        },
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate provenance key")
        result[key] = value
    return result


def _read_manifest(package: Path) -> BuildProvenance:
    path = package / MANIFEST
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError("invalid provenance file")
        raw: object = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
        if not isinstance(raw, dict):
            raise ValueError("invalid provenance object")
        value = cast(dict[str, object], raw)
        if set(value) != {
            "format_version",
            "code_revision",
            "package_files",
            "build_inputs",
        }:
            raise ValueError("invalid provenance fields")
        if type(value["format_version"]) is not int or value["format_version"] != 1:
            raise ValueError("unknown provenance format")
        if not isinstance(value["code_revision"], str):
            raise ValueError("invalid revision")
        _validate_revision(value["code_revision"])
        for field in ("package_files", "build_inputs"):
            inventory = value[field]
            if not isinstance(inventory, dict) or not inventory:
                raise ValueError("invalid provenance inventory")
            for name, digest in cast(dict[object, object], inventory).items():
                if (
                    not isinstance(name, str)
                    or not isinstance(digest, str)
                    or PurePosixPath(name).is_absolute()
                    or PurePosixPath(name).as_posix() != name
                    or ".." in PurePosixPath(name).parts
                    or "\\" in name
                    or name in {".", MANIFEST}
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                ):
                    raise ValueError("invalid provenance inventory entry")
        return cast(BuildProvenance, value)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("release build provenance is missing or malformed") from exc


def verify_package(package: Path, provenance: BuildProvenance) -> None:
    if _hashes(_files(package)) != provenance["package_files"]:
        raise RuntimeError("installed runtime differs from release build provenance")


def source_provenance(root: Path) -> BuildProvenance:
    # A broken or dirty Git checkout must never downgrade to a packaged stamp.
    if (root / ".git").exists() or (root / ".git").is_symlink():
        return _git_provenance(root)
    provenance = _read_manifest(root / "src" / PACKAGE)
    expected = dict(provenance["build_inputs"])
    expected.update(
        {f"src/{PACKAGE}/{name}": value for name, value in provenance["package_files"].items()}
    )
    if _hashes(_source_files(root)) != expected:
        raise RuntimeError("source distribution differs from release build provenance")
    return provenance


def runtime_code_revision() -> str:
    package = Path(__file__).resolve().parent
    if package.parent.name == "src":
        provenance = source_provenance(package.parent.parent)
    else:
        provenance = _read_manifest(package)
        verify_package(package, provenance)
    return provenance["code_revision"]


def require_runtime_code_revision(expected_revision: str) -> None:
    _validate_revision(expected_revision)
    if runtime_code_revision() != expected_revision:
        raise RuntimeError("code revision does not match the running runtime")


def write_manifest(package: Path, provenance: BuildProvenance) -> None:
    verify_package(package, provenance)
    with (package / MANIFEST).open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(provenance, sort_keys=True, indent=2) + "\n")


def prepare_container_context(output: Path) -> str:
    root = Path(__file__).resolve().parents[2]
    provenance = source_provenance(root)
    files = _source_files(root)
    expected = dict(provenance["build_inputs"])
    expected.update(
        {f"src/{PACKAGE}/{name}": value for name, value in provenance["package_files"].items()}
    )
    if _hashes(files) != expected:
        raise RuntimeError("build inputs changed while preparing container context")
    output.mkdir(mode=0o700)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    write_manifest(output / "src" / PACKAGE, provenance)
    return provenance["code_revision"]


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(runtime_code_revision())
    elif len(sys.argv) == 2:
        require_runtime_code_revision(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] == "--prepare-container":
        print(prepare_container_context(Path(sys.argv[2])))
    else:
        raise SystemExit(
            "usage: python -m cross_assistant_memory.runtime_provenance [expected-revision]"
        )
