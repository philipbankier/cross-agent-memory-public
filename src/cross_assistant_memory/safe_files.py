from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path

_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 1


def open_regular_file_no_symlinks(path: Path, label: str) -> tuple[int, Path]:
    normalized = Path(os.path.abspath(path.expanduser()))
    parts = normalized.parts
    if not normalized.is_absolute() or len(parts) < 2:
        raise ValueError(f"{label} must be an absolute regular file without symlinks")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_descriptor: int | None = None
    try:
        directory_descriptor = os.open(parts[0], directory_flags)
        for component in parts[1:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise ValueError(f"{label} must be a regular file without symlink components") from error
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"{label} must be a regular file without symlink components")
    return descriptor, normalized


def secure_path_stat(path: Path, label: str) -> os.stat_result:
    descriptor, _normalized = open_regular_file_no_symlinks(path, label)
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def remove_owned_directory_at(parent: int, name: str, expected: os.stat_result) -> bool:
    """Remove through the owned inode, never through a subsequently substituted name."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
            return False
        raise
    try:
        if not os.path.samestat(expected, os.fstat(descriptor)):
            return False
        for child in os.listdir(descriptor):
            details = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(details.st_mode):
                if not remove_owned_directory_at(descriptor, child, details):
                    return False
            else:
                os.unlink(child, dir_fd=descriptor)
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not os.path.samestat(expected, current):
            return False
        os.rmdir(name, dir_fd=parent)
        return True
    finally:
        os.close(descriptor)


def publish_directory_no_replace(
    source: Path,
    target: Path,
    *,
    required_mode: int,
    label: str,
    expected_identity: os.stat_result | None = None,
    expected_parent_identity: os.stat_result | None = None,
) -> None:
    normalized_source = Path(os.path.abspath(source.expanduser()))
    normalized_target = Path(os.path.abspath(target.expanduser()))
    if normalized_source.parent != normalized_target.parent:
        raise ValueError(f"{label} publication must stay within one parent directory")
    if normalized_source.name in {"", ".", ".."} or normalized_target.name in {"", ".", ".."}:
        raise ValueError(f"{label} publication path is invalid")

    parent_descriptor = open_directory_no_symlinks(normalized_source.parent, f"{label} parent")
    if expected_parent_identity is not None and not os.path.samestat(
        expected_parent_identity, os.fstat(parent_descriptor)
    ):
        os.close(parent_descriptor)
        raise RuntimeError(f"{label} parent identity changed")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        source_descriptor = os.open(
            normalized_source.name,
            directory_flags,
            dir_fd=parent_descriptor,
        )
    except BaseException:
        os.close(parent_descriptor)
        raise
    try:
        source_identity = os.fstat(source_descriptor)
        if (
            not stat.S_ISDIR(source_identity.st_mode)
            or stat.S_IMODE(source_identity.st_mode) != required_mode
            or source_identity.st_uid != os.geteuid()
            or (
                expected_identity is not None
                and not os.path.samestat(expected_identity, source_identity)
            )
        ):
            raise RuntimeError(f"{label} staging root identity or permissions changed")
        original_mode = stat.S_IMODE(source_identity.st_mode)
        if original_mode != 0o700:
            os.fchmod(source_descriptor, 0o700)
        try:
            result = _rename_directory_no_replace(
                parent_descriptor,
                normalized_source.name,
                normalized_target.name,
                label,
            )
        finally:
            if original_mode != 0o700:
                os.fchmod(source_descriptor, original_mode)
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(f"{label} output already exists: {normalized_target}")
            raise OSError(error_number, os.strerror(error_number), normalized_target)
        published = os.stat(
            normalized_target.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            published.st_dev != source_identity.st_dev
            or published.st_ino != source_identity.st_ino
            or not stat.S_ISDIR(published.st_mode)
            or stat.S_IMODE(published.st_mode) != required_mode
        ):
            raise RuntimeError(f"published {label} identity or permissions changed")
        os.fsync(parent_descriptor)
        if expected_parent_identity is not None:
            current = open_directory_no_symlinks(normalized_source.parent, f"{label} parent")
            try:
                if not os.path.samestat(expected_parent_identity, os.fstat(current)):
                    raise RuntimeError(f"{label} parent identity changed after publication")
            finally:
                os.close(current)
    finally:
        os.close(source_descriptor)
        os.close(parent_descriptor)


def publish_file_no_replace(
    source: Path,
    target: Path,
    *,
    required_mode: int,
    label: str,
    retain_on_failure: bool = False,
) -> None:
    normalized_source = Path(os.path.abspath(source.expanduser()))
    normalized_target = Path(os.path.abspath(target.expanduser()))
    if normalized_source.parent != normalized_target.parent:
        raise ValueError(f"{label} publication must stay within one parent directory")
    if normalized_source.name in {"", ".", ".."} or normalized_target.name in {"", ".", ".."}:
        raise ValueError(f"{label} publication path is invalid")

    parent_descriptor = open_directory_no_symlinks(normalized_source.parent, f"{label} parent")
    try:
        publish_file_no_replace_at(
            parent_descriptor,
            normalized_source.name,
            normalized_target.name,
            required_mode=required_mode,
            label=label,
            retain_on_failure=retain_on_failure,
        )
    finally:
        os.close(parent_descriptor)


def publish_file_no_replace_at(
    parent_descriptor: int,
    source_name: str,
    target_name: str,
    *,
    required_mode: int,
    label: str,
    expected_source_descriptor: int | None = None,
    retain_on_failure: bool = False,
) -> None:
    if (
        Path(source_name).name != source_name
        or Path(target_name).name != target_name
        or source_name in {"", ".", ".."}
        or target_name in {"", ".", ".."}
    ):
        raise ValueError(f"{label} publication name is invalid")
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    source_descriptor = os.open(
        source_name,
        file_flags,
        dir_fd=parent_descriptor,
    )
    try:
        source_identity = os.fstat(source_descriptor)
        expected_source_identity = (
            os.fstat(expected_source_descriptor)
            if expected_source_descriptor is not None
            else source_identity
        )
        if (
            not stat.S_ISREG(source_identity.st_mode)
            or stat.S_IMODE(source_identity.st_mode) != required_mode
            or source_identity.st_uid != os.geteuid()
            or source_identity.st_nlink != 1
            or source_identity.st_dev != expected_source_identity.st_dev
            or source_identity.st_ino != expected_source_identity.st_ino
        ):
            raise RuntimeError(f"{label} staging file identity or permissions changed")
        renamed = False
        try:
            result = _rename_directory_no_replace(
                parent_descriptor,
                source_name,
                target_name,
                label,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                if error_number == errno.EEXIST:
                    raise FileExistsError(f"{label} output already exists: {target_name}")
                raise OSError(error_number, os.strerror(error_number), target_name)
            renamed = True
            published = os.stat(
                target_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                published.st_dev != source_identity.st_dev
                or published.st_ino != source_identity.st_ino
                or published.st_size != source_identity.st_size
                or published.st_mtime_ns != source_identity.st_mtime_ns
                or not stat.S_ISREG(published.st_mode)
                or stat.S_IMODE(published.st_mode) != required_mode
                or published.st_nlink != 1
            ):
                raise RuntimeError(f"published {label} identity or permissions changed")
            os.fsync(parent_descriptor)
        except BaseException:
            # Journaled maintenance moves must preserve originals after a failed flush.
            if renamed and not retain_on_failure:
                with suppress(FileNotFoundError):
                    current = os.stat(
                        target_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if (
                        current.st_dev == source_identity.st_dev
                        and current.st_ino == source_identity.st_ino
                    ):
                        os.unlink(target_name, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
            raise
    finally:
        os.close(source_descriptor)


def _rename_directory_no_replace(
    parent_descriptor: int,
    source_name: str,
    target_name: str,
    label: str,
) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    target_bytes = os.fsencode(target_name)
    if sys.platform == "darwin":
        rename = libc.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        return rename(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            _RENAME_EXCL,
        )
    if sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise RuntimeError(f"atomic no-replace {label} publication is unavailable")
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        return rename(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            target_bytes,
            _RENAME_NOREPLACE,
        )
    raise RuntimeError(f"atomic no-replace {label} publication is unavailable")


def open_directory_no_symlinks(path: Path, label: str) -> int:
    normalized = Path(os.path.abspath(path.expanduser()))
    parts = normalized.parts
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(parts[0], flags)
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(f"{label} must be an existing directory without symlinks") from error
    return descriptor
