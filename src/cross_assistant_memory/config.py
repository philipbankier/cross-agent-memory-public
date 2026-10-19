from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_DIR_NAME = "cross-assistant-memory"


def default_data_root() -> Path:
    configured = os.environ.get("CAM_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "Library" / "Application Support" / APP_DIR_NAME


@dataclass(frozen=True)
class Settings:
    data_root: Path

    @classmethod
    def from_environment(cls, data_root: Path | None = None) -> Settings:
        return cls(data_root=(data_root or default_data_root()).expanduser())

    @property
    def database_path(self) -> Path:
        return self.data_root / "ledger.sqlite3"

    @property
    def object_root(self) -> Path:
        return self.data_root / "objects" / "sha256"

    @property
    def run_root(self) -> Path:
        return self.data_root / "runs"

    def ensure_directories(self) -> None:
        for path in (
            self.data_root,
            self.data_root / "objects",
            self.object_root,
            self.run_root,
        ):
            _ensure_private_directory(path)


def _ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"private data directory must not be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
