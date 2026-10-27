"""Read-only preflight for the selected Python; no package or account access."""

import json
import os
import sqlite3
import sys
from contextlib import closing


def sqlite_has_wal_fix(version: tuple[int, ...]) -> bool:
    return (
        version >= (3, 51, 3)
        or (3, 50, 7) <= version < (3, 51, 0)
        or (3, 44, 6) <= version < (3, 45, 0)
    )


def inspect_runtime() -> dict[str, object]:
    with closing(sqlite3.connect(":memory:")) as connection:
        try:
            connection.execute("CREATE VIRTUAL TABLE probe USING fts5(text)")
            fts5 = True
        except sqlite3.OperationalError:
            fts5 = False
    checks = {
        "python_3_11_or_newer": sys.version_info >= (3, 11),
        "posix": os.name == "posix",
        "sqlite_fts5": fts5,
        "sqlite_known_wal_fix": sqlite_has_wal_fix(sqlite3.sqlite_version_info),
    }
    return {
        "status": "passed" if all(checks.values()) else "action_required",
        "python": ".".join(map(str, sys.version_info[:3])),
        "sqlite": sqlite3.sqlite_version,
        "checks": checks,
        "scope": "runtime prerequisites only; no data, credentials or services inspected",
        "next": (
            "Choose a Python linked to SQLite 3.51.3+, 3.50.7+ (3.50 branch), or "
            "3.44.6+ (3.44 branch). Older vendor versions need independent patch confirmation. "
            "See docs/deployment/runtime-notes.md."
            if not checks["sqlite_known_wal_fix"]
            else "Continue with the setup guide; this is not installation or security acceptance."
        ),
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("usage: PYTHON_BIN=python3 script/doctor", file=sys.stderr)
        return 2
    report = inspect_runtime()
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
