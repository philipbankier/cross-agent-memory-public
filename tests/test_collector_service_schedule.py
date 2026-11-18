from __future__ import annotations

import configparser
import plistlib
from pathlib import Path

from cross_assistant_memory import collector_service as service


def test_launchd_defaults_to_hourly_without_changing_startup_behavior() -> None:
    arguments = ("/private/venv/bin/cross-memory", "collector-sync", "--quiet")
    files = service._launchd_service_file(  # pyright: ignore[reportPrivateUsage]
        Path("/private/home"), arguments
    )
    definition = plistlib.loads(files[0].content)
    assert service.COLLECTOR_SERVICE_SCHEDULE_SECONDS == 3600
    assert definition["StartInterval"] == 3600
    assert definition["RunAtLoad"] is True
    assert definition["ProgramArguments"] == list(arguments)
    assert definition["LowPriorityIO"] is True


def test_systemd_defaults_to_hourly_without_accumulating_missed_runs() -> None:
    files = service._systemd_service_files(  # pyright: ignore[reportPrivateUsage]
        Path("/private/home"), ("/private/venv/bin/cross-memory", "collector-sync", "--quiet")
    )
    definition = configparser.ConfigParser(interpolation=None)
    definition.read_string(files[1].content.decode())
    assert definition["Timer"]["OnUnitActiveSec"] == "3600s"
    assert definition["Timer"]["OnStartupSec"] == "1min"
    assert definition["Timer"]["Persistent"] == "false"
    assert definition["Timer"]["Unit"] == service.SYSTEMD_SERVICE_NAME
