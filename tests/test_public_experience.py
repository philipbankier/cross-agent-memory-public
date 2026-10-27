from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from starlette.testclient import TestClient

from cross_assistant_memory.control_panel import create_control_panel_app


def load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).parents[1] / "script" / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("version", "accepted"),
    [
        ((3, 51, 2), False),
        ((3, 51, 3), True),
        ((3, 53, 1), True),
        ((3, 50, 6), False),
        ((3, 50, 7), True),
        ((3, 44, 6), True),
        ((3, 45, 3), False),
        ((3, 46, 1), False),
    ],
)
def test_runtime_preflight_wal_versions(version: tuple[int, ...], accepted: bool) -> None:
    assert load_script("doctor").sqlite_has_wal_fix(version) is accepted


def test_demo_uses_real_panel_without_owner_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "do-not-touch"
    monkeypatch.setenv("CAM_HOME", str(live))
    with load_script("demo").demo_node() as (settings, token):
        root = settings.data_root.parent
        assert root.stat().st_mode & 0o777 == 0o700
        app = create_control_panel_app(settings, host="127.0.0.1", port=58000)
        with TestClient(app, base_url="http://127.0.0.1:58000") as client:
            assert client.get("/").status_code == 200
            assert client.get("/api/overview").status_code == 401
            headers = {"Authorization": f"Bearer {token}"}
            assert client.get("/api/overview", headers=headers).status_code == 200
            navigation = {
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            }
            assert client.get("/", headers=navigation).status_code == 200
            assert client.get("/api/overview", headers={**headers, **navigation}).status_code == 403
            assert client.post("/", headers=navigation).status_code == 403
            assert (
                client.get("/", headers={**navigation, "Sec-Fetch-Dest": "iframe"}).status_code
                == 403
            )
            assert (
                client.get("/", headers={**navigation, "Origin": "https://example.org"}).status_code
                == 403
            )
            for override, status in [
                ({"Origin": "https://example.org"}, 403),
                ({"Host": "example.org"}, 421),
                ({"Sec-Fetch-Site": "cross-site"}, 403),
            ]:
                assert (
                    client.get("/api/overview", headers={**headers, **override}).status_code
                    == status
                )
            response = client.post(
                "/api/search",
                headers=headers,
                json={
                    "query": "Atlas",
                    "mode": "find_evidence",
                    "scopes": ["user_global"],
                    "limit": 10,
                },
            )
            assert response.status_code == 200
            assert "Atlas" in response.text
            assert response.headers["cache-control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert not root.exists()
    assert not live.exists()
