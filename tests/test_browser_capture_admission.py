from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from starlette.testclient import TestClient

from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CreateDeviceEnrollmentRequest,
    MemoryApplication,
    RegisterSourceAccountRequest,
)
from cross_assistant_memory.browser_capture_upload import browser_observation_uploads
from cross_assistant_memory.browser_observation import (
    BrowserMessage,
    BrowserObservation,
    BrowserProvider,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.mcp_server import create_mcp_server
from cross_assistant_memory.models import Capability, ClientKind, Scope, SourceSystem, UploadReceipt
from cross_assistant_memory.storage import Ledger
from cross_assistant_memory.uploads import validate_upload_receipt


def _enrolled_collector(
    root: Path, label: str
) -> tuple[MemoryApplication, ApplicationPrincipal, dict[str, str]]:
    application = MemoryApplication(Ledger(Settings(root)))
    now = datetime.now(UTC)
    enrollment = application.create_device_enrollment(
        ApplicationPrincipal.local_admin("local:test"),
        CreateDeviceEnrollmentRequest(
            label=label,
            platform="macOS",
            expires_at=now + timedelta(minutes=10),
            credential_expires_at=now + timedelta(days=1),
        ),
    )
    redeemed = application.redeem_device_enrollment(cast(str, enrollment["code"]))
    principal = ApplicationPrincipal(
        principal_id=redeemed["client"]["client_id"],
        kind=ClientKind.COLLECTOR,
        capabilities=frozenset({Capability.SOURCE_UPLOAD, Capability.MEMORY_STATUS}),
        device_id=redeemed["device"]["device_id"],
    )
    return (
        application,
        principal,
        {
            "device_id": redeemed["device"]["device_id"],
            "token": redeemed["credential"]["token"],
        },
    )


def _register_account(
    application: MemoryApplication,
    device_id: str,
    *,
    source_system: SourceSystem,
    label: str = "browser-test",
) -> dict[str, str]:
    result = application.register_source_account(
        ApplicationPrincipal.local_admin("local:test"),
        RegisterSourceAccountRequest(
            device_id=device_id,
            source_system=source_system,
            account_label=label,
            scope=Scope.USER_GLOBAL,
            project_id=None,
        ),
    )
    return {"source_account_id": result["source_account_id"]}


def _observation(account: str, provider: BrowserProvider = "chatgpt_web") -> BrowserObservation:
    conversation = "00000000-0000-4000-8000-000000000001"
    return BrowserObservation(
        format_version=1,
        provider=provider,
        account_binding=account,
        conversation_id=conversation,
        canonical_url={
            "chatgpt_web": "https://chatgpt.com/c/",
            "claude_web": "https://claude.ai/chat/",
            "grok_web": "https://grok.com/c/",
        }[provider]
        + conversation,
        observed_at="2026-10-20T12:00:00Z",
        capture_kind="rendered_browser_observation",
        completeness="visible_messages_only",
        messages=(
            BrowserMessage(
                "0" if provider == "claude_web" else "00000000-0000-4000-8000-000000000002",
                "rendered_position" if provider == "claude_web" else "provider_message_id",
                "user",
                "We discussed the Atlas handoff in this conversation.",
            ),
        ),
    )


@pytest.mark.parametrize("provider", ["chatgpt_web", "claude_web", "grok_web"])
def test_browser_capture_admits_and_replays_without_fake_export_or_provider_time(
    tmp_path: Path, provider: BrowserProvider
) -> None:
    settings = Settings(tmp_path / "data")
    application, principal, enrollment = _enrolled_collector(settings.data_root, "Browser Mac")
    account = _register_account(
        application, enrollment["device_id"], source_system=SourceSystem(provider)
    )
    observation = _observation(account["source_account_id"], provider)
    result = application.upload_browser_observation(principal, observation.canonical_bytes())
    batch = browser_observation_uploads(observation)[0]
    validate_upload_receipt(batch, UploadReceipt.from_dict(result), status_code=201)
    repeated = application.upload_browser_observation(
        principal,
        replace(observation, observed_at="2026-10-21T12:00:00Z").canonical_bytes(),
    )
    validate_upload_receipt(batch, UploadReceipt.from_dict(repeated), status_code=200)
    assert result["event_count"] == 1
    assert repeated["status"] == "already_applied"
    with sqlite3.connect(settings.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert connection.execute("SELECT occurred_at FROM events").fetchone()[0] is None
        assert connection.execute("SELECT COUNT(*) FROM web_export_batches").fetchone()[0] == 0
        assert (
            connection.execute("SELECT capture_capability FROM source_capture_metadata").fetchone()[
                0
            ]
            == "rendered_visible_messages_only"
        )
    assert observation.messages[0].text not in json.dumps(result)
    ledger = Ledger(settings)
    matches = ledger.search("Atlas handoff")
    assert len(matches) == 1
    evidence = ledger.get_evidence(matches[0].event_id)
    assert evidence["source_account_id"] == observation.account_binding
    assert evidence["content_text"] == observation.messages[0].text
    assert evidence["web_export"] is None
    assert evidence["browser_observation"] == {
        "observed_at": observation.observed_at,
        "timestamp_semantics": "capture_time_not_provider_message_time",
        "completeness": "visible_messages_only",
        "evidence_semantics": "captured_rendered_text_not_official_export",
    }
    health = next(item for item in ledger.source_health() if item["source_system"] == provider)
    assert health["browser_capture"] == {
        "admitted_observations": 1,
        "latest_observed_at": observation.observed_at,
        "coverage": "opened_rendered_text_only",
        "provider_message_times": "unknown",
    }


def test_two_accounts_with_same_conversation_and_message_ids_stay_separate(tmp_path: Path) -> None:
    application, principal, enrollment = _enrolled_collector(tmp_path / "data", "Browser Mac")
    accounts = [
        _register_account(
            application,
            enrollment["device_id"],
            source_system=SourceSystem.CHATGPT_WEB,
            label=label,
        )["source_account_id"]
        for label in ("first-account", "second-account")
    ]
    for account in accounts:
        application.upload_browser_observation(principal, _observation(account).canonical_bytes())
    ledger = Ledger(Settings(tmp_path / "data"))
    matches = ledger.search("Atlas handoff")
    assert len(matches) == 2
    assert {ledger.get_evidence(match.event_id)["source_account_id"] for match in matches} == set(
        accounts
    )


def test_browser_upload_requires_collector_capability(tmp_path: Path) -> None:
    application, collector, enrollment = _enrolled_collector(tmp_path / "data", "Browser Mac")
    account = _register_account(
        application, enrollment["device_id"], source_system=SourceSystem.CHATGPT_WEB
    )
    reader = replace(collector, capabilities=frozenset({Capability.MEMORY_STATUS}))
    with pytest.raises(PermissionError):
        application.upload_browser_observation(
            reader, _observation(account["source_account_id"]).canonical_bytes()
        )


def test_browser_capture_other_device_and_other_provider_refused(tmp_path: Path) -> None:
    application, principal, enrollment = _enrolled_collector(tmp_path / "data", "Browser Mac")
    _other_application, other, _other_enrollment = _enrolled_collector(
        tmp_path / "data", "Other Mac"
    )
    account = _register_account(
        application, enrollment["device_id"], source_system=SourceSystem.CHATGPT_WEB
    )
    observation = _observation(account["source_account_id"])
    with pytest.raises(PermissionError):
        application.upload_browser_observation(other, observation.canonical_bytes())
    changed_provider = replace(
        observation,
        provider="grok_web",
        canonical_url="https://grok.com/c/" + observation.conversation_id,
    )
    with pytest.raises(PermissionError):
        application.upload_browser_observation(principal, changed_provider.canonical_bytes())


def test_browser_endpoint_auth_and_native_endpoint_remain_separate(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "data")
    application, _principal, enrollment = _enrolled_collector(settings.data_root, "Browser Mac")
    account = _register_account(
        application, enrollment["device_id"], source_system=SourceSystem.CHATGPT_WEB
    )
    body = _observation(account["source_account_id"]).canonical_bytes()
    server = create_mcp_server(
        settings, transport="streamable-http", http_auth_url="http://127.0.0.1:8765/mcp"
    )
    app = server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True
    )
    headers = {"authorization": f"Bearer {enrollment['token']}"}
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert client.post("/upload/browser-observations", content=b"bad").status_code == 401
        assert client.post("/upload/batches", content=body, headers=headers).status_code == 400
        accepted = client.post("/upload/browser-observations", content=body, headers=headers)
        assert accepted.status_code == 201
        assert accepted.headers["cache-control"] == "no-store"
        assert (
            client.post("/upload/browser-observations", content=body, headers=headers).status_code
            == 200
        )
