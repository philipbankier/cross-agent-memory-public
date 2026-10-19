from __future__ import annotations

import json
from pathlib import Path

import pytest

import cross_assistant_memory.uploads as uploads_module
from cross_assistant_memory.admission import (
    classify_attachment,
    classify_record,
    is_admission_exclusion_reason,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.ingest import parse_file
from cross_assistant_memory.models import (
    AdmissionDecision,
    CollectorProvenance,
    Privacy,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.storage import DEFAULT_MAX_RECORD_BYTES, Ledger
from cross_assistant_memory.uploads import (
    build_upload_batch,
    parse_upload_batch,
    reclassify_upload_batch,
)

# Synthetic format regressions, never provider credentials.
COVALENT_KEYS = ("ckey_" + "a" * 27, "cqt_wF" + "b" * 26, "cqt_rQ" + "3" * 26)
HEX_KEY = "sk_" + "0123456789abcdef" * 3
KEYS = (
    *((key, "secret:covalent_key") for key in COVALENT_KEYS),
    (HEX_KEY, "secret:hex_service_key"),
)


@pytest.mark.parametrize("key,reason", KEYS)
@pytest.mark.parametrize("source_system", list(SourceSystem))
@pytest.mark.parametrize("location", ["normalized", "raw", "json-value", "json-key"])
def test_credentials_are_excluded_across_sources_and_representations(
    key: str, reason: str, source_system: SourceSystem, location: str
) -> None:
    text = "Ordinary visible message."
    raw = text.encode()
    if location == "normalized":
        text = f'Synthetic API_KEY = "{key}"'
    elif location == "raw":
        raw = f'Synthetic API_KEY = "{key}"'.encode()
    else:
        value = {"token": key} if location == "json-value" else {key: "synthetic"}
        raw = json.dumps(value).replace("c", r"\u0063").replace("sk_", r"\u0073k_").encode()
        assert key.encode() not in raw
    result = classify_record(source_system, text, raw, max_record_bytes=DEFAULT_MAX_RECORD_BYTES)
    assert not result.accepted
    assert result.privacy is Privacy.NO_MEMORY
    assert result.reason == reason
    assert is_admission_exclusion_reason(result.reason)
    assert key not in repr(result)


@pytest.mark.parametrize("key", COVALENT_KEYS)
@pytest.mark.parametrize("location", ["normalized", "raw", "json-value", "json-key"])
def test_escaped_covalent_credentials_are_excluded(key: str, location: str) -> None:
    token = key.replace("_", r"\_")
    text = "Ordinary visible message."
    raw = text.encode()
    if location == "normalized":
        text = f'Synthetic API_KEY = "{token}"'
    elif location == "raw":
        raw = f'Synthetic API_KEY = "{token}"'.encode()
    else:
        value = {"token": token} if location == "json-value" else {token: "synthetic"}
        raw = json.dumps(value).replace("c", r"\u0063").encode()
    result = classify_record(
        SourceSystem.CLAUDE_WEB, text, raw, max_record_bytes=DEFAULT_MAX_RECORD_BYTES
    )
    assert not result.accepted
    assert result.reason == "secret:covalent_key"


@pytest.mark.parametrize("key", COVALENT_KEYS)
@pytest.mark.parametrize("emphasis", ["_", "__"])
@pytest.mark.parametrize("markdown_escape", [False, True])
def test_balanced_covalent_emphasis_is_excluded(
    key: str, emphasis: str, markdown_escape: bool
) -> None:
    token = key.replace("_", r"\_") if markdown_escape else key
    text = f"Synthetic {emphasis}{token}{emphasis}."
    result = classify_record(
        SourceSystem.CLAUDE_WEB,
        text,
        json.dumps({"text": text}).encode(),
        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
    )
    assert not result.accepted
    assert result.reason == "secret:covalent_key"


@pytest.mark.parametrize(
    "text",
    [
        "ckey_example",
        "ckey_" + "a" * 26,
        "ckey_" + "a" * 28,
        "ckey_" + "g" * 27,
        "cqt_wF" + "b" * 25,
        "cqt_wF" + "b" * 27,
        "cqt_wF" + "a" * 26,
        "cqt_wf" + "b" * 26,
        "cqt_xx" + "b" * 26,
        "prefix" + COVALENT_KEYS[0],
        COVALENT_KEYS[0] + "suffix",
        COVALENT_KEYS[0] + "_suffix",
        "_" + COVALENT_KEYS[0] + "__",
        "__" + COVALENT_KEYS[0] + "_",
        "prefix_" + COVALENT_KEYS[0] + "_",
        "__" + COVALENT_KEYS[0] + "__suffix",
        "sk_example",
        "sk_" + "a" * 47,
        "sk_" + "a" * 49,
        "sk_" + "g" * 48,
        "prefix" + HEX_KEY,
        HEX_KEY + "suffix",
        HEX_KEY + "_suffix",
        "API_KEY = 'replace with your key'",
    ],
)
def test_rule_does_not_guess_other_formats(text: str) -> None:
    assert classify_record(
        SourceSystem.CLAUDE_WEB, text, text.encode(), max_record_bytes=DEFAULT_MAX_RECORD_BYTES
    ).accepted


@pytest.mark.parametrize("text", ["CKEY_" + "a" * 27, "ckey_" + "A" * 27, "CQT_wF" + "b" * 26])
@pytest.mark.parametrize("location", ["normalized", "raw", "json-value", "json-key"])
def test_covalent_case_restrictions_are_consistent(text: str, location: str) -> None:
    content = text if location == "normalized" else "Ordinary evidence."
    raw = content.encode()
    if location == "raw":
        raw = text.encode()
    elif location == "json-value":
        raw = json.dumps({"token": text}).encode()
    elif location == "json-key":
        raw = json.dumps({text: "synthetic"}).encode()
    assert classify_record(
        SourceSystem.CLAUDE_WEB, content, raw, max_record_bytes=DEFAULT_MAX_RECORD_BYTES
    ).accepted


@pytest.mark.parametrize("key,reason", KEYS)
@pytest.mark.parametrize(
    "media_type", ["application/json", "text/csv", "text/markdown", "text/plain"]
)
def test_text_attachments_are_excluded(key: str, reason: str, media_type: str) -> None:
    raw = json.dumps({"synthetic_token": key}).encode()
    result = classify_attachment(
        SourceSystem.CLAUDE_WEB, media_type, raw, max_record_bytes=DEFAULT_MAX_RECORD_BYTES
    )
    assert not result.accepted
    assert result.reason == reason


def credential_source(path: Path, key: str) -> Path:
    path.write_text(
        "".join(
            json.dumps(
                {
                    "type": "user",
                    "sessionId": "synthetic-session",
                    "uuid": identifier,
                    "message": {"role": "user", "content": text},
                }
            )
            + "\n"
            for identifier, text in (
                ("synthetic-private", f'Synthetic API_KEY = "{key}"'),
                ("synthetic-public", "Keep ordinary evidence."),
            )
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("key,reason", KEYS)
def test_ingest_excludes_credential_and_preserves_replay(
    tmp_path: Path, key: str, reason: str
) -> None:
    source = credential_source(tmp_path / "claude.jsonl", key)
    settings = Settings(tmp_path / "ledger")
    ledger = Ledger(settings)
    parsed = parse_file(source, SourceSystem.CLAUDE_CODE)
    result = ledger.ingest(
        parsed, source_account="synthetic", scope=Scope.USER_GLOBAL, project_id=None
    )
    assert result.inserted_events == 1
    assert result.quarantine_reasons == {reason: 1}
    assert ledger.search("ordinary evidence")
    assert not ledger.search("Synthetic API_KEY")
    objects = list(settings.object_root.glob("*/*"))
    assert len(objects) == 1
    assert key.encode() not in objects[0].read_bytes()
    generation = ledger.generation_digest()
    repeated = ledger.ingest(
        parsed, source_account="synthetic", scope=Scope.USER_GLOBAL, project_id=None
    )
    assert repeated.inserted_events == 0
    assert ledger.generation_digest() == generation
    assert key.encode() not in settings.database_path.read_bytes()


@pytest.mark.parametrize("key,reason", KEYS)
def test_node_refuses_old_upload_and_reclassification_preserves_neighbor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str, reason: str
) -> None:
    parsed = parse_file(credential_source(tmp_path / "claude.jsonl", key), SourceSystem.CLAUDE_CODE)
    provenance = CollectorProvenance(
        source_client="claude-code",
        source_client_version="test-client-1.0.0",
        capture_capability="native-jsonl-history",
        adapter_name="cross-memory-native-collector",
        adapter_version="0.1.0",
        schema_fingerprint=parsed.schema_fingerprint,
    )

    def legacy_admission(*_args: object, **_kwargs: object) -> AdmissionDecision:
        return AdmissionDecision(True, Privacy.INCLUDED, "included")

    with monkeypatch.context() as patch:
        patch.setattr(uploads_module, "classify_record", legacy_admission)
        old_body = build_upload_batch(
            parsed, source_account_id="source_account:synthetic", provenance=provenance
        )
        assert len(parse_upload_batch(old_body).parsed.records) == 2
    with pytest.raises(ValueError, match=f"failed node admission: {reason}") as error:
        parse_upload_batch(old_body)
    assert key not in str(error.value)
    new_body = reclassify_upload_batch(old_body)
    assert key.encode() not in new_body
    batch = parse_upload_batch(new_body)
    assert len(batch.parsed.records) == 1
    assert batch.parsed.records[0].content_text == "Keep ordinary evidence."
    assert [receipt.reason for receipt in batch.exclusion_receipts] == [reason]
    assert reclassify_upload_batch(new_body) == new_body
