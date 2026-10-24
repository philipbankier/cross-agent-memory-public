from __future__ import annotations

import concurrent.futures
import json
import socket
import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from cross_assistant_memory.browser_capture_host import CaptureHostConfig, handle_capture_request
from cross_assistant_memory.browser_capture_spool import (
    BrowserCaptureSpool,
    BrowserCaptureSpoolFull,
)
from cross_assistant_memory.browser_capture_transport import flush_browser_capture
from cross_assistant_memory.browser_capture_upload import browser_observation_uploads
from cross_assistant_memory.browser_observation import BrowserObservation, parse_browser_observation
from cross_assistant_memory.models import UploadReceipt
from cross_assistant_memory.tink_crypto import Keyset
from cross_assistant_memory.uploads import expected_upload_source_file_id

SENTINEL = "SYNTHETIC_RESPONSE_MUST_NOT_ESCAPE"
CREDENTIAL = "synthetic-localhost-only-credential"
ORIGIN = "chrome-extension://" + "a" * 32 + "/"
Responder = Callable[[BaseHTTPRequestHandler, bytes], None]


@dataclass(frozen=True)
class Queue:
    root: Path
    key: Path
    credential: Path
    spool: BrowserCaptureSpool


@pytest.fixture
def queue(tmp_path: Path) -> Queue:
    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    root = private / "spool"
    root.mkdir(mode=0o700)
    key = private / "fixture.key"
    key.write_bytes(Keyset.generate_aead().serialize_cleartext())
    key.chmod(0o400)
    credential = private / "fixture.credential"
    credential.write_text(CREDENTIAL, encoding="ascii")
    credential.chmod(0o400)
    return Queue(root, key, credential, BrowserCaptureSpool(root, key))


def _observation(account: str = "a", position: str = "0") -> BrowserObservation:
    conversation = "11111111-2222-4333-8444-555555555555"
    return parse_browser_observation(
        json.dumps(
            {
                "format_version": 1,
                "provider": "claude_web",
                "account_binding": "source_account:" + account * 64,
                "conversation_id": conversation,
                "canonical_url": "https://claude.ai/chat/" + conversation,
                "observed_at": "2026-10-20T12:00:00Z",
                "capture_kind": "rendered_browser_observation",
                "completeness": "visible_messages_only",
                "messages": [
                    {
                        "locator": position,
                        "locator_kind": "rendered_position",
                        "role": "user",
                        "text": "Synthetic transport fixture",
                    }
                ],
            }
        ).encode()
    )


def _files(queue: Queue) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in queue.root.glob("observation.*")}


def _receipt(body: bytes, status: int = 201) -> dict[str, object]:
    batch = browser_observation_uploads(parse_browser_observation(body))[0]
    return UploadReceipt(
        batch_id=batch.batch_id,
        status="applied" if status == 201 else "already_applied",
        source_file_id=expected_upload_source_file_id(batch),
        conversation_id=batch.parsed.conversation_id,
        event_count=1,
        quarantined_records=0,
        quarantine_reasons={},
        created_at="2026-10-20T12:01:00Z",
    ).as_dict()


def _respond(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@contextmanager
def _server(responder: Responder) -> Generator[tuple[str, list[bytes]]]:
    requests: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append(body)
            responder(self, body)

        def do_GET(self) -> None:
            requests.append(b"")
            _respond(self, 500, b"unexpected redirected GET")

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/upload/browser-observations", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _valid(handler: BaseHTTPRequestHandler, body: bytes) -> None:
    _respond(handler, 201, json.dumps(_receipt(body)).encode())


@pytest.mark.parametrize("status", [200, 201])
def test_success_removes_only_exact_receipted_items(queue: Queue, status: int) -> None:
    observations = [_observation(account) for account in ("a", "b", "c")]
    for observation in observations:
        queue.spool.put(observation)
    pending = queue.spool.pending(limit=10)
    before = _files(queue)

    def respond(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        assert handler.path == "/upload/browser-observations"
        assert handler.headers["Authorization"] == f"Bearer {CREDENTIAL}"
        assert handler.headers["Content-Type"] == "application/json"
        observation = parse_browser_observation(body)
        assert body == observation.canonical_bytes()
        _respond(handler, status, json.dumps(_receipt(body, status)).encode())

    with _server(respond) as (endpoint, requests):
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
            "status": "uploaded"
        }
        assert [parse_browser_observation(body).content_digest for body in requests] == list(
            pending[:2]
        )
        remaining_name = f"observation.{pending[2]}"
        assert _files(queue) == {remaining_name: before[remaining_name]}
        restarted = BrowserCaptureSpool(queue.root, queue.key)
        assert restarted.pending() == (pending[2],)
        assert flush_browser_capture(restarted, endpoint, queue.credential) == {
            "status": "uploaded"
        }
        assert _files(queue) == {}
        assert flush_browser_capture(restarted, endpoint, queue.credential) == {"status": "ready"}
        assert len(requests) == 3


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_http_failures_retain_ciphertext_without_response_leak(
    queue: Queue, status: int, capsys: pytest.CaptureFixture[str]
) -> None:
    queue.spool.put(_observation())
    before = _files(queue)
    with _server(lambda handler, _: _respond(handler, status, SENTINEL.encode())) as (
        endpoint,
        requests,
    ):
        result = flush_browser_capture(queue.spool, endpoint, queue.credential)
    assert result == {
        "status": "upload_not_authorized" if status in {401, 403} else "upload_pending"
    }
    assert len(requests) == 1
    assert _files(queue) == before
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert SENTINEL not in repr(result) and CREDENTIAL not in repr(result)


def test_offline_connection_retains_ciphertext(queue: Queue) -> None:
    queue.spool.put(_observation())
    before = _files(queue)
    # Reserve a loopback port without listening, so no unrelated service can receive the request.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        endpoint = f"http://127.0.0.1:{reserved.getsockname()[1]}/upload/browser-observations"
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
            "status": "upload_pending"
        }
    assert _files(queue) == before


def test_actual_socket_timeout_retains_ciphertext(queue: Queue) -> None:
    queue.spool.put(_observation())
    before = _files(queue)
    release = threading.Event()
    finished = threading.Event()

    def stall(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        try:
            release.wait(timeout=10)
        finally:
            finished.set()

    with _server(stall) as (endpoint, requests):
        try:
            assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
                "status": "upload_pending"
            }
        finally:
            release.set()
            assert finished.wait(timeout=2)
    assert len(requests) == 1
    assert _files(queue) == before


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_to_other_loopback_server_is_refused(queue: Queue, status: int) -> None:
    queue.spool.put(_observation())
    before = _files(queue)
    with _server(_valid) as (destination, redirected):

        def redirect(handler: BaseHTTPRequestHandler, body: bytes) -> None:
            handler.send_response(status)
            handler.send_header("Location", destination)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with _server(redirect) as (endpoint, requests):
            assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
                "status": "upload_pending"
            }
        assert len(requests) == 1
        assert redirected == []
    assert _files(queue) == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("batch_id", "batch:" + "f" * 64),
        ("source_file_id", "source_segment:" + "f" * 64),
        ("conversation_id", "another-conversation"),
        ("status", "already_applied"),
        ("event_count", 0),
        ("event_count", True),
        ("quarantined_records", 1),
        ("quarantine_reasons", {"unexpected": 1}),
        ("created_at", "not-a-date"),
        ("unexpected", SENTINEL),
    ],
)
def test_mismatched_receipt_retains_ciphertext(queue: Queue, field: str, value: object) -> None:
    queue.spool.put(_observation())
    before = _files(queue)

    def respond(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        receipt = _receipt(body)
        receipt[field] = value
        _respond(handler, 201, json.dumps(receipt).encode())

    with _server(respond) as (endpoint, _):
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
            "status": "invalid_receipt"
        }
    assert _files(queue) == before


@pytest.mark.parametrize("body", [b"{", b"[]", b"null", b"{}", b"\xff", b"x" * 16385])
def test_malformed_receipt_retains_ciphertext(queue: Queue, body: bytes) -> None:
    queue.spool.put(_observation())
    before = _files(queue)
    with _server(lambda handler, _: _respond(handler, 201, body)) as (endpoint, _):
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
            "status": "invalid_receipt"
        }
    assert _files(queue) == before


@pytest.mark.parametrize("nested", [False, True])
def test_duplicate_key_receipt_must_not_acknowledge(queue: Queue, nested: bool) -> None:
    queue.spool.put(_observation())
    before = _files(queue)

    def respond(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        receipt = _receipt(body)
        if nested:
            receipt["event_count"] = 0
            receipt["quarantined_records"] = 1
            receipt["quarantine_reasons"] = {"no_memory_tombstone": 1}
            raw = json.dumps(receipt).replace(
                '"no_memory_tombstone": 1',
                '"no_memory_tombstone": 99, "no_memory_tombstone": 1',
            )
        else:
            raw = '{"batch_id":"batch:' + "f" * 64 + '",' + json.dumps(receipt)[1:]
        _respond(handler, 201, raw.encode())

    with _server(respond) as (endpoint, _):
        result = flush_browser_capture(queue.spool, endpoint, queue.credential)
    assert (result, _files(queue)) == ({"status": "invalid_receipt"}, before)


@pytest.mark.parametrize("through_host", [False, True])
def test_bad_http_status_is_sanitized_and_retained(
    queue: Queue, through_host: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    queue.spool.put(_observation())
    before = _files(queue)

    def bad_status(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        handler.wfile.write(SENTINEL.encode() + b"\r\n\r\n")

    with _server(bad_status) as (endpoint, _):
        if through_host:
            config = CaptureHostConfig(
                extension_origin=ORIGIN,
                spool_root=queue.root,
                key_file=queue.key,
                bindings={},
                upload_endpoint=endpoint,
                credential_file=queue.credential,
            )
            result = handle_capture_request(b'{"operation":"flush"}', config, ORIGIN)
            assert result in ({"status": "capture_failed"}, {"status": "upload_pending"})
        else:
            result = flush_browser_capture(queue.spool, endpoint, queue.credential)
            assert result == {"status": "upload_pending"}
    assert _files(queue) == before
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert SENTINEL not in repr(result)


@pytest.mark.parametrize("chunked", [False, True])
def test_truncated_response_must_not_acknowledge(queue: Queue, chunked: bool) -> None:
    queue.spool.put(_observation())
    before = _files(queue)

    def truncated(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        raw = json.dumps(_receipt(body)).encode()
        handler.send_response(201)
        if chunked:
            handler.send_header("Transfer-Encoding", "chunked")
            handler.end_headers()
            # A complete JSON value is not a completed HTTP response.
            handler.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n")
        else:
            handler.send_header("Content-Length", str(len(raw) + 20))
            handler.end_headers()
            handler.wfile.write(raw)
        handler.close_connection = True

    with _server(truncated) as (endpoint, _):
        result = flush_browser_capture(queue.spool, endpoint, queue.credential)
    assert _files(queue) == before
    assert result in ({"status": "upload_pending"}, {"status": "invalid_receipt"})


def test_partial_flush_removes_success_only_and_stops_at_failure(queue: Queue) -> None:
    for account in ("a", "b", "c"):
        queue.spool.put(_observation(account))
    pending = queue.spool.pending(limit=10)
    before = _files(queue)
    count = 0

    def respond(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        nonlocal count
        count += 1
        if count == 1:
            _valid(handler, body)
        else:
            _respond(handler, 201, b"{}")

    with _server(respond) as (endpoint, requests):
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
            "status": "invalid_receipt"
        }
    assert len(requests) == 2
    assert _files(queue) == {
        f"observation.{digest}": before[f"observation.{digest}"] for digest in pending[1:]
    }
    assert BrowserCaptureSpool(queue.root, queue.key).pending(limit=10) == pending[1:]


def test_capacity_frees_only_after_valid_receipt(queue: Queue) -> None:
    queue.spool.put(_observation())
    size = queue.spool.status()["ciphertext_bytes"]
    limited = BrowserCaptureSpool(queue.root, queue.key, max_bytes=size)
    before = _files(queue)
    with pytest.raises(BrowserCaptureSpoolFull):
        limited.put(_observation("b"))
    with _server(lambda handler, _: _respond(handler, 403, SENTINEL.encode())) as (endpoint, _):
        assert flush_browser_capture(limited, endpoint, queue.credential) == {
            "status": "upload_not_authorized"
        }
    assert _files(queue) == before
    with pytest.raises(BrowserCaptureSpoolFull):
        limited.put(_observation("b"))
    with _server(_valid) as (endpoint, _):
        assert flush_browser_capture(limited, endpoint, queue.credential) == {"status": "uploaded"}
    assert limited.status()["available_bytes"] == size
    assert limited.put(_observation("b")) == "queued"
    assert limited.read(_observation("b").content_digest) == _observation("b")


def test_overlapping_browser_and_scheduled_flush_share_one_delivery_slot(queue: Queue) -> None:
    queue.spool.put(_observation())
    started = threading.Event()
    release = threading.Event()

    def respond(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        started.set()
        assert release.wait(timeout=3)
        _valid(handler, body)

    with (
        _server(respond) as (endpoint, requests),
        concurrent.futures.ThreadPoolExecutor() as executor,
    ):
        first = executor.submit(flush_browser_capture, queue.spool, endpoint, queue.credential)
        try:
            assert started.wait(timeout=2)
            assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {
                "status": "upload_pending"
            }
            assert len(requests) == 1
        finally:
            release.set()
        assert first.result(timeout=3) == {"status": "uploaded"}
        assert flush_browser_capture(queue.spool, endpoint, queue.credential) == {"status": "ready"}
        assert len(requests) == 1


def test_verified_delivery_health_has_opaque_receipt_not_content(queue: Queue) -> None:
    from cross_assistant_memory.browser_capture_diagnostics import inspect_diagnostics

    observation = _observation()
    queue.spool.put(observation)
    with _server(_valid) as (endpoint, _):
        assert (
            flush_browser_capture(queue.spool, endpoint, queue.credential)["status"] == "uploaded"
        )
    health = inspect_diagnostics(queue.root)
    assert cast(dict[str, object], health["delivery"])["status"] == "uploaded"
    assert observation.account_binding in cast(dict[str, object], health["last_receipts"])
    encoded = json.dumps(health)
    assert observation.messages[0].text not in encoded
    assert observation.canonical_url not in encoded
    assert CREDENTIAL not in encoded
