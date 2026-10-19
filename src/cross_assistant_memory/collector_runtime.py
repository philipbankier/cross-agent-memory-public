from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from http.client import HTTPException, HTTPMessage, IncompleteRead, RemoteDisconnected
from pathlib import Path
from typing import IO, cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cross_assistant_memory.collector import (
    CollectorConfig,
    CollectorNodeConfig,
    InitialSourceCursor,
    NativeSourceOptIn,
    iter_native_source_files,
    load_collector_config,
)
from cross_assistant_memory.collector_queue import (
    CollectorQueue,
    FileObservation,
    QueueCapacityError,
    QueueConflictError,
    QueueFailureCode,
    ReplayBoundary,
    exclusive_collector_sync,
    source_key_for,
)
from cross_assistant_memory.collector_service import COLLECTOR_SERVICE_SCHEDULE_SECONDS
from cross_assistant_memory.ingest import (
    DEFAULT_MAX_FILE_BYTES,
    MAX_METADATA_RECORD_BYTES,
    parse_incremental_file,
)
from cross_assistant_memory.models import (
    ParseResult,
    SourceCursor,
    SourceKind,
    SourceSystem,
    UploadReceipt,
)
from cross_assistant_memory.safe_files import open_regular_file_no_symlinks, secure_path_stat
from cross_assistant_memory.uploads import (
    MAX_UPLOAD_RECORDS,
    UploadBatch,
    UploadCursorGap,
    UploadPublicationPending,
    accepted_native_parsers,
    build_upload_batch,
    parse_upload_batch,
    validate_upload_receipt,
)

MAX_COLLECTOR_SEGMENT_BYTES = 4 * 1024 * 1024
MAX_SINGLE_RECORD_BYTES = DEFAULT_MAX_FILE_BYTES
MAX_SEGMENTS_PER_SOURCE = 16
MAX_SOURCES_PER_SYNC = 64
MAX_SEGMENTS_PER_SYNC = 64
MAX_SOURCE_READ_BYTES_PER_SYNC = 8 * 1024 * 1024 * 1024
MAX_UPLOADS_PER_SYNC = 256
MAX_PUBLICATION_RETRIES_PER_SYNC = 32
MAX_PUBLICATION_RETRY_SECONDS = 300
MAX_CREDENTIAL_BYTES = 4096
MAX_UPLOAD_RESPONSE_BYTES = 64 * 1024
READ_CHUNK_BYTES = 1024 * 1024
MAX_CURSOR_GAP_READ_BYTES = 256 * 1024 * 1024

UploadTransport = Callable[
    [CollectorNodeConfig, str, bytes],
    QueueFailureCode | UploadCursorGap | UploadPublicationPending | None,
]


class _ScanWorkLimit(Exception):
    state = "work_limit"


class _SourceReadLimit(_ScanWorkLimit):
    state = "source_read_limit"


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class SourceSyncResult:
    source_system: SourceSystem
    source_path_hash: str
    state: str
    segments_enqueued: int

    def as_dict(self) -> dict[str, object]:
        return {
            "source_system": self.source_system.value,
            "source_path_hash": self.source_path_hash,
            "state": self.state,
            "segments_enqueued": self.segments_enqueued,
        }


@dataclass(frozen=True)
class FlushResult:
    uploaded: int
    failed: int
    failure_code: str | None
    checkpoints_advanced: int
    publication_pending: bool = False


@dataclass
class _ScanBudget:
    segments: int = 0
    reserved_bytes: int = 0

    def reserve(self, read_bytes: int) -> bool:
        if (
            self.segments >= MAX_SEGMENTS_PER_SYNC
            or self.reserved_bytes + read_bytes > MAX_SOURCE_READ_BYTES_PER_SYNC
        ):
            return False
        self.segments += 1
        self.reserved_bytes += read_bytes
        return True


def sync_collector(
    config_path: Path,
    *,
    transport: UploadTransport | None = None,
    now_epoch: int | None = None,
) -> dict[str, object]:
    config = load_collector_config(config_path)
    with exclusive_collector_sync(config.queue):
        queue = CollectorQueue.initialize(config.queue)
        return _sync_collector_locked(
            queue,
            config,
            transport=transport,
            now_epoch=now_epoch,
        )


def _sync_collector_locked(
    queue: CollectorQueue,
    config: CollectorConfig,
    *,
    transport: UploadTransport | None,
    now_epoch: int | None,
) -> dict[str, object]:
    now = _now_epoch(now_epoch)
    expired_items = queue.expire(now_epoch=now)
    source_results: list[SourceSyncResult] = []
    seen_sources: set[tuple[SourceSystem, str]] = set()
    sources: dict[str, tuple[NativeSourceOptIn, Path]] = {}
    configured_selections = _configured_initial_selections(config)
    observations = queue.file_observations()
    unchanged: set[str] = set()
    priority_keys: set[str] = set()
    for source in config.sources:
        for path in iter_native_source_files(
            source.root, source.adapter, excluded_files=source.excluded_files
        ):
            path_hash = _source_path_hash(path)
            seen_sources.add((source.source_system, path_hash))
            key = source_key_for(source.source_system, source.source_account_id, path_hash)
            sources[key] = (source, path)
            try:
                queue.validate_initial_cursor(key, source.initial_cursor_for(path))
                signature = _file_signature(secure_path_stat(path, "collector source"))
                observation = observations.get(key)
                if observation is not None and observation.signature == signature:
                    if observation.complete and observation.matches_cursor(queue.scan_cursor(key)):
                        unchanged.add(key)
                elif (
                    observation is not None
                    or signature[3] >= (now - COLLECTOR_SERVICE_SCHEDULE_SECONDS) * 1_000_000_000
                ):
                    priority_keys.add(key)
            except (OSError, RuntimeError, ValueError):
                # Let the ordinary scanner report the exact source failure without hiding it.
                pass

    lanes: dict[bool, deque[str]] = {}
    lane_positions: dict[bool, str | None] = {}
    for priority in (True, False):
        position = queue.scan_after(priority=priority)
        after = position or ""
        keys = sorted(
            key for key in sources if key not in unchanged and (key in priority_keys) == priority
        )
        lanes[priority] = deque(
            [key for key in keys if key > after] + [key for key in keys if key <= after]
        )
        # The backfill column is non-nullable; its last key wraps to an unset start.
        lane_positions[priority] = (
            keys[-1] if not priority and position is None and keys else position
        )
    budget = _ScanBudget()
    stop_reason = None
    priority = queue.next_scan_is_priority()
    priority_attempts = 0
    deferred_positions: dict[bool, str | None] = {}
    while lanes[True] or lanes[False]:
        if len(source_results) >= MAX_SOURCES_PER_SYNC:
            stop_reason = "source_limit"
            break
        if not lanes[priority]:
            priority = not priority
        previous_position = lane_positions[priority]
        key = lanes[priority].popleft()
        lane_positions[priority] = key
        source, path = sources[key]
        result = _scan_source(queue, source, path, now=now, budget=budget, priority=priority)
        source_results.append(result)
        priority_attempts += int(priority)
        if result.state == "queue_full":
            stop_reason = result.state
            break
        if result.state == "work_limit":
            if result.segments_enqueued == 0:
                deferred_positions.setdefault(priority, previous_position)
            stop_reason = result.state
        priority = not priority

    # Smaller files can use remaining work; keep the first deferred file's next turn.
    for deferred_priority, position in reversed(deferred_positions.items()):
        queue.defer_scan_lane(priority=deferred_priority, after_source_key=position)

    flush = _flush_due_uploads(
        queue,
        config.node,
        transport=transport or post_upload_batch,
        now=now_epoch,
        opted_in_sources={
            (source.source_system, source.source_account_id) for source in config.sources
        },
        excluded_sources={
            source_key_for(source.source_system, source.source_account_id, _source_path_hash(path))
            for source in config.sources
            for path in source.excluded_files
        },
        sources=sources,
        initial_selections=configured_selections,
    )
    queue_status = queue.status(now_epoch=now_epoch)
    selection_conflicts = sorted(
        key
        for key, retained in queue_status.initial_selections.items()
        if configured_selections.get(key) != retained
    )
    missing_selected = sorted(
        (configured_selections.keys() | queue_status.initial_selections.keys()) - sources.keys()
    )
    missing_sources = [
        {
            "source_system": source.source_system.value,
            "source_path_hash": source.source_path_hash,
            "last_success_at_epoch": source.last_success_at_epoch,
            "action": (
                "restore_source_for_expired_replay"
                if source.replay_required
                else "restore_or_reconcile_source"
            ),
        }
        for source in queue_status.sources
        if (source.source_system, source.source_path_hash) not in seen_sources
    ]
    source_attention = [
        item.as_dict()
        for item in source_results
        if item.state
        not in {"current", "queued", "work_limit", "segment_limit", "initial_selection_pending"}
    ]
    attention_required = bool(
        queue_status.attention_items
        or selection_conflicts
        or missing_selected
        or missing_sources
        or source_attention
        or flush.failed
        or any(source.replay_required for source in queue_status.sources)
    )
    pending = (
        flush.publication_pending
        or queue_status.queued_items > 0
        or stop_reason is not None
        or any(
            item.state in {"segment_limit", "initial_selection_pending"} for item in source_results
        )
    )
    return {
        "status": "attention_required" if attention_required else "pending" if pending else "ok",
        "content_opened": budget.segments > 0,
        "source_files_seen": len(sources),
        "source_files_attempted": len(source_results),
        "metadata_unchanged_files": len(unchanged),
        "selection_conflicts": selection_conflicts,
        "missing_selected_files": missing_selected,
        "scan_work": {
            "stop_reason": stop_reason,
            "segment_reads_reserved": budget.segments,
            "source_read_bytes_reserved": budget.reserved_bytes,
            "max_source_read_bytes": MAX_SOURCE_READ_BYTES_PER_SYNC,
            "max_sources": MAX_SOURCES_PER_SYNC,
            "max_segments": MAX_SEGMENTS_PER_SYNC,
            "priority_file_attempts": priority_attempts,
            "backfill_file_attempts": len(source_results) - priority_attempts,
            "unchanged_basis": "file_metadata_and_cursor_not_fresh_content_verification",
        },
        "segments_enqueued": sum(item.segments_enqueued for item in source_results),
        "uploaded_batches": flush.uploaded,
        "failed_uploads": flush.failed,
        "publication_pending": flush.publication_pending,
        "failure_code": flush.failure_code,
        "cursor_checkpoints_advanced": flush.checkpoints_advanced,
        "expired_items_removed": expired_items,
        "source_attention": source_attention,
        "missing_sources": missing_sources,
        "queue": queue_status.as_dict(),
    }


def _configured_initial_selections(config: CollectorConfig) -> dict[str, InitialSourceCursor]:
    return {
        source_key_for(
            source.source_system, source.source_account_id, _source_path_hash(selection.path)
        ): selection.cursor
        for source in config.sources
        for selection in source.initial_selections
    }


def collector_status(config_path: Path, *, now_epoch: int | None = None) -> dict[str, object]:
    now = _now_epoch(now_epoch)
    config = load_collector_config(config_path)
    current_sources = {
        source_key_for(
            source.source_system, source.source_account_id, _source_path_hash(path)
        ): path
        for source in config.sources
        for path in iter_native_source_files(
            source.root, source.adapter, excluded_files=source.excluded_files
        )
    }
    configured_selections = _configured_initial_selections(config)
    coverage: dict[str, object] = {
        "basis": "file_metadata_and_acknowledged_cursor_not_fresh_content_verification",
        "acknowledged_unchanged_files": 0,
        "pending_or_unverified_files": len(current_sources),
        "freshness_guaranteed": False,
    }
    database = config.queue.root / "queue.sqlite3"
    if not database.exists() and not config.queue.key_file.exists():
        return {
            "status": "uninitialized",
            "content_opened": False,
            "current_source_files": len(current_sources),
            "coverage": coverage,
            "queue": None,
            "missing_sources": [],
        }
    queue = CollectorQueue.open(config.queue)
    queue_status = queue.status(now_epoch=now)
    observations = queue.file_observations() if queue_status.schema_version >= 5 else {}
    acknowledged = 0
    selection_conflicts: set[str] = set()
    for key in current_sources.keys() | queue_status.initial_selections.keys():
        try:
            queue.validate_initial_cursor(key, configured_selections.get(key))
        except QueueConflictError:
            selection_conflicts.add(key)
    missing_selected = sorted(
        (configured_selections.keys() | queue_status.initial_selections.keys())
        - current_sources.keys()
    )
    for key, path in current_sources.items():
        if key in selection_conflicts:
            continue
        observation = observations.get(key)
        if observation is None or not observation.complete:
            continue
        try:
            signature = _file_signature(secure_path_stat(path, "collector source"))
        except (OSError, RuntimeError, ValueError):
            continue
        if observation.signature == signature and observation.matches_cursor(queue.cursor(key)):
            acknowledged += 1
    pending = len(current_sources) - acknowledged
    coverage["acknowledged_unchanged_files"] = acknowledged
    coverage["pending_or_unverified_files"] = pending
    coverage["selected_prefixes"] = queue_status.as_dict()["initial_selections"]
    coverage["selection_conflicts"] = sorted(selection_conflicts)
    coverage["missing_selected_files"] = missing_selected
    missing_sources = [
        {
            "source_system": source.source_system.value,
            "source_path_hash": source.source_path_hash,
            "last_success_at_epoch": source.last_success_at_epoch,
            "action": (
                "restore_source_for_expired_replay"
                if source.replay_required
                else "restore_or_reconcile_source"
            ),
        }
        for source in queue_status.sources
        if source.source_key not in current_sources
    ]
    attention_required = bool(
        queue_status.attention_items
        or selection_conflicts
        or missing_selected
        or missing_sources
        or any(source.replay_required for source in queue_status.sources)
    )
    return {
        "status": (
            "attention_required"
            if attention_required
            else "pending"
            if pending or queue_status.queued_items
            else "ok"
        ),
        "content_opened": False,
        "current_source_files": len(current_sources),
        "coverage": coverage,
        "queue": queue_status.as_dict(),
        "missing_sources": missing_sources,
    }


def retry_blocked_upload(
    config_path: Path,
    item_id: str,
    *,
    now_epoch: int | None = None,
) -> dict[str, object]:
    config = load_collector_config(config_path)
    queue = CollectorQueue.open(config.queue)
    queue.retry_blocked(item_id, now_epoch=_now_epoch(now_epoch))
    return {"status": "retry_scheduled", "item_id": item_id}


def post_upload_batch(
    node: CollectorNodeConfig,
    credential: str,
    body: bytes,
) -> QueueFailureCode | UploadCursorGap | UploadPublicationPending | None:
    batch = parse_upload_batch(body)
    request = Request(
        node.upload_url,
        data=body,
        headers={
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with build_opener(_RejectRedirects()).open(
            request,
            timeout=node.timeout_seconds,
        ) as response:
            status_code = response.status
            response_body = response.read(MAX_UPLOAD_RESPONSE_BYTES + 1)
    except HTTPError as error:
        try:
            if error.code in {409, 503}:
                response_body = error.read(MAX_UPLOAD_RESPONSE_BYTES + 1)
                if len(response_body) > MAX_UPLOAD_RESPONSE_BYTES:
                    return (
                        QueueFailureCode.HTTP_SERVER_ERROR
                        if error.code == 503
                        else QueueFailureCode.INVALID_RESPONSE
                    )
                try:
                    value: object = json.loads(response_body, object_pairs_hook=_unique_json_object)
                except (UnicodeDecodeError, ValueError, RecursionError):
                    # Older nodes and intermediary outages may return an unstructured 503.
                    return (
                        QueueFailureCode.HTTP_SERVER_ERROR
                        if error.code == 503
                        else QueueFailureCode.INVALID_RESPONSE
                    )
                if isinstance(value, dict):
                    gap_value = cast(dict[str, object], value)
                    if error.code == 409 and gap_value.get("status") == "cursor_gap":
                        return UploadCursorGap.from_dict(gap_value, batch)
                    if error.code == 503 and gap_value.get("status") == "publication_pending":
                        return UploadPublicationPending.from_dict(gap_value, batch)
        except TimeoutError:
            return QueueFailureCode.TIMEOUT
        except OSError:
            return QueueFailureCode.NETWORK_UNREACHABLE
        except IncompleteRead:
            return QueueFailureCode.NETWORK_UNREACHABLE
        except (HTTPException, UnicodeDecodeError, ValueError, RecursionError):
            return QueueFailureCode.INVALID_RESPONSE
        finally:
            error.close()
        return _http_failure_code(error.code)
    except TimeoutError:
        return QueueFailureCode.TIMEOUT
    except URLError as error:
        if isinstance(error.reason, TimeoutError):
            return QueueFailureCode.TIMEOUT
        return QueueFailureCode.NETWORK_UNREACHABLE
    except (RemoteDisconnected, IncompleteRead):
        return QueueFailureCode.NETWORK_UNREACHABLE
    except HTTPException:
        return QueueFailureCode.INVALID_RESPONSE
    except ValueError:
        return QueueFailureCode.LOCAL_ERROR
    except OSError:
        return QueueFailureCode.NETWORK_UNREACHABLE
    if status_code not in {200, 201}:
        return _http_failure_code(status_code)
    if len(response_body) > MAX_UPLOAD_RESPONSE_BYTES:
        return QueueFailureCode.INVALID_RESPONSE
    try:
        value = json.loads(response_body, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return QueueFailureCode.INVALID_RESPONSE
    if not isinstance(value, dict):
        return QueueFailureCode.INVALID_RESPONSE
    result = cast(dict[str, object], value)
    try:
        receipt = UploadReceipt.from_dict(result)
        validate_upload_receipt(batch, receipt, status_code=status_code)
    except ValueError:
        return QueueFailureCode.INVALID_RESPONSE
    return None


def load_transport_credential(path: Path) -> str:
    descriptor, _normalized = open_regular_file_no_symlinks(
        path,
        "collector transport credential",
    )
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(descriptor)
        raise ValueError("collector transport credential must be a private regular file")
    if metadata.st_uid != os.getuid():
        os.close(descriptor)
        raise ValueError("collector transport credential must be owned by the current user")
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAX_CREDENTIAL_BYTES:
        raise ValueError("collector transport credential is invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("collector transport credential is invalid") from error
    credential = text.rstrip("\r\n")
    if (
        not credential
        or credential.strip() != credential
        or any(character.isspace() for character in credential)
        or any(not (character.isalnum() or character in "-._~+/=") for character in credential)
    ):
        raise ValueError("collector transport credential is invalid")
    return credential


def _scan_source(
    queue: CollectorQueue,
    source: NativeSourceOptIn,
    path: Path,
    *,
    now: int,
    budget: _ScanBudget,
    priority: bool = False,
) -> SourceSyncResult:
    path_hash = _source_path_hash(path)
    source_key = source_key_for(source.source_system, source.source_account_id, path_hash)
    enqueued = 0
    state = "segment_limit"
    try:
        initial = source.initial_cursor_for(path)
        queue.validate_initial_cursor(source_key, initial)
        for _index in range(MAX_SEGMENTS_PER_SOURCE):
            held = queue.schema_hold(source_key)
            checkpoint = queue.cursor_checkpoint(source_key)
            if held is not None and checkpoint is not None:
                if held.end_byte_offset < checkpoint.end_byte_offset:
                    checkpoint = None
                else:
                    held = None
            retained = checkpoint or held
            cursor = (
                retained.start_cursor
                if retained is not None
                else queue.scan_cursor(source_key) or initial
            )
            replay = queue.replay_boundary(source_key) if checkpoint is None else None
            if replay is not None and queue.queued_replay_matches(source_key, replay):
                replay = None
            replay_limit = _replay_limit(replay, cursor)
            segment_limit = (
                retained.end_byte_offset - (0 if cursor is None else cursor.next_byte_offset)
                if retained is not None
                else replay_limit
            )
            before_signature = _file_signature(secure_path_stat(path, "collector source"))
            source_size = before_signature[2]
            read_bytes = _segment_read_reservation(
                source.source_system, source_size, cursor, segment_limit
            )
            if read_bytes > MAX_SOURCE_READ_BYTES_PER_SYNC:
                queue.record_scan_attempt(source_key, priority=priority)
                state = "source_read_limit"
                break
            if not budget.reserve(read_bytes):
                state = "work_limit"
                break
            # Rotation is not an evidence cursor. A crash must not pin every retry to this file.
            if _index == 0:
                queue.record_scan_attempt(source_key, priority=priority)
            parsed = _parse_next_segment(
                path,
                source.source_system,
                cursor,
                max_increment_bytes=segment_limit,
                max_source_bytes=source_size,
            )
            if (
                len(parsed.records) > MAX_UPLOAD_RECORDS
                and not parsed.unknown_record_types
                and not parsed.malformed_records
                and retained is None
                and replay_limit is None
            ):
                # Dense JSONL can hit the record limit before the byte limit. Reparse the
                # shorter physical prefix; retained envelopes keep their original boundaries.
                limit = parsed.records[MAX_UPLOAD_RECORDS].byte_start - parsed.segment_start_byte
                extra_reads = _segment_read_reservation(
                    source.source_system, source_size, cursor, limit
                )
                if extra_reads > MAX_SOURCE_READ_BYTES_PER_SYNC:
                    state = "source_read_limit"
                    break
                if not budget.reserve(extra_reads):
                    state = "work_limit"
                    break
                parsed = _parse_next_segment(
                    path,
                    source.source_system,
                    cursor,
                    max_increment_bytes=limit,
                    max_source_bytes=source_size,
                )
            if (
                parsed.segment_end_byte == parsed.segment_start_byte
                and source_size - parsed.segment_start_byte >= MAX_COLLECTOR_SEGMENT_BYTES
                and retained is None
                and replay_limit is None
            ):
                limit = min(MAX_SINGLE_RECORD_BYTES, source_size - parsed.segment_start_byte)
                extra_reads = limit + 1
                if extra_reads > MAX_SOURCE_READ_BYTES_PER_SYNC:
                    state = "source_read_limit"
                    break
                if not budget.reserve(extra_reads):
                    state = "work_limit"
                    break
                larger = _parse_large_record(
                    path, source.source_system, cursor, source_size, limit, budget=budget
                )
                if larger is not None:
                    parsed = larger
            large_frame = (
                parsed.segment_end_byte - parsed.segment_start_byte > MAX_COLLECTOR_SEGMENT_BYTES
            )
            if large_frame and (
                parsed.segment_end_byte - parsed.segment_start_byte > MAX_SINGLE_RECORD_BYTES
                or parsed.segment_end_ordinal_exclusive != parsed.segment_start_ordinal + 1
            ):
                raise QueueConflictError(
                    "large-frame replay must contain one bounded physical record"
                )
            if retained is not None and (
                parsed.segment_end_ordinal_exclusive,
                parsed.segment_end_byte,
                parsed.end_prefix_digest,
            ) != (
                retained.end_record_ordinal,
                retained.end_byte_offset,
                retained.end_prefix_sha256,
            ):
                raise QueueConflictError("source no longer matches its retained reparse boundary")
            if (
                replay_limit is not None
                and replay is not None
                and (
                    parsed.segment_end_ordinal_exclusive,
                    parsed.segment_end_byte,
                    parsed.end_prefix_digest,
                )
                != (
                    replay.end_record_ordinal,
                    replay.end_byte_offset,
                    replay.end_prefix_sha256,
                )
            ):
                raise QueueConflictError("source no longer matches its expired replay boundary")
            if parsed.segment_end_byte == parsed.segment_start_byte:
                remaining_bytes = parsed.observed_file_size - parsed.segment_start_byte
                if (
                    isinstance(cursor, SourceCursor)
                    and remaining_bytes < MAX_COLLECTOR_SEGMENT_BYTES
                ):
                    _record_file_observation(
                        queue, source_key, parsed, before_signature, complete=True, now=now
                    )
                return SourceSyncResult(
                    source_system=source.source_system,
                    source_path_hash=path_hash,
                    state=(
                        "record_too_large"
                        if remaining_bytes >= MAX_COLLECTOR_SEGMENT_BYTES
                        else "queued"
                        if enqueued
                        else "initial_selection_pending"
                        if isinstance(cursor, InitialSourceCursor)
                        else "current"
                    ),
                    segments_enqueued=enqueued,
                )
            if parsed.unknown_record_types or parsed.malformed_records:
                if large_frame:
                    # Do not persist an unverified large frame in the ordinary 4 MiB hold queue.
                    return SourceSyncResult(
                        source.source_system, path_hash, "large_record_schema_unverified", enqueued
                    )
                if checkpoint is not None:
                    return SourceSyncResult(
                        source.source_system, path_hash, "checkpoint_revalidation_failed", enqueued
                    )
                if held is not None:
                    return SourceSyncResult(
                        source.source_system, path_hash, "schema_hold", enqueued
                    )
                raw = _read_verified_segment(parsed)
                queue.enqueue_schema_hold(
                    raw,
                    source_system=source.source_system,
                    source_account_id=source.source_account_id,
                    source_path_hash=path_hash,
                    start_record_ordinal=parsed.segment_start_ordinal,
                    start_byte_offset=parsed.segment_start_byte,
                    end_record_ordinal=parsed.segment_end_ordinal_exclusive,
                    end_byte_offset=parsed.segment_end_byte,
                    start_prefix_sha256=parsed.start_prefix_digest,
                    end_prefix_sha256=parsed.end_prefix_digest,
                    now_epoch=now,
                    initial_cursor=initial,
                )
                return SourceSyncResult(
                    source_system=source.source_system,
                    source_path_hash=path_hash,
                    state="schema_hold",
                    segments_enqueued=enqueued,
                )
            if (
                source.source_system is SourceSystem.CLAUDE_CODE
                and parsed.source_kind is SourceKind.UNKNOWN
            ):
                return SourceSyncResult(
                    source_system=source.source_system,
                    source_path_hash=path_hash,
                    state="source_identity_pending",
                    segments_enqueued=enqueued,
                )
            upload_parsed = parsed
            if replay_limit is not None and replay is not None:
                upload_parsed = replace(
                    parsed,
                    observed_file_size=replay.observed_file_size,
                    file_mtime_ns=replay.file_mtime_ns,
                )
            body = build_upload_batch(
                upload_parsed,
                source_account_id=source.source_account_id,
                provenance=source.provenance(parsed),
            )
            if (
                replay_limit is not None
                and replay is not None
                and parse_upload_batch(body).batch_id != replay.expected_batch_id
            ):
                for parser_name, parser_version in accepted_native_parsers(source.source_system):
                    if parser_name != parsed.parser_name:
                        continue
                    if (parser_name, parser_version) == (parsed.parser_name, parsed.parser_version):
                        continue
                    compatible = replace(
                        upload_parsed, parser_name=parser_name, parser_version=parser_version
                    )
                    candidate = build_upload_batch(
                        compatible,
                        source_account_id=source.source_account_id,
                        provenance=source.provenance(parsed),
                    )
                    if parse_upload_batch(candidate).batch_id == replay.expected_batch_id:
                        body = candidate
                        break
                else:
                    raise QueueConflictError("expired upload idempotency identity changed")
            if checkpoint is not None:
                queue.replace_cursor_checkpoint(checkpoint.item_id, body, now_epoch=now)
            else:
                queue.enqueue_upload(
                    body,
                    now_epoch=now,
                    revalidated_hold=(held.item_id, _read_verified_segment(parsed))
                    if held is not None
                    else None,
                    initial_cursor=initial,
                )
            enqueued += 1
            if (
                _record_file_observation(
                    queue,
                    source_key,
                    parsed,
                    before_signature,
                    complete=parsed.segment_end_byte == source_size,
                    now=now,
                )
                and parsed.segment_end_byte == source_size
            ):
                return SourceSyncResult(source.source_system, path_hash, "queued", enqueued)
    except _ScanWorkLimit as exc:
        state = exc.state
    except QueueCapacityError:
        state = "queue_full"
    except QueueConflictError:
        queue.record_scan_attempt(source_key, priority=priority)
        state = "queue_blocked"
    except (OSError, RuntimeError, ValueError):
        queue.record_scan_attempt(source_key, priority=priority)
        state = "source_error"
    return SourceSyncResult(
        source_system=source.source_system,
        source_path_hash=path_hash,
        state=state,
        segments_enqueued=enqueued,
    )


def _file_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _record_file_observation(
    queue: CollectorQueue,
    source_key: str,
    parsed: ParseResult,
    before_signature: tuple[int, int, int, int, int],
    *,
    complete: bool,
    now: int,
) -> bool:
    try:
        after = _file_signature(secure_path_stat(parsed.path, "collector source"))
    except (OSError, ValueError):
        return False
    if before_signature != after or parsed.observed_file_size != after[2]:
        return False
    queue.record_file_observation(
        source_key,
        FileObservation(
            after,
            parsed.segment_end_ordinal_exclusive,
            parsed.segment_end_byte,
            parsed.end_prefix_digest,
            complete,
        ),
        now_epoch=now,
    )
    return True


def _segment_read_reservation(
    source_system: SourceSystem,
    source_size: int,
    cursor: SourceCursor | InitialSourceCursor | None,
    replay_limit: int | None,
) -> int:
    start = 0 if cursor is None else cursor.next_byte_offset
    segment = min(max(0, source_size - start), replay_limit or MAX_COLLECTOR_SEGMENT_BYTES)
    metadata = MAX_METADATA_RECORD_BYTES + 1 if source_system is SourceSystem.CODEX else source_size
    # Metadata, boundary byte, two prefix checks, two segment reads, and a possible schema hold.
    return metadata + 1 + 3 * start + 4 * segment


def _parse_next_segment(
    path: Path,
    source_system: SourceSystem,
    cursor: SourceCursor | InitialSourceCursor | None,
    *,
    max_increment_bytes: int | None = None,
    max_source_bytes: int | None = None,
) -> ParseResult:
    return parse_incremental_file(
        path,
        source_system,
        start_ordinal=0 if cursor is None else cursor.next_record_ordinal,
        start_byte=0 if cursor is None else cursor.next_byte_offset,
        expected_prefix_digest=None if cursor is None else cursor.prefix_digest,
        max_increment_bytes=max_increment_bytes or MAX_COLLECTOR_SEGMENT_BYTES,
        max_source_bytes=max_source_bytes,
    )


def _replay_limit(
    replay: ReplayBoundary | None, cursor: SourceCursor | InitialSourceCursor | None
) -> int | None:
    if replay is None:
        return None
    start_byte = 0 if cursor is None else cursor.next_byte_offset
    if start_byte == replay.end_byte_offset:
        return None
    if start_byte > replay.end_byte_offset:
        raise QueueConflictError("collector cursor passed its expired replay boundary")
    replay_bytes = replay.end_byte_offset - start_byte
    if replay_bytes <= 0 or replay_bytes > MAX_SINGLE_RECORD_BYTES:
        raise QueueConflictError("expired replay boundary exceeds the collector segment limit")
    return replay_bytes


def _parse_large_record(
    path: Path,
    source_system: SourceSystem,
    cursor: SourceCursor | InitialSourceCursor | None,
    source_size: int,
    limit: int,
    *,
    budget: _ScanBudget,
) -> ParseResult | None:
    """Locate one bounded complete frame, then reparse its exact range with normal verification."""
    start = 0 if cursor is None else cursor.next_byte_offset
    descriptor, _normalized = open_regular_file_no_symlinks(path, "collector large record")
    length = 0
    complete = False
    with os.fdopen(descriptor, "rb") as handle:
        if os.fstat(handle.fileno()).st_size > source_size:
            raise RuntimeError("source grew beyond the reserved large-record read budget")
        handle.seek(start)
        while length <= limit:
            chunk = handle.readline(min(READ_CHUNK_BYTES, limit + 1 - length))
            if not chunk:
                break
            length += len(chunk)
            if chunk.endswith(b"\n"):
                complete = True
                break
    if not complete or length > limit:
        return None
    read_bytes = _segment_read_reservation(source_system, source_size, cursor, length)
    if read_bytes > MAX_SOURCE_READ_BYTES_PER_SYNC:
        raise _SourceReadLimit
    if not budget.reserve(read_bytes):
        raise _ScanWorkLimit
    parsed = _parse_next_segment(
        path, source_system, cursor, max_increment_bytes=length, max_source_bytes=source_size
    )
    if (
        parsed.segment_end_byte != start + length
        or parsed.segment_end_ordinal_exclusive != parsed.segment_start_ordinal + 1
    ):
        raise RuntimeError("large record framing changed before verification")
    return parsed


def _flush_due_uploads(
    queue: CollectorQueue,
    node: CollectorNodeConfig,
    *,
    transport: UploadTransport,
    now: int | None,
    opted_in_sources: set[tuple[SourceSystem, str]],
    excluded_sources: set[str],
    sources: dict[str, tuple[NativeSourceOptIn, Path]],
    initial_selections: dict[str, InitialSourceCursor] | None = None,
) -> FlushResult:
    uploaded = 0
    failed = 0
    failure_code: str | None = None
    credential: str | None = None
    checkpoints_advanced = 0
    gap_budget = _ScanBudget()
    transport = _publication_retry_transport(transport)
    for _index in range(MAX_UPLOADS_PER_SYNC):
        # None keeps queue checks and receipts on the current clock after slow requests.
        due = queue.due_uploads(now_epoch=now, limit=1)
        if not due:
            break
        item = due[0]
        batch = parse_upload_batch(item.body)
        source_key = source_key_for(
            batch.parsed.source_system, batch.source_account_id, batch.source_path_hash
        )
        try:
            queue.validate_initial_cursor(source_key, (initial_selections or {}).get(source_key))
        except QueueConflictError:
            queue.mark_failure(item.item_id, QueueFailureCode.SOURCE_EXCLUDED, now_epoch=now)
            failed += 1
            failure_code = QueueFailureCode.SOURCE_EXCLUDED.value
            continue
        if (
            batch.parsed.source_system,
            batch.source_account_id,
        ) not in opted_in_sources or source_key in excluded_sources:
            queue.mark_failure(item.item_id, QueueFailureCode.SOURCE_EXCLUDED, now_epoch=now)
            failed += 1
            failure_code = QueueFailureCode.SOURCE_EXCLUDED.value
            continue
        if credential is None:
            try:
                credential = load_transport_credential(node.credential_file)
            except (OSError, ValueError):
                queue.mark_failure(item.item_id, QueueFailureCode.LOCAL_ERROR, now_epoch=now)
                return FlushResult(
                    uploaded=uploaded,
                    failed=failed + 1,
                    failure_code=QueueFailureCode.LOCAL_ERROR.value,
                    checkpoints_advanced=checkpoints_advanced,
                )
        result = transport(node, credential, item.body)
        if isinstance(result, UploadCursorGap):
            result = _repair_metadata_gap(
                parse_upload_batch(item.body),
                result,
                sources,
                node,
                credential,
                transport=transport,
                budget=gap_budget,
            )
            if result is None:
                # The retained batch remains the durable retry anchor until its own receipt.
                result = transport(node, credential, item.body)
                if isinstance(result, UploadCursorGap):
                    result = QueueFailureCode.HTTP_REJECTED
        if isinstance(result, UploadPublicationPending):
            # Keep the exact ciphertext and cursor until a final verified node receipt.
            return FlushResult(uploaded, failed, failure_code, checkpoints_advanced, True)
        if result is None:
            queue.mark_success(item.item_id, now_epoch=now)
            uploaded += 1
            continue
        queue.mark_failure(item.item_id, result, now_epoch=now)
        failed += 1
        failure_code = result.value
        if result is not QueueFailureCode.HTTP_REJECTED:
            break
    return FlushResult(
        uploaded=uploaded,
        failed=failed,
        failure_code=failure_code,
        checkpoints_advanced=checkpoints_advanced,
    )


def _publication_retry_transport(transport: UploadTransport) -> UploadTransport:
    # One shared budget covers original batches and metadata bridges throughout this flush.
    deadline = time.monotonic() + MAX_PUBLICATION_RETRY_SECONDS
    retries = 0

    def send(
        node: CollectorNodeConfig, credential: str, body: bytes
    ) -> QueueFailureCode | UploadCursorGap | UploadPublicationPending | None:
        nonlocal retries
        result = transport(node, credential, body)
        while isinstance(result, UploadPublicationPending):
            if result.batch_id != parse_upload_batch(body).batch_id:
                return QueueFailureCode.INVALID_RESPONSE
            if retries >= MAX_PUBLICATION_RETRIES_PER_SYNC or time.monotonic() + 1 >= deadline:
                return result
            retries += 1
            time.sleep(1)
            result = transport(node, credential, body)
        return result

    return send


def _repair_metadata_gap(
    batch: UploadBatch,
    gap: UploadCursorGap,
    sources: dict[str, tuple[NativeSourceOptIn, Path]],
    node: CollectorNodeConfig,
    credential: str,
    *,
    transport: UploadTransport,
    budget: _ScanBudget,
) -> QueueFailureCode | UploadPublicationPending | None:
    key = source_key_for(
        batch.parsed.source_system, batch.source_account_id, batch.source_path_hash
    )
    source_path = sources.get(key)
    if source_path is None or gap.batch_id != batch.batch_id:
        return QueueFailureCode.HTTP_REJECTED
    source, path = source_path
    initial = source.initial_cursor_for(path)
    if initial is not None and (
        gap.next_byte_offset < initial.next_byte_offset
        or gap.next_record_ordinal < initial.next_record_ordinal
    ):
        return QueueFailureCode.HTTP_REJECTED
    cursor = SourceCursor(
        key,
        batch.parsed.conversation_id,
        batch.parsed.source_kind,
        gap.next_record_ordinal,
        gap.next_byte_offset,
        gap.prefix_sha256,
    )
    target = batch.parsed
    bodies: list[bytes] = []
    try:
        source_size = secure_path_stat(path, "collector source").st_size
        while cursor.next_byte_offset < target.segment_start_byte:
            remaining = target.segment_start_byte - cursor.next_byte_offset
            read_bytes = _segment_read_reservation(
                source.source_system,
                source_size,
                cursor,
                min(remaining, MAX_COLLECTOR_SEGMENT_BYTES),
            )
            if budget.reserved_bytes + read_bytes > MAX_CURSOR_GAP_READ_BYTES or not budget.reserve(
                read_bytes
            ):
                return QueueFailureCode.CURSOR_GAP_WORK_LIMIT
            parsed = _parse_next_segment(
                path,
                source.source_system,
                cursor,
                max_increment_bytes=min(remaining, MAX_COLLECTOR_SEGMENT_BYTES),
                max_source_bytes=source_size,
            )
            if (
                parsed.records
                or parsed.unknown_record_types
                or parsed.malformed_records
                or parsed.segment_end_byte <= cursor.next_byte_offset
                or parsed.segment_end_byte > target.segment_start_byte
                or any(
                    getattr(parsed, field) != getattr(target, field)
                    for field in (
                        "conversation_id",
                        "branch_id",
                        "parent_conversation_id",
                        "source_kind",
                        "source_label",
                        "history_base",
                    )
                )
            ):
                return QueueFailureCode.HTTP_REJECTED
            bodies.append(
                build_upload_batch(
                    replace(
                        parsed,
                        observed_file_size=target.observed_file_size,
                        file_mtime_ns=target.file_mtime_ns,
                    ),
                    source_account_id=batch.source_account_id,
                    provenance=source.provenance(parsed),
                )
            )
            cursor = replace(
                cursor,
                next_record_ordinal=parsed.segment_end_ordinal_exclusive,
                next_byte_offset=parsed.segment_end_byte,
                prefix_digest=parsed.end_prefix_digest,
            )
        if (cursor.next_record_ordinal, cursor.next_byte_offset, cursor.prefix_digest) != (
            target.segment_start_ordinal,
            target.segment_start_byte,
            target.start_prefix_digest,
        ):
            return QueueFailureCode.HTTP_REJECTED
    except (OSError, RuntimeError, ValueError):
        return QueueFailureCode.HTTP_REJECTED
    # Only a fully verified metadata-only gap is bridged. No raw metadata bytes leave this host.
    # Lost receipts are safe: the next original-batch retry asks for the node's remaining gap.
    for body in bodies:
        result = transport(node, credential, body)
        if isinstance(result, UploadCursorGap):
            return QueueFailureCode.HTTP_REJECTED
        if result is not None:
            return result
    return None


def _read_verified_segment(parsed: ParseResult) -> bytes:
    path = parsed.path
    if (
        parsed.segment_start_byte == 0
        and parsed.start_prefix_digest != hashlib.sha256(b"").hexdigest()
    ):
        raise RuntimeError("collector source has an invalid initial prefix")
    descriptor, _normalized = open_regular_file_no_symlinks(path, "collector source")
    try:
        before = os.fstat(descriptor)
        if before.st_size < parsed.segment_end_byte:
            raise RuntimeError("collector source became shorter before queueing")
        digest = hashlib.sha256()
        segment = bytearray()
        position = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while position < parsed.segment_end_byte:
                chunk = handle.read(min(READ_CHUNK_BYTES, parsed.segment_end_byte - position))
                if not chunk:
                    raise RuntimeError("collector source became shorter before queueing")
                next_position = position + len(chunk)
                if position < parsed.segment_start_byte:
                    prefix_end = min(next_position, parsed.segment_start_byte)
                    digest.update(chunk[: prefix_end - position])
                    if prefix_end == parsed.segment_start_byte:
                        if digest.hexdigest() != parsed.start_prefix_digest:
                            raise RuntimeError("collector source prefix changed before queueing")
                        digest.update(chunk[prefix_end - position :])
                        segment.extend(chunk[prefix_end - position :])
                else:
                    digest.update(chunk)
                    segment.extend(chunk)
                position = next_position
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = secure_path_stat(path, "collector source")
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or (
        before.st_dev,
        before.st_ino,
    ) != (current.st_dev, current.st_ino):
        raise RuntimeError("collector source identity changed before queueing")
    if digest.hexdigest() != parsed.end_prefix_digest:
        raise RuntimeError("collector source segment changed before queueing")
    if len(segment) != parsed.segment_end_byte - parsed.segment_start_byte:
        raise RuntimeError("collector source segment length changed before queueing")
    return bytes(segment)


def _http_failure_code(status_code: int) -> QueueFailureCode:
    if status_code == 401:
        return QueueFailureCode.HTTP_UNAUTHORIZED
    if status_code == 403:
        return QueueFailureCode.HTTP_FORBIDDEN
    if status_code in {408, 504}:
        return QueueFailureCode.TIMEOUT
    if status_code == 429:
        return QueueFailureCode.HTTP_RATE_LIMITED
    if 500 <= status_code <= 599:
        return QueueFailureCode.HTTP_SERVER_ERROR
    return QueueFailureCode.HTTP_REJECTED


def _source_path_hash(path: Path) -> str:
    normalized = Path(os.path.abspath(path.expanduser()))
    return hashlib.sha256(str(normalized).encode()).hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("collector response contains a duplicate field")
        value[key] = item
    return value


def _now_epoch(value: int | None) -> int:
    now = int(time.time()) if value is None else value
    if isinstance(now, bool) or now < 0:
        raise ValueError("collector time is invalid")
    return now
