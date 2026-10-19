from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from typing import Any, TypeVar, cast

from cross_assistant_memory.answer_evaluation import (
    DEFAULT_ANSWER_ATTEMPTS,
    run_generated_answer_evaluation,
    verify_generated_answer_evaluation,
)
from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CorrectionPlanRequest,
    CreateDeviceEnrollmentRequest,
    DeletionPlanRequest,
    MemoryApplication,
    ProposeMemoryRequest,
    RegisterSourceAccountRequest,
    ReviewMemoryCandidateRequest,
    SearchMemoryRequest,
    ShadowSearchConfig,
    correction_plan_authorized_by,
    pending_web_evidence_claim,
)
from cross_assistant_memory.backup import (
    create_offline_clone,
    create_snapshot,
    create_web_source_configuration_snapshot,
    verify_snapshot,
)
from cross_assistant_memory.candidates import FROZEN_CANDIDATES, run_sandboxed_candidate
from cross_assistant_memory.client_evaluation import (
    run_exact_client_evaluation,
    verify_exact_client_evaluation,
)
from cross_assistant_memory.collector import discover_native_sources, load_native_source_opt_ins
from cross_assistant_memory.collector_enrollment import enroll_collector
from cross_assistant_memory.collector_runtime import (
    collector_status,
    retry_blocked_upload,
    sync_collector,
)
from cross_assistant_memory.collector_service import (
    CollectorServicePlatform,
    install_collector_service,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.control_panel import (
    create_control_panel_app,
    loopback_panel_origin,
    reserve_control_panel_listener,
)
from cross_assistant_memory.deletion import (
    deletion_plan_authorized_by,
    load_deletion_plan,
    write_deletion_plan,
)
from cross_assistant_memory.embedding_artifact import (
    DEFAULT_EMBEDDING_MODEL_ID,
    FROZEN_EMBEDDING_MODELS,
    install_embedding_artifact,
    verify_embedding_artifact,
)
from cross_assistant_memory.evaluation import (
    FROZEN_BASELINE_REVISION,
    FROZEN_WORKSET_REVISION,
    freeze_evaluation_bundle,
    run_first_party_baseline,
    run_first_party_workset_evaluation,
    run_semantic_workset_evaluation,
    score_retrieval_run,
    verify_evaluation_bundle,
)
from cross_assistant_memory.evidence_rotation import (
    apply_rotation,
    plan_rotation,
    resume_rotation,
    rotation_status,
)
from cross_assistant_memory.identity_setup import (
    apply_client_credential,
    apply_client_registration,
    apply_device_enrollment,
    apply_source_registration,
    plan_client_credential,
    plan_client_registration,
    plan_device_enrollment,
    plan_source_registration,
)
from cross_assistant_memory.incremental import (
    apply_incremental_ingestion_plan,
    build_incremental_ingestion_plan,
)
from cross_assistant_memory.ingest import DEFAULT_MAX_FILE_BYTES, NATIVE_SOURCE_SYSTEMS
from cross_assistant_memory.mcp_client import run_readonly_client
from cross_assistant_memory.mcp_server import MCPTransport, create_mcp_server
from cross_assistant_memory.mcp_ssh_client import SSHConnection, run_ssh_client
from cross_assistant_memory.models import (
    Authority,
    CandidateReviewOperation,
    CandidateReviewReason,
    Capability,
    ClientKind,
    ContextFilter,
    ContextKind,
    DeletionKind,
    MemoryType,
    ObservationRetirement,
    Privacy,
    QueryMode,
    RetrievalControl,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.portable import (
    create_filesystem_portable_export,
    import_filesystem_portable_export,
    verify_filesystem_portable_export,
)
from cross_assistant_memory.private_json import load_owner_only_json, write_owner_only_json
from cross_assistant_memory.projection import (
    build_shadow_projection,
    rebuild_shadow_projection_after_deletion,
    run_shadow_deletion_rebuild_drill,
    verify_shadow_projection,
)
from cross_assistant_memory.recovery import (
    create_b2_recovery_package,
    create_filesystem_recovery_package,
    discard_b2_preparation,
    initialize_recovery_material,
    install_operational_key,
    restore_b2_recovery_package,
    restore_filesystem_recovery_package,
)
from cross_assistant_memory.remediation import apply_remediation_plan, build_remediation_plan
from cross_assistant_memory.retrieval import effective_context_filters, suppressed_workset
from cross_assistant_memory.runtime_evidence import runtime_evidence_for_command
from cross_assistant_memory.setup_workflow import (
    apply_setup_plan,
    build_setup_plan,
    inspect_setup,
    verify_setup,
    write_setup_plan,
)
from cross_assistant_memory.storage import Ledger, exclusive_ledger_writer
from cross_assistant_memory.web_export_assistant import (
    WebExportAssistEvent,
    WebExportPauseReason,
    inspect_assisted_web_exports,
    record_assisted_web_export_event,
)
from cross_assistant_memory.web_exports import (
    DEFAULT_WEB_SOURCE_CLIENT_VERSION,
    WEB_SOURCE_SYSTEMS,
    apply_web_export_plans,
    authorize_web_export_schema,
    extract_web_export_member,
    prepare_web_export_plan,
    require_runtime_code_revision,
    revoke_web_schema_authorization,
    verify_web_export_plan,
)

EnumT = TypeVar("EnumT", bound=StrEnum)
MAX_CORRECTION_PLAN_BYTES = 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cross-memory")
    parser.add_argument("--home", type=Path, help="override the private data directory")
    parser.add_argument(
        "--evidence-config",
        type=Path,
        help="owner-only evidence access configuration (or CAM_EVIDENCE_CONFIG)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="create or migrate the local ledger")
    subparsers.add_parser("doctor", help="report runtime and ledger readiness without mutation")
    attachment_audit = subparsers.add_parser(
        "attachment-audit", help="inspect bounded local attachment admission without mutation"
    )
    attachment_audit.add_argument("--max-objects", type=int, default=1000)
    attachment_audit.add_argument("--max-total-bytes", type=int, default=64 * 1024 * 1024)
    subparsers.add_parser("setup-inspect", help="inspect setup state without mutation")
    setup_plan = subparsers.add_parser(
        "setup-plan",
        help="write a sealed, state-bound local setup plan",
    )
    setup_plan.add_argument("--output", type=Path, required=True)
    setup_apply = subparsers.add_parser(
        "setup-apply",
        help="apply an exact fresh-ledger setup plan",
    )
    setup_apply.add_argument("--plan", type=Path, required=True)
    setup_apply.add_argument("--expected-plan-sha256", required=True)
    setup_apply.add_argument("--execute", action="store_true")
    subparsers.add_parser("setup-verify", help="verify a current local setup without mutation")

    client_registration_plan = subparsers.add_parser(
        "client-registration-plan",
        help="write a sealed, state-bound client registration plan",
    )
    client_registration_plan.add_argument("--output", type=Path, required=True)
    client_registration_plan.add_argument("--label", required=True)
    client_registration_plan.add_argument("--kind", choices=_enum_values(ClientKind), required=True)
    client_registration_plan.add_argument("--intent-key", required=True)
    client_registration_plan.add_argument(
        "--capability", action="append", choices=_enum_values(Capability), required=True
    )
    client_registration_apply = subparsers.add_parser(
        "client-registration-apply",
        help="apply one exact client registration plan",
    )
    _add_identity_setup_apply_arguments(client_registration_apply)

    client_credential_plan = subparsers.add_parser(
        "client-credential-plan",
        help="write a sealed plan for one recoverable client credential",
    )
    client_credential_plan.add_argument("--output", type=Path, required=True)
    client_credential_plan.add_argument("--client-id", required=True)
    client_credential_plan.add_argument("--intent-key", required=True)
    client_credential_plan.add_argument("--ttl-hours", type=int, required=True)
    client_credential_plan.add_argument("--credential-output", type=Path, required=True)
    client_credential_apply = subparsers.add_parser(
        "client-credential-apply",
        help="apply one exact recoverable client credential plan",
    )
    _add_identity_setup_apply_arguments(client_credential_apply)

    device_enrollment_plan = subparsers.add_parser(
        "device-enrollment-plan",
        help="write a sealed plan for one recoverable device enrollment code",
    )
    device_enrollment_plan.add_argument("--output", type=Path, required=True)
    device_enrollment_plan.add_argument("--label", required=True)
    device_enrollment_plan.add_argument("--platform", required=True)
    device_enrollment_plan.add_argument("--intent-key", required=True)
    device_enrollment_plan.add_argument("--ttl-minutes", type=int, default=10)
    device_enrollment_plan.add_argument("--credential-ttl-days", type=int, default=90)
    device_enrollment_plan.add_argument("--enrollment-output", type=Path, required=True)
    device_enrollment_apply = subparsers.add_parser(
        "device-enrollment-apply",
        help="apply one exact recoverable device enrollment plan",
    )
    _add_identity_setup_apply_arguments(device_enrollment_apply)

    source_registration_plan = subparsers.add_parser(
        "source-registration-plan",
        help="write a sealed, state-bound source account registration plan",
    )
    source_registration_plan.add_argument("--output", type=Path, required=True)
    source_registration_plan.add_argument("--device-id", required=True)
    source_registration_plan.add_argument(
        "--source-system", choices=_enum_values(SourceSystem), required=True
    )
    source_registration_plan.add_argument("--account-label", required=True)
    source_registration_plan.add_argument("--scope", choices=_enum_values(Scope), required=True)
    source_registration_plan.add_argument("--project-id")
    source_registration_apply = subparsers.add_parser(
        "source-registration-apply",
        help="apply one exact source account registration plan",
    )
    _add_identity_setup_apply_arguments(source_registration_apply)

    collector_detect = subparsers.add_parser(
        "collector-detect", help="show a text-free preview of supported native history roots"
    )
    collector_detect.add_argument("--user-home", type=Path, default=Path.home())

    collector_validate = subparsers.add_parser(
        "collector-config-validate", help="validate explicit native source opt-ins"
    )
    collector_validate.add_argument("--config", type=Path, required=True)

    collector_sync = subparsers.add_parser(
        "collector-sync", help="scan opted-in native sources and flush the encrypted queue"
    )
    collector_sync.add_argument("--config", type=Path, required=True)
    collector_sync.add_argument("--quiet", action="store_true")

    collector_status_parser = subparsers.add_parser(
        "collector-status", help="show text-free native collector and queue status"
    )
    collector_status_parser.add_argument("--config", type=Path, required=True)

    collector_retry = subparsers.add_parser(
        "collector-retry", help="explicitly retry one blocked collector upload"
    )
    collector_retry.add_argument("--config", type=Path, required=True)
    collector_retry.add_argument("--item-id", required=True)

    collector_enroll = subparsers.add_parser(
        "collector-enroll",
        help="plan or redeem one collector enrollment into a private credential file",
    )
    collector_enroll.add_argument("--url", required=True)
    collector_enroll.add_argument("--credential-output", type=Path, required=True)
    collector_enroll.add_argument("--enrollment-id", required=True)
    collector_enroll.add_argument("--device-label", required=True)
    collector_enroll.add_argument("--device-platform", required=True)
    collector_enroll.add_argument("--expected-plan-sha256")
    collector_enroll.add_argument("--execute", action="store_true")

    collector_service_install = subparsers.add_parser(
        "collector-service-install",
        help="plan or install a user-level native collector schedule",
    )
    collector_service_install.add_argument(
        "--platform",
        choices=[item.value for item in CollectorServicePlatform],
        required=True,
    )
    collector_service_install.add_argument("--config", type=Path, required=True)
    collector_service_install.add_argument("--executable", type=Path, required=True)
    collector_service_install.add_argument("--expected-plan-sha256")
    collector_service_install.add_argument("--execute", action="store_true")

    snapshot = subparsers.add_parser(
        "snapshot", help="create a consistent, self-verifying local state snapshot"
    )
    snapshot.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-snapshot", help="verify one restored state snapshot")
    verify.add_argument("--snapshot", type=Path, required=True)

    offline_clone = subparsers.add_parser(
        "offline-clone", help="copy a verified snapshot into a marked non-live data root"
    )
    offline_clone.add_argument("--snapshot", type=Path, required=True)
    offline_clone.add_argument("--output", type=Path, required=True)

    recovery_init = subparsers.add_parser(
        "recovery-init", help="create separate root-key recovery material"
    )
    recovery_init.add_argument("--recovery-secret-output", type=Path, required=True)
    recovery_init.add_argument("--root-kit-output", type=Path, required=True)

    recovery_install = subparsers.add_parser(
        "recovery-install-key", help="install a mounted key for backup without the recovery secret"
    )
    recovery_install.add_argument("--root-kit", type=Path, required=True)
    recovery_install.add_argument("--recovery-secret", type=Path, required=True)
    recovery_install.add_argument("--output", type=Path, required=True)

    rotation_plan = subparsers.add_parser(
        "evidence-rotation-plan", help="preview a bounded primary-evidence maintenance rotation"
    )
    rotation_plan.add_argument("--new-operational-key", type=Path, required=True)
    rotation_apply = subparsers.add_parser(
        "evidence-rotation-apply", help="rewrap primary evidence and stage a restart"
    )
    rotation_apply.add_argument("--new-operational-key", type=Path, required=True)
    rotation_apply.add_argument("--expected-plan-sha256", required=True)
    rotation_apply.add_argument("--execute", action="store_true")
    rotation_apply.add_argument("--supersede-operation-id")
    for command_parser in (rotation_plan, rotation_apply):
        command_parser.add_argument(
            "--capacity",
            choices=("standard", "extended"),
            default="standard",
            help="explicit bounded inventory capacity; retained in the recovery journal",
        )
    for command, help_text in (
        ("evidence-rotation-resume", "resume maintenance and verify a fresh-process restart"),
        ("evidence-rotation-rollback", "reverse only the exact journaled maintenance state"),
    ):
        rotation = subparsers.add_parser(command, help=help_text)
        rotation.add_argument("--operation-id", required=True)
        rotation.add_argument("--execute", action="store_true")
    subparsers.add_parser("evidence-rotation-status", help="inspect rotation state without repair")

    backup = subparsers.add_parser("backup", help="create one complete encrypted recovery package")
    backup_backend = backup.add_mutually_exclusive_group(required=True)
    backup_backend.add_argument("--backend-root", type=Path)
    backup_backend.add_argument("--b2", action="store_true", help="use the configured B2 bucket")
    backup_key = backup.add_mutually_exclusive_group(required=True)
    backup_key.add_argument("--root-kit", type=Path)
    backup_key.add_argument("--operational-key", type=Path)
    backup.add_argument("--recovery-secret", type=Path)
    backup.add_argument("--query-suite", type=Path, required=True)
    backup.add_argument("--package-kit", type=Path, required=True)
    backup.add_argument(
        "--resume-source-generation",
        help="resume only an existing B2 capture at this exact generation, not a new snapshot",
    )
    backup_cleanup = backup.add_mutually_exclusive_group()
    backup_cleanup.add_argument(
        "--discard-empty-preparation",
        action="store_true",
        help="preview cleanup of an authenticated empty B2 preparation without creating a backup",
    )
    backup_cleanup.add_argument(
        "--discard-unpublished-preparation",
        action="store_true",
        help="preview retiring authenticated local B2 preparation before any package upload intent",
    )
    backup.add_argument("--execute", action="store_true", help="execute preparation cleanup")

    restore = subparsers.add_parser(
        "restore", help="restore an encrypted package into a new verified data root"
    )
    restore_backend = restore.add_mutually_exclusive_group(required=True)
    restore_backend.add_argument("--backend-root", type=Path)
    restore_backend.add_argument("--b2", action="store_true", help="use the configured B2 bucket")
    restore.add_argument("--package-kit", type=Path, required=True)
    restore.add_argument("--recovery-secret", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True)
    restore.add_argument("--verify", action="store_true")

    portable_export = subparsers.add_parser(
        "portable-export",
        help="create a provider-neutral encrypted export without credentials",
    )
    portable_export.add_argument("--output", type=Path, required=True)
    portable_export.add_argument("--recovery-secret", type=Path, required=True)

    portable_verify = subparsers.add_parser(
        "portable-verify",
        help="decrypt and verify a provider-neutral portable export",
    )
    portable_verify.add_argument("--export", type=Path, required=True)
    portable_verify.add_argument("--recovery-secret", type=Path, required=True)

    portable_import = subparsers.add_parser(
        "portable-import",
        help="verify and import a portable export into a new isolated data root",
    )
    portable_import.add_argument("--export", type=Path, required=True)
    portable_import.add_argument("--recovery-secret", type=Path, required=True)
    portable_import.add_argument("--output", type=Path, required=True)

    remediation_plan = subparsers.add_parser(
        "remediation-plan", help="build a private, state-bound event correction plan"
    )
    remediation_plan.add_argument("--spec", type=Path, required=True)
    remediation_plan.add_argument("--output", type=Path, required=True)

    remediation_apply = subparsers.add_parser(
        "remediation-apply", help="preview or apply one state-bound event correction plan"
    )
    remediation_apply.add_argument("--plan", type=Path, required=True)
    remediation_apply.add_argument("--execute", action="store_true")

    correction_plan = subparsers.add_parser(
        "correction-plan", help="build one opaque, state-bound event policy correction plan"
    )
    correction_plan.add_argument("--event-id", required=True)
    correction_plan.add_argument("--authority", choices=_enum_values(Authority), required=True)
    correction_plan.add_argument("--scope", choices=_enum_values(Scope), required=True)
    correction_plan.add_argument("--project-id")
    correction_plan.add_argument("--privacy", choices=_enum_values(Privacy), required=True)
    correction_plan.add_argument("--reason", required=True)
    correction_plan.add_argument("--output", type=Path, required=True)

    correction_apply = subparsers.add_parser(
        "correction-apply", help="preview or apply one exact event policy correction plan"
    )
    correction_apply.add_argument("--plan", type=Path, required=True)
    correction_apply.add_argument("--expected-plan-sha256", required=True)
    correction_apply.add_argument("--execute", action="store_true")

    deletion_plan = subparsers.add_parser(
        "deletion-plan", help="build an opaque, state-bound evidence deletion plan"
    )
    deletion_plan.add_argument("--kind", choices=_enum_values(DeletionKind), required=True)
    deletion_plan.add_argument("--source-system", choices=_enum_values(SourceSystem), required=True)
    deletion_plan.add_argument("--source-account", required=True)
    deletion_plan.add_argument("--conversation-id")
    deletion_plan.add_argument(
        "--retirement-pair",
        nargs=2,
        action="append",
        default=[],
        metavar=("OBSOLETE_EVENT", "REPLACEMENT_EVENT"),
        help="exact obsolete/replacement event pair; repeat for observation retirement",
    )
    deletion_plan.add_argument("--authorized-by", required=True)
    deletion_plan.add_argument("--authorization-scope", required=True)
    deletion_plan.add_argument("--reason", required=True)
    deletion_plan.add_argument("--output", type=Path, required=True)

    deletion_apply = subparsers.add_parser(
        "deletion-apply", help="preview or apply one exact evidence deletion plan"
    )
    deletion_apply.add_argument("--plan", type=Path, required=True)
    deletion_apply.add_argument("--expected-plan-sha256", required=True)
    deletion_apply.add_argument("--execute", action="store_true")

    embedding_install = subparsers.add_parser(
        "embedding-install", help="preview or install one frozen local embedding artifact"
    )
    embedding_install.add_argument(
        "--model",
        choices=sorted(FROZEN_EMBEDDING_MODELS),
        default=DEFAULT_EMBEDDING_MODEL_ID,
    )
    embedding_install.add_argument("--output", type=Path, required=True)
    embedding_install.add_argument("--execute", action="store_true")

    embedding_verify = subparsers.add_parser(
        "embedding-verify", help="verify one frozen local embedding artifact"
    )
    embedding_verify.add_argument("--artifact", type=Path, required=True)
    embedding_verify.add_argument("--model", choices=sorted(FROZEN_EMBEDDING_MODELS))

    shadow_build = subparsers.add_parser(
        "shadow-build", help="preview or build the disposable MemPalace projection"
    )
    _add_shadow_paths(shadow_build)
    shadow_build.add_argument("--execute", action="store_true")

    shadow_verify = subparsers.add_parser(
        "shadow-verify", help="verify the active shadow projection against the ledger"
    )
    _add_shadow_paths(shadow_verify)

    shadow_search = subparsers.add_parser(
        "shadow-search", help="compare MemPalace shadow retrieval with the baseline"
    )
    _add_shadow_paths(shadow_search)
    shadow_search.add_argument("query")
    shadow_search.add_argument(
        "--mode",
        choices=_enum_values(QueryMode),
        default=QueryMode.FIND_EVIDENCE.value,
    )
    shadow_search.add_argument("--project-id")
    shadow_search.add_argument("--scope", action="append", choices=_enum_values(Scope))
    shadow_search.add_argument("--authority", action="append", choices=_enum_values(Authority))
    shadow_search.add_argument(
        "--context",
        action="append",
        type=_parse_context_filter,
        metavar="KIND=KEY",
    )
    shadow_search.add_argument(
        "--retrieval-control",
        choices=_enum_values(RetrievalControl),
        default=RetrievalControl.AUTO.value,
    )
    shadow_search.add_argument("--limit", type=int, default=5)

    shadow_drill = subparsers.add_parser(
        "shadow-deletion-drill", help="prove deletion in a copy and rebuild from the ledger"
    )
    _add_shadow_paths(shadow_drill)
    shadow_drill.add_argument("--event-id", required=True)
    shadow_drill.add_argument("--execute", action="store_true")

    shadow_rebuild = subparsers.add_parser(
        "shadow-rebuild-after-deletion",
        help="rebuild a projection after canonical deletion and purge stale generations",
    )
    _add_shadow_paths(shadow_rebuild)
    shadow_rebuild.add_argument("--operation-id", required=True)
    shadow_rebuild.add_argument("--execute", action="store_true")

    eval_freeze = subparsers.add_parser(
        "eval-freeze", help="freeze an immutable evaluation corpus and encrypted answer key"
    )
    eval_freeze.add_argument("--source-plan", type=Path, required=True)
    eval_freeze.add_argument("--queries", type=Path, required=True)
    eval_freeze.add_argument("--answers", type=Path, required=True)
    eval_freeze.add_argument("--output", type=Path, required=True)
    eval_freeze.add_argument("--answer-key-output", type=Path, required=True)
    eval_freeze.add_argument("--gpg-recipient", required=True)

    eval_verify = subparsers.add_parser("eval-verify", help="verify an immutable evaluation corpus")
    eval_verify.add_argument("--bundle", type=Path, required=True)

    eval_run = subparsers.add_parser(
        "eval-run-baseline", help="run the frozen first-party retriever in a shadow ledger"
    )
    eval_run.add_argument("--bundle", type=Path, required=True)
    eval_run.add_argument("--output", type=Path, required=True)
    eval_run.add_argument("--revision", default=FROZEN_BASELINE_REVISION)

    eval_worksets = subparsers.add_parser(
        "eval-run-worksets",
        help="run source-aware FTS evidence worksets in a shadow ledger",
    )
    eval_worksets.add_argument("--bundle", type=Path, required=True)
    eval_worksets.add_argument("--output", type=Path, required=True)
    eval_worksets.add_argument("--revision", default=FROZEN_WORKSET_REVISION)
    eval_worksets.add_argument("--harness-revision")

    eval_semantic = subparsers.add_parser(
        "eval-run-semantic",
        help="compare one local semantic projection with the raw FTS workset",
    )
    eval_semantic.add_argument("--bundle", type=Path, required=True)
    eval_semantic.add_argument("--output", type=Path, required=True)
    eval_semantic.add_argument("--runtime", type=Path, required=True)
    eval_semantic.add_argument("--checkout", type=Path, required=True)
    eval_semantic.add_argument("--embedding-artifact", type=Path, required=True)
    eval_semantic.add_argument("--revision", default="HEAD")
    eval_semantic.add_argument("--harness-revision")

    eval_candidate = subparsers.add_parser(
        "eval-run-candidate", help="run a frozen third-party candidate in the macOS sandbox"
    )
    eval_candidate.add_argument("--bundle", type=Path, required=True)
    eval_candidate.add_argument("--output", type=Path, required=True)
    eval_candidate.add_argument("--candidate", choices=sorted(FROZEN_CANDIDATES), required=True)
    eval_candidate.add_argument("--runtime", type=Path, required=True)
    eval_candidate.add_argument("--checkout", type=Path, required=True)
    eval_candidate.add_argument("--timeout", type=int, default=1800)

    eval_score = subparsers.add_parser(
        "eval-score", help="score retrieval results from a separately supplied answer key"
    )
    eval_score.add_argument("--run", type=Path, required=True)
    eval_score.add_argument(
        "--answer-key",
        required=True,
        help="plaintext JSONL answer key path, or - to read decrypted data from stdin",
    )
    eval_score.add_argument("--output", type=Path)

    eval_answers = subparsers.add_parser(
        "eval-run-generated-answers",
        help="run the public synthetic generated-answer attack gate",
    )
    eval_answers.add_argument("--output", type=Path, required=True)
    eval_answers.add_argument("--base-url", required=True)
    eval_answers.add_argument("--model", required=True)
    eval_answers.add_argument(
        "--expected-response-model",
        action="append",
        help="accepted provider response model; repeat for explicit aliases",
    )
    eval_answers.add_argument("--api-key-env", default="CLIPROXYAPI_API_KEY")
    eval_answers.add_argument("--attempts", type=int, default=DEFAULT_ANSWER_ATTEMPTS)
    eval_answers.add_argument("--revision", default="HEAD")
    eval_answers.add_argument("--execute", action="store_true")

    eval_answers_verify = subparsers.add_parser(
        "eval-verify-generated-answers",
        help="independently verify a generated-answer security run",
    )
    eval_answers_verify.add_argument("--run", type=Path, required=True)
    eval_answers_verify.add_argument("--manifest-sha256", required=True)

    eval_clients = subparsers.add_parser(
        "eval-run-exact-clients",
        help="run exact installed clients against public-synthetic read-only memory",
    )
    eval_clients.add_argument("--contract", type=Path, required=True)
    eval_clients.add_argument("--output", type=Path, required=True)
    eval_clients.add_argument("--codex-bundled", type=Path, required=True)
    eval_clients.add_argument("--codex-path", type=Path, required=True)
    eval_clients.add_argument("--claude", type=Path, required=True)
    eval_clients.add_argument("--grok", type=Path, required=True)
    eval_clients.add_argument("--sandbox-exec", type=Path, required=True)
    eval_clients.add_argument("--revision", default="HEAD")
    eval_clients.add_argument("--execute", action="store_true")

    eval_clients_verify = subparsers.add_parser(
        "eval-verify-exact-clients",
        help="independently verify an immutable exact-client run",
    )
    eval_clients_verify.add_argument("--run", type=Path, required=True)
    eval_clients_verify.add_argument("--manifest-sha256", required=True)
    eval_clients_verify.add_argument("--contract", type=Path, required=True)
    eval_clients_verify.add_argument("--codex-bundled", type=Path, required=True)
    eval_clients_verify.add_argument("--codex-path", type=Path, required=True)
    eval_clients_verify.add_argument("--claude", type=Path, required=True)
    eval_clients_verify.add_argument("--grok", type=Path, required=True)

    ingest = subparsers.add_parser("ingest", help="preview or ingest one native history file")
    ingest.add_argument(
        "--source-system",
        choices=sorted(item.value for item in NATIVE_SOURCE_SYSTEMS),
        required=True,
    )
    ingest.add_argument("--path", type=Path, required=True)
    ingest.add_argument("--source-account", default="local")
    ingest.add_argument(
        "--source-path",
        help="absolute path on the source machine when reading a transferred copy",
    )
    ingest.add_argument("--scope", choices=_enum_values(Scope), default=Scope.PROJECT.value)
    ingest.add_argument("--project-id")
    ingest.add_argument("--max-file-mb", type=int, default=DEFAULT_MAX_FILE_BYTES // (1024 * 1024))
    ingest.add_argument("--execute", action="store_true")

    evidence_publish = subparsers.add_parser(
        "evidence-publish", help="inspect or resume pending evidence publications"
    )
    evidence_publish.add_argument("--execute", action="store_true")
    evidence_publish.add_argument(
        "--discard-unregistered",
        action="store_true",
        help="inspect or clear only unregistered local preparation; never publish",
    )

    web_export_configuration = subparsers.add_parser(
        "web-export-configuration-snapshot",
        help="copy one registered web source policy, without content or credentials, for review",
    )
    web_export_configuration.add_argument("--authoritative-node", type=Path, required=True)
    web_export_configuration.add_argument("--source-account", required=True)
    web_export_configuration.add_argument("--expected-ledger-generation", required=True)
    web_export_configuration.add_argument("--code-revision", required=True)
    web_export_configuration.add_argument("--output", type=Path, required=True)

    web_export_extract = subparsers.add_parser(
        "web-export-extract",
        help="extract and verify one exact named member from an official web-export ZIP",
    )
    web_export_extract.add_argument("--archive-path", type=Path, required=True)
    web_export_extract.add_argument("--archive-member", required=True)
    web_export_extract.add_argument("--expected-archive-sha256", required=True)
    web_export_extract.add_argument("--output", type=Path, required=True)

    web_export_plan = subparsers.add_parser(
        "web-export-plan",
        help="split official web export conversation members into exact objects and one plan",
    )
    web_export_plan.add_argument(
        "--source-system",
        choices=sorted(item.value for item in WEB_SOURCE_SYSTEMS),
        required=True,
    )
    web_export_plan.add_argument("--source-account", required=True)
    web_export_plan.add_argument(
        "--member-path",
        type=Path,
        action="append",
        required=True,
        help="extracted conversation member path; repeat in archive order for ChatGPT shards",
    )
    web_export_plan.add_argument("--archive-path", type=Path, required=True)
    web_export_plan.add_argument(
        "--archive-member",
        action="append",
        required=True,
        help="exact archive member name paired with each --member-path",
    )
    web_export_plan.add_argument("--output", type=Path, required=True)
    web_export_plan.add_argument(
        "--scope", choices=_enum_values(Scope), default=Scope.USER_GLOBAL.value
    )
    web_export_plan.add_argument("--project-id")
    web_export_plan.add_argument("--expected-ledger-generation", required=True)
    web_export_plan.add_argument("--code-revision", required=True)
    web_export_plan.add_argument(
        "--source-client-version",
        default=DEFAULT_WEB_SOURCE_CLIENT_VERSION,
        help="provider export schema/version label, or the explicit unversioned default",
    )
    web_export_plan.add_argument("--max-record-mb", type=int, default=1)

    web_export_verify = subparsers.add_parser(
        "web-export-verify",
        help="verify one exact approved web export plan without opening the ledger",
    )
    web_export_verify.add_argument("--manifest", type=Path, required=True)
    web_export_verify.add_argument("--manifest-sha256", required=True)
    web_export_verify.add_argument("--code-revision", required=True)

    web_export_authorize = subparsers.add_parser(
        "web-export-authorize",
        help="preview or record standing authorization for one exact web-export schema",
    )
    web_export_authorize.add_argument("--manifest", type=Path, required=True)
    web_export_authorize.add_argument("--manifest-sha256", required=True)
    web_export_authorize.add_argument("--code-revision", required=True)
    web_export_authorize.add_argument("--authorized-by", required=True)
    authorization_target = web_export_authorize.add_mutually_exclusive_group()
    authorization_target.add_argument("--offline-clone", action="store_true")
    authorization_target.add_argument("--authoritative-node", type=Path)
    web_export_authorize.add_argument("--reviewed-clone", type=Path)
    web_export_authorize.add_argument("--review-code-revision")
    web_export_authorize.add_argument("--expected-ledger-generation")
    web_export_authorize.add_argument("--execute", action="store_true")

    web_schema_revoke = subparsers.add_parser(
        "web-schema-revoke", help="preview or revoke one exact standing web schema grant"
    )
    web_schema_revoke.add_argument("--authoritative-node", type=Path, required=True)
    web_schema_revoke.add_argument("--source-account", required=True)
    web_schema_revoke.add_argument("--authorization-id", required=True)
    web_schema_revoke.add_argument("--expected-ledger-generation", required=True)
    web_schema_revoke.add_argument("--code-revision", required=True)
    web_schema_revoke.add_argument("--execute", action="store_true")

    web_export_apply = subparsers.add_parser(
        "web-export-apply",
        help="preview or apply verified web export plans to an explicitly selected node or clone",
    )
    web_export_apply.add_argument("--manifest", type=Path, action="append", required=True)
    web_export_apply.add_argument("--manifest-sha256", action="append", required=True)
    web_export_apply.add_argument("--code-revision", required=True)
    web_export_target = web_export_apply.add_mutually_exclusive_group()
    web_export_target.add_argument("--offline-clone", action="store_true")
    web_export_target.add_argument(
        "--authoritative-node",
        type=Path,
        help="absolute data root for routine imports with existing source/schema authorization",
    )
    web_export_apply.add_argument("--execute", action="store_true")

    subparsers.add_parser(
        "web-export-assist-status",
        help="report the next assisted action for each registered official web export",
    )

    web_export_assist_record = subparsers.add_parser(
        "web-export-assist-record",
        help="preview or record one text-free assisted web-export workflow event",
    )
    web_export_assist_record.add_argument(
        "--source-system",
        choices=sorted(item.value for item in WEB_SOURCE_SYSTEMS),
        required=True,
    )
    web_export_assist_record.add_argument("--source-account", required=True)
    web_export_assist_record.add_argument(
        "--scope", choices=_enum_values(Scope), default=Scope.USER_GLOBAL.value
    )
    web_export_assist_record.add_argument("--project-id")
    web_export_assist_record.add_argument(
        "--event", choices=_enum_values(WebExportAssistEvent), required=True
    )
    web_export_assist_record.add_argument("--occurred-at")
    web_export_assist_record.add_argument(
        "--pause-reason", choices=_enum_values(WebExportPauseReason)
    )
    web_export_assist_record.add_argument("--archive-sha256")
    web_export_assist_record.add_argument("--manifest-sha256")
    web_export_assist_record.add_argument("--execute", action="store_true")

    incremental_plan = subparsers.add_parser(
        "incremental-plan",
        help="build a private, state-bound plan for one Codex JSONL segment",
    )
    incremental_plan.add_argument("--path", type=Path, required=True)
    incremental_plan.add_argument("--source-account", default="local")
    incremental_plan.add_argument("--source-path")
    incremental_plan.add_argument(
        "--scope", choices=_enum_values(Scope), default=Scope.PROJECT.value
    )
    incremental_plan.add_argument("--project-id")
    incremental_plan.add_argument("--start-record-ordinal", type=int, default=0)
    incremental_plan.add_argument("--start-byte-offset", type=int, default=0)
    incremental_plan.add_argument("--expected-prefix-sha256")
    incremental_plan.add_argument(
        "--legacy-fork-replay-source-file-id",
        help="exact excluded legacy source to replace with the bounded child branch",
    )
    incremental_plan.add_argument(
        "--max-increment-mb", type=int, default=DEFAULT_MAX_FILE_BYTES // (1024 * 1024)
    )
    incremental_plan.add_argument("--output", type=Path, required=True)

    incremental_apply = subparsers.add_parser(
        "incremental-apply",
        help="preview or apply one state-bound incremental ingestion plan",
    )
    incremental_apply.add_argument("--plan", type=Path, required=True)
    incremental_apply.add_argument("--execute", action="store_true")

    search = subparsers.add_parser("search", help="search included evidence")
    search.add_argument("query", nargs="?", default="")
    search.add_argument(
        "--mode",
        choices=_enum_values(QueryMode),
        default=QueryMode.FIND_EVIDENCE.value,
    )
    search.add_argument("--project-id")
    search.add_argument("--scope", action="append", choices=_enum_values(Scope))
    search.add_argument("--authority", action="append", choices=_enum_values(Authority))
    search.add_argument(
        "--context",
        action="append",
        type=_parse_context_filter,
        metavar="KIND=KEY",
    )
    search.add_argument(
        "--retrieval-control",
        choices=_enum_values(RetrievalControl),
        default=RetrievalControl.AUTO.value,
    )
    search.add_argument("--limit", type=int, default=5)

    evidence = subparsers.add_parser("evidence", help="recover one exact source record")
    evidence.add_argument("event_id")

    propose = subparsers.add_parser("propose", help="create an inactive memory candidate")
    propose.add_argument("statement")
    propose.add_argument("--memory-type", choices=_enum_values(MemoryType), required=True)
    propose.add_argument("--evidence-event", action="append")
    propose.add_argument("--scope", choices=_enum_values(Scope), default=Scope.PROJECT.value)
    propose.add_argument("--project-id")
    propose.add_argument("--web-source-account-id")
    propose.add_argument(
        "--web-source-system",
        choices=sorted(item.value for item in WEB_SOURCE_SYSTEMS),
    )
    propose.add_argument("--web-conversation-id")
    propose.add_argument("--web-message-id")
    propose.add_argument("--web-parent-message-id")
    propose.add_argument("--web-branch-id")
    propose.add_argument("--web-evidence-content")

    candidate_state = subparsers.add_parser(
        "candidate-state",
        help="read one candidate's state-bound review metadata",
    )
    candidate_state.add_argument("memory_id")

    candidate_review = subparsers.add_parser(
        "candidate-review",
        help="apply one append-only local-admin candidate transition",
    )
    candidate_review.add_argument("memory_id")
    candidate_review.add_argument(
        "--operation",
        choices=_enum_values(CandidateReviewOperation),
        required=True,
    )
    candidate_review.add_argument("--expected-basis-digest", required=True)
    candidate_review.add_argument(
        "--reason-code",
        choices=_enum_values(CandidateReviewReason),
        required=True,
    )

    client_register = subparsers.add_parser(
        "client-register", help="register one local client and its bounded capabilities"
    )
    client_register.add_argument("--label", required=True)
    client_register.add_argument("--kind", choices=_enum_values(ClientKind), required=True)
    client_register.add_argument("--intent-key")
    client_register.add_argument(
        "--capability", action="append", choices=_enum_values(Capability), required=True
    )

    credential_issue = subparsers.add_parser(
        "client-credential-issue", help="issue one expiring bearer credential"
    )
    credential_issue.add_argument("--client-id", required=True)
    credential_issue.add_argument("--ttl-hours", type=int, required=True)

    credential_revoke = subparsers.add_parser(
        "client-credential-revoke", help="revoke one client credential"
    )
    credential_revoke.add_argument("--credential-id", required=True)

    enrollment_create = subparsers.add_parser(
        "device-enrollment-create",
        help="create one short-lived single-use device enrollment code",
    )
    enrollment_create.add_argument("--label", required=True)
    enrollment_create.add_argument("--platform", required=True)
    enrollment_create.add_argument("--ttl-minutes", type=int, default=10)
    enrollment_create.add_argument("--credential-ttl-days", type=int, default=90)

    source_account_register = subparsers.add_parser(
        "source-account-register",
        help="bind one source account and fixed access policy to an enrolled device",
    )
    source_account_register.add_argument("--device-id", required=True)
    source_account_register.add_argument(
        "--source-system", choices=_enum_values(SourceSystem), required=True
    )
    source_account_register.add_argument("--account-label", required=True)
    source_account_register.add_argument("--scope", choices=_enum_values(Scope), required=True)
    source_account_register.add_argument("--project-id")

    connect = subparsers.add_parser("connect", help="connect read-only stdio to a local MCP node")
    connect.add_argument("--url", required=True)
    connect.add_argument("--credential-file", type=Path, required=True)
    connect.add_argument("--evidence-text-max-bytes", type=int)

    connect_ssh = subparsers.add_parser(
        "connect-ssh", help="connect read-only using request-local SSH"
    )
    connect_ssh.add_argument("--host", required=True)
    connect_ssh.add_argument("--remote-python", required=True)
    connect_ssh.add_argument("--remote-runtime", required=True)
    connect_ssh.add_argument("--remote-credential-file", required=True)
    connect_ssh.add_argument("--url", required=True)
    connect_ssh.add_argument("--identity-file", type=Path)
    connect_ssh.add_argument("--evidence-text-max-bytes", type=int)

    serve = subparsers.add_parser("serve", help="run the MCP server")
    serve.add_argument(
        "--transport", choices=("stdio", "streamable-http"), default="streamable-http"
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--principal", default="local:mcp")
    serve.add_argument("--read-only", action="store_true")
    serve.add_argument("--memory-app", action="store_true", help="enable the read-only MCP App")
    serve.add_argument("--evidence-text-max-bytes", type=int)
    serve.add_argument("--search-text-max-bytes", type=int)
    serve.add_argument("--shadow-runtime", type=Path)
    serve.add_argument("--shadow-checkout", type=Path)
    serve.add_argument("--shadow-projection-root", type=Path)
    serve.add_argument("--shadow-embedding-artifact", type=Path)

    subparsers.add_parser("panel", help="run the local operations control panel")
    subparsers.add_parser(
        "operations-overview",
        help="report the content-free local operations view",
    )
    subparsers.add_parser(
        "administration",
        help="report the bounded local administrative view",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_environment(args.home)
    try:
        result = _dispatch(args, settings)
    except KeyboardInterrupt:
        if args.command == "ingest":
            print(
                json.dumps(
                    {
                        "status": "interrupted",
                        "error": (
                            "Native import interrupted; completion is unconfirmed. Retry the same "
                            "command with its retained source, runtime and evidence configuration."
                        ),
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(130) from None
        if args.command == "web-export-apply":
            print(
                json.dumps(
                    {
                        "status": "interrupted",
                        "error": (
                            "Web export interrupted; completion is unconfirmed. Retry the same "
                            "command with its retained inputs, runtime and evidence configuration."
                        ),
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(130) from None
        if args.command.startswith("evidence-rotation-"):
            print(
                json.dumps(
                    {
                        "status": "interrupted",
                        "error": "Rotation interrupted; inspect evidence-rotation-status "
                        "before exact resume or rollback.",
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(130) from None
        if args.command == "recovery-install-key":
            print(
                json.dumps(
                    {
                        "status": "interrupted",
                        "error": (
                            "Operational key installation interrupted; "
                            "inspect the output before retrying."
                        ),
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(130) from None
        if args.command in {"backup", "restore"} and bool(args.b2):
            print(
                json.dumps(
                    {
                        "status": "interrupted",
                        "error": (
                            "B2 recovery interrupted; success is unconfirmed. "
                            "Inspect the package kit before retrying."
                        ),
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(130) from None
        return
    except (KeyError, OSError, PermissionError, RuntimeError, ValueError, sqlite3.Error) as exc:
        if args.command.startswith("evidence-rotation-"):
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": f"Evidence rotation refused ({type(exc).__name__}); "
                        "inspect maintenance status.",
                    }
                ),
                file=sys.stderr,
            )
            raise SystemExit(2) from None
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        if not args.command.startswith("evidence-rotation-"):
            raise
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": (
                        f"Evidence rotation refused ({type(exc).__name__}); "
                        "inspect maintenance status."
                    ),
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    if result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))


def _dispatch(args: argparse.Namespace, settings: Settings) -> dict[str, Any] | None:
    command = str(args.command)
    if (
        command
        in {
            "web-export-apply",
            "web-export-configuration-snapshot",
            "web-export-authorize",
            "web-schema-revoke",
        }
        and args.authoritative_node is not None
    ):
        target = cast_path(args.authoritative_node).expanduser()
        if not target.is_absolute():
            raise ValueError("--authoritative-node requires an absolute data-root path")
        if args.home is not None and target.absolute() != settings.data_root.absolute():
            raise ValueError("--home conflicts with --authoritative-node")
        settings = Settings(target)
    if command.startswith("evidence-rotation-"):
        if command == "evidence-rotation-status":
            return rotation_status(settings)
        if command in {"evidence-rotation-resume", "evidence-rotation-rollback"}:
            return resume_rotation(
                settings,
                str(args.operation_id),
                rollback=command.endswith("rollback"),
                execute=bool(args.execute),
            )
        if args.evidence_config is None:
            raise ValueError("rotation requires explicit --evidence-config")
        if command == "evidence-rotation-plan":
            return plan_rotation(
                settings,
                cast_path(args.evidence_config),
                cast_path(args.new_operational_key),
                capacity=str(args.capacity),
            )
        return apply_rotation(
            settings,
            cast_path(args.evidence_config),
            cast_path(args.new_operational_key),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
            supersede_operation_id=args.supersede_operation_id,
            capacity=str(args.capacity),
        )
    if (
        command == "search"
        and RetrievalControl(str(args.retrieval_control)) is RetrievalControl.SUPPRESS
    ):
        return suppressed_workset(
            mode=QueryMode(str(args.mode)),
            contexts=effective_context_filters(tuple(args.context or ()), args.project_id),
        )
    if command == "backup":
        cleanup = bool(args.discard_empty_preparation or args.discard_unpublished_preparation)
        if args.resume_source_generation is not None and (not bool(args.b2) or cleanup):
            raise ValueError("capture resume requires --b2 and no preparation cleanup")
        if bool(args.execute) and not cleanup:
            raise ValueError("backup --execute requires a preparation cleanup option")
        if cleanup:
            if not bool(args.b2) or args.evidence_config is not None:
                raise ValueError("preparation cleanup requires --b2 and no evidence config")
            return discard_b2_preparation(
                settings,
                root_kit=cast_path(args.root_kit) if args.root_kit is not None else None,
                recovery_secret_path=cast_path(args.recovery_secret)
                if args.recovery_secret is not None
                else None,
                operational_key_path=cast_path(args.operational_key)
                if args.operational_key is not None
                else None,
                package_kit=cast_path(args.package_kit),
                query_suite=cast_path(args.query_suite),
                execute=bool(args.execute),
                empty_only=not bool(args.discard_unpublished_preparation),
            )
    evidence = runtime_evidence_for_command(
        settings,
        command,
        args.evidence_config,
        allow_publication=(
            (command in {"ingest", "web-export-apply"} and bool(args.execute))
            or (
                command == "evidence-publish"
                and bool(args.execute)
                and not bool(args.discard_unregistered)
            )
            or (command == "serve" and not bool(args.read_only))
            or command == "panel"
        ),
    )
    if command == "connect":
        run_readonly_client(
            str(args.url),
            cast_path(args.credential_file),
            evidence_text_max_bytes=args.evidence_text_max_bytes,
        )
        return None
    if command == "connect-ssh":
        run_ssh_client(
            SSHConnection(
                host=str(args.host),
                remote_python=str(args.remote_python),
                remote_runtime=str(args.remote_runtime),
                remote_credential_file=str(args.remote_credential_file),
                endpoint=str(args.url),
                identity_file=args.identity_file,
            ),
            evidence_text_max_bytes=args.evidence_text_max_bytes,
        )
        return None
    if command == "setup-inspect":
        return inspect_setup(settings).as_dict()
    if command == "setup-plan":
        return write_setup_plan(build_setup_plan(settings), cast_path(args.output))
    if command == "setup-apply":
        return apply_setup_plan(
            settings,
            cast_path(args.plan),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "setup-verify":
        return verify_setup(settings)
    if command == "client-registration-plan":
        return plan_client_registration(
            settings,
            cast_path(args.output),
            label=str(args.label),
            kind=ClientKind(str(args.kind)),
            capabilities=tuple(Capability(str(item)) for item in args.capability),
            intent_key=str(args.intent_key),
        )
    if command == "client-registration-apply":
        return apply_client_registration(
            settings,
            cast_path(args.plan),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "client-credential-plan":
        return plan_client_credential(
            settings,
            cast_path(args.output),
            client_id=str(args.client_id),
            intent_key=str(args.intent_key),
            ttl_hours=int(args.ttl_hours),
            credential_output=cast_path(args.credential_output),
        )
    if command == "client-credential-apply":
        return apply_client_credential(
            settings,
            cast_path(args.plan),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "device-enrollment-plan":
        return plan_device_enrollment(
            settings,
            cast_path(args.output),
            label=str(args.label),
            platform=str(args.platform),
            intent_key=str(args.intent_key),
            ttl_minutes=int(args.ttl_minutes),
            credential_ttl_days=int(args.credential_ttl_days),
            enrollment_output=cast_path(args.enrollment_output),
        )
    if command == "device-enrollment-apply":
        return apply_device_enrollment(
            settings,
            cast_path(args.plan),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "source-registration-plan":
        return plan_source_registration(
            settings,
            cast_path(args.output),
            device_id=str(args.device_id),
            source_system=SourceSystem(str(args.source_system)),
            account_label=str(args.account_label),
            scope=Scope(str(args.scope)),
            project_id=(str(args.project_id) if args.project_id is not None else None),
        )
    if command == "source-registration-apply":
        return apply_source_registration(
            settings,
            cast_path(args.plan),
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "snapshot":
        return create_snapshot(
            settings,
            cast_path(args.output),
            encrypted_evidence_reader=evidence.reader,
            max_bytes=evidence.max_snapshot_bytes,
        )
    if command == "verify-snapshot":
        return verify_snapshot(cast_path(args.snapshot))
    if command == "offline-clone":
        return create_offline_clone(
            cast_path(args.snapshot),
            cast_path(args.output),
        )
    if command == "recovery-init":
        return initialize_recovery_material(
            cast_path(args.recovery_secret_output),
            cast_path(args.root_kit_output),
        )
    if command == "recovery-install-key":
        return install_operational_key(
            settings,
            root_kit=cast_path(args.root_kit),
            recovery_secret_path=cast_path(args.recovery_secret),
            output=cast_path(args.output),
        )
    if command == "backup":
        root_kit = cast_path(args.root_kit) if args.root_kit is not None else None
        recovery_secret_path = (
            cast_path(args.recovery_secret) if args.recovery_secret is not None else None
        )
        operational_key_path = (
            cast_path(args.operational_key) if args.operational_key is not None else None
        )
        if bool(args.b2):
            return create_b2_recovery_package(
                settings,
                root_kit=root_kit,
                recovery_secret_path=recovery_secret_path,
                operational_key_path=operational_key_path,
                package_kit=cast_path(args.package_kit),
                query_suite=cast_path(args.query_suite),
                encrypted_evidence_reader=evidence.reader,
                snapshot_byte_limit=evidence.max_snapshot_bytes,
                resume_source_generation=args.resume_source_generation,
            )
        return create_filesystem_recovery_package(
            settings,
            backend_root=cast_path(args.backend_root),
            root_kit=root_kit,
            recovery_secret_path=recovery_secret_path,
            operational_key_path=operational_key_path,
            package_kit=cast_path(args.package_kit),
            query_suite=cast_path(args.query_suite),
            encrypted_evidence_reader=evidence.reader,
            snapshot_byte_limit=evidence.max_snapshot_bytes,
        )
    if command == "restore":
        if not bool(args.verify):
            raise ValueError("restore requires --verify")
        if bool(args.b2):
            return restore_b2_recovery_package(
                package_kit=cast_path(args.package_kit),
                recovery_secret_path=cast_path(args.recovery_secret),
                output=cast_path(args.output),
            )
        return restore_filesystem_recovery_package(
            backend_root=cast_path(args.backend_root),
            package_kit=cast_path(args.package_kit),
            recovery_secret_path=cast_path(args.recovery_secret),
            output=cast_path(args.output),
        )
    if command == "portable-export":
        return create_filesystem_portable_export(
            settings,
            output=cast_path(args.output),
            recovery_secret_path=cast_path(args.recovery_secret),
            encrypted_evidence_reader=evidence.reader,
            max_bytes=evidence.max_snapshot_bytes,
        )
    if command == "portable-verify":
        return verify_filesystem_portable_export(
            cast_path(args.export),
            recovery_secret_path=cast_path(args.recovery_secret),
        )
    if command == "portable-import":
        return import_filesystem_portable_export(
            cast_path(args.export),
            recovery_secret_path=cast_path(args.recovery_secret),
            output=cast_path(args.output),
        )
    if command == "remediation-plan":
        return build_remediation_plan(
            settings,
            spec_path=cast_path(args.spec),
            output=cast_path(args.output),
        )
    if command == "remediation-apply":
        return apply_remediation_plan(
            settings,
            plan_path=cast_path(args.plan),
            execute=bool(args.execute),
        )
    if command == "correction-plan":
        correction_principal = ApplicationPrincipal.local_admin("local:cli")
        planned = MemoryApplication(
            Ledger(settings, read_only=True, require_checkpointed=False)
        ).plan_event_policy_correction(
            correction_principal,
            CorrectionPlanRequest(
                event_id=str(args.event_id),
                authority=Authority(str(args.authority)),
                scope=Scope(str(args.scope)),
                project_id=(str(args.project_id) if args.project_id is not None else None),
                privacy=Privacy(str(args.privacy)),
                authorization_scope="memory:curate",
                reason=str(args.reason),
            ),
        )
        plan = cast(dict[str, Any], planned.pop("plan"))
        output = cast_path(args.output)
        write_owner_only_json(
            output,
            plan,
            label="correction plan",
            max_bytes=MAX_CORRECTION_PLAN_BYTES,
        )
        return {**planned, "output": str(output.expanduser())}
    if command == "correction-apply":
        plan = load_owner_only_json(
            cast_path(args.plan),
            label="correction plan",
            max_bytes=MAX_CORRECTION_PLAN_BYTES,
        )
        correction_principal = ApplicationPrincipal.local_admin(correction_plan_authorized_by(plan))
        return MemoryApplication(
            Ledger(settings, read_only=True, require_checkpointed=False)
        ).apply_event_policy_correction(
            correction_principal,
            plan=plan,
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "deletion-plan":
        deletion_principal = ApplicationPrincipal.local_admin(str(args.authorized_by))
        planned = MemoryApplication(
            Ledger(
                settings,
                read_only=True,
                require_checkpointed=False,
                encrypted_evidence_purger=evidence.purger,
            )
        ).plan_deletion(
            deletion_principal,
            DeletionPlanRequest(
                kind=DeletionKind(str(args.kind)),
                retirement_pairs=tuple(
                    ObservationRetirement(str(pair[0]), str(pair[1]))
                    for pair in args.retirement_pair
                ),
                source_system=SourceSystem(str(args.source_system)),
                source_account=str(args.source_account),
                conversation_id=(
                    str(args.conversation_id) if args.conversation_id is not None else None
                ),
                authorization_scope=str(args.authorization_scope),
                reason=str(args.reason),
            ),
        )
        plan = cast(dict[str, Any], planned.pop("plan"))
        output = cast_path(args.output)
        write_deletion_plan(output, plan)
        return {**planned, "output": str(output.expanduser())}
    if command == "deletion-apply":
        plan = load_deletion_plan(cast_path(args.plan))
        deletion_principal = ApplicationPrincipal.local_admin(deletion_plan_authorized_by(plan))
        return MemoryApplication(
            Ledger(
                settings,
                read_only=True,
                require_checkpointed=False,
                encrypted_evidence_purger=evidence.purger,
            )
        ).apply_deletion(
            deletion_principal,
            plan=plan,
            expected_plan_sha256=str(args.expected_plan_sha256),
            execute=bool(args.execute),
        )
    if command == "embedding-install":
        return install_embedding_artifact(
            str(args.model),
            cast_path(args.output),
            execute=bool(args.execute),
        )
    if command == "embedding-verify":
        return verify_embedding_artifact(
            cast_path(args.artifact),
            model_id=(str(args.model) if args.model is not None else None),
        )
    if command == "shadow-build":
        return build_shadow_projection(
            settings,
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            projection_root=cast_path(args.projection_root),
            execute=bool(args.execute),
            embedding_artifact=cast_optional_path(args.embedding_artifact),
        )
    if command == "shadow-verify":
        return verify_shadow_projection(
            settings,
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            projection_root=cast_path(args.projection_root),
            embedding_artifact=cast_optional_path(args.embedding_artifact),
        )
    if command == "shadow-search":
        shadow_scopes = (
            [Scope(item) for item in args.scope]
            if args.scope
            else [Scope.USER_GLOBAL, Scope.PROJECT]
        )
        shadow_authorities = (
            [Authority(item) for item in args.authority] if args.authority else None
        )
        shadow_application = MemoryApplication(Ledger(settings, read_only=True))
        return shadow_application.search_shadow(
            ApplicationPrincipal.local_admin("local:cli"),
            SearchMemoryRequest(
                query=str(args.query),
                mode=QueryMode(str(args.mode)),
                scopes=tuple(shadow_scopes),
                project_id=args.project_id,
                authorities=(tuple(shadow_authorities) if shadow_authorities is not None else None),
                limit=int(args.limit),
                contexts=tuple(args.context or ()),
                retrieval_control=RetrievalControl(str(args.retrieval_control)),
            ),
            ShadowSearchConfig(
                runtime=cast_path(args.runtime),
                checkout=cast_path(args.checkout),
                projection_root=cast_path(args.projection_root),
                embedding_artifact=cast_optional_path(args.embedding_artifact),
            ),
        )
    if command == "shadow-deletion-drill":
        return run_shadow_deletion_rebuild_drill(
            settings,
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            projection_root=cast_path(args.projection_root),
            event_id=str(args.event_id),
            execute=bool(args.execute),
            embedding_artifact=cast_optional_path(args.embedding_artifact),
        )
    if command == "shadow-rebuild-after-deletion":
        return rebuild_shadow_projection_after_deletion(
            settings,
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            projection_root=cast_path(args.projection_root),
            operation_id=str(args.operation_id),
            execute=bool(args.execute),
            embedding_artifact=cast_optional_path(args.embedding_artifact),
        )
    if command == "eval-freeze":
        return freeze_evaluation_bundle(
            source_plan_path=cast_path(args.source_plan),
            queries_path=cast_path(args.queries),
            answers_path=cast_path(args.answers),
            output=cast_path(args.output),
            answer_key_output=cast_path(args.answer_key_output),
            gpg_recipient=str(args.gpg_recipient),
        )
    if command == "eval-verify":
        return verify_evaluation_bundle(cast_path(args.bundle))
    if command == "eval-run-baseline":
        return run_first_party_baseline(
            bundle=cast_path(args.bundle),
            output=cast_path(args.output),
            revision=str(args.revision),
        )
    if command == "eval-run-worksets":
        return run_first_party_workset_evaluation(
            bundle=cast_path(args.bundle),
            output=cast_path(args.output),
            revision=str(args.revision),
            harness_revision=(
                str(args.harness_revision) if args.harness_revision is not None else None
            ),
        )
    if command == "eval-run-semantic":
        return run_semantic_workset_evaluation(
            bundle=cast_path(args.bundle),
            output=cast_path(args.output),
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            embedding_artifact=cast_path(args.embedding_artifact),
            revision=str(args.revision),
            harness_revision=(
                str(args.harness_revision) if args.harness_revision is not None else None
            ),
        )
    if command == "eval-run-candidate":
        return run_sandboxed_candidate(
            bundle=cast_path(args.bundle),
            output=cast_path(args.output),
            candidate_id=str(args.candidate),
            runtime=cast_path(args.runtime),
            checkout=cast_path(args.checkout),
            timeout_seconds=int(args.timeout),
        )
    if command == "eval-score":
        answer_key_argument = str(args.answer_key)
        if answer_key_argument == "-":
            scored = score_retrieval_run(run=cast_path(args.run), answer_key=sys.stdin)
        else:
            with Path(answer_key_argument).expanduser().open(encoding="utf-8") as answer_key:
                scored = score_retrieval_run(run=cast_path(args.run), answer_key=answer_key)
        if args.output:
            output = cast_path(args.output).expanduser()
            if output.exists() or output.is_symlink():
                raise ValueError(f"score output already exists: {output}")
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            output.write_text(json.dumps(scored, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            output.chmod(0o400)
            return {"status": "scored", "output": str(output), "aggregate": scored["aggregate"]}
        return scored
    if command == "eval-run-generated-answers":
        return run_generated_answer_evaluation(
            output=cast_path(args.output),
            base_url=str(args.base_url),
            model=str(args.model),
            expected_response_models=(
                tuple(str(item) for item in args.expected_response_model)
                if args.expected_response_model
                else None
            ),
            api_key_env=str(args.api_key_env),
            attempts=int(args.attempts),
            revision=str(args.revision),
            execute=bool(args.execute),
        )
    if command == "eval-verify-generated-answers":
        return verify_generated_answer_evaluation(
            cast_path(args.run),
            expected_manifest_sha256=str(args.manifest_sha256),
        )
    if command == "eval-run-exact-clients":
        return run_exact_client_evaluation(
            contract_path=cast_path(args.contract),
            output=cast_path(args.output),
            codex_bundled=cast_path(args.codex_bundled),
            codex_path=cast_path(args.codex_path),
            claude=cast_path(args.claude),
            grok=cast_path(args.grok),
            sandbox_exec=cast_path(args.sandbox_exec),
            revision=str(args.revision),
            execute=bool(args.execute),
        )
    if command == "eval-verify-exact-clients":
        return verify_exact_client_evaluation(
            cast_path(args.run),
            expected_manifest_sha256=str(args.manifest_sha256),
            contract_path=cast_path(args.contract),
            codex_bundled=cast_path(args.codex_bundled),
            codex_path=cast_path(args.codex_path),
            claude=cast_path(args.claude),
            grok=cast_path(args.grok),
        )
    if command == "serve":
        shadow_values = (
            args.shadow_runtime,
            args.shadow_checkout,
            args.shadow_projection_root,
        )
        if any(shadow_values) and not all(shadow_values):
            raise ValueError("shadow runtime, checkout, and projection root must be set together")
        if args.shadow_embedding_artifact is not None and not all(shadow_values):
            raise ValueError("shadow embedding artifact requires the complete shadow configuration")
        shadow = (
            ShadowSearchConfig(
                runtime=cast_path(args.shadow_runtime),
                checkout=cast_path(args.shadow_checkout),
                projection_root=cast_path(args.shadow_projection_root),
                embedding_artifact=cast_optional_path(args.shadow_embedding_artifact),
            )
            if all(shadow_values)
            else None
        )
        http_auth_url = (
            None
            if args.transport == "stdio"
            else loopback_http_auth_url(str(args.host), int(args.port))
        )
        server = create_mcp_server(
            settings,
            transport=cast(MCPTransport, str(args.transport)),
            principal=str(args.principal),
            read_only=bool(args.read_only),
            shadow=shadow,
            http_auth_url=http_auth_url,
            encrypted_evidence_reader=evidence.reader,
            evidence_publication_policy=evidence.publication_policy,
            evidence_text_max_bytes=args.evidence_text_max_bytes,
            search_text_max_bytes=args.search_text_max_bytes,
            memory_app=bool(args.memory_app),
        )
        if args.transport == "stdio":
            server.run("stdio")
        else:
            server.run(
                "streamable-http",
                host=str(args.host),
                port=int(args.port),
                streamable_http_path="/mcp",
                stateless_http=True,
                json_response=True,
            )
        return None
    if command == "panel":
        import uvicorn

        host = "127.0.0.1"
        listener, port = reserve_control_panel_listener(host)
        origin = loopback_panel_origin(host, port)
        app = create_control_panel_app(
            settings,
            host=host,
            port=port,
            encrypted_evidence_reader=evidence.reader,
            encrypted_evidence_purger=evidence.purger,
            evidence_publication_policy=evidence.publication_policy,
        )
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            access_log=False,
            log_level="warning",
            proxy_headers=False,
            server_header=False,
        )
        print(json.dumps({"status": "serving", "url": origin}), flush=True)
        try:
            uvicorn.Server(config).run(sockets=[listener])
        finally:
            listener.close()
        return None
    if command == "incremental-plan":
        path = cast_path(args.path)
        source_path = (
            str(args.source_path) if args.source_path else str(path.expanduser().resolve())
        )
        return build_incremental_ingestion_plan(
            path=path,
            output=cast_path(args.output),
            source_account=str(args.source_account),
            source_path=source_path,
            scope=Scope(str(args.scope)),
            project_id=args.project_id,
            start_record_ordinal=int(args.start_record_ordinal),
            start_byte_offset=int(args.start_byte_offset),
            expected_prefix_digest=args.expected_prefix_sha256,
            legacy_fork_replay_source_file_id=args.legacy_fork_replay_source_file_id,
            max_increment_bytes=int(args.max_increment_mb) * 1024 * 1024,
        )
    if command == "incremental-apply":
        return apply_incremental_ingestion_plan(
            settings,
            cast_path(args.plan),
            execute=bool(args.execute),
        )
    if command == "web-export-configuration-snapshot":
        require_runtime_code_revision(str(args.code_revision))
        return create_web_source_configuration_snapshot(
            settings,
            cast_path(args.output),
            source_account_id=str(args.source_account),
            expected_ledger_generation=str(args.expected_ledger_generation),
        )
    if command == "web-export-extract":
        return extract_web_export_member(
            archive_path=cast_path(args.archive_path),
            archive_member=str(args.archive_member),
            expected_archive_sha256=str(args.expected_archive_sha256),
            output=cast_path(args.output),
        )
    if command == "web-export-plan":
        member_paths = [cast_path(value) for value in args.member_path]
        archive_members = [str(value) for value in args.archive_member]
        if len(member_paths) != len(archive_members):
            raise ValueError("each --member-path requires one --archive-member")
        return prepare_web_export_plan(
            source_system=SourceSystem(str(args.source_system)),
            source_account=str(args.source_account),
            member_path=member_paths[0],
            archive_path=cast_path(args.archive_path),
            archive_member=archive_members[0],
            additional_member_paths=tuple(member_paths[1:]),
            additional_archive_members=tuple(archive_members[1:]),
            output=cast_path(args.output),
            scope=Scope(str(args.scope)),
            project_id=args.project_id,
            expected_ledger_generation=str(args.expected_ledger_generation),
            code_revision=str(args.code_revision),
            max_record_bytes=int(args.max_record_mb) * 1024 * 1024,
            source_client_version=str(args.source_client_version),
        )
    if command == "web-export-verify":
        return verify_web_export_plan(
            manifest_path=cast_path(args.manifest),
            expected_manifest_sha256=str(args.manifest_sha256),
            code_revision=str(args.code_revision),
        )
    if command == "web-export-authorize":
        return authorize_web_export_schema(
            settings,
            manifest_path=cast_path(args.manifest),
            expected_manifest_sha256=str(args.manifest_sha256),
            code_revision=str(args.code_revision),
            authorized_by=str(args.authorized_by),
            execute=bool(args.execute),
            offline_clone=bool(args.offline_clone),
            authoritative_node=args.authoritative_node,
            reviewed_clone=args.reviewed_clone,
            review_code_revision=args.review_code_revision,
            expected_ledger_generation=args.expected_ledger_generation,
        )
    if command == "web-schema-revoke":
        return revoke_web_schema_authorization(
            settings,
            authoritative_node=cast_path(args.authoritative_node),
            source_account_id=str(args.source_account),
            authorization_id=str(args.authorization_id),
            expected_ledger_generation=str(args.expected_ledger_generation),
            code_revision=str(args.code_revision),
            execute=bool(args.execute),
        )
    if command == "web-export-apply":
        manifest_values = cast(object, args.manifest)
        digest_values = cast(object, args.manifest_sha256)
        if not isinstance(manifest_values, list):
            raise ValueError("manifest arguments were not parsed as paths")
        if not isinstance(digest_values, list):
            raise ValueError("manifest SHA-256 arguments were not parsed as strings")
        manifest_paths: list[Path] = []
        for item in cast(list[object], manifest_values):
            if not isinstance(item, Path):
                raise ValueError("manifest arguments were not parsed as paths")
            manifest_paths.append(item)
        manifest_digests: list[str] = []
        for item in cast(list[object], digest_values):
            if not isinstance(item, str):
                raise ValueError("manifest SHA-256 arguments were not parsed as strings")
            manifest_digests.append(item)
        return apply_web_export_plans(
            settings,
            manifest_paths=manifest_paths,
            expected_manifest_sha256s=manifest_digests,
            code_revision=str(args.code_revision),
            execute=bool(args.execute),
            offline_clone=bool(args.offline_clone),
            encrypted_evidence_reader=evidence.reader,
            evidence_publication_policy=evidence.publication_policy,
            authoritative_node=args.authoritative_node,
        )
    if command == "web-export-assist-status":
        return inspect_assisted_web_exports(settings)
    if command == "web-export-assist-record":
        return record_assisted_web_export_event(
            settings,
            source_system=SourceSystem(str(args.source_system)),
            source_account_id=str(args.source_account),
            scope=Scope(str(args.scope)),
            project_id=args.project_id,
            event=WebExportAssistEvent(str(args.event)),
            occurred_at=(
                _parse_rfc3339(str(args.occurred_at), "occurred-at") if args.occurred_at else None
            ),
            pause_reason=(
                WebExportPauseReason(str(args.pause_reason)) if args.pause_reason else None
            ),
            archive_sha256=args.archive_sha256,
            manifest_sha256=args.manifest_sha256,
            execute=bool(args.execute),
        )
    if command == "collector-detect":
        previews = discover_native_sources(cast_path(args.user_home))
        return {
            "status": "preview",
            "content_opened": False,
            "sources": [preview.as_dict() for preview in previews],
        }
    if command == "collector-config-validate":
        sources = load_native_source_opt_ins(cast_path(args.config))
        return {
            "status": "valid",
            "source_count": len(sources),
            "sources": [
                {
                    "source_system": source.source_system.value,
                    "root": str(source.root),
                    "source_client_version": source.source_client_version,
                    "excluded_file_count": len(source.excluded_files),
                    "initial_selection_count": len(source.initial_selections),
                }
                for source in sources
            ],
        }
    if command == "collector-sync":
        result = sync_collector(cast_path(args.config))
        if bool(args.quiet):
            if result["status"] in {"ok", "pending"}:
                return None
            return _quiet_collector_result(result)
        return result
    if command == "collector-status":
        return collector_status(cast_path(args.config))
    if command == "collector-retry":
        return retry_blocked_upload(cast_path(args.config), str(args.item_id))
    if command == "collector-enroll":
        return enroll_collector(
            str(args.url),
            cast_path(args.credential_output),
            enrollment_id=str(args.enrollment_id),
            device_label=str(args.device_label),
            device_platform=str(args.device_platform),
            execute=bool(args.execute),
            expected_plan_sha256=args.expected_plan_sha256,
            code_stream=sys.stdin.buffer,
        )
    if command == "collector-service-install":
        return install_collector_service(
            CollectorServicePlatform(str(args.platform)),
            cast_path(args.config),
            cast_path(args.executable),
            execute=bool(args.execute),
            expected_plan_sha256=args.expected_plan_sha256,
        )

    if command == "ingest":
        path = cast_path(args.path)
        source_system = SourceSystem(str(args.source_system))
        scope = Scope(str(args.scope))
        source_path = (
            str(args.source_path) if args.source_path else str(path.expanduser().resolve())
        )
        preview = {
            "status": "preview",
            "source_system": source_system.value,
            "path": str(path.expanduser()),
            "source_path": source_path,
            "size": path.expanduser().stat().st_size,
            "scope": scope.value,
            "project_id": args.project_id,
            "execute": bool(args.execute),
        }
        if not args.execute:
            return preview
        ledger = Ledger(
            settings,
            encrypted_evidence_reader=evidence.reader,
            encrypted_evidence_purger=evidence.purger,
            evidence_publication_policy=evidence.publication_policy,
            defer_initialization=settings.database_path.exists(),
        )
        report, consumed_bytes = ledger.ingest_native_file(
            path,
            source_system,
            source_account=str(args.source_account),
            scope=scope,
            project_id=args.project_id,
            source_path=source_path,
            max_file_bytes=int(args.max_file_mb) * 1024 * 1024,
        )
        return {
            **preview,
            "status": report.status,
            "consumed_bytes": consumed_bytes,
            "remaining_bytes": max(0, path.expanduser().stat().st_size - consumed_bytes),
            "source_file_id": report.source_file_id,
            "conversation_id": report.conversation_id,
            "inserted_events": report.inserted_events,
            "existing_events": report.existing_events,
            "quarantined_records": report.quarantined_records,
            "quarantine_reasons": report.quarantine_reasons,
        }

    if command == "evidence-publish" and args.execute and not args.discard_unregistered:
        if evidence.publication_policy is None:
            raise ValueError(
                "evidence-publish --execute requires a remote-primary evidence configuration"
            )
        return Ledger(
            settings,
            encrypted_evidence_reader=evidence.reader,
            encrypted_evidence_purger=evidence.purger,
            evidence_publication_policy=evidence.publication_policy,
        ).drain_evidence_publications()

    local_admin = ApplicationPrincipal.local_admin("local:cli")
    if command == "attachment-audit":
        return dict(
            Ledger(settings, read_only=True, require_checkpointed=False).audit_attachments(
                max_objects=int(args.max_objects), max_total_bytes=int(args.max_total_bytes)
            )
        )
    if command == "doctor":
        return _doctor(
            MemoryApplication(Ledger(settings, read_only=True, require_checkpointed=False)),
            local_admin,
        )
    if command == "operations-overview":
        return MemoryApplication(
            Ledger(settings, read_only=True, require_checkpointed=False)
        ).operations_overview(local_admin)
    if command == "administration":
        return MemoryApplication(
            Ledger(settings, read_only=True, require_checkpointed=False)
        ).administration(local_admin)
    if command == "candidate-state":
        return MemoryApplication(Ledger(settings, read_only=True)).candidate_review_state(
            local_admin,
            str(args.memory_id),
        )
    read_only = command in {"evidence", "evidence-publish"}
    wal_paths = [Path(f"{settings.database_path}{suffix}") for suffix in ("-wal", "-shm")]
    journal = Path(f"{settings.database_path}-journal")
    active_wal = (
        all(path.is_file() and not path.is_symlink() for path in wal_paths)
        and not journal.exists()
        and not journal.is_symlink()
    )
    ledger = Ledger(
        settings,
        read_only=read_only,
        require_checkpointed=not (read_only and active_wal),
        allow_schema_upgrade=command == "init",
        encrypted_evidence_reader=evidence.reader,
        encrypted_evidence_purger=evidence.purger,
    )
    if command == "evidence-publish":
        if args.discard_unregistered:
            preview = ledger.preview_unregistered_publication()
            if not args.execute:
                return preview
            with exclusive_ledger_writer(settings) as token:
                writer = Ledger(
                    settings,
                    exclusive_writer_token=token,
                    encrypted_evidence_reader=evidence.reader,
                )
                return writer.discard_unregistered_publication(
                    expected_generation_digest=str(preview["generation_digest"]),
                    authorized_by="local:cli",
                    authorization_scope="unregistered-local-publication-preparation",
                    reason="recover interrupted local preparation without publishing",
                    expected_preparation_scope_sha256=str(preview["preparation_scope_sha256"]),
                )
        return ledger.evidence_publication_status()
    application = MemoryApplication(ledger)
    if command == "init":
        return {"status": "initialized", **application.status(local_admin)}
    if command == "client-register":
        return application.register_client(
            local_admin,
            label=str(args.label),
            kind=ClientKind(str(args.kind)),
            capabilities=tuple(Capability(str(item)) for item in args.capability),
            intent_key=(str(args.intent_key) if args.intent_key is not None else None),
        )
    if command == "client-credential-issue":
        ttl_hours = int(args.ttl_hours)
        if ttl_hours <= 0 or ttl_hours > 24 * 365:
            raise ValueError("credential TTL must be between 1 and 8760 hours")
        return application.issue_client_credential(
            local_admin,
            str(args.client_id),
            expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
        )
    if command == "client-credential-revoke":
        return application.revoke_client_credential(local_admin, str(args.credential_id))
    if command == "device-enrollment-create":
        ttl_minutes = int(args.ttl_minutes)
        credential_ttl_days = int(args.credential_ttl_days)
        if ttl_minutes <= 0 or ttl_minutes > 60:
            raise ValueError("enrollment TTL must be between 1 and 60 minutes")
        if credential_ttl_days <= 0 or credential_ttl_days > 365:
            raise ValueError("device credential TTL must be between 1 and 365 days")
        now = datetime.now(UTC)
        return application.create_device_enrollment(
            local_admin,
            CreateDeviceEnrollmentRequest(
                label=str(args.label),
                platform=str(args.platform),
                expires_at=now + timedelta(minutes=ttl_minutes),
                credential_expires_at=now + timedelta(days=credential_ttl_days),
            ),
        )
    if command == "source-account-register":
        return application.register_source_account(
            local_admin,
            RegisterSourceAccountRequest(
                device_id=str(args.device_id),
                source_system=SourceSystem(str(args.source_system)),
                account_label=str(args.account_label),
                scope=Scope(str(args.scope)),
                project_id=(str(args.project_id) if args.project_id is not None else None),
            ),
        )
    if command == "search":
        scopes = (
            [Scope(item) for item in args.scope]
            if args.scope
            else [Scope.USER_GLOBAL, Scope.PROJECT]
        )
        authorities = [Authority(item) for item in args.authority] if args.authority else None
        return application.search(
            local_admin,
            SearchMemoryRequest(
                query=str(args.query),
                mode=QueryMode(str(args.mode)),
                scopes=tuple(scopes),
                project_id=args.project_id,
                authorities=tuple(authorities) if authorities is not None else None,
                limit=int(args.limit),
                contexts=tuple(args.context or ()),
                retrieval_control=RetrievalControl(str(args.retrieval_control)),
            ),
        )
    if command == "evidence":
        return application.get_evidence(local_admin, str(args.event_id))
    if command == "propose":
        return application.propose(
            local_admin,
            ProposeMemoryRequest(
                statement=str(args.statement),
                memory_type=MemoryType(str(args.memory_type)),
                evidence_event_ids=tuple(str(item) for item in (args.evidence_event or ())),
                scope=Scope(str(args.scope)),
                project_id=args.project_id,
                created_by=local_admin.principal_id,
                pending_web_evidence=pending_web_evidence_claim(
                    source_account_id=args.web_source_account_id,
                    source_system=args.web_source_system,
                    conversation_id=args.web_conversation_id,
                    message_id=args.web_message_id,
                    parent_message_id=args.web_parent_message_id,
                    branch_id=args.web_branch_id,
                    content_text=args.web_evidence_content,
                ),
            ),
        )
    if command == "candidate-review":
        return application.review_candidate(
            local_admin,
            ReviewMemoryCandidateRequest(
                memory_id=str(args.memory_id),
                operation=CandidateReviewOperation(str(args.operation)),
                expected_basis_digest=str(args.expected_basis_digest),
                reason_code=CandidateReviewReason(str(args.reason_code)),
            ),
        )
    raise ValueError(f"unknown command: {command}")


def _quiet_collector_result(result: dict[str, object]) -> dict[str, object]:
    # Scheduled attention logs must not repeat the entire growing source inventory.
    summary = dict(result)
    for field in (
        "source_attention",
        "missing_sources",
        "selection_conflicts",
        "missing_selected_files",
    ):
        values = result.get(field)
        if isinstance(values, list):
            items = cast(list[object], values)
            summary[field] = items[:10]
            summary[f"{field}_count"] = len(items)
    queue = result.get("queue")
    if isinstance(queue, dict):
        counts = dict(cast(dict[str, object], queue))
        sources = counts.pop("sources", None)
        if isinstance(sources, list):
            source_rows = cast(list[dict[str, object]], sources)
            counts["source_count"] = len(source_rows)
            replay = [source for source in source_rows if source.get("replay_required") is True]
            counts["replay_required_sources"] = replay[:10]
            counts["replay_required_source_count"] = len(replay)
        selections = counts.pop("initial_selections", None)
        if isinstance(selections, dict):
            counts["initial_selection_count"] = len(cast(dict[str, object], selections))
        attention = counts.get("attention_items")
        if isinstance(attention, list):
            items = cast(list[object], attention)
            counts["attention_items"] = items[:10]
            counts["attention_items_count"] = len(items)
        summary["queue"] = counts
    return summary


def _doctor(
    application: MemoryApplication,
    principal: ApplicationPrincipal,
) -> dict[str, Any]:
    fts_ready = False
    with sqlite3.connect(":memory:") as connection:
        try:
            connection.execute("CREATE VIRTUAL TABLE probe USING fts5(value)")
            fts_ready = True
        except sqlite3.Error:
            pass
    return {
        "status": "ready" if fts_ready else "blocked",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version,
        "sqlite_fts5": fts_ready,
        "mcp_sdk": importlib.metadata.version("mcp"),
        "ledger": application.status(principal),
    }


def loopback_http_auth_url(host: str, port: int) -> str:
    if port < 1 or port > 65535:
        raise ValueError("MCP HTTP port must be between 1 and 65535")
    if host == "localhost":
        authority = host
    else:
        try:
            address = ip_address(host)
        except ValueError as error:
            raise ValueError("MCP HTTP host must be a loopback IP address or localhost") from error
        if not address.is_loopback:
            raise ValueError(
                "non-loopback MCP HTTP requires the future approved OAuth-fronted HTTPS profile"
            )
        authority = f"[{host}]" if address.version == 6 else host
    return f"http://{authority}:{port}/mcp"


def _enum_values(enum_type: type[EnumT]) -> tuple[str, ...]:
    return tuple(item.value for item in enum_type)


def _add_identity_setup_apply_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--execute", action="store_true")


def _parse_context_filter(value: str) -> ContextFilter:
    kind, separator, key = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("context must use KIND=KEY")
    try:
        return ContextFilter(kind=ContextKind(kind), key=key)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _parse_rfc3339(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _add_shadow_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--projection-root", type=Path, required=True)
    parser.add_argument("--embedding-artifact", type=Path)


def cast_path(value: object) -> Path:
    if not isinstance(value, Path):
        raise ValueError("path argument was not parsed as a path")
    return value


def cast_optional_path(value: object) -> Path | None:
    if value is None:
        return None
    return cast_path(value)
