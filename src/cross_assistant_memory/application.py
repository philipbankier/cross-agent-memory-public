from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cross_assistant_memory.deletion import (
    apply_deletion_plan_value,
    create_deletion_plan,
)
from cross_assistant_memory.models import (
    CLIENT_KIND_CAPABILITIES,
    MAX_PENDING_EVIDENCE_ID_BYTES,
    MAX_PROPOSAL_EVENT_ID_BYTES,
    MAX_PROPOSAL_EVIDENCE_EVENTS,
    MAX_PROPOSAL_STATEMENT_BYTES,
    Access,
    Authority,
    CandidateReviewOperation,
    CandidateReviewReason,
    Capability,
    ClientKind,
    ContextFilter,
    DeletionKind,
    EventCorrection,
    MemoryType,
    ObservationRetirement,
    PendingWebEvidenceClaim,
    Privacy,
    QueryMode,
    RetrievalControl,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.projection import search_shadow_projection
from cross_assistant_memory.recovery_status import inspect_recovery_status
from cross_assistant_memory.retrieval import effective_context_filters, suppressed_workset
from cross_assistant_memory.storage import Ledger, event_state_digest
from cross_assistant_memory.uploads import UploadBatch
from cross_assistant_memory.web_export_assistant import inspect_assisted_web_exports

CORRECTION_PLAN_FORMAT_VERSION = 1
NATIVE_SOURCE_SYSTEMS = frozenset(
    {SourceSystem.CODEX, SourceSystem.CLAUDE_CODE, SourceSystem.GROK_BUILD}
)
WEB_SOURCE_SYSTEMS = frozenset(
    {SourceSystem.CHATGPT_WEB, SourceSystem.CLAUDE_WEB, SourceSystem.GROK_WEB}
)


@dataclass(frozen=True)
class ApplicationPrincipal:
    principal_id: str
    kind: ClientKind
    capabilities: frozenset[Capability]
    device_id: str | None = None

    def __post_init__(self) -> None:
        if not self.principal_id.strip():
            raise ValueError("application principal id is required")
        if not self.capabilities:
            raise ValueError("application principal requires at least one capability")
        disallowed = self.capabilities - CLIENT_KIND_CAPABILITIES[self.kind]
        if disallowed:
            values = ", ".join(sorted(item.value for item in disallowed))
            raise ValueError(f"{self.kind.value} principal cannot receive capabilities: {values}")

    @classmethod
    def local_admin(cls, principal_id: str) -> ApplicationPrincipal:
        return cls(
            principal_id=principal_id,
            kind=ClientKind.LOCAL_ADMIN,
            capabilities=CLIENT_KIND_CAPABILITIES[ClientKind.LOCAL_ADMIN],
        )


@dataclass(frozen=True)
class SearchMemoryRequest:
    query: str
    mode: QueryMode
    scopes: tuple[Scope, ...]
    project_id: str | None
    authorities: tuple[Authority, ...] | None
    limit: int
    contexts: tuple[ContextFilter, ...] = ()
    retrieval_control: RetrievalControl = RetrievalControl.AUTO


@dataclass(frozen=True)
class ProposeMemoryRequest:
    statement: str
    memory_type: MemoryType
    evidence_event_ids: tuple[str, ...]
    scope: Scope
    project_id: str | None
    created_by: str
    pending_web_evidence: PendingWebEvidenceClaim | None = None


@dataclass(frozen=True)
class CreateDeviceEnrollmentRequest:
    label: str
    platform: str
    expires_at: datetime
    credential_expires_at: datetime


@dataclass(frozen=True)
class RegisterSourceAccountRequest:
    device_id: str
    source_system: SourceSystem
    account_label: str
    scope: Scope
    project_id: str | None


@dataclass(frozen=True)
class DeletionPlanRequest:
    kind: DeletionKind
    source_system: SourceSystem
    source_account: str
    conversation_id: str | None
    authorization_scope: str
    reason: str
    retirement_pairs: tuple[ObservationRetirement, ...] = ()


@dataclass(frozen=True)
class CorrectionPlanRequest:
    event_id: str
    authority: Authority
    scope: Scope
    project_id: str | None
    privacy: Privacy
    authorization_scope: str
    reason: str


@dataclass(frozen=True)
class ApplyEventCorrectionsRequest:
    corrections: tuple[EventCorrection, ...]
    expected_generation_digest: str
    authorization_scope: str
    reason: str


@dataclass(frozen=True)
class ReviewMemoryCandidateRequest:
    memory_id: str
    operation: CandidateReviewOperation
    expected_basis_digest: str
    reason_code: CandidateReviewReason


@dataclass(frozen=True)
class ShadowSearchConfig:
    runtime: Path
    checkout: Path
    projection_root: Path
    embedding_artifact: Path | None = None


def pending_web_evidence_claim(
    *,
    source_account_id: str | None,
    source_system: str | None,
    conversation_id: str | None,
    message_id: str | None,
    parent_message_id: str | None,
    branch_id: str | None,
    content_text: str | None,
) -> PendingWebEvidenceClaim | None:
    values = (
        source_account_id,
        source_system,
        conversation_id,
        message_id,
        parent_message_id,
        branch_id,
        content_text,
    )
    if all(value is None for value in values):
        return None
    required = (source_account_id, source_system, conversation_id, message_id, content_text)
    if any(value is None for value in required):
        raise ValueError("a pending web evidence claim requires its complete exact identity")
    parsed_source_system = SourceSystem(cast(str, source_system))
    if parsed_source_system not in {
        SourceSystem.CHATGPT_WEB,
        SourceSystem.CLAUDE_WEB,
        SourceSystem.GROK_WEB,
    }:
        raise ValueError("pending web evidence requires an official web source")
    return PendingWebEvidenceClaim(
        source_account_id=_canonical_bounded_value(
            cast(str, source_account_id),
            "pending web source account id",
            256,
        ),
        source_system=parsed_source_system,
        conversation_id=_canonical_bounded_value(
            cast(str, conversation_id),
            "pending web conversation id",
            MAX_PENDING_EVIDENCE_ID_BYTES,
        ),
        message_id=_canonical_bounded_value(
            cast(str, message_id),
            "pending web message id",
            MAX_PENDING_EVIDENCE_ID_BYTES,
        ),
        parent_message_id=(
            _canonical_bounded_value(
                parent_message_id,
                "pending web parent message id",
                MAX_PENDING_EVIDENCE_ID_BYTES,
            )
            if parent_message_id is not None
            else None
        ),
        branch_id=(
            _canonical_bounded_value(
                branch_id,
                "pending web branch id",
                MAX_PENDING_EVIDENCE_ID_BYTES,
            )
            if branch_id is not None
            else None
        ),
        content_text=_exact_bounded_text(
            cast(str, content_text),
            "pending web evidence content",
            MAX_PROPOSAL_STATEMENT_BYTES,
        ),
    )


def _canonical_bounded_value(value: object, field: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\0" in value:
        raise ValueError(f"{field} is invalid")
    if len(value.encode()) > max_bytes:
        raise ValueError(f"{field} exceeds its size limit")
    return value


def _exact_bounded_text(value: str, field: str, max_bytes: int) -> str:
    if not value.strip() or "\0" in value:
        raise ValueError(f"{field} is invalid")
    if len(value.encode()) > max_bytes:
        raise ValueError(f"{field} exceeds its size limit")
    return value


def _sha256_value(value: dict[str, Any]) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def correction_plan_authorized_by(plan: dict[str, Any]) -> str:
    authorization = plan.get("authorization")
    if not isinstance(authorization, dict):
        raise ValueError("correction plan authorization is invalid")
    authorized_by = cast(dict[str, object], authorization).get("authorized_by")
    if not isinstance(authorized_by, str):
        raise ValueError("correction plan authorization is invalid")
    return _canonical_bounded_value(
        authorized_by,
        "correction principal",
        1024,
    )


def _required_digest(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} is invalid")
    return value


def _validated_policy(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} is invalid")
    policy = cast(dict[str, object], value)
    if set(policy) != {"authority", "scope", "project_id", "privacy"}:
        raise ValueError(f"{field} is invalid")
    for key in ("authority", "scope", "privacy"):
        if not isinstance(policy[key], str):
            raise ValueError(f"{field} is invalid")
    authority = Authority(cast(str, policy["authority"]))
    scope = Scope(cast(str, policy["scope"]))
    privacy = Privacy(cast(str, policy["privacy"]))
    project_value = policy["project_id"]
    if project_value is not None and not isinstance(project_value, str):
        raise ValueError(f"{field} is invalid")
    project_id = (
        None
        if project_value is None
        else _canonical_bounded_value(
            project_value,
            f"{field} project id",
            512,
        )
    )
    if scope is Scope.PROJECT and project_id is None:
        raise ValueError(f"{field} requires a project id")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError(f"{field} cannot carry a project id")
    return {
        "authority": authority.value,
        "scope": scope.value,
        "project_id": project_id,
        "privacy": privacy.value,
    }


def _source_operations_views(
    sources: list[dict[str, Any]],
    assisted_exports: dict[str, Any],
) -> list[dict[str, Any]]:
    web_sources: dict[str, list[dict[str, Any]]] = {}
    for value in assisted_exports["sources"]:
        item = cast(dict[str, Any], value)
        web_sources.setdefault(cast(str, item["source_system"]), []).append(item)

    views: list[dict[str, Any]] = []
    for source in sources:
        source_system = SourceSystem(cast(str, source["source_system"]))
        active_accounts = cast(int, source["active_accounts"])
        registered_accounts = cast(int, source["registered_accounts"])
        source_files = cast(int, source["source_files"])
        attention_required = False

        if registered_accounts == 0:
            if source_files:
                sync_state = "historical_only"
                status_source = "node_observation"
            elif active_accounts:
                sync_state = "registration_incomplete"
                status_source = "registration"
                attention_required = True
            else:
                sync_state = "not_configured"
                status_source = "node_observation"
        elif source_system in NATIVE_SOURCE_SYSTEMS:
            if cast(int, source["upload_batches"]):
                sync_state = "upload_observed"
                status_source = "central_upload_receipt"
            else:
                sync_state = "status_unavailable"
                status_source = "registration_only"
                attention_required = True
        elif source_system in WEB_SOURCE_SYSTEMS:
            summaries = web_sources.get(source_system.value, [])
            if not summaries:
                sync_state = "status_unavailable"
                attention_required = True
            elif any(item["blocking_reason"] is not None for item in summaries):
                sync_state = "blocked"
                attention_required = True
            elif any(item["next_action"] != "wait" for item in summaries):
                sync_state = "action_required"
                attention_required = True
            else:
                sync_state = "scheduled"
            status_source = "assisted_export_workflow"
        else:  # pragma: no cover - SourceSystem is exhaustive
            raise RuntimeError("source system has no operations status policy")

        views.append(
            {
                **source,
                "state": "available" if source["state"] == "ready" else source["state"],
                "sync": {
                    "state": sync_state,
                    "status_source": status_source,
                    "attention_required": attention_required,
                    "freshness_guaranteed": False,
                    "unmanaged_account_count": max(0, active_accounts - registered_accounts),
                    "expected_cadence_minutes": (
                        15 if source_system in NATIVE_SOURCE_SYSTEMS else None
                    ),
                    "request_cadence_days": (
                        cast(int, assisted_exports["cadence_days"])
                        if source_system in WEB_SOURCE_SYSTEMS
                        else None
                    ),
                },
            }
        )
    return views


class MemoryApplication:
    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    @staticmethod
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def authenticate_token(self, token: str) -> ApplicationPrincipal | None:
        verified = self._ledger.verify_client_token(token)
        if verified is None:
            return None
        return ApplicationPrincipal(
            principal_id=verified.client_id,
            kind=verified.kind,
            capabilities=frozenset(verified.capabilities),
            device_id=verified.device_id,
        )

    def search(
        self,
        principal: ApplicationPrincipal,
        request: SearchMemoryRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_SEARCH)
        if request.retrieval_control is RetrievalControl.SUPPRESS:
            return suppressed_workset(
                mode=request.mode,
                contexts=effective_context_filters(request.contexts, request.project_id),
            )
        return self._ledger.retrieve_workset(
            request.query,
            mode=request.mode,
            scopes=request.scopes,
            contexts=request.contexts,
            project_id=request.project_id,
            authorities=request.authorities,
            accesses=self._allowed_accesses(principal),
            limit=request.limit,
            control=request.retrieval_control,
            principal=principal.principal_id,
        )

    def search_shadow(
        self,
        principal: ApplicationPrincipal,
        request: SearchMemoryRequest,
        config: ShadowSearchConfig,
    ) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_SEARCH)
        return search_shadow_projection(
            self._ledger.settings,
            request.query,
            runtime=config.runtime,
            checkout=config.checkout,
            projection_root=config.projection_root,
            mode=request.mode,
            scopes=list(request.scopes),
            contexts=request.contexts,
            project_id=request.project_id,
            authorities=(list(request.authorities) if request.authorities is not None else None),
            accesses=list(self._allowed_accesses(principal)),
            limit=request.limit,
            control=request.retrieval_control,
            principal=principal.principal_id,
            embedding_artifact=config.embedding_artifact,
            require_checkpointed=self._ledger.read_only and self._ledger.require_checkpointed,
            encrypted_evidence_reader=self._ledger.encrypted_evidence_reader,
        )

    def get_evidence(
        self,
        principal: ApplicationPrincipal,
        event_id: str,
        *,
        include_context: bool = False,
    ) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_EVIDENCE_READ)
        return self._ledger.get_evidence(
            event_id,
            allowed_accesses=self._allowed_accesses(principal),
            include_context=include_context,
        )

    def propose(
        self,
        principal: ApplicationPrincipal,
        request: ProposeMemoryRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_PROPOSE_WRITE)
        _canonical_bounded_value(
            request.statement,
            "proposal statement",
            MAX_PROPOSAL_STATEMENT_BYTES,
        )
        if len(request.evidence_event_ids) > MAX_PROPOSAL_EVIDENCE_EVENTS:
            raise ValueError("proposal evidence count exceeds its limit")
        if len(request.evidence_event_ids) != len(set(request.evidence_event_ids)):
            raise ValueError("proposal evidence ids contain duplicates")
        for event_id in request.evidence_event_ids:
            _canonical_bounded_value(
                event_id,
                "proposal evidence event id",
                MAX_PROPOSAL_EVENT_ID_BYTES,
            )
        if request.scope is Scope.PROJECT:
            if request.project_id is None:
                raise ValueError("project_id is required for project-scoped memory")
            _canonical_bounded_value(request.project_id, "proposal project id", 512)
        elif request.project_id is not None:
            raise ValueError("only project-scoped memory may carry project_id")
        if request.pending_web_evidence is not None:
            claim = request.pending_web_evidence
            pending_web_evidence_claim(
                source_account_id=claim.source_account_id,
                source_system=claim.source_system.value,
                conversation_id=claim.conversation_id,
                message_id=claim.message_id,
                parent_message_id=claim.parent_message_id,
                branch_id=claim.branch_id,
                content_text=claim.content_text,
            )
        if request.created_by != principal.principal_id:
            raise PermissionError("proposal creator must match the authenticated principal")
        allowed_accesses = self._allowed_accesses(principal)
        for event_id in request.evidence_event_ids:
            self._ledger.get_evidence(event_id, allowed_accesses=allowed_accesses)
        return self._ledger.propose_memory(
            statement=request.statement,
            memory_type=request.memory_type,
            scope=request.scope,
            evidence_event_ids=request.evidence_event_ids,
            project_id=request.project_id,
            created_by=request.created_by,
            pending_web_evidence=request.pending_web_evidence,
            allowed_accesses=allowed_accesses,
            proposer_principal=principal.principal_id,
            proposer_kind=principal.kind,
        )

    def candidate_review_state(
        self,
        principal: ApplicationPrincipal,
        memory_id: str,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.candidate_review_state(memory_id)

    def review_candidate(
        self,
        principal: ApplicationPrincipal,
        request: ReviewMemoryCandidateRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        if principal.kind is not ClientKind.LOCAL_ADMIN:
            raise PermissionError("candidate review requires a local administrator")
        return self._ledger.review_memory_candidate(
            request.memory_id,
            operation=request.operation,
            expected_basis_digest=request.expected_basis_digest,
            reason_code=request.reason_code,
            authorized_by=principal.principal_id,
            authorization_scope="memory:curate",
        )

    def plan_event_policy_correction(
        self,
        principal: ApplicationPrincipal,
        request: CorrectionPlanRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        event_id = _canonical_bounded_value(request.event_id, "correction event id", 256)
        authorization_scope = _canonical_bounded_value(
            request.authorization_scope,
            "correction authorization scope",
            1024,
        )
        if authorization_scope != "memory:curate":
            raise PermissionError("event correction requires memory:curate authorization")
        reason = _canonical_bounded_value(request.reason, "correction reason", 1024)
        target_policy = _validated_policy(
            {
                "authority": request.authority.value,
                "scope": request.scope.value,
                "project_id": request.project_id,
                "privacy": request.privacy.value,
            },
            "target policy",
        )
        state, generation = self._ledger.event_state_with_generation(event_id)
        previous_policy = {
            key: state[key] for key in ("authority", "scope", "project_id", "privacy")
        }
        if target_policy == previous_policy:
            raise ValueError("correction does not change event policy")
        target_state = {
            key: state[key]
            for key in (
                "event_type",
                "actor_kind",
                "assistant",
                "authority",
                "scope",
                "project_id",
                "privacy",
                "content_digest",
                "content_text",
                "parser_version",
            )
        }
        target_state.update(target_policy)
        plan = {
            "format_version": CORRECTION_PLAN_FORMAT_VERSION,
            "text_free": True,
            "created_at": datetime.now(UTC).isoformat(),
            "event_id": event_id,
            "expected_generation_digest": generation,
            "expected_state_digest": state["state_digest"],
            "target_state_digest": event_state_digest(target_state),
            "previous_policy": previous_policy,
            "target_policy": target_policy,
            "authorization": {
                "authorized_by": principal.principal_id,
                "authorization_scope": authorization_scope,
                "reason": reason,
            },
        }
        return {
            "status": "planned",
            "plan": plan,
            "plan_sha256": _sha256_value(plan),
            "event_id": event_id,
            "previous_policy": previous_policy,
            "target_policy": target_policy,
            "text_free": True,
        }

    def apply_event_policy_correction(
        self,
        principal: ApplicationPrincipal,
        *,
        plan: dict[str, Any],
        expected_plan_sha256: str,
        execute: bool,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        _required_digest(expected_plan_sha256, "expected correction plan")
        actual_plan_sha256 = _sha256_value(plan)
        if actual_plan_sha256 != expected_plan_sha256:
            raise RuntimeError("correction plan digest does not match the approved plan")
        if set(plan) != {
            "format_version",
            "text_free",
            "created_at",
            "event_id",
            "expected_generation_digest",
            "expected_state_digest",
            "target_state_digest",
            "previous_policy",
            "target_policy",
            "authorization",
        }:
            raise ValueError("correction plan has an invalid shape")
        if (
            isinstance(plan["format_version"], bool)
            or plan["format_version"] != CORRECTION_PLAN_FORMAT_VERSION
            or plan["text_free"] is not True
        ):
            raise ValueError("correction plan version is invalid")
        created_at = _canonical_bounded_value(
            cast(str, plan["created_at"]),
            "correction plan creation time",
            128,
        )
        parsed_created_at = datetime.fromisoformat(created_at)
        if parsed_created_at.tzinfo is None or parsed_created_at.utcoffset() is None:
            raise ValueError("correction plan creation time is invalid")
        event_id = _canonical_bounded_value(
            cast(str, plan["event_id"]),
            "correction event id",
            256,
        )
        expected_generation = _required_digest(
            plan["expected_generation_digest"],
            "expected correction ledger generation",
        )
        expected_state = _required_digest(
            plan["expected_state_digest"],
            "expected correction event state",
        )
        target_state_digest = _required_digest(
            plan["target_state_digest"],
            "target correction event state",
        )
        previous_policy = _validated_policy(plan["previous_policy"], "previous policy")
        target_policy = _validated_policy(plan["target_policy"], "target policy")
        authorization_value = plan["authorization"]
        if not isinstance(authorization_value, dict):
            raise ValueError("correction authorization is invalid")
        authorization = cast(dict[str, object], authorization_value)
        if set(authorization) != {"authorized_by", "authorization_scope", "reason"}:
            raise ValueError("correction authorization is invalid")
        authorized_by = _canonical_bounded_value(
            cast(str, authorization["authorized_by"]),
            "correction principal",
            1024,
        )
        if authorized_by != principal.principal_id:
            raise PermissionError("correction plan belongs to another principal")
        authorization_scope = _canonical_bounded_value(
            cast(str, authorization["authorization_scope"]),
            "correction authorization scope",
            1024,
        )
        if authorization_scope != "memory:curate":
            raise PermissionError("event correction requires memory:curate authorization")
        reason = _canonical_bounded_value(
            cast(str, authorization["reason"]),
            "correction reason",
            1024,
        )
        state = self._ledger.event_state(event_id)
        if state["state_digest"] != expected_state:
            raise RuntimeError("event changed after the correction plan was created")
        actual_previous_policy = {
            key: state[key] for key in ("authority", "scope", "project_id", "privacy")
        }
        if previous_policy != actual_previous_policy:
            raise RuntimeError("correction plan previous policy does not match the event")
        target_state = {
            key: state[key]
            for key in (
                "event_type",
                "actor_kind",
                "assistant",
                "authority",
                "scope",
                "project_id",
                "privacy",
                "content_digest",
                "content_text",
                "parser_version",
            )
        }
        target_state.update(target_policy)
        if event_state_digest(target_state) != target_state_digest:
            raise RuntimeError("correction target state does not match the approved plan")
        preview = {
            "status": "preview",
            "execute": execute,
            "plan_sha256": actual_plan_sha256,
            "event_id": event_id,
            "expected_generation_digest": expected_generation,
            "previous_policy": previous_policy,
            "target_policy": target_policy,
            "text_free": True,
        }
        if not execute:
            return preview
        correction = EventCorrection(
            event_id=event_id,
            expected_state_digest=expected_state,
            event_type=cast(str, state["event_type"]),
            actor_kind=cast(str, state["actor_kind"]),
            assistant=cast(str | None, state["assistant"]),
            authority=Authority(cast(str, target_policy["authority"])),
            scope=Scope(cast(str, target_policy["scope"])),
            project_id=cast(str | None, target_policy["project_id"]),
            privacy=Privacy(cast(str, target_policy["privacy"])),
            content_text=cast(str, state["content_text"]),
            parser_version=cast(str, state["parser_version"]),
            reason=reason,
        )
        result = self.apply_event_corrections(
            principal,
            ApplyEventCorrectionsRequest(
                corrections=(correction,),
                expected_generation_digest=expected_generation,
                authorization_scope=authorization_scope,
                reason=reason,
            ),
        )
        return {**preview, **result, "execute": True}

    def apply_event_corrections(
        self,
        principal: ApplicationPrincipal,
        request: ApplyEventCorrectionsRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return Ledger(self._ledger.settings).apply_event_corrections(
            request.corrections,
            expected_generation_digest=request.expected_generation_digest,
            authorized_by=principal.principal_id,
            authorization_scope=request.authorization_scope,
            reason=request.reason,
        )

    def status(self, principal: ApplicationPrincipal) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_STATUS)
        return self._ledger.status(
            source_freshness_accesses=(
                self._allowed_accesses(principal)
                if Capability.MEMORY_SEARCH in principal.capabilities
                else None
            )
        )

    def operations_overview(self, principal: ApplicationPrincipal) -> dict[str, Any]:
        self._require(principal, Capability.MEMORY_STATUS)
        self._require(principal, Capability.CLIENT_ADMIN)
        snapshot = self._ledger.operations_snapshot()
        status = snapshot["status"]
        publication = snapshot["publication"]
        local_copies = snapshot["local_copies"]
        assisted_exports = inspect_assisted_web_exports(self._ledger.settings)
        sources = _source_operations_views(snapshot["sources"], assisted_exports)
        count_fields = (
            "devices",
            "source_accounts",
            "registered_source_accounts",
            "upload_batches",
            "active_source_schema_authorizations",
            "web_export_batches",
            "web_export_conversation_observations",
            "contexts",
            "clients",
            "active_client_credentials",
            "pending_device_enrollments",
            "source_streams",
            "source_files",
            "events",
            "quarantined_records",
            "memory_candidates",
            "pending_memory_evidence_claims",
            "reconciled_memory_evidence_claims",
            "event_corrections",
        )
        return {
            "status": (
                "attention_required"
                if (
                    any(source["sync"]["attention_required"] for source in sources)
                    or publication["pending_objects"]
                    or publication["registered_unverified_objects"]
                    or local_copies["missing_local_objects"]
                    or local_copies["uninspectable_objects"]
                    or local_copies["size_mismatch_objects"]
                )
                else "operational"
            ),
            "schema_version": status["schema_version"],
            "generation_digest": status["generation_digest"],
            "latest_ingested_at": status["latest_ingested_at"],
            "counts": {field: status[field] for field in count_fields},
            "sources": sources,
            "publication": publication,
            "local_copies": local_copies,
            "assisted_exports": {
                "status": assisted_exports["status"],
                "blocking_reason": assisted_exports["blocking_reason"],
                "cadence_days": assisted_exports["cadence_days"],
                "observed_at": assisted_exports["observed_at"],
                "registered_source_count": assisted_exports["registered_source_count"],
                "sources": [
                    {
                        field: source[field]
                        for field in (
                            "source_system",
                            "stage",
                            "blocking_reason",
                            "last_request_at",
                            "next_request_due_at",
                            "cadence_overdue",
                            "archive_verified",
                            "manifest_verified",
                            "next_action",
                            "requires_authenticated_ui",
                        )
                    }
                    for source in assisted_exports["sources"]
                ],
            },
            "retrieval": {
                "baseline": "sqlite_fts5",
                "optional_semantic": "disabled_by_default",
            },
            "telemetry": "off",
        }

    def assisted_web_exports(self, principal: ApplicationPrincipal) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return inspect_assisted_web_exports(self._ledger.settings)

    def administration(self, principal: ApplicationPrincipal) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        snapshot = self._ledger.administration_snapshot()
        snapshot["recovery"] = inspect_recovery_status(self._ledger.settings)
        return snapshot

    def register_client(
        self,
        principal: ApplicationPrincipal,
        *,
        label: str,
        kind: ClientKind,
        capabilities: tuple[Capability, ...],
        intent_key: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.register_client(
            label=label,
            kind=kind,
            capabilities=capabilities,
            intent_key=intent_key,
            expected_identity_state_sha256=expected_identity_state_sha256,
            expected_installation_id=expected_installation_id,
            authorized_by=principal.principal_id,
        )

    def issue_client_credential(
        self,
        principal: ApplicationPrincipal,
        client_id: str,
        *,
        expires_at: datetime,
        token: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
        require_existing: bool = False,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.issue_client_credential(
            client_id,
            expires_at=expires_at,
            token=token,
            expected_identity_state_sha256=expected_identity_state_sha256,
            expected_installation_id=expected_installation_id,
            require_existing=require_existing,
            authorized_by=principal.principal_id,
        )

    def revoke_client_credential(
        self,
        principal: ApplicationPrincipal,
        credential_id: str,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.revoke_client_credential(
            credential_id,
            authorized_by=principal.principal_id,
        )

    def create_device_enrollment(
        self,
        principal: ApplicationPrincipal,
        request: CreateDeviceEnrollmentRequest,
        *,
        code: str | None = None,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
        require_existing: bool = False,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.create_device_enrollment(
            label=request.label,
            platform=request.platform,
            expires_at=request.expires_at,
            credential_expires_at=request.credential_expires_at,
            created_by=principal.principal_id,
            code=code,
            expected_identity_state_sha256=expected_identity_state_sha256,
            expected_installation_id=expected_installation_id,
            require_existing=require_existing,
        )

    def redeem_device_enrollment(
        self,
        code: str,
        credential_token: str | None = None,
    ) -> dict[str, Any]:
        return self._ledger.redeem_device_enrollment(code, credential_token)

    def register_source_account(
        self,
        principal: ApplicationPrincipal,
        request: RegisterSourceAccountRequest,
        *,
        expected_identity_state_sha256: str | None = None,
        expected_installation_id: str | None = None,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return self._ledger.register_source_account(
            device_id=request.device_id,
            source_system=request.source_system,
            account_label=request.account_label,
            scope=request.scope,
            project_id=request.project_id,
            created_by=principal.principal_id,
            expected_identity_state_sha256=expected_identity_state_sha256,
            expected_installation_id=expected_installation_id,
        )

    def plan_deletion(
        self,
        principal: ApplicationPrincipal,
        request: DeletionPlanRequest,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        return create_deletion_plan(
            self._ledger.settings,
            kind=request.kind,
            source_system=request.source_system,
            source_account=request.source_account,
            conversation_id=request.conversation_id,
            authorized_by=principal.principal_id,
            authorization_scope=request.authorization_scope,
            reason=request.reason,
            encrypted_evidence_purger=self._ledger.encrypted_evidence_purger,
            retirement_pairs=request.retirement_pairs,
        )

    def apply_deletion(
        self,
        principal: ApplicationPrincipal,
        *,
        plan: dict[str, Any],
        expected_plan_sha256: str,
        execute: bool,
    ) -> dict[str, Any]:
        self._require(principal, Capability.CLIENT_ADMIN)
        authorization_value = plan.get("authorization")
        if not isinstance(authorization_value, dict):
            raise ValueError("deletion plan authorization is invalid")
        authorization = cast(dict[str, Any], authorization_value)
        if authorization.get("authorized_by") != principal.principal_id:
            raise PermissionError("deletion plan belongs to another principal")
        return apply_deletion_plan_value(
            self._ledger.settings,
            plan=plan,
            expected_plan_sha256=expected_plan_sha256,
            execute=execute,
            encrypted_evidence_purger=self._ledger.encrypted_evidence_purger,
        )

    def upload_batch(
        self,
        principal: ApplicationPrincipal,
        batch: UploadBatch,
    ) -> dict[str, Any]:
        self._require(principal, Capability.SOURCE_UPLOAD)
        if principal.device_id is None:
            raise PermissionError("source upload requires an enrolled device")
        return self._ledger.ingest_upload_batch(
            batch.parsed,
            batch_id=batch.batch_id,
            request_digest=batch.request_digest,
            source_account_id=batch.source_account_id,
            client_id=principal.principal_id,
            device_id=principal.device_id,
            source_path_hash=batch.source_path_hash,
            provenance=batch.provenance,
            exclusion_receipts=batch.exclusion_receipts,
            # Yield between objects; full-ledger integrity checks can dominate publication.
            max_publication_objects=1,
        )

    @staticmethod
    def _require(principal: ApplicationPrincipal, capability: Capability) -> None:
        if capability not in principal.capabilities:
            raise PermissionError(f"missing required capability: {capability.value}")

    @staticmethod
    def _allowed_accesses(principal: ApplicationPrincipal) -> tuple[Access, ...]:
        if principal.kind is ClientKind.LOCAL_ADMIN:
            return tuple(Access)
        return (Access.OWNER,)
