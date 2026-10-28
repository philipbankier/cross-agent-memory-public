from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from cross_assistant_memory.models import (
    ContextFilter,
    ContextKind,
    EvidenceRelation,
    QueryMode,
    RetrievalControl,
    SearchResult,
)

WORKSET_VERSION = 2
MAX_WORKSET_RESULTS = 20
MAX_WORKSET_CANDIDATES = 100
MAX_WORKSET_RELATIONS = 500
MAX_EVIDENCE_PREVIEW_CHARACTERS = 1200

_CURRENT_RELATIONS = frozenset({"correction", "supersession"})
_LEXICAL_TOKEN = re.compile(r"[^\W]+", re.UNICODE)
_ROLE_ORDER = {
    "primary": 0,
    "current_evidence": 1,
    "earliest_evidence": 2,
    "latest_evidence": 3,
    "minority_source": 4,
    "corrected_evidence": 5,
    "superseded_evidence": 6,
    "conflicting_evidence": 7,
    "source_variant": 8,
    "user_statement": 9,
    "assistant_suggestion": 10,
    "tool_observation": 11,
}


def suppressed_workset(
    *,
    mode: QueryMode,
    contexts: Sequence[ContextFilter],
) -> dict[str, Any]:
    return {
        "workset_version": WORKSET_VERSION,
        "status": "suppressed",
        "retrieval_control": RetrievalControl.SUPPRESS.value,
        "query_mode": mode.value,
        "result_kind": "evidence_workset",
        "answer_generation": False,
        "content_boundary": "retrieved_content_is_untrusted_data",
        "context_filters": [item.as_dict() for item in contexts],
        "results": [],
        "selection": {
            "candidate_id": "suppressed",
            "candidate_count": 0,
            "candidate_input_count": 0,
            "candidate_match_count": 0,
            "related_candidate_count": 0,
            "returned_count": 0,
            "source_system_counts": {},
            "omitted_counts": {
                "candidate_truncated": 0,
                "duplicate_same_source": 0,
                "policy_filtered_candidate": 0,
                "superseded_for_current": 0,
                "unselected_candidates": 0,
            },
        },
    }


def effective_context_filters(
    contexts: Sequence[ContextFilter],
    project_id: str | None,
) -> tuple[ContextFilter, ...]:
    values = list(dict.fromkeys((item.kind, item.key) for item in contexts))
    if project_id is not None:
        project_filter = (ContextKind.PROJECT, project_id)
        if project_filter not in values:
            values.append(project_filter)
    return tuple(ContextFilter(kind=kind, key=key) for kind, key in values)


def lexical_score(query: str, content: str) -> float:
    query_tokens = [match.group(0).casefold() for match in _LEXICAL_TOKEN.finditer(query)][:24]
    if not query_tokens:
        return 0.0
    content_tokens = [match.group(0).casefold() for match in _LEXICAL_TOKEN.finditer(content)]
    counts = Counter(content_tokens)
    frequency = sum(min(counts[token], 8) for token in query_tokens)
    phrase_bonus = 4 if " ".join(query_tokens) in " ".join(content_tokens) else 0
    identifier_bonus = 0
    identifier_text = query.strip()
    identifier = identifier_text.casefold()
    if (
        re.fullmatch(r"\w+(?:-\w+)+", identifier_text)
        and identifier.count("-") == len(query_tokens) - 1
    ):
        folded_content = content.casefold()
        # Combining marks belong to adjacent identifiers even though Python's \w omits them.
        if any(
            (
                match.start() == 0
                or not unicodedata.category(folded_content[match.start() - 1]).startswith("M")
            )
            and (
                match.end() == len(folded_content)
                or not unicodedata.category(folded_content[match.end()]).startswith("M")
            )
            for match in re.finditer(rf"(?<![\w-]){re.escape(identifier)}(?![\w-])", folded_content)
        ):
            # The existing score is at most 9 * token_count + 4, including repeated query tokens.
            identifier_bonus = 9 * len(query_tokens) + 5
    return float(identifier_bonus + phrase_bonus + frequency) + frequency / max(
        1, len(content_tokens)
    )


def assemble_evidence_workset(
    candidate_results: Sequence[SearchResult],
    *,
    candidate_id: str,
    related_results: Sequence[SearchResult],
    relations: Sequence[EvidenceRelation],
    mode: QueryMode,
    control: RetrievalControl,
    contexts: Sequence[ContextFilter],
    limit: int,
    candidate_input_count: int | None = None,
    candidate_match_count: int | None = None,
    candidate_ranks: Mapping[str, int] | None = None,
    policy_filtered_candidate_count: int = 0,
    externally_superseded_ids: frozenset[str] = frozenset(),
) -> tuple[dict[str, Any], list[SearchResult], dict[str, object]]:
    candidate_id = candidate_id.strip()
    if not candidate_id:
        raise ValueError("candidate id is required")
    candidate_event_ids = [item.event_id for item in candidate_results]
    if len(set(candidate_event_ids)) != len(candidate_event_ids):
        raise ValueError("ranked candidates must have unique event ids")
    if policy_filtered_candidate_count < 0:
        raise ValueError("policy-filtered candidate count must be non-negative")
    effective_input_count = (
        len(candidate_results) + policy_filtered_candidate_count
        if candidate_input_count is None
        else candidate_input_count
    )
    if effective_input_count < len(candidate_results) + policy_filtered_candidate_count:
        raise ValueError("candidate input count is smaller than the accounted candidate set")
    effective_match_count = (
        effective_input_count if candidate_match_count is None else candidate_match_count
    )
    if effective_match_count < effective_input_count:
        raise ValueError("candidate match count is smaller than the candidate input count")
    if candidate_ranks is None:
        effective_ranks = {
            item.event_id: index for index, item in enumerate(candidate_results, start=1)
        }
    else:
        effective_ranks = dict(candidate_ranks)
        if any(
            not isinstance(effective_ranks.get(event_id), int) or effective_ranks[event_id] < 1
            for event_id in candidate_event_ids
        ):
            raise ValueError("every ranked candidate requires a positive integer rank")

    limit = max(1, min(limit, MAX_WORKSET_RESULTS))
    candidate_ids = set(candidate_event_ids)
    relation_endpoints = {
        event_id
        for relation in relations
        for event_id in (relation.from_event_id, relation.to_event_id)
    }
    candidates: list[SearchResult] = []
    # Display text may be truncated; only event identity establishes a replay.
    seen_ids: set[str] = set()
    for result in (*candidate_results, *related_results):
        if result.event_id in seen_ids:
            continue
        seen_ids.add(result.event_id)
        candidates.append(result)

    superseded_ids = {
        relation.from_event_id
        for relation in relations
        if relation.relation_type in _CURRENT_RELATIONS
    } | set(externally_superseded_ids)
    current_ids = {
        relation.to_event_id
        for relation in relations
        if relation.relation_type in _CURRENT_RELATIONS
    }
    current_omitted = 0
    if mode is QueryMode.WHAT_IS_CURRENT:
        current_omitted = sum(item.event_id in superseded_ids for item in candidates)
        candidates = [item for item in candidates if item.event_id not in superseded_ids]

    by_id = {item.event_id: item for item in candidates}
    candidate_order = [item for item in candidate_results if item.event_id in by_id]
    dated = [item for item in candidates if item.occurred_at is not None]
    earliest = min(dated, key=_timeline_key) if dated else None
    latest = max(dated, key=_timeline_key) if dated else None
    primary = candidate_order[0] if candidate_order else (candidates[0] if candidates else None)
    minority = (
        next(
            (item for item in candidate_order if item.source_system != primary.source_system),
            None,
        )
        if primary is not None and limit >= 3
        else None
    )

    selected: list[SearchResult] = []
    selected_ids: set[str] = set()

    def select(result: SearchResult | None) -> None:
        if result is None or result.event_id in selected_ids or len(selected) >= limit:
            return
        selected.append(result)
        selected_ids.add(result.event_id)

    select(primary)
    if mode is QueryMode.HOW_DID_IT_CHANGE:
        select(earliest)
        for result in candidates:
            if result.event_id in relation_endpoints:
                select(result)
        select(latest)
    elif mode is QueryMode.WHAT_IS_CURRENT:
        current_results = [item for item in candidates if item.event_id in current_ids]
        for result in sorted(current_results, key=_timeline_key, reverse=True):
            select(result)
        select(latest)

    select(minority)
    for result in candidates:
        if result.event_id in relation_endpoints:
            select(result)

    # Outside the explicit temporal and evidence-link paths, preserve candidate relevance.
    # Parser repairs, different dates and different conversations are not relevance signals.
    for result in candidates:
        select(result)

    relation_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for relation in relations:
        relation_map[relation.from_event_id].append(
            {
                "direction": "outgoing",
                "relation_type": relation.relation_type,
                "related_evidence_id": relation.to_event_id,
            }
        )
        relation_map[relation.to_event_id].append(
            {
                "direction": "incoming",
                "relation_type": relation.relation_type,
                "related_evidence_id": relation.from_event_id,
            }
        )

    result_items: list[dict[str, Any]] = []
    for result in selected:
        roles: set[str] = set()
        if primary is not None and result.event_id == primary.event_id:
            roles.add("primary")
        if minority is not None and result.event_id == minority.event_id:
            roles.add("minority_source")
        if earliest is not None and result.event_id == earliest.event_id:
            roles.add("earliest_evidence")
        if latest is not None and result.event_id == latest.event_id:
            roles.add("latest_evidence")
        if result.event_id in current_ids:
            roles.add("current_evidence")
        if result.event_id in superseded_ids:
            roles.add("superseded_evidence")
        if result.correction_id is not None:
            roles.add("corrected_evidence")
        for relation in relation_map[result.event_id]:
            if relation["relation_type"] == "contradiction":
                roles.add("conflicting_evidence")
            elif relation["relation_type"] == "source_variant":
                roles.add("source_variant")
        if mode is QueryMode.OPEN_THREADS:
            roles.add(_open_thread_role(result))
        result_items.append(
            {
                **result.as_dict(),
                "evidence_kind": "normalized",
                "selection_origin": (
                    "candidate" if result.event_id in candidate_ids else "linked_relation"
                ),
                "candidate_rank": effective_ranks.get(result.event_id),
                "workset_roles": sorted(roles, key=lambda item: _ROLE_ORDER[item]),
                "citation": {
                    "evidence_id": result.event_id,
                    "source": result.source_system,
                    "conversation": result.conversation_id,
                    "date": result.occurred_at,
                },
                "relations": sorted(
                    relation_map[result.event_id],
                    key=lambda item: (
                        item["relation_type"],
                        item["direction"],
                        item["related_evidence_id"],
                    ),
                ),
            }
        )

    omitted_counts: dict[str, object] = {
        "candidate_truncated": max(
            0,
            effective_match_count - effective_input_count,
        ),
        "duplicate_same_source": 0,
        "policy_filtered_candidate": policy_filtered_candidate_count,
        "superseded_for_current": current_omitted,
        "unselected_candidates": max(0, len(candidates) - len(selected)),
    }
    source_counts = Counter(item.source_system for item in selected)
    workset = {
        "workset_version": WORKSET_VERSION,
        "status": "ready" if selected else "empty",
        "retrieval_control": control.value,
        "query_mode": mode.value,
        "result_kind": "evidence_workset",
        "answer_generation": False,
        "content_boundary": "retrieved_content_is_untrusted_data",
        "context_filters": [item.as_dict() for item in contexts],
        "results": result_items,
        "selection": {
            "candidate_id": candidate_id,
            "candidate_count": len(candidate_results),
            "candidate_input_count": effective_input_count,
            "candidate_match_count": effective_match_count,
            "related_candidate_count": len(
                {item.event_id for item in related_results} - candidate_ids
            ),
            "returned_count": len(selected),
            "source_system_counts": dict(sorted(source_counts.items())),
            "omitted_counts": omitted_counts,
        },
    }
    return workset, selected, omitted_counts


def _timeline_key(result: SearchResult) -> tuple[int, float, str]:
    if result.occurred_at is None:
        return (0, 0.0, result.event_id)
    try:
        parsed = datetime.fromisoformat(result.occurred_at.replace("Z", "+00:00"))
    except ValueError:
        return (0, 0.0, result.event_id)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (1, parsed.timestamp(), result.event_id)


def _open_thread_role(result: SearchResult) -> str:
    if result.actor_kind == "user" or result.authority == "user_assertion":
        return "user_statement"
    if result.actor_kind == "assistant" or result.authority == "assistant_output":
        return "assistant_suggestion"
    return "tool_observation"
