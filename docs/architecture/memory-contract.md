# Normative Memory Contract

Version: 0.7

Status: accepted v1 target; implementation remains partial

Date: 2026-08-27

The terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative.

## Purpose

This contract prevents a retrieval system from quietly turning text into authority. It defines
what is stored, what can become durable memory, how history changes, and what every answer must
disclose. The v0.7 target separates access control from optional organizational contexts,
generalizes the existing private Mac mini deployment into a single-owner self-hosted product, and
adds explicit source-version, storage, encryption, archive-safety, client-compatibility, and
deletion requirements from the 2026-08-27 specification audit.

The current schema still uses legacy `scope` and `project_id` fields. Until the v0.7 migration is
implemented, those fields MUST retain their existing restrictive behavior. Documentation of a
target field is not evidence that the running ledger supports it.

## Record Families

### Source object manifest

A source object preserves exact source bytes or an exact exported representation.

Required fields:

```json
{
  "source_object_id": "opaque-random-id",
  "storage_object_id": "opaque-random-id",
  "object_kind": "conversation_record",
  "ciphertext_digest": "sha256:<digest>",
  "plaintext_digest": "sha256:<digest>",
  "byte_length": 0,
  "media_type": "application/jsonl",
  "source_system": "codex",
  "source_client": "codex-cli",
  "source_client_version": "pinned-version",
  "capture_capability": "native-history",
  "source_account": "opaque-local-id",
  "device_id": "opaque-device-id",
  "conversation_id": "source-native-id",
  "branch_id": "source-native-or-derived-id",
  "attachment_of_event_id": null,
  "captured_at": "RFC3339 timestamp",
  "source_updated_at": "RFC3339 timestamp or null",
  "parser_name": "codex-jsonl",
  "parser_version": "pinned-version",
  "adapter_version": "pinned-version",
  "schema_fingerprint": "sha256:<digest>",
  "encryption_profile": "versioned-profile",
  "wrapped_data_key": "encoded-wrapped-key",
  "privacy": "included",
  "supersedes_source_object_id": null
}
```

Requirements:

- Exact raw bytes MUST be hashed before encryption.
- Encryption MUST occur before upload.
- Manifests MUST NOT contain credentials or plaintext excerpts.
- A remote storage provider MUST receive ciphertext, never an unencrypted source object.
- Remote object keys MUST be opaque and MUST NOT encode plaintext digests, source systems, account
  identifiers, paths, titles, or content-derived labels.
- New v0.7 source and storage object identifiers MUST be random. Existing digest-derived internal
  source identifiers MUST remain stable through an explicit legacy mapping and MUST NOT be reused
  as remote storage keys.
- ETags MUST NOT be used as the content-integrity contract.
- Per-object data keys MUST be wrapped by the installation root key.
- Source updates create new immutable objects and a supersession link.
- Attachments and large tool outputs MUST have independent manifests, hashes, media types, sizes,
  and links to their conversation or event.
- A source object MUST remain recoverable without its search projection.
- Eviction MUST NOT remove the only verified copy of an object.
- Every source object MUST record the source client and version, capture capability, adapter and
  parser versions, and schema fingerprint used to interpret it.

### Object storage and encryption

V1 requires local-filesystem and Backblaze B2 profiles. AWS S3 and Cloudflare R2 are optional future
claims, not release prerequisites. Provider compatibility and ordinary application integration MUST
be proved independently; a passing provider library is not proof of remote-backed ledger operation.
Passing one profile MUST NOT be treated as proof for another.

Requirements:

- Object writes MUST move through explicit `pending`, `uploaded`, and `verified` states.
- Verification MUST include authenticated metadata and GET/readback according to the provider
  profile.
- Multipart uploads MUST be bounded, aborted on failure, inventoried, and cleaned after a stated
  grace period.
- Provider versioning, lifecycle, replication, retention, and Object Lock settings MUST be
  detected or requested and their effect on deletion and recovery MUST be disclosed.
- Immutable retention MUST NOT be enabled by default.
- Primary object storage MUST NOT be described as a backup.
- A remote backup MUST encrypt the consistent SQLite snapshot as well as source objects.
- The application MUST use a reviewed streaming AEAD library and a versioned envelope. Custom
  cryptography is prohibited.
- The envelope MUST bind its format version, algorithm profile, opaque object identity,
  ciphertext and plaintext digests, plaintext length, wrapped per-object key material, and required
  authenticated metadata.
- Sensitive labels MUST NOT be placed in additional authenticated data because it is authenticated
  but not encrypted.
- The running node and its host MUST be documented as trusted plaintext compute. The product MUST
  NOT claim searchable end-to-end encryption.
- The provider-visible size, object-count, timing, and access-pattern leakage MUST be documented.
- First real import MUST remain blocked until the recovery kit restores a synthetic canary after
  the operational root-key copy is unavailable.
- Encryption release tests MUST cover supported architectures, large streamed objects, wrong keys,
  corrupt or reordered segments, truncation, interrupted writes, rotation, rewrap, and recovery.

### SQLite placement and consistency

- The SQLite database, WAL, and shared-memory files MUST live on one node-local filesystem.
- SQLite MUST NOT run from NFS, SMB, an object store, or another network filesystem.
- One serialized application writer MUST own ledger mutations.
- Backup MUST use SQLite's online backup API rather than a raw copy of a live database file.
- Snapshot verification MUST run both `integrity_check` and `foreign_key_check`.
- Reader duration and checkpoint health MUST be observable so a long reader cannot silently cause
  unbounded WAL growth.

### Installation, device, and source identity

Every installation has one owner, one authoritative writable node, and one installation identity.
Every collector, assistant client, provider account, and source account has a separate opaque
identity.

Requirements:

- Identity linking MUST be explicit and MUST NOT be inferred from email addresses or display names.
- Provider credentials MUST remain on the device that uses them.
- A collector credential MUST be bound to its registered device and source accounts.
- A client credential MUST be independently revocable.
- Short-lived enrollment codes MAY issue a device credential but MUST NOT become reusable bearer
  credentials.
- Mixed-owner installations are unsupported in v1.

### Append-only source stream

A growing native history is a logical stream composed of immutable admitted segments. Its cursor contains the source account and canonical path identity, first native conversation identity, source provenance kind, next record ordinal, next complete-line byte offset, and the SHA-256 digest of every byte before that offset.

Requirements:

- Segment identifiers and event identifiers MUST NOT depend on a later whole-file digest.
- A new segment MUST begin exactly at the registered ordinal, byte offset, and prefix digest.
- Truncation, rewrite, overlap, gap, inode replacement, incomplete JSONL tails, and provenance drift MUST fail closed.
- A plan MUST bind execution to exact start and end ordinals, byte offsets, prefix digests, parser
  version, admission counts, access, and context assignments.
- Planning and preview MUST NOT open or migrate the live ledger.
- The first valid Codex `session_meta` record establishes the child conversation identity. Replayed parent metadata MUST NOT replace it.
- Fork parent identity and `history_base` MUST remain explicit. A fork with replayed history requires an approved replay boundary before ingestion.
- Within approved source scope, an exact verified producer's native copied-history boundary MAY
  establish that boundary without a new human prompt. Consumed records MUST have validated native
  ordinals and physical locators. Inherited records MUST NOT become child evidence or raw holds;
  bounded prefix progress requires normal node acknowledgement and MUST NOT imply copying finished.
  Incomplete prefixes at EOF and unverified layouts MUST refuse. Parent sources MUST NOT be opened.
- In a verified reference-only native format, inherited native ordinals MUST be distinguished from physical child record/byte cursors. `history_base` addresses another rollout and MUST NOT be used as a child-file skip or authorization to read another source/account.
- A legacy whole-file fork MAY be replaced by a bounded child stream only when the plan names the exact legacy source, the legacy source was admitted under the declared parent identity, every legacy event is currently `no_memory`, the child segment ends at the exact admitted file digest, and the replacement uses a newer parser.
- Only a recognized interactive source MAY establish `user_assertion` from a user-role record. Subagent prompts are assistant output; automation and unknown-source prompts are tool observations or excluded.
- Machine-injected context wrappers and rolled-back turns MUST be excluded before persistence.
- Transport copies MAY be collapsed by a pinned parser when one exact canonical record remains recoverable. Machine-only citation envelopes MAY be omitted from normalized text only when exact raw evidence is retained and the transformation is versioned.

### Official web export batch

A web export batch is one or more immutable official account exports prepared
for a single ledger generation and code revision.

Requirements:

- The complete archive and one exact named member MUST be hashed independently.
- An extracted member MUST match the named archive member in byte length and SHA-256.
- Archive inspection MUST enforce limits for compressed bytes, member count, unique names, total
  and per-member uncompressed bytes, compression ratio, supported compression methods, encryption
  status, CRC, CPU, memory, temporary disk, and elapsed time.
- Duplicate member names, encrypted members, unsupported compression, CRC failure, or any resource
  limit MUST fail closed before ledger mutation.
- Parsing MUST enforce limits for nesting, record count, string length, attachment bytes, CPU,
  memory, temporary disk, and elapsed time.
- Every planned conversation MUST retain its exact member byte range and unchanged private split bytes.
- Approval manifests MUST exclude transcript excerpts, titles, raw conversation or branch IDs,
  provider timestamps, and raw unknown-field discriminators. Provider-controlled metadata needed
  for verification MUST appear only as SHA-256 bindings.
- Manifest JSON MUST reject duplicate keys at every object depth.
- A manifest MUST bind the archive, member, split hashes, source account, access, context
  assignments, parser and extractor versions, admission counts, full code revision, and expected
  ledger generation.
- Export planning and import preview MUST NOT open, initialize, or migrate a ledger. Explicit
  schema-transfer and revocation previews MAY inspect existing ledgers read-only; they MUST NOT
  initialize, migrate or change ledger rows.
- Protected CLI planning, verification, authorization, and apply commands MUST bind the supplied
  code revision to a clean tracked runtime checkout or release-embedded build provenance.
- Execution MUST require an active owner-approved source registration and exact manifest
  verification.
- First import, access broadening, source-account changes, unrecognized schemas, and imports
  without standing authorization MUST pause for owner approval.
- A routine export from an already authorized source MAY execute without per-conversation or
  per-manifest review when every registered policy and schema check passes.
- Every manifest in one execution batch MUST bind the same pre-import ledger generation.
- Initial schema authorization and validation of new or changed schemas MUST target an explicitly
  marked offline clone. Because authorization changes the generation, subsequent import planning
  MUST bind the authorized state. Installing that exact reviewed grant on an explicitly selected
  existing node MUST verify the configuration-only snapshot lineage, matching installation/source/
  device/access registration, active reviewed grant and committed isolated-import receipt. Rebuild
  archive/parser/admission verification with the current pinned runtime while preserving the
  original review revision. Refuse incompatible proof, stale live generations and revoked grants.
  This operation MUST change only the grant, never replace the database or import content. Exact
  active retries MAY be no-ops after unrelated writes. Exact generation-bound revocation MUST only
  disable the selected grant; it does not erase admitted data or reactivate a revoked grant.
- Accepted September 14: routine imports of already authorized, unchanged source schemas MAY
  target an explicitly selected authoritative node. They MUST recheck registration, access,
  schema, manifest and generation under its exclusive writer and commit the complete batch in one
  transaction. Never infer a live target from default configuration. The explicit
  `--authoritative-node` route now has local receipt, interruption and post-commit publication
  proof; a release still requires verified deployment, recovery and real-client acceptance.
- Archive, member, split, parser, and admission results MUST be reverified before execution.
- Post-verification source reads MUST reject path replacement and MUST NOT read or copy beyond the
  approved byte length except for the single bounded byte needed to detect overrun.
- A completion receipt MUST be fully written and fsynced before atomic no-clobber publication,
  publication MUST occur only after ledger writer teardown succeeds, and no later unhandled step
  may turn that published success into a reported failure.
- Execution MUST be transactional or target an isolated disposable clone bound to a verified
  source generation.
- Partial execution MUST remain invisible to ordinary retrieval and disposable.
- Routine-refresh retry receipts MUST distinguish committed admission from completed encrypted
  publication. Provider I/O MUST occur after admission commits; a failed or lost response MUST
  permit bounded recovery without repeating admission or manually repairing the database.
- Promotion MUST preserve rollback state and occur only after count, integrity, foreign-key,
  access, authority, exclusion, search, exact-evidence, and projection checks pass.
- A text-free private receipt MUST bind the approved manifest hashes and pre/post ledger generations.

### Normalized event

An event is an append-only, source-linked occurrence.

Required fields:

```json
{
  "event_id": "stable-id",
  "event_type": "message",
  "actor": {
    "kind": "user",
    "assistant": null,
    "account": "opaque-local-id"
  },
  "authority": "user_assertion",
  "source_ref": {
    "source_object_id": "opaque-random-id",
    "conversation_id": "source-native-id",
    "branch_id": "source-native-or-derived-id",
    "message_id": "source-native-or-derived-id",
    "byte_or_record_locator": "recoverable-locator"
  },
  "occurred_at": "RFC3339 timestamp or null",
  "mentioned_at": "RFC3339 timestamp or null",
  "ingested_at": "RFC3339 timestamp",
  "access": "owner",
  "context_ids": ["context:project:example"],
  "privacy": "included",
  "content_digest": "sha256:<digest>",
  "parser_version": "pinned-version"
}
```

Requirements:

- Speaker role and assistant identity MUST survive normalization.
- Conversation branches MUST NOT be flattened without branch metadata.
- The source locator MUST recover the exact supporting record or byte range.
- Parser upgrades MUST create reproducible migrations or new event versions.
- Normalized text MUST NOT silently rewrite source text.
- Access filtering MUST occur before ranking.
- Context membership MUST be optional and many-to-many.
- Inferred contexts MUST NOT broaden access or authority.
- Correlated repetition MUST NOT be treated as independent evidence.

### Event correction

A correction changes the current interpretation of an admitted event without rewriting the
original event row or exact source object.

Required fields:

```json
{
  "correction_id": "stable-id",
  "event_id": "event-id",
  "previous_state_digest": "sha256:<digest>",
  "new_state_digest": "sha256:<digest>",
  "event_type": "message",
  "actor_kind": "user",
  "assistant": null,
  "authority": "user_assertion",
  "access": "owner",
  "context_ids": ["context:project:stable-project-id"],
  "privacy": "included",
  "content_digest": "sha256:<digest>",
  "parser_version": "pinned-version",
  "reason": "bounded-text-or-code",
  "authorized_by": "principal-id",
  "authorization_scope": "bounded-approval",
  "created_at": "RFC3339 timestamp",
  "previous_correction_id": null
}
```

Requirements:

- The original event row and exact source object MUST remain unchanged.
- A plan MUST bind to the ledger generation and each event's previous state digest.
- Changed normalized text MUST be derivable from a decoded value in the exact source record.
- Corrections MUST be append-only, attributable, ordered, and covered by a mutation receipt.
- Search and derived projections MUST use the latest correction while evidence responses retain
  both current policy fields and original state.
- A projection MUST become stale when the current event generation changes.

### Derived memory

A memory is a typed interpretation supported by one or more events.

Required fields:

```json
{
  "memory_id": "stable-id",
  "memory_type": "decision",
  "statement": "normalized proposition",
  "authority": "user_assertion",
  "lifecycle": "candidate",
  "access": "owner",
  "context_ids": ["context:project:stable-project-id"],
  "valid_from": "RFC3339 timestamp or null",
  "valid_to": null,
  "temporal_status": "current",
  "confidence": 0.0,
  "confidence_method": "named-method",
  "evidence_event_ids": ["event-id"],
  "counterevidence_event_ids": [],
  "supersedes_memory_id": null,
  "created_by": "extractor-or-human-id",
  "created_at": "RFC3339 timestamp",
  "reviewed_by": null,
  "reviewed_at": null
}
```

Requirements:

- A memory MUST cite supporting events.
- Counterevidence MUST remain linked and retrievable.
- Confidence MUST NOT upgrade authority or lifecycle.
- Context-bound evidence MUST NOT become a standing owner-wide policy automatically.
- Assistant-generated procedures and preferences MUST begin as candidates.
- A summary MUST be labeled as derived and MUST NOT replace source evidence.

### Pending evidence proposal

An explicit proposal captured before an official web export is available is not yet a derived
memory. It is an inactive proposal envelope with exactly one pending evidence claim. The envelope
MAY have no `evidence_event_ids` only while that claim remains unresolved.

Requirements:

- The claim MUST bind an active registered source account, official web source, conversation ID,
  certified provider message ID, content digest, and candidate scope. Parent-message and branch IDs
  are optional exact qualifiers; supplied values MUST match.
- The proposing principal MUST be permitted to read the registered source-account policy. A pending
  claim MUST NOT bypass the evidence-access boundary applied to an existing event.
- Claim storage MUST NOT retain transcript text. It stores only the opaque native identity,
  qualifiers, content digest, creator, and timestamps needed for exact reconciliation.
- The unresolved envelope MUST remain outside retrieval, qualification, approval, standing
  instructions, and policy. Its initial authority is `assistant_output`.
- Reconciliation MUST require the exact registered account, source, conversation, certified message
  ID, content digest, compatible scope, and every supplied qualifier. Fuzzy or text-similarity
  identity is forbidden.
- Reconciliation MUST work in either commit order: export then proposal, or proposal then export.
  It appends the canonical event ID without creating another proposal.
- The immutable evidence-link row is the specialized mutation receipt. It records the claim,
  canonical reconciliation key, event ID, and candidate evidence and authority before and after the
  link. The envelope becomes a normal evidence-backed candidate only after this receipt exists.

### Mutation receipt

Every qualification, approval, rejection, correction, supersession, redaction, deletion, access
change, or context change creates a mutation receipt.

Required fields:

```json
{
  "mutation_id": "stable-id",
  "target_id": "record-id",
  "operation": "approve",
  "previous_version_digest": "sha256:<digest>",
  "new_version_digest": "sha256:<digest>",
  "authorized_by": "principal-id",
  "authorization_scope": "memory:curate",
  "reason": "bounded-text-or-code",
  "created_at": "RFC3339 timestamp",
  "previous_mutation_digest": "sha256:<digest-or-null>"
}
```

Requirements:

- Mutations MUST be attributable and ordered.
- The previous version digest MUST prevent lost updates.
- The mutation chain SHOULD be tamper-evident.
- Deletion MUST create a tombstone even when content is removed.
- Mutation history MUST NOT expose deleted plaintext to ordinary readers.

### Query receipt

Every material query result produces a receipt containing:

- Query mode and normalized intent
- Principal and granted capabilities
- Access, privacy, context, authority, and temporal filters
- Retrieval and reranking versions
- Token and result budgets
- Source-diversity and conflict-selection decisions
- Returned memory and event identifiers
- Exact source pointers
- Omitted or blocked result counts by reason
- Latency and model usage
- Any inference clearly separated from retrieved evidence

## Authority Classes

| Authority               | What it can establish                 | What it cannot establish automatically                               |
| ----------------------- | ------------------------------------- | -------------------------------------------------------------------- |
| `user_assertion`        | A statement the user made             | Objective truth, durable policy, or current validity                 |
| `assistant_output`      | What an assistant proposed or claimed | User preference, approval, completed action, or external fact        |
| `tool_observation`      | What a named tool observed at a time  | Permanent state, user intent, or authority outside the tool boundary |
| `external_content`      | What an external source reported      | User intent, trusted instruction, or verified local state            |
| `system_policy`         | Active system-level instruction       | User-authored preference or historical fact                          |
| `admin_approved_policy` | Explicitly approved standing behavior | Facts outside the policy's scope                                     |

Authority is attached to the smallest supportable unit. A conversation containing a user message and an assistant response MUST produce records with different authority.

## Access And Context

Access controls who may retrieve a record. Context organizes evidence. They MUST remain separate.

Initial access classes are:

- `owner`: available to authorized owner clients.
- `assistant_private`: available only to a named assistant integration.
- `session`: temporary context that expires with the work session.

Privacy remains a separate field:

- `included`: eligible for retrieval subject to access and authority.
- `private`: retained only under an explicit private policy and excluded from ordinary retrieval.
- `no_memory`: MUST NOT be persisted beyond transient processing needed to enforce exclusion.

Exclusion MUST cover raw containers as well as normalized records. A mixed official export MUST
NOT retain excluded text through an archive, selected member, conversation copy, snapshot, portable
export, or remote object. Admitted original evidence and its source provenance MUST remain usable;
rejecting every mixed conversation is not a substitute for record-level exclusion. Retained source
hashes and locators MUST NOT falsely imply that the original container is stored. Existing retained
copies require explicit remediation; readers MUST NOT silently purge or migrate them.

Context is optional and many-to-many. Initial context kinds are:

- `project`
- `topic`
- `person_or_relationship`
- `life_area`
- `custom`

Requirements:

- An event or memory MAY have zero or more contexts.
- Evidence without a context MUST remain searchable in the owner's general corpus.
- A context suggestion MAY be inferred, but inference MUST be labeled and reviewable.
- Context assignment MUST NOT change access, privacy, authority, or lifecycle.
- Access and privacy filtering MUST happen before lexical or semantic ranking.
- The legacy `user_global` scope maps to owner access with no required context.
- The legacy `project` scope maps to owner access plus one project context.

## Memory Types And Review

| Type                  | Default lifecycle | Typical authority                  | Context and approval rule             |
| --------------------- | ----------------- | ---------------------------------- | ------------------------------------- |
| Episodic event        | Observed          | Source-dependent                   | Preserve source contexts              |
| Claim or state        | Candidate         | Source-dependent                   | Qualify for intended contexts         |
| Preference or persona | Candidate         | User assertion                     | Approval required for standing use    |
| Decision              | Candidate         | User assertion or approved policy  | Keep source contexts by default       |
| Task or open thread   | Candidate         | User assertion or tool observation | Context or session                    |
| Procedure or skill    | Candidate         | Mixed                              | Approval required for standing use    |
| Artifact              | Observed          | Tool observation                   | Preserve source and context linkage   |

## Promotion Rules

### Observed

The record is normalized and source-linked. It has not been accepted as a durable interpretation.

### Candidate

An extractor or client proposes a typed interpretation. Candidates MUST NOT silently affect standing instructions or policy.

Proposal creation MUST emit an authenticated proposal receipt that binds the immutable candidate
creation digest, proposing principal, principal kind, required `memory:propose-write` capability,
policy version, and creation time. The recorded creator MUST equal the authenticated principal.
Candidates without a valid receipt are legacy or untrusted candidates: they MAY be rejected, but
MUST NOT qualify.

### Qualified

Deterministic checks have passed:

- Evidence exists and is recoverable.
- Actor, role, authority, access, and time are present.
- No exclusion or secret rule blocks persistence.
- Contradictions and prior versions were searched.
- The proposed type permits the proposed access and contexts.
- The proposing principal had `memory:propose-write`.

Qualification is a state-bound local-administrator operation. Its basis digest MUST cover the
candidate, proposal receipt, exact evidence state, access, contexts, pending-evidence status,
relevant correction, supersession, and contradiction relations, duplicate candidates, and prior
review history. Missing or excluded evidence, unresolved pending evidence, invalid provenance,
conflicts requiring judgment, superseded evidence without its current version, or exact duplicates
with the same canonical statement, type, authority, evidence set, access, and contexts MUST fail
closed. Duplicate evaluation MAY ignore only candidates whose complete review chain validates to
`rejected`; malformed review history MUST fail closed. A stale basis digest MUST NOT mutate state.

### Approved

The required reviewer accepted the candidate. Standing preferences, policies, procedures,
access broadening, conflict resolution, redaction, and deletion require explicit owner or local
administrator approval. A direct bounded `remember this as ...` instruction MAY itself supply the
approval for that exact candidate.

Remote web clients MUST NOT directly approve their own proposals.

Review lifecycle is derived only from append-only, hash-bound transitions:

- `candidate -> qualified` records deterministic checks passing.
- `qualified -> approved` records explicit owner or local-administrator approval.
- `candidate -> rejected` and `qualified -> rejected` retain a bounded reason code.
- Approved and rejected states are terminal.

The immutable base candidate remains labeled `candidate`; implementations MUST derive effective
lifecycle by validating the complete transition chain. Each transition is the mutation receipt for
that review operation and binds the prior lifecycle, new lifecycle, prior transition, reviewed
basis, reviewer, authorization scope, policy version, reason, and time. Rejection remains available
when qualification blockers exist so invalid or legacy candidates can be closed without promotion.

In v1, approval is a reviewed decision record, not automatic standing-memory materialization.
Approved candidates remain outside event retrieval and MUST NOT change instructions, policy, or
current-state answers until a separately specified, authorized, and evidenced materialization path
exists.

## Time And Change

- Occurrence time, mention time, ingestion time, and validity time are distinct.
- Missing occurrence time MUST remain unknown rather than defaulting to ingestion time.
- New conflicting evidence MUST NOT overwrite an old version.
- Current-state selection MUST show why a version is current.
- Historical queries MUST be able to include superseded versions.
- Perishability is type-specific. A temporary task can expire while a biographical event remains valid.

## Conflict And Correction

When evidence conflicts, the system MUST:

1. Preserve both evidence paths.
2. Mark the relationship as contradiction, correction, or supersession.
3. Avoid promoting a single current fact when authority or time cannot resolve the conflict.
4. Surface the uncertainty and ask for review when the answer materially changes behavior.

Corrections do not erase that an earlier statement existed.

## Retrieval Contract

Supported query modes are:

- `where_did_i_leave_off`
- `what_did_i_say`
- `what_did_i_think`
- `what_is_current`
- `how_did_it_change`
- `open_threads`
- `find_evidence`

Requirements:

- `what_did_i_say` and `what_did_i_think` MUST default to user-role evidence.
- `what_is_current` MUST apply validity and supersession filters.
- `how_did_it_change` MUST include transition evidence.
- `open_threads` MUST distinguish user commitments, assistant suggestions, and inferred next steps.
- Retrieval MUST be intent-triggered and MUST support explicit force and suppress controls.
- Workset assembly MUST consider earliest evidence, later corrections, current conclusions,
  contradictions, and useful minority-source evidence.
- One source MUST NOT monopolize a workset merely because it produced many similar lexical or
  semantic hits.
- Source balancing MUST NOT impose equal provider quotas when the evidence is genuinely uneven.
- Retrieval MUST reserve a bounded path for current or superseding constraints so a large volume of
  stale evidence cannot consume the entire workset.
- Results MUST identify evidence kind: raw, normalized, derived, or inference.
- Inference MUST NOT be rendered as a quotation or user statement.
- Default citations SHOULD be concise and MUST identify source, conversation, date when known,
  and a stable evidence identifier.
- Exact evidence, authority, speaker, conflicts, and source locators MUST be available on demand.
- Bounded exact-evidence delivery MUST label partial fields, preserve UTF-8 byte boundaries and
  full-field/chunk digests, and bind continuations to unchanged evidence and attribution. Every
  page MUST recheck access, privacy and source integrity. A final suffix is not a complete record;
  withheld raw evidence MUST NOT become available through pagination. Transport paging MUST NOT
  change stored source bytes or silently omit metadata to fit a response.
- Search display MAY use bounded previews but MUST disclose truncation rather than present an
  excerpt as a complete statement. Display limits MUST NOT merge distinct evidence identities or
  bypass access, correction, authority, or source-balancing rules.
- The node MUST return a structured evidence workset. Final prose generation belongs to the
  calling assistant unless an optional answer service is explicitly enabled.

## Untrusted Content Boundary

Retrieved memory, external pages, assistant output, tool output, and imported transcripts are data, not instructions.

- Instruction-like text inside source content MUST remain quoted data.
- Admission checks MUST be deterministic before any LLM extraction.
- High-confidence secrets MUST be blocked on the source device before upload.
- Lower-confidence secret matches SHOULD be flagged for review rather than silently rewritten.
- A blocked record MUST leave only a text-free local reason and recoverable source locator.
- A false-positive exception MUST be narrow, attributable, and reviewable.
- Repeated claims MUST NOT gain authority merely through frequency.
- Query probing, abnormal write frequency, and cross-access attempts SHOULD be detected and logged.
- Models MAY propose classification or links but MUST NOT bypass access or promotion gates.

## Synchronization And Collector Queue

- Native source collectors SHOULD reconcile every 15 minutes while their device is active.
- A collector MUST expose an explicit immediate synchronization command.
- Web-source reconciliation SHOULD run as a weekly assisted official-export workflow.
- Weekly MUST be described as a request cadence, not a freshness guarantee.
- Browser automation MUST pause for login, CAPTCHA, 2FA, changed provider UI, expired links, or
  approval.
- Fully unattended browser export MUST remain experimental and disabled by default.
- Private web API scraping MUST NOT be a first-party canonical ingestion path.
- A collector MAY queue admitted uploads while the node is unavailable.
- The queue MUST be encrypted, bounded by age and size, visible to the owner, and retried with
  backoff.
- Queue expiry MUST NOT imply source deletion. A later reconciliation SHOULD rediscover eligible
  records from canonical local history.
- Successful routine sync SHOULD remain quiet. Stale sources and required human action SHOULD be
  surfaced.

## Client Authorization

Each client MUST use a separate revocable credential. A shared installation-wide bearer token is
not permitted.

- Collectors receive upload access only for registered device and source identities.
- Assistant clients receive search, evidence-read, and proposal access.
- Schedulers may stage, verify, and import under standing source authorization but may not curate.
- Approval, correction, deletion, key management, and client management remain local
  administration capabilities.
- Public network access MUST terminate at an authenticated HTTPS or OAuth/OIDC boundary.
- Every local application HTTP route that reads or mutates application state MUST require
  authentication. A fixed application shell and its content-free static assets MAY remain
  unauthenticated solely to accept an in-memory credential. A liveness route MAY also remain
  unauthenticated when it returns a fixed content-free status. Neither exception may expose
  installation, source, account, storage, version, or readiness metadata. Loopback binding is
  containment, not authorization.
- Local same-host operation SHOULD prefer stdio or a Unix-domain socket where the client supports
  it.
- Remote MCP authorization MUST use protected-resource metadata, PKCE, resource indicators,
  issuer and audience validation, short-lived resource-bound tokens, narrow scopes, and step-up
  authorization where required by the current MCP specification.
- OAuth discovery MUST reject unsafe redirects, private-address pivots, and mixed authorization
  servers. State MUST bind the client, redirect URI, resource, and initiating session.
- Token passthrough and a shared installation-wide bearer token are prohibited.
- MCP compatibility MUST be accepted separately for each client, client version, transport, and
  capability. A passing Codex client MUST NOT be used as proof for ChatGPT, Claude, or Grok web.
- The SQLite database, object-store credentials, and root key MUST NOT be exposed through MCP.

## Attachments And Enrichment

- Admitted attachments MUST retain identity, media type, byte length, digest, source linkage, and
  conversation linkage.
- Bounded deterministic extraction MAY index straightforward text and PDF content.
- Attachment type and size limits MUST be configurable.
- Large attachments SHOULD be hydrated and verified only when requested.
- OCR, transcription, image captioning, and model-based analysis MUST be optional enrichments.
- Derived enrichment MUST identify its model artifact revision and digest, reviewed license,
  runtime and version, hardware, preprocessing, creation time, and source object.
- Model-specific remote code MUST NOT be enabled during install or inference.
- Model inference SHOULD run without network access after an explicitly approved artifact download.
- Derived enrichment MUST NOT replace or silently alter the original attachment.
- Attachment preservation MUST work when no LLM or multimodal model is configured.
- Explicitly approved, already-held uninspected attachments MAY be preserved in encrypted backup
  without content inspection. Their contents MUST remain unavailable to search and model-facing
  evidence, including inline payloads inside raw message JSON. Label unsupported content
  `not_inspected`; storage/extraction alone does not verify inspection. Keep original bytes,
  digests and provenance unchanged, and identify withheld raw evidence rather than presenting a
  filtered record as exact. Known secrets and explicit no-memory exclusions remain blocked.
  This exception does not authorize importing new uninspectable attachments.

## Community Adapters

- Community adapters MUST be explicitly installed and execute out-of-process.
- An adapter MUST declare required filesystem and network capabilities.
- An adapter MUST receive only the selected source or export.
- An adapter MUST NOT receive ledger, storage, or encryption credentials.
- The core MUST reapply schema, admission, authority, access, and privacy validation to adapter
  output.
- Unknown adapter output MUST fail closed into encrypted staging.

These boundaries reduce exposure but do not constitute a perfect sandbox claim.

## Telemetry

Telemetry MUST be disabled by default. Explicitly enabled diagnostics MAY contain coarse version,
platform, connector, error category, latency, and success data. They MUST NOT include content,
queries, paths, account identifiers, device identifiers, storage locations, or credentials.

## Redaction And Deletion

- High-confidence secrets MUST be rejected before source upload and indexing.
- Redaction creates a new representation plus an auditable reference to the action.
- Ordinary retrieval MUST not expose redacted content or stale projections.
- Deletion MUST support selected conversations and complete source accounts.
- Deletion MUST cover source objects, normalized events, projections, caches, attachments, and
  derived summaries according to policy.
- Deletion MUST retain a text-free tombstone sufficient to prevent routine reimport.
- Registered source-account deletion MUST use canonical identity, not shared display labels.
  Legacy local-import aliases MUST NOT broaden deletion or reimport blocks to enrolled devices.
- Record erasure MUST preserve admitted neighbors and refuse unresolved shared-evidence conflicts.
  Certified message identities cover source variants; exact-byte fallback MUST NOT be described
  as protection against changed-byte records lacking a reliable identity. A privacy correction
  marking an existing record no-memory is pending erasure, not completed deletion.
- Retiring redundant web-container copies is not conversation or account deletion. It MUST preserve
  admitted records and provenance, record an auditable operation, and leave future admitted imports
  enabled. It MUST NOT claim erasure from other references, earlier packages, or remote versions.
- Message-level redaction MAY be omitted when a source format cannot support it without ambiguous
  evidence claims.
- Restore tests MUST verify that deleted material is not silently reintroduced from an older projection or backup.
- Deletion MUST rebuild affected FTS and optional semantic projections and MUST vacuum or replace
  the database under a documented procedure. `secure_delete` alone is not deletion proof.
- Verification MUST show that ordinary retrieval, exact-evidence recovery, hydration, and portable
  exports cannot return the deleted content.
- Any immutable-retention feature MUST be reconciled with promised deletion before activation.
- Product documentation MUST state the actual backup-retention limit and MUST NOT imply deletion
  from backups that still retain the object.
- Every deletion preview and completion MUST disclose retained local snapshots, recovery packages,
  portable exports, provider histories, and remote objects/versions outside its explicit scope.
  Remote deletion requires an authorized version-aware operation. Its durable exact scope MUST
  precede removal of storage mappings; a local-only plan MUST NOT silently acquire remote targets.

## Rebuild And Recovery

A valid rebuild MUST:

1. Start from an empty local database.
2. Restore source manifests and required encrypted objects.
3. Verify ciphertext and plaintext hashes after decryption.
4. Verify the SQLite snapshot with both `integrity_check` and `foreign_key_check`.
5. Recreate normalized events with pinned source, adapter, schema, and parser versions.
6. Rebuild projections.
7. Compare record counts, graph links, exclusions, and a frozen query suite.
8. Verify that tombstones and redactions remain effective.

An upload success message is not recovery proof.

Before first real import, setup MUST create and verify a provider-independent offline recovery
kit for the installation root key. A platform keychain or mounted secret MAY hold the operational
key but MUST NOT be the only recovery path.

The ordinary recovery surface is intentionally small:

- `backup` uses SQLite's online backup API to create one consistent encrypted snapshot and uploads
  it when configured.
- `restore --verify` restores into a new location and verifies schema, manifests, hashes, and
  required objects.
- Backup scheduling is optional.
- The last successful backup and last verified restore MUST be inspectable.
- Recovery status receipts MUST be fully written and fsynced in a same-directory staging file,
  then atomically published without replacement. Snapshot recovery MUST preserve their private
  read-only mode.
- A digest-named local receipt detects corruption or an unexpected rewrite on a trusted host. It
  does not authenticate evidence against a malicious process running as the same local user. Any
  stronger claim requires a keyed signature or an independently stored anchor.

## Portable Export

The default portable export MUST be encrypted and provider-neutral. It includes admitted source
objects, normalized events, provenance, contexts, candidates, approvals, corrections, tombstones,
and device and source mappings without credentials. Rebuildable search indexes SHOULD be omitted.

A plaintext export MAY exist only as an explicit high-risk operation. Importing a portable bundle
MUST verify its schema, manifest, object hashes, and encryption metadata before changing a live
ledger.

## Contract Versioning

- Schema and policy versions MUST be recorded on every derived artifact.
- Breaking changes require a migration plan and replay test against the frozen corpus.
- Old query receipts MUST remain interpretable after upgrades.
- A contract change that affects admission, access, context, authority, or retrieval requires the
  full adversarial evaluation suite.

The evidence and assumptions behind v0.7 are recorded in the
[2026-08-27 specification audit](../research/spec-audit-2026-08-27.md).
