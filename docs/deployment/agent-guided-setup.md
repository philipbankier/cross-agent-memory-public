# Agent-Guided Setup

The setup self-check verifies isolated synthetic state on macOS and Linux: a fresh node,
client identities and credentials, enrollment, source registration, collector pairing and
service planning. Verify your own real import, questions, exact evidence, replay and reconnect
before relying on an installation. The self-check is not live-account or answer-quality proof.

The canonical bootstrap skill is `skills/cross-agent-memory/SKILL.md`. Thin adapters under
`.agents/skills/`, `.claude/skills/` and `.grok/skills/` expose that one workflow in this checkout.
`CLAUDE.md` imports the repository `AGENTS.md`, so both agents receive the same constraints.

Repository-local skills are not automatically available from other projects. When connecting a
daily-use client, also make the canonical skill discoverable in that client's supported user-skill
directory. Use a thin adapter pointing to this checkout's absolute canonical path, not a second
copy of the workflow or a repository-relative path from the home directory. Preserve existing
skills. Verify discovery from an unrelated working directory and verify the client actually reads
the skill during a memory question. MCP connection alone proves neither of those boundaries.
On a thin client without the repository, a pinned byte-identical installation of the canonical
skill may be the adapter target instead. Record its source revision and digest, refresh it when
the canonical workflow changes, and identify it as query-only: setup operations still require
a verified full checkout and its current instructions. Do not maintain a second edited workflow.

## Design Contract

Setup is a sequence of small, dependency-ordered operations. It is not one installer with ambient
authority. Each operation inspects a narrow state, seals its intended change and precondition in a
plan hash, and either performs an exact no-op or changes only that leaf.

The local ledger sequence is `setup-inspect`, `setup-plan`, `setup-apply`, and `setup-verify`.
Inspection and verification use immutable read-only database descriptors and never select or emit
transcript values. Verification runs SQLite integrity and foreign-key checks and requires exactly
one installation identity. Neither operation initializes directories or migrates a schema.

Identity operations use these separate plan and apply pairs:

- `client-registration-plan` and `client-registration-apply`
- `client-credential-plan` and `client-credential-apply`
- `device-enrollment-plan` and `device-enrollment-apply`
- `source-registration-plan` and `source-registration-apply`

Each plan is a singly linked mode-`0400` file in a mode-`0700` directory. It contains no bearer
secret, enrollment secret, provider credential, or transcript text. Repeating the same plan command
at the same path reuses an exact matching plan and rejects a conflicting request. Credential and
enrollment apply stage secret material before database mutation, publish a text-free receipt, and
atomically publish the secret file without replacement. Lost responses and interrupted publication
therefore resume with the same credential rather than creating another one.

Use explicit stable intent keys for clients, credentials, and device enrollments. An intent key is
operator-chosen configuration, not a label inferred from an email address, account name, transcript,
or filesystem path. Source account labels must likewise be stable opaque operator labels because
the schema uses them as part of source identity.

Applying one identity plan changes the identity-state digest. Plan and apply one leaf before
planning its dependent leaf. This technical sequencing does not require a separate human approval
for each leaf of an already-authorized operation.

## Typed Human Gates

Every consequential plan returns `required_human_gates`. Each entry has exactly:

- `format_version`
- `kind`
- `action`
- `target`
- `target_state_sha256`
- `impact`
- `rollback`
- `gate_sha256`

The containing `plan_sha256` binds the complete gate for machine verification. Obtain authorization
for a named operation with its devices/accounts, access, cost, impact, and rollback. That scope
covers expected substeps and safe retries. Preserve exact hashes in private receipts, but do not ask
the user to approve again solely because the next leaf or regenerated plan has another hash.

Changed state requires inspection and a current plan. Ask again only when the operation materially
changes identity, access, cost, destructive impact, public exposure, or product/security semantics.
Do not execute a stale plan or treat a receipt as authorization for an unrelated operation.

Fresh local ledger initialization has no human gate because it is local, empty, and reversible.
Identity creation, credentials, pairing, source registration, service installation, transcript
access/import, and cloud operations require coverage by the named authorization; they need not
each interrupt the user. Required login/2FA, unverified devices/accounts, new access or cost,
destructive user-data changes, public exposure/publication, and material ambiguity still stop for
input. Continue independent safe work while a dependent action awaits that input.

## Private Working Directory

Choose one durable private directory outside `CAM_HOME` and retain it until the complete setup is
verified. Do not use a disposable directory that an agent may lose between turns.

```bash
export CAM_HOME="$HOME/Library/Application Support/cross-assistant-memory"
export CAM_SETUP_STATE="$HOME/Library/Application Support/cross-assistant-memory-setup"
install -d -m 700 "$CAM_SETUP_STATE"
```

On Linux, explicitly set the data root to
`${XDG_DATA_HOME:-$HOME/.local/share}/cross-assistant-memory`; use a separate mode-`0700` setup-state
directory beside it. The runtime's implicit default currently uses the macOS-style path on every
platform, so this explicit choice is required to use XDG. Existing roots are never moved automatically.

## Recovery Key Placement

Before affected real-data work, verify independent recovery custody and a synthetic fresh restore;
`setup-verify` does not establish either. The [remote storage guide](../../REMOTE.md#encrypted-b2)
covers recovery command discovery, including
`recovery-install-key` and `backup --operational-key` for an owned mounted key file outside
`CAM_HOME`. Its parent must already be owned by the runtime user with mode `0700`.

Install from an existing verified root kit and recovery secret. Exact retry preserves the existing
operational file. Routine backup can then use that file without loading the independent recovery
secret. Treat the operational file as a secret, not a recovery copy; never include it in source
collection, Git, or cloud uploads. Installation reports independent custody as unverified and does
not rotate keys, change services, or authorize removal of any existing copy. Confirm the separate
recovery location with the user and perform the recovery drill before claiming readiness.

## Initialize Or Verify The Ledger

From the repository root:

```bash
script/setup
script/cross-memory --home "$CAM_HOME" setup-inspect
script/cross-memory --home "$CAM_HOME" setup-plan \
  --output "$CAM_SETUP_STATE/local-ledger.plan.json"
```

Read the JSON response directly. Do not scrape a rendered terminal or recompute its hash.

For `initialize_fresh_local_ledger`, preview and apply the same plan:

```bash
script/cross-memory --home "$CAM_HOME" setup-apply \
  --plan "$CAM_SETUP_STATE/local-ledger.plan.json" \
  --expected-plan-sha256 '<exact plan_sha256>'

script/cross-memory --home "$CAM_HOME" setup-apply \
  --plan "$CAM_SETUP_STATE/local-ledger.plan.json" \
  --expected-plan-sha256 '<exact plan_sha256>' \
  --execute
```

For `verify_existing_local_ledger`, use the first apply command only. Finish either path with:

```bash
script/cross-memory --home "$CAM_HOME" setup-verify
```

Fresh setup builds the selected runtime's current schema and a plan marker in a deterministic
private sibling staging root, then publishes it with an atomic no-replace rename. An exact complete
staging root left by an abrupt
exit is resumed only when its path, schema, private metadata, and markers match the plan. Incomplete
staging is deleted and rebuilt only when narrow ownership evidence proves it belongs to the exact
plan; unmarked, unsafe, or conflicting state is preserved for review. Reapplying the original
successful plan returns `already_configured` and cannot adopt an unrelated ledger.

## Register An Assistant Client

Plan one assistant identity with only the capabilities it needs:

```bash
script/cross-memory --home "$CAM_HOME" client-registration-plan \
  --output "$CAM_SETUP_STATE/macbook-codex-client.plan.json" \
  --label 'MacBook Codex' \
  --kind assistant \
  --intent-key 'assistant:macbook:codex' \
  --capability memory:search \
  --capability memory:evidence-read \
  --capability memory:status
```

Preview the exact plan with `client-registration-apply` without `--execute`. After approval of its
typed gate, repeat with the same plan and hash plus `--execute`. Record the returned `client_id`,
then immediately reapply the same plan and require `already_configured`.

Create its bearer credential as a separate leaf:

```bash
script/cross-memory --home "$CAM_HOME" client-credential-plan \
  --output "$CAM_SETUP_STATE/macbook-codex-credential.plan.json" \
  --client-id '<exact client_id>' \
  --intent-key 'primary' \
  --ttl-hours 2160 \
  --credential-output "$CAM_SETUP_STATE/macbook-codex.token"
```

Preview, review the typed credential gate, then apply the same plan and hash with `--execute`.
The token appears only in the mode-`0600` output file. It is not returned in plan, apply, receipt,
or log output. Exact replay verifies the same database row, receipt, and token file and returns
`already_configured`. An expired or revoked credential requires an explicit new intent and review;
the old plan is not silently renewed.

Repeat the two leaves for each distinct assistant client. Do not share one client credential among
Codex, Claude Code, ChatGPT, or another host merely because they belong to the same person.

## Enroll A Source Device

On the authoritative node, create one short-lived pairing-code plan:

```bash
script/cross-memory --home "$CAM_HOME" device-enrollment-plan \
  --output "$CAM_SETUP_STATE/imac-enrollment.plan.json" \
  --label 'iMac Claude Code collector' \
  --platform 'macOS arm64' \
  --intent-key 'device:imac:claude-code-collector' \
  --ttl-minutes 10 \
  --credential-ttl-days 90 \
  --enrollment-output "$CAM_SETUP_STATE/imac-enrollment.code"
```

Preview, review the typed enrollment gate, then apply the same plan and hash with `--execute`.
Transfer the resulting mode-`0600` code through the approved local secret channel. Never put it in
arguments, chat, logs, Git, or documentation.

On the source device, preview collector redemption using the exact non-secret enrollment metadata:

```bash
script/cross-memory collector-enroll \
  --url 'https://approved-node.example/enroll' \
  --credential-output "$CAM_SETUP_STATE/collector.token" \
  --enrollment-id '<exact enrollment_id>' \
  --device-label 'iMac Claude Code collector' \
  --device-platform 'macOS arm64'
```

After approval of that command's typed gate and plan SHA-256, repeat the exact arguments with
`--expected-plan-sha256`, `--execute`, and the code on stdin. The source device stages its own
collector token before network use. An ambiguous response retries the same code and staged token;
the node accepts only an exact replay. A completed rerun reads neither the code nor the network and
returns `already_enrolled`.

The returned `device_id` is the dependency for source registration. Provider credentials and native
history never move during pairing.

## Register Source Policies

Plan one source account after device enrollment is complete:

```bash
script/cross-memory --home "$CAM_HOME" source-registration-plan \
  --output "$CAM_SETUP_STATE/imac-claude-code-source.plan.json" \
  --device-id '<exact device_id>' \
  --source-system claude_code \
  --account-label 'imac-claude-code-primary' \
  --scope user_global
```

Use `--scope project --project-id '<exact project id>'` only for a genuinely project-scoped source.
Do not invent a project for account-wide evidence. Preview, review the typed source-policy gate,
apply the exact plan with `--execute`, and immediately require an `already_configured` replay.
Repeat sequentially for each approved Codex, Claude Code, or Grok Build identity on that device.

## Collector Config And Service

Build one explicit format-2 private collector config from the approved node URL, collector-token
path, separate bounded queue and queue-key paths, and returned source-account IDs. Creating the
config does not authorize opening its source roots. Validate it without syncing:

```bash
script/cross-memory collector-config-validate \
  --config "$CAM_SETUP_STATE/collector.json"
```

Preview the service as a separate leaf:

```bash
script/cross-memory collector-service-install \
  --platform launchd \
  --config "$CAM_SETUP_STATE/collector.json" \
  --executable '/absolute/reviewed/venv/bin/cross-memory'
```

Use `--platform systemd` on Linux. The preview returns exact file hashes, target paths, a typed
service gate, and one plan SHA-256 without creating files or calling the manager. After approval,
repeat the exact arguments with `--expected-plan-sha256` and `--execute`. Exact ready state is a
no-op; verified file-first partial state resumes; conflicting manager or filesystem state is
preserved. See `docs/deployment/native-collector-service.md`.

Do not run `collector-sync` until real source access and ingestion are separately approved.

## Pause And Recovery Rules

- `active`: SQLite coordination state is uncheckpointed, incomplete, changing, or its writer
  lease is occupied. Identify the writer before any service action. An unchanged, private
  WAL/SHM pair with a zero-byte WAL may be verified while setup holds the existing exclusive
  writer-file lease. Inspection neither checkpoints nor deletes sidecars; readiness does not
  prove that a service is stopped. Frozen backup readers still require no sidecars.
- `legacy`: preserve a verified backup and use the separate reviewed migration workflow.
- `newer`: install a compatible reviewed runtime.
- `partial`: rebuild only narrowly proven plan-owned crash debris; preserve unmarked or ambiguous
  state for diagnosis.
- `invalid`: schema metadata or integrity is unavailable.
- `unsafe`: a path, owner, mode, link count, or file type violates the private-state contract.
- `expired unredeemed enrollment`: create a new intent only after review; never extend the sealed
  expiry in place.
- `changed target` or `intent conflicts`: stop. Do not overwrite, chmod, delete, or regenerate a
  different credential in the same turn.

Retry the exact approved plan after uncertainty. It may resume complete plan-owned staging or
remove and rebuild narrowly proven incomplete crash debris. Preserve unmarked, unsafe, unrelated,
or conflicting state. Never repair state merely to make a verifier pass.

## Acceptance

A clean-host setup pass is accepted only when:

- every plan and gate hash is retained;
- every consequential leaf has an approval-bound apply receipt;
- a second pass returns only verified or already-configured states;
- database counts show exactly the intended clients, credentials, devices, enrollments, and source
  policies;
- no second credential or service-manager transition occurs;
- plans, receipts, command output, logs, and Git contain no secret material or transcript text;
- unsafe, stale, conflicting, and interrupted cases pause without destructive cleanup; and
- `setup-verify`, `doctor`, and the applicable text-free client or collector status checks pass.

Local tests and clean synthetic passage do not prove live provider accounts, real source freshness,
cloud recovery, real ingestion, client compatibility, or useful cross-source retrieval. Those are
separate roadmap boundaries.
