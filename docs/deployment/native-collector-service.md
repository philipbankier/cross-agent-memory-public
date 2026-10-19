# Native Collector Service

Date: 2026-08-30
Updated: 2026-09-20

This profile runs the Codex, Claude Code, and Grok Build collector from one explicit format-2
collector configuration. It provides equivalent user-level launchd and systemd schedules without
copying provider credentials into a service file.

## Schedule Contract

- The service runs as the logged-in user, never as root or a system daemon.
- Every invocation runs `collector-sync --config <absolute-path> --quiet`.
- launchd uses a user LaunchAgent with `RunAtLoad` and `StartInterval=900`.
- systemd uses a user oneshot service and timer with `OnStartupSec=1min`,
  `OnUnitActiveSec=15min`, and `Persistent=false`.
- A powered-off or inactive device does not accumulate catch-up executions.
- Routine success is silent. Attention and failure output contains collector state and hashes, not
  transcript text.
- With `--quiet`, attention output keeps progress/failure counters but replaces the full queue
  source inventory and initial-selection mapping with counts. Source-attention, missing-source,
  selection-conflict, missing-selection, queue-attention and replay-required-source lists show
  at most ten entries each, with their full counts. A displayed list is not the complete inventory.
  `collector-status` and `collector-sync` without `--quiet` retain detailed output. This bounds
  scheduled diagnostic amplification, not lifetime log retention; existing logs are not truncated.
- The collector scans and encrypts admitted local segments before attempting upload, so an offline
  node does not turn a scheduled run into evidence loss.

Both platforms use the same config path and executable. Generated service definitions contain
those two paths, the fixed collector command, and logging or timer settings. The two launchd log
leaves are pre-created as empty private regular files. None of the installation files contains the
node bearer credential, queue key, provider credential, account content, or transcript text.

## Bounded Backfill

Each source may include `excluded_files`, an optional list of at most 256 unique absolute file
paths beneath that source's root. No globs, directories or symlinks are accepted. Omission keeps
the existing behavior. Use exact paths for known evaluation histories; normal discovery still
follows new sessions and projects under the root. Validation reports only the exclusion count.
Excluded files are not opened or counted as current sources. If a batch was already queued before
exclusion, upload is blocked with `source_excluded` even if the original file is now absent.
Its retained ciphertext needs separate reconciliation; this setting is not local or remote erasure.

Each sync also checks every retained upload against its loaded configuration's opted-in
`(source_system, source_account_id)` pairs before credential or network access. Removing the last
matching opt-in blocks that account's queued uploads with the existing `source_excluded` state;
other opted-in accounts can continue. Restoring the opt-in does not silently release blocked
items: use the existing `collector-retry --config <path> --item-id <id>` when recovery is intended.
Ciphertext, batch identity and acknowledged cursors are preserved. Native file cleanup alone
does not revoke an account opt-in, so its already-captured batches remain recoverable. This is
not root-level revocation, an immediate change to an in-flight sync, node credential revocation,
deletion of admitted evidence, or cancellation of already-committed publication work.

One sync reserves at most 64 source-file attempts, 64 segment reads, and 8 GiB of logical source
read work. Normal segments remain at most 4 MiB, with at most 16 per file. Reservations cover metadata,
prefix verification, segment rereads, and a possible schema-hold reread; they are conservative
estimates, not measured disk traffic, RAM allocation, staging space, or a wall-clock deadline.
Directory enumeration and queue bookkeeping are outside this source-content budget. Uploads keep
their separate 256-batch cap and configured timeout; metadata bridges and the bounded publication
retries below are additional HTTP requests, not additional acknowledged batches.

If the first complete physical JSONL record exceeds 4 MiB, the collector reserves additional
read work and reparses exactly one record, capped at the existing 64 MiB file-parser bound.
This is not a larger normal batch or permission to retain oversized messages: existing admission
excludes them, while known ignored metadata produces a small ordinary metadata-only upload.
Partial/over-limit records remain unacknowledged. Unknown/malformed large records report
`large_record_schema_unverified` without storing their raw bytes in the ordinary schema-hold
queue. Source, prefix and native-ordinal verification remain mandatory. Exact replay uses the
retained frame boundary. Metadata-gap repair keeps its existing 4 MiB segment and 256 MiB read
bounds; large skipped frames still refuse, as do message-bearing gaps. No cursor is advanced
without a verified node acknowledgement.

With remote-primary storage configured, each HTTP upload completes at most one publication
object, including work needed to recover a full admission queue. The response validator still
accepts one through four completed objects for compatibility with older nodes. This reduces
consecutive expensive publication work under the writer; it does not bound lock acquisition,
admission or an individual object's provider/integrity work. A healthy bounded drain may
acknowledge a committed batch once all its own and shared objects have authenticated verified
encrypted mappings and no remaining publication or owned-plaintext retirement work. Unrelated
queued work does not withhold that receipt, including for excluded-only metadata bridges. The
check stays under the exclusive writer, finishes the object-write journal first and makes no
provider reads. Global status and snapshot refusal still reflect all pending work.
If the batch remains unfinished, the node returns a text-free, batch-bound
`503 publication_pending` response with completed-object count and `Retry-After: 1`. This is
progress, not an acknowledgement. Provider failures, invalid mappings and pre-admission capacity
failures cannot take the completion shortcut. The collector retries the exact
retained request, with at most 32 extra progress retries shared across the flush and its metadata
bridges. It starts no further progress retry once its 300-second window has elapsed; an in-flight
request still has its configured timeout. Neither this window nor the object cap is a hard
whole-sync or HTTP wall-clock deadline. Individual provider operations can still time out.

The native node is a latency-sensitive HTTP service, unlike the scheduled laptop scanner.
Writable HTTP nodes refuse a contended writer lease promptly with `503 writer_busy` and
`Retry-After: 30`, rather than retaining request workers throughout a backup or other exclusive
write. Authentication and MCP reads keep their read-only connections. The existing collector
classifies this response as retryable server failure, retaining exact encrypted batches and
cursors for normal backoff; it does not block the batch as a malformed upload or accelerate retries.
Enrollment likewise yields without consuming its code. Ordinary CLI writers retain blocking
lock acquisition, and a verified owning writer token is never reacquired. This is an internal
HTTP policy, not a new schedule, client option or grant of write access.
Do not copy the collector's macOS background process class to the node without timing its
complete requests. In the September 15 deployment, background scheduling made four-object
requests cross the existing 60-second client timeout. The node now launches with
`ProcessType=Standard`, `/usr/sbin/taskpolicy -c utility`, and retained `Nice=10`; the collector's
background schedule and all request/queue limits are unchanged. Check the executable on the
target host before updating its plist. Preserve the existing definition and verify readiness,
exact evidence and an ordinary collector retry after the change. See the measured
[node scheduling follow-through](../evaluation/publication-scheduling-2026-09-15.md#native-node-follow-through),
not a guarantee about other hosts or provider latency.

On budget exhaustion the collector reports `publication_pending` without recording a new failure,
retains its ciphertext/cursor, and leaves continuation for the next ordinary invocation. Actual
provider/transport failures retain normal backoff. Generic, malformed and oversized 503 pages are
not accepted as progress. A final verified receipt remains required before local acknowledgement.
Unbounded CLI maintenance drains are unchanged. Upgrade the node before the collector; older
collectors safely back off on the new 503 response but do not accelerate its retry.

Connection closure before an HTTP response and interrupted response-body reads retain the exact
batch with ordinary network backoff. The pass reports the failed upload; a later matching receipt
is still required before acknowledgement. Malformed completed responses and mismatched receipts
remain blocked. Existing holds from older transport classification require explicit
`collector-retry`, not automatic clearing or a queue reset.

Opaque account/path-bound rotation points live in the existing queue database. Changed files and
new files modified within one cadence receive priority turns, alternating with ordinary backfill.
Each group has its own rotation point. The next group also survives interruption or insufficient
remaining byte budget, so neither a continuously busy file nor a large backlog owns every fresh
pass. A position advances before a file's first reserved read but never advances an evidence
cursor. Prefix validation, exact expired-batch replay, and node acknowledgement still control
admission/progress. Queue capacity failure stops scanning and still permits the bounded upload flush.

At most 4,096 text-free observations retain a stable device/inode/size/mtime/ctime tuple and exact
scanned cursor. Unchanged completed files consume no source-content budget. A saved observation
must match both current metadata and the current scan cursor; expiration or a changed cursor
invalidates the skip. Incomplete final records wait for a metadata change without being admitted.
Appends, rewrites, replacements and unknown files still use the ordinary prefix-hashing reader.
Observations are recorded only when file metadata stays stable around that read. Evicting an old
observation removes no evidence or cursor. These are scheduling hints, not a transcript cache or
new cryptographic verification; `metadata_unchanged_files` names that limited basis explicitly.

`collector-status` separately reports `coverage.acknowledged_unchanged_files` and
`coverage.pending_or_unverified_files`. A matching complete observation must agree with the
account-bound acknowledged cursor and current file metadata, not only a queued scan boundary.
Unscanned, changed, partially read or unacknowledged files make an initialized collector `pending`,
even with an empty queue. Actionable failures still take precedence. Queue schemas 3 and 4 have
no file observations, so status reports coverage as unverified without migrating them. Coverage
does not read source contents or contact the node; `freshness_guaranteed` remains false.

Budget-limited work returns `pending`, which is silent with `--quiet`.
`collector-sync` also remains `pending` while any queue item awaits acknowledgement, including
upload-limit exhaustion and retained transport backoff. Waiting does not create another failure,
retry early, or override actionable attention. Only a drained queue can clear this condition.
Without `--quiet`, `scan_work` reports reservations and limits; `source_files_seen` includes the discovered inventory
and `source_files_attempted` includes this pass's attempts. A single verification exceeding the
entire byte budget reports `source_read_limit`, not success or an unsupported schema. Other files
can still progress. The measured 2.4 GB Codex file fits the default reservation, but this arithmetic
is not a real backfill performance test. Eligible skips avoid unchanged-prefix reads; changed files
still pay their full verification cost. There is no metadata-only admission shortcut or promise
that every pending file completes in one cadence when aggregate work exceeds the limits.

The first sync upgrades pinned schema-3, schema-4 or schema-5 queues to schema 6 transactionally.
Ciphertext, keys, cursors, replay boundaries, observations and rotation points are preserved;
payload authentication remains format 3. Read-only status accepts all four versions without migrating.
Unknown legacy schemas fail closed. This is unrelated to the node ledger schema or service cutover.

## Selected Initial History

A Codex source may optionally list `initial_selections`, with at most 256 exact JSONL paths
under its opted-in root. Each entry has exactly `path`, `start_record_ordinal`,
`start_byte_offset` and `start_prefix_sha256`. Both offsets are positive physical positions;
the digest is the lowercase SHA-256 of every byte before that boundary. Do not use native
history ordinals or offsets from a previous file revision. No globs, symlinks, directories,
duplicate paths or overlap with `excluded_files` are allowed. Other source families do not
support this setting. Omission preserves collection from zero.
Overlapping roots under one account must agree on each selected file's initial boundary;
neither source ordering nor an overlapping exclusion can silently change that selection.

Use this only after approving the content scope and independently verifying the physical
boundary of a source that has not initialized under this enrolled account/path. It is not an
existing-stream reset, a queue repair, proof of a copied-history boundary, or authority to read
a different account. The parser still derives conversation, lineage, speaker and authority;
the selection only limits the collected range. Prefix hashing reads the omitted bytes locally
for verification, but neither stores nor uploads their messages. Those reads consume the existing
work budget. Normal privacy admission still applies to the selected suffix.

Queue schema 6 commits the selection with the first encrypted upload or schema hold. The
starting position is not an acknowledgement: `last_success_at_epoch` stays unset until a
matching ordinary node receipt. Exact retries and expired-batch reconstruction preserve that
start. Changing or removing a retained selection refuses scanning and blocks pending uploads
with `source_excluded`; restoring it requires ordinary explicit retry of blocked work. There
is no setter to rewind or replace it. Metadata-gap repair refuses gaps before the selection.

`collector-status` exposes retained starts as `queue.initial_selections` and
`coverage.selected_prefixes`, plus `selection_conflicts` and `missing_selected_files`. These
text-free boundaries disclose omitted physical prefixes, not a claim that all other captures
omit the same content or that provider history is complete. A selection does not delete legacy
evidence. Preserve the previous runtime and queue before a controlled collector upgrade;
older runtimes refuse schema 6. No node schema or upload-format change is required.

## Parser Upgrades

Deploy compatible node readers before upgraded collectors. Codex uploads accept the explicit
0.2.0, 0.2.1 and 0.2.2 parser versions, not arbitrary versions. Retained batches keep their original bytes;
expired retries must reproduce the retained batch ID exactly, including earlier parser metadata.
A changed interpretation that cannot reproduce that identity remains blocked.
After reconstruction, scanning successors requires the encrypted queue head to match all retained
replay fields and the acknowledged starting cursor. The replay boundary is not cleared by that
check; only the exact node receipt clears it. This avoids treating ordinary successors as an
expired-boundary conflict while preserving ordered acknowledgement after interrupted delivery.

Codex 0.2.2 recognizes copied-context boundaries for the four exact producers listed in
`docs/research/codex-copied-history-boundaries-2026-09-14.md`. This requires a paginated subagent
history, child metadata at native ordinal zero, a parent identity, no history base and a positive
native child-start ordinal. Every consumed line must have its expected physical/native ordinal
and a known schema. Copied metadata is allowed only before the child boundary. Inherited content
is not emitted as evidence or stored in schema holds; later delegated prompts retain assistant
authority. Fully copied prefixes with no child messages use ordinary metadata-only uploads.
Partial prefixes cannot be reported complete at EOF. Unverified declarations, malformed records
and unknown copied schemas refuse without storing their raw content. This changes no source
authorization, node schema or remote key policy, and does not read another history/account.

Each bounded sync may reparse an existing schema hold's exact original byte range, before any
later append. Replacement requires matching source/account/path binding, ordinal and byte bounds,
prefix digests, and authenticated held plaintext. The replacement upload, including an empty
metadata-only upload, commits in the same SQLite transaction as hold removal. Admission, capacity or insert
failure retains the original hold; only ordinary ordered acknowledgement advances the source
cursor. Unknown formats stay held without resetting their age. No queue reset or manual database
edit is part of upgrading. Explicit Codex forks still need verified replay boundaries.

## Metadata-Only Progress And Legacy Gaps

Every valid advancing segment uses the ordinary encrypted queue and authenticated upload receipt,
including a segment with no message records or exclusions. Upload format 2 accepts such segments
only when both ordinal and byte bounds advance. No raw metadata bytes are sent. Deploy the updated
node before collectors; older nodes reject empty batches. `cursor_checkpoints_advanced` remains
zero for output compatibility, not as a second acknowledgement channel.

Legacy queued checkpoints are reparsed at their original exact bounds and replaced atomically by
empty uploads. The encrypted checkpoint authenticates source/provenance, ordinals, bytes and both
prefixes. Successors retain their ciphertext. Missing, changed, newly meaningful or unknown source
data refuses conversion. Checkpoint-containing chains remain byte-bounded but may exceed the age
limit until conversion; expiry must not silently acknowledge them. Ordinary expiry resumes after
conversion, with the existing exact-batch replay guard.

For an already locally acknowledged gap, only the authenticated, authorized upload route returns
the node cursor in a batch-bound `409 cursor_gap` response. The collector verifies the entire
missing interval against the retained batch's starting ordinal/prefix, requiring known schema,
unchanged source identity and no parsed message records. It then sends empty ordinary bridge
batches before retrying the unchanged retained upload. Neither cursor is manually edited. The
original encrypted queue item is the durable retry anchor: after lost acknowledgements or restart,
the original request either succeeds or reports the remaining gap. Bridges do not carry evidence
objects or raw metadata and do not establish fresh provider coverage.

Each sync reserves at most 256 MiB of extra source-read work for these legacy gaps, including
prefix verification and metadata inspection. Budget exhaustion stays retryable and visible as
`cursor_gap_work_limit`; oversized or unavailable source ranges require investigation, not a
weakened guard. Other rejected uploads remain blocked until an explicit diagnostic retry.

## Review Before Install

Set absolute paths to the private collector config and the installed CLI entry point. The CLI entry
point must be a regular executable owned by the current user or root and not group- or
world-writable.

On macOS:

```bash
script/cross-memory collector-service-install \
  --platform launchd \
  --config /absolute/private/collector.json \
  --executable /absolute/venv/bin/cross-memory
```

On Linux:

```bash
script/cross-memory collector-service-install \
  --platform systemd \
  --config /absolute/private/collector.json \
  --executable /absolute/venv/bin/cross-memory
```

Without `--execute`, the command is read-only. It validates the config and executable, renders the
platform files in memory, and returns their target paths, modes, SHA-256 hashes, the config and
executable hashes, one `plan_sha256`, and a typed `service_installation` gate. The gate includes the
exact action, target, target-state SHA-256, impact, rollback, and `gate_sha256`; the plan hash binds
all of those fields. It does not create a directory or file and does not call launchctl or systemctl.

Changing the config bytes, executable bytes, platform, target user home, schedule, rendered service
files, or human-gate content changes `plan_sha256`.

## Install After Approval

Installation starts the collector immediately and may read opted-in local histories, create the
encrypted queue and queue key, and contact the configured node. Treat it as a live-data and service
change. Confirm authorization covers this device, source scope, service and resource impact.
Retain the exact config, typed gate, `gate_sha256`, and dry-run `plan_sha256` as machine checks;
an internal hash change alone does not require renewed approval within unchanged authorized scope.
Revalidate the plan against current state, then run:

```bash
script/cross-memory collector-service-install \
  --platform launchd \
  --config /absolute/private/collector.json \
  --executable /absolute/venv/bin/cross-memory \
  --expected-plan-sha256 <approved-plan-sha256> \
  --execute
```

Use `--platform systemd` on Linux. Execution rebuilds the plan and refuses a hash mismatch, root
execution, conflicting target bytes or metadata, a manager identity loaded from another path, a
manager-first state without exact service definitions, a failed manager-state probe, symlinked or
broadly writable service directories, an unsafe executable or config, or the wrong operating
system. systemd drop-ins, stale definitions requiring a daemon reload, and masked units are not
accepted as ready state. New files and the private advisory lock use mode `0600`; an existing lock
must already have exact private metadata and is never chmodded into compliance.

A loaded launchd identity is path-bound and definition-bound. Its reported executable, complete
argument vector, stdout and stderr paths, interval, throttle, background process type, `RunAtLoad`,
and low-priority I/O state must match the approved plist. A matching pathname alone is not ready
state. systemd readiness likewise requires both exact fragment paths, no drop-ins, and no pending
daemon reload.

Installation is convergent for one exact plan. Exact service files plus a ready manager return
`already_installed` without another manager command. Exact file-first partial state is resumed by
creating only missing files and applying only missing manager transitions. launchd log contents may
grow after an exact service definition exists, so reruns verify their owner, type, mode, and link
count rather than requiring them to remain empty. A nonempty log cannot establish a fresh install
by itself. launchd clears an explicit disabled override before bootstrap and accepts both current
`enabled`/`disabled` and boolean disabled-state output. An ambiguous manager-command failure is
accepted only when an immediate state probe proves the requested transition occurred. systemd
reload proof additionally requires `NeedDaemonReload=no`. A definite failure leaves verified files
and observable manager state in place for an identical retry; it does not perform destructive
rollback that could remove a service it no longer knows it exclusively owns.

The installer rehashes the config and executable and rechecks every service file immediately before
each manager transition and before reporting success. This detects accidental concurrent drift. It
does not claim protection from a malicious process running as the same user, which can replace
user-owned inputs again after any check.

launchd writes:

```text
~/Library/LaunchAgents/cross-assistant-memory.collector.plist
~/Library/Logs/cross-assistant-memory/collector.out.log
~/Library/Logs/cross-assistant-memory/collector.err.log
```

systemd writes:

```text
~/.config/systemd/user/cross-assistant-memory-collector.service
~/.config/systemd/user/cross-assistant-memory-collector.timer
```

## Verification

After an approved installation, verify the service manager and the text-free collector state:

```bash
launchctl print "gui/$UID/cross-assistant-memory.collector"
script/cross-memory collector-status --config /absolute/private/collector.json
```

On Linux:

```bash
systemctl --user status cross-assistant-memory-collector.timer
script/cross-memory collector-status --config /absolute/private/collector.json
```

The expected proof is one scheduled execution plus an immediate sync, a quiet successful run, and
a visible stale or actionable failure state under a synthetic or explicitly approved outage.

## Proof Boundary

Unit tests render and apply both service formats inside temporary directories and inject synthetic
service-manager results. That proves deterministic planning, user-level paths, cadence, secret-free
rendering, strict plan binding, private file modes, exact no-op replay, file-first recovery,
ambiguous-success reconciliation, conflict refusal, and serialized identical intents. Parser tests
also bind launchd and systemd state to exact definition paths, reject systemd drop-ins and stale
reload state, handle launchd disabled overrides, preserve unrelated lock metadata, and catch input
replacement before activation. Read-only checks against macOS 26.2 confirmed launchd's missing-job
return code and current state-output syntax. This does not prove a real installation, clean Linux
passage, Mac-to-node connectivity, a real credential, source retention, provider behavior,
scheduled passage, or private-data ingestion.
