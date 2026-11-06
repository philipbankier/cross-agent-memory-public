# Grok Bot Capture Qualification

This adapter provides bounded personal-Bot history support, not full Grok Bot support.
Native read-only querying and
source collection are separate permissions. An OAuth memory reader cannot upload history.
Do not point an older six-source node at these uploads or change a working fleet to test them.

## Start With Your Own Installation

Use v0.2.0 or a later verified release, not a release that predates the Bot adapter.
The [agent-guided setup](agent-guided-setup.md) supplies node, identity and recovery commands.
The [operator recipe](grok-bot-setup.md) connects those existing steps to native Bot capture.
Do not copy another operator's account IDs, cloud paths, credentials or deployment files.

One personal-account pilot has verified native querying, bounded source admission, encrypted
sent-file recovery, replay/reconnect and an actual unattended six-hour upload run. That does not
qualify every account, client version or the unsupported provider surfaces below. A clean second
installation still needs its own native-tool and real-source checks.

The current adapter retains eligible outward `SendToUser` requests and verbatim user-role text
from a target-bound native `ReadTranscript` page. Outward requests include text replies, the
qualified question widget, and attachment references. It does not retain reasoning or unrelated
tool traffic. User-role text is a source observation, not attested human authorship: embedded timestamp,
turn and machine tags are not parsed into authoritative fields. Sending a reply is not proof of delivery.
The internal `grok-bot-app:<Bot ID>` scope
is not a provider conversation ID. Author, native conversation and occurrence time stay unknown.

Text and user-role observations retain format 1 and parser `0.1.0`, including their original
hashes and replay identities. Structured requests use format 2 and parser `0.2.0`. A compatible
node must accept both before the collector emits structured requests. Declaring a structured
record as the old parser, or a text record as the new parser, refuses.

Native `SendToUser` arguments may be an object or a JSON-encoded object; decoding rejects
duplicate keys and non-JSON constants before the same field and privacy checks. Other tools'
serialized inputs remain unqualified. Tool-call IDs retain their exact bytes, including the
observed `call-<UUID>-<integer>\nfc_<UUID>_<integer>` compound form with one literal newline.
Do not split or normalize that identifier or treat either component as proof of delivery.
Deploy a reader accepting the compound form before its collector; old observation bytes and
replay identities remain unchanged. Other multiline identifiers refuse.

The observed question widget supports both single-question `prompt`/`options` and multi-step
`prompt`/`steps` layouts. Boolean flags, help text and option descriptions/styles are validated
against the native schema. Optional values are retained as supplied, never synthesized into an
answer or approval. Structured sends may include a boolean `end_turn`; it stays inside the
request content, not a delivery receipt. Unknown fields and mixed single/multi-step layouts refuse.
Keep existing multi-step canonical bytes and replay identities unchanged. Preserve the exact
structured request as canonical JSON, not as an answered question or an approval. Unknown fields,
types and widgets refuse. The 32-step and 64-option bounds are CAM resource limits, not claims
about provider limits. Ordinary privacy and byte limits still apply before retention.

The qualified attachment send has `type=attachment` and one `file:///workspace/...` URL. Retain
that locator as an attachment reference only: do not open it or imply its bytes, delivery or
original version are verified. Hosts, query/fragment credentials, path traversal and unqualified
URL schemes refuse. A reference does not authorize reading an arbitrary file. Binary retention,
artifact contents/versions and other provider attachment layouts require their own acquisition
and privacy qualification; do not silently omit them and call history complete. Default policy
status reports `attachment_contents_captured=false` and `question_answers_attested=false`.

## Sent Artifact Acquisition

The guarded reader in `grok_bot_artifacts.py` selects attachment sends from a target-bound
transcript page and the existing explicit personal-Bot scope. It opens only the exact referenced
workspace file, with no symlink traversal, folder discovery, URL fetching or filename substitution.
Credential and collector paths, hard links and foreign-owned files refuse before payload access.
The caller must supply a byte bound. File-descriptor and directory-entry identity must remain
stable across the bounded read; a missing, oversized or changed file is a disclosed gap.

Known privacy exclusions apply even to opaque media metadata. The existing deterministic text
policy can make eligible text inspectable; other payloads remain uninspected and must not enter
model-facing output. Manifests contain reference/content digests, size and media hints, never
payload bytes. A file URL does not attest the version sent, its creator, delivery or immutability.
Observed filesystem times stay separate from stable content identity: touching an unchanged
file must not invent a new artifact version.

Artifact retention is a separate opt-in. Use policy format 2 with the same enrolled source/Bots
and `preserve_sent_artifacts: true`; policy format 1 remains reference-only. Both the collector
and native writer must be updated first. The node requires encrypted evidence publication,
including when the encrypted backend is a local filesystem rather than B2.

```sh
script/cross-memory grok-bot-capture-artifact --config /private/collector.json \
  --policy /private/grok-bot-policy.json --bot-id <enrolled-UUID> \
  --transcript /provider-owned/original-page.txt --tool-call-id <exact-send-call-ID> \
  --max-bytes 1048576
```

This command queues one bounded current-file observation, never uploads directly. Ordinary
flush and exact receipts apply. The format-3 upload preserves the original reference/parser and
adds one independently hashed payload. The encrypted queue gives this child upload its own
batch-bound receipt cursor, without rewinding or duplicating the parent transcript stream.
Lost receipts and restarts replay the identical ciphertext. The parent event gains metadata-only
manifests, not another searchable event or payload-reading tool. Changing bytes can retain a new
observed content version, never overwrite or attest the originally sent version. Admission caps
each file at 1 MiB and each parent at 32 observations; larger or unavailable files remain gaps.
These are implementation resource bounds, not provider limits.

Ledger schema 25 adds only the child-object linkage. Upgrade all readers before admission and
preserve the prior schema-24 recovery checkpoint; older readers cannot open schema 25. Snapshots
include links and exact objects, and parent erasure includes unshared child objects. Old collectors
cannot decode retained format-3 uploads: retain the compatible runtime, queue and separate key
until those receipts settle. Do not treat an old wrapper as a compatible rollback.

The personal-account pilot has recovered one real sent-file snapshot byte-for-byte from encrypted
storage. Both live readers return only its metadata. The upload receipt-loss/reconnect/replay
check passes without duplicate parent events. This is current observed-file recovery, not proof
of its originally sent version or a complete media archive. Qualify your installation separately;
an attachment reference or enabled policy alone proves none of these outcomes.

## Enrolled Collection

Use an existing separately enrolled collector principal, bound to one Grok Bot source account
and device. Keep its token and the queue encryption key in different owner-only files, outside
the queue. All personal Bots on a shared provider computer may be able to read those files;
this is not per-Bot credential isolation. Shared/group capture is not qualified.

The existing control panel names this source Grok Bot, separately from Grok Build and Grok web
history. Use its ordinary source-registration and deletion controls; registration does not
enable capture or prove a routine is running. Source status distinguishes indexed history from
observed collection and never promises freshness from an upload receipt.

The collector JSON uses the ordinary native collector configuration, with `sources: []` and
a dedicated encrypted queue. `CollectorConfig` in `collector.py` defines that contract.
The separate `0400` owner-only policy has this shape, using returned account IDs and actual
operator-enrolled personal Bot IDs rather than display names:

```json
{
  "format_version": 1,
  "enabled": false,
  "source_account_id": "source_account:<returned 64-character lowercase digest>",
  "bot_ids": ["<enrolled personal Bot UUID>"],
  "collector_bot_id": "<capture Bot UUID>",
  "excluded_bot_ids": ["<evaluation Bot UUID>"]
}
```

The collecting Bot cannot be a target. Do not infer personal visibility from an owned Bot's
name, account access or a library listing. An explicit policy is required before any source read
or queue operation. Disabling it refuses subsequent page capture and upload without deleting
pending ciphertext or admitted evidence. Revoke the collector credential separately to stop
another process from submitting, and stop its native routine. Disconnecting query OAuth is a
different operation and does not delete source data.

## Queue And Recovery

```sh
script/cross-memory grok-bot-capture-page --config /private/collector.json \
  --policy /private/grok-bot-policy.json --bot-id <enrolled-UUID> \
  --transcript /provider-owned/exact-transcript-page.txt
script/cross-memory grok-bot-capture-status --config /private/collector.json \
  --policy /private/grok-bot-policy.json
script/cross-memory grok-bot-capture-flush --config /private/collector.json \
  --policy /private/grok-bot-policy.json --limit 4
```

Page capture performs no network request. It reads one bounded stable page and retains only
filtered observations in the existing encrypted queue. A queued observation is not searchable
yet. Flush uses existing authenticated uploads and exact receipt validation; it advances only
after node acknowledgement. A lost acknowledgement can be retried with the identical queued
body after restart. Duplicate pages retain one pending item per exact observation. Without native
user-message IDs, byte-identical user text coalesces; edits, utterance counts and complete chronology
are not qualified. Do not treat admission order as conversation order. Status is
read-only, including for an existing older queue.

The observed native transcript can repeat an identical reply tool call within one page. Exact
call-ID/content/end-turn matches coalesce; conflicting reuse of that ID on a page refuses capture.
Tool-call IDs remain source metadata, not globally unique event keys. Ledger identity includes the
source stream and complete normalized observation object. Neither duplicate observations nor
header position ranges establish the number or chronology of unique native messages.

Queue schema 7 widens the source checks, preserving ciphertext, cursor state and relationships
when explicitly initialized from schemas 3 through 6. Older collectors cannot open schema 7;
an old wrapper is not a queue rollback. This change does not migrate the ledger schema.

## Older History Progress

Keep ordinary head refresh separate from older-history traversal. A recent page or a positive
overlap count is not proof of complete history. Native header positions can include gaps; do not
convert their spans into message counts or infer individual message positions from page overlap.

Use one private progress file per enrolled Bot, with its parent owned by the current user and
mode `0700`. The file is `0400`, bound to the enrolled source/Bot, collector and queue/key. It
stores only pagination metadata, observation digests and the original provider file's path, not
transcript text. It is not another database or scheduler.

```sh
script/cross-memory grok-bot-capture-next --config /private/collector.json \
  --policy /private/grok-bot-policy.json --bot-id <enrolled-UUID> \
  --progress /private/bot-progress.json --limit 20
```

`read_page` returns the exact native `in`, `limit` and `before` request. On first use it requests
a head page, without creating progress. Acquire the original native output and submit it with
the progress file:

```sh
script/cross-memory grok-bot-capture-page --config /private/collector.json \
  --policy /private/grok-bot-policy.json --bot-id <enrolled-UUID> \
  --progress /private/bot-progress.json --transcript /provider-owned/original-page.txt
```

Before any observation is queued, the command durably records the complete pending-page intent.
It still uses the same privacy filter, ciphertext queue and authenticated upload protocol. Flush
with the existing command, then call `grok-bot-capture-next` again. Its actions are:

- `flush`: retained uploads remain; honor normal backoff and the existing four-item flush bound.
- `replay_page`: the queue has no pending uploads but acknowledgement is missing. Replay only the
  returned original file/hash, including after expiry or a partial enqueue interruption.
- `attention`: a blocked upload or schema hold needs diagnosis; never skip it or force a cursor.
- `read_page`: all expected observations have acknowledged cursors. Only then does older-page
  progress move to the actual native footer token.
- `native_pagination_exhausted`: the validated native page chain reached its beginning. This does
  not attest a complete conversation, unexposed messages, stable revisions or native memories.

The next older page must end immediately before the requested native boundary. A skipped page,
changed pending source, wrong Bot/account/queue/key or unsafe progress file refuses. Replaying the
last exact traversed page is a no-op. An empty queue alone never advances progress: expiry is not
acknowledgement. Internal-only or excluded-only pages may record validated traversal without
claiming any node ingestion. Normal head capture without `--progress` cannot reset this frontier.

Retain original provider page files until their page intent is acknowledged. A process restart can
flush queued ciphertext first, then replay a partially queued original. If the original is lost
and some observations were never queued, report that source gap; do not reconstruct source text
with a model or repair SQLite. Keep the queue, progress file and separate queue key for this
collector's recovery. They are distinct from CAM's admitted-evidence snapshots.

CAM snapshots restore admitted evidence and configuration, not Grok's cloud computer, its
native learned memories or connector logins. Retain the queue and its separately protected key
for unsent records. Never reconstruct an acknowledgement or skip a failed page to catch up.

For a private remote node, the optional [upload-only relay](../../deploy/grok-bot-upload/README.md)
forwards only this enrolled source/account to the existing native writer. It has no query route
or stored bearer credential. Its VPC binding must target the writer, not a read-only App reader.
Batch-bound publication-pending responses remain retryable progress, never acknowledgements.
Keep the existing query OAuth connection unchanged and enable neither route nor routine until
compatible readers and actual admission/recovery checks pass.

## Remaining Qualification

| Surface | Current boundary |
| ------- | ---------------- |
| Personal Bot querying and filtered capture | Verified on one explicitly enrolled personal Bot; each new owner must qualify their own source and reader access. |
| Six-hour operation | Actual scheduled dispatch, receiver upload and node receipts verified in that pilot. Some runs only drain retained uploads. |
| Older history | Acknowledgement-bound traversal works; a partial frontier is not complete backfill or chronology. |
| Sent files | Encrypted observed-file snapshots and exact recovery work; original versions, creators and delivery remain unverified. |
| Native learned memory | No exact target-bound snapshot/revision source has been established. Ranked recall is not an export. |
| Routine/delegation outcomes | Tool requests and reported outcomes are not independently verified completion receipts. |
| Shared/group Bots | Not qualified. Account-level access does not establish conversation audience or per-Bot credential isolation. |
| Portable setup | Existing commands and operator recipe are available; another owner's real native trial remains required. |

The tested personal runtime exposes memory through ranked `RecallMemory`, including the calling
Bot's memory and shared user memory, not a verified exact per-Bot snapshot with revisions. A
Bot-named cache folder or an empty local transcript table is not that snapshot. Do not read
other Bots or shared-memory contents merely because the computer is account-shared. Keep this
limitation separate from the qualified conversation-observation path.

Memory search is not a complete memory snapshot. A routine read is not its execution history.
An artifact link or current text is not its version history. Keep these distinctions visible
when the provider does not supply the corresponding source or metadata.

As checked November 2, 2026, the available personal-runtime definitions expose ranked memory
recall but no exact per-target snapshot with shared-memory exclusion. They expose saved routine
configuration rather than run-result history, and current file reads rather than original sent
versions. A missing field in a tool definition is not proof no provider output can ever supply
it. Preserve unverified fields as unknown; do not infer chronology or human authorship from
display tags. [Provider memory behavior](https://cursor.com/help/grok-bot/memory) and
[working with Bots](https://prod.cursor.com/docs/grok-bot/work) describe the relevant native
boundaries. Enterprise telemetry is a different entitlement and opt-in, not a personal-account
fallback that setup may enable automatically.
