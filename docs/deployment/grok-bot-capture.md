# Grok Bot Capture Qualification

This feature branch is not released full Grok Bot support. Native read-only querying and
source collection are separate permissions. An OAuth memory reader cannot upload history.
Do not point an older six-source node at these uploads or change a working fleet to test them.

The current adapter retains eligible outward `SendToUser` requests and verbatim user-role text
from a target-bound native `ReadTranscript` page. It does not retain reasoning or other tool
traffic. User-role text is a source observation, not attested human authorship: embedded timestamp,
turn and machine tags are not parsed into authoritative fields. Sending a reply is not proof of delivery.
The internal `grok-bot-app:<Bot ID>` scope
is not a provider conversation ID. Author, native conversation and occurrence time stay unknown.

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

- Real source enrollment, compatible deployed readers and a separately approved upload route.
- Verified user authorship/chronology, native memories, autonomous/delegated work and linked artifacts.
- Native identity, chronology, edits, visibility and completeness limits, without fabricated IDs.
- Real capture, reconnect, replay, revocation and restore through the approved transport.
- The approved six-hour native routine, created only after actual admission/recovery acceptance.
- Panel/setup integration and clean-user qualification before calling the feature supported.

The tested personal runtime exposes memory through ranked `RecallMemory`, including the calling
Bot's memory and shared user memory, not a verified exact per-Bot snapshot with revisions. A
Bot-named cache folder or an empty local transcript table is not that snapshot. Do not read
other Bots or shared-memory contents merely because the computer is account-shared. Keep this
limitation separate from the qualified conversation-observation path.

Memory search is not a complete memory snapshot. A routine read is not its execution history.
An artifact link or current text is not its version history. Keep these distinctions visible
when the provider does not supply the corresponding source or metadata.
