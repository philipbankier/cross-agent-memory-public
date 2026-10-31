# Grok Bot Capture Qualification

This feature branch is not released full Grok Bot support. Native read-only querying and
source collection are separate permissions. An OAuth memory reader cannot upload history.
Do not point an older six-source node at these uploads or change a working fleet to test them.

The current adapter retains only eligible outward `SendToUser` requests from a target-bound
native `ReadTranscript` page. It does not retain reasoning, other tool traffic or user-role
messages. Sending a reply is not proof of delivery. The internal `grok-bot-app:<Bot ID>` scope
is not a provider conversation ID. Author, native conversation and occurrence time stay unknown.

## Enrolled Collection

Use an existing separately enrolled collector principal, bound to one Grok Bot source account
and device. Keep its token and the queue encryption key in different owner-only files, outside
the queue. All personal Bots on a shared provider computer may be able to read those files;
this is not per-Bot credential isolation. Shared/group capture is not qualified.

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
body after restart. Duplicate pages retain one pending item per exact observation. Status is
read-only, including for an existing older queue.

Queue schema 7 widens the source checks, preserving ciphertext, cursor state and relationships
when explicitly initialized from schemas 3 through 6. Older collectors cannot open schema 7;
an old wrapper is not a queue rollback. This change does not migrate the ledger schema.

CAM snapshots restore admitted evidence and configuration, not Grok's cloud computer, its
native learned memories or connector logins. Retain the queue and its separately protected key
for unsent records. Never reconstruct an acknowledgement or skip a failed page to catch up.

## Remaining Qualification

- Real source enrollment, compatible deployed readers and a separately approved upload route.
- User messages, native memories, autonomous/delegated work and linked artifact representations.
- Native identity, chronology, edits, visibility and completeness limits, without fabricated IDs.
- Real capture, reconnect, replay, revocation and restore through the approved transport.
- The approved six-hour native routine, created only after actual admission/recovery acceptance.
- Panel/setup integration and clean-user qualification before calling the feature supported.

Memory search is not a complete memory snapshot. A routine read is not its execution history.
An artifact link or current text is not its version history. Keep these distinctions visible
when the provider does not supply the corresponding source or metadata.
