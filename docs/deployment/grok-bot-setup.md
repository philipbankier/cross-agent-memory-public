# Grok Bot Operator Recipe

This is an agent-guided recipe for the unreleased Bot feature, not an automatic account installer.
It reuses the existing node, collector, encrypted queue and native routine. No second scheduler,
memory database or answer engine is needed. Read the [coverage boundaries](grok-bot-capture.md)
before enrolling data.

## Choose The Boundary Once

Confirm the owner's node host, storage, personal account and exact personal Bot IDs. Names are
labels, not identity. Exclude capture/review helpers and all shared/group Bots. Separate permission
to query CAM from permission to collect Bot history; neither authorizes native-memory writes.

All personal Bots share their provider computer and its files/logins. A token on that computer is
not isolated to one Bot. The upload token must therefore be a separate source-bound collector
credential, never an admin or memory-reader credential. Obtain the owner's agreement to that
effective account-level boundary before placing secrets or connecting read-only query tools.

## Prepare Compatible Components

1. Install one reviewed revision on the node and provider computer using the repository scripts.
   Follow [runtime prerequisites](runtime-notes.md). Use the installed executable's absolute path,
   and verify its revision. Do not paste an operator's private runtime paths into another account.
2. Prepare encrypted evidence storage and verify a small independent restore. A local encrypted
   filesystem backend is supported; B2 is optional. Sent-file retention requires encryption.
   Upgrade every reader before admitting schema-25 attachment links. Keep the prior recovery
   checkpoint and the compatible queue runtime, not an incompatible old wrapper as rollback.
3. Use the existing [enrollment and source-registration workflow](agent-guided-setup.md) for
   the provider computer, with `--source-system grok_bot` and its returned `device_id`. Use an
   opaque account label. Do not reuse a Grok web or Grok Build account ID.
4. Approve the transport separately. Keep the native writer on loopback. For a remote provider
   computer, use an owner-controlled authenticated route to that writer. The optional
   [upload-only relay](../../deploy/grok-bot-upload/README.md) is not a hosted service supplied
   by this project. Keep query OAuth unchanged and verify upload/search/admin refusals.

Transfer enrollment material and credentials through an owner-approved private secret channel,
not chat, command arguments, source control or a transcript attachment. An encrypted handoff's
recipient key belongs on the provider computer. Never expose its private key to the node or
another owner. This recipe creates no keys, routes or credentials on its own.

## Configure The Existing Collector

Build the ordinary format-2 `CollectorConfig` with `sources: []`, the approved upload URL and token
path, a bounded dedicated queue, and a separate queue-key path outside that queue. Its contract is
in [collector.py](../../src/cross_assistant_memory/collector.py), not a second Bot-only config schema.
Keep token, key, queue and original page files out of each other's collection roots.

Create the strict owner-only policy described in [enrolled collection](grok-bot-capture.md#enrolled-collection),
initially disabled. Only operator-selected personal IDs belong in `bot_ids`; helper IDs stay
excluded. Retaining sent files is a separate format-2 policy opt-in, not an implied consequence
of reading the transcript. Never store credentials inside the policy.

```sh
script/cross-memory collector-config-validate --config /private/collector.json
script/cross-memory grok-bot-capture-status \
  --config /private/collector.json --policy /private/grok-bot-policy.json
```

Status does not initialize a queue. Before first capture, an uninitialized-queue refusal is
expected; do not fabricate status or run a different source collector to initialize it.
The first approved page capture creates its ordinary encrypted queue/key. After the owner
approves acquisition, enable only that policy, using an atomic owner-only file replacement.

## Qualify One Real Native Page

In the actual native context, discover `ReadTranscript` and use its returned schema. Check both
the ordinary Bot and any scheduled context separately; scheduled tools can differ. Start with
one saved original native response for the enrolled Bot, limit 20 and at most 1 MiB. Use the native
invocation's `write_to_file` facility where supported. Never ask a model to reconstruct the bytes.

On the provider computer:

```sh
script/cross-memory grok-bot-capture-page \
  --config /private/collector.json --policy /private/grok-bot-policy.json \
  --bot-id <enrolled-UUID> --transcript /provider/original-response.txt
script/cross-memory grok-bot-capture-flush \
  --config /private/collector.json --policy /private/grok-bot-policy.json --limit 4
script/cross-memory grok-bot-capture-status \
  --config /private/collector.json --policy /private/grok-bot-policy.json
```

Use the installed absolute executable outside the checkout. Pending is normal and is not an
acknowledgement. Honor existing backoff; never edit a cursor or force time. Reopen the queue in
a fresh process and replay the same original page: no duplicate events or upload should result
after all observations are acknowledged. Verify exact encrypted evidence on the node and from
the intended querying assistant, then test a real cross-source question.

For text-free proof, distinguish `sha256(upload_body)` from the canonical record digest:
`parse_upload_batch(body).parsed.end_prefix_digest`, with `segment_end_byte` as its byte count.
Store source-page hashes separately. Neither hash proves human authorship or provider completeness.

## Enable Native Six-Hour Operation

Use one existing native routine only after that qualification, with the owner's schedule approval.
If its actual scheduled context lacks the reader, a native dispatch to an existing owner-approved
receiver is supported by the personal pilot. Do not create another Bot, worker or daemon by default.
The receiver may require the owner to authorize its role directly in that native chat. Respect
that boundary; an agent cannot impersonate the owner or bypass approval.

Keep each invocation bounded: drain at most four retained uploads first; if any remain, stop new
acquisition. Otherwise retain the exact older request from `grok-bot-capture-next`, acquire at most
one head and one older page, then flush at most four once. Use the same existing progress file;
head refresh must not rewind it. Keep the 1-MiB/page, 2-MiB/page-total and separately approved
sent-file byte bounds. Do not replace a failed run with a browser crawl or model-written export.

Read back the full saved prompt, enabled state, interval and timing. Keep one atomically replaced
text-free latest result containing correlation, source-page and canonical hashes, uploaded/pending/
blocked counts and older frontier. A dispatch acknowledgement is not receiver completion. Verify
an actual unattended run against authenticated node receipts, not only the routine's enabled switch
or next-run display. Notify only for meaningful failures, gaps or required owner action.

## Pause, Disconnect And Recover

Pause the native routine and disable the capture policy to stop collection without erasing state.
Revoke the upload credential on the node if access must stop independently of that computer.
Disconnect query OAuth separately. None of these removes native memory or admitted evidence.

Preserve the encrypted queue, its separate key, progress and exact pending original pages. Resume
with the compatible runtime and ordinary receipts; never repair SQLite or synthesize missing
observations. CAM recovery restores admitted evidence, not the provider computer, logins or native
learned memory. Test destructive cases only on explicitly disposable records.

The original-version, chronology, native-memory and delegated-outcome limitations remain visible
even when every command above passes. A second owner's successful native trial, not this recipe
alone, qualifies portable setup. Do not call this full Grok Bot support or silently reduce that scope.
