# Native Collector Pairing

Date: 2026-09-03
Updated: 2026-09-04

This profile pairs one source Mac with the authoritative node without moving any Codex, Claude
Code, or Grok Build provider credential. The source Mac receives a separate, revocable collector
credential that can report status and upload only for source accounts the node later binds to that
device.

## Boundary

Pairing has three distinct actions:

1. The node creates one short-lived, single-use enrollment code for a predeclared device label and
   platform.
2. The source Mac creates a separate collector token, stages it privately, and sends it with the
   code to `/enroll`. The node stores only its digest and the source Mac publishes the token to the
   approved private file after accepting the response.
3. A local node administrator registers each allowed native source account and its fixed scope,
   then the source Mac references those opaque account IDs in its collector config.

The enrollment code is not a provider credential and never becomes the collector credential. The
collector token cannot search, retrieve evidence, curate memory, administer clients, delete data,
or upload for an unregistered source account. Source account registration is not bundled into
redemption because its scope and project policy require a separate owner decision.

Creating a code, redeeming it, registering source accounts, opening a tunnel, creating a live
config, or reading native histories crosses a live approval boundary. The commands below are an
operator runbook, not authorization to execute them.

## Prepare The Source Mac

Install the same reviewed revision and create a current-user directory with mode `0700`. Choose a
new credential leaf that does not exist. Do not start the collector or create its live config yet.

Remote enrollment requires HTTPS. Plain HTTP is accepted only for `localhost` or a loopback IP. A
node that remains bound to loopback can be reached through a separately approved SSH local-forward
instead of exposing the origin:

```bash
ssh -N -L 18765:127.0.0.1:8765 node-host
```

In that case, use `http://127.0.0.1:18765/enroll` in both preview and execution. The SSH transport
protects the remote leg while the enrollment client still sees a loopback HTTP endpoint. Bind the
forward to loopback and do not use `-g`.

## Create One Enrollment On The Node

Create a sealed, text-free plan in a private mode-`0700` setup-state directory on the authoritative
node:

```bash
script/cross-memory --home /absolute/node/data device-enrollment-plan \
  --output /absolute/private/device-enrollment.plan.json \
  --label "Approved source Mac" \
  --platform "macOS arm64" \
  --intent-key "device:approved-source-mac" \
  --ttl-minutes 10 \
  --credential-ttl-days 90 \
  --enrollment-output /absolute/private/device-enrollment.code
```

Preview the returned plan with `device-enrollment-apply` without `--execute`. Obtain approval for
its exact action, target, impact, rollback, `plan_sha256`, and `gate_sha256`, then apply only that
plan:

```bash
script/cross-memory --home /absolute/node/data device-enrollment-apply \
  --plan /absolute/private/device-enrollment.plan.json \
  --expected-plan-sha256 <approved-plan-sha256> \
  --execute
```

The code is written only to the mode-`0600` output file. Do not place it in shell arguments, chat,
logs, tickets, Git, or documentation. Transfer it through the approved local secret channel and
redeem it before expiry. The node stores only the code digest and rejects modification and expiry.
After the first redemption, only the exact same code and client-generated credential token can
replay the result; a different token is rejected. Reapplying the exact creation plan recognizes a
redeemed enrollment as already configured while its device credential lifetime remains valid.

The result also contains the non-secret `enrollment_id`, `device_label`, and `device_platform`.
Record those three exact values separately from the code. They bind approval and response
validation to the intended device.

## Preview On The Source Mac

Preview the exact endpoint, output path, and non-secret enrollment metadata:

```bash
script/cross-memory collector-enroll \
  --url https://memory.example/enroll \
  --credential-output /absolute/private/collector.token \
  --enrollment-id <enrollment-id> \
  --device-label "Approved source Mac" \
  --device-platform "macOS arm64"
```

The preview is read-only. It validates the endpoint and every output-path component, opens no
network connection, reads no enrollment code or credential content, and creates no file. Its
`plan_sha256` binds the format version, exact URL, absolute credential path, enrollment ID, device
label, and platform. Changing any of those fields invalidates approval. If the output already
exists, preview reports `credential_verification_required`; only an execute run may read it and
verify its matching receipt.

## Redeem On The Source Mac

Re-run the preview immediately before execution and obtain approval for its exact `plan_sha256`,
device, endpoint, and credential path. Execution requires the matching digest and reads one code
line from stdin:

```bash
script/cross-memory collector-enroll \
  --url https://memory.example/enroll \
  --credential-output /absolute/private/collector.token \
  --enrollment-id <enrollment-id> \
  --device-label "Approved source Mac" \
  --device-platform "macOS arm64" \
  --expected-plan-sha256 <approved-plan-sha256> \
  --execute
```

When stdin is a terminal, the client disables echo while reading the code and restores it before
any network use. Do not put the code in the command line. Before reading the code or contacting the
node, the client creates and fsyncs a random credential token in a plan-hash-bound mode-`0600`
staging file. A mode-`0600` advisory lock serializes identical local attempts. The request sends the
code and staged token; neither appears in command output. The node returns only identifiers and
expiry metadata, never the token.

The client ignores environment proxies, enforces a 15-second deadline across DNS, connection,
headers, and body, and rejects redirects and unbounded or unexpected responses. First acceptance
uses HTTP `201`; an exact replay uses `200`. After a valid response, the client atomically publishes
a text-free, plan-bound mode-`0400` receipt, then atomically moves the staged token to the exact
approved output at mode `0600`. It never overwrites an existing output.

An ambiguous transport failure retains the same staged token. Re-running the same approved plan and
code sends the same token, so the node returns the original device, client, and credential instead
of creating an orphan. If a valid receipt was durable before interruption, the next execute run can
finish local publication without reading the code or using the network. Once output and receipt are
both complete, another execute run verifies them and returns `already_enrolled` without network or
code access. Invalid, mismatched, symlinked, hard-linked, or conflicting state fails closed and is
not replaced automatically. Legacy mode-`000` markers from older revisions are not auto-recovered;
inspect and resolve them under the credential-recovery boundary.

## Register Allowed Sources On The Node

Use the returned `device_id` to plan each approved local provider account separately. The account
label is a stable opaque operator label, not a provider login or secret:

```bash
script/cross-memory --home /absolute/node/data source-registration-plan \
  --output /absolute/private/codex-source.plan.json \
  --device-id <enrolled-device-id> \
  --source-system codex \
  --account-label <approved-opaque-label> \
  --scope project \
  --project-id <approved-project-id>
```

Preview `source-registration-apply` without `--execute`, review its typed gate, then apply only the
exact approved plan and hash with `--execute`. Reapply it and require `already_configured` before
planning the next source because each applied policy changes the identity-state digest.

Repeat only for approved `claude_code` and `grok_build` accounts. A non-project source may use the
approved broader scope supported by the policy contract; do not invent a project merely to satisfy
the example. Record each returned `source_account_id` for the config, not the provider credential.

## Build And Validate The Collector Config

The format-2 config contains:

- the node's `/upload/batches` URL and the new collector-token file;
- a separate queue root and queue-key file outside that root;
- bounded queue size and age;
- one explicit native source root, returned source-account ID, and observed client version per
  approved source.

Detecting roots is text-free, but opening real histories is separately gated:

```bash
script/cross-memory collector-detect --user-home /Users/source-user
script/cross-memory collector-config-validate --config /absolute/private/collector.json
script/cross-memory collector-status --config /absolute/private/collector.json
```

The config must use absolute no-symlink paths. Keep the transport credential, queue key, and queue
root separate. Validate before any `collector-sync`; synchronization opens opted-in native history,
creates encrypted local state, and contacts the node.

## Acceptance And Revocation

Live pairing is not accepted until all of the following are recorded without transcript text:

- the node and source Mac run the same reviewed revision;
- the approved enrollment plan digest matches execution;
- the code, response enrollment ID, device label, and platform match that approved plan;
- the token file is a current-user regular file with mode `0600`;
- the enrolled device and collector client exist, with only `memory:status` and `source:upload`;
- every source-account policy names the intended device, source family, scope, and optional project;
- a synthetic or explicitly approved upload is accepted only for its matching source account;
- replay, a mismatched source account, and use after revocation fail closed; and
- no provider credential appears in the node, config, service file, queue, logs, or evidence.

Revocation occurs on the node by credential ID. It does not alter the provider account or delete
the source Mac's history. Removing the local token or source config is a separate destructive
action and requires its own approval.

## Proof Boundary

Local tests cover device-bound plan approval, no-read dry-run behavior, no-echo terminal input, a
real in-process `/enroll` schema round trip, proxy bypass, redirect and total-deadline enforcement,
private no-symlink descriptor publication, exact response validation, exact-path reservation, and
failure-marker behavior with synthetic identities. They do not protect a source account after the
source device or current user is compromised, and they do not prove a Mac-to-Mac tunnel, TLS
deployment, real code transfer, source-account policy, real token, provider isolation,
native-history access, upload, revocation, or service installation.
