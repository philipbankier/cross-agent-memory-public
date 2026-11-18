# Set Up For Daily Use

The finish line is Codex and Claude Code finding your approved history and picking up each other's
work, with evidence you can check and new history arriving without a manual import each time.
A demo, a listed MCP tool or one successful import is only a checkpoint.

## Choose The Scope Once

Use the [README prompt](../README.md#connect-your-own-history) in either agent. Its default is
local storage on this Mac, both clients and hourly native collection. No B2 account, separate
server, browser extension or extra model subscription is required.

| Choice | Full local setup |
| ------ | ------------------- |
| Node | This computer, with a persistent loopback receiving service |
| Query clients | Codex and Claude Code with separate read-only identities |
| Storage | Local; encrypted B2 is optional and not part of this path |
| History | The local native roots/accounts and exclusions you approve once |

Confirm roots and account identities before reading conversation content. Include archived
histories only where their location and format are supported. Do not scan the whole home directory
or include another person's/shared account by inference. Preserve private/no-memory exclusions.

For a small trial instead, explicitly choose one conversation and no background jobs. Stop after
the small-import and question checks below. Do not describe that trial as full daily-use setup.
For a remote node, choose your own host and follow [REMOTE.md](../REMOTE.md).

You do not need a project taxonomy. Global, project, session and assistant-private scopes exist;
use the one that matches the material. Do not make personal work fit a fictional project.

## What Your Agent Must Finish

1. Verify the checkout and selected Python with `script/doctor`, then install using `script/setup`.
   Choose a durable source folder, explicit `CAM_HOME`, and private credentials/setup state outside
   both the checkout and collection roots. Preserve any existing installation rather than replacing it.
2. Initialize/verify the node and create separate read-only client identities for Codex and Claude
   Code. Connect the actual clients, not only an SDK test. Install the canonical query skill for each
   client's user-wide use and verify it from an unrelated working directory.
3. Import a small approved native conversation first. Ask useful questions, open exact evidence,
   and repeat the import without duplicate events. Then finish backfill for both approved native
   sources in bounded passes. Report excluded, missing, unsupported and pending history separately.
4. Keep the receiving node running independently of a terminal using a reviewed user service.
   Install the existing native collector's hourly service for only the approved roots. These are
   separate processes: the query MCP does not collect history, and a collector needs a reachable
   receiving node. See [local node persistence](deployment/agent-guided-setup.md#same-mac-daily-use).
5. Verify new history from both clients reaches searchable exact evidence. Check a natural scheduled
   collector run, not just its service definition. Use manual sync for the immediate handoff tests;
   do not pretend that this proves the hourly timer ran.
6. Test handoff in both directions from fresh sessions outside this repository, then replay and
   reconnect. Restart only the new node/service when safe. Preserve originals and verify recovery
   for the chosen storage path without replacing the working database.
7. Leave a private operating note with actual paths, installed revision, service labels, source
   coverage, credential file locations (never contents), sync/status/pause commands, and the
   recovery/update procedure. Do not leave a foreground terminal as the only daily-use service.

On Linux choose `CAM_HOME` explicitly, for example
`${XDG_DATA_HOME:-$HOME/.local/share}/cross-assistant-memory`. The current runtime's implicit default
is a macOS-style directory on every platform. Do not assume it selects XDG automatically.

One authorization for that named scope covers normal substeps and safe retries. You still handle
account login, permissions, new cost, recovery-key custody and decisions about destructive changes.
The [detailed guide](deployment/agent-guided-setup.md) contains the machine-verifiable steps.

## Test A Real Handoff

Use a real piece of work rather than a secret or an artificial expected-answer string. After
collection, ask the other agent in a new session:

```text
Use Cross-Agent Memory to find where I left off on [my actual task].
What was decided, what was only proposed, and what is the next unfinished step?
Show the exact evidence for the important claims before continuing the work.
```

Repeat in the other direction. Confirm source, speaker and date, and open exact evidence for at
least one important claim in each answer. The assistant should inspect the current project files
before editing: history is context, not proof of the current code or completed work.

This does not transplant an agent's hidden reasoning, unsaved buffers or working directory. Both
agents still need access to the actual project. Collection is not instant, and an answer can be
wrong even when the retrieved evidence is correct.

## Day-To-Day Use

Ask either assistant to use Cross-Agent Memory when continuing earlier work. User-wide skill and
MCP registration make it available across projects; they do not guarantee every model will invoke
it without being asked. The node stores your data locally in this setup. Retrieved evidence becomes
context for the querying assistant's model, under that provider's terms.

The native collector checks at startup and hourly while its user service can run. It inspects only
approved local history roots, skips unchanged completed files, and processes new/changed files
under bounded work limits. Changed files may require prefix rereads for integrity. Eligible records
pass source/privacy checks, enter an encrypted local queue, and are delivered to the configured
node with acknowledgments and deduplication. It does not run an LLM or trigger website exports.

For an immediate handoff, run these with the actual private config path left by setup:

```sh
script/cross-memory collector-config-validate --config '/absolute/private/collector.json'
script/cross-memory collector-sync --config '/absolute/private/collector.json'
```

A queued batch is not yet searchable evidence. Check the returned admission/acknowledgment status
and query the new record. An asleep Mac, unavailable node, unsupported format or backlog can delay
capture. An initial backfill may take several passes. Preserve the queue and retry normally after
an interruption; do not reset its cursors or database.

Existing installed schedules stay unchanged. Updating an old installation to hourly requires a
reviewed service replacement, not merely pulling the new source. Web capture and Grok Bot routines
have their own boundaries and are not changed by the native hourly default.

## Open The Control Panel

For a configured node, run `script/cross-memory --home "$CAM_HOME" panel` on that node.
Open its printed loopback URL. It is a local administrative UI, not a public website.
A remote node's localhost URL belongs to the remote host; follow the remote guide for access.

The unlock credential belongs to a `local_admin` client on your node. It is not your macOS
password, provider login or assistant's read-only token. Have your setup agent issue and privately
store that credential through the existing client-credential workflow. Never paste it into chat.
The disposable `script/demo` credential cannot unlock your real node.

## When Something Stops

| Symptom | Next action |
| ------- | ----------- |
| `script/doctor` reports SQLite action required | Select a Python linked to a fixed SQLite, or independently verify the vendor backport. Do not use a passing behavioral test as advisory clearance. |
| Install rejects dirty source | Preserve your changes, commit the intended candidate, then reinstall from clean source. Do not disable provenance. |
| Tool listed but answers lack context | Check admitted sources and the canonical query skill. Tool discovery is not an import. |
| Search returns no results | Try a distinctive phrase and inspect source coverage. Lexical search does not establish absence. |
| Native history is stale | Check the receiving node, collector service, queue/acknowledgment results and excluded/unsupported sources. Do not request a website export to fix native collection. |
| Browser observation queued but not searchable | Inspect/flush the native host as documented in the capture guide. A queue receipt is not admission. |
| A source reports an unknown schema | Keep the source unchanged and report a sanitized format/version description. Do not guess imports. |

## Send Back A Sanitized Result

Report each item as passed, failed or unverified, with a short reason for any gap:

- Git revision; OS, Python, linked SQLite and client versions.
- Local install, both real MCP connections and user-wide skill discovery outside this repo.
- Both source backfills, coverage/exclusions and searchable new-history capture.
- Three useful questions, including both handoff directions, with exact-evidence checks.
- Duplicate-free replay, reconnect and observed scheduled-run result.
- Node persistence and the chosen storage path's recovery check.

Do not send transcripts, account identifiers, tokens, full logs, raw receipts or recovery material.
Do not say all history is covered if files are missing or unsupported. The private operating note
stays on your machine. [Report an issue](https://github.com/philipbankier/cross-agent-memory-public/issues/new/choose).
