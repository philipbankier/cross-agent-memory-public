# Cross-Agent Memory

Search your assistant histories from Codex or Claude Code, with concise citations and exact
evidence available on demand. Your existing assistant writes the answers from retrieved evidence.

You run your own isolated instance with your own data, keys and storage. This repository includes no
original operator history, credentials, personal installers or Git history. Do not connect friends
to a shared personal memory database.

## Start Here

Clone the tagged source release, then open the folder in Codex or Claude Code:

```sh
gh repo clone philipbankier/cross-agent-memory-public -- --branch v0.1.0
cd cross-agent-memory-public
```

> Read AGENTS.md and set up Cross-Agent Memory for me. First confirm which host should hold my
> memory, which assistants will query it (Codex, Claude Code, or both), whether I want local or
> encrypted B2 evidence storage, and one small source I approve for the trial. Use my own accounts
> and configuration. Handle the technical steps and safe retries; involve me for login,
> new access/cost, keys or destructive
> changes. Test three real questions, exact evidence, replay and reconnect. Do not expose anything
> publicly, schedule full collection, or import my entire history yet.

Python 3.11 or newer is required on each runtime host. Python 3.12 is used for the package check.
macOS and POSIX/Linux are intended targets; a clean install on your actual host must pass before
claiming that host works. No model download is required. Your existing assistant synthesizes answers.

Fresh setup is tested on Python 3.11.12 / Apple-linked SQLite 3.51.0 and Python 3.12.8 /
SQLite 3.45.3. Setup can verify retained, checkpointed WAL/SHM files while holding the existing
writer-file lease; active, uncheckpointed or unsafe state still refuses. Do not delete SQLite
files or weaken setup guards. The inherited runtime passed macOS/Linux installed-package checks
and the setup self-check. The [checks workflow](.github/workflows/checks.yml) records that recipe.
These do not qualify every runtime,
friend-owned setup or real-answer quality; verify the actual installation before using personal data.

Behavioral tests are not SQLite advisory clearance. Choose a build with the upstream
[WAL-reset fix](https://www.sqlite.org/wal.html#walreset): SQLite 3.51.3 or later, or the documented
3.50.7 / 3.44.6 backports. An older vendor version label needs separate confirmation of its fix.
Check the SQLite library that the selected Python actually loads, not the standalone SQLite CLI.

The agent can install the runtime with:

```sh
# Run from the cloned folder. Choose an installed Python 3.11+ if python3 is older.
PYTHON_BIN=python3.12 script/setup
script/cross-memory --help
```

The installer is POSIX shell and runtime-only: no Node, browser, test suite or global npm
installation. It installs hash-locked wheels in this folder's `.venv` and verifies dependencies.
Keep the folder in a durable location after setup. Do not move a configured virtual environment.
Setup and its self-check avoid creating source bytecode. If an older checkout reports that runtime
bytecode differs from verified source, preserve it for inspection and use a clean clone. Do not
disable provenance checks or remove data, keys or uninspected files to force an update.

## Pick Where It Lives

- On your computer: simplest first session, with a new explicitly chosen private data directory.
- On your own remote Mac/Linux host: the node holds the index and does the processing; the laptop
  runs a small request-scoped SSH relay. See [remote setup](REMOTE.md).
- Encrypted B2 evidence: supported independently of host choice. The index, keys and bounded
  temporary storage still live on the node. B2 evidence and recovery backups are separate.
  Configure and verify your own bucket/key path before importing data when choosing this mode.

Remote and cloud setup is assisted, not one-click provisioning. No bare public MCP port, shared
operator endpoint, or new cloud bill is created automatically.

## First Session

1. Inspect and initialize a new private node using the existing setup plan/apply workflow.
2. Register each querying client and the approved source scope. Connect the read-only MCP tools.
3. Preview and import one small real source that you chose. Keep its original file.
4. Ask three questions whose answers you can check. Require concise source/date citations and
   exact evidence for consequential claims. Record missing evidence and wrong answers honestly.
5. Replay that exact import; verify no duplicate events. Restart/reconnect once and repeat a query.
6. Decide whether it is useful enough to add a second source, then try one cross-source question.

Setup convergence with synthetic fixtures is not proof that your real questions work. Perfect
recall, all six personal histories, scheduled backfill and optional ranking experiments are not
requirements for this first session. They remain work beyond it.

## Sources And Query Clients

All six importer implementations are included: Codex, Claude Code, Grok Build native histories;
ChatGPT, Claude and Grok web exports. Native import uses `ingest`; web exports use the separate
`web-export-*` commands and exact schema checks. Ask the installed CLI for each command's help.
Provider format changes may require a fix; do not bypass an unsupported schema.

Claude copied histories include verified 2.1.271 and 2.1.289 producer/stop-hook layouts and the
exact 2.1.281 SessionStart child-link and earlier-parent assistant repairs. Supported forks retain
the final child and its immediate parent, not inherited messages as new evidence. Unknown
producers, malformed links and histories beyond three verified generations refuse import.
Codex reference-only history includes exact 0.162.0-alpha.17.2, not adjacent versions; physical
child cursors and copied-history guards remain unchanged, and parent files are not opened.

Codex and Claude Code can both query the same instance, subject to each client's access. Give each
a separate client identity and, for authenticated connections, its own revocable credential.
Import each source once, not once per querying assistant. Verify tool discovery, a real question
and exact evidence in each client you configure; success in one does not verify the other.
Connecting an assistant for queries does not automatically enable collection of its conversations.

Start with Codex, Claude Code, or both as querying clients. Website query connectors are separate
from website history import and are not automatically installed or advertised as verified by
the initial setup. Export snapshots are not live website sync. There is no recurring export schedule.

Optional [browser capture](browser/capture/README.md) automatically observes rendered text in
opened, foreground saved chats on ChatGPT, Claude and Grok. It verifies the visible account,
encrypts accepted observations locally and sends them to your node using a scoped collector
credential. Each provider account keeps its own source identity. Recovery can drain the encrypted
queue without an active browser tab through the native host's bounded `--flush` command; configure
that hook in your existing collector schedule if you need unattended delivery. The Chrome
extension is opt-in and installed separately. Keep exports for backfill, unopened/mobile history
and attachments. Capture times do not establish the original message dates.

Keep different accounts on the same provider distinct when importing exports. Each retains its
own source registration and provenance; moving a subscription does not move earlier conversations.
Browser-capable agents may supplement indexed results with an authorized site's own chat search.
Verify exact account identity, cite the account and conversation, and report unchecked accounts.
That lookup does not import new messages or give a tool-only client access to another host's browser.

## Limits And Privacy

- Broad or vague questions can miss relevant history. Zero hits do not prove it never happened.
- Previews can omit qualifications. Exact reads can be paginated; follow completeness metadata.
- Attachment support is restricted. Missing media/OCR is not full attachment preservation.
- Imported dates are not proof of current provider freshness.
- Admission excludes known credential formats, including Hex and Covalent tokens in text or
  decoded JSON metadata. This is not a complete secret audit and does not erase earlier imports.
- This is one owner's trust domain, not a multi-tenant hosted service or an authorization boundary
  between mutually untrusted users of the same computer account.
- Recovery, B2 access and remote reliability must be verified on your actual configuration.
  A healthy local setup does not prove cloud backup or unattended operation.

During an exclusive node backup or other writer maintenance, native HTTP uploads and enrollment
can return retryable `503 writer_busy`. Read-only queries remain available. Keep queued batches,
cursors and enrollment codes; let normal backoff retry after maintenance, rather than resetting
state or treating this response as a login failure. Ordinary CLI writers still wait for the lease.

An approved primary-evidence key-rotation drill can explicitly select `--capacity extended` on
plan and apply: at most 100,000 mappings, 112 MiB per inventory and a 192 MiB authenticated
journal. These are independent bounds, not a promise that every manifest set fits. Default
capacity stays unchanged; issued older journals retain their original limits during recovery.
Keep both independently recoverable keys and use the existing resume/rollback commands, never
edit a journal or raise limits to force a run. This maintenance is not needed for a first session.

If ordinary admissions advance the ledger during an interrupted B2 upload, an operator can add
`--resume-source-generation SHA256` with the original authenticated capture generation. This
resumes only a complete retained preparation or its published kit, never a new capture. Source,
destination, bucket, key and query bindings still have to match. A local restore must verify;
captured content, provenance and access must still exist unchanged. Corrections, removals, access
changes and schema changes refuse the retry. Only the noncanonical stream observation timestamp
may advance. Results disclose `source_ledger_generation`, `current_ledger_generation` and
`capture_is_current`: newer admissions are not included in this historical recovery point.
Default retries remain strict. Do not edit staging or encrypted bindings to force a retry.

Keep secrets and receipts private. Do not post transcripts, database files, evidence, export URLs
or full logs as bug reports. Do not delete originals or keys after an upload or a successful query.
First-party code is licensed under [Apache-2.0](LICENSE). Verify your actual runtime and client
before importing personal history; inherited platform checks do not establish answer quality.
Original third-party notices and source-obtaining directions are in the
[distribution companion](docs/third-party/README.md), separate from the first-party license.

See [release verification](docs/deployment/verify-release.md) before installing downloaded binary
artifacts. These documents are in the tagged Git repository. [RELEASE-SOURCE.json](RELEASE-SOURCE.json)
records the inherited qualification scope; the current clean Git revision identifies a source
installation. Package archives retain the existing protected runtime/build inputs and notices.

## Feedback

Send the installed revision from `.venv/bin/python -m cross_assistant_memory.runtime_provenance`,
OS/Python/assistant version, which source
type you tried, and pass/fail for: install, import, three questions, replay, reconnect. Include
elapsed time and sanitized error class/command/exit code. Describe answer failures without copying
private conversation text. We want useful/not useful feedback, not just a green tool connection.

`PILOT-SOURCE.json` records the tested archive this Git edition came from and later verified
source overlays. It is historical provenance, not the installed runtime's revision. A clean Git checkout supplies its own commit
identity during installation; the built package verifies its runtime files against that identity.
Do not copy the ZIP's build stamp into this checkout or override the runtime revision.

## Updates

Have your agent review the next release tag and its diff before applying an update. A tag clone
has a detached HEAD: fetch and select the reviewed tag without discarding local edits rather than
pulling an unrelated branch. Coordinate any node/client restart, then rerun `script/setup`. Verify the installed
revision and repeat a query after reconnecting. Do not reset local edits, delete data or keys,
perform a migration, or change collection scope merely because a code update is available.
Keep data and credentials outside this source checkout. GitHub's source ZIP is not a prepared
runtime package; use the tagged Git clone for source installation.

## Operator References

- [Agent instructions](AGENTS.md)
- [Setup commands](docs/deployment/agent-guided-setup.md)
- [Memory query skill](skills/cross-agent-memory/SKILL.md)
- [Remote host and B2](REMOTE.md)
- [Optional native pairing](docs/deployment/native-collector-pairing.md)
- [Optional collection service](docs/deployment/native-collector-service.md)
