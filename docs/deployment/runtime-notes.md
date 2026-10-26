# Runtime And Operational Notes

These are reference notes, not extra steps for the first small trial. Start with the
[README](../../README.md) and [setup guide](agent-guided-setup.md). Keep the existing privacy,
provenance and recovery checks when adapting a deployment.

## Python And SQLite

Fresh setup is tested on Python 3.11.12 / Apple-linked SQLite 3.51.0 and Python 3.12.8 /
SQLite 3.45.3. Setup can verify retained, checkpointed WAL/SHM files while holding the existing
writer-file lease; active, uncheckpointed or unsafe state still refuses. Do not delete SQLite
files or weaken setup guards. The inherited runtime passed macOS/Linux installed-package checks
and the setup self-check. The [checks workflow](../../.github/workflows/checks.yml) records that recipe.
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

## Native History Compatibility

Claude copied histories include verified 2.1.271 and 2.1.289 producer/stop-hook layouts and the
exact 2.1.281 SessionStart child-link and earlier-parent assistant repairs. Supported forks retain
the final child and its immediate parent, not inherited messages as new evidence. Unknown
producers, malformed links and histories beyond three verified generations refuse import.
Codex reference-only history includes exact 0.162.0-alpha.17.2, not adjacent versions; physical
child cursors and copied-history guards remain unchanged, and parent files are not opened.

## Maintenance And Interrupted Uploads

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

## Historical Source Records

`PILOT-SOURCE.json` records the tested archive this Git edition came from and later verified
source overlays. It is historical provenance, not the installed runtime's revision. A clean Git checkout supplies its own commit
identity during installation; the built package verifies its runtime files against that identity.
Do not copy the ZIP's build stamp into this checkout or override the runtime revision.

## Updating A Node

Have your agent review the next release tag and its diff before applying an update. A tag clone
has a detached HEAD: fetch and select the reviewed tag without discarding local edits rather than
pulling an unrelated branch. Coordinate any node/client restart, then rerun `script/setup`. Verify the installed
revision and repeat a query after reconnecting. Do not reset local edits, delete data or keys,
perform a migration, or change collection scope merely because a code update is available.
Keep data and credentials outside this source checkout. GitHub's source ZIP is not a prepared
runtime package; use the tagged Git clone for source installation.

## Sanitized Feedback

Include installed revision, OS/Python/assistant version, source type, command, sanitized error
class/exit code and elapsed time. Mark install, import, three questions, replay and reconnect
as passed, failed or unverified. Describe answer problems without private conversation text.
Never attach transcripts, tokens, export URLs, database files, recovery material or full logs.
Use the [public issue forms](https://github.com/philipbankier/cross-agent-memory-public/issues/new/choose)
for sanitized reports and [private security reporting](../../SECURITY.md) for vulnerabilities.
