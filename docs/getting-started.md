# Your First Session

The finish line is a useful answer from your own history, with evidence you can check.
Not a dashboard full of green statuses, and not your entire history imported on day one.

## 1. Choose The Smallest Useful Setup

Tell your Codex or Claude Code agent four things:

| Choice | A small first trial |
| ------ | ------------------- |
| Node | This computer, or one named Mac/Linux host you control |
| Query client | Codex, Claude Code, or both with separate identities |
| Storage | Local to start; encrypted B2 is optional |
| History | One small native conversation or one bounded export scope you approve |

You do not need a project taxonomy. Global, project, session and assistant-private scopes exist;
use the one that matches the material. Do not make personal work fit a fictional project.

## 2. Let Your Agent Set It Up

Use the [README prompt](../README.md#connect-your-own-history). Your agent checks the selected
Python with `script/doctor`, installs from clean source, chooses an explicit data directory,
creates the node and client identities, then connects the actual querying assistant.

On Linux choose `CAM_HOME` explicitly, for example
`${XDG_DATA_HOME:-$HOME/.local/share}/cross-assistant-memory`. The current runtime's implicit default
is a macOS-style directory on every platform. Do not assume it selects XDG automatically.

One authorization for that named scope covers normal substeps and safe retries. You still handle
account login, permissions, new cost, recovery-key custody and decisions about destructive changes.
The [detailed guide](deployment/agent-guided-setup.md) contains the machine-verifiable steps.

## 3. Test The Work, Not Just The Connection

Ask three questions that matter to you. Examples, adapted to your actual source:

```text
What did I decide, and which alternatives did I reject?
Where did I leave off, and what was still only a proposal?
Show the exact message behind that answer. Is any evidence missing or truncated?
```

Confirm the source, speaker and date. A tool result is not proof that an assistant's interpretation
is correct. Then re-import the same source and require no duplicates. Restart/reconnect only this
new node or client, and repeat a question. Preserve the original source.

## 4. Add Context Gradually

Add a second source and ask one question spanning both. Only then choose native collection,
browser capture or larger backfill. Connecting an MCP client reads memory; it does not capture
its history. Each capture path needs its own account and source approval.

For daily queries, install the canonical [query skill](../skills/cross-agent-memory/SKILL.md) in
the assistant's supported skill location and check it from another working directory. A
repository-local skill is not automatically global. Do not create a second edited workflow.

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
| Browser observation queued but not searchable | Inspect/flush the native host as documented in the capture guide. A queue receipt is not admission. |
| A source reports an unknown schema | Keep the source unchanged and report a sanitized format/version description. Do not guess imports. |

Share only a sanitized result: source revision, OS/runtime/client versions, and pass/fail/unverified
for install, import, questions, evidence, replay and reconnect. No transcripts, account identifiers,
tokens, full logs or recovery material. [Report an issue](https://github.com/philipbankier/cross-agent-memory-public/issues/new/choose).
