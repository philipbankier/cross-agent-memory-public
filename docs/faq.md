# Frequently Asked Questions

## Is This A New Chatbot Or A Hosted Service?

Neither. It is a memory node you operate, queried through your existing assistant. Run it locally
or on your own remote Mac/Linux host. No managed hosting or multi-tenant account system is included.

## Can Codex And Claude Code Both Use It?

Yes. Connect each separately with its own identity and allowed capabilities. They can query the same
admitted sources without importing a second copy. Verify each actual client, not only an SDK probe.

## Why Both MCP And Exports?

The MCP connector lets an assistant query this node. It is not a provider API for reading all your
old website conversations. Official exports provide backfill; opt-in browser capture adds eligible
opened chats. It cannot see conversations opened only on another browser or mobile device.

## Can I Connect Two Accounts On The Same Provider?

Yes. Use separate, stable source identities and approve each account. Account verification is part
of browser capture. Similar titles or matching text do not justify merging accounts.

## Is My History Sent To A New Model Provider?

The node does not require a separate model. Evidence returned to a querying assistant enters that
assistant's context and is subject to its provider's terms. Local storage is not a promise that
queries stay off the internet. Choose querying clients and scopes accordingly.

## Do I Need B2, Docker, An Extension Or A GPU?

No. The core local runtime needs Python and SQLite FTS5. B2, containers and Chrome capture are
separate optional paths. No local model or GPU is required. Developer checks additionally use Node.

## Is Everything Encrypted?

No. Remote B2 evidence is encrypted under the configured policy. The searchable SQLite index and
local evidence are not automatically encrypted by this application. Use OS disk encryption and
owner-only permissions. Keep recovery material separate and test a restore before relying on it.

## Does It Remember Everything Automatically?

No. Collection is opt-in, source formats evolve, and web history is not complete live sync.
Inspect coverage and exclusions. Attachments/OCR are limited. A fresh capture timestamp is not the
original message date and does not prove complete account coverage.

## Can I Trust Every Generated Answer?

No. The system preserves evidence and attribution; the assistant can still misread it. Search is
lexical, not a semantic guarantee. Check consequential claims, quotations and truncated evidence.
Claude/Grok automatic synthesis remains experimental.

## How Do I Contribute Without Sharing My History?

Use the disposable demo, synthetic fixtures and sanitized issue forms. [CONTRIBUTING.md](../CONTRIBUTING.md)
maps the source and checks. Never attach a real export, database, credential or recovery kit.
