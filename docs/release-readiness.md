# Release Status

Current source and published artifacts are different things. This page records the boundary,
not a blanket claim that every deployment or assistant answer is safe.

## Published v0.1.0

The release was verified from actual public downloads on macOS and Linux amd64/arm64, with
16 assets, 13 signed subjects, checksum checks and source/image provenance. Those checks establish
identity and tested behavior at that revision. They do not clear newly published advisories.

The October 27, 2026 audit found four advisories in its Python and UI dependency locks:

| Dependency | Advisory | Source fix |
| ---------- | -------- | ---------- |
| MCP 2.1.1 | [CVE-2026-59951](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv): retained stateful HTTP sessions can grow memory without bound | MCP and mcp-types 2.2.0 |
| OpenTelemetry API 1.44.0 | [CVE-2026-114603](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-xcq7-p3pf-p88h): pathological inbound tracestate parsing | opentelemetry-api 1.45.1 |
| MCP TypeScript client 2.2.0 | [GHSA-6prh-2h8m-c8cw](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6prh-2h8m-c8cw): HTTP/OAuth cross-origin redirects can forward custom headers and bodies | Client and matching core 2.3.0 |
| Zod 4.2.0 | [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5): oversized collection validation can exhaust memory | Zod 4.6.6 |

The HTTP server uses stateful MCP, so the session-retention advisory is relevant. Authentication
restricts who can trigger it; it does not bound a token holder's sessions. Stdio is not affected by
that advisory. The OpenTelemetry dependency is present; exploitability depends on propagation and
HTTP header limits. No exploit against a real node was run or claimed.
The visual App uses its host bridge rather than the affected HTTP/OAuth client path; no credential
leak was observed or claimed. Its dependency and the checked-in bundle are updated nonetheless.

These pins are corrected in current source. The previously published binaries and images are
unchanged. Do not call them patched until a new release is built, signed and verified from its
actual published downloads. Existing deployments are not upgraded by a repository merge.

## First-Run Findings

- Python version alone is insufficient. The linked SQLite needs the upstream WAL-reset fix.
  The read-only `script/doctor` now reports that requirement explicitly before real-data setup.
- The package's source-provenance guard rejects dirty builds. Contributor instructions now put
  installation before edits and require reinstalling the clean committed candidate for acceptance.
- Linux setup must explicitly choose CAM_HOME to use an XDG path. The current implicit default is
  macOS-style on all hosts; the documentation no longer claims otherwise.
- `script/demo` gives a disposable real-panel trial without asking for personal accounts or history.
  Its invented data is not evidence of provider coverage or real-answer quality.

## What A Public Patch Release Must Verify

1. Clean candidate installation, lint/types, full tests, capture tests and setup self-check.
2. Current runtime and UI dependency scans, plus public-history/staged secret checks.
3. Actual desktop and narrow-screen first-run, search, evidence and empty-state behavior.
4. New package/image builds, updated inventories, signatures and public-download verification.

The private pilot's accepted source gaps, snapshot-based web coverage and experimental Claude/Grok
synthesis remain disclosed limitations. This audit does not broaden collection, change credentials,
retest every live account or alter any operator's running fleet.
