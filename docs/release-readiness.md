# Release Status

Current source and published artifacts are different things. This page records the boundary,
not a blanket claim that every deployment or assistant answer is safe.

## v0.1.2

This correction restores deployed behavior omitted from the earlier public source:
native context across verified upload batches, bounded complete MCP envelopes, copyable
continuation requests, fixed continuation-error feedback, literal-identifier ranking,
Boolean-query diagnostics and collector read-budget fairness. The accompanying regression
tests include the request-scoped SSH lifecycle and its four-connection limit.

It retains v0.1.1's dependency, parser, recovery, maintenance and interface repairs. There is
no database migration, credential rotation, account expansion or browser-permission change.
Browser capture executable files remain version 0.2.2. Qualification includes equal-input,
read-only comparisons against a working node before any fleet switch; synthetic tests alone
did not catch the previous omission. The signed release and download-verification results
are recorded in the [v0.1.2 release notes](https://github.com/philipbankier/cross-agent-memory-public/releases/tag/v0.1.2).
Publication and fleet deployment remain separate outcomes.

## Published v0.1.1

This patch includes the dependency fixes, prerequisite checks, disposable demo, first-run repair
and documentation improvements below. The [release notes](https://github.com/philipbankier/cross-agent-memory-public/releases/tag/v0.1.1)
record its exact source revision, signed artifacts and download-verification runs. Until that
release is published, source qualification is not published-artifact verification.

The release procedure uploads verified artifacts only to an existing, revision-bound draft, with
no asset replacement. Independent macOS and Linux amd64/arm64 jobs download and verify that draft
before publication, then repeat against the public release. v0.1.0 remains unchanged.
Publishing a patch does not upgrade any running node or client.

## Published v0.1.0

The release was verified from actual public downloads on macOS and Linux amd64/arm64, with
16 assets, 13 signed subjects, checksum checks and source/image provenance. Those checks establish
identity and tested behavior at that revision. They do not clear newly published advisories.

The October 27, 2026 audit found five advisories across runtime, UI and build dependency locks:

| Dependency | Advisory | Source fix |
| ---------- | -------- | ---------- |
| MCP 2.1.1 | [CVE-2026-59951](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv): retained stateful HTTP sessions can grow memory without bound | MCP and mcp-types 2.2.0 |
| OpenTelemetry API 1.44.0 | [CVE-2026-114603](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-xcq7-p3pf-p88h): pathological inbound tracestate parsing | opentelemetry-api 1.45.1 |
| MCP TypeScript client 2.2.0 | [GHSA-6prh-2h8m-c8cw](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6prh-2h8m-c8cw): HTTP/OAuth cross-origin redirects can forward custom headers and bodies | Client and matching core 2.3.0 |
| Zod 4.2.0 | [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5): oversized collection validation can exhaust memory | Zod 4.6.6 |
| Setuptools 84.0.0 | [GHSA-xmj3-9gf7-h52w](https://github.com/advisories/GHSA-xmj3-9gf7-h52w): Windows path escape in legacy wheel installation | Setuptools 84.1.0 |

The HTTP server uses stateful MCP, so the session-retention advisory is relevant. Authentication
restricts who can trigger it; it does not bound a token holder's sessions. Stdio is not affected by
that advisory. The OpenTelemetry dependency is present; exploitability depends on propagation and
HTTP header limits. No exploit against a real node was run or claimed.
The visual App uses its host bridge rather than the affected HTTP/OAuth client path; no credential
leak was observed or claimed. Its dependency and the checked-in bundle are updated nonetheless.
The setuptools issue concerns legacy wheel installation on Windows, not a supported node platform;
the build-tool pin is updated without claiming a macOS/Linux runtime exploit.

These pins are corrected in v0.1.1 source. The v0.1.0 binaries and images remain unchanged.
Only new, signed artifacts verified from their actual downloads establish a patched release.
Existing deployments are not upgraded by a repository merge.

## First-Run Findings

- Python version alone is insufficient. The linked SQLite needs the upstream WAL-reset fix.
  The read-only `script/doctor` now reports that requirement explicitly before real-data setup.
- The package's source-provenance guard rejects dirty builds. Contributor instructions now put
  installation before edits, distinguish source regressions from tests of the installed copy,
  and require reinstalling the clean committed candidate for acceptance.
- Linux setup must explicitly choose CAM_HOME to use an XDG path. The current implicit default is
  macOS-style on all hosts; the documentation no longer claims otherwise.
- `script/demo` gives a disposable real-panel trial without asking for personal accounts or history.
  Its invented data is not evidence of provider coverage or real-answer quality.
- Opening the panel from another app incorrectly rejected the login shell as cross-site.
  Top-level GET navigation to that shell now works; cross-site data/API requests and frames remain
  refused, and host/origin checks and authentication remain in force.
- Source inventories still named the old dependency pins and a private candidate. Both now match
  the locks, changed Python source archives have verified hashes, and regressions check the real
  inventories for drift. This does not replace a new release's artifact provenance.

## Verified Candidate

The runtime changes at `7addf64`, plus the source inventory and drift checks at `d32236c`, were
checked on macOS arm64 with Python 3.12.15 and SQLite 3.53.1. These are local qualification
results, not new release attestations or another live-account acceptance claim.

| Check | Result |
| ----- | ------ |
| Clean hash-locked setup and installed dependency consistency | Passed |
| Ruff, formatting and Pyright | Passed |
| Full installed Python suite | 1,040 passed; one opt-in browser test skipped |
| The skipped browser test, run explicitly | Passed: four account fixtures, restart, offline queue, replay and recovery |
| Extension unit tests | 88 passed |
| Visual App type/format/bundle checks and tests | Passed; 28 tests |
| Installed agent-guided setup | Passed at `2c9ed73`; final CI checks the exact PR head |
| Dependency advisories | pip-audit 2.10.1 and npm audit: no known findings after fixes |
| Secret and private-identifier checks | Gitleaks history/staged scan and targeted operator-identifier scan passed |
| Real Chrome panel checks | Search, exact evidence, empty-state recovery, four views, lock/purge; no console errors |
| Responsive checks | No horizontal overflow at 320, 375 and 1,440 CSS pixels; first result visible at 375 x 812 |
| Demo isolation and cleanup | Owner CAM_HOME untouched; temporary node removed on SIGTERM |
| Indexed public source archives | 170 complete archive hashes verified by [the bounded CI run](https://github.com/philipbankier/cross-agent-memory-public/actions/runs/40547016721); no archive bytes retained |

The automated provider test uses controlled pages, not fresh logins to real provider accounts.
GitHub's PR checks supply independent macOS, Linux, installed-image and browser-fixture results.
The private pilot's previously accepted proofs are retained, not relabeled as tests of new binaries.

## What A Public Patch Release Must Verify

1. Clean candidate installation, lint/types, full tests, capture tests and setup self-check.
2. Current runtime and UI dependency scans, plus public-history/staged secret checks.
3. Actual desktop and narrow-screen first-run, search, evidence and empty-state behavior.
4. New package/image builds, updated inventories, signatures and public-download verification.

The private pilot's accepted source gaps, snapshot-based web coverage and experimental Claude/Grok
synthesis remain disclosed limitations. This audit does not broaden collection, change credentials,
retest every live account or alter any operator's running fleet.
