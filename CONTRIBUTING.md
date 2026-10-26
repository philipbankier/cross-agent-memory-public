# Contributing

Small, focused contributions are welcome. A reproducible setup problem or a clearer example
can be as useful as a new feature.

[Understand the system](docs/architecture/0001-canonical-evidence-ledger.md) /
[Find the relevant code](README.md#for-developers-and-tinkerers) /
[Open a sanitized issue](https://github.com/philipbankier/cross-agent-memory-public/issues/new/choose)

## Pick A Starting Point

| Area | A useful first contribution |
| ---- | --------------------------- |
| Setup and docs | Reproduce a confusing step on a clean host and explain where it breaks. |
| Source formats | Add a small synthetic fixture for a changed export or native history layout. |
| Browser capture | Test an identity/layout change without copying cookies or personal conversations. |
| Retrieval | Add a focused example that exposes a missed result or wrong source attribution. |
| Interfaces | Improve an existing search, evidence, access or diagnostic interaction. |

For changes to public contracts or storage, open an issue first so the intended behavior and
privacy boundary are clear. A small bug fix does not need a separate design process.

## Local Development

Read [AGENTS.md](AGENTS.md) and use a feature branch in your fork. Do not push directly to
the default branch. Use Python 3.11+ and Node for the existing extension syntax/tests.

```sh
git switch -c fix/describe-the-problem
PYTHON_BIN=python3.12 script/setup-dev
script/lint
script/test
node --test browser/capture/*.test.mjs
```

Development dependencies are hash-locked. Normal users keep the runtime-only `script/setup`
path; it does not install development or browser tools. Do not guess dependency versions,
bypass provenance checks or replace the lockfiles as part of an unrelated change.

Some operations verify the exact committed runtime. Commit the intended changes, reinstall
with `script/setup`, and run the setup self-check from that clean checkout:

```sh
script/verify-agent-guided-setup
```

This checks isolated synthetic setup, not personal-history coverage, answer quality, another
operating system or cloud recovery. The test script uses an isolated temporary directory and
removes its default state on exit.

For the optional real Chromium/native-host integration test:

```sh
npm --prefix ui/memory-app ci
cd ui/memory-app
npx playwright install chromium
cd ../..
script/test-browser-capture
```

The fixture uses synthetic provider pages and a disposable node, not your browser accounts.
It adds browser/dependency downloads; it is not a prerequisite for ordinary runtime setup.
Clean up only artifacts you created and no longer need.

## Keep Changes Reviewable

Describe the observed problem, intended result and remaining limitation. Keep the patch limited
to one problem and report the commands actually run and their outcomes. Use semantic commit
prefixes such as `fix:`, `docs:` or `test:`. Preserve existing notices and licensing.

Add a regression test for a behavior change. Use synthetic data, not a copy of a private session.
Preserve attribution, exclusions, unknown-schema refusal and read-only querying boundaries.
Do not weaken guards, silently raise limits, discard journals or reset data to make a test pass.
Coordinate any change to a real node, collector, credential or client with that instance's owner.

## Report Problems Safely

Include the release/commit, OS/Python/assistant version, source family, minimal steps, expected
versus actual result, and sanitized command/error class/exit code. Mark install, import, questions,
replay and reconnect as passed, failed or unverified where relevant.

Never post transcripts, credentials, account identifiers, export URLs, databases, recovery
material or full logs. Describe an answer-quality problem without copying private conversation
text. For vulnerabilities use [private security reporting](SECURITY.md), not a public issue.
