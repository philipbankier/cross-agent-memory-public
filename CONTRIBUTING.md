# Contributing

Start with README.md and AGENTS.md. Work on a feature branch and keep changes limited to one
problem. Describe the observed behavior, intended result and any remaining limitation in the pull
request. Do not push to the default branch.

Use Python 3.11 or newer. Normal users keep the runtime-only `script/setup` path. For development:

```sh
script/setup-dev
script/lint
script/test
script/verify-agent-guided-setup
```

The setup verifier uses isolated synthetic data. Run it from a clean Git clone after installation
so the installed package and checkout have matching revision provenance. Review incoming changes
before rerunning setup. Development setup uses the hash-locked runtime and development pins,
without installing a guessed tool version or bypassing provenance checks. The test command uses
an isolated temporary directory and removes its default test state when it exits.

Keep fixtures synthetic. Exclude private histories, credentials, recovery material, machine paths
and deployment receipts from commits and bug reports. Preserve source attribution, privacy
exclusions, unknown-schema refusal and read-only querying boundaries. Coordinate changes that
would affect collection, storage, keys or a running client with that instance's owner.

Report the commands actually run and their results. The setup self-check does not establish real
answer quality, cloud recovery or another operating system's support. See SECURITY.md for private
vulnerability reports.
