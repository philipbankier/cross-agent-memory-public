# Container Profile

Date: 2026-08-30

This is the supported Docker Compose profile for a single-node Linux installation. It preserves
the authenticated loopback origin instead of adding a public container listener.

## Runtime Contract

- `Containerfile` pins the multi-architecture Debian Trixie base and separate SHA-256-verified
  CPython 3.12.15 standalone archives from Astral's 20261013 release for AMD64 and ARM64.
  The bundled SQLite must include the WAL-reset fix. No custom SQLite compilation or journal-mode
  change is used. Alpine is not a compatible replacement: the locked Tink package needs glibc wheels.
- Debian's signed package repositories supply the CA certificate bundle during the build;
  the image SBOM records the resulting packages. Certificate trust paths are explicit because the
  standalone interpreter's default paths are not Debian's. Those package versions are not pinned
  by the base digest; the final built image, SBOM and provenance identify their actual versions.
- The runtime image contains the installed application environment, not the repository, tests,
  documentation or compiler. It includes only the required CA-store package additions.
- The image additionally retains the standalone runtime's upstream aggregate third-party notices
  at `/usr/share/doc/cross-agent-memory/python-runtime-licenses.rst`, fetched from the exact
  20261013 source commit with a SHA-256 check. The verifier checks those complete bytes. This is
  an overinclusive upstream notice collection, not a claim that every listed component is used.
  It does not replace Python/pip/package notices or Debian package copyrights, and does not
  change the application's Apache-2.0 license. Runtime source/build information is available from
  [the pinned upstream release](https://github.com/astral-sh/python-build-standalone/releases/tag/20261013)
  and [its source commit](https://github.com/astral-sh/python-build-standalone/tree/9e40cba825ca0997a01cab9f60a0b15ffb976af2).
- The process runs as fixed UID and GID `65532`, drops every Linux capability, sets
  `no-new-privileges`, and uses a read-only root filesystem.
- `/var/lib/cross-assistant-memory` is the only persistent writable mount. `/tmp` is a bounded
  non-executable tmpfs.
- The node binds `127.0.0.1` inside the Linux host network namespace. Compose publishes no port and
  does not introduce an unauthenticated or non-loopback mode.
- `/health` is content-free. MCP remains bearer-authenticated and enrollment and upload retain
  their application capability checks.

Linux host networking is intentional. It lets a host-local private ingress reach the origin while
the node itself remains on loopback. Docker Desktop may keep that Linux loopback inside its VM and
unreachable from macOS. Docker Desktop is therefore useful for image verification but is not the
documented deployment profile.

## Start On Linux

Use a clean Git checkout or a verified source archive. Prepare a bounded build context containing
only the verified source and build inputs, without Git history or private workspace files. The
existing provenance command validates either form and returns its runtime revision, not an
archive's upstream revision. The build binds those bytes to the same revision as the image label:

```bash
export CAM_PORT=8765
CAM_BUILD_WORK="$(mktemp -d)"
export CAM_BUILD_CONTEXT="$CAM_BUILD_WORK/context"
CAM_BUILD_REVISION="$(PYTHONPATH=src python3 -B -m cross_assistant_memory.runtime_provenance \
  --prepare-container "$CAM_BUILD_CONTEXT")"
export CAM_BUILD_REVISION
docker compose build --pull node
rm -rf "$CAM_BUILD_WORK"
unset CAM_BUILD_CONTEXT CAM_BUILD_WORK
docker compose up --detach --wait node
```

Do not build directly from an unstamped checkout or supply an arbitrary revision label. The
container build refuses missing provenance, changed inputs and a mismatched `VCS_REF`.
`script/verify-container` prepares and removes its own isolated context automatically.

The named Compose volume is the authoritative node data root. Do not replace it, run `down
--volumes`, or move its SQLite and WAL files independently. Snapshot and recovery commands remain
the supported portability path.

Check only the content-free endpoint without a credential:

```bash
curl --fail --silent "http://127.0.0.1:${CAM_PORT}/health"
```

MCP requests without a valid client bearer credential must return `401`. A private-network or
public ingress is a separate reviewed deployment. Follow [remote host guidance](../../REMOTE.md); never publish this
origin directly.

## Exact Architecture Check

Run on a native Linux `arm64` or `amd64` Docker engine from a clean tracked worktree:

```bash
CAM_EXPECT_ARCH=arm64 script/verify-container
```

Use `amd64` on an AMD64 engine. The verifier refuses an architecture mismatch, builds the pinned
image, validates the rendered Compose contract and OCI labels, and proves:

- native runtime architecture and non-root identity;
- read-only root and writable data volume boundaries;
- content-free health and unauthenticated MCP rejection;
- fresh schema initialization and FTS5 readiness;
- a loaded SQLite version at or above the upstream WAL-reset fix and a usable TLS trust store;
- the checksum-matched standalone runtime third-party notices;
- host-loopback reachability in the Linux namespace; and
- data persistence across full container recreation.

It removes its synthetic container, volume, and auto-named verification image. A caller-supplied
`CAM_IMAGE` tag is retained. Emulation can be a development check but does not satisfy native
architecture proof.

The verifier checks the schema against the installed image's version and requires a positive
execution marker from the loopback probe. A fresh synthetic volume does not prove an upgrade
from an older ledger; migration and recovery keep their separate evidence boundaries.

## Proof Boundary

The October 16 dependency review does not claim a CVE-free image. Debian retains a
[resolver availability issue](https://security-tracker.debian.org/tracker/CVE-2026-8674)
when host DHCP/VPN configuration supplies a long DNS search domain. It also retains a
[libstdc++ large-allocation issue](https://security-tracker.debian.org/tracker/CVE-2026-95619)
in the library loaded by Tink and a [compiled-template finding](https://security-tracker.debian.org/tracker/CVE-2026-102010).
No application trigger was demonstrated for either; absence from all transitive native code was
not established. Keep the default non-root profile and a trusted host/network configuration.
Package matches and index silence are neither whole-image nor transitive security clearance.
The upstream source/build links and runtime notices above remain part of the distribution record.

This profile packages the node. It does not configure an OAuth edge, private ingress, operational
keys, B2 credentials, collectors, real data, Mac mini services, or assistant clients. Those remain
separate roadmap and approval gates.
