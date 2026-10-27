# Source Index

This is the source inventory for the current candidate, not an attestation for a new binary
release or legal clearance. The repository and v0.1.0 are public. That release predates the
dependency fixes described in [release status](release-readiness.md).

`release-source-index.json` records the inspected runtime revision and build-input hashes, the pinned Python
runtime producer and source table, the 56 Debian source releases behind 80 installed packages,
the 41 Python dependency pins and the six bundled UI packages. Debian descriptors distinguish
required source members from one supplementary Git sidecar outside their source list. Its
source-archive hashes are descriptor declarations, not claims that those bytes were downloaded.
The runtime table is overinclusive; it is not a list of everything present in the image.
Debian's direct source-package observation is from ARM64. Seventy-nine AMD64 binary versions
match; ARM64's `grep` has a binary-only `+b1` rebuild of the same `3.11-4` source. This is not a
separate AMD64 `dpkg` source-package inspection or a claim of identical architecture binaries.

Before binary publication, verify and provide the required complete source/build inputs and
clear source-obtaining directions alongside the approved artifacts. Check source access and
bind this index to actual published image digests and authenticated provenance. Local image IDs
alone do not identify registry manifests. Keep the original package licenses and notices;
the application's Apache-2.0 license does not replace them.

Do not download or execute arbitrary dependencies as part of reading this index. Source archives
are data: verify their complete declared hashes before extraction. The 40 Python source archives
and required Debian source archives total about 326 MiB; that is not the memory-backup size and
does not include runtime sources or other build inputs. The source-bearing `bazel-runfiles`
wheel is recorded separately because PyPI has no source distribution for its tested version.

The `Checks` workflow has an opt-in `verify_release_sources` dispatch input. It checks
the indexed Debian/Python source archives and UI archive integrity on a GitHub-hosted runner.
It downloads at most 512 MiB, checks a ten-minute budget between reads, uses read timeouts of
at most 20 seconds, and has a 15-minute runner limit. It refuses redirects and environment proxies
and retains only a hash receipt. It extracts or executes no downloaded code.
Ordinary PR runs do not start this transfer. Runtime sources, descriptor signatures, full native
source closure, public access and signing remain separate requirements.

The portable inventory in `third-party/source-index.json` carries the same Python/UI source
bindings in the installed package. Tests compare both inventories with the dependency locks and
compare recorded build-input hashes with the checkout. Update both when dependencies change.
Old private-candidate image IDs are not evidence for this candidate and have been removed.
