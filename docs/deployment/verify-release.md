# Verify A Release

Use the published tag and its complete source revision from the release notes. GitHub CLI must
support `gh attestation verify`; inspect its help before using a different version. Download into
a new empty directory. Verify artifacts before installing packages or loading image archives.

```sh
gh release download v0.1.2 --repo philipbankier/cross-agent-memory-public
```

Set `RELEASE_REVISION` to the complete source commit shown in the release notes. The commands below
must fail if the repository, workflow or source revision differs. Keep the downloaded attestation
bundles alongside their artifacts. An artifact checksum alone does not authenticate its publisher.

## Python Packages

The Python set contains the wheel, source distribution, `python-SHA256SUMS` and
`python-attestation.json`. Verify the checksum file's attestation before using its contents:

```sh
gh attestation verify python-SHA256SUMS --bundle python-attestation.json \
  --repo philipbankier/cross-agent-memory-public \
  --signer-workflow philipbankier/cross-agent-memory-public/.github/workflows/attested-packages.yml \
  --signer-digest "$RELEASE_REVISION" --source-digest "$RELEASE_REVISION" \
  --deny-self-hosted-runners
```

On Linux run `sha256sum --check --strict python-SHA256SUMS`; on macOS run
`shasum -a 256 --check python-SHA256SUMS`. Then verify the wheel and source archive with the same
command above, replacing only `python-SHA256SUMS` with each exact filename. Install the verified
wheel in a dedicated Python environment. Follow README.md and the owner-controlled setup workflow.

## Linux Images

Choose your host architecture, `amd64` or `arm64`. Each set contains:

- `memory-image-ARCH.docker.tar.gz`
- `linux-ARCH-image.sbom.cdx.json`
- `linux-ARCH-ui-source.sbom.cdx.json`
- `linux-ARCH-build-identity.json`
- `linux-ARCH-SHA256SUMS`
- `linux-ARCH-attestation.json`

Replace `ARCH` with that architecture in each filename. Verify the checksum file and each named
artifact using the image workflow:

```sh
gh attestation verify linux-amd64-SHA256SUMS --bundle linux-amd64-attestation.json \
  --repo philipbankier/cross-agent-memory-public \
  --signer-workflow philipbankier/cross-agent-memory-public/.github/workflows/attested-images.yml \
  --signer-digest "$RELEASE_REVISION" --source-digest "$RELEASE_REVISION" \
  --deny-self-hosted-runners
sha256sum --check --strict linux-amd64-SHA256SUMS
docker image load --input memory-image-amd64.docker.tar.gz
```

The example uses Linux amd64. For arm64, change every architecture filename consistently.
After loading, inspect the exact image ID named in `linux-ARCH-build-identity.json`; require its
Linux platform, architecture and `org.opencontainers.image.revision` label to match. Follow
the container guide for private storage, loopback binding and authenticated access before use.

The image archive is Docker-save format. Its checksum is distinct from the loaded image ID and
from a container-registry digest. The UI-source SBOM covers source/build dependencies; it does not
assert that every listed package is present in the runtime image. Preserve notices and the indexed
third-party source references when redistributing. Signatures establish build identity, not freedom
from vulnerabilities or correct assistant answers.
