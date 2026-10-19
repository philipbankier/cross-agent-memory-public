# Remote Hosts And Storage

Cross-Agent Memory does not require keeping a full history corpus on your laptop. Choose the node before
importing data. Use a computer or private Linux host you control; it owns the SQLite index, keys,
and processing. The assistant laptop can run only the small MCP relay. This is one owner's
instance, not a shared service for unrelated users.

The installed CLI's `--help` is authoritative. The repository includes all six importers and the
encrypted B2 implementation. It does not provision a server, bucket, public endpoint or paid plan.
Have your agent configure these only after you approve the actual host, cost and source scope.

## Node And Client

1. Clone the reviewed release tag on your selected node. Run `script/setup` there, initialize using
   the agent-guided setup instructions, and register separate read-only credentials per assistant.
2. Keep the HTTP origin on loopback. Verify `serve --help` before choosing the read-only or native
   upload service. Configure only your own node and credentials. Do not expose the bare MCP port.
3. Start in a supervised terminal for the initial trial. Persistence and automatic collection are
   separate, explicitly approved steps after successful queries. The personal legacy launchd
   installers are intentionally absent.
4. Install the runtime on the client too. Configure its MCP command as the absolute path to
   `script/cross-memory`, using the `connect-ssh` arguments below. Verify the host key independently
   and retain strict SSH checking. The client and node should use the same reviewed Git revision.

```sh
script/cross-memory connect-ssh --host user@your-memory-host \
  --remote-python /absolute/cross-agent-memory/.venv/bin/python \
  --remote-runtime /absolute/cross-agent-memory \
  --remote-credential-file /absolute/private/client.token \
  --url http://127.0.0.1:28765/mcp
```

Use the actual chosen origin port. Optional `--identity-file` selects an existing SSH key.
The bearer token stays on the node. Connections are request-scoped: idle clients retain no SSH
connection; four slots per local OS user bound concurrency. No persistent SSH pool or weakened
host-key check is needed. A saturated startup can time out; reconnect after the burst, not in a loop.
Never put bearer tokens in MCP arguments or feedback. Reconnect clients after a tool schema change.

The included `Containerfile` and `compose.yaml` are the existing Linux host-network profile,
not a Docker Desktop quickstart. Its prepared build context must come from this clean Git revision;
do not use the historical archive revision in PILOT-SOURCE.json. Follow the included
[container profile](docs/deployment/container-profile.md) and verify the actual built revision.
A fresh native Linux installation still requires verification on that host. An image build is not
remote-host or backup acceptance.

## Encrypted B2

Remote-primary evidence and disaster-recovery backups are different configurations. The node still
needs disk for its searchable SQLite index, bounded queues and temporary staging. B2 is not a
diskless database. Encrypted cloud evidence does not encrypt the node's live index at rest;
use the host's disk encryption and restrict its account access.

Before importing anything, have the agent inspect these existing CLI commands:

```sh
script/cross-memory recovery-init --help
script/cross-memory recovery-install-key --help
script/cross-memory evidence-publish --help
script/cross-memory backup --help
script/cross-memory restore --help
```

Use owner-only secret files outside the node data directory and collection roots. Never print key
contents. Keep the recovery secret and recovery kit independently saved before depending on cloud
storage. Use your own private bucket and least-privilege credentials, not someone else's account.

Evidence access uses an owner-only, single-link `0400` JSON configuration selected with
`--evidence-config`. Example shape, replace every path and choose your actual B2 region and limits:

```json
{
  "format_version": 1,
  "data_root": "/private/memory/node",
  "operational_key": "/private/memory/keys/evidence.json",
  "backend": {
    "profile": "backblaze-b2-s3-v1",
    "bucket": "your-private-evidence-bucket",
    "region": "us-west-004",
    "application_key_id_env": "CAM_EVIDENCE_B2_KEY_ID",
    "application_key_env": "CAM_EVIDENCE_B2_KEY"
  },
  "max_plaintext_bytes": 67108864,
  "max_ciphertext_bytes": 134217728,
  "max_snapshot_bytes": 536870912,
  "publication": {
    "mode": "remote-primary",
    "max_pending_bytes": 67108864,
    "max_pending_objects": 10000
  }
}
```

All paths must be existing physical absolute paths without symlinks. This configuration does not
itself create keys, grant source access or upload anything. After import, distinguish admitted
records, pending publication and verified encrypted evidence. Pending publication is not backed up.
Retry the original bounded operation after interruption; do not discard journals or manually edit
SQLite. Backup uses the separate `CAM_B2_*` configuration, root/package kits and recovery secret.

For a friend's B2 trial, require a small real import, a verified cloud-backed evidence read, and an
independent restore into a new empty directory before calling that friend's storage path verified.
Do not delete originals or saved keys just because upload succeeded. Large full-history backfills,
key rotation and deletion rehearsals are not prerequisites for the first small session.
