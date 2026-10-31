# Grok Bot Upload Relay

Experimental, not a hosted memory service. This stateless Worker connects an enrolled cloud
collector to an existing private node when that collector cannot reach its private network.
It uses no database, OAuth grant, query tool, account password or stored bearer credential.
The Python native-upload decoder remains the full protocol contract.

The owner must separately approve source collection, the account-wide cloud credential boundary
and this private network route. Personal Bots share a computer; a file credential is not isolated
to one Bot. Do not reuse query OAuth or an administrator credential for collection.

## Setup Boundary

Prepare compatible native and hosted readers, plus a rollback reader that can decode the new
source identity, before registering or admitting a Grok Bot source. Preserve all existing source
parsers, data, credentials and capture settings. Do not deploy an older public base over a newer
working private node.

Create one separately enrolled collector device/source account using the ordinary node workflow.
Keep its credential in an owner-only file on the approved cloud computer. The existing encrypted
queue owns retry state; this Worker has none. Revoke that credential on the node to stop collection.
Disabling the capture policy stops the normal collector but is not credential revocation.

Use an explicitly approved Cloudflare VPC service bound to the existing collector listener.
Do not expose the Mini's port publicly or point this route at its read-only hosted listener.
Keep the real Wrangler configuration outside this source directory. The template intentionally
does not deploy until its source-account ID, public origin and private service are configured.
Set the collector URL to the new HTTPS origin's `/upload/batches`, with explicit `:443` in the
collector configuration. The query gateway and its grants remain unchanged.

The Worker accepts only a single-record format-2 Grok Bot upload for its configured account.
It forwards the caller's collector bearer and exact body to the configured loopback origin;
the node validates credentials, device/account authorization, parser, hashes and record privacy.
It has no other route and refuses cookies or browser-origin requests. Payloads, receipt reads and
the total transfer time are bounded; redirects are not followed. Access and payload logging are
disabled in the template. Cloudflare still terminates transport encryption, as with the separate
query edge, so approve that processing boundary before deployment.

## Verification

Run `sh script/test-grok-bot-upload` from the repository root. The repository lint/test scripts
include relay syntax checks; the interface CI job also runs the relay regressions. With the repository's TypeScript toolchain installed, run
`tsc -p deploy/grok-bot-upload/tsconfig.json` for the JSDoc contract check. Deployment is a separate
operator action, using a current official Wrangler release and a private configuration.

Local mocks do not prove a VPC route, live admission, credential revocation or cloud recovery.
After deployment, require one real exact-source admission, unchanged replay, interrupted upload
and reconnect, denied unauthorized requests and independent evidence recovery before enabling
the approved native six-hour routine. A pending queue is not an admitted record or fresh history.
