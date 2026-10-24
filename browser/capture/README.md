# Optional Browser Capture

The pilot verified capture, exact searchable evidence and replay/reconnect for two separate
ChatGPT accounts, one Claude account and one Grok account. These are bounded real-account
checks, not a guarantee that future website layouts remain compatible. The memory-query
connectors themselves do not capture website conversations.

This optional Chrome extension observes rendered text in an opened, foreground saved conversation.
It does not read cookies, call undocumented history APIs, crawl unopened chats, or capture media.
Private browsing is disallowed by the manifest. Unknown identity, layout and privacy states stop
capture. The current implementation verifies account identity through the site's visible profile
menu while the user is idle; this can briefly open that menu.
An ambiguous multi-message image-gallery unit currently refuses the whole page; this text-only
path does not silently omit an unknown layout or establish complete provider history.

Capture is disabled by default, separately from Chrome's extension On switch.
Its permissions are `nativeMessaging`, `storage`, and access
to `https://chatgpt.com/*`, `https://claude.ai/*`, `https://grok.com/*` only. It has no external
network destination. The native host binds each verified provider/email pair to a separately
registered opaque source-account ID, encrypts accepted text, and uploads through the existing
loopback collection tunnel. Provider credentials never enter this path.

The queue has a 32 MiB limit. It never evicts unacknowledged observations. Foreground conversation
polls deliver immediately. The native host also supports an independent bounded `--flush` pass
for the existing collector schedule, so delivery need not depend on an open tab. That hook must
be installed separately; code support alone does not prove scheduled operation. A local `queued`
response is not proof of searchable admission. Only an exact node receipt permits deletion of
a queued ciphertext. Concurrent drain attempts share a short-lived OS file lock.

Per-message content identity excludes observation time. Reopening unchanged text reuses its first
admission; it does not fabricate new activity. Changed content is another rendered observation,
not a verified edit relationship. Message occurrence times stay unknown. Exports remain necessary
for historical completeness, unopened/mobile conversations and attachments.

## Native Host

The executable entry point is `python -m cross_assistant_memory.browser_capture_host
--config /absolute/private/config.json`, followed by the caller origin supplied by Chrome.
The host handles one framed request and exits. No persistent process or SSH connection is added.

For unattended diagnostics use the same executable and config with `--inspect` instead of a
browser caller origin. Its content-free JSON shows bounded per-page states, opaque account IDs,
check age/staleness, encrypted queue counts and the last verified receipt identity per account.
It does not emit transcript text, page URLs, email addresses or credential contents. `--flush`
delivers at most ten queued messages within a 60-second process deadline; failures retain the
remaining ciphertext. Neither command requests provider exports or logs into websites.

`script/test-browser-capture` runs an isolated Chromium profile, the actual native messaging
host and a disposable memory node. Provider pages and accounts are synthetic fixtures; all
provider network requests are intercepted locally. It checks capture, multi-account separation,
exact retrieved text, restart/replay and recovery with the browser closed. This is not a
substitute for the separately recorded real-account qualification. The profile, node and
synthetic credentials are removed afterward; the everyday Chrome profile is never opened.

The config is owner-only (0600), with exact fields:

```json
{
  "format_version": 1,
  "extension_origin": "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
  "spool_root": "/absolute/private/spool",
  "key_file": "/absolute/private/spool-key.json",
  "bindings": [
    {
      "provider": "chatgpt_web",
      "email": "approved-owner@example.com",
      "account_binding": "source_account:0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "upload_endpoint": "http://127.0.0.1:28765/upload/browser-observations",
  "credential_file": "/absolute/private/collector-token"
}
```

These are nonfunctional examples, not installation defaults. The source account must be registered
for the enrolled uploading device. Use the actual approved tunnel port and extension ID. The
spool directory is 0700; an existing Tink AEAD key file is 0400/0600 in a 0700 directory. The
credential file contains only the scoped node upload token, never a website session credential.
Omitting both upload fields permits local qualification without network upload.

Before installation: confirm the owner's approved accounts and unpacked-extension permissions,
and prepare an exact native-host `allowed_origins` entry. Load this folder using Chrome's
unpacked-extension flow, then configure the host for the exact extension ID Chrome assigns.
Refresh an approved saved conversation and verify its account-bound searchable evidence and
replay before relying on capture. The tagged Git clone and source distribution contain this
extension folder; a Python wheel alone does not install a browser extension. Never use
wildcards or enable capture while its account bindings or node admission path are unverified.
