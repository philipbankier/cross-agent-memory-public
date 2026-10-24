export const PROVIDERS = Object.freeze({
  "https://chatgpt.com": "chatgpt_web",
  "https://claude.ai": "claude_web",
  "https://grok.com": "grok_web",
});

const PAGE_STATUSES = new Set([
  "checking_page",
  "page_not_eligible",
  "identity_not_verified",
  "identity_settling",
  "account_not_authorized",
  "messages_not_ready",
  "snapshot_changed",
  "unchanged",
  "ready_to_queue",
  "queued",
  "already_queued",
  "queue_full",
  "capture_failed",
  "inactive",
]);

export function validateSender(message, sender) {
  if (
    !message ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    !sender?.tab ||
    sender.frameId !== 0 ||
    sender.tab.incognito ||
    !["status", "flush", "authorize", "observe", "capture_status"].includes(
      message.operation,
    )
  )
    return false;
  try {
    const url = new URL(sender.url);
    if (!PROVIDERS[url.origin] || sender.origin !== url.origin) return false;
    if (url.hash) return false;
    if (url.search) {
      const values = [...url.searchParams];
      if (
        url.origin !== "https://grok.com" ||
        values.length !== 1 ||
        values[0][0] !== "rid" ||
        !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(values[0][1])
      )
        return false;
    }
    if (["status", "flush"].includes(message.operation))
      return Object.keys(message).length === 1;
    if (message.operation === "capture_status")
      return (
        Object.keys(message).sort().join(",") ===
          "account_email,operation,status" &&
        (message.account_email === null ||
          (typeof message.account_email === "string" &&
            message.account_email.length <= 254)) &&
        Number.isSafeInteger(sender.tab.id) &&
        sender.tab.id >= 0 &&
        PAGE_STATUSES.has(message.status)
      );
    if (message.operation === "authorize")
      return (
        Object.keys(message).sort().join(",") ===
          "account_email,operation,provider" &&
        message.provider === PROVIDERS[url.origin] &&
        typeof message.account_email === "string" &&
        message.account_email.length <= 254
      );
    if (
      Object.keys(message).sort().join(",") !==
      "account_email,observation,operation"
    )
      return false;
    const observation = message.observation;
    if (observation?.provider !== PROVIDERS[url.origin]) return false;
    if (observation?.canonical_url !== url.origin + url.pathname) return false;
    if (
      typeof message.account_email !== "string" ||
      message.account_email.length > 254
    )
      return false;
    return (
      new TextEncoder().encode(JSON.stringify(message)).byteLength <= 256 * 1024
    );
  } catch {
    return false;
  }
}

const STATUSES = new Set([
  "ready",
  "unconfigured",
  "queued",
  "already_queued",
  "account_not_authorized",
  "privacy_excluded",
  "queue_full",
  "schema_rejected",
  "capture_failed",
  "uploaded",
  "upload_pending",
  "upload_unconfigured",
  "upload_not_authorized",
  "invalid_receipt",
]);

export function classifyReply(reply) {
  if (!reply || typeof reply !== "object" || !STATUSES.has(reply.status))
    return { status: "invalid_collector_response" };
  // A local queue acknowledgement is deliberately not an ingestion receipt.
  return { status: reply.status };
}
