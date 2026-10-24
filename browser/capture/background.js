import { validateSender, classifyReply, PROVIDERS } from "./protocol.mjs";

const HOST = "com.cross_agent_memory.capture";
let busy = false;

async function forward(message, sender) {
  if (!validateSender(message, sender)) return { status: "invalid_source" };
  if (!(await chrome.storage.local.get("enabled")).enabled)
    return { status: "disabled" };
  if (message.operation === "capture_status") {
    const pageKey = Array.from(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(sender.origin + ":" + sender.tab.id),
        ),
      ),
    )
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    await chrome.storage.local.set({
      pageStatus: message.status,
      pageCheckedAt: new Date().toISOString(),
    });
    try {
      return classifyReply(
        await chrome.runtime.sendNativeMessage(HOST, {
          operation: "diagnostic",
          provider: PROVIDERS[sender.origin],
          page_key: pageKey,
          status: message.status,
          account_email: message.account_email,
          extension_version: chrome.runtime.getManifest().version,
        }),
      );
    } catch {
      return { status: "local_collector_unavailable" };
    }
  }
  if (busy) return { status: "busy" };
  busy = true;
  try {
    const reply = classifyReply(
      await chrome.runtime.sendNativeMessage(HOST, message),
    );
    const field =
      message.operation === "flush"
        ? "uploadStatus"
        : message.operation === "observe"
          ? "captureStatus"
          : "bridgeStatus";
    await chrome.storage.local.set({
      [field]: reply.status,
      lastCheckAt: new Date().toISOString(),
    });
    if (
      message.operation === "flush" ||
      !["ready", "queued", "already_queued"].includes(reply.status)
    )
      await chrome.action.setBadgeText({
        text: ["ready", "uploaded"].includes(reply.status) ? "" : "!",
      });
    return reply;
  } catch {
    await chrome.storage.local.set({
      bridgeStatus: "local_collector_unavailable",
      lastCheckAt: new Date().toISOString(),
    });
    await chrome.action.setBadgeText({ text: "!" });
    return { status: "local_collector_unavailable" };
  } finally {
    busy = false;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  forward(message, sender).then(sendResponse, () =>
    sendResponse({ status: "capture_failed" }),
  );
  return true;
});
