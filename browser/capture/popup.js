const enabled = document.querySelector("#enabled");
const status = document.querySelector("#status");
const saved = await chrome.storage.local.get([
  "enabled",
  "bridgeStatus",
  "captureStatus",
  "uploadStatus",
  "pageStatus",
  "pageCheckedAt",
  "lastCheckAt",
]);
enabled.checked = saved.enabled === true;
const labels = {
  ready: "Ready",
  unconfigured: "Not configured",
  queued: "Queued locally",
  already_queued: "Already queued locally",
  uploaded: "Verified upload progress",
  upload_pending: "Pending, retained locally",
  upload_unconfigured: "Not configured",
  upload_not_authorized: "Authorization required",
  invalid_receipt: "Invalid receipt, retained locally",
  queue_full: "Queue full, waiting for uploads",
  account_not_authorized: "Account not authorized",
  local_collector_unavailable: "Local collector unavailable",
  checking_page: "Checking page",
  page_not_eligible: "Not an eligible saved conversation",
  identity_not_verified: "Account check did not complete",
  identity_settling: "Account confirmed, waiting for the next check",
  messages_not_ready: "Waiting for completed messages",
  snapshot_changed: "Page changed during verification",
  unchanged: "No changes since the last queued observation",
  ready_to_queue: "Page verified",
  capture_failed: "Page check failed",
};
const label = (value) =>
  labels[value] || (value ? "Needs attention" : "Not yet checked");
const freshness = (at) => {
  const age = Date.now() - Date.parse(at || "");
  return !Number.isFinite(age)
    ? "Not checked"
    : age > 120000
      ? "Stale"
      : "Recent";
};
status.textContent = enabled.checked
  ? `Local host (${freshness(saved.lastCheckAt)}): ${label(saved.bridgeStatus)}`
  : "Capture disabled";
document.querySelector("#queue").textContent =
  `Capture: ${label(saved.captureStatus)}`;
document.querySelector("#upload").textContent =
  `Upload: ${label(saved.uploadStatus)}`;
document.querySelector("#page").textContent =
  `Last page check (${freshness(saved.pageCheckedAt)}): ${label(saved.pageStatus)}`;
document.querySelector("#version").textContent =
  `Version ${chrome.runtime.getManifest().version}`;
enabled.addEventListener("change", async () => {
  await chrome.storage.local.set({ enabled: enabled.checked });
  status.textContent = enabled.checked
    ? "Waiting for a supported conversation"
    : "Capture disabled";
});
