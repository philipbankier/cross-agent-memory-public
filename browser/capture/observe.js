(() => {
  "use strict";
  const providers = {
    "https://chatgpt.com": "chatgpt_web",
    "https://claude.ai": "claude_web",
    "https://grok.com": "grok_web",
  };
  const provider = providers[location.origin];
  if (!provider || window !== window.top) return;
  const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
  const route = new RegExp(
    `^/${provider === "claude_web" ? "chat" : "c"}/(${uuid})$`,
    "i",
  );
  let busy = false;
  let lastInput = Date.now();
  let acknowledged = null;
  let acknowledgedAccount = null;
  let inputEpoch = 0;
  let mutationEpoch = 0;
  let settledEpoch = -1;
  let settledUrl = null;
  let confirmedIdentity = null;
  new MutationObserver(() => {
    mutationEpoch += 1;
  }).observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: [
      "hidden",
      "aria-hidden",
      "data-is-streaming",
      "data-talvt-turn-state",
      "data-chatgpt-search-message-ids",
      "data-chatgpt-search-unit-key",
      "data-index",
      "data-testid",
    ],
  });
  for (const name of ["keydown", "pointerdown", "paste"])
    document.addEventListener(
      name,
      (event) => {
        if (!event.isTrusted) return;
        lastInput = Date.now();
        inputEpoch += 1;
      },
      true,
    );

  const visible = (node) =>
    node instanceof HTMLElement && node.getClientRects().length > 0;
  const pause = () => new Promise((resolve) => setTimeout(resolve, 100));
  const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const buttons = () => [...document.querySelectorAll("button")];

  async function setProfileOpen(trigger, open, epoch) {
    const menuId = trigger.getAttribute("aria-controls");
    const reached = () =>
      (trigger.getAttribute("aria-expanded") === "true") === open;
    if (epoch !== inputEpoch || document.visibilityState !== "visible")
      return false;
    if (reached()) return true;
    trigger.click();
    await pause();
    if (epoch !== inputEpoch || document.visibilityState !== "visible")
      return false;
    if (!reached()) {
      // Radix triggers handle pointer-down/keyboard activation, not click alone.
      trigger.dispatchEvent(
        new KeyboardEvent("keydown", {
          key: "Enter",
          bubbles: true,
          cancelable: true,
        }),
      );
      await pause();
    }
    // A closed Radix menu can remain mounted during its exit animation.
    if (!open && reached() && menuId) {
      for (let attempt = 0; attempt < 10; attempt += 1) {
        if (
          epoch !== inputEpoch ||
          document.visibilityState !== "visible" ||
          !document.getElementById(menuId)
        )
          break;
        await pause();
      }
      if (document.getElementById(menuId)) return false;
    }
    return (
      epoch === inputEpoch &&
      document.visibilityState === "visible" &&
      reached()
    );
  }

  async function accountEmail(epoch) {
    if (
      [...document.querySelectorAll('[role="dialog"],[role="menu"]')].some(
        visible,
      )
    )
      return null;
    const selector =
      provider === "chatgpt_web"
        ? 'button[aria-label="Open profile menu"]'
        : provider === "claude_web"
          ? 'button[data-testid="user-menu-button"]'
          : 'button[aria-label^="Account menu,"]';
    const triggers = [...document.querySelectorAll(selector)].filter(visible);
    if (triggers.length !== 1 || triggers[0].disabled) return null;
    const trigger = triggers[0];
    let identity = null;
    let closed = false;
    try {
      if (!(await setProfileOpen(trigger, true, epoch))) return null;
      for (let attempt = 0; attempt < 10; attempt += 1) {
        await pause();
        if (epoch !== inputEpoch || document.visibilityState !== "visible")
          return null;
        const root = document.getElementById(
          trigger.getAttribute("aria-controls"),
        );
        if (
          !root ||
          !visible(root) ||
          root.getAttribute("aria-labelledby") !== trigger.id
        )
          continue;
        let identityMenu = root;
        if (provider === "chatgpt_web") {
          const accounts = [
            ...root.querySelectorAll('[role="menuitem"][aria-haspopup="menu"]'),
          ].filter(
            (item) =>
              visible(item) &&
              /\b(Pro|Plus|Free|Business|Enterprise)$/.test(
                item.innerText.trim(),
              ),
          );
          if (accounts.length !== 1) return null;
          if (accounts[0].getAttribute("data-state") !== "open") {
            accounts[0].click();
            continue;
          }
          identityMenu = document.getElementById(
            accounts[0].getAttribute("aria-controls"),
          );
          if (
            !identityMenu ||
            !visible(identityMenu) ||
            identityMenu.getAttribute("aria-labelledby") !== accounts[0].id
          )
            continue;
        }
        let candidates;
        if (provider === "chatgpt_web") {
          const headers = [
            ...identityMenu.querySelectorAll(
              '[role="menuitem"].cursor-default.select-text',
            ),
          ].filter(visible);
          // The newer account switcher marks the current row with this exact icon.
          const rowRoots = [
            identityMenu,
            ...identityMenu.querySelectorAll(":scope > div"),
          ].filter(
            (root) => root === identityMenu || root.attributes.length === 0,
          );
          const checked = rowRoots
            .flatMap((root) => [
              ...root.querySelectorAll(':scope > [role="menuitem"]'),
            ])
            .filter(
              (row) =>
                visible(row) &&
                [
                  ...row.querySelectorAll(
                    ':scope > [data-menu-row-content="true"] > svg[aria-hidden="true"] > use',
                  ),
                ].some((icon) =>
                  /^\/cdn\/assets\/icons-[0-9a-f]+\.svg#codex-icon-checkmark-lg-light-16$/.test(
                    icon.getAttribute("href") || "",
                  ),
                ),
            );
          if (checked.length > 1 || (headers.length && checked.length))
            return null;
          candidates = headers.length
            ? headers
            : checked.flatMap((row) => [
                ...row.querySelectorAll(
                  ':scope > [data-menu-row-content="true"] > div > span',
                ),
              ]);
        } else {
          candidates = identityMenu.querySelectorAll("div,span");
        }
        const matches = [...candidates]
          .filter(
            (node) =>
              visible(node) &&
              (provider === "chatgpt_web" ||
                !node.closest(
                  '[role="menuitem"],[role="menuitemradio"],[role="menuitemcheckbox"],button,a',
                )),
          )
          .map((node) => node.innerText.trim())
          .filter((text) => email.test(text));
        if (new Set(matches).size === 1) {
          identity = matches[0];
          break;
        }
        if (matches.length > 1) return null;
      }
    } finally {
      // Do not close a menu the user took over during our identity check.
      if (
        epoch === inputEpoch &&
        trigger.getAttribute("aria-expanded") === "true"
      )
        closed = await setProfileOpen(trigger, false, epoch);
    }
    return closed ? identity : null;
  }

  function textOf(element) {
    const chunks = [];
    function walk(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        chunks.push(node.textContent);
        return;
      }
      if (!(node instanceof HTMLElement)) return;
      if (
        node.matches(
          "button,input,textarea,select,script,style,svg,img,video,audio,canvas",
        ) ||
        node.matches(
          '[aria-hidden="true"],.sr-only,[hidden],.thinking-container',
        ) ||
        node.isContentEditable
      )
        return;
      const style = getComputedStyle(node);
      if (style.display === "none" || style.visibility === "hidden") return;
      const block = /^(block|flex|grid|list-item|table-row)$/.test(
        style.display,
      );
      if (block || node.tagName === "BR") chunks.push("\n");
      for (const child of node.childNodes) walk(child);
      if (block) chunks.push("\n");
    }
    walk(element);
    return chunks
      .join("")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function readMessages() {
    const messages = [];
    if (provider === "chatgpt_web") {
      const nodes = document.querySelectorAll(
        "[data-chatgpt-search-message-ids]",
      );
      if (!nodes.length) return null;
      for (const node of nodes) {
        if (
          node
            .closest("[data-talvt-turn-state]")
            ?.getAttribute("data-talvt-turn-state") !== "complete"
        )
          return null;
        const ids = new Set(
          node.getAttribute("data-chatgpt-search-message-ids").split(/\s+/),
        );
        const role = node
          .getAttribute("data-chatgpt-search-unit-key")
          ?.split(":")
          .at(-1);
        if (ids.size !== 1 || !["user", "assistant"].includes(role))
          return null;
        messages.push({
          locator: [...ids][0],
          locator_kind: "provider_message_id",
          role,
          text: textOf(node),
        });
      }
    } else if (provider === "grok_web") {
      for (const node of document.querySelectorAll('[id^="response-"]')) {
        const article = node.querySelector(':scope > [role="article"]');
        if (!article) continue;
        const label = article.querySelector(
          'h2[id^="turn-heading-"]',
        )?.textContent;
        const body = article.querySelector(":scope > .relative");
        if (!body || !["You", "Grok"].includes(label)) return null;
        messages.push({
          locator: node.id.slice("response-".length),
          locator_kind: "provider_message_id",
          role: label === "You" ? "user" : "assistant",
          text: textOf(body),
        });
      }
    } else {
      for (const row of document.querySelectorAll(
        '[data-testid="transcript-row"]',
      )) {
        if (row.querySelector('[data-is-streaming="true"]')) return null;
        const node = row.querySelector(
          '[data-testid="user-message"],[data-testid="assistant-message"]',
        );
        const position = row.getAttribute("data-index");
        if (!node || !/^\d+$/.test(position || "")) return null;
        messages.push({
          locator: position,
          locator_kind: "rendered_position",
          role:
            node.getAttribute("data-testid") === "user-message"
              ? "user"
              : "assistant",
          text: textOf(node),
        });
      }
    }
    if (
      !messages.length ||
      messages.length > 100 ||
      messages.some((m) => !m.text)
    )
      return null;
    return messages;
  }

  function eligiblePage() {
    const match = route.exec(location.pathname);
    if (!match || document.visibilityState !== "visible") return null;
    if (location.hash) return null;
    if (location.search) {
      const values = [...new URLSearchParams(location.search)];
      if (
        provider !== "grok_web" ||
        values.length !== 1 ||
        values[0][0] !== "rid" ||
        !new RegExp(`^${uuid}$`, "i").test(values[0][1]) ||
        !document.getElementById("response-" + values[0][1])
      )
        return null;
    }
    if (document.querySelector('a[aria-label="Switch to Default Chat"]'))
      return null;
    if (
      buttons().some((button) =>
        [button.getAttribute("aria-label") || "", button.innerText].some(
          (label) =>
            /^(Temporary( chat)?|Incognito( chat)?)$/i.test(label.trim()) ||
            (visible(button) &&
              /^Stop( model response| response| generating| streaming)?$/i.test(
                label.trim(),
              )),
        ),
      )
    )
      return null;
    if (provider !== "grok_web") {
      const saved = [
        ...document.querySelectorAll("nav a[href],aside a[href]"),
      ].some((a) => {
        const url = new URL(a.href, location.href);
        return (
          url.origin === location.origin &&
          url.pathname === location.pathname &&
          !url.hash &&
          !url.search
        );
      });
      if (!saved) return null;
    } else if (
      !document.querySelector('nav button[aria-label="Create share link"]')
    ) {
      return null;
    }
    return match;
  }

  function readObservation() {
    const match = eligiblePage();
    if (!match) return null;
    const messages = readMessages();
    if (!messages) return null;
    return {
      format_version: 1,
      capture_kind: "rendered_browser_observation",
      completeness: "visible_messages_only",
      provider,
      conversation_id: match[1].toLowerCase(),
      canonical_url: location.origin + location.pathname,
      messages,
    };
  }

  async function tick() {
    if (busy || Date.now() - lastInput < 5000) return;
    if (
      !route.test(location.pathname) ||
      document.visibilityState !== "visible"
    )
      return;
    busy = true;
    let stage = "checking_page";
    let report = false;
    let verifiedAccount = null;
    try {
      const ready = await chrome.runtime.sendMessage({ operation: "status" });
      if (ready?.status !== "ready") return;
      report = true;
      await chrome.runtime.sendMessage({ operation: "flush" });
      if (!eligiblePage()) {
        stage = "page_not_eligible";
        return;
      }
      if (settledEpoch === mutationEpoch && settledUrl === location.href) {
        stage = "unchanged";
        verifiedAccount = acknowledgedAccount;
        return;
      }
      const epoch = inputEpoch;
      stage = "identity_not_verified";
      const account = await accountEmail(epoch);
      if (!account || epoch !== inputEpoch) return;
      const identity = account + "\n" + location.origin + location.pathname;
      if (confirmedIdentity !== identity) {
        confirmedIdentity = identity;
        acknowledged = null;
        acknowledgedAccount = null;
        settledUrl = null;
        stage = "identity_settling";
        return;
      }
      stage = "account_not_authorized";
      const authorized = await chrome.runtime.sendMessage({
        operation: "authorize",
        provider,
        account_email: account,
      });
      if (authorized?.status !== "ready" || epoch !== inputEpoch) return;
      verifiedAccount = account;
      stage = "messages_not_ready";
      const observation = readObservation();
      if (!observation) return;
      const revision = JSON.stringify(observation);
      const capturedUrl = location.href;
      stage = "snapshot_changed";
      if (
        (await accountEmail(epoch)) !== account ||
        epoch !== inputEpoch ||
        location.href !== capturedUrl ||
        JSON.stringify(readObservation()) !== revision
      )
        return;
      const identityRevision = account + "\n" + revision;
      const capturedEpoch = mutationEpoch;
      if (identityRevision === acknowledged) {
        settledEpoch = capturedEpoch;
        settledUrl = location.href;
        stage = "unchanged";
        return;
      }
      if (JSON.stringify(readObservation()) !== revision) return;
      stage = "ready_to_queue";
      const reply = await chrome.runtime.sendMessage({
        operation: "observe",
        account_email: account,
        observation: { ...observation, observed_at: new Date().toISOString() },
      });
      stage = ["queued", "already_queued", "queue_full"].includes(reply?.status)
        ? reply.status
        : "capture_failed";
      if (reply?.status === "queued" || reply?.status === "already_queued") {
        acknowledged = identityRevision;
        acknowledgedAccount = account;
        settledEpoch = capturedEpoch;
        settledUrl = location.href;
      }
    } catch {
      // No page text, account details, or native errors enter Chrome's logs.
      stage = "capture_failed";
    } finally {
      if (report)
        try {
          await chrome.runtime.sendMessage({
            operation: "capture_status",
            status: stage,
            account_email: verifiedAccount,
          });
        } catch {
          // An unloaded extension cannot receive status; never log page state.
        }
      busy = false;
    }
  }
  setInterval(tick, 15000 + Math.floor(Math.random() * 1000));
})();
