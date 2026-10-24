import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const source = readFileSync(new URL("./observe.js", import.meta.url), "utf8");
const conversation = "11111111-2222-4333-8444-555555555555";
const messageId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const accounts = {
  chatgpt_web: ["first@example.test", "second@example.test"],
  claude_web: ["claude@example.test"],
  grok_web: ["grok@example.test"],
};
const origins = {
  chatgpt_web: "https://chatgpt.com",
  claude_web: "https://claude.ai",
  grok_web: "https://grok.com",
};

function fixture(provider = "chatgpt_web") {
  const state = {
    enabled: false,
    account: accounts[provider][0],
    saved: true,
    private: false,
    streaming: false,
    extraButtons: [],
    header: true,
    accountLayout: "legacy",
    accountWrapper: "none",
    checkedAccounts: 1,
    accountCheckHref:
      "/cdn/assets/icons-0123abcd.svg#codex-icon-checkmark-lg-light-16",
    menuLinked: true,
    visible: true,
    text: "SYNTHETIC rendered message",
    textReads: 0,
    profileOpens: 0,
    profileActivation: "click",
    profileClicks: 0,
    profileKeys: 0,
    closingPauses: 0,
    dialog: "absent",
    requests: [],
    errors: [],
    onOpen: () => {},
    onProfileClick: () => {},
    onClosingPause: () => {},
  };
  let now = Date.parse("2026-10-20T12:00:00Z");
  let interval;
  let mutation;
  let observerOptions;
  let pauses = 0;
  let menuOpen = false;
  let submenuOpen = false;
  let closingRemaining = 0;
  const listeners = new Map();
  const canonical = `${origins[provider]}/${provider === "claude_web" ? "chat" : "c"}/${conversation}`;
  const location = new URL(canonical);
  const unsupported = (operation, selector) => {
    const error = new Error(`Unsupported fixture ${operation}: ${selector}`);
    state.errors.push(error);
    throw error;
  };
  class Element {
    constructor(attrs = {}, text = "") {
      this.attrs = attrs;
      this.innerText = text;
      this.id = attrs.id || "";
      this.disabled = false;
      this.tagName = "DIV";
      this.isContentEditable = false;
      this.childNodes = [];
      this.queries = new Map();
      this.ancestors = new Map();
    }
    getAttribute(name) {
      return this.attrs[name] ?? null;
    }
    getClientRects() {
      return [{}];
    }
    querySelectorAll(selector) {
      if (!this.queries.has(selector)) return unsupported("query", selector);
      const result = this.queries.get(selector);
      return typeof result === "function" ? result() : result;
    }
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] ?? null;
    }
    closest(selector) {
      if (!this.ancestors.has(selector))
        return unsupported("closest", selector);
      return this.ancestors.get(selector);
    }
    matches(selector) {
      if (
        selector ===
          "button,input,textarea,select,script,style,svg,img,video,audio,canvas" ||
        selector ===
          '[aria-hidden="true"],.sr-only,[hidden],.thinking-container'
      )
        return false;
      return unsupported("matches", selector);
    }
  }
  const mutate = () => mutation();
  const trigger = new Element({
    id: "profile",
    "aria-controls": "profile-menu",
  });
  const toggleProfile = () => {
    menuOpen = !menuOpen;
    trigger.attrs["aria-expanded"] = String(menuOpen);
    if (menuOpen) {
      closingRemaining = 0;
      state.profileOpens += 1;
      state.onOpen(state.profileOpens);
    } else {
      closingRemaining = state.closingPauses;
      submenuOpen = false;
      accountTrigger.attrs["data-state"] = "closed";
    }
    mutate();
  };
  trigger.click = () => {
    state.profileClicks += 1;
    state.onProfileClick();
    if (state.profileActivation === "click") toggleProfile();
  };
  trigger.dispatchEvent = (event) => {
    assert.equal(event.type, "keydown");
    assert.equal(event.key, "Enter");
    assert.equal(event.bubbles, true);
    assert.equal(event.cancelable, true);
    state.profileKeys += 1;
    listeners.get("keydown")(event);
    if (state.profileActivation === "keyboard") toggleProfile();
    return true;
  };
  const root = new Element({ "aria-labelledby": trigger.id });
  const accountTrigger = new Element(
    { id: "account", "aria-controls": "account-menu", "data-state": "closed" },
    "Synthetic Pro",
  );
  accountTrigger.click = () => {
    submenuOpen = true;
    accountTrigger.attrs["data-state"] = "open";
    mutate();
  };
  root.queries.set('[role="menuitem"][aria-haspopup="menu"]', [accountTrigger]);
  const submenu = new Element({ "aria-labelledby": accountTrigger.id });
  const actionSelector =
    '[role="menuitem"],[role="menuitemradio"],[role="menuitemcheckbox"],button,a';
  const header = new Element();
  Object.defineProperty(header, "innerText", { get: () => state.account });
  header.ancestors.set(actionSelector, null);
  const alternative = new Element({}, "second@example.test");
  alternative.ancestors.set(actionSelector, new Element({ role: "menuitem" }));
  // ChatGPT's inactive actionable account does not match the current-account header selector.
  submenu.queries.set('[role="menuitem"].cursor-default.select-text', () =>
    state.header && state.accountLayout !== "checked" ? [header] : [],
  );
  const accountRows = [header, alternative].map((identity, index) => {
    const accountRow = new Element({ role: "menuitem" });
    const check = new Element();
    check.getAttribute = (name) => {
      assert.equal(name, "href");
      return state.accountCheckHref;
    };
    accountRow.queries.set(
      ':scope > [data-menu-row-content="true"] > svg[aria-hidden="true"] > use',
      () => (index < state.checkedAccounts ? [check] : []),
    );
    accountRow.queries.set(
      ':scope > [data-menu-row-content="true"] > div > span',
      [new Element({}, "Synthetic Account"), identity],
    );
    return accountRow;
  });
  submenu.queries.set(':scope > [role="menuitem"]', () =>
    state.accountLayout === "legacy" || state.accountWrapper !== "none"
      ? []
      : accountRows,
  );
  const accountWrapper = new Element();
  Object.defineProperty(accountWrapper, "attributes", {
    get: () => (state.accountWrapper === "marked" ? [{ name: "role" }] : []),
  });
  accountWrapper.queries.set(':scope > [role="menuitem"]', () =>
    state.accountWrapper === "nested" ? [] : accountRows,
  );
  submenu.queries.set(":scope > div", () =>
    state.accountWrapper === "none" ? [] : [accountWrapper],
  );
  root.queries.set("div,span", () =>
    state.header ? [header, alternative] : [alternative],
  );
  const message = new Element({
    "data-chatgpt-search-message-ids": messageId,
    "data-chatgpt-search-unit-key": "synthetic:user",
    "data-testid": "user-message",
  });
  message.childNodes = [
    {
      nodeType: 3,
      get textContent() {
        state.textReads += 1;
        return state.text;
      },
    },
  ];
  const turn = new Element();
  turn.getAttribute = (name) => {
    assert.equal(name, "data-talvt-turn-state");
    return state.streaming ? "streaming" : "complete";
  };
  message.ancestors.set("[data-talvt-turn-state]", turn);
  const row = new Element({ "data-index": "0" });
  row.queries.set('[data-is-streaming="true"]', () =>
    state.streaming ? [new Element()] : [],
  );
  row.queries.set(
    '[data-testid="user-message"],[data-testid="assistant-message"]',
    [message],
  );
  const response = new Element({ id: `response-${messageId}` });
  const article = new Element();
  const heading = new Element();
  heading.textContent = "You";
  article.queries.set('h2[id^="turn-heading-"]', [heading]);
  article.queries.set(":scope > .relative", [message]);
  response.queries.set(':scope > [role="article"]', [article]);
  const savedLink = new Element();
  savedLink.href = canonical;
  const dialog = new Element({ role: "dialog", "aria-modal": "true" });
  dialog.getClientRects = () => (state.dialog === "visible" ? [{}] : []);
  const selectors = new Map([
    [
      '[role="dialog"],[role="menu"]',
      () => [
        ...(menuOpen || closingRemaining > 0 ? [root] : []),
        ...(state.dialog !== "absent" ? [dialog] : []),
      ],
    ],
    ['button[aria-label="Open profile menu"]', () => [trigger]],
    ['button[data-testid="user-menu-button"]', () => [trigger]],
    ['button[aria-label^="Account menu,"]', () => [trigger]],
    [
      'a[aria-label="Switch to Default Chat"]',
      () => (state.private ? [new Element()] : []),
    ],
    [
      "button",
      () => [
        ...(state.streaming && provider === "grok_web"
          ? [new Element({ "aria-label": "Stop model response" }, "")]
          : []),
        ...state.extraButtons.map(({ label, rendered }) => {
          const button = new Element({}, label);
          button.getClientRects = () => (rendered ? [{}] : []);
          return button;
        }),
      ],
    ],
    ["nav a[href],aside a[href]", () => (state.saved ? [savedLink] : [])],
    [
      'nav button[aria-label="Create share link"]',
      () => (state.saved ? [new Element()] : []),
    ],
    ["[data-chatgpt-search-message-ids]", () => [message]],
    ['[data-testid="transcript-row"]', () => [row]],
    ['[id^="response-"]', () => [response]],
  ]);
  const document = {
    documentElement: new Element(),
    get visibilityState() {
      return state.visible ? "visible" : "hidden";
    },
    addEventListener(name, callback) {
      listeners.set(name, callback);
    },
    querySelectorAll(selector) {
      if (!selectors.has(selector))
        return unsupported("document query", selector);
      return selectors.get(selector)();
    },
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] ?? null;
    },
    getElementById(id) {
      if (id === "profile-menu")
        return (menuOpen || closingRemaining > 0) && state.menuLinked
          ? root
          : null;
      if (id === "account-menu") return submenuOpen ? submenu : null;
      if (id === `response-${messageId}`) return response;
      if (id?.startsWith("response-")) return null;
      return unsupported("id", id);
    },
  };
  const window = {};
  window.top = window;
  runInNewContext(
    source,
    {
      window,
      document,
      location,
      HTMLElement: Element,
      Node: { TEXT_NODE: 3 },
      KeyboardEvent: class {
        constructor(type, options) {
          Object.assign(this, { type, isTrusted: false }, options);
        }
      },
      URL,
      URLSearchParams,
      Date: class extends Date {
        constructor(value) {
          super(value === undefined ? now : value);
        }
        static now() {
          return now;
        }
      },
      MutationObserver: class {
        constructor(callback) {
          mutation = callback;
        }
        observe(target, options) {
          assert.equal(target, document.documentElement);
          observerOptions = JSON.parse(JSON.stringify(options));
        }
      },
      getComputedStyle: () => ({ display: "block", visibility: "visible" }),
      setInterval(callback, delay) {
        assert.ok(Number.isInteger(delay) && delay >= 15000 && delay < 16000);
        assert.equal(interval, undefined);
        interval = callback;
      },
      setTimeout(callback, delay) {
        assert.equal(delay, 100);
        if (++pauses > 50) return unsupported("timer", "pause budget");
        queueMicrotask(() => {
          if (closingRemaining > 0) {
            closingRemaining -= 1;
            state.onClosingPause();
            if (closingRemaining === 0) mutate();
          }
          callback();
        });
      },
      chrome: {
        runtime: {
          async sendMessage(request) {
            const body = JSON.parse(JSON.stringify(request));
            state.requests.push(body);
            if (!state.enabled) return { status: "disabled" };
            if (body.operation === "status") return { status: "ready" };
            if (body.operation === "flush") return { status: "ready" };
            if (body.operation === "capture_status") {
              assert.equal(
                Object.keys(body).sort().join(","),
                "operation,status",
              );
              return { status: "ready" };
            }
            if (body.operation === "authorize")
              return {
                status: accounts[provider].includes(body.account_email)
                  ? "ready"
                  : "account_not_authorized",
              };
            if (body.operation === "observe") return { status: "queued" };
            return unsupported("chrome operation", body.operation);
          },
        },
      },
    },
    { timeout: 1000 },
  );
  return {
    state,
    location,
    canonical,
    mutate,
    get observerOptions() {
      return observerOptions;
    },
    get menuOpen() {
      return menuOpen;
    },
    get menuMounted() {
      return menuOpen || closingRemaining > 0;
    },
    observations: () =>
      state.requests.filter((item) => item.operation === "observe"),
    pageStatus: () =>
      state.requests
        .filter((item) => item.operation === "capture_status")
        .at(-1)?.status,
    input: () => listeners.get("pointerdown")({ isTrusted: true }),
    async tick() {
      now += 15000;
      pauses = 0;
      await interval();
      assert.deepEqual(
        state.errors,
        [],
        "fixture must expose selector/API drift",
      );
    },
  };
}

test("default disabled never opens identity menus or reads message text", async () => {
  const f = fixture();
  await f.tick();
  assert.deepEqual(f.state.requests, [{ operation: "status" }]);
  assert.equal(f.state.profileOpens, 0);
  assert.equal(f.state.textReads, 0);
});

for (const provider of Object.keys(accounts)) {
  test(`${provider}: hidden Stop controls do not reject a saved conversation`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.extraButtons = Array.from({ length: 4 }, () => ({
      label: "Stop",
      rendered: false,
    }));
    await f.tick();
    await f.tick();
    assert.equal(f.observations().length, 1);
    assert.equal(f.pageStatus(), "queued");
  });
  test(`${provider}: a rendered Stop control still prevents capture`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    await f.tick();
    f.state.extraButtons = [{ label: "Stop", rendered: true }];
    f.mutate();
    await f.tick();
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
    assert.equal(f.pageStatus(), "page_not_eligible");
  });
  for (const label of ["Temporary chat", "Incognito chat"]) {
    test(`${provider}: hidden ${label} markers retain conservative refusal`, async () => {
      const f = fixture(provider);
      f.state.enabled = true;
      f.state.extraButtons = [{ label, rendered: false }];
      await f.tick();
      await f.tick();
      assert.equal(f.state.profileOpens, 0);
      assert.equal(f.state.textReads, 0);
      assert.deepEqual(f.observations(), []);
      assert.equal(f.pageStatus(), "page_not_eligible");
    });
  }
  test(`${provider}: an unrendered dialog does not block account verification`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.dialog = "hidden";
    await f.tick();
    await f.tick();
    assert.equal(f.observations().length, 1);
    assert.equal(f.pageStatus(), "queued");
  });
  test(`${provider}: a visible dialog prevents profile interaction and text reads`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.dialog = "visible";
    await f.tick();
    await f.tick();
    assert.equal(f.state.profileOpens, 0);
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
    assert.equal(f.pageStatus(), "identity_not_verified");
  });
  test(`${provider}: keyboard-driven profile menu captures and closes`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.profileActivation = "keyboard";
    await f.tick();
    assert.equal(f.menuOpen, false);
    await f.tick();
    assert.equal(f.observations().length, 1);
    assert.equal(f.menuOpen, false);
    assert.equal(f.state.profileKeys, 6);
  });
  test(`${provider}: closing animation finishes before the next identity check`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.profileActivation = "keyboard";
    f.state.closingPauses = 2;
    await f.tick();
    await f.tick();
    assert.equal(f.observations().length, 1);
    assert.equal(f.menuMounted, false);
  });
}

test("a profile menu that stays mounted refuses capture within the wait bound", async () => {
  const f = fixture("grok_web");
  f.state.enabled = true;
  f.state.profileActivation = "keyboard";
  f.state.closingPauses = Infinity;
  await f.tick();
  await f.tick();
  assert.equal(f.menuMounted, true);
  assert.equal(f.state.textReads, 0);
  assert.deepEqual(f.observations(), []);
  assert.equal(f.state.profileKeys, 2);
});

test("trusted input during profile closing stops capture and further activation", async () => {
  const f = fixture("grok_web");
  f.state.enabled = true;
  f.state.profileActivation = "keyboard";
  f.state.closingPauses = 2;
  f.state.onClosingPause = () => f.input();
  await f.tick();
  assert.equal(f.state.profileKeys, 2);
  assert.equal(f.state.textReads, 0);
  assert.deepEqual(f.observations(), []);
});

test("unsupported profile activation remains bounded and reads no text", async () => {
  const f = fixture();
  f.state.enabled = true;
  f.state.profileActivation = "none";
  await f.tick();
  assert.equal(f.state.profileClicks, 1);
  assert.equal(f.state.profileKeys, 1);
  assert.equal(f.state.textReads, 0);
  assert.deepEqual(f.observations(), []);
});

test("user input during profile activation prevents fallback and text reads", async () => {
  const f = fixture();
  f.state.enabled = true;
  f.state.profileActivation = "keyboard";
  f.state.onProfileClick = () => f.input();
  await f.tick();
  assert.equal(f.state.profileKeys, 0);
  assert.equal(f.state.textReads, 0);
  assert.deepEqual(f.observations(), []);
});

for (const [provider, emails] of Object.entries(accounts)) {
  for (const email of emails) {
    test(`${provider} ${email}: stable enabled saved conversation queues exact body`, async () => {
      const f = fixture(provider);
      f.state.enabled = true;
      f.state.account = email;
      await f.tick();
      assert.equal(f.state.textReads, 0);
      assert.equal(f.pageStatus(), "identity_settling");
      assert.deepEqual(f.observations(), []);
      await f.tick();
      assert.deepEqual(f.observations(), [
        {
          operation: "observe",
          account_email: email,
          observation: {
            format_version: 1,
            capture_kind: "rendered_browser_observation",
            completeness: "visible_messages_only",
            provider,
            conversation_id: conversation,
            canonical_url: f.canonical,
            messages: [
              {
                locator: provider === "claude_web" ? "0" : messageId,
                locator_kind:
                  provider === "claude_web"
                    ? "rendered_position"
                    : "provider_message_id",
                role: "user",
                text: f.state.text,
              },
            ],
            observed_at: "2026-10-20T12:00:30.000Z",
          },
        },
      ]);
      const opens = f.state.profileOpens;
      const reads = f.state.textReads;
      await f.tick();
      await f.tick();
      assert.equal(f.observations().length, 1);
      assert.equal(f.pageStatus(), "unchanged");
      assert.equal(f.state.profileOpens, opens);
      assert.equal(f.state.textReads, reads);
    });
  }
  test(`${provider}: unknown account never reads message text`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.account = "unknown@example.test";
    await f.tick();
    await f.tick();
    assert.ok(f.state.requests.some((r) => r.operation === "authorize"));
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
    assert.equal(f.pageStatus(), "account_not_authorized");
  });
  test(`${provider}: inactive alternative email is not accepted as identity`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.header = false;
    await f.tick();
    await f.tick();
    assert.equal(f.state.textReads, 0);
    assert.equal(
      f.state.requests.some((r) => r.operation === "authorize"),
      false,
    );
    assert.deepEqual(f.observations(), []);
  });
  test(`${provider}: streaming and private states do not stick after recovery`, async () => {
    const f = fixture(provider);
    f.state.enabled = true;
    f.state.private = true;
    await f.tick();
    assert.equal(f.state.profileOpens, 0);
    f.state.private = false;
    f.state.streaming = true;
    f.mutate();
    await f.tick();
    await f.tick();
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
    f.state.streaming = false;
    f.mutate();
    await f.tick();
    await f.tick();
    assert.equal(f.observations().length, 1);
  });
}

for (const change of ["identity", "url", "input", "revision", "private"]) {
  test(`mid-snapshot ${change} change prevents submission`, async () => {
    const f = fixture();
    f.state.enabled = true;
    await f.tick();
    f.state.onOpen = (count) => {
      if (count !== 3) return;
      if (change === "identity") f.state.account = accounts.chatgpt_web[1];
      if (change === "url") f.location.pathname = `/c/${messageId}`;
      if (change === "input") f.input();
      if (change === "revision")
        f.state.text = "SYNTHETIC changed during verification";
      if (change === "private") f.state.private = true;
      f.mutate();
    };
    await f.tick();
    assert.ok(f.state.textReads > 0);
    assert.deepEqual(f.observations(), []);
  });
}

for (const suffix of ["?rid=" + messageId, "?unknown=1", "#fragment"]) {
  test(`ChatGPT rejects ${suffix} before profile interaction`, async () => {
    const f = fixture();
    f.state.enabled = true;
    f.location.href += suffix;
    await f.tick();
    assert.equal(f.state.profileOpens, 0);
    assert.equal(f.state.textReads, 0);
  });
}

test("invalid route and unsaved conversation are rejected before profile click", async () => {
  for (const route of ["invalid", "unsaved"]) {
    const f = fixture();
    f.state.enabled = true;
    if (route === "invalid") f.location.pathname = "/c/not-a-uuid";
    else f.state.saved = false;
    await f.tick();
    assert.equal(f.state.profileOpens, 0);
    assert.equal(f.state.textReads, 0);
  }
});

test("unlinked identity menu cannot authorize or read messages", async () => {
  const f = fixture();
  f.state.enabled = true;
  f.state.menuLinked = false;
  await f.tick();
  await f.tick();
  assert.equal(f.state.textReads, 0);
  assert.equal(
    f.state.requests.some((r) => r.operation === "authorize"),
    false,
  );
});

test("Grok rid requires a matching rendered response and emits a query-free URL", async () => {
  for (const rid of [messageId, conversation]) {
    const f = fixture("grok_web");
    f.state.enabled = true;
    f.location.search = `?rid=${rid}`;
    await f.tick();
    await f.tick();
    if (rid === messageId) {
      assert.equal(f.observations().length, 1);
      assert.equal(f.observations()[0].observation.canonical_url, f.canonical);
    } else {
      assert.equal(f.state.profileOpens, 0);
      assert.equal(f.state.textReads, 0);
    }
  }
});

for (const suffix of [
  `?rid=${messageId}&rid=${messageId}`,
  `?rid=${messageId}&unknown=1`,
  "?rid=invalid",
  `?rid=${messageId}#fragment`,
]) {
  test(`Grok rejects ${suffix} before profile interaction`, async () => {
    const f = fixture("grok_web");
    f.state.enabled = true;
    f.location.href += suffix;
    await f.tick();
    assert.equal(f.state.profileOpens, 0);
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
  });
}

test("switching between the approved ChatGPT accounts requires fresh stable identity", async () => {
  const f = fixture();
  f.state.enabled = true;
  await f.tick();
  await f.tick();
  assert.equal(f.observations().length, 1);
  const reads = f.state.textReads;
  f.state.account = accounts.chatgpt_web[1];
  f.state.text = "SYNTHETIC second-account message";
  f.mutate();
  await f.tick();
  assert.equal(f.state.textReads, reads);
  assert.equal(f.observations().length, 1);
  await f.tick();
  assert.deepEqual(
    f
      .observations()
      .map((body) => [body.account_email, body.observation.messages[0].text]),
    [
      [accounts.chatgpt_web[0], "SYNTHETIC rendered message"],
      [accounts.chatgpt_web[1], "SYNTHETIC second-account message"],
    ],
  );
});

for (const wrapper of ["none", "plain"]) {
  test(`ChatGPT checked-account row with ${wrapper} wrapper captures only its selected identity`, async () => {
    const f = fixture();
    f.state.enabled = true;
    f.state.accountLayout = "checked";
    f.state.accountWrapper = wrapper;
    await f.tick();
    await f.tick();
    assert.equal(f.observations().length, 1);
    assert.equal(f.observations()[0].account_email, accounts.chatgpt_web[0]);
    f.state.account = accounts.chatgpt_web[1];
    f.state.text = "SYNTHETIC second-account message";
    f.mutate();
    await f.tick();
    assert.equal(f.observations().length, 1);
    await f.tick();
    assert.equal(f.observations().length, 2);
    assert.equal(f.observations()[1].account_email, accounts.chatgpt_web[1]);
  });
}

for (const [name, overrides] of [
  ["missing marker", { checkedAccounts: 0 }],
  ["two checked accounts", { checkedAccounts: 2 }],
  [
    "two wrapped checked accounts",
    { checkedAccounts: 2, accountWrapper: "plain" },
  ],
  ["marked account wrapper", { accountWrapper: "marked" }],
  ["nested account wrapper", { accountWrapper: "nested" }],
  [
    "unknown icon",
    { accountCheckHref: "/cdn/assets/icons-0123abcd.svg#other" },
  ],
  [
    "foreign icon",
    {
      accountCheckHref:
        "https://other.test/icons-0123abcd.svg#codex-icon-checkmark-lg-light-16",
    },
  ],
  ["mixed legacy and checked layouts", { accountLayout: "mixed" }],
]) {
  test(`ChatGPT checked-account layout refuses ${name} before reading messages`, async () => {
    const f = fixture();
    Object.assign(
      f.state,
      { enabled: true, accountLayout: "checked" },
      overrides,
    );
    await f.tick();
    await f.tick();
    assert.equal(f.state.textReads, 0);
    assert.deepEqual(f.observations(), []);
    assert.equal(f.pageStatus(), "identity_not_verified");
  });
}

test("ChatGPT checked-account layout still refuses an unauthorized account", async () => {
  const f = fixture();
  Object.assign(f.state, {
    enabled: true,
    accountLayout: "checked",
    account: "unknown@example.test",
  });
  await f.tick();
  await f.tick();
  assert.equal(f.state.textReads, 0);
  assert.deepEqual(f.observations(), []);
  assert.equal(f.pageStatus(), "account_not_authorized");
});

test("attribute observer covers capture-relevant completion, visibility and locator changes", () => {
  const f = fixture();
  assert.equal(f.observerOptions.attributes, true);
  assert.equal(f.observerOptions.subtree, true);
  for (const attribute of [
    "hidden",
    "aria-hidden",
    "data-is-streaming",
    "data-talvt-turn-state",
    "data-chatgpt-search-message-ids",
    "data-chatgpt-search-unit-key",
    "data-index",
  ])
    assert.ok(f.observerOptions.attributeFilter.includes(attribute), attribute);
});
