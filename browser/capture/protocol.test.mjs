import test from "node:test";
import assert from "node:assert/strict";
import { validateSender, classifyReply } from "./protocol.mjs";

const url = "https://chatgpt.com/c/12345678-1234-1234-1234-123456789abc";
const sender = {
  tab: { id: 1, incognito: false },
  frameId: 0,
  origin: "https://chatgpt.com",
  url,
};
const message = {
  operation: "observe",
  account_email: "owner@example.test",
  observation: { provider: "chatgpt_web", canonical_url: url },
};

test("only a supported top-level sender can request capture", () => {
  assert.equal(validateSender(message, sender), true);
  for (const change of [
    { frameId: 1 },
    { tab: { incognito: true } },
    { tab: null },
    { origin: "https://other.test" },
    { url: "https://chatgpt.com.evil.test/c/a" },
  ])
    assert.equal(validateSender(message, { ...sender, ...change }), false);
});

test("provider, canonical page and envelope must agree", () => {
  assert.equal(
    validateSender({ ...message, secret: "not allowed" }, sender),
    false,
  );
  assert.equal(
    validateSender(
      {
        ...message,
        observation: { ...message.observation, provider: "grok_web" },
      },
      sender,
    ),
    false,
  );
  assert.equal(
    validateSender(
      {
        ...message,
        observation: {
          ...message.observation,
          canonical_url: url + "?token=no",
        },
      },
      sender,
    ),
    false,
  );
  assert.equal(
    validateSender({ ...message, account_email: "x".repeat(255) }, sender),
    false,
  );
});

test("oversize requests are rejected before native messaging", () => {
  assert.equal(
    validateSender(
      {
        ...message,
        observation: { ...message.observation, text: "x".repeat(256 * 1024) },
      },
      sender,
    ),
    false,
  );
});

test("status requests do not carry site text", () => {
  assert.equal(validateSender({ operation: "status" }, sender), true);
  assert.equal(
    validateSender({ operation: "status", text: "private" }, sender),
    false,
  );
});

test("page diagnostics accept only fixed states with no page data", () => {
  const report = {
    operation: "capture_status",
    status: "identity_not_verified",
    account_email: null,
  };
  assert.equal(validateSender(report, sender), true);
  for (const change of [
    { status: "private error text" },
    { text: "private" },
    { account_email: "x".repeat(255) },
    { url },
    { status: "uploaded" },
  ])
    assert.equal(validateSender({ ...report, ...change }, sender), false);
  assert.equal(
    validateSender(report, { ...sender, tab: { incognito: true } }),
    false,
  );
});

test("background exports content-free diagnostics through the native host", async () => {
  const original = globalThis.chrome;
  let receive;
  const stored = { enabled: true };
  const nativeCalls = [];
  globalThis.chrome = {
    storage: {
      local: {
        async get() {
          return stored;
        },
        async set(values) {
          Object.assign(stored, values);
        },
      },
    },
    runtime: {
      getManifest() {
        return { version: "0.2.0" };
      },
      onMessage: {
        addListener(callback) {
          receive = callback;
        },
      },
      async sendNativeMessage(host, body) {
        nativeCalls.push({ host, body });
        return { status: "ready" };
      },
    },
    action: { async setBadgeText() {} },
  };
  try {
    await import("./background.js");
    const send = (body, from = sender) =>
      new Promise((resolve) => receive(body, from, resolve));
    const report = {
      operation: "capture_status",
      status: "identity_not_verified",
      account_email: null,
    };
    assert.deepEqual(await send(report), { status: "ready" });
    assert.equal(stored.pageStatus, "identity_not_verified");
    assert.equal(nativeCalls.length, 1);
    assert.deepEqual(nativeCalls[0].body, {
      operation: "diagnostic",
      provider: "chatgpt_web",
      page_key: nativeCalls[0].body.page_key,
      status: "identity_not_verified",
      account_email: null,
      extension_version: "0.2.0",
    });
    assert.match(nativeCalls[0].body.page_key, /^[0-9a-f]{64}$/);
    assert.ok(!JSON.stringify(nativeCalls).includes(url));
    assert.deepEqual(await send({ ...report, text: "private" }), {
      status: "invalid_source",
    });
    assert.deepEqual(await send(report, { ...sender, frameId: 1 }), {
      status: "invalid_source",
    });
    assert.equal(nativeCalls.length, 1);
    await send({ operation: "status" });
    assert.deepEqual(nativeCalls.slice(1), [
      {
        host: "com.cross_agent_memory.capture",
        body: { operation: "status" },
      },
    ]);
    stored.enabled = false;
    assert.deepEqual(await send({ ...report, status: "capture_failed" }), {
      status: "disabled",
    });
    assert.equal(stored.pageStatus, "identity_not_verified");
  } finally {
    if (original === undefined) delete globalThis.chrome;
    else globalThis.chrome = original;
  }
});

test("account authorization precedes observation and cannot carry transcript text", () => {
  const authorize = {
    operation: "authorize",
    provider: "chatgpt_web",
    account_email: "owner@example.test",
  };
  assert.equal(validateSender(authorize, sender), true);
  assert.equal(
    validateSender({ ...authorize, text: "private" }, sender),
    false,
  );
  assert.equal(
    validateSender({ ...authorize, provider: "grok_web" }, sender),
    false,
  );
});

test("native replies are allowlisted and never echo private values", () => {
  assert.deepEqual(classifyReply({ status: "queued", token: "private" }), {
    status: "queued",
  });
  assert.deepEqual(classifyReply({ status: "ingested" }), {
    status: "invalid_collector_response",
  });
  assert.deepEqual(classifyReply("private error"), {
    status: "invalid_collector_response",
  });
});

const grokCanonical = "https://grok.com/c/12345678-1234-1234-1234-123456789abc";
const rid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const grokMessage = {
  operation: "observe",
  account_email: "grok@example.test",
  observation: { provider: "grok_web", canonical_url: grokCanonical },
};
const grokSender = {
  ...sender,
  origin: "https://grok.com",
  url: grokCanonical,
};

test("single UUID Grok rid preserves the query-free canonical observation URL", () => {
  const withRid = { ...grokSender, url: `${grokCanonical}?rid=${rid}` };
  assert.equal(validateSender(grokMessage, withRid), true);
  assert.equal(validateSender({ operation: "status" }, withRid), true);
  assert.equal(
    validateSender(
      {
        ...grokMessage,
        observation: { ...grokMessage.observation, canonical_url: withRid.url },
      },
      withRid,
    ),
    false,
  );
});

for (const suffix of [
  `?rid=${rid}&rid=${rid}`,
  `?rid=${rid}&rid=12345678-1234-1234-1234-123456789abc`,
  `?rid=${rid}&unknown=1`,
  "?unknown=1",
  "?rid=",
  "?rid=not-a-uuid",
  `?rid=${rid}#fragment`,
  "#fragment",
]) {
  test(`Grok rejects ambiguous or unsupported URL suffix ${suffix}`, () => {
    const invalidSender = { ...grokSender, url: grokCanonical + suffix };
    assert.equal(validateSender(grokMessage, invalidSender), false);
    assert.equal(validateSender({ operation: "flush" }, invalidSender), false);
  });
}

test("Grok rid exception does not extend to ChatGPT or Claude", () => {
  for (const [origin, provider, path] of [
    ["https://chatgpt.com", "chatgpt_web", "c"],
    ["https://claude.ai", "claude_web", "chat"],
  ]) {
    const canonical = `${origin}/${path}/12345678-1234-1234-1234-123456789abc`;
    assert.equal(
      validateSender(
        {
          ...message,
          observation: { provider, canonical_url: canonical },
        },
        { ...sender, origin, url: `${canonical}?rid=${rid}` },
      ),
      false,
    );
  }
});
