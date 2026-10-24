// Real extension/native-messaging test. All provider requests are fulfilled locally.
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "../../ui/memory-app/node_modules/playwright/index.mjs";

const [root, configPath, host, port] = process.argv.slice(2);
const extension = path.dirname(fileURLToPath(import.meta.url));
const profile = path.join(root, "profile");
const api = `http://127.0.0.1:${port}`;
const conversation = "11111111-2222-4333-8444-555555555555";
const message = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const specs = [
  ["chatgpt.com", "first@example.test"],
  ["chatgpt.com", "second@example.test"],
  ["claude.ai", "claude@example.test"],
  ["grok.com", "grok@example.test"],
];
let current = specs[0];
let context;
let extensionId;
const nativeErrors = [];

function fixture(domain, email) {
  const route = domain === "claude.ai" ? "chat" : "c";
  const trigger =
    domain === "chatgpt.com"
      ? 'aria-label="Open profile menu"'
      : domain === "claude.ai"
        ? 'data-testid="user-menu-button"'
        : 'aria-label="Account menu, fixture"';
  const text = `SYNTHETICCAPTURE ${email}`;
  const body =
    domain === "chatgpt.com"
      ? `<section data-talvt-turn-state="complete"><div data-chatgpt-search-message-ids="${message}" data-chatgpt-search-unit-key="turn:user">${text}</div></section>`
      : domain === "claude.ai"
        ? `<section data-testid="transcript-row" data-index="0"><div data-testid="user-message">${text}</div></section>`
        : `<section id="response-${message}"><div role="article"><h2 id="turn-heading-1">You</h2><div class="relative">${text}</div></div></section>`;
  return `<!doctype html><html><body><nav><a href="/${route}/${conversation}">Saved fixture</a><button aria-label="Create share link">Share</button></nav>
    <button id="profile" ${trigger} aria-controls="menu" aria-expanded="false">Account</button>${body}
    <script>
      const trigger=document.getElementById('profile');
      trigger.onclick=()=>{
        const open=trigger.getAttribute('aria-expanded')==='true';
        trigger.setAttribute('aria-expanded', String(!open));
        if(open){document.getElementById('menu')?.remove();document.getElementById('sub')?.remove();return;}
        const menu=document.createElement('div');menu.id='menu';menu.setAttribute('role','menu');menu.setAttribute('aria-labelledby','profile');
        if(location.hostname==='chatgpt.com'){
          const item=document.createElement('div');item.id='account';item.setAttribute('role','menuitem');item.setAttribute('aria-haspopup','menu');item.setAttribute('aria-controls','sub');item.textContent='Fixture Pro';
          item.onclick=()=>{if(document.getElementById('sub'))return;item.setAttribute('data-state','open');const sub=document.createElement('div');sub.id='sub';sub.setAttribute('role','menu');sub.setAttribute('aria-labelledby','account');sub.innerHTML='<div><div role="menuitem"><div data-menu-row-content="true"><div><span>Fixture</span><span>${email}</span></div><svg aria-hidden="true" width="16" height="16"><use href="/cdn/assets/icons-0123abcd.svg#codex-icon-checkmark-lg-light-16"></use></svg></div></div><div role="menuitem"><div data-menu-row-content="true"><div><span>Other account</span><span>inactive@example.test</span></div></div></div></div>';document.body.append(sub);};
          menu.append(item);
        }else{const identity=document.createElement('span');identity.textContent='${email}';menu.append(identity);}
        document.body.append(menu);
      };
    </script></body></html>`;
}

async function launch() {
  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${extension}`,
      `--load-extension=${extension}`,
    ],
  });
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (specs.some(([domain]) => url.hostname === domain))
      return route.fulfill({
        status: 200,
        contentType: "text/html",
        body: fixture(...current),
      });
    return route.abort();
  });
  const worker =
    context.serviceWorkers()[0] ||
    (await context.waitForEvent("serviceworker"));
  extensionId = new URL(worker.url()).hostname;
  const config = JSON.parse(await readFile(configPath, "utf8"));
  config.extension_origin = `chrome-extension://${extensionId}/`;
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const manifests = path.join(profile, "NativeMessagingHosts");
  await mkdir(manifests, { recursive: true, mode: 0o700 });
  await writeFile(
    path.join(manifests, "com.cross_agent_memory.capture.json"),
    JSON.stringify({
      name: "com.cross_agent_memory.capture",
      description: "Isolated capture qualification",
      path: host,
      type: "stdio",
      allowed_origins: [config.extension_origin],
    }),
    { mode: 0o600 },
  );
  const reply = await worker.evaluate(async () => {
    await chrome.storage.local.set({ enabled: true });
    return chrome.runtime.sendNativeMessage("com.cross_agent_memory.capture", {
      operation: "status",
    });
  });
  assert.equal(reply.status, "ready");
}

const state = async () => (await fetch(`${api}/state`)).json();
async function waitFor(check, label, timeout = 75000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    last = await state();
    if (check(last)) return last;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`${label}: ${JSON.stringify(last)}`);
}
async function openFixture(spec) {
  current = spec;
  const page = context.pages()[0] || (await context.newPage());
  page.on("pageerror", () => nativeErrors.push("fixture_page_error"));
  const [domain] = spec;
  await page.goto(
    `https://${domain}/${domain === "claude.ai" ? "chat" : "c"}/${conversation}`,
  );
  await page.bringToFront();
  return page;
}

try {
  await launch();
  for (let i = 0; i < specs.length; i++) {
    await openFixture(specs[i]);
    await waitFor(
      (s) => s.events === i + 1 && s.health.queue.queued_observations === 0,
      `capture account ${i}`,
    );
  }
  // An actual browser restart recreates content scripts and service workers.
  await context.close();
  context = null;
  await launch();
  await fetch(`${api}/offline`, { method: "POST" });
  for (let i = 0; i < specs.length; i++) {
    await openFixture(specs[i]);
    await waitFor(
      (s) => s.health.queue.queued_observations === i + 1,
      `offline replay account ${i}`,
    );
  }
  await context.close();
  context = null;
  const before = await state();
  const offline = spawnSync(host, ["--flush"], { encoding: "utf8" });
  assert.equal(offline.status, 1);
  const failed = JSON.parse(offline.stdout);
  assert.equal(failed.status, "upload_pending");
  assert.equal(
    failed.queue.queued_observations,
    before.health.queue.queued_observations,
  );
  await fetch(`${api}/online`, { method: "POST" });
  const recovered = JSON.parse(
    execFileSync(host, ["--flush"], { encoding: "utf8" }),
  );
  assert.equal(recovered.status, "uploaded");
  assert.equal(recovered.queue.queued_observations, 0);
  assert.equal((await state()).events, 4);
  assert.deepEqual(nativeErrors, []);
  console.log(
    JSON.stringify({
      captured_accounts: 4,
      browser_closed_recovery: true,
      replayed_without_duplicates: true,
    }),
  );
} finally {
  if (context) await context.close();
}
