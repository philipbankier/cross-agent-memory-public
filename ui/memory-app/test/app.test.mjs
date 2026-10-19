import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import { build } from "esbuild";

let browser, server, origin;
before(async () => {
  const app = await readFile(
    new URL(
      "../../../src/cross_assistant_memory/static/memory-app.html",
      import.meta.url,
    ),
  );
  const host = await build({
    entryPoints: [new URL("host.ts", import.meta.url).pathname],
    bundle: true,
    write: false,
    format: "esm",
    target: "es2022",
  });
  server = createServer((req, res) => {
    res.setHeader("cache-control", "no-store");
    if (req.url === "/app.html") {
      res.setHeader("content-type", "text/html");
      res.end(app);
    } else if (req.url === "/host.js") {
      res.setHeader("content-type", "text/javascript");
      res.end(host.outputFiles[0].text);
    } else {
      res.setHeader("content-type", "text/html");
      res.end(
        '<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><script type="module" src="/host.js"></script>',
      );
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch(
    process.platform === "darwin"
      ? { channel: "chrome", headless: true }
      : { headless: true },
  );
});
after(async () => {
  await browser?.close();
  await new Promise((resolve) => (server ? server.close(resolve) : resolve()));
});

async function open(
  t,
  scenario = "normal",
  viewport = { width: 1100, height: 800 },
) {
  const context = await browser.newContext({ viewport });
  t.after(() => context.close());
  const page = await context.newPage();
  const unexpected = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(origin)) unexpected.push(request.url());
  });
  t.after(() => assert.deepEqual(unexpected, []));
  await page.goto(`${origin}/?scenario=${scenario}`);
  const frame = page.frameLocator("iframe");
  await frame.locator("#search-button:enabled").waitFor();
  return { page, frame };
}
async function search(frame) {
  await frame.locator("#query").fill("synthetic");
  await frame.locator("#search-button").click();
  await frame.locator("#search-button:enabled").waitFor();
}
async function evidence(frame) {
  await search(frame);
  await frame.locator("#results button").first().click();
  await frame.locator("#search-button:enabled").waitFor();
}

test("opening status is displayed without a second server request", async (t) => {
  const { page, frame } = await open(t, "initial-only");
  await frame
    .locator("#coverage dt")
    .waitFor({ state: "attached", timeout: 2000 });
  assert.match(await frame.locator("#coverage").textContent(), /claude_code/);
  assert.equal(await frame.locator("#notice").textContent(), "");
  assert.deepEqual(await page.evaluate(() => window.calls), []);
  await frame.locator("summary").click();
  await frame.locator("#refresh").click();
  await frame.locator("#search-button:enabled").waitFor();
  assert.equal((await page.evaluate(() => window.calls)).length, 1);
  assert.match(await frame.locator("#notice").textContent(), /Retry/);
  assert.doesNotMatch(
    await frame.locator("body").innerText(),
    /PRIVATE_ERROR_SENTINEL/,
  );
});

test("missing or delayed opening status never starts a request", async (t) => {
  for (const scenario of ["initial-missing", "initial-delayed"]) {
    const { page, frame } = await open(t, scenario);
    await frame.locator("#notice").filter({ hasText: /^$/ }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.calls), []);
    assert.equal(await frame.locator("#coverage dt").count(), 0);
    if (scenario === "initial-delayed") {
      await page.evaluate(() => window.releaseOpeningResult());
      await frame.locator("#coverage dt").waitFor({ state: "attached" });
    } else {
      await frame.locator("summary").click();
      await frame.locator("#refresh").click();
      await frame.locator("#coverage dt").waitFor({ state: "attached" });
    }
    assert.match(await frame.locator("#coverage").textContent(), /claude_code/);
    assert.equal(
      (await page.evaluate(() => window.calls)).length,
      scenario === "initial-missing" ? 1 : 0,
    );
  }
});

test("invalid opening status is text-free and manually recoverable", async (t) => {
  for (const scenario of ["initial-error", "initial-malformed"]) {
    const { page, frame } = await open(t, scenario);
    await frame.locator("#notice").filter({ hasText: /Retry/ }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.calls), []);
    assert.equal(await frame.locator("#coverage dt").count(), 0);
    assert.doesNotMatch(
      await frame.locator("body").innerText(),
      /PRIVATE_ERROR_SENTINEL/,
    );
    await frame.locator("summary").click();
    await frame.locator("#refresh").click();
    await frame.locator("#coverage dt").waitFor({ state: "attached" });
  }
});

for (const width of [1100, 375])
  test(`search, evidence and deliberate context at ${width}px`, async (t) => {
    const { page, frame } = await open(t, "normal", { width, height: 900 });
    await evidence(frame);
    assert.match(
      await frame.locator("#text").innerText(),
      /proposal, not approval/,
    );
    assert.match(
      await frame.locator("#provenance").innerText(),
      /claude_code \/ assistant \/ assistant_proposal/,
    );
    assert.equal(await frame.locator("#results img").count(), 0);
    assert.deepEqual(await page.evaluate(() => window.contexts), []);
    await frame.locator("#select").click();
    await frame.locator("#select:enabled").waitFor();
    const contexts = await page.evaluate(() => window.contexts);
    assert.equal(contexts.length, 1);
    const selected = JSON.parse(contexts[0].content[0].text);
    assert.equal(selected.authority, "assistant_proposal");
    assert.equal(selected.scope, "project");
    assert.equal(selected.project_id, "synthetic-project");
    assert.deepEqual(selected.contexts, [
      {
        context_id: `context:${"c".repeat(64)}`,
        kind: "project",
        key: "synthetic-project",
        label: "Synthetic project",
        assignment_kind: "legacy_project_id",
      },
      {
        context_id: `context:${"d".repeat(64)}`,
        kind: "topic",
        key: "discussion",
        label: "Synthetic topic",
        assignment_kind: "manual",
      },
    ]);
    assert.match(selected.purpose, /not instructions/);
    assert.equal(selected.raw_record_access, "withheld_attachment");
    const bytes = Buffer.byteLength(selected.content_text, "utf8");
    assert.deepEqual(selected.content_text_delivery, {
      offset_bytes: 0,
      returned_bytes: bytes,
      total_bytes: bytes,
      complete: true,
    });
    assert.equal(
      await frame
        .locator("body")
        .evaluate((body) => body.scrollWidth <= innerWidth),
      true,
    );
    await frame.locator("#clear").click();
    await frame.locator("#clear:enabled").waitFor();
    assert.deepEqual(
      (await page.evaluate(() => window.contexts)).at(-1).content,
      [],
    );
    assert.match(
      await frame.locator("#selection").innerText(),
      /does not erase/,
    );
    assert.equal(
      await frame
        .locator("body")
        .evaluate((body) => body.scrollWidth <= innerWidth),
      true,
    );
    assert.ok((await frame.locator("#results").boundingBox()).y < 300);
    await frame.locator("summary").click();
    assert.match(await frame.locator("#coverage").innerText(), /claude_code/);
    await page.screenshot({
      path: join(tmpdir(), `cam-memory-app-${width}.png`),
      fullPage: true,
    });
  });

test("empty search has recovery and no model context", async (t) => {
  const { frame, page } = await open(t, "empty");
  await search(frame);
  assert.match(await frame.locator("#results").innerText(), /No matching/);
  await frame.locator("#reset").click();
  assert.equal(await frame.locator("#query").inputValue(), "");
  assert.deepEqual(await page.evaluate(() => window.contexts), []);
});

test("selected scope preserves unknown versus explicitly unassigned contexts", async (t) => {
  for (const scenario of ["missing-scope", "unassigned-contexts"]) {
    const { frame, page } = await open(t, scenario);
    await evidence(frame);
    await frame.locator("#select").click();
    await frame.locator("#select:enabled").waitFor();
    const selected = JSON.parse(
      (await page.evaluate(() => window.contexts))[0].content[0].text,
    );
    assert.equal(
      selected.scope,
      scenario === "missing-scope" ? null : "user_global",
    );
    assert.equal(selected.project_id, null);
    assert.deepEqual(
      selected.contexts,
      scenario === "missing-scope" ? null : [],
    );
  }
});
test("search continuation keeps the original query and response binding", async (t) => {
  const { frame, page } = await open(t, "search-paging");
  await search(frame);
  assert.equal(await frame.locator("#more-results").count(), 1);
  await frame.locator("#query").fill("unsent edited query");
  await frame.locator("#more-results").click();
  await frame.locator("#search-button:enabled").waitFor();
  assert.deepEqual((await page.evaluate(() => window.calls)).at(-1).arguments, {
    query: "synthetic",
    limit: 10,
    page: { result_offset: 1, expected_search_sha256: "b".repeat(64) },
  });
  assert.equal(await frame.locator("#more-results").isVisible(), false);
  assert.match(await frame.locator("#results-state").innerText(), /2-2 of 2/);
});
for (const field of ["version", "unit", "count", "next"])
  for (const continued of [false, true])
    test(`search refuses invalid ${field} on ${continued ? "continued" : "first"} pages`, async (t) => {
      const { frame, page } = await open(
        t,
        `search-contract-${field}${continued ? "-continued" : ""}`,
      );
      await search(frame);
      if (continued) {
        assert.equal(await frame.locator("#results button").count(), 1);
        await frame.locator("#more-results").click();
        await frame.locator("#search-button:enabled").waitFor();
      }
      assert.equal(await frame.locator("#results button").count(), 0);
      assert.equal(await frame.locator("#select").isDisabled(), true);
      assert.match(await frame.locator("#notice").innerText(), /Retry/);
      assert.deepEqual(await page.evaluate(() => window.contexts), []);
    });
test("status-only permissions and unsupported host are honest", async (t) => {
  const first = await open(t, "status-only");
  assert.match(
    await first.frame.locator("#coverage-state").textContent(),
    /permissions/,
  );
  const second = await open(t, "unsupported");
  await evidence(second.frame);
  assert.equal(await second.frame.locator("#select").isDisabled(), true);
  assert.match(
    await second.frame.locator("#selection").innerText(),
    /unavailable/,
  );
});
test("unpaged UTF-8 evidence marks only normalized text complete", async (t) => {
  const { page, frame } = await open(t, "utf8-evidence");
  await evidence(frame);
  await frame.locator("#select").click();
  await frame.locator("#select:enabled").waitFor();
  const selected = JSON.parse(
    (await page.evaluate(() => window.contexts))[0].content[0].text,
  );
  assert.equal(selected.content_text, "Synthetic caf\u00e9");
  assert.deepEqual(selected.content_text_delivery, {
    offset_bytes: 0,
    returned_bytes: 15,
    total_bytes: 15,
    complete: true,
  });
  assert.equal(selected.evidence_page, null);
  assert.equal(selected.raw_record_access, "withheld_attachment");
});
test("evidence continuation retains its binding and only sends the displayed page", async (t) => {
  const { page, frame } = await open(t, "paging");
  await evidence(frame);
  await frame.locator("#select").click();
  await frame.locator("#select:enabled").waitFor();
  const first = JSON.parse(
    (await page.evaluate(() => window.contexts))[0].content[0].text,
  );
  assert.equal(first.content_text, "first");
  assert.equal(first.scope, "project");
  assert.equal(first.project_id, "synthetic-project");
  assert.deepEqual(first.content_text_delivery, {
    offset_bytes: 0,
    returned_bytes: 5,
    total_bytes: 11,
    complete: false,
  });
  await frame.locator("#next").click();
  await frame.locator("#select:enabled").waitFor();
  assert.equal(await frame.locator("#text").innerText(), "second");
  assert.equal(await frame.locator("#next").isVisible(), false);
  const calls = await page.evaluate(() => window.calls);
  assert.deepEqual(calls.at(-1).arguments.page, {
    content_offset: 5,
    expected_evidence_sha256: "b".repeat(64),
  });
  await frame.locator("#select").click();
  await frame.locator("#select:enabled").waitFor();
  const selected = JSON.parse(
    (await page.evaluate(() => window.contexts)).at(-1).content[0].text,
  );
  assert.equal(selected.content_text, "second");
  assert.equal(selected.scope, first.scope);
  assert.equal(selected.project_id, first.project_id);
  assert.deepEqual(selected.contexts, first.contexts);
  assert.equal(selected.evidence_page.fields.content_text.offset_bytes, 5);
  assert.deepEqual(selected.content_text_delivery, {
    offset_bytes: 5,
    returned_bytes: 6,
    total_bytes: 11,
    complete: false,
  });
});
test("failed pages clear stale evidence without leaking error text", async (t) => {
  const { frame } = await open(t, "page-failure");
  await evidence(frame);
  await frame.locator("#next").click();
  await frame.locator("#search-button:enabled").waitFor();
  assert.equal(await frame.locator("#select").isDisabled(), true);
  assert.equal(await frame.locator("#text").innerText(), "");
  assert.doesNotMatch(
    await frame.locator("body").innerText(),
    /PRIVATE_ERROR_SENTINEL/,
  );
});
for (const mismatch of ["digest", "offset", "missing"])
  test(`evidence continuation refuses a ${mismatch} binding mismatch`, async (t) => {
    const { frame, page } = await open(t, `page-binding-${mismatch}`);
    await evidence(frame);
    await frame.locator("#next").click();
    await frame.locator("#search-button:enabled").waitFor();
    assert.equal(await frame.locator("#select").isDisabled(), true);
    assert.equal(await frame.locator("#text").innerText(), "");
    assert.deepEqual(await page.evaluate(() => window.contexts), []);
  });
test("malformed results and page boundaries fail without partial display", async (t) => {
  const badSearch = await open(t, "malformed");
  await search(badSearch.frame);
  assert.equal(await badSearch.frame.locator("#results button").count(), 0);
  const badPage = await open(t, "invalid-page");
  await evidence(badPage.frame);
  assert.equal(await badPage.frame.locator("#select").isDisabled(), true);
});
test("oversize and refused context never claim selection", async (t) => {
  for (const scenario of [
    "oversized",
    "metadata-oversized",
    "context-refused",
  ]) {
    const { frame, page } = await open(t, scenario);
    await evidence(frame);
    await frame.locator("#select").click();
    await frame.locator("#select:enabled").waitFor();
    assert.deepEqual(await page.evaluate(() => window.contexts), []);
    assert.doesNotMatch(
      await frame.locator("#selection").innerText(),
      /Sent to this assistant/,
    );
    if (scenario === "metadata-oversized") {
      assert.match(
        await frame.locator("#notice").innerText(),
        /text and metadata.*64 KiB.*read the evidence ID directly/,
      );
      assert.doesNotMatch(
        await frame.locator("#notice").innerText(),
        /smaller delivery limit/,
      );
    }
    assert.notEqual(await frame.locator("#notice").innerText(), "");
  }
});
test("unavailable server remains retryable and text-free", async (t) => {
  const { frame } = await open(t, "outage");
  await search(frame);
  assert.match(await frame.locator("#notice").innerText(), /Retry/);
  assert.doesNotMatch(
    await frame.locator("body").innerText(),
    /PRIVATE_ERROR_SENTINEL/,
  );
});
test("tool timeout releases the interface", async (t) => {
  const { page, frame } = await open(t, "timeout");
  await page.clock.install();
  await frame.locator("#query").fill("synthetic");
  await frame.locator("#search-button").click();
  await page.clock.fastForward(46000);
  await frame.locator("#search-button:enabled").waitFor();
  assert.match(await frame.locator("#notice").innerText(), /Retry/);
});
test("tool progress cannot extend the deadline and late results stay cleared", async (t) => {
  const { page, frame } = await open(t, "progress-timeout");
  await page.clock.install();
  await frame.locator("#query").fill("synthetic");
  await frame.locator("#search-button").click();
  await page.waitForFunction(
    () => typeof window.sendSearchProgress === "function",
  );
  await page.clock.fastForward(30000);
  await page.evaluate(() => window.sendSearchProgress());
  await page.clock.fastForward(16000);
  await frame.locator("#search-button:enabled").waitFor({ timeout: 2000 });
  await page.waitForFunction(() => window.searchCancelled, undefined, {
    timeout: 2000,
  });
  assert.match(await frame.locator("#notice").innerText(), /Retry/);
  assert.equal(await frame.locator("#results button").count(), 0);
  assert.equal((await page.evaluate(() => window.calls)).length, 1);
  await page.evaluate(() => window.releaseSearch());
  assert.equal(await frame.locator("#results button").count(), 0);
  assert.deepEqual(await page.evaluate(() => window.contexts), []);
  await search(frame);
  assert.equal(await frame.locator("#results button").count(), 1);
  assert.equal((await page.evaluate(() => window.calls)).length, 2);
});
