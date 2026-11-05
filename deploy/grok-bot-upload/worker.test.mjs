import assert from "node:assert/strict";
import { test } from "node:test";
import { handleUpload } from "./worker.mjs";

const account = "source_account:" + "0".repeat(64);
const envelope = {
  format_version: 2,
  batch_id: "batch:" + "0".repeat(64),
  source_system: "grok_bot",
  source_account_id: account,
  records: [{}],
};

function setup({
  status = 201,
  receipt = '{"status":"applied"}',
  responseHeaders = {},
} = {}) {
  const calls = [];
  const env = {
    PUBLIC_ORIGIN: "https://upload.example.com",
    PRIVATE_ORIGIN_URL: "http://127.0.0.1:28765",
    SOURCE_ACCOUNT_ID: account,
    PRIVATE_COLLECTOR_ORIGIN: {
      async fetch(request) {
        calls.push(request);
        return new Response(receipt, {
          status,
          headers: { "content-type": "application/json", ...responseHeaders },
        });
      },
    },
  };
  return { env, calls };
}

function request(body = JSON.stringify(envelope), options = {}) {
  return new Request("https://upload.example.com/upload/batches", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer synthetic-token",
    },
    body,
    ...options,
  });
}

test("forwards exact bytes and collector bearer only to the private writer", async () => {
  const { env, calls } = setup({
    responseHeaders: {
      "set-cookie": "never-forward",
      location: "https://other.invalid",
    },
  });
  const body = JSON.stringify(envelope);
  const response = await handleUpload(request(body), env);
  assert.equal(response.status, 201);
  assert.equal(await response.text(), '{"status":"applied"}');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:28765/upload/batches");
  assert.equal(calls[0].headers.get("authorization"), "Bearer synthetic-token");
  assert.equal(await calls[0].text(), body);
  assert.equal(calls[0].redirect, "manual");
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("location"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

for (const altered of [
  { ...envelope, source_system: "codex" },
  { ...envelope, source_account_id: "source_account:" + "1".repeat(64) },
  { ...envelope, format_version: true },
  { ...envelope, batch_id: "unbound" },
  { ...envelope, records: [] },
  { ...envelope, records: [{}, {}] },
])
  test("other sources/accounts and multi-record requests never reach the node", async () => {
    const { env, calls } = setup();
    assert.equal(
      (await handleUpload(request(JSON.stringify(altered)), env)).status,
      403,
    );
    assert.equal(calls.length, 0);
  });

for (const path of ["/mcp", "/", "/upload/batches?redirect=other", "/admin"])
  test(`refuses ${path}`, async () => {
    const { env, calls } = setup();
    const input = new Request(`https://upload.example.com${path}`, request());
    assert.equal((await handleUpload(input, env)).status, 404);
    assert.equal(calls.length, 0);
  });

for (const forbidden of [
  { cookie: "synthetic" },
  { origin: "https://upload.example.com" },
])
  test("browser sessions are refused", async () => {
    const { env, calls } = setup();
    const headers = new Headers(request().headers);
    for (const [key, value] of Object.entries(forbidden))
      headers.set(key, value);
    assert.equal(
      (await handleUpload(request(undefined, { headers }), env)).status,
      403,
    );
    assert.equal(calls.length, 0);
  });

test("bounded bodies, invalid JSON and missing credentials refuse without forwarding", async () => {
  for (const input of [
    request("x".repeat(256 * 1024 + 1)),
    request("not-json"),
    request(undefined, { headers: { "content-type": "application/json" } }),
  ]) {
    const { env, calls } = setup();
    assert.ok(
      [400, 401, 413].includes((await handleUpload(input, env)).status),
    );
    assert.equal(calls.length, 0);
  }
});

test("one bounded attachment reaches the same source-bound route unchanged", async () => {
  const { env, calls } = setup();
  const body = JSON.stringify({ ...envelope, format_version: 3, exclusions: [],
    native_attachments: [{byte_length: 1024 * 1024, data_base64: "A".repeat(1398104)}] });
  assert.equal((await handleUpload(request(body), env)).status, 201);
  assert.equal(await calls[0].text(), body);
});

test("ordinary references retain their previous body limit", async () => {
  const { env, calls } = setup();
  const body = JSON.stringify({ ...envelope, padding: "x".repeat(256 * 1024) });
  assert.equal((await handleUpload(request(body), env)).status, 413);
  assert.equal(calls.length, 0);
});

for (const attachments of [[], [{byte_length: true}], [{byte_length: -1}],
  [{byte_length: 1024 * 1024 + 1}], [{byte_length: 1}, {byte_length: 1}]])
  test("unbounded or ambiguous attachment envelopes never reach the node", async () => {
    const { env, calls } = setup();
    const body = JSON.stringify({...envelope, format_version: 3, native_attachments: attachments, exclusions: []});
    assert.equal((await handleUpload(request(body), env)).status, 403);
    assert.equal(calls.length, 0);
  });

test("missing configuration and unexpected private origin stay disabled", async () => {
  for (const change of [
    { SOURCE_ACCOUNT_ID: "unknown" },
    { PRIVATE_ORIGIN_URL: "https://other.invalid" },
    { PRIVATE_COLLECTOR_ORIGIN: undefined },
  ]) {
    const { env, calls } = setup();
    assert.equal(
      (await handleUpload(request(), { ...env, ...change })).status,
      503,
    );
    assert.equal(calls.length, 0);
  }
});

test("redirects, malformed or oversized receipts and provider errors are secret-free", async () => {
  for (const options of [
    { status: 302, receipt: "synthetic-secret" },
    { status: 401, receipt: "synthetic-secret" },
    { receipt: "x".repeat(64 * 1024 + 1) },
    {
      responseHeaders: { "content-type": "text/html" },
      receipt: "synthetic-secret",
    },
  ]) {
    const { env } = setup(options);
    const response = await handleUpload(request(), env);
    assert.ok([401, 502, 503].includes(response.status));
    assert.ok(!(await response.text()).includes("synthetic-secret"));
  }
});

for (const status of [200, 201, 202])
  test(`preserves receipt status ${status}`, async () => {
    const { env } = setup({ status });
    assert.equal((await handleUpload(request(), env)).status, status);
  });

test("preserves only exact batch-bound encrypted publication progress", async () => {
  const progress = {
    status: "publication_pending",
    batch_id: envelope.batch_id,
    completed_objects: 1,
  };
  const receipt = JSON.stringify(progress);
  const { env } = setup({ status: 503, receipt });
  const response = await handleUpload(request(), env);
  assert.equal(response.status, 503);
  assert.equal(await response.text(), receipt);

  for (const changed of [
    { ...progress, batch_id: "batch:" + "1".repeat(64) },
    { ...progress, completed_objects: true },
    { ...progress, completed_objects: -1 },
    { ...progress, completed_objects: 5 },
    { ...progress, extra: "synthetic-secret" },
    null,
  ]) {
    const { env } = setup({ status: 503, receipt: JSON.stringify(changed) });
    const refused = await handleUpload(request(), env);
    assert.equal(refused.status, 503);
    assert.deepEqual(await refused.json(), { error: "upload_rejected" });
  }
});

test("explicit alternative loopback collector ports remain portable", async () => {
  const { env, calls } = setup();
  env.PRIVATE_ORIGIN_URL = "http://127.0.0.1:47123";
  assert.equal((await handleUpload(request(), env)).status, 201);
  assert.equal(calls[0].url, "http://127.0.0.1:47123/upload/batches");
});

test("interrupted inbound stream is cancelled and never forwarded", async () => {
  const controller = new AbortController();
  let cancelled = false;
  const body = new ReadableStream({
    cancel() {
      cancelled = true;
    },
  });
  const input = request(body, { signal: controller.signal, duplex: "half" });
  const { env, calls } = setup();
  const pending = handleUpload(input, env);
  controller.abort();
  assert.equal((await pending).status, 400);
  assert.equal(calls.length, 0);
  assert.equal(cancelled, true);
});
