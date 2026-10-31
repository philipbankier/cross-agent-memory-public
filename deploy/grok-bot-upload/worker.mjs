// @ts-check

/** @typedef {{fetch(request: Request): Promise<Response>}} PrivateOrigin */
/** @typedef {{PUBLIC_ORIGIN: string, PRIVATE_ORIGIN_URL: string, SOURCE_ACCOUNT_ID: string, PRIVATE_COLLECTOR_ORIGIN: PrivateOrigin}} UploadEnvironment */

const MAX_BODY_BYTES = 256 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;

/** @param {number} status @param {string} code */
function refuse(status, code) {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

/** @param {ReadableStream<Uint8Array> | null} stream @param {number} limit @param {AbortSignal} signal */
async function boundedBody(stream, limit, signal) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error("interrupted body");
      const { value, done } = await reader.read();
      if (signal.aborted) throw new Error("interrupted body");
      if (done) break;
      size += value.length;
      if (size > limit) {
        await reader.cancel();
        throw new RangeError("body limit");
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/** @param {Request} request @param {UploadEnvironment} env */
export async function handleUpload(request, env) {
  let publicOrigin;
  let privateOrigin;
  try {
    publicOrigin = new URL(env.PUBLIC_ORIGIN);
    privateOrigin = new URL(env.PRIVATE_ORIGIN_URL);
    if (
      publicOrigin.protocol !== "https:" ||
      publicOrigin.href !== `${publicOrigin.origin}/` ||
      privateOrigin.protocol !== "http:" ||
      privateOrigin.hostname !== "127.0.0.1" ||
      !privateOrigin.port ||
      Number(privateOrigin.port) < 1 ||
      privateOrigin.href !== `${privateOrigin.origin}/` ||
      !/^source_account:[0-9a-f]{64}$/.test(env.SOURCE_ACCOUNT_ID) ||
      typeof env.PRIVATE_COLLECTOR_ORIGIN?.fetch !== "function"
    )
      return refuse(503, "not_configured");
  } catch {
    return refuse(503, "not_configured");
  }
  const url = new URL(request.url);
  if (url.origin !== publicOrigin.origin) return refuse(421, "wrong_origin");
  if (url.pathname !== "/upload/batches" || url.search || url.hash)
    return refuse(404, "not_found");
  if (request.method !== "POST") return refuse(405, "method_not_allowed");
  if (request.headers.has("cookie") || request.headers.has("origin"))
    return refuse(403, "browser_request_refused");
  const authorization = request.headers.get("authorization");
  if (!authorization || !/^Bearer [A-Za-z0-9._~-]{1,4096}$/.test(authorization))
    return refuse(401, "not_authorized");
  if (request.headers.get("content-type") !== "application/json")
    return refuse(415, "json_required");

  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(35_000)]);
  let body;
  try {
    body = await boundedBody(request.body, MAX_BODY_BYTES, signal);
  } catch (error) {
    return refuse(error instanceof RangeError ? 413 : 400, "invalid_body");
  }
  let batchId;
  try {
    const envelope = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
    );
    if (
      envelope?.format_version !== 2 ||
      envelope.source_system !== "grok_bot" ||
      envelope.source_account_id !== env.SOURCE_ACCOUNT_ID ||
      !/^batch:[0-9a-f]{64}$/.test(envelope.batch_id) ||
      !Array.isArray(envelope.records) ||
      envelope.records.length !== 1
    )
      return refuse(403, "source_not_enrolled");
    batchId = envelope.batch_id;
  } catch {
    return refuse(400, "invalid_envelope");
  }

  try {
    // The node authenticates the collector and validates the unchanged full envelope.
    const response = await env.PRIVATE_COLLECTOR_ORIGIN.fetch(
      new Request(`${privateOrigin.origin}/upload/batches`, {
        method: "POST",
        headers: { authorization, "content-type": "application/json" },
        body,
        redirect: "manual",
        signal,
      }),
    );
    const receipt = await boundedBody(response.body, MAX_RECEIPT_BYTES, signal);
    const jsonReceipt =
      response.headers.get("content-type")?.split(";", 1)[0].trim() ===
      "application/json";
    let publicationPending = false;
    if (response.status === 503 && jsonReceipt) {
      try {
        const progress = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(receipt),
        );
        publicationPending =
          Object.keys(progress).sort().join(",") ===
            "batch_id,completed_objects,status" &&
          progress.status === "publication_pending" &&
          progress.batch_id === batchId &&
          Number.isInteger(progress.completed_objects) &&
          progress.completed_objects >= 0 &&
          progress.completed_objects <= 4;
      } catch {
        // A generic failure is never an acknowledgement or a progress receipt.
      }
    }
    if (![200, 201, 202].includes(response.status) && !publicationPending) {
      return refuse(
        [400, 401, 403, 409, 413, 422, 429].includes(response.status)
          ? response.status
          : 503,
        "upload_rejected",
      );
    }
    if (!jsonReceipt)
      return refuse(502, "invalid_receipt");
    return new Response(receipt, {
      status: response.status,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    });
  } catch {
    return refuse(503, "collector_unavailable");
  }
}

export default { fetch: handleUpload };
