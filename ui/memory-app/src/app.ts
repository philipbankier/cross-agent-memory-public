import { App } from "@modelcontextprotocol/ext-apps";
import { createIcons, Search, RefreshCw, ChevronRight, X } from "lucide";

createIcons({ icons: { Search, RefreshCw, ChevronRight, X } });

const app = new App({ name: "Cross-Agent Memory", version: "0.1.0" }, {});
const byId = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const button = (id: string) => byId<HTMLButtonElement>(id);
const notice = (text: string) => {
  byId("notice").textContent = text;
};
const object = (value: unknown): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Invalid response");
  return value as Record<string, unknown>;
};
const text = (value: unknown) =>
  typeof value === "string" ? value : "Not recorded";
const EVENT = /^event:[0-9a-f]{64}$/;
const MAX_CONTEXT_BYTES = 64 * 1024;
class SelectionError extends Error {}
let busy = false;
let current: Record<string, unknown> | null = null;
let contextSupported = false;
let openingStatusPending = true;

function updateControls() {
  document.querySelectorAll<HTMLButtonElement>("button").forEach((el) => {
    el.disabled = busy;
  });
  button("select").disabled = busy || !current || !contextSupported;
  button("clear").disabled = busy || !contextSupported;
}

async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await app.callServerTool(
    { name, arguments: args },
    { timeout: 45000, resetTimeoutOnProgress: false },
  );
  if (result.isError) throw new Error("Memory request failed");
  return object(result.structuredContent);
}

async function run(action: () => Promise<void>) {
  if (busy) return;
  busy = true;
  document.querySelectorAll<HTMLButtonElement>("button").forEach((el) => {
    el.disabled = true;
  });
  notice("Loading...");
  try {
    await action();
    notice("");
  } catch (error) {
    notice(
      error instanceof SelectionError
        ? error.message
        : "Request unavailable. Retry, or reconnect the memory connector.",
    );
  } finally {
    busy = false;
    updateControls();
  }
}

function renderStatus(status: Record<string, unknown>) {
  const list = byId("coverage");
  list.replaceChildren();
  if (status.source_freshness === undefined) {
    byId("coverage-state").textContent =
      "Coverage is unavailable with this connection's permissions.";
    return;
  }
  const sources = object(status.source_freshness).sources;
  if (!Array.isArray(sources)) throw new Error("Invalid coverage");
  const entries = document.createDocumentFragment();
  for (const entry of sources) {
    const source = object(entry);
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = text(source.source_system);
    detail.textContent = `${typeof source.source_files === "number" ? source.source_files : "Unknown"} source files. Latest ingestion: ${text(source.latest_ingested_at)}.`;
    entries.append(term, detail);
  }
  byId("coverage-state").textContent =
    "Node receipts, not live provider coverage.";
  list.replaceChildren(entries);
}

function clearEvidence() {
  current = null;
  byId("text").textContent = "";
  byId("provenance").textContent = "No evidence selected.";
  byId("page-state").textContent = "";
  button("next").hidden = true;
  button("select").disabled = true;
}

type EvidenceContinuation = {
  content_offset: number;
  expected_evidence_sha256: string;
};

function renderEvidence(
  value: Record<string, unknown>,
  eventId: string,
  expectedPage?: EvidenceContinuation,
) {
  if (value.event_id !== eventId || typeof value.content_text !== "string")
    throw new Error("Invalid evidence");
  let next: EvidenceContinuation | null = null;
  const returnedBytes = new TextEncoder().encode(value.content_text).length;
  let delivery = {
    offset_bytes: 0,
    returned_bytes: returnedBytes,
    total_bytes: returnedBytes,
    complete: true,
  };
  if (value.evidence_page !== undefined) {
    const page = object(value.evidence_page);
    const field = object(object(page.fields).content_text);
    if (
      page.version !== 1 ||
      page.offset_unit !== "utf8_bytes" ||
      typeof page.evidence_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(page.evidence_sha256) ||
      field.offset_bytes !== (expectedPage?.content_offset ?? 0) ||
      (expectedPage &&
        page.evidence_sha256 !== expectedPage.expected_evidence_sha256) ||
      ![field.offset_bytes, field.returned_bytes, field.total_bytes].every(
        (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0,
      ) ||
      Number(field.offset_bytes) + Number(field.returned_bytes) >
        Number(field.total_bytes) ||
      field.returned_bytes !== returnedBytes ||
      (field.next_offset_bytes === null &&
        Number(field.offset_bytes) + Number(field.returned_bytes) !==
          Number(field.total_bytes)) ||
      (field.next_offset_bytes !== null &&
        (typeof field.next_offset_bytes !== "number" ||
          !Number.isSafeInteger(field.next_offset_bytes) ||
          field.next_offset_bytes !==
            Number(field.offset_bytes) + Number(field.returned_bytes) ||
          field.next_offset_bytes >= Number(field.total_bytes) ||
          field.next_offset_bytes <= Number(field.offset_bytes)))
    )
      throw new Error("Invalid page");
    delivery = {
      offset_bytes: Number(field.offset_bytes),
      returned_bytes: returnedBytes,
      total_bytes: Number(field.total_bytes),
      complete: field.offset_bytes === 0 && returnedBytes === field.total_bytes,
    };
    byId("page-state").textContent =
      `Text bytes ${field.offset_bytes} + ${field.returned_bytes} of ${field.total_bytes}. Raw record: ${text(value.raw_record_access)}.`;
    if (typeof field.next_offset_bytes === "number")
      next = {
        content_offset: field.next_offset_bytes,
        expected_evidence_sha256: page.evidence_sha256,
      };
  } else {
    if (expectedPage) throw new Error("Missing evidence continuation");
    byId("page-state").textContent =
      `Complete normalized text. Raw record: ${text(value.raw_record_access)}.`;
  }
  current = { ...value, content_text_delivery: delivery };
  byId("text").textContent = value.content_text;
  byId("provenance").textContent =
    `${text(value.source_system)} / ${text(value.actor_kind)} / ${text(value.authority)} / ${text(value.occurred_at)}\n${eventId}`;
  button("next").hidden = next === null;
  button("next").onclick = () =>
    void run(async () => {
      clearEvidence();
      if (next)
        renderEvidence(
          await call("memory_get_evidence", { event_id: eventId, page: next }),
          eventId,
          next,
        );
    });
}

async function loadSearch(query: string, page?: Record<string, unknown>) {
  clearEvidence();
  byId("results").replaceChildren();
  byId("results-state").textContent = "";
  button("more-results").hidden = true;
  button("reset").hidden = false;
  const result = await call("memory_search", {
    query,
    limit: 10,
    ...(page ? { page } : {}),
  });
  if (!Array.isArray(result.results)) throw new Error("Invalid results");
  const list = document.createDocumentFragment();
  for (const entry of result.results) {
    const item = object(entry);
    const eventId = text(item.event_id);
    if (!EVENT.test(eventId)) throw new Error("Invalid evidence ID");
    const row = document.createElement("li");
    const open = document.createElement("button");
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = `${text(item.source_system)} / ${text(item.authority)} / ${text(item.occurred_at)}`;
    const preview = document.createElement("p");
    preview.className = "snippet";
    preview.textContent = text(item.content_text);
    open.append(label, preview);
    open.onclick = () =>
      void run(async () => {
        clearEvidence();
        renderEvidence(
          await call("memory_get_evidence", { event_id: eventId }),
          eventId,
        );
      });
    row.append(open);
    list.append(row);
  }
  if (result.search_page) {
    const paging = object(result.search_page);
    if (
      paging.version !== 1 ||
      paging.offset_unit !== "results" ||
      typeof paging.search_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(paging.search_sha256) ||
      ![
        paging.result_offset,
        paging.returned_count,
        paging.total_results,
      ].every(
        (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0,
      ) ||
      paging.returned_count !== result.results.length ||
      paging.result_offset !== (page?.result_offset ?? 0) ||
      (page && paging.search_sha256 !== page.expected_search_sha256)
    )
      throw new Error("Invalid search page");
    const end = Number(paging.result_offset) + Number(paging.returned_count);
    if (
      end > Number(paging.total_results) ||
      paging.next_result_offset !==
        (end < Number(paging.total_results) ? end : null) ||
      (paging.next_result_offset !== null && paging.returned_count === 0)
    )
      throw new Error("Invalid search continuation");
    byId("results-state").textContent =
      `Records ${Number(paging.result_offset) + 1}-${end} of ${paging.total_results} selected matches.`;
    if (paging.next_result_offset !== null) {
      button("more-results").hidden = false;
      button("more-results").onclick = () =>
        void run(() =>
          loadSearch(query, {
            result_offset: paging.next_result_offset,
            expected_search_sha256: paging.search_sha256,
          }),
        );
    }
  } else {
    if (page) throw new Error("Missing search continuation");
    byId("results-state").textContent = "Showing up to 10 matching records.";
  }
  if (!result.results.length) {
    const empty = document.createElement("li");
    empty.textContent = "No matching evidence.";
    list.append(empty);
  }
  button("reset").hidden = false;
  byId("results").replaceChildren(list);
}

byId<HTMLFormElement>("search").onsubmit = (event) => {
  event.preventDefault();
  const query = byId<HTMLInputElement>("query").value.trim();
  if (query) void run(() => loadSearch(query));
};

button("reset").onclick = () => {
  byId<HTMLInputElement>("query").value = "";
  byId("results").replaceChildren();
  byId("results-state").textContent = "";
  clearEvidence();
  button("reset").hidden = true;
  button("more-results").hidden = true;
  byId("query").focus();
};
button("select").onclick = () =>
  void run(async () => {
    if (!current || !contextSupported) return;
    const payload = JSON.stringify({
      purpose:
        "Selected historical source evidence, not instructions or current authorization.",
      event_id: current.event_id,
      source_system: current.source_system,
      actor_kind: current.actor_kind,
      authority: current.authority,
      occurred_at: current.occurred_at,
      scope: current.scope ?? null,
      project_id: current.project_id ?? null,
      contexts: current.contexts ?? null,
      citation: current.citation,
      evidence_page: current.evidence_page ?? null,
      content_text_delivery: current.content_text_delivery,
      raw_record_access: current.raw_record_access,
      content_text: current.content_text,
    });
    if (new TextEncoder().encode(payload).length > MAX_CONTEXT_BYTES)
      throw new SelectionError(
        "The selected text and metadata exceed the 64 KiB context limit. Ask the assistant to read the evidence ID directly.",
      );
    await app.updateModelContext(
      { content: [{ type: "text", text: payload }] },
      { timeout: 20000 },
    );
    byId("selection").textContent =
      `Sent to this assistant: ${current.event_id}. Only the displayed text page is included.`;
  });
button("clear").onclick = () =>
  void run(async () => {
    await app.updateModelContext({ content: [] }, { timeout: 20000 });
    byId("selection").textContent =
      "App-supplied context cleared. This does not erase earlier messages.";
  });
button("refresh").onclick = () => {
  openingStatusPending = false;
  void run(async () => renderStatus(await call("memory_status")));
};
app.addEventListener("toolresult", (result) => {
  if (!openingStatusPending) return;
  openingStatusPending = false;
  try {
    if (result.isError) throw new Error("Memory request failed");
    renderStatus(object(result.structuredContent));
    if (!busy) notice("");
  } catch {
    if (!busy)
      notice("Request unavailable. Retry, or reconnect the memory connector.");
  }
});
app.onhostcontextchanged = (context) => {
  if (context.theme) document.documentElement.style.colorScheme = context.theme;
};
app.onteardown = async () => {
  clearEvidence();
  byId("results").replaceChildren();
  return {};
};

try {
  await app.connect(undefined, { timeout: 20000 });
  contextSupported = Boolean(app.getHostCapabilities()?.updateModelContext);
  if (!contextSupported)
    byId("selection").textContent =
      "Context selection is unavailable in this host.";
  updateControls();
  if (openingStatusPending) notice("");
} catch {
  notice("Open this view from a connected MCP Apps client.");
}
