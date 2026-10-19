import {
  AppBridge,
  PostMessageTransport,
} from "@modelcontextprotocol/ext-apps/app-bridge";

const scenario =
  new URLSearchParams(location.search).get("scenario") ?? "normal";
const eventId = `event:${"a".repeat(64)}`;
const digest = "b".repeat(64);
const calls: unknown[] = [];
const contexts: unknown[] = [];
Object.assign(window, { calls, contexts });
const result = (value: Record<string, unknown>) => ({
  content: [{ type: "text" as const, text: JSON.stringify(value) }],
  structuredContent: value,
});
const status = {
  source_freshness: {
    sources: [
      {
        source_system: "claude_code",
        source_files: 2,
        latest_ingested_at: "2026-09-30T00:00:00Z",
      },
    ],
  },
};
const evidence = {
  event_id: eventId,
  source_system: "claude_code",
  actor_kind: "assistant",
  authority: "assistant_proposal",
  occurred_at: "2026-09-29T12:00:00Z",
  scope: "project",
  project_id: "synthetic-project",
  contexts: [
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
  ],
  content_text: "Synthetic evidence. This is a proposal, not approval.",
  raw_record_access: "withheld_attachment",
};
const bridge = new AppBridge(
  null,
  { name: "Synthetic test host", version: "1" },
  {
    serverTools: {},
    ...(scenario === "unsupported" ? {} : { updateModelContext: {} }),
  },
);
bridge.oncalltool = async (params, extra) => {
  calls.push(params);
  if (params.name === "memory_status") {
    if (scenario === "initial-only")
      return {
        isError: true,
        content: [{ type: "text", text: "PRIVATE_ERROR_SENTINEL" }],
      };
    return result(scenario === "status-only" ? {} : status);
  }
  if (params.name === "memory_search") {
    if (
      scenario === "search-paging" ||
      scenario.startsWith("search-contract-")
    ) {
      const continued = params.arguments?.page !== undefined;
      const invalid = !scenario.endsWith("-continued") || continued;
      return result({
        results: [evidence],
        search_page: {
          version:
            invalid && scenario.startsWith("search-contract-version") ? 2 : 1,
          offset_unit:
            invalid && scenario.startsWith("search-contract-unit")
              ? "utf8_bytes"
              : "results",
          search_sha256: digest,
          result_offset: continued ? 1 : 0,
          returned_count:
            invalid && scenario.startsWith("search-contract-count") ? 2 : 1,
          total_results: 2,
          next_result_offset:
            invalid && scenario.startsWith("search-contract-next")
              ? 5
              : continued
                ? null
                : 1,
        },
      });
    }
    if (scenario === "progress-timeout" && calls.length === 1) {
      const progressToken = extra.mcpReq._meta?.progressToken;
      if (
        typeof progressToken !== "string" &&
        typeof progressToken !== "number"
      )
        throw new Error("Missing progress token");
      extra.mcpReq.signal.addEventListener("abort", () => {
        Object.assign(window, { searchCancelled: true });
      });
      return new Promise((resolve) => {
        Object.assign(window, {
          sendSearchProgress: () =>
            extra.mcpReq.notify({
              method: "notifications/progress",
              params: { progressToken, progress: 1, total: 2 },
            }),
          releaseSearch: () => resolve(result({ results: [evidence] })),
          searchCancelled: false,
        });
      });
    }
    if (scenario === "timeout") return new Promise(() => {});
    if (scenario === "outage")
      return {
        isError: true,
        content: [{ type: "text", text: "PRIVATE_ERROR_SENTINEL" }],
      };
    if (scenario === "empty") return result({ results: [] });
    if (scenario === "malformed")
      return result({ results: [evidence, { event_id: "not-an-event" }] });
    return result({
      results: [
        {
          ...evidence,
          content_text: "<img src=x onerror=alert(1)> Synthetic proposal",
        },
      ],
    });
  }
  if (params.name === "memory_get_evidence") {
    if (scenario === "missing-scope")
      return result({
        event_id: evidence.event_id,
        source_system: evidence.source_system,
        actor_kind: evidence.actor_kind,
        authority: evidence.authority,
        occurred_at: evidence.occurred_at,
        content_text: evidence.content_text,
        raw_record_access: evidence.raw_record_access,
      });
    if (scenario === "unassigned-contexts")
      return result({
        ...evidence,
        scope: "user_global",
        project_id: null,
        contexts: [],
      });
    if (scenario === "metadata-oversized")
      return result({
        ...evidence,
        contexts: [{ ...evidence.contexts[0], label: "x".repeat(70000) }],
      });
    if (scenario === "utf8-evidence")
      return result({ ...evidence, content_text: "Synthetic caf\u00e9" });
    if (scenario === "oversized")
      return result({ ...evidence, content_text: "x".repeat(70000) });
    if (
      scenario === "paging" ||
      scenario === "page-failure" ||
      scenario === "invalid-page" ||
      scenario.startsWith("page-binding-")
    ) {
      const continued = params.arguments?.page !== undefined;
      if (continued && scenario === "page-failure")
        return {
          isError: true,
          content: [{ type: "text", text: "PRIVATE_ERROR_SENTINEL" }],
        };
      if (continued && scenario === "page-binding-missing")
        return result(evidence);
      return result({
        ...evidence,
        content_text: continued ? "second" : "first",
        evidence_page: {
          version: 1,
          offset_unit: "utf8_bytes",
          evidence_sha256:
            continued && scenario === "page-binding-digest"
              ? "c".repeat(64)
              : digest,
          fields: {
            content_text: {
              offset_bytes:
                continued && scenario === "page-binding-offset"
                  ? 0
                  : continued
                    ? 5
                    : 0,
              returned_bytes: continued ? 6 : 5,
              total_bytes:
                continued && scenario === "page-binding-offset" ? 6 : 11,
              next_offset_bytes:
                scenario === "invalid-page" ? 500 : continued ? null : 5,
            },
          },
        },
      });
    }
    return result(evidence);
  }
  throw new Error("Unexpected tool");
};
bridge.onupdatemodelcontext = async (params) => {
  if (scenario === "context-refused") throw new Error("PRIVATE_ERROR_SENTINEL");
  contexts.push(params);
  return {};
};
bridge.oninitialized = async () => {
  await bridge.sendToolInput({ arguments: {} });
  if (scenario === "initial-missing") return;
  const openingResult =
    scenario === "initial-error"
      ? {
          isError: true,
          content: [{ type: "text" as const, text: "PRIVATE_ERROR_SENTINEL" }],
        }
      : scenario === "initial-malformed"
        ? result({
            source_freshness: {
              sources: [status.source_freshness.sources[0], null],
            },
          })
        : result(scenario === "status-only" ? {} : status);
  if (scenario === "initial-delayed") {
    Object.assign(window, {
      releaseOpeningResult: () => bridge.sendToolResult(openingResult),
    });
    return;
  }
  await bridge.sendToolResult(openingResult);
};
const frame = document.createElement("iframe");
frame.title = "Memory app";
frame.style.cssText = "width:100%;height:100vh;border:0;display:block";
document.body.style.margin = "0";
document.body.append(frame);
await bridge.connect(
  new PostMessageTransport(frame.contentWindow!, frame.contentWindow!),
);
frame.src = "/app.html";
