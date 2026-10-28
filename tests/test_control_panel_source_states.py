from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, cast

import pytest

from cross_assistant_memory.control_panel import _PANEL_JS  # pyright: ignore[reportPrivateUsage]

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node is required; enforced by the interfaces CI job"
)

HARNESS = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
function element() {
  return {
    children: [], elements: [], textContent: '', value: '', disabled: false, dataset: {},
    listeners: new Map(), classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, callback) { this.listeners.set(name, callback); },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = [...children]; },
    querySelectorAll() { return []; }, querySelector() { return element(); },
    setAttribute() {}, reset() {}, focus() {},
    showModal() { this.open = true; }, close() { this.open = false; }
  };
}
const elements = new Map();
const byId = (id) => {
  if (!elements.has(id)) elements.set(id, element());
  return elements.get(id);
};
const context = vm.createContext({
  document: {getElementById: byId, querySelectorAll: () => [], createElement: element},
  window: {setTimeout: () => 0, clearTimeout() {}}, Headers, AbortController, DOMException
});
const ending = '  lock();\n})();';
assert(input.script.includes(ending));
vm.runInContext(input.script.replace(ending,
  '  globalThis.renderOverview = renderOverview;\n' + ending), context);
context.renderOverview(input.payload);
process.stdout.write(JSON.stringify({
  total: byId('source-total').textContent,
  status: byId('system-state').textContent,
  rows: byId('source-grid').children.map((row) => ({
    texts: row.children[0].children.flatMap((child) => [
      child.textContent, ...child.children.map((nested) => nested.textContent)
    ]),
    status_class: row.children[1].className,
    title: row.title
  }))
}));
"""


def render_sources(payload: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"script": _PANEL_JS, "payload": payload}),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return cast(dict[str, Any], json.loads(result.stdout))


@pytest.mark.parametrize("sync_state", ["blocked", "action_required", "scheduled"])
def test_imported_web_history_is_distinct_from_export_refresh(sync_state: str) -> None:
    attention = sync_state != "scheduled"
    result = render_sources(
        {
            "status": "attention_required" if attention else "operational",
            "sources": [
                {
                    "source_system": "chatgpt_web",
                    "state": "available",
                    "latest_ingested_at": "2026-09-02T22:55:35+00:00",
                    "sync": {
                        "state": sync_state,
                        "status_source": "assisted_export_workflow",
                        "attention_required": attention,
                    },
                }
            ],
        }
    )
    assert result["rows"][0]["texts"] == [
        "ChatGPT",
        "Indexed history: available",
        "Imported 2026-09-02",
        f"Export refresh: {sync_state.replace('_', ' ')}",
    ]
    assert result["rows"][0]["status_class"] == (
        "source-status attention" if attention else "source-status available"
    )
    assert result["total"] == "1 of 1 available"
    assert result["status"] == ("Attention" if attention else "Operational")
    assert "Source freshness and collector liveness are unknown" in result["rows"][0]["title"]


@pytest.mark.parametrize(
    "state,sync_state,last_import",
    [
        ("available", "upload_observed", "2026-10-09T03:18:12+00:00"),
        ("available", "historical_only", "2026-09-02T22:55:35+00:00"),
        ("registered", "status_unavailable", None),
    ],
)
def test_native_history_does_not_promote_collection_to_freshness(
    state: str, sync_state: str, last_import: str | None
) -> None:
    result = render_sources(
        {
            "sources": [
                {
                    "source_system": "codex",
                    "state": state,
                    "latest_ingested_at": last_import,
                    "sync": {"state": sync_state, "status_source": "node_observation"},
                }
            ]
        }
    )
    assert result["rows"][0]["texts"] == [
        "Codex",
        f"Indexed history: {state}",
        f"Imported {last_import[:10]}" if last_import else "Not imported",
        f"Collection: {sync_state.replace('_', ' ')}",
    ]
    assert result["total"] == f"{int(state == 'available')} of 1 available"
