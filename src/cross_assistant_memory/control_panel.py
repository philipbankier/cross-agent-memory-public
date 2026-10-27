# ruff: noqa: E501

from __future__ import annotations

import errno
import json
import secrets
import socket
import sqlite3
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import TypeVar, cast

from starlette.applications import Starlette
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Send
from starlette.types import Scope as ASGIScope

from cross_assistant_memory.application import (
    ApplicationPrincipal,
    CorrectionPlanRequest,
    CreateDeviceEnrollmentRequest,
    DeletionPlanRequest,
    MemoryApplication,
    ProposeMemoryRequest,
    RegisterSourceAccountRequest,
    ReviewMemoryCandidateRequest,
    SearchMemoryRequest,
    pending_web_evidence_claim,
)
from cross_assistant_memory.config import Settings
from cross_assistant_memory.evidence_deletion import EncryptedEvidencePurger
from cross_assistant_memory.evidence_locations import EncryptedEvidenceReader
from cross_assistant_memory.models import (
    MAX_PROPOSAL_EVIDENCE_EVENTS,
    MAX_PROPOSAL_STATEMENT_BYTES,
    Authority,
    CandidateReviewOperation,
    CandidateReviewReason,
    Capability,
    ClientKind,
    ContextFilter,
    ContextKind,
    DeletionKind,
    MemoryType,
    Privacy,
    QueryMode,
    RetrievalControl,
    Scope,
    SourceSystem,
)
from cross_assistant_memory.publication_work import EvidencePublicationPolicy
from cross_assistant_memory.storage import Ledger

MAX_JSON_BODY_BYTES = 32 * 1024
MAX_QUERY_BYTES = 4096
MAX_EVENT_ID_BYTES = 256
MAX_STATEMENT_BYTES = MAX_PROPOSAL_STATEMENT_BYTES
MAX_EVIDENCE_EVENTS = MAX_PROPOSAL_EVIDENCE_EVENTS
MAX_CONTEXTS = 32
MAX_RESULTS = 20
MAX_CREDENTIAL_TTL_HOURS = 365 * 24
MAX_ENROLLMENT_TTL_MINUTES = 60
MAX_DEVICE_CREDENTIAL_TTL_DAYS = 365
EPHEMERAL_PORT_START = 49152
EPHEMERAL_PORT_COUNT = 65536 - EPHEMERAL_PORT_START
MAX_BIND_ATTEMPTS = 128

EnumItem = TypeVar("EnumItem", Scope, Authority)

_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "content-security-policy": (
        "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": (
        "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()"
    ),
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}

_PANEL_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cross-Agent Memory</title>
  <link rel="stylesheet" href="/assets/panel.css">
</head>
<body>
  <header class="topbar">
    <div>
      <p class="product">Cross-Agent Memory</p>
      <p id="generation" class="generation">Locked</p>
    </div>
    <div class="topbar-actions">
      <span id="system-state" class="state state-locked">Locked</span>
      <button id="lock-button" class="quiet-button" type="button" hidden>Lock</button>
    </div>
  </header>

  <main id="workspace" class="workspace" aria-busy="false">
    <section class="source-panel" aria-labelledby="sources-heading">
      <div class="section-heading">
        <h1 id="sources-heading">Sources</h1>
        <span id="source-total" class="count">0 available</span>
      </div>
      <div id="source-grid" class="source-grid" aria-live="polite"></div>
      <div class="export-band">
        <span>Web exports</span>
        <strong id="export-state">Locked</strong>
      </div>
    </section>

    <section class="work-panel" aria-label="Memory workspace">
      <nav class="tabs" role="tablist" aria-label="Workspace views">
        <button class="tab-button active" type="button" role="tab" aria-selected="true" aria-controls="search-view" data-tab="search">Search</button>
        <button class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="memory-view" data-tab="memory">Memory</button>
        <button class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="access-view" data-tab="access">Access</button>
        <button class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="operations-view" data-tab="operations">Operations</button>
      </nav>

      <section id="search-view" class="tab-view" role="tabpanel" data-tab-panel="search">
        <div class="section-heading">
          <div>
            <h2 id="retrieval-heading">Retrieval</h2>
            <p id="result-summary" class="muted">Unlock to search exact evidence.</p>
          </div>
        </div>

        <form id="search-form" class="search-form">
          <label class="query-field">
            <span>Question or evidence phrase</span>
            <textarea id="query" name="query" rows="2" maxlength="4096" disabled></textarea>
          </label>
          <div class="filters">
            <label>
              <span>Mode</span>
              <select id="mode" name="mode" disabled>
                <option value="find_evidence">Find evidence</option>
                <option value="what_is_current">Current state</option>
                <option value="how_did_it_change">Changes</option>
                <option value="where_did_i_leave_off">Where I left off</option>
                <option value="what_did_i_say">What I said</option>
                <option value="what_did_i_think">What I thought</option>
                <option value="open_threads">Open threads</option>
              </select>
            </label>
            <label>
              <span>Project context</span>
              <input id="project" name="project" type="text" maxlength="512" disabled>
            </label>
            <label>
              <span>Results</span>
              <select id="limit" name="limit" disabled>
                <option value="5">5</option>
                <option value="10">10</option>
                <option value="20">20</option>
              </select>
            </label>
            <button id="search-button" class="primary-button" type="submit" disabled>Search</button>
          </div>
          <fieldset id="scope-filters" class="scope-filters" disabled>
            <legend>Scope</legend>
            <label><input type="checkbox" value="user_global" checked> Global</label>
            <label><input type="checkbox" value="project" checked> Project</label>
            <label><input type="checkbox" value="assistant_private" checked> Assistant private</label>
            <label><input type="checkbox" value="session" checked> Session</label>
          </fieldset>
        </form>

        <div id="empty-state" class="empty-state">
          <span id="empty-message">No retrieval has run.</span>
          <button id="clear-search" class="quiet-button" type="button" hidden>Clear search</button>
        </div>
        <ol id="results" class="results" aria-live="polite"></ol>
      </section>

      <section id="memory-view" class="tab-view" role="tabpanel" data-tab-panel="memory" hidden>
        <section class="candidate-panel" aria-labelledby="candidate-heading">
          <div class="section-heading">
            <div>
              <h2 id="candidate-heading">New candidate</h2>
              <p id="candidate-state" class="muted">Inactive until reviewed.</p>
            </div>
          </div>
          <form id="candidate-form" class="candidate-form">
            <label class="candidate-statement">
              <span>Statement</span>
              <textarea id="candidate-statement" maxlength="16384" rows="2" disabled></textarea>
            </label>
            <div class="candidate-fields">
              <label>
                <span>Type</span>
                <select id="candidate-type" disabled>
                  <option value="claim">Claim</option>
                  <option value="preference">Preference</option>
                  <option value="decision">Decision</option>
                  <option value="task">Task</option>
                  <option value="procedure">Procedure</option>
                  <option value="artifact">Artifact</option>
                  <option value="episodic_event">Event</option>
                </select>
              </label>
              <label>
                <span>Scope</span>
                <select id="candidate-scope" disabled>
                  <option value="project" selected>Project</option>
                  <option value="user_global">Global</option>
                  <option value="assistant_private">Assistant private</option>
                  <option value="session">Session</option>
                </select>
              </label>
              <label id="candidate-project-field">
                <span>Project context</span>
                <input id="candidate-project" maxlength="512" required disabled>
              </label>
              <button id="candidate-button" class="primary-button" type="submit" disabled>Create</button>
            </div>
            <fieldset id="candidate-evidence-mode" class="mode-switch" disabled>
              <legend>Evidence</legend>
              <label><input type="radio" name="candidate-evidence-mode" value="stored" checked> Stored events</label>
              <label><input type="radio" name="candidate-evidence-mode" value="pending_web"> Pending web evidence</label>
            </fieldset>
            <div id="candidate-stored-evidence">
              <label>
                <span>Evidence IDs</span>
                <textarea id="candidate-evidence" maxlength="25700" rows="2" disabled></textarea>
              </label>
            </div>
            <div id="candidate-pending-evidence" class="pending-evidence" hidden>
              <div class="compact-fields">
                <label><span>Source account ID</span><input id="candidate-web-source-account" maxlength="256" disabled></label>
                <label><span>Source</span><select id="candidate-web-source-system" disabled><option value="chatgpt_web">ChatGPT</option><option value="claude_web">Claude</option><option value="grok_web">Grok</option></select></label>
              </div>
              <div class="compact-fields">
                <label><span>Conversation ID</span><input id="candidate-web-conversation" maxlength="4096" disabled></label>
                <label><span>Message ID</span><input id="candidate-web-message" maxlength="4096" disabled></label>
              </div>
              <div class="compact-fields">
                <label><span>Parent message ID</span><input id="candidate-web-parent" maxlength="4096" disabled></label>
                <label><span>Branch ID</span><input id="candidate-web-branch" maxlength="4096" disabled></label>
              </div>
              <label><span>Exact evidence content</span><textarea id="candidate-web-content" maxlength="16384" rows="4" disabled></textarea></label>
            </div>
          </form>
        </section>

        <div class="action-grid operation-actions">
          <form id="correction-plan-form" class="action-form">
            <h2>Plan event correction</h2>
            <label><span>Evidence ID</span><input id="correction-event-id" maxlength="256" required disabled></label>
            <div class="compact-fields">
              <label><span>Authority</span><select id="correction-authority" required disabled><option value="">Select</option><option value="user_assertion">User assertion</option><option value="assistant_output">Assistant output</option><option value="tool_observation">Tool observation</option><option value="external_content">External content</option><option value="system_policy">System policy</option><option value="admin_approved_policy">Admin approved policy</option></select></label>
              <label><span>Privacy</span><select id="correction-privacy" required disabled><option value="">Select</option><option value="included">Included</option><option value="private">Private</option><option value="no_memory">No memory</option></select></label>
            </div>
            <div class="compact-fields">
              <label><span>Scope</span><select id="correction-scope" required disabled><option value="">Select</option><option value="user_global">Global</option><option value="project">Project</option><option value="assistant_private">Assistant private</option><option value="session">Session</option></select></label>
              <label id="correction-project-field" hidden><span>Project context</span><input id="correction-project" maxlength="512" disabled></label>
            </div>
            <label><span>Reason</span><input id="correction-reason" maxlength="1024" required disabled></label>
            <button id="correction-plan-button" class="secondary-button" type="submit" disabled>Preview correction</button>
          </form>
          <form id="correction-apply-form" class="action-form">
            <h2>Planned correction</h2>
            <dl class="plan-summary"><div><dt>Plan hash</dt><dd id="correction-plan-hash">None</dd></div><div><dt>Change</dt><dd id="correction-plan-change">No plan</dd></div></dl>
            <button id="correction-apply-button" class="primary-button" type="submit" disabled>Apply planned correction</button>
          </form>
        </div>

        <section class="data-section" aria-labelledby="contexts-heading">
          <div class="section-heading"><h2 id="contexts-heading">Contexts</h2><span id="contexts-count" class="count">0</span></div>
          <div class="table-scroll"><table><thead><tr><th>Label</th><th>Kind</th><th>Events</th><th>Streams</th><th>Candidates</th></tr></thead><tbody id="contexts-body"></tbody></table></div>
        </section>
        <section class="data-section" aria-labelledby="candidates-heading">
          <div class="section-heading"><h2 id="candidates-heading">Candidates</h2><span id="candidates-count" class="count">0</span></div>
          <div class="table-scroll"><table><thead><tr><th>Statement</th><th>Type</th><th>Scope</th><th>Evidence</th><th>Lifecycle</th><th>Review</th><th>Created</th></tr></thead><tbody id="candidates-body"></tbody></table></div>
        </section>
        <section class="data-section" aria-labelledby="corrections-heading">
          <div class="section-heading"><h2 id="corrections-heading">Corrections</h2><span id="corrections-count" class="count">0</span></div>
          <div class="table-scroll"><table><thead><tr><th>Event</th><th>Reason</th><th>Authorization</th><th>Created</th></tr></thead><tbody id="corrections-body"></tbody></table></div>
        </section>
      </section>

      <section id="access-view" class="tab-view" role="tabpanel" data-tab-panel="access" hidden>
        <div class="section-heading"><h2>Client access</h2></div>
        <div class="action-grid">
          <form id="client-form" class="action-form">
            <h2>Register client</h2>
            <label><span>Label</span><input id="client-label" maxlength="512" disabled></label>
            <label><span>Kind</span><select id="client-kind" disabled><option value="assistant">Assistant</option><option value="collector">Collector</option><option value="scheduler">Scheduler</option><option value="local_admin">Local admin</option></select></label>
            <fieldset id="client-capabilities" class="capability-list" disabled><legend>Capabilities</legend><label><input type="checkbox" value="memory:search" checked> Search</label><label><input type="checkbox" value="memory:evidence-read" checked> Evidence</label><label><input type="checkbox" value="memory:status" checked> Status</label><label><input type="checkbox" value="memory:propose-write" checked> Propose</label><label><input type="checkbox" value="source:upload"> Upload</label><label><input type="checkbox" value="client:admin"> Admin</label></fieldset>
            <button id="client-button" class="primary-button" type="submit" disabled>Register</button>
          </form>
          <form id="credential-form" class="action-form">
            <h2>Issue credential</h2>
            <label><span>Client ID</span><input id="credential-client-id" maxlength="256" disabled></label>
            <label><span>TTL hours</span><input id="credential-ttl" type="number" min="1" max="8760" value="720" disabled></label>
            <button id="credential-button" class="primary-button" type="submit" disabled>Issue</button>
          </form>
          <form id="revoke-form" class="action-form">
            <h2>Revoke credential</h2>
            <label><span>Credential ID</span><input id="revoke-credential-id" maxlength="256" disabled></label>
            <button id="revoke-button" class="danger-button" type="submit" disabled>Revoke</button>
          </form>
          <form id="enrollment-form" class="action-form">
            <h2>Enroll device</h2>
            <label><span>Label</span><input id="enrollment-label" maxlength="512" disabled></label>
            <label><span>Platform</span><input id="enrollment-platform" maxlength="512" disabled></label>
            <div class="compact-fields"><label><span>Code minutes</span><input id="enrollment-ttl" type="number" min="1" max="60" value="10" disabled></label><label><span>Credential days</span><input id="enrollment-credential-days" type="number" min="1" max="365" value="90" disabled></label></div>
            <button id="enrollment-button" class="primary-button" type="submit" disabled>Create code</button>
          </form>
          <form id="source-account-form" class="action-form">
            <h2>Register source</h2>
            <label><span>Device ID</span><input id="source-device-id" maxlength="256" disabled></label>
            <div class="compact-fields"><label><span>Source</span><select id="source-system" disabled><option value="codex">Codex</option><option value="claude_code">Claude Code</option><option value="grok_build">Grok Build</option><option value="chatgpt_web">ChatGPT</option><option value="claude_web">Claude</option><option value="grok_web">Grok</option></select></label><label><span>Scope</span><select id="source-scope" disabled><option value="user_global">Global</option><option value="project">Project</option><option value="assistant_private">Assistant private</option><option value="session">Session</option></select></label></div>
            <label><span>Account label</span><input id="source-account-label" maxlength="512" disabled></label>
            <label><span>Project context</span><input id="source-project-id" maxlength="512" disabled></label>
            <button id="source-account-button" class="primary-button" type="submit" disabled>Register</button>
          </form>
        </div>

        <section id="one-time-values" class="one-time-values" aria-labelledby="one-time-heading" hidden>
          <div class="section-heading"><h2 id="one-time-heading">One-time values</h2><button id="clear-one-time" class="quiet-button" type="button">Clear</button></div>
          <dl><dt>Credential</dt><dd id="issued-secret"></dd><dt>Enrollment code</dt><dd id="enrollment-secret"></dd></dl>
        </section>

        <section class="data-section"><div class="section-heading"><h2>Clients</h2><span id="clients-count" class="count">0</span></div><div class="table-scroll"><table><thead><tr><th>Client</th><th>Kind</th><th>Capabilities</th><th>Credentials</th><th>Status</th></tr></thead><tbody id="clients-body"></tbody></table></div></section>
        <section class="data-section"><div class="section-heading"><h2>Credentials</h2><span id="credentials-count" class="count">0</span></div><div class="table-scroll"><table><thead><tr><th>Credential</th><th>Client</th><th>Status</th><th>Expires</th></tr></thead><tbody id="credentials-body"></tbody></table></div></section>
        <section class="data-section"><div class="section-heading"><h2>Source accounts</h2><span id="source-accounts-count" class="count">0</span></div><div class="table-scroll"><table><thead><tr><th>Account</th><th>Source</th><th>Scope</th><th>Device</th><th>Registration</th><th>Last node receipt</th></tr></thead><tbody id="source-accounts-body"></tbody></table></div></section>
      </section>

      <section id="operations-view" class="tab-view" role="tabpanel" data-tab-panel="operations" hidden>
        <div class="section-heading"><h2>Storage and recovery</h2></div>
        <dl class="metrics"><div><dt>Objects</dt><dd id="storage-objects">0</dd></div><div><dt>Evidence (logical)</dt><dd id="storage-object-bytes">0 B</dd></div><div><dt>Database</dt><dd id="storage-database-bytes">0 B</dd></div><div><dt>Free pages</dt><dd id="storage-free-bytes">0 B</dd></div><div><dt>Encrypted objects</dt><dd id="storage-encrypted-objects">0</dd></div><div><dt>Queued objects</dt><dd id="storage-queued-objects">0</dd></div><div><dt>Queued bytes</dt><dd id="storage-queued-bytes">0 B</dd></div><div><dt>Unverified uploads</dt><dd id="storage-unverified-objects">0</dd></div></dl>
        <p id="storage-residency" class="muted" title="Registered evidence paths only, checked without reading content or contacting storage providers. Logical file sizes are not physical disk usage or integrity verification. Backups, staging, caches, and unregistered files are excluded. Encrypted mappings do not authorize deleting local copies.">Local copies: not assessed</p>
        <p id="storage-residency-detail" class="muted"></p>
        <div class="recovery-band"><span>Recovery evidence</span><strong id="recovery-state">Locked</strong><span id="recovery-detail" class="muted"></span></div>
        <section class="data-section" aria-labelledby="assisted-exports-heading">
          <div class="section-heading"><h2 id="assisted-exports-heading">Assisted web exports</h2><span id="assisted-exports-count" class="count">0</span></div>
          <div class="table-scroll"><table><thead><tr><th>Source</th><th>Stage</th><th>Last request</th><th>Next due</th><th>Next action</th><th>Operator</th></tr></thead><tbody id="assisted-exports-body"></tbody></table></div>
        </section>
        <div class="action-grid operation-actions">
          <form id="deletion-plan-form" class="action-form">
            <h2>Plan deletion</h2>
            <label><span>Target</span><select id="deletion-kind" disabled><option value="conversation">Conversation</option><option value="source_account">Source account</option></select></label>
            <label><span>Source</span><select id="deletion-source-system" disabled><option value="codex">Codex</option><option value="claude_code">Claude Code</option><option value="grok_build">Grok Build</option><option value="chatgpt_web">ChatGPT</option><option value="claude_web">Claude</option><option value="grok_web">Grok</option></select></label>
            <label><span>Source account ID or unique label</span><input id="deletion-source-account" maxlength="1024" required disabled></label>
            <label id="deletion-conversation-field"><span>Conversation ID</span><input id="deletion-conversation" maxlength="4096" required disabled></label>
            <label><span>Reason</span><input id="deletion-reason" maxlength="1024" required disabled></label>
            <button id="deletion-plan-button" class="secondary-button" type="submit" disabled>Preview targets</button>
          </form>
          <form id="deletion-apply-form" class="action-form">
            <h2>Planned deletion</h2>
            <dl class="plan-summary"><div><dt>Plan hash</dt><dd id="deletion-plan-hash">None</dd></div><div><dt>Target counts</dt><dd id="deletion-plan-counts">No plan</dd></div><div><dt>Scope and retained copies</dt><dd id="deletion-retained-copies">No plan</dd></div></dl>
            <button id="deletion-apply-button" class="danger-button" type="submit" disabled>Delete planned evidence</button>
          </form>
        </div>
        <section class="data-section"><div class="section-heading"><h2>Deletion operations</h2><span id="deletions-count" class="count">0</span></div><div class="table-scroll"><table><thead><tr><th>Operation</th><th>Kind</th><th>Status</th><th>Targets</th><th>Completed</th></tr></thead><tbody id="deletions-body"></tbody></table></div></section>
      </section>
    </section>
  </main>

  <dialog id="unlock-dialog" class="unlock-dialog">
    <form id="unlock-form" method="dialog">
      <h2>Unlock local memory</h2>
      <label>
        <span>Local admin credential</span>
        <input id="credential" name="credential" type="password" autocomplete="off"
               autocapitalize="off" spellcheck="false" required>
      </label>
      <p id="unlock-error" class="error" role="alert"></p>
      <button class="primary-button" type="submit">Unlock</button>
    </form>
  </dialog>

  <dialog id="evidence-dialog" class="evidence-dialog">
    <div class="dialog-heading">
      <h2>Exact evidence</h2>
      <button id="close-evidence" class="quiet-button" type="button">Close</button>
    </div>
    <dl id="evidence-meta" class="evidence-meta"></dl>
    <pre id="evidence-content" class="evidence-content"></pre>
  </dialog>

  <div id="status-message" class="status-message" role="status" aria-live="polite"></div>
  <script src="/assets/panel.js" defer></script>
</body>
</html>
"""

_PANEL_CSS = """:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #ffffff;
  color: #18232d;
  font-synthesis: none;
  font-size: 14px;
  line-height: 1.45;
}

* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; min-width: 320px; min-height: 100vh; background: #ffffff; }
button, input, select, textarea { font: inherit; letter-spacing: 0; }
button, select, input { min-height: 38px; }
button { cursor: pointer; }
button:disabled, input:disabled, select:disabled, textarea:disabled { cursor: not-allowed; opacity: .56; }

.topbar {
  min-height: 58px;
  padding: 10px 18px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  color: #18232d;
  background: #ffffff;
  border-bottom: 1px solid #cbd3d9;
}
.product { margin: 0; font-size: 18px; font-weight: 720; }
.generation { margin: 3px 0 0; max-width: 56ch; color: #5c6c7b; font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.topbar-actions { display: flex; align-items: center; gap: 10px; }
.topbar > div:first-child { min-width: 0; }
.state { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; }
.state-ready { color: #d6fff7; background: #17645d; }
.state-attention { color: #fff4d8; background: #8a5b0a; }
.state-locked { color: #f8eac5; background: #705416; }

.workspace { min-height: calc(100vh - 58px); display: grid; grid-template-columns: 258px minmax(0, 1fr); }
.source-panel { padding: 18px; }
.source-panel { background: #f6f8fa; border-right: 1px solid #d5dce2; }
.work-panel { min-width: 0; padding: 0 24px 24px; }
.section-heading { min-height: 38px; display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
h1, h2 { margin: 0; font-size: 17px; line-height: 1.3; letter-spacing: 0; }
.count, .muted { color: #66716e; font-size: 12px; }
.muted { margin: 3px 0 0; }

.tabs { min-height: 56px; display: flex; align-items: end; gap: 8px; border-bottom: 1px solid #d5dce2; background: #ffffff; }
.tab-button { min-height: 38px; padding: 0 12px; color: #56615e; background: transparent; border: 0; border-bottom: 3px solid transparent; font-size: 13px; font-weight: 700; }
.tab-button:hover { color: #18201f; background: #e7ecea; }
.tab-button.active { color: #075e57; border-bottom-color: #087d73; }
.tab-view { padding-top: 18px; }

.source-grid { margin-top: 12px; display: grid; gap: 7px; }
.source-row { min-height: 56px; padding: 10px; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px; border: 1px solid #d5dce2; border-radius: 4px; background: #fff; }
.source-name { min-width: 0; font-size: 13px; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.source-detail { margin-top: 2px; color: #6c7774; font-size: 11px; }
.source-import { display: block; }
.source-status { width: 10px; height: 10px; border-radius: 50%; background: #9ca5a3; }
.source-status.available { background: #168270; }
.source-status.attention { background: #c47613; }
.source-status.registered { background: #d49722; }
.source-status.disconnected { background: #aeb6b4; }
.export-band { margin-top: 12px; padding-top: 11px; display: flex; justify-content: space-between; gap: 8px; border-top: 1px solid #d5dcda; color: #5c6764; font-size: 12px; }
.export-band strong { color: #1f5551; }

.search-form { margin-top: 14px; padding: 14px 0; border-top: 1px solid #cbd3d1; border-bottom: 1px solid #cbd3d1; }
label > span, legend { display: block; margin-bottom: 6px; color: #475765; font-size: 12px; font-weight: 600; }
textarea, input, select { width: 100%; color: #18201f; background: #fff; border: 1px solid #abb6b3; border-radius: 5px; outline: none; }
textarea, input { padding: 9px 10px; }
textarea { min-height: 66px; resize: vertical; line-height: 1.4; }
select { padding: 0 30px 0 9px; }
textarea:focus, input:focus, select:focus, button:focus-visible { border-color: #087d73; box-shadow: 0 0 0 3px #b9e7e1; }
.filters { margin-top: 10px; display: grid; grid-template-columns: minmax(150px, 1fr) minmax(150px, 1fr) 90px 100px; gap: 9px; align-items: end; }
.scope-filters { margin: 11px 0 0; padding: 0; display: flex; flex-wrap: wrap; gap: 7px 14px; border: 0; }
.scope-filters legend { float: left; margin: 4px 14px 0 0; }
.scope-filters label { display: flex; align-items: center; gap: 5px; color: #4e5b58; font-size: 12px; }
.scope-filters input { width: 15px; min-height: 15px; accent-color: #087d73; }
.primary-button, .quiet-button, .danger-button { border-radius: 5px; font-weight: 700; }
.primary-button { padding: 0 14px; color: #fff; background: #087d73; border: 1px solid #07665e; }
.primary-button:hover:not(:disabled) { background: #066a62; }
.quiet-button { padding: 0 10px; color: inherit; background: transparent; border: 1px solid #87928f; }
.danger-button { padding: 0 14px; color: #fff; background: #a12628; border: 1px solid #7f1e20; }
.danger-button:hover:not(:disabled) { background: #851f21; }
.topbar .quiet-button { color: #344756; border-color: #c5d0d9; }

.empty-state { min-height: 180px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; color: #647381; font-size: 14px; }
.results { margin: 10px 0 0; padding: 0; display: grid; gap: 0; list-style: none; }
.result { padding: 20px 0; border-bottom: 1px solid #d5dce2; background: #fff; }
.result-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.result-source { color: #205cb7; font-size: 13px; font-weight: 750; }
.result-meta { margin-top: 2px; color: #6b7673; font-size: 11px; }
.result-text { margin: 12px 0 0; max-width: 90ch; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 14px; line-height: 1.65; }
.evidence-button { min-height: 34px; flex: none; padding: 0 12px; color: #344756; background: #fff; border: 1px solid #c5d0d9; border-radius: 4px; font-size: 12px; font-weight: 600; }
.roles { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 5px; }
.role { padding: 2px 5px; color: #5c3f0b; background: #fff1cd; border-radius: 3px; font-size: 10px; }
.candidate-panel { padding-bottom: 18px; }
.candidate-form { margin-top: 12px; display: grid; gap: 10px; }
.candidate-fields { display: grid; grid-template-columns: minmax(120px, .8fr) minmax(120px, .8fr) minmax(150px, 1fr) 100px; gap: 9px; align-items: end; }
.mode-switch { margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 7px 16px; border: 0; }
.mode-switch legend { float: left; margin: 4px 14px 0 0; }
.mode-switch label { display: flex; align-items: center; gap: 5px; color: #4e5b58; font-size: 12px; }
.mode-switch input { width: 15px; min-height: 15px; accent-color: #087d73; }
.pending-evidence { display: grid; gap: 10px; }
.operation-actions { margin-top: 14px; }
.plan-summary { margin: 0; display: grid; gap: 10px; }
.plan-summary div { display: grid; gap: 3px; }
.plan-summary dt { color: #66716e; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.plan-summary dd { margin: 0; color: #26302e; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.danger-button { min-height: 38px; padding: 0 14px; color: #fff; background: #a23b35; border: 1px solid #7f2c28; border-radius: 4px; font-weight: 750; }
.danger-button:hover:not(:disabled) { background: #87302b; }

.data-section { margin-top: 20px; padding-top: 16px; border-top: 1px solid #cbd3d1; }
.table-scroll { overflow: auto; border: 1px solid #c4cdca; border-radius: 6px; background: #fff; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 8px 10px; text-align: left; vertical-align: top; border-bottom: 1px solid #e0e5e3; overflow-wrap: normal; word-break: normal; }
th { color: #53605d; background: #eef2f0; font-size: 10px; text-transform: uppercase; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
.empty-row { color: #75807d; text-align: center; }
.mono { white-space: pre-wrap; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
.statement-cell { min-width: 240px; max-width: 580px; white-space: pre-wrap; overflow-wrap: anywhere; }
.candidate-lifecycle { min-width: 105px; }
.candidate-lifecycle strong { display: block; color: #1f5551; text-transform: capitalize; }
.candidate-lifecycle span { display: block; margin-top: 3px; color: #7a4f0b; font-size: 10px; }
.candidate-review-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.candidate-review-actions.interactive { min-width: 250px; }
.candidate-review-actions select { width: auto; min-width: 145px; min-height: 30px; font-size: 11px; }
.candidate-review-button { min-height: 30px; padding: 0 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.candidate-review-button.advance { color: #fff; background: #087d73; border: 1px solid #07665e; }
.candidate-review-button.reject { color: #fff; background: #a23b35; border: 1px solid #7f2c28; }
.candidate-review-button:hover:not(:disabled) { filter: brightness(.9); }
.candidate-created { white-space: nowrap; font-size: 11px; }

.action-grid { margin-top: 12px; display: grid; grid-template-columns: repeat(3, minmax(220px, 1fr)); gap: 12px; align-items: start; }
.action-form { padding: 13px; display: grid; gap: 10px; border: 1px solid #c4cdca; border-radius: 6px; background: #fff; }
.action-form h2 { font-size: 14px; }
.compact-fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.capability-list { margin: 0; padding: 0; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px 10px; border: 0; }
.capability-list legend { grid-column: 1 / -1; }
.capability-list label { display: flex; align-items: center; gap: 5px; color: #4e5b58; font-size: 11px; }
.capability-list input { width: 15px; min-height: 15px; accent-color: #087d73; }
.one-time-values { margin-top: 16px; padding: 12px 13px; border: 1px solid #d49722; border-left-width: 4px; background: #fffaf0; }
.one-time-values dl { margin: 8px 0 0; display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 5px 12px; font-size: 12px; }
.one-time-values dt { color: #66716e; }
.one-time-values dd { margin: 0; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.metrics { margin: 12px 0 0; display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); border: 1px solid #c4cdca; background: #fff; }
.metrics div { padding: 12px; border-right: 1px solid #d5dcda; }
.metrics div:last-child { border-right: 0; }
.metrics dt { color: #66716e; font-size: 10px; font-weight: 700; text-transform: uppercase; }
.metrics dd { margin: 5px 0 0; font: 16px ui-monospace, SFMono-Regular, Menlo, monospace; }
.recovery-band { margin-top: 12px; padding: 11px 0; display: flex; align-items: center; gap: 12px; border-top: 1px solid #cbd3d1; border-bottom: 1px solid #cbd3d1; font-size: 12px; }
.recovery-band strong { color: #7b5716; }

dialog { width: min(92vw, 620px); padding: 0; color: #18201f; background: #fff; border: 1px solid #8f9a97; border-radius: 7px; box-shadow: 0 18px 50px rgb(24 32 31 / 22%); }
dialog::backdrop { background: rgb(16 23 22 / 48%); }
.unlock-dialog { width: min(92vw, 430px); }
.unlock-dialog form { padding: 20px; display: grid; gap: 14px; }
.unlock-dialog .primary-button { min-height: 40px; }
.error { min-height: 17px; margin: 0; color: #a12628; font-size: 12px; }
.dialog-heading { padding: 14px 16px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #cbd3d1; }
.evidence-meta { margin: 0; padding: 14px 16px; display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 5px 12px; border-bottom: 1px solid #cbd3d1; font-size: 12px; }
.evidence-meta dt { color: #66716e; }
.evidence-meta dd { margin: 0; overflow-wrap: anywhere; }
.evidence-content { max-height: 48vh; margin: 0; padding: 16px; overflow: auto; color: #26302e; background: #f4f6f5; white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
.status-message { position: fixed; right: 14px; bottom: 14px; max-width: min(440px, calc(100vw - 28px)); padding: 9px 11px; color: #fff; background: #7d2729; border-radius: 5px; font-size: 12px; opacity: 0; pointer-events: none; transition: opacity 120ms ease; }
.status-message.visible { opacity: 1; }

@media (max-width: 760px) {
  .topbar { padding: 9px 12px; }
  .workspace { display: block; }
  .source-panel { padding: 10px 12px; }
  .work-panel { padding: 0 12px 13px; }
  .source-panel { border-right: 0; border-bottom: 1px solid #cbd3d1; }
  .source-grid { margin-top: 6px; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 5px; }
  .source-row { min-height: 46px; padding: 6px 7px; gap: 4px; }
  .source-name { font-size: 11px; }
  .source-detail { font-size: 10px; overflow-wrap: anywhere; }
  .source-import { display: none; }
  .source-panel .section-heading { min-height: 28px; }
  .export-band { margin-top: 8px; padding-top: 8px; }
  .tabs { min-height: 46px; gap: 4px; }
  .tab-view { padding-top: 12px; }
  .search-form { margin-top: 10px; padding: 10px 0; }
  .filters { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
  .candidate-fields { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
  .action-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metrics div:nth-child(2) { border-right: 0; }
  .metrics div:nth-child(-n + 2) { border-bottom: 1px solid #d5dcda; }
  .filters .primary-button { min-height: 38px; }
  .empty-state { min-height: 110px; }
}

@media (max-width: 390px) {
  .topbar { gap: 8px; }
  .product { font-size: 14px; }
  .tabs { overflow-x: auto; }
  .tab-button { flex: 0 0 auto; padding: 0 8px; font-size: 12px; }
  .candidate-fields { grid-template-columns: 1fr; }
  .action-grid, .compact-fields, .metrics { grid-template-columns: 1fr; }
  .metrics div { border-right: 0; border-bottom: 1px solid #d5dcda; }
  .metrics div:last-child { border-bottom: 0; }
  .scope-filters legend { float: none; width: 100%; }
}

@media (prefers-reduced-motion: reduce) {
  .status-message { transition: none; }
}
"""

_PANEL_JS = """(() => {
  'use strict';

  let credential = '';
  let sessionGeneration = 0;
  let statusTimer = 0;
  let activeMutations = 0;
  let deletionPlan = null;
  let deletionPlanHash = '';
  let correctionPlan = null;
  let correctionPlanHash = '';
  const pendingRequests = new Set();
  const retainedCopyKinds = [
    'local_snapshots_and_recovery_packages',
    'portable_exports',
    'remote_backup_objects_and_versions',
    'provider_native_histories_and_exports'
  ];
  const retainedCopyMessage =
    'Existing backups, exports, provider histories, and remote backup versions remain.';
  const byId = (id) => document.getElementById(id);
  const unlockDialog = byId('unlock-dialog');
  const evidenceDialog = byId('evidence-dialog');
  const searchForm = byId('search-form');
  const candidateForm = byId('candidate-form');
  const clientForm = byId('client-form');
  const credentialForm = byId('credential-form');
  const revokeForm = byId('revoke-form');
  const enrollmentForm = byId('enrollment-form');
  const sourceAccountForm = byId('source-account-form');
  const correctionPlanForm = byId('correction-plan-form');
  const correctionApplyForm = byId('correction-apply-form');
  const deletionPlanForm = byId('deletion-plan-form');
  const deletionApplyForm = byId('deletion-apply-form');
  const authenticatedForms = [
    searchForm,
    candidateForm,
    clientForm,
    credentialForm,
    revokeForm,
    enrollmentForm,
    sourceAccountForm,
    correctionPlanForm,
    correctionApplyForm,
    deletionPlanForm,
    deletionApplyForm
  ];

  function setText(id, value) {
    byId(id).textContent = value == null ? '' : String(value);
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function message(value) {
    const node = byId('status-message');
    node.textContent = value;
    node.classList.add('visible');
    window.clearTimeout(statusTimer);
    statusTimer = window.setTimeout(() => node.classList.remove('visible'), 3200);
  }

  async function request(path, options = {}) {
    const requestGeneration = sessionGeneration;
    const controller = new AbortController();
    pendingRequests.add(controller);
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${credential}`);
    if (options.body) headers.set('Content-Type', 'application/json');
    try {
      const response = await fetch(path, {
        ...options,
        headers,
        cache: 'no-store',
        signal: controller.signal
      });
      let payload;
      try {
        payload = await response.json();
      } catch (_error) {
        if (response.status === 401) lock(true);
        const error = new Error('request_failed');
        error.status = response.status;
        throw error;
      }
      if (!response.ok) {
        if (response.status === 401) lock(true);
        const error = new Error(payload.error || 'request_failed');
        error.status = response.status;
        throw error;
      }
      if (requestGeneration !== sessionGeneration || credential === '') {
        throw new DOMException('Request cancelled', 'AbortError');
      }
      return payload;
    } finally {
      pendingRequests.delete(controller);
    }
  }

  function setControls(enabled) {
    for (const form of authenticatedForms) {
      for (const control of form.elements) control.disabled = !enabled;
    }
    syncCandidateFields();
    syncCorrectionFields();
    syncDeletionFields();
  }

  function clearOneTimeValues() {
    setText('issued-secret', '');
    setText('enrollment-secret', '');
    byId('one-time-values').hidden = true;
  }

  function clearDeletionPlan() {
    deletionPlan = null;
    deletionPlanHash = '';
    setText('deletion-plan-hash', 'None');
    setText('deletion-plan-counts', 'No plan');
    setText('deletion-retained-copies', 'No plan');
    byId('deletion-apply-button').disabled = true;
  }

  function hasExactKeys(value, keys) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === keys.length &&
      keys.every((key) => Object.hasOwn(value, key));
  }

  function requireRetainedCopyDisclosure(disclosure, plan, completed) {
    const version = plan && plan.format_version;
    const encrypted = version === 2;
    const planKeys = [
      'format_version', 'text_free', 'created_at', 'selector',
      'expected_generation_digest', 'target_digest', 'target_counts', 'authorization'
    ];
    if (encrypted) planKeys.push('encrypted_targets');
    if (
      (version !== 1 && version !== 2) || !hasExactKeys(plan, planKeys) ||
      plan.text_free !== true || typeof completed !== 'boolean'
    ) throw new Error('invalid_deletion_plan');
    const targets = encrypted ? plan.encrypted_targets : [];
    const profiles = ['filesystem-v1', 'deterministic-fake-v1', 'backblaze-b2-s3-v1'];
    if (encrypted && (
      !Array.isArray(targets) || targets.length < 1 || targets.length > 10000 ||
      targets.some((target) => !target || !profiles.includes(target.backend_profile))
    )) throw new Error('invalid_deletion_plan');
    const keys = [
      'operation_scope', 'remote_deletion_performed',
      'requires_separate_version_aware_deletion', 'copies_outside_operation'
    ];
    if (encrypted) keys.push('registered_encrypted_object_count', 'registered_encrypted_cleanup_completed');
    if (!hasExactKeys(disclosure, keys)) throw new Error('invalid_retained_copy_disclosure');
    const copies = disclosure.copies_outside_operation;
    const scope = encrypted
      ? 'local_canonical_state_and_registered_encrypted_objects'
      : 'local_canonical_state_only';
    const remote = completed && targets.some((target) => target.backend_profile === 'backblaze-b2-s3-v1');
    if (
      disclosure.operation_scope !== scope ||
      disclosure.remote_deletion_performed !== remote ||
      disclosure.requires_separate_version_aware_deletion !== true ||
      !Array.isArray(copies) ||
      copies.length !== retainedCopyKinds.length ||
      retainedCopyKinds.some((name, index) => copies[index] !== name) ||
      (encrypted && (
        !Number.isSafeInteger(disclosure.registered_encrypted_object_count) ||
        disclosure.registered_encrypted_object_count !== targets.length ||
        disclosure.registered_encrypted_cleanup_completed !== completed
      ))
    ) throw new Error('invalid_retained_copy_disclosure');
    return disclosure;
  }

  function deletionDisclosureMessage(disclosure) {
    if (disclosure.operation_scope === 'local_canonical_state_only') {
      return `Local canonical state only. ${retainedCopyMessage}`;
    }
    const count = disclosure.registered_encrypted_object_count;
    const cleanup = disclosure.registered_encrypted_cleanup_completed ? 'completed' : 'planned';
    const remote = disclosure.remote_deletion_performed
      ? 'Registered remote deletion was performed.'
      : 'No remote deletion was performed.';
    return `Local canonical state and ${count} registered encrypted object(s). ` +
      `Encrypted cleanup ${cleanup}. ${remote} ${retainedCopyMessage}`;
  }

  function clearCorrectionPlan() {
    correctionPlan = null;
    correctionPlanHash = '';
    setText('correction-plan-hash', 'None');
    setText('correction-plan-change', 'No plan');
    byId('correction-apply-button').disabled = true;
  }

  function clearAdministration() {
    for (const id of [
      'contexts-body',
      'candidates-body',
      'corrections-body',
      'clients-body',
      'credentials-body',
      'source-accounts-body',
      'deletions-body',
      'assisted-exports-body'
    ]) byId(id).replaceChildren();
    for (const id of [
      'contexts-count',
      'candidates-count',
      'corrections-count',
      'clients-count',
      'credentials-count',
      'source-accounts-count',
      'deletions-count',
      'assisted-exports-count'
    ]) setText(id, '0');
    setText('storage-objects', '0');
    setText('storage-object-bytes', '0 B');
    setText('storage-database-bytes', '0 B');
    setText('storage-free-bytes', '0 B');
    setText('storage-encrypted-objects', '0');
    setText('storage-queued-objects', '0');
    setText('storage-queued-bytes', '0 B');
    setText('storage-unverified-objects', '0');
    setText('storage-residency', 'Local copies: not assessed');
    setText('storage-residency-detail', '');
    setText('recovery-state', 'Locked');
    setText('recovery-detail', '');
    byId('recovery-detail').title = '';
  }

  function lock(force = false) {
    if (!force && activeMutations > 0) {
      message('An update is still being committed. Lock after it finishes.');
      return false;
    }
    invalidateRequests();
    credential = '';
    byId('credential').value = '';
    byId('query').value = '';
    byId('project').value = '';
    candidateForm.reset();
    clientForm.reset();
    credentialForm.reset();
    revokeForm.reset();
    enrollmentForm.reset();
    sourceAccountForm.reset();
    correctionPlanForm.reset();
    deletionPlanForm.reset();
    clearCorrectionPlan();
    clearDeletionPlan();
    clearOneTimeValues();
    clearAdministration();
    setControls(false);
    byId('lock-button').hidden = true;
    byId('system-state').className = 'state state-locked';
    setText('system-state', 'Locked');
    setText('generation', 'Locked');
    setText('export-state', 'Locked');
    setText('source-total', '0 available');
    setText('result-summary', 'Unlock to search exact evidence.');
    setText('candidate-state', 'Inactive until reviewed.');
    byId('source-grid').replaceChildren();
    byId('results').replaceChildren();
    byId('empty-state').hidden = false;
    setText('empty-message', 'No retrieval has run.');
    byId('clear-search').hidden = true;
    if (evidenceDialog.open) evidenceDialog.close();
    purgeEvidence();
    if (!unlockDialog.open) unlockDialog.showModal();
    byId('credential').focus();
    return true;
  }

  function invalidateRequests() {
    sessionGeneration += 1;
    for (const controller of pendingRequests) controller.abort();
    pendingRequests.clear();
  }

  function isCancelled(error) {
    return error != null && error.name === 'AbortError';
  }

  function purgeEvidence() {
    byId('evidence-meta').replaceChildren();
    byId('evidence-content').textContent = '';
  }

  function closeEvidence() {
    if (evidenceDialog.open) evidenceDialog.close();
    purgeEvidence();
  }

  function sourceLabel(value) {
    return {
      codex: 'Codex',
      claude_code: 'Claude Code',
      grok_build: 'Grok Build',
      chatgpt_web: 'ChatGPT',
      claude_web: 'Claude',
      grok_web: 'Grok'
    }[value] || value;
  }

  function formatBytes(value) {
    let amount = Number(value) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) {
      amount /= 1024;
      unit += 1;
    }
    const digits = unit === 0 || amount >= 10 ? 0 : 1;
    return `${amount.toFixed(digits)} ${units[unit]}`;
  }

  function formatTimestamp(value, fallback = 'Not recorded') {
    const text = value == null ? '' : String(value);
    if (!text) return fallback;
    return text.replace('T', ' ').replace('+00:00', ' UTC');
  }

  function formatEvidenceDay(value) {
    const text = value == null ? '' : String(value);
    return text ? text.slice(0, 10) : 'no evidence';
  }

  function formatState(value) {
    const text = value == null ? '' : String(value);
    return text ? text.replaceAll('_', ' ') : 'unknown';
  }

  function compactId(value) {
    const text = value == null ? '' : String(value);
    return text.length > 24 ? `${text.slice(0, 12)}...${text.slice(-8)}` : text;
  }

  function renderTable(bodyId, rows, columns) {
    const body = byId(bodyId);
    body.replaceChildren();
    if (!rows.length) {
      const row = element('tr');
      const cell = element('td', 'empty-row', 'None');
      cell.colSpan = columns.length;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const item of rows) {
      const row = element('tr');
      for (const column of columns) {
        const cell = element('td', column.className || '', column.value(item));
        if (column.title) cell.title = String(column.title(item) || '');
        row.append(cell);
      }
      body.append(row);
    }
  }

  function renderCandidates(candidates) {
    const body = byId('candidates-body');
    body.replaceChildren();
    if (!candidates.length) {
      const row = element('tr');
      const cell = element('td', 'empty-row', 'None');
      cell.colSpan = 7;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const item of candidates) {
      const row = element('tr');
      row.append(
        element('td', 'statement-cell', item.statement || ''),
        element('td', '', item.memory_type || ''),
        element('td', '', [item.scope, item.project_id].filter(Boolean).join(' / ')),
        element(
          'td',
          '',
          item.pending_claim ? item.pending_claim.status : (item.evidence_event_ids || []).length
        )
      );

      const blockers = Array.isArray(item.qualification_blockers)
        ? item.qualification_blockers
        : [];
      const lifecycle = element('td', 'candidate-lifecycle');
      lifecycle.append(element('strong', '', item.lifecycle || 'candidate'));
      if (!item.proposal_authenticated) {
        lifecycle.append(element('span', '', 'Unverified proposal'));
      } else if (blockers.length) {
        lifecycle.append(element('span', '', `${blockers.length} blocker${blockers.length === 1 ? '' : 's'}`));
      }
      lifecycle.title = blockers.join(', ');
      row.append(lifecycle);

      const actionsCell = element('td');
      const actions = element('div', 'candidate-review-actions');
      const canAdvance = blockers.length === 0;
      const reviewable = item.lifecycle === 'candidate' || item.lifecycle === 'qualified';
      if (reviewable) actions.classList.add('interactive');
      if (item.lifecycle === 'candidate' && canAdvance) {
        const qualify = element('button', 'candidate-review-button advance', 'Qualify');
        qualify.type = 'button';
        qualify.addEventListener('click', () => reviewCandidate(
          item,
          'qualify',
          'deterministic_checks_passed',
          qualify,
          row
        ));
        actions.append(qualify);
      } else if (item.lifecycle === 'qualified' && canAdvance) {
        const approve = element('button', 'candidate-review-button advance', 'Approve');
        approve.type = 'button';
        approve.addEventListener('click', () => reviewCandidate(
          item,
          'approve',
          'owner_approved',
          approve,
          row
        ));
        actions.append(approve);
      }
      if (reviewable) {
        const reason = element('select');
        reason.setAttribute('aria-label', 'Rejection reason');
        for (const [value, label] of [
          ['insufficient_evidence', 'Insufficient evidence'],
          ['duplicate', 'Duplicate'],
          ['incorrect', 'Incorrect'],
          ['out_of_scope', 'Out of scope'],
          ['superseded', 'Superseded']
        ]) {
          const option = element('option', '', label);
          option.value = value;
          reason.append(option);
        }
        const reject = element('button', 'candidate-review-button reject', 'Reject');
        reject.type = 'button';
        reject.addEventListener('click', () => reviewCandidate(
          item,
          'reject',
          reason.value,
          reject,
          row
        ));
        actions.append(reason, reject);
      }
      if (!actions.childNodes.length) actions.append(element('span', 'muted', 'Complete'));
      actionsCell.append(actions);
      row.append(actionsCell, element('td', 'candidate-created', item.created_at || ''));
      body.append(row);
    }
  }

  async function reviewCandidate(item, operation, reasonCode, trigger, row) {
    for (const control of row.querySelectorAll('button, select')) control.disabled = true;
    beginMutation();
    try {
      await request('/api/candidates/review', {
        method: 'POST',
        body: JSON.stringify({
          memory_id: item.memory_id,
          operation,
          expected_basis_digest: item.review_basis_digest,
          reason_code: reasonCode
        })
      });
      await refreshState();
      message('Candidate reviewed.');
    } catch (error) {
      if (!isCancelled(error)) {
        try {
          await refreshState();
        } catch (refreshError) {
          if (isCancelled(refreshError)) return;
        }
        message(error instanceof Error ? error.message : 'candidate_review_rejected');
      }
    } finally {
      if (row.isConnected) {
        for (const control of row.querySelectorAll('button, select')) {
          control.disabled = credential === '';
        }
      }
      trigger.disabled = credential === '';
      endMutation();
    }
  }

  function renderAdministration(payload) {
    const contexts = Array.isArray(payload.contexts) ? payload.contexts : [];
    const candidates = Array.isArray(payload.candidates) ? payload.candidates : [];
    const corrections = Array.isArray(payload.corrections) ? payload.corrections : [];
    const clients = Array.isArray(payload.clients) ? payload.clients : [];
    const credentials = Array.isArray(payload.credentials) ? payload.credentials : [];
    const sourceAccounts = Array.isArray(payload.source_accounts) ? payload.source_accounts : [];
    const deletions = Array.isArray(payload.deletions) ? payload.deletions : [];
    const truncated = payload.truncated || {};
    for (const [id, name, rows] of [
      ['contexts-count', 'contexts', contexts],
      ['candidates-count', 'candidates', candidates],
      ['corrections-count', 'corrections', corrections],
      ['clients-count', 'clients', clients],
      ['credentials-count', 'credentials', credentials],
      ['source-accounts-count', 'source_accounts', sourceAccounts],
      ['deletions-count', 'deletions', deletions]
    ]) setText(id, `${rows.length}${truncated[name] ? '+' : ''}`);

    renderTable('contexts-body', contexts, [
      { value: (item) => item.label || item.key || '' },
      { value: (item) => item.kind || '' },
      { value: (item) => item.event_count || 0 },
      { value: (item) => item.source_stream_count || 0 },
      { value: (item) => item.candidate_count || 0 }
    ]);
    renderCandidates(candidates);
    renderTable('corrections-body', corrections, [
      { value: (item) => compactId(item.event_id), title: (item) => item.event_id, className: 'mono' },
      { value: (item) => item.reason || '', className: 'statement-cell' },
      { value: (item) => [item.authorized_by, item.authorization_scope].filter(Boolean).join(' / ') },
      { value: (item) => item.created_at || '' }
    ]);
    renderTable('clients-body', clients, [
      { value: (item) => `${item.label || ''}\n${compactId(item.client_id)}`, title: (item) => item.client_id, className: 'mono' },
      { value: (item) => item.kind || '' },
      { value: (item) => (item.capabilities || []).join(', '), className: 'statement-cell' },
      { value: (item) => item.active_credential_count || 0 },
      { value: (item) => item.status || '' }
    ]);
    renderTable('credentials-body', credentials, [
      { value: (item) => compactId(item.credential_id), title: (item) => item.credential_id, className: 'mono' },
      { value: (item) => compactId(item.client_id), title: (item) => item.client_id, className: 'mono' },
      { value: (item) => item.status || '' },
      { value: (item) => item.expires_at || '' }
    ]);
    renderTable('source-accounts-body', sourceAccounts, [
      { value: (item) => `${item.label || ''}\n${compactId(item.source_account_id)}`, title: (item) => item.source_account_id, className: 'mono' },
      { value: (item) => sourceLabel(item.source_system) },
      { value: (item) => [item.scope, item.project_id].filter(Boolean).join(' / ') },
      { value: (item) => item.device_label || compactId(item.device_id), title: (item) => `${item.device_id} / ${item.device_status || 'unknown'}` },
      { value: (item) => item.status || '' },
      { value: (item) => [
        item.latest_native_admission_at ? `Upload ${formatTimestamp(item.latest_native_admission_at)}` : '',
        item.latest_web_observation_at ? `Export ${formatTimestamp(item.latest_web_observation_at)}` : ''
      ].filter(Boolean).join(' / ') || 'No receipt', title: () => 'Receipt time only; source freshness and collector liveness are unknown.' }
    ]);
    renderTable('deletions-body', deletions, [
      { value: (item) => compactId(item.operation_id), title: (item) => item.operation_id, className: 'mono' },
      { value: (item) => [item.kind, sourceLabel(item.source_system)].filter(Boolean).join(' / ') },
      { value: (item) => item.status || '' },
      { value: (item) => Object.entries(item.target_counts || {}).map(([key, value]) => `${key}: ${value}`).join(', ') },
      { value: (item) => item.completed_at || '' }
    ]);

    const storage = payload.storage || {};
    setText('storage-objects', storage.object_count || 0);
    setText('storage-object-bytes', formatBytes(storage.object_bytes));
    setText('storage-database-bytes', formatBytes(storage.database_bytes));
    setText('storage-free-bytes', formatBytes(storage.database_free_bytes));
    setText('storage-encrypted-objects', storage.mapped_encrypted_objects || 0);
    setText('storage-queued-objects', storage.queued_publication_objects || 0);
    setText('storage-queued-bytes', formatBytes(storage.queued_publication_bytes));
    setText('storage-unverified-objects', storage.pending_encrypted_publications || 0);
    const localCopies = storage.local_copies;
    if (localCopies && storage.local_copy_residency !== 'not_assessed') {
      setText('storage-residency', `Local copies: ${localCopies.present_objects} (${formatBytes(localCopies.logical_file_bytes)} logical) / encrypted-mapped copies: ${localCopies.encrypted_mapped_present_objects} (${formatBytes(localCopies.encrypted_mapped_present_bytes)} logical)`);
      setText('storage-residency-detail', [
        `${localCopies.inspected_objects} of ${storage.object_count} registered paths checked`,
        `${localCopies.uninspected_objects} unchecked`,
        `${localCopies.uninspectable_objects} uninspectable`,
        `${localCopies.missing_local_objects} missing required local files`,
        `${localCopies.size_mismatch_objects} size mismatches`
      ].join(' / '));
    } else {
      setText('storage-residency', 'Local copies: not assessed');
      setText('storage-residency-detail', '');
    }
    const recovery = payload.recovery || {};
    setText('recovery-state', formatState(recovery.status));
    const backup = recovery.last_successful_backup || null;
    const restore = recovery.last_verified_restore || null;
    setText('recovery-detail', [
      backup ? `Backup ${formatTimestamp(backup.created_at)}` : '',
      restore ? `Restore ${formatTimestamp(restore.verified_at)}` : ''
    ].filter(Boolean).join(' / ') || 'No verified recovery evidence recorded');
    byId('recovery-detail').title = [
      backup ? `backup ${backup.package_id || ''} / ${backup.receipt_sha256 || ''}` : '',
      restore ? `restore ${restore.package_id || ''} / ${restore.receipt_sha256 || ''}` : ''
    ].filter(Boolean).join(' / ');
  }

  async function refreshState() {
    const [overview, administration] = await Promise.all([
      request('/api/overview'),
      request('/api/administration')
    ]);
    renderOverview(overview);
    renderAdministration(administration);
  }

  function renderOverview(payload) {
    const sources = Array.isArray(payload.sources) ? payload.sources : [];
    const exports = payload.assisted_exports || {};
    const exportSources = Array.isArray(exports.sources) ? exports.sources : [];
    const grid = byId('source-grid');
    grid.replaceChildren();
    let available = 0;
    for (const source of sources) {
      if (source.state === 'available') available += 1;
      const sync = source.sync || {};
      const row = element('div', 'source-row');
      const body = element('div');
      const detail = element('div', 'source-detail', formatState(sync.state));
      detail.append(element('span', 'source-import', source.latest_ingested_at
        ? `Imported ${formatEvidenceDay(source.latest_ingested_at)}` : 'Not imported'));
      body.append(
        element('div', 'source-name', sourceLabel(source.source_system)),
        detail
      );
      const visualState = sync.attention_required ? 'attention' : (source.state || 'disconnected');
      const status = element('span', `source-status ${visualState}`);
      status.title = `${formatState(source.state)} / sync ${formatState(sync.state)}`;
      row.title = [
        `data ${formatState(source.state)}`,
        `sync ${formatState(sync.state)}`,
        `${source.conversations || 0} conversations`,
        `${source.upload_batches || 0} native batches`,
        `${source.web_export_batches || 0} web batches`,
        `${sync.unmanaged_account_count || 0} unmanaged accounts`,
        `latest import ${formatTimestamp(source.latest_ingested_at)}`,
        'Source freshness and collector liveness are unknown'
      ].join(' / ');
      row.append(body, status);
      grid.append(row);
    }
    setText('source-total', `${available} of ${sources.length} available`);
    setText('export-state', exports.status || 'unavailable');
    setText('assisted-exports-count', exportSources.length);
    renderTable('assisted-exports-body', exportSources, [
      { value: (item) => sourceLabel(item.source_system) },
      { value: (item) => item.stage || '' },
      { value: (item) => formatTimestamp(item.last_request_at) },
      { value: (item) => formatTimestamp(item.next_request_due_at) },
      { value: (item) => item.next_action || '' },
      { value: (item) => item.requires_authenticated_ui ? 'Authenticated browser' : 'Agent or CLI' }
    ]);
    setText('generation', `Generation ${String(payload.generation_digest || '').slice(0, 16)}`);
    setText('result-summary', 'Ready to search exact evidence.');
    const needsAttention = payload.status === 'attention_required';
    byId('system-state').className = needsAttention ? 'state state-attention' : 'state state-ready';
    setText('system-state', needsAttention ? 'Attention' : 'Operational');
  }

  function renderResults(payload) {
    const results = Array.isArray(payload.results) ? payload.results : [];
    const list = byId('results');
    list.replaceChildren();
    byId('empty-state').hidden = results.length > 0;
    if (!results.length) setText('empty-message', 'No matching evidence.');
    byId('clear-search').hidden = results.length > 0;
    const selection = payload.selection || {};
    setText('result-summary', `${results.length} of ${selection.candidate_match_count || 0} matches`);
    for (const item of results) {
      const row = element('li', 'result');
      const top = element('div', 'result-top');
      const labels = element('div');
      labels.append(
        element('div', 'result-source', sourceLabel(item.source_system)),
        element('div', 'result-meta', [item.actor_kind, item.authority, item.occurred_at].filter(Boolean).join(' / '))
      );
      const button = element('button', 'evidence-button', 'Evidence');
      button.type = 'button';
      button.addEventListener('click', () => showEvidence(item.event_id));
      top.append(labels, button);
      row.append(top, element('p', 'result-text', item.content_text));
      if (Array.isArray(item.workset_roles) && item.workset_roles.length) {
        const roles = element('div', 'roles');
        for (const role of item.workset_roles) roles.append(element('span', 'role', role.replaceAll('_', ' ')));
        row.append(roles);
      }
      list.append(row);
    }
  }

  async function showEvidence(eventId) {
    try {
      const payload = await request('/api/evidence', {
        method: 'POST',
        body: JSON.stringify({ event_id: eventId })
      });
      const meta = byId('evidence-meta');
      meta.replaceChildren();
      for (const [label, value] of [
        ['Evidence ID', payload.event_id],
        ['Source', sourceLabel(payload.source_system)],
        ['Speaker', payload.actor_kind],
        ['Authority', payload.authority],
        ['Conversation', payload.conversation_id],
        ['Date', payload.occurred_at || 'Unknown'],
        ['Scope', payload.scope]
      ]) {
        meta.append(element('dt', '', label), element('dd', '', value));
      }
      if (payload.raw_record_access === 'withheld_uninspected_attachment') {
        meta.append(element('dt', '', 'Raw evidence'), element('dd', '', 'Withheld: attachment not inspected. Showing message text only.'));
      }
      for (const attachment of payload.web_export?.attachment_manifests || []) {
        const label = attachment.inspection_status === 'not_inspected' ? 'Not inspected' : 'Inspection not verified';
        meta.append(element('dt', '', 'Attachment'), element('dd', '', `${attachment.media_type_hint}: ${label}; metadata only`));
      }
      byId('evidence-content').textContent = payload.raw_record || payload.content_text || '';
      evidenceDialog.showModal();
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    }
  }

  function selectTab(name) {
    for (const button of document.querySelectorAll('[data-tab]')) {
      const selected = button.dataset.tab === name;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', String(selected));
    }
    for (const panel of document.querySelectorAll('[data-tab-panel]')) {
      panel.hidden = panel.dataset.tabPanel !== name;
    }
  }

  function setClientCapabilityDefaults() {
    const allowed = {
      assistant: ['memory:search', 'memory:evidence-read', 'memory:status', 'memory:propose-write'],
      collector: ['source:upload', 'memory:status'],
      scheduler: ['source:upload', 'memory:status'],
      local_admin: ['memory:search', 'memory:evidence-read', 'memory:status', 'memory:propose-write', 'source:upload', 'client:admin']
    }[byId('client-kind').value] || [];
    for (const control of byId('client-capabilities').querySelectorAll('input')) {
      control.checked = allowed.includes(control.value);
    }
  }

  function showOneTimeValue(id, value) {
    setText(id, value || '');
    byId('one-time-values').hidden = false;
  }

  function syncCandidateFields() {
    const enabled = credential !== '';
    const projectScoped = byId('candidate-scope').value === 'project';
    const pendingMode = byId('candidate-evidence-mode')
      .querySelector('input:checked').value === 'pending_web';
    const projectField = byId('candidate-project-field');
    const projectInput = byId('candidate-project');
    const storedEvidence = byId('candidate-stored-evidence');
    const storedInput = byId('candidate-evidence');
    const pendingEvidence = byId('candidate-pending-evidence');

    projectField.hidden = !projectScoped;
    projectInput.required = projectScoped;
    projectInput.disabled = !enabled || !projectScoped;
    if (!projectScoped) projectInput.value = '';

    storedEvidence.hidden = pendingMode;
    storedInput.required = !pendingMode;
    storedInput.disabled = !enabled || pendingMode;
    pendingEvidence.hidden = !pendingMode;
    for (const control of pendingEvidence.querySelectorAll('input, select, textarea')) {
      control.disabled = !enabled || !pendingMode;
    }
    for (const id of [
      'candidate-web-source-account',
      'candidate-web-conversation',
      'candidate-web-message',
      'candidate-web-content'
    ]) byId(id).required = pendingMode;
  }

  function syncDeletionFields() {
    const enabled = credential !== '';
    const conversationTarget = byId('deletion-kind').value === 'conversation';
    const field = byId('deletion-conversation-field');
    const input = byId('deletion-conversation');
    field.hidden = !conversationTarget;
    input.required = conversationTarget;
    input.disabled = !enabled || !conversationTarget;
    if (!conversationTarget) input.value = '';
    byId('deletion-apply-button').disabled = !enabled || deletionPlan === null;
  }

  function syncCorrectionFields() {
    const enabled = credential !== '';
    const projectScoped = byId('correction-scope').value === 'project';
    const field = byId('correction-project-field');
    const input = byId('correction-project');
    field.hidden = !projectScoped;
    input.required = projectScoped;
    input.disabled = !enabled || !projectScoped;
    if (!projectScoped) input.value = '';
    byId('correction-apply-button').disabled = !enabled || correctionPlan === null;
  }

  function beginMutation() {
    activeMutations += 1;
    byId('lock-button').disabled = true;
    byId('workspace').setAttribute('aria-busy', 'true');
  }

  function endMutation() {
    activeMutations = Math.max(0, activeMutations - 1);
    if (activeMutations === 0) {
      byId('lock-button').disabled = credential === '';
      byId('workspace').setAttribute('aria-busy', 'false');
    }
  }

  async function mutate(buttonId, path, payload, onSuccess) {
    const button = byId(buttonId);
    button.disabled = true;
    beginMutation();
    try {
      const result = await request(path, { method: 'POST', body: JSON.stringify(payload) });
      clearCorrectionPlan();
      clearDeletionPlan();
      if (onSuccess) onSuccess(result);
      await refreshState();
      message('Updated.');
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      button.disabled = credential === '';
      endMutation();
    }
  }

  for (const button of document.querySelectorAll('[data-tab]')) {
    button.addEventListener('click', () => selectTab(button.dataset.tab));
  }
  byId('client-kind').addEventListener('change', setClientCapabilityDefaults);
  byId('candidate-scope').addEventListener('change', syncCandidateFields);
  byId('candidate-evidence-mode').addEventListener('change', syncCandidateFields);
  byId('correction-scope').addEventListener('change', () => {
    clearCorrectionPlan();
    syncCorrectionFields();
  });
  for (const id of [
    'correction-event-id',
    'correction-authority',
    'correction-privacy',
    'correction-project',
    'correction-reason'
  ]) byId(id).addEventListener('input', clearCorrectionPlan);
  byId('deletion-kind').addEventListener('change', () => {
    clearDeletionPlan();
    syncDeletionFields();
  });
  for (const id of [
    'deletion-source-system',
    'deletion-source-account',
    'deletion-conversation',
    'deletion-reason'
  ]) byId(id).addEventListener('input', clearDeletionPlan);
  byId('clear-one-time').addEventListener('click', clearOneTimeValues);
  byId('clear-search').addEventListener('click', () => {
    searchForm.reset();
    byId('results').replaceChildren();
    setText('result-summary', 'Ready to search exact evidence.');
    setText('empty-message', 'No retrieval has run.');
    byId('clear-search').hidden = true;
    byId('query').focus();
  });

  byId('unlock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = byId('credential');
    invalidateRequests();
    credential = input.value.trim();
    input.value = '';
    setText('unlock-error', '');
    try {
      await refreshState();
      unlockDialog.close();
      setControls(true);
      syncCandidateFields();
      byId('lock-button').hidden = false;
      byId('query').focus();
    } catch (error) {
      credential = '';
      const rejected = error && (error.status === 401 || error.status === 403);
      setText('unlock-error', rejected ? 'Credential rejected.' : 'Memory service unavailable.');
      if (!unlockDialog.open) unlockDialog.showModal();
      input.focus();
    }
  });

  searchForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = byId('search-button');
    button.disabled = true;
    byId('workspace').setAttribute('aria-busy', 'true');
    try {
      const project = byId('project').value.trim();
      const scopes = Array.from(byId('scope-filters').querySelectorAll('input:checked'), (node) => node.value);
      const payload = {
        query: byId('query').value,
        mode: byId('mode').value,
        project_id: project || null,
        contexts: project ? [{ kind: 'project', key: project }] : [],
        scopes,
        limit: Number(byId('limit').value),
        retrieval_control: 'force'
      };
      renderResults(await request('/api/search', { method: 'POST', body: JSON.stringify(payload) }));
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      button.disabled = credential === '';
      byId('workspace').setAttribute('aria-busy', 'false');
    }
  });

  candidateForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = byId('candidate-button');
    button.disabled = true;
    beginMutation();
    try {
      const project = byId('candidate-project').value.trim();
      const pendingMode = byId('candidate-evidence-mode')
        .querySelector('input:checked').value === 'pending_web';
      const evidenceIds = pendingMode
        ? []
        : byId('candidate-evidence').value
          .split(/\\r?\\n/)
          .map((value) => value.trim())
          .filter(Boolean);
      const parentMessage = byId('candidate-web-parent').value.trim();
      const branch = byId('candidate-web-branch').value.trim();
      const payload = {
        statement: byId('candidate-statement').value,
        memory_type: byId('candidate-type').value,
        evidence_event_ids: evidenceIds,
        scope: byId('candidate-scope').value,
        project_id: project || null,
        pending_web_evidence: pendingMode ? {
          source_account_id: byId('candidate-web-source-account').value.trim(),
          source_system: byId('candidate-web-source-system').value,
          conversation_id: byId('candidate-web-conversation').value.trim(),
          message_id: byId('candidate-web-message').value.trim(),
          parent_message_id: parentMessage || null,
          branch_id: branch || null,
          content_text: byId('candidate-web-content').value
        } : null
      };
      const result = await request('/api/candidates', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setText('candidate-state', `Candidate ${String(result.memory_id || '').slice(0, 8)} created.`);
      clearCorrectionPlan();
      clearDeletionPlan();
      byId('candidate-statement').value = '';
      byId('candidate-evidence').value = '';
      for (const id of [
        'candidate-web-source-account',
        'candidate-web-conversation',
        'candidate-web-message',
        'candidate-web-parent',
        'candidate-web-branch',
        'candidate-web-content'
      ]) byId(id).value = '';
      await refreshState();
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      button.disabled = credential === '';
      endMutation();
    }
  });

  clientForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const capabilities = Array.from(
      byId('client-capabilities').querySelectorAll('input:checked'),
      (node) => node.value
    );
    mutate('client-button', '/api/clients', {
      label: byId('client-label').value.trim(),
      kind: byId('client-kind').value,
      capabilities
    }, (result) => {
      byId('credential-client-id').value = result.client_id || '';
      clientForm.reset();
      setClientCapabilityDefaults();
    });
  });

  credentialForm.addEventListener('submit', (event) => {
    event.preventDefault();
    mutate('credential-button', '/api/credentials', {
      client_id: byId('credential-client-id').value.trim(),
      ttl_hours: Number(byId('credential-ttl').value)
    }, (result) => {
      showOneTimeValue('issued-secret', result.token);
      byId('revoke-credential-id').value = result.credential_id || '';
    });
  });

  revokeForm.addEventListener('submit', (event) => {
    event.preventDefault();
    mutate('revoke-button', '/api/credentials/revoke', {
      credential_id: byId('revoke-credential-id').value.trim()
    }, () => revokeForm.reset());
  });

  enrollmentForm.addEventListener('submit', (event) => {
    event.preventDefault();
    mutate('enrollment-button', '/api/enrollments', {
      label: byId('enrollment-label').value.trim(),
      platform: byId('enrollment-platform').value.trim(),
      ttl_minutes: Number(byId('enrollment-ttl').value),
      credential_ttl_days: Number(byId('enrollment-credential-days').value)
    }, (result) => {
      showOneTimeValue('enrollment-secret', result.code);
      enrollmentForm.reset();
    });
  });

  sourceAccountForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const project = byId('source-project-id').value.trim();
    mutate('source-account-button', '/api/source-accounts', {
      device_id: byId('source-device-id').value.trim(),
      source_system: byId('source-system').value,
      account_label: byId('source-account-label').value.trim(),
      scope: byId('source-scope').value,
      project_id: project || null
    }, () => sourceAccountForm.reset());
  });

  correctionPlanForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = byId('correction-plan-button');
    const project = byId('correction-project').value.trim();
    clearCorrectionPlan();
    button.disabled = true;
    byId('workspace').setAttribute('aria-busy', 'true');
    try {
      const result = await request('/api/corrections/plan', {
        method: 'POST',
        body: JSON.stringify({
          event_id: byId('correction-event-id').value.trim(),
          authority: byId('correction-authority').value,
          scope: byId('correction-scope').value,
          project_id: project || null,
          privacy: byId('correction-privacy').value,
          reason: byId('correction-reason').value.trim()
        })
      });
      if (!result.plan || typeof result.plan_sha256 !== 'string') throw new Error('invalid_correction_plan');
      correctionPlan = result.plan;
      correctionPlanHash = result.plan_sha256;
      const previous = result.previous_policy || {};
      const target = result.target_policy || {};
      const changes = ['authority', 'scope', 'project_id', 'privacy']
        .filter((name) => previous[name] !== target[name])
        .map((name) => `${name}: ${String(previous[name])} -> ${String(target[name])}`)
        .join(', ');
      setText('correction-plan-hash', correctionPlanHash);
      setText('correction-plan-change', changes || 'No policy change');
      syncCorrectionFields();
      message('Correction plan ready for review.');
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      button.disabled = credential === '';
      byId('workspace').setAttribute('aria-busy', 'false');
    }
  });

  correctionApplyForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (correctionPlan === null || correctionPlanHash === '') return;
    const button = byId('correction-apply-button');
    button.disabled = true;
    beginMutation();
    try {
      await request('/api/corrections/apply', {
        method: 'POST',
        body: JSON.stringify({
          plan: correctionPlan,
          expected_plan_sha256: correctionPlanHash,
          execute: true
        })
      });
      clearCorrectionPlan();
      clearDeletionPlan();
      correctionPlanForm.reset();
      syncCorrectionFields();
      await refreshState();
      message('Correction applied.');
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      syncCorrectionFields();
      endMutation();
    }
  });

  deletionPlanForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = byId('deletion-plan-button');
    const conversation = byId('deletion-conversation').value.trim();
    clearDeletionPlan();
    button.disabled = true;
    byId('workspace').setAttribute('aria-busy', 'true');
    try {
      const result = await request('/api/deletions/plan', {
        method: 'POST',
        body: JSON.stringify({
          kind: byId('deletion-kind').value,
          source_system: byId('deletion-source-system').value,
          source_account: byId('deletion-source-account').value.trim(),
          conversation_id: conversation || null,
          reason: byId('deletion-reason').value.trim()
        })
      });
      if (result.status !== 'planned' || typeof result.plan_sha256 !== 'string' ||
          !/^[0-9a-f]{64}$/.test(result.plan_sha256)) {
        throw new Error('invalid_deletion_plan');
      }
      const disclosure = requireRetainedCopyDisclosure(result.retained_copy_disclosure, result.plan, false);
      deletionPlan = result.plan;
      deletionPlanHash = result.plan_sha256;
      const counts = Object.entries(result.target_counts || {})
        .filter(([, value]) => Number(value) > 0)
        .map(([name, value]) => `${name}: ${value}`)
        .join(', ');
      setText('deletion-plan-hash', deletionPlanHash);
      setText('deletion-plan-counts', counts || 'No retained targets');
      setText(
        'deletion-retained-copies',
        deletionDisclosureMessage(disclosure)
      );
      syncDeletionFields();
      message('Deletion plan ready for review.');
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      button.disabled = credential === '';
      byId('workspace').setAttribute('aria-busy', 'false');
    }
  });

  deletionApplyForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (deletionPlan === null || deletionPlanHash === '') return;
    const plan = deletionPlan;
    const planHash = deletionPlanHash;
    const button = byId('deletion-apply-button');
    button.disabled = true;
    beginMutation();
    try {
      const result = await request('/api/deletions/apply', {
        method: 'POST',
        body: JSON.stringify({
          plan,
          expected_plan_sha256: planHash,
          execute: true
        })
      });
      if (result.status !== 'deleted' || result.plan_sha256 !== planHash) {
        throw new Error('invalid_deletion_result');
      }
      const disclosure = requireRetainedCopyDisclosure(result.retained_copy_disclosure, plan, true);
      const disclosureMessage = deletionDisclosureMessage(disclosure);
      clearCorrectionPlan();
      clearDeletionPlan();
      setText('deletion-retained-copies', disclosureMessage);
      deletionPlanForm.reset();
      syncDeletionFields();
      await refreshState();
      message(`Deletion complete. ${disclosureMessage}`);
    } catch (error) {
      if (!isCancelled(error)) message(error instanceof Error ? error.message : 'request_failed');
    } finally {
      syncDeletionFields();
      endMutation();
    }
  });

  byId('lock-button').addEventListener('click', () => lock());
  byId('close-evidence').addEventListener('click', closeEvidence);
  evidenceDialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    closeEvidence();
  });
  evidenceDialog.addEventListener('close', purgeEvidence);
  unlockDialog.addEventListener('cancel', (event) => event.preventDefault());
  lock();
})();
"""


class _PanelSecurityMiddleware:
    def __init__(self, app: ASGIApp, *, authority: str, origin: str) -> None:
        self._app = app
        self._authority = authority
        self._origin = origin

    async def __call__(self, scope: ASGIScope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if headers.get("host") != self._authority:
            await self._rejection(scope, receive, send, 421, "untrusted_host")
            return
        origin = headers.get("origin")
        if origin is not None and origin != self._origin:
            await self._rejection(scope, receive, send, 403, "untrusted_origin")
            return
        # Opening a link may serve the inert login shell, never a data endpoint or frame.
        shell_navigation = (
            scope["method"] == "GET"
            and scope["path"] == "/"
            and headers.get("sec-fetch-mode") == "navigate"
            and headers.get("sec-fetch-dest") == "document"
        )
        if headers.get("sec-fetch-site", "").lower() == "cross-site" and not shell_navigation:
            await self._rejection(scope, receive, send, 403, "cross_site_request")
            return

        async def add_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    response_headers[name] = value
            await send(message)

        await self._app(scope, receive, add_headers)

    async def _rejection(
        self,
        scope: ASGIScope,
        receive: Receive,
        send: Send,
        status_code: int,
        error: str,
    ) -> None:
        response = _api_error(status_code, error)

        async def add_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    response_headers[name] = value
            await send(message)

        await response(scope, receive, add_headers)


def loopback_panel_origin(host: str, port: int) -> str:
    if port < 1024 or port > 65535:
        raise ValueError("control panel port must be between 1024 and 65535")
    try:
        address = ip_address(host)
    except ValueError as error:
        raise ValueError("control panel host must be a loopback IP address") from error
    if not address.is_loopback:
        raise ValueError("control panel host must be a loopback IP address")
    authority = f"[{address.compressed}]:{port}" if address.version == 6 else f"{address}:{port}"
    return f"http://{authority}"


def reserve_control_panel_listener(host: str = "127.0.0.1") -> tuple[socket.socket, int]:
    try:
        address = ip_address(host)
    except ValueError as error:
        raise ValueError("control panel host must be a loopback IP address") from error
    if not address.is_loopback:
        raise ValueError("control panel host must be a loopback IP address")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    for _ in range(MAX_BIND_ATTEMPTS):
        port = EPHEMERAL_PORT_START + secrets.randbelow(EPHEMERAL_PORT_COUNT)
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            if address.version == 6:
                listener.bind((address.compressed, port, 0, 0))
            else:
                listener.bind((address.compressed, port))
            listener.listen(128)
            listener.setblocking(False)
            return listener, port
        except OSError as error:
            listener.close()
            if error.errno != errno.EADDRINUSE:
                raise
    raise OSError("unable to reserve a fresh control panel origin")


def create_control_panel_app(
    settings: Settings,
    *,
    host: str,
    port: int,
    encrypted_evidence_reader: EncryptedEvidenceReader | None = None,
    encrypted_evidence_purger: EncryptedEvidencePurger | None = None,
    evidence_publication_policy: EvidencePublicationPolicy | None = None,
) -> ASGIApp:
    origin = loopback_panel_origin(host, port)
    authority = origin.removeprefix("http://")
    ledger = Ledger(
        settings,
        read_only=True,
        require_checkpointed=False,
        encrypted_evidence_reader=encrypted_evidence_reader,
        encrypted_evidence_purger=encrypted_evidence_purger,
        evidence_publication_policy=evidence_publication_policy,
    )
    application = MemoryApplication(ledger)

    def writable_application() -> MemoryApplication:
        return MemoryApplication(
            Ledger(
                settings,
                encrypted_evidence_reader=encrypted_evidence_reader,
                encrypted_evidence_purger=encrypted_evidence_purger,
                evidence_publication_policy=evidence_publication_policy,
            )
        )

    async def panel(_: Request) -> Response:
        return HTMLResponse(_PANEL_HTML)

    async def stylesheet(_: Request) -> Response:
        return Response(_PANEL_CSS, media_type="text/css")

    async def script(_: Request) -> Response:
        return Response(_PANEL_JS, media_type="text/javascript")

    async def favicon(_: Request) -> Response:
        return Response(status_code=204)

    async def health(_: Request) -> Response:
        return JSONResponse(application.health())

    async def overview(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            return JSONResponse(application.operations_overview(principal_or_response))
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (OSError, RuntimeError, sqlite3.Error, ValueError):
            return _api_error(503, "overview_unavailable")

    async def administration(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            return JSONResponse(application.administration(principal_or_response))
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (OSError, RuntimeError, sqlite3.Error, ValueError):
            return _api_error(503, "administration_unavailable")

    async def search(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            search_request = _parse_search_request(payload)
        except ValueError:
            return _api_error(400, "invalid_search_request")
        try:
            return JSONResponse(
                writable_application().search(principal_or_response, search_request)
            )
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (OSError, RuntimeError, ValueError, sqlite3.Error):
            return _api_error(503, "search_unavailable")

    async def evidence(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            event_id = _required_bounded_string(
                payload,
                "event_id",
                max_bytes=MAX_EVENT_ID_BYTES,
            )
            if set(payload) != {"event_id"}:
                raise ValueError("evidence request keys are invalid")
        except ValueError:
            return _api_error(400, "invalid_evidence_request")
        try:
            return JSONResponse(application.get_evidence(principal_or_response, event_id))
        except KeyError:
            return _api_error(404, "evidence_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (OSError, RuntimeError, ValueError, sqlite3.Error):
            return _api_error(503, "evidence_unavailable")

    async def propose(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            proposal = _parse_proposal_request(payload, principal_or_response)
        except ValueError:
            return _api_error(400, "invalid_proposal_request")
        try:
            result = writable_application().propose(principal_or_response, proposal)
            return JSONResponse(result, status_code=201)
        except KeyError:
            return _api_error(404, "proposal_evidence_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "proposal_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "proposal_unavailable")

    async def review_candidate(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            review = _parse_candidate_review_request(payload)
        except ValueError:
            return _api_error(400, "invalid_candidate_review_request")
        try:
            return JSONResponse(
                writable_application().review_candidate(principal_or_response, review)
            )
        except KeyError:
            return _api_error(404, "candidate_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (RuntimeError, ValueError):
            return _api_error(409, "candidate_review_rejected")
        except (OSError, sqlite3.Error):
            return _api_error(503, "candidate_review_unavailable")

    async def register_client(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            label, kind, capabilities = _parse_client_registration(payload)
        except ValueError:
            return _api_error(400, "invalid_client_request")
        try:
            result = writable_application().register_client(
                principal_or_response,
                label=label,
                kind=kind,
                capabilities=capabilities,
            )
            return JSONResponse(result, status_code=201)
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "client_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "client_unavailable")

    async def issue_credential(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            client_id, ttl_hours = _parse_credential_issue(payload)
        except ValueError:
            return _api_error(400, "invalid_credential_request")
        try:
            result = writable_application().issue_client_credential(
                principal_or_response,
                client_id,
                expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
            )
            return JSONResponse(result, status_code=201)
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "credential_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "credential_unavailable")

    async def revoke_credential(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            credential_id = _only_bounded_string(
                payload,
                "credential_id",
                max_bytes=256,
            )
        except ValueError:
            return _api_error(400, "invalid_credential_request")
        try:
            result = writable_application().revoke_client_credential(
                principal_or_response,
                credential_id,
            )
            return JSONResponse(result)
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "credential_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "credential_unavailable")

    async def create_enrollment(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            enrollment_request = _parse_enrollment_request(payload)
        except ValueError:
            return _api_error(400, "invalid_enrollment_request")
        try:
            result = writable_application().create_device_enrollment(
                principal_or_response,
                enrollment_request,
            )
            return JSONResponse(result, status_code=201)
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "enrollment_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "enrollment_unavailable")

    async def register_source_account(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            registration = _parse_source_account_registration(payload)
        except ValueError:
            return _api_error(400, "invalid_source_account_request")
        try:
            result = writable_application().register_source_account(
                principal_or_response,
                registration,
            )
            return JSONResponse(result, status_code=201)
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "source_account_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "source_account_unavailable")

    async def plan_deletion(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            deletion_request = _parse_deletion_plan_request(payload)
        except ValueError:
            return _api_error(400, "invalid_deletion_plan_request")
        try:
            return JSONResponse(
                application.plan_deletion(principal_or_response, deletion_request),
                status_code=201,
            )
        except KeyError:
            return _api_error(404, "deletion_target_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "deletion_plan_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "deletion_plan_unavailable")

    async def plan_correction(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            correction_request = _parse_correction_plan_request(payload)
        except ValueError:
            return _api_error(400, "invalid_correction_plan_request")
        try:
            return JSONResponse(
                application.plan_event_policy_correction(
                    principal_or_response,
                    correction_request,
                ),
                status_code=201,
            )
        except KeyError:
            return _api_error(404, "correction_target_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except ValueError:
            return _api_error(409, "correction_plan_rejected")
        except (OSError, RuntimeError, sqlite3.Error):
            return _api_error(503, "correction_plan_unavailable")

    async def apply_correction(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            plan, expected_plan_sha256 = _parse_correction_apply_request(payload)
        except ValueError:
            return _api_error(400, "invalid_correction_apply_request")
        try:
            return JSONResponse(
                application.apply_event_policy_correction(
                    principal_or_response,
                    plan=plan,
                    expected_plan_sha256=expected_plan_sha256,
                    execute=True,
                )
            )
        except KeyError:
            return _api_error(404, "correction_target_not_found")
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (RuntimeError, ValueError):
            return _api_error(409, "correction_plan_conflict")
        except (OSError, sqlite3.Error):
            return _api_error(503, "correction_unavailable")

    async def apply_deletion(request: Request) -> Response:
        principal_or_response = _authenticate(request, application)
        if isinstance(principal_or_response, Response):
            return principal_or_response
        try:
            payload = await _bounded_json_object(request)
            plan, expected_plan_sha256 = _parse_deletion_apply_request(payload)
        except ValueError:
            return _api_error(400, "invalid_deletion_apply_request")
        try:
            return JSONResponse(
                application.apply_deletion(
                    principal_or_response,
                    plan=plan,
                    expected_plan_sha256=expected_plan_sha256,
                    execute=True,
                )
            )
        except PermissionError:
            return _api_error(403, "insufficient_capability")
        except (RuntimeError, ValueError):
            return _api_error(409, "deletion_plan_conflict")
        except (OSError, sqlite3.Error):
            return _api_error(503, "deletion_unavailable")

    app = Starlette(
        debug=False,
        routes=[
            Route("/", panel, methods=["GET"]),
            Route("/assets/panel.css", stylesheet, methods=["GET"]),
            Route("/assets/panel.js", script, methods=["GET"]),
            Route("/favicon.ico", favicon, methods=["GET"]),
            Route("/health", health, methods=["GET"]),
            Route("/api/overview", overview, methods=["GET"]),
            Route("/api/administration", administration, methods=["GET"]),
            Route("/api/search", search, methods=["POST"]),
            Route("/api/evidence", evidence, methods=["POST"]),
            Route("/api/candidates", propose, methods=["POST"]),
            Route("/api/candidates/review", review_candidate, methods=["POST"]),
            Route("/api/clients", register_client, methods=["POST"]),
            Route("/api/credentials", issue_credential, methods=["POST"]),
            Route("/api/credentials/revoke", revoke_credential, methods=["POST"]),
            Route("/api/enrollments", create_enrollment, methods=["POST"]),
            Route("/api/source-accounts", register_source_account, methods=["POST"]),
            Route("/api/corrections/plan", plan_correction, methods=["POST"]),
            Route("/api/corrections/apply", apply_correction, methods=["POST"]),
            Route("/api/deletions/plan", plan_deletion, methods=["POST"]),
            Route("/api/deletions/apply", apply_deletion, methods=["POST"]),
        ],
    )
    return _PanelSecurityMiddleware(app, authority=authority, origin=origin)


def _authenticate(
    request: Request,
    application: MemoryApplication,
) -> ApplicationPrincipal | Response:
    authorization = request.headers.get("authorization", "")
    if len(authorization.encode("utf-8")) > 1024:
        return _api_error(401, "authentication_required", authenticate=True)
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or " " in token:
        return _api_error(401, "authentication_required", authenticate=True)
    try:
        principal = application.authenticate_token(token)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return _api_error(503, "authentication_unavailable")
    if principal is None:
        return _api_error(401, "authentication_required", authenticate=True)
    if (
        principal.kind is not ClientKind.LOCAL_ADMIN
        or Capability.CLIENT_ADMIN not in principal.capabilities
    ):
        return _api_error(403, "local_admin_required")
    return principal


async def _bounded_json_object(request: Request) -> dict[str, object]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        raise ValueError("request content type must be application/json")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise ValueError("request content length is invalid") from error
        if declared_length < 0 or declared_length > MAX_JSON_BODY_BYTES:
            raise ValueError("request body exceeds its size limit")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_JSON_BODY_BYTES:
            raise ValueError("request body exceeds its size limit")
    try:
        value: object = json.loads(body, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("request body is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("request body must be a JSON object")
    return cast(dict[str, object], value)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("request body contains duplicate JSON keys")
        value[key] = item
    return value


def _parse_search_request(payload: dict[str, object]) -> SearchMemoryRequest:
    allowed_keys = {
        "query",
        "mode",
        "scopes",
        "project_id",
        "authorities",
        "contexts",
        "limit",
        "retrieval_control",
    }
    if set(payload) - allowed_keys:
        raise ValueError("search request keys are invalid")
    query = _required_string(payload, "query")
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES or "\x00" in query:
        raise ValueError("search query is invalid")
    mode = QueryMode(_optional_string(payload, "mode") or QueryMode.FIND_EVIDENCE.value)
    project_id_value = payload.get("project_id")
    if project_id_value is None:
        project_id = None
    elif isinstance(project_id_value, str):
        project_id = _bounded_value(project_id_value, "project_id", 512)
    else:
        raise ValueError("project_id is invalid")
    scopes = _enum_list(payload.get("scopes"), Scope, default=tuple(Scope))
    authorities = _enum_list(payload.get("authorities"), Authority, default=None)
    contexts = _context_list(payload.get("contexts"))
    limit_value = payload.get("limit", 5)
    if isinstance(limit_value, bool) or not isinstance(limit_value, int):
        raise ValueError("limit is invalid")
    if limit_value < 1 or limit_value > MAX_RESULTS:
        raise ValueError("limit is invalid")
    control = RetrievalControl(
        _optional_string(payload, "retrieval_control") or RetrievalControl.AUTO.value
    )
    return SearchMemoryRequest(
        query=query,
        mode=mode,
        scopes=cast(tuple[Scope, ...], scopes),
        project_id=project_id,
        authorities=authorities,
        limit=limit_value,
        contexts=contexts,
        retrieval_control=control,
    )


def _parse_proposal_request(
    payload: dict[str, object],
    principal: ApplicationPrincipal,
) -> ProposeMemoryRequest:
    allowed_keys = {
        "statement",
        "memory_type",
        "evidence_event_ids",
        "scope",
        "project_id",
        "pending_web_evidence",
    }
    if set(payload) - allowed_keys:
        raise ValueError("proposal request keys are invalid")
    statement = _required_bounded_string(
        payload,
        "statement",
        max_bytes=MAX_STATEMENT_BYTES,
    )
    memory_type = MemoryType(_required_string(payload, "memory_type"))
    scope = Scope(_optional_string(payload, "scope") or Scope.PROJECT.value)
    project_id = _optional_bounded_string(payload, "project_id", max_bytes=512)

    evidence_value = payload.get("evidence_event_ids", [])
    if not isinstance(evidence_value, list):
        raise ValueError("proposal evidence ids are invalid")
    evidence_items = cast(list[object], evidence_value)
    if len(evidence_items) > MAX_EVIDENCE_EVENTS:
        raise ValueError("proposal evidence ids are invalid")
    evidence_ids: list[str] = []
    for value in evidence_items:
        if not isinstance(value, str):
            raise ValueError("proposal evidence ids are invalid")
        evidence_ids.append(_bounded_value(value, "event_id", MAX_EVENT_ID_BYTES))
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("proposal evidence ids contain duplicates")

    pending_value = payload.get("pending_web_evidence")
    pending = None
    if pending_value is not None:
        if not isinstance(pending_value, dict):
            raise ValueError("pending web evidence is invalid")
        fields = cast(dict[str, object], pending_value)
        if set(fields) != {
            "source_account_id",
            "source_system",
            "conversation_id",
            "message_id",
            "parent_message_id",
            "branch_id",
            "content_text",
        }:
            raise ValueError("pending web evidence is invalid")
        source_system = _required_bounded_string(
            fields,
            "source_system",
            max_bytes=64,
        )
        if SourceSystem(source_system) not in {
            SourceSystem.CHATGPT_WEB,
            SourceSystem.CLAUDE_WEB,
            SourceSystem.GROK_WEB,
        }:
            raise ValueError("pending web evidence source is invalid")
        pending = pending_web_evidence_claim(
            source_account_id=_required_bounded_string(
                fields,
                "source_account_id",
                max_bytes=256,
            ),
            source_system=source_system,
            conversation_id=_required_bounded_string(
                fields,
                "conversation_id",
                max_bytes=4096,
            ),
            message_id=_required_bounded_string(fields, "message_id", max_bytes=4096),
            parent_message_id=_optional_bounded_string(
                fields,
                "parent_message_id",
                max_bytes=4096,
            ),
            branch_id=_optional_bounded_string(fields, "branch_id", max_bytes=4096),
            content_text=_required_exact_text(
                fields,
                "content_text",
                max_bytes=MAX_STATEMENT_BYTES,
            ),
        )
    if not evidence_ids and pending is None:
        raise ValueError("proposal requires evidence")
    return ProposeMemoryRequest(
        statement=statement,
        memory_type=memory_type,
        evidence_event_ids=tuple(evidence_ids),
        scope=scope,
        project_id=project_id,
        created_by=principal.principal_id,
        pending_web_evidence=pending,
    )


def _parse_candidate_review_request(
    payload: dict[str, object],
) -> ReviewMemoryCandidateRequest:
    if set(payload) != {
        "memory_id",
        "operation",
        "expected_basis_digest",
        "reason_code",
    }:
        raise ValueError("candidate review request keys are invalid")
    return ReviewMemoryCandidateRequest(
        memory_id=_required_bounded_string(payload, "memory_id", max_bytes=256),
        operation=CandidateReviewOperation(_required_string(payload, "operation")),
        expected_basis_digest=_required_bounded_string(
            payload,
            "expected_basis_digest",
            max_bytes=64,
        ),
        reason_code=CandidateReviewReason(_required_string(payload, "reason_code")),
    )


def _parse_client_registration(
    payload: dict[str, object],
) -> tuple[str, ClientKind, tuple[Capability, ...]]:
    if set(payload) != {"label", "kind", "capabilities"}:
        raise ValueError("client request keys are invalid")
    label = _required_bounded_string(payload, "label", max_bytes=512)
    kind = ClientKind(_required_string(payload, "kind"))
    raw_capabilities = payload["capabilities"]
    if not isinstance(raw_capabilities, list):
        raise ValueError("client capabilities are invalid")
    capability_values = cast(list[object], raw_capabilities)
    if not capability_values or len(capability_values) > len(Capability):
        raise ValueError("client capabilities are invalid")
    if any(not isinstance(value, str) for value in capability_values):
        raise ValueError("client capabilities are invalid")
    capabilities = tuple(Capability(cast(str, value)) for value in capability_values)
    if len(capabilities) != len(set(capabilities)):
        raise ValueError("client capabilities contain duplicates")
    return label, kind, capabilities


def _parse_credential_issue(payload: dict[str, object]) -> tuple[str, int]:
    if set(payload) != {"client_id", "ttl_hours"}:
        raise ValueError("credential request keys are invalid")
    client_id = _required_bounded_string(payload, "client_id", max_bytes=256)
    ttl_hours = payload["ttl_hours"]
    if (
        isinstance(ttl_hours, bool)
        or not isinstance(ttl_hours, int)
        or ttl_hours < 1
        or ttl_hours > MAX_CREDENTIAL_TTL_HOURS
    ):
        raise ValueError("credential TTL is invalid")
    return client_id, ttl_hours


def _parse_enrollment_request(payload: dict[str, object]) -> CreateDeviceEnrollmentRequest:
    if set(payload) != {"label", "platform", "ttl_minutes", "credential_ttl_days"}:
        raise ValueError("enrollment request keys are invalid")
    label = _required_bounded_string(payload, "label", max_bytes=512)
    platform = _required_bounded_string(payload, "platform", max_bytes=512)
    ttl_minutes = payload["ttl_minutes"]
    credential_ttl_days = payload["credential_ttl_days"]
    if (
        isinstance(ttl_minutes, bool)
        or not isinstance(ttl_minutes, int)
        or ttl_minutes < 1
        or ttl_minutes > MAX_ENROLLMENT_TTL_MINUTES
    ):
        raise ValueError("enrollment TTL is invalid")
    if (
        isinstance(credential_ttl_days, bool)
        or not isinstance(credential_ttl_days, int)
        or credential_ttl_days < 1
        or credential_ttl_days > MAX_DEVICE_CREDENTIAL_TTL_DAYS
    ):
        raise ValueError("device credential TTL is invalid")
    now = datetime.now(UTC)
    return CreateDeviceEnrollmentRequest(
        label=label,
        platform=platform,
        expires_at=now + timedelta(minutes=ttl_minutes),
        credential_expires_at=now + timedelta(days=credential_ttl_days),
    )


def _parse_source_account_registration(
    payload: dict[str, object],
) -> RegisterSourceAccountRequest:
    if set(payload) != {
        "device_id",
        "source_system",
        "account_label",
        "scope",
        "project_id",
    }:
        raise ValueError("source-account request keys are invalid")
    return RegisterSourceAccountRequest(
        device_id=_required_bounded_string(payload, "device_id", max_bytes=256),
        source_system=SourceSystem(_required_string(payload, "source_system")),
        account_label=_required_bounded_string(payload, "account_label", max_bytes=512),
        scope=Scope(_required_string(payload, "scope")),
        project_id=_optional_bounded_string(payload, "project_id", max_bytes=512),
    )


def _parse_deletion_plan_request(payload: dict[str, object]) -> DeletionPlanRequest:
    if set(payload) != {
        "kind",
        "source_system",
        "source_account",
        "conversation_id",
        "reason",
    }:
        raise ValueError("deletion plan request keys are invalid")
    kind = DeletionKind(_required_string(payload, "kind"))
    conversation_id = _optional_bounded_string(
        payload,
        "conversation_id",
        max_bytes=4096,
    )
    if kind is DeletionKind.CONVERSATION and conversation_id is None:
        raise ValueError("conversation deletion requires a conversation id")
    if kind is DeletionKind.SOURCE_ACCOUNT and conversation_id is not None:
        raise ValueError("source-account deletion cannot include a conversation id")
    return DeletionPlanRequest(
        kind=kind,
        source_system=SourceSystem(_required_string(payload, "source_system")),
        source_account=_required_bounded_string(
            payload,
            "source_account",
            max_bytes=1024,
        ),
        conversation_id=conversation_id,
        authorization_scope="memory:delete",
        reason=_required_bounded_string(payload, "reason", max_bytes=1024),
    )


def _parse_correction_plan_request(payload: dict[str, object]) -> CorrectionPlanRequest:
    if set(payload) != {
        "event_id",
        "authority",
        "scope",
        "project_id",
        "privacy",
        "reason",
    }:
        raise ValueError("correction plan request keys are invalid")
    scope = Scope(_required_string(payload, "scope"))
    project_id = _optional_bounded_string(payload, "project_id", max_bytes=512)
    if scope is Scope.PROJECT and project_id is None:
        raise ValueError("project correction requires a project id")
    if scope is not Scope.PROJECT and project_id is not None:
        raise ValueError("non-project correction cannot carry a project id")
    return CorrectionPlanRequest(
        event_id=_required_bounded_string(payload, "event_id", max_bytes=256),
        authority=Authority(_required_string(payload, "authority")),
        scope=scope,
        project_id=project_id,
        privacy=Privacy(_required_string(payload, "privacy")),
        authorization_scope="memory:curate",
        reason=_required_bounded_string(payload, "reason", max_bytes=1024),
    )


def _parse_correction_apply_request(
    payload: dict[str, object],
) -> tuple[dict[str, object], str]:
    return _parse_hashed_plan_apply_request(payload, "correction")


def _parse_deletion_apply_request(
    payload: dict[str, object],
) -> tuple[dict[str, object], str]:
    return _parse_hashed_plan_apply_request(payload, "deletion")


def _parse_hashed_plan_apply_request(
    payload: dict[str, object],
    label: str,
) -> tuple[dict[str, object], str]:
    if set(payload) != {"plan", "expected_plan_sha256", "execute"}:
        raise ValueError(f"{label} apply request keys are invalid")
    plan = payload["plan"]
    if not isinstance(plan, dict) or payload["execute"] is not True:
        raise ValueError(f"{label} apply request is invalid")
    digest = _required_bounded_string(payload, "expected_plan_sha256", max_bytes=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{label} plan digest is invalid")
    return cast(dict[str, object], plan), digest


def _context_list(value: object) -> tuple[ContextFilter, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("contexts are invalid")
    values = cast(list[object], value)
    if len(values) > MAX_CONTEXTS:
        raise ValueError("contexts are invalid")
    contexts: list[ContextFilter] = []
    for raw in values:
        if not isinstance(raw, dict):
            raise ValueError("context is invalid")
        item = cast(dict[str, object], raw)
        if set(item) != {"kind", "key"}:
            raise ValueError("context is invalid")
        kind = ContextKind(_required_string(item, "kind"))
        key = _required_bounded_string(item, "key", max_bytes=512)
        contexts.append(ContextFilter(kind=kind, key=key))
    return tuple(contexts)


def _enum_list(
    value: object,
    enum_type: type[EnumItem],
    *,
    default: tuple[EnumItem, ...] | None,
) -> tuple[EnumItem, ...] | None:
    if value is None:
        return default
    if not isinstance(value, list):
        raise ValueError("enum list is invalid")
    values = cast(list[object], value)
    if not values or any(not isinstance(item, str) for item in values):
        raise ValueError("enum list is invalid")
    try:
        converted = tuple(enum_type(cast(str, item)) for item in values)
    except (TypeError, ValueError) as error:
        raise ValueError("enum list is invalid") from error
    if len(set(converted)) != len(converted):
        raise ValueError("enum list contains duplicates")
    return converted


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} is required")
    return value


def _optional_string(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} is invalid")
    return value


def _optional_bounded_string(
    payload: dict[str, object],
    key: str,
    *,
    max_bytes: int,
) -> str | None:
    value = _optional_string(payload, key)
    return None if value is None else _bounded_value(value, key, max_bytes)


def _required_bounded_string(
    payload: dict[str, object],
    key: str,
    *,
    max_bytes: int,
) -> str:
    return _bounded_value(_required_string(payload, key), key, max_bytes)


def _required_exact_text(
    payload: dict[str, object],
    key: str,
    *,
    max_bytes: int,
) -> str:
    value = _required_string(payload, key)
    if not value.strip() or "\0" in value or len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{key} is invalid")
    return value


def _only_bounded_string(
    payload: dict[str, object],
    key: str,
    *,
    max_bytes: int,
) -> str:
    if set(payload) != {key}:
        raise ValueError(f"{key} request keys are invalid")
    return _required_bounded_string(payload, key, max_bytes=max_bytes)


def _bounded_value(value: str, label: str, max_bytes: int) -> str:
    if not value or value != value.strip() or "\x00" in value:
        raise ValueError(f"{label} is invalid")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} is invalid")
    return value


def _api_error(status_code: int, error: str, *, authenticate: bool = False) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if authenticate else None
    return JSONResponse({"status": "error", "error": error}, status_code, headers=headers)
