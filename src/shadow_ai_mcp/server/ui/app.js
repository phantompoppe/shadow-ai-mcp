"use strict";

const $ = (id) => document.getElementById(id);
const state = { filters: {}, cursors: [null], page: 0, nextCursor: null, sequence: 0, focusReturn: null };
const detectionNames = {
  "SHAI-001": "Proxy bypass",
  "SHAI-002": "Required AI route",
  "SHAI-003": "Gateway bypass",
  "SHAI-004": "Unapproved MCP server",
  "SHAI-005": "Expired approval",
};
const sourceNames = { siem: "Central logs", llm_proxy: "LLM proxy", mcp_gateway: "MCP gateway", registry: "Approval registry" };

function node(tag, className = "", value = "") {
  const item = document.createElement(tag);
  if (className) item.className = className;
  item.textContent = value == null ? "—" : String(value);
  return item;
}

function clear(element) { element.replaceChildren(); }
function safe(value, fallback = "—") { return value == null || value === "" ? fallback : String(value); }
function stamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-US", { timeZone: "UTC", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }).format(date) + " UTC";
}
function setText(id, value) { $(id).textContent = value; }
function addParagraph(parent, value) { parent.append(node("p", "", value)); }
function addKeyValue(parent, label, value) {
  const box = node("div", "key-value");
  box.append(node("small", "", label), node("span", "", safe(value)));
  parent.append(box);
}
function addList(parent, values, fallback = "No additional evidence available") {
  if (!values || !values.length) { addParagraph(parent, fallback); return; }
  const list = node("ul");
  values.forEach((value) => list.append(node("li", "", value)));
  parent.append(list);
}
function section(parent, title) { const box = node("section", "detail-section"); box.append(node("h3", "", title)); parent.append(box); return box; }

async function requestJSON(path, body) {
  const options = { headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { throw new Error("The service returned an unreadable response."); }
  if (!response.ok || data.error) throw new Error(data.error?.message || data.message || "The request failed.");
  return data;
}

function switchView(view) {
  for (const name of ["findings", "registry", "telemetry"]) {
    const active = name === view;
    $(`${name}-view`).hidden = !active;
    $(`${name}-view`).classList.toggle("active", active);
    const button = document.querySelector(`[data-view="${name}"]`);
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  }
  setText("breadcrumb-title", { findings: "Findings", registry: "Approval registry", telemetry: "Telemetry health" }[view]);
  window.scrollTo({ top: 0, behavior: "instant" });
}

function renderCoverage(freshness = {}, warnings = []) {
  const entries = Object.entries(freshness);
  const healthy = entries.filter(([, item]) => item.health === "healthy" && !item.stale).length;
  const banner = $("coverage-banner");
  banner.classList.toggle("warning", warnings.length > 0);
  setText("coverage-title", warnings.length ? "Coverage needs attention" : "Telemetry coverage is current");
  setText("coverage-detail", warnings.length ? `${warnings.length} warning${warnings.length === 1 ? "" : "s"}: ${warnings.slice(0, 2).join(" · ")}` : "Configured sources synchronized successfully. Interpret findings with their individual evidence.");
  setText("metric-sources", `${healthy}/${entries.length || 4}`);
  setText("metric-sources-foot", warnings.length ? "Coverage gaps present" : "Sources reporting healthy");
  const grid = $("health-grid"); clear(grid);
  for (const [id, item] of entries) {
    const card = node("article", "health-card");
    const top = node("div", "health-card-top");
    const label = node("div");
    label.append(node("strong", "", sourceNames[item.source_type] || item.source_type), node("small", "", id.startsWith("missing:") ? "Not configured" : id));
    top.append(label, node("span", `health-state ${item.stale || item.health !== "healthy" ? "bad" : "good"}`, item.stale || item.health !== "healthy" ? "Gap" : "Healthy"));
    const meta = node("div", "health-meta");
    meta.append(node("span", "", `Last sync  ${stamp(item.last_success)}`), node("br"), node("span", "", `Latest event  ${stamp(item.latest_observation)}`));
    card.append(top, meta); grid.append(card);
  }
  setText("health-count", `${healthy} / ${entries.length || 4} healthy`);
  const note = $("health-note"); note.classList.toggle("ok", warnings.length === 0);
  note.textContent = warnings.length ? warnings.join(" · ") : "No configured connector reported a freshness warning. Source delay and field coverage still require review.";
}

function renderFindings(data) {
  const body = $("findings-body"); clear(body);
  const findings = data.findings || [];
  for (const finding of findings) {
    const row = node("tr"); row.tabIndex = 0;
    row.setAttribute("aria-label", `Open finding ${finding.detection_id}: ${finding.title}`);
    const title = node("td", "finding-cell"); title.append(node("strong", "", finding.title), node("span", "", `${finding.detection_id} · ${detectionNames[finding.detection_id] || "Detection"}`));
    const severity = node("td"); severity.append(node("span", `pill severity-${finding.severity}`, finding.severity));
    const actor = node("td", "actor-cell", finding.user_id || finding.device_id || finding.application_id || "Identity unavailable");
    const destination = node("td", "destination-cell", finding.destination || finding.provider || finding.mcp_server_id || "—");
    const confidence = node("td", `confidence-${finding.confidence}`, finding.confidence);
    const lastSeen = node("td", "time-cell", stamp(finding.last_seen));
    row.append(title, severity, actor, destination, confidence, lastSeen, node("td", "row-arrow", "›"));
    row.addEventListener("click", () => openFinding(finding.finding_id));
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openFinding(finding.finding_id); } });
    body.append(row);
  }
  setText("findings-state", findings.length ? "" : "No findings match these filters. Try clearing a filter or check telemetry coverage.");
  setText("result-counter", `${findings.length} on this page`);
  setText("nav-count", String(findings.length));
  setText("metric-findings", String(findings.length));
  setText("metric-high", String(findings.filter((f) => ["high", "critical"].includes(f.severity)).length));
  setText("metric-mcp", String(findings.filter((f) => ["SHAI-003", "SHAI-004"].includes(f.detection_id)).length));
  setText("page-label", `Page ${state.page + 1}`);
  $("previous-page").disabled = state.page === 0;
  state.nextCursor = data.next_cursor;
  $("next-page").disabled = !data.next_cursor;
  renderCoverage(data.telemetry_freshness, data.warnings);
}

async function loadFindings() {
  const sequence = ++state.sequence;
  setText("findings-state", "Loading findings…");
  const filters = { limit: 25 };
  for (const [key, value] of Object.entries(state.filters)) if (value) filters[key] = key === "detection_ids" || key === "severities" || key === "confidence_levels" ? [value] : value;
  if (state.cursors[state.page]) filters.cursor = state.cursors[state.page];
  try {
    const data = await requestJSON("./api/findings", filters);
    if (sequence === state.sequence) renderFindings(data);
  } catch (error) {
    if (sequence === state.sequence) {
      clear($("findings-body"));
      setText("findings-state", `Could not load findings: ${error.message}`);
      setText("result-counter", "Unavailable");
    }
  }
}

function closeFinding() {
  $("detail-drawer").hidden = true;
  $("drawer-backdrop").hidden = true;
  document.querySelector(".app-shell").inert = false;
  document.body.style.overflow = "";
  state.focusReturn?.focus();
}

function renderFinding(finding, detail, explanation) {
  const container = $("detail-content"); clear(container);
  container.append(node("div", "detail-id", finding.detection_id));
  container.append(node("h2", "", finding.title));
  const meta = node("div", "detail-meta");
  meta.append(node("span", `pill severity-${finding.severity}`, finding.severity), node("span", `confidence-${finding.confidence}`, `${finding.confidence} confidence`));
  container.append(meta);
  addParagraph(container, finding.summary);

  const observed = section(container, "WHAT WAS OBSERVED");
  addParagraph(observed, explanation?.what_was_observed || finding.summary);
  const fields = node("div", "detail-grid");
  addKeyValue(fields, "First seen", stamp(finding.first_seen));
  addKeyValue(fields, "Last seen", stamp(finding.last_seen));
  addKeyValue(fields, "User / device", finding.user_id || finding.device_id);
  addKeyValue(fields, "Destination", finding.destination || finding.mcp_server_id);
  addKeyValue(fields, "Expected route", finding.required_route || "Not specified");
  addKeyValue(fields, "Observed route", finding.observed_route || "Not observed");
  addKeyValue(fields, "Occurrences", finding.occurrence_count);
  addKeyValue(fields, "Approval", finding.approval_status || "Unmatched");
  observed.append(fields);

  const reasons = section(container, "WHY THIS WAS FLAGGED");
  addList(reasons, finding.reason_codes, "No reason codes recorded");
  const confidence = section(container, "CONFIDENCE & LIMITS");
  addParagraph(confidence, explanation?.confidence_explanation || finding.explanation);
  addList(confidence, explanation?.evidence_not_available, "No additional telemetry gaps reported");
  const evidence = section(container, "EVIDENCE REFERENCES");
  for (const reference of finding.evidence_references || []) evidence.append(node("div", "evidence-item", reference));
  if (!finding.evidence_references?.length) addParagraph(evidence, "No references available");
  if (detail.asset) {
    const asset = section(container, "MATCHED REGISTRY ASSET");
    const assetFields = node("div", "detail-grid");
    addKeyValue(assetFields, "Asset", detail.asset.name);
    addKeyValue(assetFields, "Owner", detail.asset.owner);
    addKeyValue(assetFields, "Risk tier", detail.asset.risk_tier);
    addKeyValue(assetFields, "Expiration", stamp(detail.asset.expiration_date));
    asset.append(assetFields);
  }
  const steps = section(container, "HUMAN INVESTIGATION STEPS");
  addList(steps, explanation?.recommended_steps || finding.recommended_investigation_steps);
  const caveats = section(container, "POSSIBLE FALSE POSITIVES");
  addList(caveats, explanation?.likely_false_positives);
}

async function openFinding(findingId) {
  state.focusReturn = document.activeElement;
  $("detail-drawer").hidden = false;
  $("drawer-backdrop").hidden = false;
  document.querySelector(".app-shell").inert = true;
  document.body.style.overflow = "hidden";
  setText("detail-content", "Loading finding and explanation…");
  $("close-drawer").focus();
  try {
    const [detail, explained] = await Promise.all([
      requestJSON(`./api/findings/${encodeURIComponent(findingId)}`),
      requestJSON(`./api/findings/${encodeURIComponent(findingId)}/explanation`),
    ]);
    if (!$("detail-drawer").hidden) renderFinding(detail.finding, detail, explained.details);
  } catch (error) { setText("detail-content", `Could not load finding: ${error.message}`); }
}

async function checkApproval(event) {
  event.preventDefault();
  const kind = $("approval-kind").value;
  const value = $("approval-value").value.trim();
  if (!value) return;
  const result = $("approval-result"); clear(result);
  if (kind === "endpoint" && /[?#]/.test(value)) {
    result.append(node("strong", "", "Enter an endpoint without query parameters or fragments."));
    return;
  }
  result.append(node("p", "", "Checking registry…"));
  try {
    const data = await requestJSON("./api/approval", { [kind]: value }); clear(result);
    if (!data.asset) {
      result.append(node("strong", "", "No registry match found"));
      addParagraph(result, "This only describes the current imported registry. Check coverage before treating an unmatched asset as unapproved.");
    } else {
      result.append(node("span", `pill ${data.details.expired ? "severity-high" : "severity-low"}`, data.details.expired ? "Expired" : data.asset.approval_status));
      result.append(node("h2", "", data.asset.name));
      const grid = node("div", "approval-grid");
      addKeyValue(grid, "Asset ID", data.asset.asset_id);
      addKeyValue(grid, "Asset type", data.asset.asset_type);
      addKeyValue(grid, "Required route", data.details.required_route);
      addKeyValue(grid, "Owner", data.details.owner);
      addKeyValue(grid, "Risk tier", data.details.risk_tier);
      addKeyValue(grid, "Expiration", stamp(data.asset.expiration_date));
      addKeyValue(grid, "Endpoint", data.asset.canonical_endpoint);
      addKeyValue(grid, "Match method", data.details.match_method);
      result.append(grid);
      if (data.details.ambiguous) result.append(node("p", "approval-warning", "Multiple assets matched. Verify the asset ID before drawing a conclusion."));
    }
    if (data.warnings?.length) result.append(node("p", "approval-warning", data.warnings.join(" · ")));
  } catch (error) { clear(result); result.append(node("strong", "", `Lookup failed: ${error.message}`)); }
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
$("view-health").addEventListener("click", () => switchView("telemetry"));
$("filters-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.filters = {
    destination: $("filter-destination").value.trim(),
    detection_ids: $("filter-detection").value,
    severities: $("filter-severity").value,
    confidence_levels: $("filter-confidence").value,
  };
  state.cursors = [null]; state.page = 0; loadFindings();
});
$("clear-filters").addEventListener("click", () => { $("filters-form").reset(); state.filters = {}; state.cursors = [null]; state.page = 0; loadFindings(); });
$("next-page").addEventListener("click", () => { if (state.nextCursor) { state.cursors.push(state.nextCursor); state.page += 1; loadFindings(); } });
$("previous-page").addEventListener("click", () => { if (state.page > 0) { state.page -= 1; state.cursors.pop(); loadFindings(); } });
$("approval-form").addEventListener("submit", checkApproval);
$("close-drawer").addEventListener("click", closeFinding);
$("drawer-backdrop").addEventListener("click", closeFinding);
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !$("detail-drawer").hidden) closeFinding(); });
setText("utc-clock", new Intl.DateTimeFormat("en-US", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date()) + " UTC");
loadFindings();
