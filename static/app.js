const $ = id => document.getElementById(id);

// API base can be supplied by a meta tag, localStorage, or the current origin.
// This keeps the UI usable on GitHub Pages while allowing the scanner backend
// to run separately on Python-capable hosting such as Render.
const API_BASE = String(
  document.querySelector('meta[name="api-base"]')?.content ||
  localStorage.getItem("clickjacking_api_base") ||
  ""
).replace(/\/$/, "");

async function api(path, options) {
  return fetch(API_BASE + path, options);
}

function normalizeUrl(value) {
  let url = String(value || "").trim();
  if (!url) return "";
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  return url;
}

function setStatus(text, state) {
  const el = $("scanStatus");
  el.className = "status-pill " + (state || "ready");
  el.innerHTML = "<i></i> " + text;
}

function stateClass(state) {
  return String(state || "").toLowerCase().replace(/[^a-z0-9_]+/g, "-");
}

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>'"]/g, ch => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"
  }[ch] || ch));
}

function browserLabel(browser) {
  if (!browser) return "—";
  if (browser.status === "FRAME_REACHED") return "FRAME REACHED";
  if (browser.status === "FRAME_BLOCKED_OR_UNREACHABLE") return "NOT REACHED";
  return "CHECK ERROR";
}

function renderAffectedPages(data) {
  const box = $("affectedPages");
  const vuln = (data.results || []).filter(r => r.state === "VULNERABLE");
  if (!vuln.length) {
    box.innerHTML = '<span class="muted">No confirmed vulnerable pages.</span>';
    return;
  }
  box.innerHTML = vuln.map(r =>
    '<div class="affected-item"><span class="dot"></span><span>' +
    escapeHtml(r.url) + '</span></div>'
  ).join("");
}

function renderResults(data) {
  const box = $("results");
  const empty = $("empty");
  box.innerHTML = "";
  empty.style.display = data.results.length ? "none" : "grid";

  for (const row of data.results) {
    const reasons = (row.reasons || []).map(x => "<li>" + escapeHtml(x) + "</li>").join("");
    const controls = [];
    if (row.x_frame_options) controls.push("XFO: " + escapeHtml(row.x_frame_options));
    if (row.csp_frame_ancestors) controls.push("CSP: frame-ancestors " + escapeHtml(row.csp_frame_ancestors));
    const controlText = controls.length ? controls.join("<br>") : "No explicit anti-framing header";

    const node = document.createElement("article");
    node.className = "result-row";
    node.innerHTML =
      '<div class="page-cell">' +
        '<div class="url">' + escapeHtml(row.url) + "</div>" +
        (row.final_url && row.final_url !== row.url ? '<div class="final">→ ' + escapeHtml(row.final_url) + "</div>" : "") +
        '<ul class="reasons">' + reasons + "</ul>" +
      "</div>" +
      '<div class="http">' + escapeHtml(row.status_code || "—") + "</div>" +
      '<div><span class="state ' + stateClass(row.state) + '">' + escapeHtml(row.state) + "</span>" +
        "<small>" + escapeHtml(row.confidence || "") + "</small></div>" +
      '<div class="control">' + controlText + "</div>" +
      '<div><span class="browser">' + browserLabel(row.browser) + "</span></div>";

    box.appendChild(node);
  }

  $("mScanned").textContent = data.pages_scanned || 0;
  $("mVuln").textContent = data.counts && data.counts.VULNERABLE || 0;
  $("mProtected").textContent = data.counts && data.counts.PROTECTED || 0;
  $("mReview").textContent =
    ((data.counts && data.counts.REVIEW) || 0) +
    ((data.counts && data.counts.UNPROTECTED) || 0);
  $("targetDisplay").textContent = data.target || "Ready";
  renderAffectedPages(data);
}

async function scanSite() {
  const url = normalizeUrl($("urlInput").value);
  const maxPages = Math.max(1, Math.min(25, Number($("pagesInput").value) || 15));
  const browserVerify = $("browserVerify").checked;

  if (!/^https?:\/\//i.test(url)) return;

  $("scanBtn").disabled = true;
  setStatus("SCANNING", "loading");
  $("targetDisplay").textContent = url;

  try {
    const response = await api("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        url: url,
        max_pages: maxPages,
        browser_verify: browserVerify
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed");

    renderResults(data);
    setStatus(
      (data.counts && data.counts.VULNERABLE) ? "EXPOSURE FOUND" : "SCAN COMPLETE",
      (data.counts && data.counts.VULNERABLE) ? "danger" : "loaded"
    );
  } catch (error) {
    setStatus("ERROR", "danger");
    $("results").innerHTML = '<div class="error-box">' + escapeHtml(error.message) + "</div>";
    $("empty").style.display = "none";
  } finally {
    $("scanBtn").disabled = false;
  }
}

$("scanBtn").onclick = scanSite;
$("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter") scanSite();
});

$("resetBtn").onclick = () => {
  $("urlInput").value = "https://example.com/";
  $("pagesInput").value = 15;
  $("results").innerHTML = "";
  $("empty").style.display = "grid";
  $("mScanned").textContent = "0";
  $("mVuln").textContent = "0";
  $("mProtected").textContent = "0";
  $("mReview").textContent = "0";
  $("targetDisplay").textContent = "Ready";
  $("affectedPages").innerHTML = '<span class="muted">No scan yet.</span>';
  setStatus("READY", "ready");
};

$("openTarget").onclick = () => {
  const url = normalizeUrl($("urlInput").value);
  if (/^https?:\/\//i.test(url)) window.open(url, "_blank", "noopener,noreferrer");
};

$("fullscreen").onclick = async () => {
  const el = document.querySelector(".results-wrap");
  if (!document.fullscreenElement) await (el.requestFullscreen && el.requestFullscreen());
  else await document.exitFullscreen();
};