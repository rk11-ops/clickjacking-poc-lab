const $ = id => document.getElementById(id);

// API base can be supplied by a meta tag, localStorage, or the current origin.
// This keeps the UI usable on GitHub Pages while allowing the scanner backend
// to run separately on Python-capable hosting such as Render.
const API_BASE = String(
  document.querySelector('meta[name="api-base"]')?.content ||
  localStorage.getItem("clickjacking_api_base") ||
  ""
).replace(/\\/$/, "");

async function api(path, options) {
  return fetch(API_BASE + path, options);
}

async function assertApiReady() {
  const response = await api("/api/health", { method: "GET" });
  const type = response.headers.get("content-type") || "";
  if (!type.includes("application/json")) {
    throw new Error("Scanner backend is not connected. The frontend reached an HTML page instead of the scanner API.");
  }
  const data = await response.json();
  if (!response.ok || !data.ok) {
    throw new Error("Scanner backend is not healthy.");
  }
  return data;
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
  if (browser.status === "IFRAME_ATTEMPTED") return "ATTEMPTED";
  return "CHECK ERROR";
}

function renderAffectedPages(data) {
  const box = $("affectedPages");
  const vuln = (data.results || []).filter(r => r.state === "VULNERABLE");
  if (!vuln.length) {
    box.innerHTML = '<span class="muted">No header-exposed pages found.</span>';
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
    ((data.counts && data.counts.ERROR) || 0) +
    ((data.counts && data.counts.UNPROTECTED) || 0);
  $("targetDisplay").textContent = data.target || "Ready";
  renderAffectedPages(data);
}

async function publicHeaderCheck(url) {
  const res = await fetch("https://api.domainee.dev/v1/tools/http-header-checker?url=" + encodeURIComponent(url), {credentials:"omit"});
  const type = res.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("Header service returned a non-JSON response.");
  const body = await res.json();
  if (!body.ok) throw new Error(body.error?.message || "Header check failed.");
  return body.data;
}

async function publicFetchHtml(url) {
  try {
    const direct = await fetch(url, {credentials:"omit", redirect:"follow"});
    const type = direct.headers.get("content-type") || "";
    if (direct.ok && (type.includes("text/html") || type.includes("application/xhtml+xml"))) {
      return {html: await direct.text(), finalUrl: direct.url || url};
    }
  } catch (_) {}
  const proxy = await fetch("https://proxy.cors.dev/" + url, {credentials:"omit"});
  if (!proxy.ok) throw new Error("Unable to fetch HTML for crawling (" + proxy.status + ").");
  return {html: await proxy.text(), finalUrl: url};
}

function clientTargetGuard(raw) {
  const u = new URL(raw);
  const h = u.hostname.toLowerCase();
  if (!["http:","https:"].includes(u.protocol)) throw new Error("Only HTTP/HTTPS targets are supported.");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h === "0.0.0.0" || h === "::1") {
    throw new Error("Local/private hostnames are blocked.");
  }
  if (/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(h)) {
    const [a,b] = h.split(".").map(Number);
    if (a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) {
      throw new Error("Private, loopback, link-local, or CGNAT IP targets are blocked.");
    }
  }
  return u;
}

function clientExtractLinks(html, base, origin) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const links = [];
  const seen = new Set();
  for (const a of doc.querySelectorAll("a[href]")) {
    const href = a.getAttribute("href") || "";
    if (!href || /^(#|mailto:|tel:|javascript:|data:|blob:)/i.test(href)) continue;
    try {
      const u = new URL(href, base);
      u.hash = "";
      if (!["http:","https:"].includes(u.protocol) || u.origin !== origin) continue;
      const s = u.toString();
      if (!seen.has(s)) { seen.add(s); links.push(s); }
    } catch (_) {}
    if (links.length >= 100) break;
  }
  return links;
}

function clientPolicy(data) {
  const headers = Object.fromEntries(Object.entries(data.headers || {}).map(([k,v]) => [k.toLowerCase(), v]));
  const xfo = String(headers["x-frame-options"] || "").trim();
  const csp = String(headers["content-security-policy"] || "").trim();
  let ancestors = null;
  for (const part of csp.split(";")) {
    const bits = part.trim().split(/\\s+/);
    if (bits[0]?.toLowerCase() === "frame-ancestors") { ancestors = bits.slice(1); break; }
  }
  const reasons = [];
  let state = "VULNERABLE";
  if (xfo) {
    reasons.push("X-Frame-Options: " + xfo);
    state = ["DENY","SAMEORIGIN"].includes(xfo.toUpperCase()) ? "PROTECTED" : "REVIEW";
  }
  if (ancestors !== null) {
    reasons.push("CSP frame-ancestors: " + ancestors.join(" "));
    const low = new Set(ancestors.map(x => x.toLowerCase()));
    state = (low.has("'none'") || low.has("'self'")) ? "PROTECTED" : "REVIEW";
  }
  if (!xfo && ancestors === null) reasons.push("No X-Frame-Options or CSP frame-ancestors directive observed.");
  if (state === "VULNERABLE") reasons.push("Header evidence indicates this page may be frameable.");
  return {state, x_frame_options:xfo || null, csp_frame_ancestors:ancestors ? ancestors.join(" ") : null, reasons, confidence:state === "PROTECTED" ? "high" : "medium"};
}

async function clientFrameAttempt(url) {
  return new Promise(resolve => {
    const frame = document.createElement("iframe");
    frame.style.cssText = "position:fixed;left:-10000px;top:-10000px;width:1px;height:1px;border:0;opacity:0;pointer-events:none;";
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      frame.remove();
      resolve({status:"IFRAME_ATTEMPTED", detail:"A cross-origin iframe framing attempt was made. Static browser policy prevents inspecting the framed document."});
    };
    frame.onload = finish;
    frame.onerror = finish;
    document.body.appendChild(frame);
    frame.src = url;
    setTimeout(finish, 2200);
  });
}

async function scanGitHubPages(root, maxPages, browserVerify) {
  const origin = new URL(root).origin;
  const queue = [root];
  const queued = new Set(queue);
  const results = [];

  while (queue.length && results.length < maxPages) {
    const current = queue.shift();
    try {
      const header = await publicHeaderCheck(current);
      const p = clientPolicy(header);
      let htmlInfo = null;
      try { htmlInfo = await publicFetchHtml(current); } catch (_) {}

      let browser = null;
      if (browserVerify && p.state !== "PROTECTED") browser = await clientFrameAttempt(current);

      results.push({
        url: current,
        final_url: htmlInfo?.finalUrl || current,
        status_code: header.status || 0,
        state: p.state,
        confidence: p.confidence,
        x_frame_options: p.x_frame_options,
        csp_frame_ancestors: p.csp_frame_ancestors,
        reasons: p.reasons,
        browser
      });

      if (htmlInfo) {
        for (const link of clientExtractLinks(htmlInfo.html, htmlInfo.finalUrl || current, origin)) {
          if (!queued.has(link) && queued.size < maxPages * 4) {
            queued.add(link);
            queue.push(link);
          }
        }
      }
    } catch (error) {
      results.push({
        url:current, final_url:current, status_code:0, state:"ERROR", confidence:"low",
        x_frame_options:null, csp_frame_ancestors:null, reasons:[error.message || String(error)], browser:null
      });
    }
  }

  const counts = {VULNERABLE:0, PROTECTED:0, REVIEW:0, ERROR:0};
  for (const r of results) counts[r.state] = (counts[r.state] || 0) + 1;
  return {
    target:root,
    pages_scanned:results.length,
    counts,
    results,
    vulnerable_pages:results.filter(r => r.state === "VULNERABLE").map(r => r.url),
    note:"VULNERABLE is a response-header frameability signal. Browser iframe attempts are shown separately; a static browser page cannot inspect a cross-origin framed document."
  };
}

async function scanSite() {
  const url = normalizeUrl($("urlInput").value);
  const maxPages = Math.max(1, Math.min(15, Number($("pagesInput").value) || 15));
  const browserVerify = $("browserVerify").checked;

  try { clientTargetGuard(url); }
  catch (error) {
    setStatus("ERROR", "danger");
    $("results").innerHTML = '<div class="error-box">' + escapeHtml(error.message) + "</div>";
    $("empty").style.display = "none";
    return;
  }

  $("scanBtn").disabled = true;
  setStatus("SCANNING", "loading");
  $("targetDisplay").textContent = url;

  try {
    const data = await scanGitHubPages(url, maxPages, browserVerify);
    renderResults(data);
    setStatus(data.counts.VULNERABLE ? "EXPOSURE FOUND" : "SCAN COMPLETE", data.counts.VULNERABLE ? "danger" : "loaded");
  } catch (error) {
    setStatus("ERROR", "danger");
    $("results").innerHTML = '<div class="error-box">' + escapeHtml(error.message || String(error)) + "</div>";
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