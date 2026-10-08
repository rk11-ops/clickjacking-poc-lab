const $ = id => document.getElementById(id);

const API_BASE = String(
  document.querySelector('meta[name="api-base"]')?.content ||
  localStorage.getItem("clickjacking_api_base") ||
  ""
).replace(/\/$/, "");

const HEADER_API = "https://api.domainee.dev/v1/tools/http-header-checker?url=";
const HTML_PROXY = "https://proxy.cors.dev/";

function esc(v) {
  return String(v ?? "").replace(/[&<>'"]/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;","\"":"&quot;"
  }[c]));
}

function normalize(raw) {
  let s = String(raw || "").trim();
  if (!s) throw new Error("Enter a target URL.");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  if (!["http:","https:"].includes(u.protocol)) throw new Error("Only HTTP/HTTPS targets are supported.");
  u.hash = "";
  return u.toString();
}

function guardTarget(raw) {
  const u = new URL(raw);
  const h = u.hostname.toLowerCase();
  if (
    h === "localhost" || h.endsWith(".localhost") ||
    h === "local" || h.endsWith(".local") ||
    h.endsWith(".internal") || h === "0.0.0.0" || h === "::1"
  ) throw new Error("Local/private hostnames are not supported.");
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) {
    const [a,b] = h.split(".").map(Number);
    const blocked =
      a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127);
    if (blocked) throw new Error("Private, loopback, link-local, or CGNAT IP targets are blocked.");
  }
}

function setStatus(label, state) {
  const el = $("scanStatus");
  el.className = "status-pill " + (state || "ready");
  el.innerHTML = "<i></i> " + label;
}

function renderAffected(data) {
  const box = $("affectedPages");
  const rows = (data.results || []).filter(r => r.state === "VULNERABLE");
  box.innerHTML = rows.length
    ? rows.map(r => '<div class="affected-item"><span class="dot"></span><span>' + esc(r.url) + '</span></div>').join("")
    : '<span class="muted">No confirmed header-exposed pages.</span>';
}

function render(data) {
  const box = $("results");
  const empty = $("empty");
  box.innerHTML = "";
  empty.style.display = data.results.length ? "none" : "grid";

  for (const r of data.results) {
    const reasons = (r.reasons || []).map(x => "<li>" + esc(x) + "</li>").join("");
    const controls = [];
    if (r.x_frame_options) controls.push("XFO: " + esc(r.x_frame_options));
    if (r.csp_frame_ancestors) controls.push("CSP: frame-ancestors " + esc(r.csp_frame_ancestors));

    const node = document.createElement("article");
    node.className = "result-row";
    node.innerHTML =
      '<div class="page-cell">' +
        '<div class="url">' + esc(r.url) + "</div>" +
        (r.final_url && r.final_url !== r.url ? '<div class="final">→ ' + esc(r.final_url) + "</div>" : "") +
        '<ul class="reasons">' + reasons + "</ul>" +
      "</div>" +
      '<div class="http">' + esc(r.status_code || "—") + "</div>" +
      '<div><span class="state ' + esc(String(r.state).toLowerCase()) + '">' + esc(r.state) + "</span>" +
        "<small>" + esc(r.confidence || "") + "</small></div>" +
      '<div class="control">' + (controls.length ? controls.join("<br>") : "No explicit anti-framing header") + "</div>" +
      '<div><span class="browser">' + (r.browser ? "ATTEMPTED" : "—") + "</span></div>";
    box.appendChild(node);
  }

  $("mScanned").textContent = data.pages_scanned || 0;
  $("mVuln").textContent = data.counts?.VULNERABLE || 0;
  $("mProtected").textContent = data.counts?.PROTECTED || 0;
  $("mReview").textContent = (data.counts?.REVIEW || 0) + (data.counts?.ERROR || 0);
  $("targetDisplay").textContent = data.target || "Ready";
  renderAffected(data);
}

async function backendScan(url, maxPages, browserVerify) {
  const res = await fetch(API_BASE + "/api/scan", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({url, max_pages:maxPages, browser_verify:browserVerify})
  });
  const type = res.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("Configured backend returned a non-JSON response.");
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Scan failed.");
  return data;
}

async function headerCheck(url) {
  const res = await fetch(HEADER_API + encodeURIComponent(url), {credentials:"omit"});
  const type = res.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("Header service returned a non-JSON response.");
  const body = await res.json();
  if (!body.ok) throw new Error(body.error?.message || "Header check failed.");
  return body.data;
}

async function fetchHtml(url) {
  const proxy = await fetch(HTML_PROXY + url, {credentials:"omit"});
  if (!proxy.ok) throw new Error("HTML fetch failed (" + proxy.status + ").");
  return {html: await proxy.text(), finalUrl: url};
}

function policy(data) {
  const h = Object.fromEntries(Object.entries(data.headers || {}).map(([k,v]) => [k.toLowerCase(), v]));
  const xfo = String(h["x-frame-options"] || "").trim();
  const csp = String(h["content-security-policy"] || "").trim();
  let ancestors = null;

  for (const p of csp.split(";")) {
    const b = p.trim().split(/\s+/);
    if (b[0]?.toLowerCase() === "frame-ancestors") {
      ancestors = b.slice(1);
      break;
    }
  }

  let state = "VULNERABLE";
  const reasons = [];

  if (xfo) {
    reasons.push("X-Frame-Options: " + xfo);
    state = ["DENY","SAMEORIGIN"].includes(xfo.toUpperCase()) ? "PROTECTED" : "REVIEW";
  }

  if (ancestors !== null) {
    reasons.push("CSP frame-ancestors: " + ancestors.join(" "));
    const low = new Set(ancestors.map(x => x.toLowerCase()));
    state = (low.has("'none'") || low.has("'self'")) ? "PROTECTED" : "REVIEW";
  }

  if (!xfo && ancestors === null) {
    reasons.push("No X-Frame-Options or CSP frame-ancestors directive observed.");
    reasons.push("Header evidence indicates this page may be frameable.");
  }

  return {
    state,
    x_frame_options: xfo || null,
    csp_frame_ancestors: ancestors ? ancestors.join(" ") : null,
    reasons,
    confidence: state === "PROTECTED" ? "high" : "medium"
  };
}

function links(html, base, origin) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const out = [];
  const seen = new Set();

  for (const a of doc.querySelectorAll("a[href]")) {
    const href = a.getAttribute("href") || "";
    if (!href || /^(#|mailto:|tel:|javascript:|data:|blob:)/i.test(href)) continue;
    try {
      const u = new URL(href, base);
      u.hash = "";
      if (!["http:","https:"].includes(u.protocol) || u.origin !== origin) continue;
      const s = u.toString();
      if (!seen.has(s)) { seen.add(s); out.push(s); }
    } catch (_) {}
    if (out.length >= 100) break;
  }
  return out;
}

function frameAttempt(url) {
  return new Promise(resolve => {
    const frame = document.createElement("iframe");
    frame.style.cssText = "position:fixed;left:-10000px;top:-10000px;width:1px;height:1px;border:0;opacity:0;pointer-events:none;";
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      frame.remove();
      resolve({
        status: "IFRAME_ATTEMPTED",
        detail: "A browser iframe attempt was made; cross-origin browser policy prevents this static page from inspecting the framed document."
      });
    };
    frame.onload = finish;
    frame.onerror = finish;
    document.body.appendChild(frame);
    frame.src = url;
    setTimeout(finish, 2200);
  });
}

async function staticScan(root, maxPages, browserVerify) {
  const origin = new URL(root).origin;
  const queue = [root];
  const queued = new Set(queue);
  const results = [];

  while (queue.length && results.length < maxPages) {
    const current = queue.shift();
    try {
      const h = await headerCheck(current);
      const p = policy(h);
      let html = null;
      try { html = await fetchHtml(current); } catch (_) {}

      const browser = browserVerify && p.state !== "PROTECTED"
        ? await frameAttempt(current)
        : null;

      results.push({
        url: current,
        final_url: html?.finalUrl || current,
        status_code: h.status || 0,
        state: p.state,
        confidence: p.confidence,
        x_frame_options: p.x_frame_options,
        csp_frame_ancestors: p.csp_frame_ancestors,
        reasons: p.reasons,
        browser
      });

      if (html) {
        for (const u of links(html.html, html.finalUrl || current, origin)) {
          if (!queued.has(u) && queued.size < maxPages * 4) {
            queued.add(u);
            queue.push(u);
          }
        }
      }
    } catch (e) {
      results.push({
        url: current, final_url: current, status_code: 0, state: "ERROR",
        confidence: "low", x_frame_options: null, csp_frame_ancestors: null,
        reasons: [e.message || String(e)], browser: null
      });
    }
  }

  const counts = {VULNERABLE:0, PROTECTED:0, REVIEW:0, ERROR:0};
  for (const r of results) counts[r.state]++;

  return {
    target: root,
    pages_scanned: results.length,
    counts,
    results,
    vulnerable_pages: results.filter(r => r.state === "VULNERABLE").map(r => r.url),
    note: "VULNERABLE is a response-header frameability signal. Browser iframe attempts are shown separately because a static cross-origin page cannot inspect the framed document."
  };
}

async function scanSite() {
  let url;
  try {
    url = normalize($("urlInput").value);
    guardTarget(url);
  } catch (e) {
    setStatus("ERROR", "danger");
    $("results").innerHTML = '<div class="error-box">' + esc(e.message) + "</div>";
    $("empty").style.display = "none";
    return;
  }

  const maxPages = Math.max(1, Math.min(15, Number($("pagesInput").value) || 15));
  const browserVerify = $("browserVerify").checked;

  $("scanBtn").disabled = true;
  setStatus("SCANNING", "loading");
  $("targetDisplay").textContent = url;

  try {
    const data = API_BASE
      ? await backendScan(url, maxPages, browserVerify)
      : await staticScan(url, maxPages, browserVerify);

    render(data);
    setStatus(data.counts.VULNERABLE ? "EXPOSURE FOUND" : "SCAN COMPLETE", data.counts.VULNERABLE ? "danger" : "loaded");
  } catch (e) {
    setStatus("ERROR", "danger");
    $("results").innerHTML = '<div class="error-box">' + esc(e.message || String(e)) + "</div>";
    $("empty").style.display = "none";
  } finally {
    $("scanBtn").disabled = false;
  }
}

$("scanBtn").onclick = scanSite;
$("urlInput").addEventListener("keydown", e => { if (e.key === "Enter") scanSite(); });

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
  try {
    const u = normalize($("urlInput").value);
    guardTarget(u);
    window.open(u, "_blank", "noopener,noreferrer");
  } catch (e) {
    setStatus("ERROR", "danger");
  }
};

$("fullscreen").onclick = async () => {
  const el = document.querySelector(".results-wrap");
  if (!document.fullscreenElement) await (el.requestFullscreen && el.requestFullscreen());
  else await document.exitFullscreen();
};