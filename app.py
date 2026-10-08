from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright

APP_DIR = Path(__file__).resolve().parent
MAX_REDIRECTS = 4
MAX_BODY_BYTES = 1500000
MAX_PAGES = 25
TIMEOUT = 12.0
USER_AGENT = "Clickjacking-PoC-Lab/4.0 (authorized-security-testing)"

app = FastAPI(title="Clickjacking PoC Lab", version="4.0.0")
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    max_pages: int = Field(default=15, ge=1, le=MAX_PAGES)
    browser_verify: bool = True


@dataclass
class FetchResult:
    url: str
    status: int
    headers: httpx.Headers
    body: str
    final_url: str
    error: str | None = None


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise ValueError("Only valid HTTP/HTTPS URLs are supported")
    return urlunparse((p.scheme.lower(), p.netloc, p.path or "/", "", p.query, ""))


def public_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def assert_public(url: str) -> None:
    p = urlparse(url)
    host = p.hostname
    if p.scheme not in {"http", "https"} or not host:
        raise ValueError("Only HTTP/HTTPS targets are allowed")
    try:
        literal = ipaddress.ip_address(host)
        if not literal.is_global:
            raise ValueError("Private, loopback, link-local, or otherwise non-public IP targets are blocked")
        return
    except ValueError as exc:
        if "blocked" in str(exc):
            raise

    try:
        resolved = {x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError("DNS resolution failed for target") from exc
    if not resolved or any(not public_ip(ip) for ip in resolved):
        raise ValueError("Target resolves to a private or non-public address")


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and port_a == port_b
    )


def policy(headers: httpx.Headers) -> dict:
    xfo = headers.get("x-frame-options", "").strip()
    csp = headers.get("content-security-policy", "").strip()
    ancestors = None

    for part in csp.split(";"):
        bits = part.strip().split()
        if bits and bits[0].lower() == "frame-ancestors":
            ancestors = bits[1:]
            break

    reasons = []
    state = "UNPROTECTED"

    if xfo:
        reasons.append("X-Frame-Options: " + xfo)
        if xfo.upper() in {"DENY", "SAMEORIGIN"}:
            state = "PROTECTED"
        else:
            state = "REVIEW"

    if ancestors is not None:
        low = {x.lower() for x in ancestors}
        if "'none'" in low or "'self'" in low:
            reasons.append("CSP frame-ancestors restricts embedding")
            if state != "PROTECTED":
                state = "PROTECTED"
        elif "*" in low:
            reasons.append("CSP frame-ancestors allows broad framing")
            state = "REVIEW"
        elif ancestors:
            reasons.append("CSP frame-ancestors contains an explicit allowlist")
            state = "REVIEW"
        else:
            reasons.append("CSP frame-ancestors is empty")
            state = "REVIEW"

    if not xfo and ancestors is None:
        reasons.append("No X-Frame-Options or CSP frame-ancestors directive present")

    return {
        "state": state,
        "x_frame_options": xfo or None,
        "csp_frame_ancestors": " ".join(ancestors) if ancestors is not None else None,
        "reasons": reasons,
        "confidence": "high" if state in {"PROTECTED", "UNPROTECTED"} else "medium",
    }


def links_from(html: str, base_url: str, origin: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        try:
            u = normalize_url(urljoin(base_url, href))
        except ValueError:
            continue
        if same_origin(u, origin) and u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= 100:
            break
    return out


async def fetch(client: httpx.AsyncClient, url: str) -> FetchResult:
    current = normalize_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        assert_public(current)
        try:
            r = await client.get(current, follow_redirects=False)
        except Exception as exc:
            return FetchResult(url, 0, httpx.Headers(), "", current, str(exc))

        if 300 <= r.status_code < 400 and r.headers.get("location"):
            current = normalize_url(urljoin(current, r.headers["location"]))
            continue

        ctype = r.headers.get("content-type", "")
        body = ""
        if "text/html" in ctype.lower():
            body = r.content[:MAX_BODY_BYTES].decode(r.encoding or "utf-8", errors="replace")
        return FetchResult(url, r.status_code, r.headers, body, str(r.url))

    return FetchResult(url, 0, httpx.Headers(), "", current, "Too many redirects")


async def frame_probe(browser, target_url: str) -> dict:
    page = await browser.new_page()
    try:
        await page.goto("about:blank")
        target_host = (urlparse(target_url).hostname or "").lower()
        await page.evaluate(
            """url => {
                const f = document.createElement("iframe");
                f.id = "probe";
                f.src = url;
                f.style.width = "1200px";
                f.style.height = "800px";
                f.style.border = "0";
                document.body.appendChild(f);
            }""",
            target_url,
        )
        await page.wait_for_timeout(1800)
        frames = [f for f in page.frames if f != page.main_frame]
        reached = any(
            (urlparse(f.url).hostname or "").lower() == target_host
            and urlparse(f.url).scheme in {"http", "https"}
            for f in frames
        )
        if reached:
            return {
                "status": "FRAME_REACHED",
                "detail": "A separate-origin browser frame reached the target page."
            }
        return {
            "status": "FRAME_BLOCKED_OR_UNREACHABLE",
            "detail": "The browser did not reach the target page inside the separate-origin frame."
        }
    except Exception as exc:
        return {"status": "BROWSER_CHECK_ERROR", "detail": str(exc)}
    finally:
        await page.close()


@app.get("/api/health")
async def health():
    return {"ok": True, "version": "4.0.0"}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    try:
        root = normalize_url(req.url)
        assert_public(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    queue = deque([root])
    queued = {root}
    seen = set()
    results = []
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=4)

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
        timeout=TIMEOUT,
        verify=True,
        limits=limits,
    ) as client:
        browser_cm = async_playwright() if req.browser_verify else None
        if browser_cm:
            async with browser_cm as pw:
                browser = await pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--no-sandbox"])
                try:
                    while queue and len(results) < req.max_pages:
                        current = queue.popleft()
                        if current in seen:
                            continue
                        seen.add(current)
                        item = await build_result(client, browser, current, root, req.browser_verify)
                        results.append(item)

                        if item["state"] in {"ERROR", "NON_HTML"}:
                            continue
                        for link in links_from(item.pop("_crawl_body", ""), item["final_url"], root):
                            if link not in queued and len(queued) < req.max_pages * 4:
                                queued.add(link)
                                queue.append(link)
                finally:
                    await browser.close()
        else:
            while queue and len(results) < req.max_pages:
                current = queue.popleft()
                if current in seen:
                    continue
                seen.add(current)
                item = await build_result(client, None, current, root, False)
                results.append(item)
                if item["state"] in {"ERROR", "NON_HTML"}:
                    continue
                for link in links_from(item.pop("_crawl_body", ""), item["final_url"], root):
                    if link not in queued and len(queued) < req.max_pages * 4:
                        queued.add(link)
                        queue.append(link)

    counts = {}
    for state in {"VULNERABLE", "PROTECTED", "REVIEW", "UNPROTECTED", "ERROR", "NON_HTML"}:
        counts[state] = sum(1 for x in results if x["state"] == state)

    return {
        "target": root,
        "pages_scanned": len(results),
        "counts": counts,
        "results": results,
        "vulnerable_pages": [x["url"] for x in results if x["state"] == "VULNERABLE"],
        "note": "VULNERABLE requires an unprotected response plus a separate-origin browser framing probe that reached the page."
    }


async def build_result(client, browser, current, root, browser_verify):
    fetched = await fetch(client, current)
    if fetched.error:
        return {
            "url": current, "status_code": 0, "final_url": fetched.final_url,
            "state": "ERROR", "confidence": "low", "browser": None,
            "x_frame_options": None, "csp_frame_ancestors": None,
            "reasons": [fetched.error], "_crawl_body": ""
        }

    ctype = fetched.headers.get("content-type", "")
    if "text/html" not in ctype.lower():
        return {
            "url": current, "status_code": fetched.status, "final_url": fetched.final_url,
            "state": "NON_HTML", "confidence": "high", "browser": None,
            "x_frame_options": fetched.headers.get("x-frame-options"),
            "csp_frame_ancestors": None,
            "reasons": ["Response is not HTML; no page links were crawled."],
            "_crawl_body": ""
        }

    info = policy(fetched.headers)
    browser_info = None
    if browser_verify and info["state"] in {"UNPROTECTED", "REVIEW"} and browser is not None:
        browser_info = await frame_probe(browser, fetched.final_url)

    if info["state"] == "UNPROTECTED" and browser_info and browser_info["status"] == "FRAME_REACHED":
        info["state"] = "VULNERABLE"
        info["confidence"] = "high"
        info["reasons"].append("Separate-origin browser probe reached the page without an explicit anti-framing control.")
    elif info["state"] == "UNPROTECTED" and browser_info and browser_info["status"] == "FRAME_BLOCKED_OR_UNREACHABLE":
        info["state"] = "REVIEW"
        info["confidence"] = "medium"
        info["reasons"].append("Headers appear unprotected, but browser framing was not confirmed.")

    return {
        "url": current,
        "status_code": fetched.status,
        "final_url": fetched.final_url,
        "content_type": ctype,
        **info,
        "browser": browser_info,
        "_crawl_body": fetched.body,
    }


@app.get("/")
async def index():
    return FileResponse(APP_DIR / "index.html")
