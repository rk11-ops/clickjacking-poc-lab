# Clickjacking PoC Lab v4.0 — Site Scanner

This version is a server-backed authorized-security-testing utility that crawls same-origin HTML pages and reports clickjacking exposure per page.

## Capabilities

- Start with one HTTP/HTTPS root URL.
- Crawl same-origin HTML links only.
- Scan up to 25 pages per run.
- Check X-Frame-Options and CSP frame-ancestors for every HTML page.
- Optionally perform a separate-origin browser iframe verification.
- Show exactly which pages are VULNERABLE, PROTECTED, REVIEW, ERROR, or NON_HTML.
- Keep a dedicated AFFECTED PAGES list for confirmed vulnerable URLs.
- Block private, loopback, link-local, and other non-global target addresses.

## Result meaning

VULNERABLE means the page response did not expose an explicit anti-framing control and the separate-origin browser probe reached the target page.

PROTECTED means X-Frame-Options or a restrictive CSP frame-ancestors directive was observed.

REVIEW means the headers or browser result are ambiguous and require manual verification.

This is an assessment signal, not a guarantee of exploitability in every application workflow.

## Run locally

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/

## Production

Run behind HTTPS and keep the public scanner protected with rate limits and access controls appropriate to your environment.

Use only against systems you own or are explicitly authorized to assess.

## One-click hosted deployment

The app is packaged as a single Render web service with the UI and scanner API on the same origin. Render supports deploying a repository Blueprint from a `render.yaml` file, and its Deploy to Render flow can be launched directly from a repository URL.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/rk11-ops/clickjacking-poc-lab)

After the service is live, open its Render URL. The scanner UI will call `/api/health` and `/api/scan` on the same origin, so no GitHub Pages API wiring is required.
