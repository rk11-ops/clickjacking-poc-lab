# Clickjacking PoC Lab v3.1 — Offensive Edition

A client-side Clickjacking Proof-of-Concept utility with a redesigned
offensive-security UI: crimson/black terminal theme, boot-sequence intro,
scanline sweep, and target-lock guide animation. Original implementation
with ReconForge branding.

## What it does

- Enter an HTTP/HTTPS target.
- Load it live in an iframe.
- Resize the left control panel.
- Toggle a framing guide.
- Adjust frame opacity.
- Open the target in a new tab.
- Fullscreen the preview.
- Copy a generic iframe PoC snippet.
- Save a standalone HTML PoC template.

## What changed in v3.1

- New offensive/red-team visual theme (crimson accent on near-black).
- One-time terminal "boot sequence" intro animation.
- Continuous subtle scanline sweep across the live preview.
- Pulsing target-lock corners on the framing guide.
- Animated status pill (amber while loading, green glow when loaded).
- Respects `prefers-reduced-motion` — all animation disables automatically.
- All v3.0 functionality preserved as-is.

## Important browser limitation

The browser's cross-origin security model means a client-side tool cannot
reliably inspect the target's response headers directly. A visible iframe
load event is therefore not proof that clickjacking is exploitable.

For a real assessment, verify the target's HTTP response for:
- X-Frame-Options
- Content-Security-Policy: frame-ancestors

A target may also refuse framing for reasons other than these headers.

## Run locally

This project is static. No backend is required.

### Option 1
Open `index.html` directly in a browser.

### Option 2
```bash
python3 -m http.server 8080
```
Open http://127.0.0.1:8080

### Option 3
Deploy to GitHub Pages, Cloudflare Pages, Netlify, or any static hosting.
See `GITHUB_PAGES.md` for step-by-step GitHub Pages instructions.

## Public deployment

Because target pages are loaded directly by the visitor's browser, the server
does not fetch arbitrary target URLs. That keeps the public version simple and
avoids turning the application into a server-side SSRF proxy.

Use only against targets you own or are explicitly authorized to assess.
