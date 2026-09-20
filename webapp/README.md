# breachlab webapp

A real, interactive, publicly-hostable demo of the breachlab course: a
sandboxed XSS playground covering the five execution mechanisms taught
across the modules (tag parsing, event-handler attributes, URI schemes,
DOM sinks, context escape / mXSS).

**This is intentionally a safe, client-only reimplementation, distinct
from the original local Flask/Node labs in `module_04/`, `module_05/`,
`module_06/`, `module_09/`, etc.** Those modules run real local servers
(`lab_server.py` / `lab_server.js`) meant for offline, localhost-only use
and are unchanged by this webapp. This `webapp/` demo ships **zero**
backend code: every "vulnerable" sink is reimplemented in the browser and
executed inside an `<iframe sandbox="allow-scripts allow-same-origin">`
fed via `srcdoc`. A payload genuinely executes — `alert()`/`confirm()`/
`prompt()` pop real browser dialogs, not a simulated report — and can
genuinely read `document.cookie`, which the page seeds with a fake,
disposable `demo_session=...` value regenerated on every load. The
sandbox still blocks top-level navigation and new windows regardless of
`allow-same-origin`, so the blast radius stays "you alert() your own tab":
no server, no database, no real account, no shared state between
visitors, no persistence beyond the current page load.

## Attack Payload Library

Below the sandbox is a library of all 122 real, annotated payloads from the
course's `module_19/payloads/*.html` payload bank, grouped into the same 10
attack categories. `scripts/parse-payload-bank.mjs` parses those real course
files (never hand-transcribed) plus curated category metadata in
`scripts/payload-docs-data.mjs` into `src/payloadBank.generated.ts` — run
`npm run generate-payload-bank` after editing either source. Opening a
category shows, per payload: the code, its severity tier, and its real
course annotations (Context/Mechanism/Bypasses/Stopped by/Origin), plus
three tabs covering the attacker's thought process for that category, a
threat-model summary (who's attacking, what they gain, blast radius), and
links to primary sources (MDN, OWASP, CWE, PortSwigger). Payloads that map
onto one of the five sandbox mechanisms get a "Try it in the sandbox"
button that loads and runs them live, above.

## Local development

```bash
cd webapp
npm install
npm run dev
```

## Production build

```bash
cd webapp
npm run build
```

Output goes to `webapp/dist/`. The build must complete with zero errors.

## Static hosting (Vercel / Netlify / Cloudflare Pages)

This is a static site — no server, no environment variables, no functions.

| Setting | Value |
|---|---|
| Root directory | `webapp` |
| Build command | `npm run build` |
| Output directory | `dist` |

That's it — point any static host at the `webapp` subdirectory with those
three settings and it will deploy.

## Safety notes

- No backend, no API route, no database anywhere in this directory.
- Payload execution is real (`allow-scripts allow-same-origin`), including
  real `alert`/`confirm`/`prompt` dialogs and real `document.cookie` access
  — but the cookie is a fake `demo_session=lab_xxxx` value generated fresh
  client-side on every page load, and there is no account or data behind it.
- The sandbox still blocks top-level navigation and popups, so a payload
  cannot redirect the tab or open new windows regardless of same-origin access.
- Nothing typed into the playground is ever sent to a server, stored, or
  shown to any other visitor — it exists only in this browser tab, for
  the duration of one page load.
