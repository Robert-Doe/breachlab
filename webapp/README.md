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
executed inside a sandboxed `<iframe sandbox="allow-scripts">` (without
`allow-same-origin`) fed via `srcdoc`, so a payload can genuinely fire
while touching nothing real — no server, no database, no shared state
between visitors, no persistence of any kind.

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
- All payload execution happens inside a sandboxed, cross-origin-opaque
  `<iframe>` with no access to this page's real cookies, storage, or DOM.
- Nothing typed into the playground is ever sent to a server, stored, or
  shown to any other visitor — it exists only in this browser tab, for
  the duration of one page load.
