/**
 * XSS Mastery Lab — Module 02
 * Cumulative: everything from Module 01, plus /parse-demo.
 * Mirrors lab_server.py exactly.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Module 01 routes ─────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/ping", (req, res) => {
  res.json({ status: "ok", module: 2 });
});

// ── Module 02 — Raw HTML echo endpoint ───────────────────────────────────────

app.get("/parse-demo", (req, res) => {
  // Pull the raw HTML string from the query param — no sanitisation.
  const raw = req.query.html || "<!-- supply ?html=... to inject markup -->";

  // We build the page using a template literal and inject 'raw' directly.
  // This is the Node.js equivalent of Flask's make_response with no escaping.
  // Every modern JS framework (React, Vue, Angular) protects against this by
  // default — they HTML-encode output automatically. Raw string concatenation
  // like this is the pattern that vulnerable legacy apps use.
  const page = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Parser Demo — Module 02</title>
  <style>
    body { background:#0b0f1a; color:#e2e8f0; font-family:sans-serif; padding:24px; }
    .injected { background:#141c2e; border:1px solid #1e3a5f; padding:16px;
                border-radius:6px; margin-top:16px; }
  </style>
</head>
<body>
  <h2 style="color:#38bdf8">Browser Parser Output</h2>
  <p style="color:#7a9bbf">The markup below was injected raw. Open DevTools Elements panel
     to see how the browser parsed it.</p>
  <div class="injected">
    ${raw}
  </div>
</body>
</html>`;

  // Set Content-Type explicitly — express would default to text/html anyway
  // but being explicit is a good habit and mirrors what we study in M17.
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page);
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 02`);
  console.log(`  Listening on http://localhost:${PORT}`);
  console.log(`  Parser demo: http://localhost:${PORT}/parse-demo?html=<b>test</b>`);
  console.log(`  Press Ctrl+C to stop\n`);
});
