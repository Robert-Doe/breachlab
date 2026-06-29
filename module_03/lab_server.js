/**
 * XSS Mastery Lab — Module 03
 * Cumulative: M01 + M02 + new /reflect endpoint for mechanism demos.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── M01 ──────────────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/ping", (req, res) => {
  res.json({ status: "ok", module: 3 });
});

// ── M02 ──────────────────────────────────────────────────────────────────────

app.get("/parse-demo", (req, res) => {
  const raw = req.query.html || "<!-- supply ?html=... -->";
  const page = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{background:#0b0f1a;color:#e2e8f0;font-family:sans-serif;padding:24px}
.injected{background:#141c2e;border:1px solid #1e3a5f;padding:16px;border-radius:6px;margin-top:16px}</style>
</head><body><h2 style="color:#38bdf8">Parser Demo</h2>
<div class="injected">${raw}</div></body></html>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page);
});

// ── M03 — Reflector ───────────────────────────────────────────────────────────

app.get("/reflect", (req, res) => {
  const q = req.query.q || "";

  // Direct string interpolation into HTML — intentionally vulnerable.
  // This is the server-side Reflected XSS pattern that Module 04 studies
  // in depth. Here we use it only to demonstrate Mechanism 1 (tag parsing).
  const page = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Reflect — Mechanism Demo</title>
  <style>
    body { background:#0b0f1a; color:#e2e8f0; font-family:sans-serif; padding:24px; }
    .result { background:#141c2e; border:1px solid #1e3a5f;
              padding:16px; border-radius:6px; margin-top:16px; }
    label { color:#7a9bbf; font-size:12px; display:block; margin-bottom:6px; }
  </style>
</head>
<body>
  <h2 style="color:#38bdf8">Mechanism 1 — Tag Parsing Reflector</h2>
  <label>Your input reflected raw into the HTML body:</label>
  <div class="result">
    ${q}
  </div>
  <p style="color:#7a9bbf; font-size:13px; margin-top:16px">
    Open DevTools Elements panel. Check Console for execution.
  </p>
</body>
</html>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page);
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 03`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  Mechanisms demo: http://localhost:${PORT}/mechanisms_demo.html`);
  console.log(`  Reflector: http://localhost:${PORT}/reflect?q=<b>test</b>`);
  console.log(`  Press Ctrl+C to stop\n`);
});
