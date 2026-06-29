/**
 * XSS Mastery Lab — Module 04
 * Cumulative: M01–M03 + three new vulnerable search endpoints.
 * Mirrors lab_server.py exactly.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Shared shell helper ───────────────────────────────────────────────────────

function pageShell(title, bodyContent) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>${title}</title>
  <style>
    body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;padding:32px;max-width:700px}
    h2{color:#38bdf8;margin-bottom:8px}
    .box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
    label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}
    form{margin-bottom:20px;display:flex;gap:8px}
    input[type=text]{flex:1;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;
                     border-radius:4px;padding:8px 12px;font-size:14px}
    button{background:#38bdf8;color:#0b0f1a;border:none;border-radius:4px;
           padding:8px 16px;font-weight:700;cursor:pointer}
    .back{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}
    a{color:#38bdf8}
    pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;
        overflow-x:auto;white-space:pre-wrap}
    code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;
         color:#38bdf8;padding:2px 5px;border-radius:3px}
  </style>
</head>
<body>
  <a class="back" href="/attack_01_script.html">← Attack 01 Demo Page</a>
  ${bodyContent}
</body>
</html>`;
}

// ── M01–M03 routes ────────────────────────────────────────────────────────────

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/ping", (req, res) => res.json({ status: "ok", module: 4 }));

app.get("/parse-demo", (req, res) => {
  const raw = req.query.html || "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<div style="background:#0b0f1a;color:#e2e8f0;padding:20px">${raw}</div>`);
});

app.get("/reflect", (req, res) => {
  const q = req.query.q || "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`);
});

// ── M04 — Body context ───────────────────────────────────────────────────────

app.get("/search", (req, res) => {
  // DELIBERATE VULNERABILITY: template literal interpolation with no escaping.
  // Production fix: use a templating engine with auto-escaping, or manually
  // apply the equivalent of Python's html.escape():
  //   const safe = q.replace(/&/g,"&amp;").replace(/</g,"&lt;")
  //                 .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  const q = req.query.q || "";
  const body = `
  <h2>Search Results</h2>
  <form method="GET" action="/search">
    <input type="text" name="q" value="${q}" placeholder="Search...">
    <button type="submit">Search</button>
  </form>
  <div class="box">
    <label>Results for:</label>
    <div id="query-echo">${q}</div>
  </div>
  <div class="box">
    <label>Injection context: HTML BODY</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${q}</div>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:16px">
    Try: <code>?q=&lt;b&gt;bold&lt;/b&gt;</code> then
    <code>?q=&lt;script&gt;alert(document.domain)&lt;/script&gt;</code>
  </p>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(pageShell("Search — Body Context", body));
});

// ── M04 — Attribute context ──────────────────────────────────────────────────

app.get("/search-attr", (req, res) => {
  const q = req.query.q || "";
  const body = `
  <h2>Search — Attribute Context</h2>
  <div class="box">
    <label>Your query is pre-filled into the input value attribute:</label>
    <input type="text" name="q" value="${q}"
           style="width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
                  border:1px solid #1e3a5f;border-radius:4px">
  </div>
  <div class="box">
    <label>Raw HTML being generated:</label>
    <pre>&lt;input type="text" name="q" value="<b style="color:#f5c842">${q}</b>"&gt;</pre>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Try: <code>?q=" onmouseover="alert(document.domain)" x="</code>
  </p>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(pageShell("Search — Attribute Context", body));
});

// ── M04 — Script context ─────────────────────────────────────────────────────

app.get("/search-js", (req, res) => {
  const q = req.query.q || "";
  const body = `
  <h2>Search — Script Context</h2>
  <div class="box">
    <label>Your query is embedded in a JavaScript variable:</label>
    <pre>var searchQuery = "<b style="color:#f5c842">${q}</b>";
document.getElementById('result').textContent = 'You searched for: ' + searchQuery;</pre>
  </div>
  <div class="box" id="result"></div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Try: <code>?q=";alert(document.domain);//</code>
  </p>
  <script>
    var searchQuery = "${q}";
    document.getElementById('result').textContent = 'You searched for: ' + searchQuery;
  </script>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(pageShell("Search — Script Context", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 04`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  Body context:   /search?q=test`);
  console.log(`  Attr context:   /search-attr?q=test`);
  console.log(`  Script context: /search-js?q=test`);
  console.log(`  Attack demo:    /attack_01_script.html\n`);
});
