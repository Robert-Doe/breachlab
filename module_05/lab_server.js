/**
 * XSS Mastery Lab — Module 05
 * Cumulative: M01–M04 + two new event-handler-focused endpoints.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Shared shell ──────────────────────────────────────────────────────────────

const shell = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;padding:32px;max-width:720px}
h2{color:#38bdf8;margin-bottom:10px}.box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}a{color:#38bdf8}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}
.back{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#fb923c}</style>
</head><body><a class="back" href="/attack_02_events.html">← Attack 02 Demo Page</a>${body}</body></html>`;

// ── M01–M04 ───────────────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:5}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/search", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search",`<h2>Search</h2><div class="box"><label>Results for:</label><div>${q}</div></div>`)); });
app.get("/search-attr", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search Attr",`<h2>Search Attr</h2><div class="box"><input value="${q}" style="width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px"></div>`)); });
app.get("/search-js", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search JS",`<h2>Search JS</h2><div class="box" id="r"></div><script>var q="${q}";document.getElementById("r").textContent="Searched: "+q<\/script>`)); });

// ── M05 — vuln-display ────────────────────────────────────────────────────────

app.get("/vuln-display", (req, res) => {
  const content = req.query.content || "";

  // Naive script-tag filter — strips <script>...</script> only.
  // Equivalent to Python's re.sub(r'<script[\s\S]*?</script>', '', content).
  // All event handlers pass through completely unaffected.
  const filtered = content.replace(/<script[\s\S]*?<\/script>/gi, "");

  const body = `
  <h2>Display with "Script Filter"</h2>
  <div class="box"><label>Original input:</label><pre>${content}</pre></div>
  <div class="box"><label>After removing &lt;script&gt; tags:</label><pre>${filtered}</pre></div>
  <div class="box">
    <label>Rendered (event handlers still execute here):</label>
    <div id="rendered" style="min-height:40px;padding:8px;
         border:2px dashed #f5c842;border-radius:4px">${filtered}</div>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Try: <code>?content=&lt;img src=x onerror=alert(document.domain)&gt;</code>
  </p>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("Vuln Display", body));
});

// ── M05 — filter-demo ─────────────────────────────────────────────────────────

app.get("/filter-demo", (req, res) => {
  let q = req.query.q || "";

  // Naive blocklist — blocks specific keywords but misses the long tail.
  const rules = [
    [/<script/gi,   "stripped <script"],
    [/javascript:/gi,"stripped javascript:"],
    [/onerror/gi,   "stripped onerror"],
    [/onload/gi,    "stripped onload"],
    [/onclick/gi,   "stripped onclick"],
  ];

  const applied = [];
  for (const [re, label] of rules) {
    if (re.test(q)) { q = q.replace(re, ""); applied.push(label); }
  }

  const rulesHtml = applied.length
    ? applied.map(r => `<li style="color:#f87171">${r}</li>`).join("")
    : `<li style="color:#4ade80">No rules triggered</li>`;

  const body = `
  <h2>Filter Demo — Naive Blocklist</h2>
  <div class="box"><label>Rules applied:</label>
    <ul style="font-size:13px;padding-left:18px">${rulesHtml}</ul></div>
  <div class="box">
    <label>Output after filtering:</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px;min-height:40px">${q}</div>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Bypasses: <code>ontoggle</code>, <code>onfocus</code>, <code>onmouseover</code>,
    <code>onanimationstart</code>, <code>onpointerover</code>
  </p>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("Filter Demo", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 05`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  vuln-display: /vuln-display?content=<img src=x onerror=alert(1)>`);
  console.log(`  filter-demo:  /filter-demo?q=<details open ontoggle=alert(1)>\n`);
});
