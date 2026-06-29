/**
 * XSS Mastery Lab — Module 07
 * Cumulative: M01–M06 + three new namespace-confusion endpoints.
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
</head><body><a class="back" href="/attack_04_namespace.html">← Attack 04 Demo Page</a>${body}</body></html>`;

// ── M01–M06 ───────────────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:7}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/search", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search",`<h2>Search</h2><div class="box"><label>Results:</label><div>${q}</div></div>`)); });
app.get("/search-attr", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search Attr",`<h2>Search Attr</h2><div class="box"><input value="${q}" style="width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px"></div>`)); });
app.get("/search-js", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search JS",`<h2>Search JS</h2><div class="box" id="r"></div><script>var q="${q}";document.getElementById("r").textContent="Searched: "+q<\/script>`)); });
app.get("/vuln-display", (req,res) => { const c=req.query.content||""; const f=c.replace(/<script[\s\S]*?<\/script>/gi,""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Vuln Display",`<h2>Vuln Display</h2><div class="box"><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${f}</div></div>`)); });
app.get("/filter-demo", (req,res) => {
  let q=req.query.q||"";
  const rules=[[/<script/gi,"stripped &lt;script"],[/javascript:/gi,"stripped javascript:"],[/onerror/gi,"stripped onerror"],[/onload/gi,"stripped onload"],[/onclick/gi,"stripped onclick"]];
  const applied=[];
  for(const [re,label] of rules){if(re.test(q)){q=q.replace(re,"");applied.push(label);}}
  const rh=applied.length?applied.map(r=>`<li style="color:#f87171">${r}</li>`).join(""):`<li style="color:#4ade80">No rules triggered</li>`;
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(shell("Filter Demo",`<h2>Filter Demo</h2><div class="box"><label>Rules applied:</label><ul style="font-size:13px;padding-left:18px">${rh}</ul></div><div class="box"><label>Output:</label><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${q}</div></div>`));
});
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/link-preview", (req,res) => { const url=req.query.url||""; const label=req.query.label||"Visit link"; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Link Preview",`<h2>Link Preview</h2><div class="box"><a href="${url}" style="font-size:18px;color:#f5c842">${label}</a></div>`)); });
app.get("/profile", (req,res) => {
  const username=req.query.username||"alice"; const bio=req.query.bio||"Security researcher";
  const site=req.query.site||""; const avatar=req.query.avatar||"";
  const av=avatar?`<img src="${avatar}" style="width:80px;height:80px;border-radius:50%;object-fit:cover">`:`<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;font-size:32px">👤</div>`;
  const sh=site?`<a href="${site}" style="color:#38bdf8">${site}</a>`:`<em style="color:#7a9bbf">No website</em>`;
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(shell(`Profile — ${username}`,`<h2>Profile</h2><div class="box" style="display:flex;gap:20px">${av}<div><p style="font-size:20px;font-weight:700">${username}</p><p style="color:#7a9bbf">${bio}</p><p style="font-size:13px">Site: ${sh}</p></div></div>`));
});

// ── M07 — SVG namespace injection ─────────────────────────────────────────────

app.get("/svg-inject", (req, res) => {
  const q = req.query.q || "";
  const body = `
  <h2>SVG Injection</h2>
  <div class="box">
    <label>SVG output (q= injected inside &lt;svg&gt;):</label>
    <div style="border:2px dashed #a78bfa;padding:10px;border-radius:4px;min-height:60px">
      <svg xmlns="http://www.w3.org/2000/svg" width="400" height="100"
           style="background:#060d1a;display:block;border-radius:4px">
        <text x="10" y="30" fill="#38bdf8" font-size="14">SVG context — injection below:</text>
        ${q}
      </svg>
    </div>
  </div>
  <div class="box">
    <label>Injection context:</label>
    <pre>&lt;svg ...&gt;\n  &lt;text ...&gt;SVG context:&lt;/text&gt;\n  ${q}   &lt;!-- injected --&gt;\n&lt;/svg&gt;</pre>
  </div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("SVG Inject", body));
});

// ── M07 — MathML namespace injection ──────────────────────────────────────────

app.get("/math-inject", (req, res) => {
  const q = req.query.q || "";
  const body = `
  <h2>MathML Injection</h2>
  <div class="box">
    <label>MathML output (q= injected inside &lt;math&gt;):</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px;min-height:40px">
      <math xmlns="http://www.w3.org/1998/Math/MathML">
        <mrow><mi>x</mi><mo>=</mo><mn>42</mn>${q}</mrow>
      </math>
    </div>
  </div>
  <div class="box">
    <label>Injection context:</label>
    <pre>&lt;math&gt;\n  &lt;mrow&gt;\n    &lt;mi&gt;x&lt;/mi&gt;&lt;mo&gt;=&lt;/mo&gt;&lt;mn&gt;42&lt;/mn&gt;\n    ${q}\n  &lt;/mrow&gt;\n&lt;/math&gt;</pre>
  </div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("MathML Inject", body));
});

// ── M07 — iframe srcdoc injection ─────────────────────────────────────────────

app.get("/iframe-inject", (req, res) => {
  const q = req.query.q || "";
  const body = `
  <h2>iframe srcdoc Injection</h2>
  <div class="box">
    <label>iframe rendered (srcdoc contains injected content):</label>
    <iframe srcdoc="<html><body style='background:#0b0f1a;color:#e2e8f0;padding:10px;font-family:sans-serif'><p>iframe document</p>${q}</body></html>"
            style="width:100%;height:100px;border:2px dashed #38bdf8;border-radius:4px"
            sandbox="allow-scripts allow-same-origin"></iframe>
  </div>
  <div class="box">
    <label>Injection context (srcdoc attribute value):</label>
    <pre>srcdoc="...&lt;p&gt;iframe doc&lt;/p&gt;${q}..."</pre>
  </div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("iframe srcdoc Inject", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 07`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  svg-inject:    /svg-inject?q=<script>alert(1)<\/script>`);
  console.log(`  math-inject:   /math-inject?q=<mtext><img src=x onerror=alert(1)></mtext>`);
  console.log(`  iframe-inject: /iframe-inject?q=<img src=x onerror=alert(1)>\n`);
});
