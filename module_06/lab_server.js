/**
 * XSS Mastery Lab — Module 06
 * Cumulative: M01–M05 + three new URI-scheme-focused endpoints.
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
</head><body><a class="back" href="/attack_03_uri.html">← Attack 03 Demo Page</a>${body}</body></html>`;

// ── M01–M05 ───────────────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:6}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/search", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search",`<h2>Search</h2><div class="box"><label>Results for:</label><div>${q}</div></div>`)); });
app.get("/search-attr", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search Attr",`<h2>Search Attr</h2><div class="box"><input value="${q}" style="width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px"></div>`)); });
app.get("/search-js", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search JS",`<h2>Search JS</h2><div class="box" id="r"></div><script>var q="${q}";document.getElementById("r").textContent="Searched: "+q<\/script>`)); });
app.get("/vuln-display", (req,res) => { const c=req.query.content||""; const f=c.replace(/<script[\s\S]*?<\/script>/gi,""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Vuln Display",`<h2>Display with Script Filter</h2><div class="box"><label>Filtered:</label><pre>${f}</pre></div><div class="box"><label>Rendered:</label><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${f}</div></div>`)); });
app.get("/filter-demo", (req,res) => {
  let q=req.query.q||"";
  const rules=[[/<script/gi,"stripped &lt;script"],[/javascript:/gi,"stripped javascript:"],[/onerror/gi,"stripped onerror"],[/onload/gi,"stripped onload"],[/onclick/gi,"stripped onclick"]];
  const applied=[];
  for(const [re,label] of rules){if(re.test(q)){q=q.replace(re,"");applied.push(label);}}
  const rh=applied.length?applied.map(r=>`<li style="color:#f87171">${r}</li>`).join(""):`<li style="color:#4ade80">No rules triggered</li>`;
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(shell("Filter Demo",`<h2>Filter Demo</h2><div class="box"><label>Rules applied:</label><ul style="font-size:13px;padding-left:18px">${rh}</ul></div><div class="box"><label>Output:</label><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${q}</div></div>`));
});

// ── M06 — open redirect ───────────────────────────────────────────────────────

app.get("/redirect", (req, res) => {
  const url = req.query.url || "/";
  // No scheme validation — javascript: passes through to the Location header.
  // Browsers follow javascript: Location headers by executing the JS in the
  // origin of the page that was being navigated away from.
  res.redirect(url);
});

// ── M06 — link preview (href injection) ───────────────────────────────────────

app.get("/link-preview", (req, res) => {
  const url   = req.query.url   || "";
  const label = req.query.label || "Visit link";

  const body = `
  <h2>Link Preview</h2>
  <div class="box">
    <label>URL supplied:</label>
    <pre>${url}</pre>
  </div>
  <div class="box">
    <label>Rendered link (click to execute):</label>
    <p style="margin-top:8px">
      <a href="${url}" style="font-size:18px;color:#f5c842">${label}</a>
    </p>
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Right-click → Copy Link Address to inspect the raw href.
    </p>
  </div>
  <div class="box">
    <label>Server code that produced this:</label>
    <pre>const url = req.query.url || "";
// NO scheme check — anything goes into href
res.send(\`&lt;a href="\${url}"&gt;${label}&lt;/a&gt;\`);</pre>
  </div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("Link Preview", body));
});

// ── M06 — profile page ────────────────────────────────────────────────────────

app.get("/profile", (req, res) => {
  const username = req.query.username || "alice";
  const bio      = req.query.bio      || "Security researcher";
  const site     = req.query.site     || "";
  const avatar   = req.query.avatar   || "";

  const avatarHtml = avatar
    ? `<img src="${avatar}" alt="avatar" style="width:80px;height:80px;border-radius:50%;object-fit:cover;border:2px solid #1e3a5f">`
    : `<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;font-size:32px">👤</div>`;

  const siteHtml = site
    ? `<a href="${site}" style="color:#38bdf8">${site}</a>`
    : `<em style="color:#7a9bbf">No website</em>`;

  const body = `
  <h2>User Profile</h2>
  <div class="box" style="display:flex;gap:24px;align-items:flex-start">
    ${avatarHtml}
    <div>
      <p style="font-size:22px;font-weight:700;margin-bottom:4px">${username}</p>
      <p style="color:#7a9bbf;margin-bottom:8px">${bio}</p>
      <p style="font-size:13px">Website: ${siteHtml}</p>
    </div>
  </div>
  <div class="box">
    <label>Injection points:</label>
    <ul style="font-size:13px;padding-left:18px">
      <li><code>bio=</code> → body context (event handlers from M05)</li>
      <li><code>site=</code> → placed in <code>href</code> (javascript: / data:)</li>
      <li><code>avatar=</code> → placed in <code>img src</code> (onerror / data: URI)</li>
    </ul>
  </div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell(`Profile — ${username}`, body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 06`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  redirect:     /redirect?url=javascript:alert(document.origin)`);
  console.log(`  link-preview: /link-preview?url=javascript:alert(1)`);
  console.log(`  profile:      /profile?username=eve&site=javascript:alert(1)\n`);
});
