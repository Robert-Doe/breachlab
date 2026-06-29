/**
 * XSS Mastery Lab — Module 13
 * Cumulative: M01–M12 + mutation XSS (mXSS) endpoints.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Stores ────────────────────────────────────────────────────────────────────

const oobHits    = [];
const logEntries = [];
const comments   = [];
const profiles   = [];

// ── Shell ─────────────────────────────────────────────────────────────────────

const CSS = `body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;padding:32px;max-width:780px}
h2{color:#38bdf8;margin-bottom:10px}.box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;box-sizing:border-box}
button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#fb923c}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}`;

const page = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>${CSS}</style></head>
<body><a class="back" href="/">← Lab Home</a>${body}</body></html>`;

// ── Naive sanitiser ───────────────────────────────────────────────────────────

function naiveSanitise(html) {
  return html
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
    .replace(/javascript\s*:/gi, "[blocked]:");
}

// ── M01–M12 condensed ─────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:13}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/api/search", (req,res) => res.json({query:req.query.q||"",results:[],count:0}));
app.get("/board", (req,res) => { const items=comments.length?comments.map(c=>`<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700">${c.author}</span><p style="margin-top:6px;font-size:14px">${c.text}</p></div>`).join(""):`<p style="color:#7a9bbf">No comments.</p>`; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Board",`<h2>Board</h2><div class="box"><form method="POST" action="/board/post"><input name="author" placeholder="Name" required><textarea name="text" placeholder="Comment…" required></textarea><button type="submit">Post</button></form></div>${items}`)); });
app.post("/board/post", (req,res) => { comments.push({author:req.body.author||"Anon",text:req.body.text||""}); res.redirect("/board"); });
app.get("/board/clear", (req,res) => { comments.length=0; res.redirect("/board"); });
app.get("/admin", (req,res) => { const rows=profiles.map(p=>`<tr><td style="padding:8px;color:#f5c842">${p.username}</td><td style="padding:8px">${p.bio}</td><td style="padding:8px"><a href="${p.website}">${p.website||"—"}</a></td></tr>`).join(""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Admin",`<h2 style="color:#f5c842">Admin</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th></tr></thead><tbody>${rows}</tbody></table></div>`)); });
app.get("/admin/profile", (req,res) => { res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Register",`<h2>Register</h2><div class="box"><form method="POST"><input name="username" placeholder="Username" required><textarea name="bio" placeholder="Bio…"></textarea><input name="website" placeholder="Website"><button type="submit">Register</button></form></div>`)); });
app.post("/admin/profile", (req,res) => { profiles.push({username:req.body.username||"",bio:req.body.bio||"",website:req.body.website||""}); res.redirect("/admin"); });
app.get("/admin/clear", (req,res) => { profiles.length=0; res.redirect("/admin"); });
app.get("/oob", (req,res) => { oobHits.push({ts:new Date().toISOString().slice(0,19),ip:req.ip,ua:req.headers["user-agent"]||"",origin:req.headers["origin"]||"",referer:req.headers["referer"]||"",params:req.query}); const gif=Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7","base64"); res.setHeader("Content-Type","image/gif"); res.setHeader("Cache-Control","no-store"); res.send(gif); });
app.get("/oob/log", (req,res) => res.json({count:oobHits.length,hits:oobHits}));
app.get("/oob/clear", (req,res) => { oobHits.length=0; res.json({cleared:true}); });
app.get("/log-viewer", (req,res) => { const rows=logEntries.length?logEntries.map(e=>`<tr><td style="padding:6px 10px;font-size:11px;color:#7a9bbf">${e.ts}</td><td style="padding:6px 10px;font-size:11px">${e.level}</td><td style="padding:6px 10px;font-size:12px">${e.message}</td></tr>`).join(""):`<tr><td colspan="3" style="padding:8px;color:#7a9bbf">No entries.</td></tr>`; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Log Viewer",`<h2 style="color:#f5c842">Log Viewer</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th></tr></thead><tbody>${rows}</tbody></table></div>`)); });
app.post("/log-entry", (req,res) => { logEntries.push({ts:new Date().toTimeString().slice(0,8),level:req.body.level||"INFO",message:req.body.message||""}); res.json({stored:true,count:logEntries.length}); });
app.get("/log-viewer/clear", (req,res) => { logEntries.length=0; res.redirect("/log-viewer"); });
app.get("/pdf-preview", (req,res) => { const c=req.query.content||"Report."; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("PDF Preview",`<h2>PDF Preview</h2><div class="box"><div style="background:#fff;color:#111;padding:40px;font-family:Georgia,serif;font-size:14px;line-height:1.8">${c}</div></div>`)); });
app.get("/email-preview", (req,res) => { const to=req.query.to||"user@example.com",sub=req.query.subject||"Notification",b=req.query.body||"Thank you!"; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Email Preview",`<h2>Email Preview</h2><div class="box" style="padding:0;overflow:hidden"><div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;border-bottom:1px solid #1e3a5f">To: <strong>${to}</strong> · Subject: <strong>${sub}</strong></div><div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;font-size:14px">${b}</div></div>`)); });
app.get("/filter/blocklist", (req,res) => { const q=req.query.q||""; let f=q; ["script","alert","onerror","onload","javascript"].forEach(kw=>{f=f.split(kw).join("***");}); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Blocklist",`<h2>Blocklist</h2><div class="box"><form method="GET"><input name="q" value="${q.replace(/"/g,'&quot;')}"><button type="submit">Submit</button></form><p style="font-size:12px;margin-top:10px;color:#7a9bbf">After: <code style="color:#fb923c">${f.slice(0,300)}</code></p></div><div class="box">${f}</div>`)); });
app.get("/waf-sim", (req,res) => { const q=req.query.q||""; let c=q; c=c.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi,""); c=c.split("alert").join("***"); c=c.replace(/javascript\s*:/gi,"[JS-BLOCKED]:"); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("WAF Sim",`<h2>WAF Simulator</h2><div class="box"><form method="GET"><input name="q" value="${q.replace(/"/g,'&quot;')}"><button type="submit">Submit</button></form></div><div class="box"><div style="font-size:14px">${c}</div></div>`)); });

// ── M13 mXSS shared renderer ──────────────────────────────────────────────────

function mxssPage(res, title, desc, q, sanitised, note) {
  const sanitisedJson = JSON.stringify(sanitised);
  const body = `
<h2>${title}</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">${desc}</p>
  <form method="GET">
    <input name="q" value="${q.replace(/"/g,'&quot;')}" placeholder="Payload">
    <button type="submit">Submit</button>
  </form>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf">Server-sanitised output:</p>
  <pre id="sanitised-display"></pre>
  <p style="font-size:12px;color:#7a9bbf;margin-top:10px">${note}</p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Client renders via innerHTML ↓</p>
  <div id="mxss-target" style="font-size:14px"></div>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Actual DOM after innerHTML (innerHTML readback):</p>
  <pre id="dom-dump" style="color:#4ade80"></pre>
</div>
<script>
  const sanitised = ${sanitisedJson};
  document.getElementById('sanitised-display').textContent = sanitised;
  const target = document.getElementById('mxss-target');
  target.innerHTML = sanitised;
  document.getElementById('dom-dump').textContent = target.innerHTML;
</script>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page(title, body));
}

// ── M13 mXSS routes ───────────────────────────────────────────────────────────

app.get("/mxss/innerHTML", (req, res) => {
  const q = req.query.q || "";
  const sanitised = naiveSanitise(q);
  mxssPage(res,
    "mXSS: Basic innerHTML Insertion",
    "Server strips &lt;script&gt; and javascript:. Sanitised string inserted via innerHTML client-side. " +
    "Observe DOM readback — the browser may re-parse differently.",
    q, sanitised,
    "mXSS opportunity: innerHTML re-parsing may produce a different DOM than the sanitiser modelled.");
});

app.get("/mxss/table", (req, res) => {
  const q = req.query.q || "";
  const sanitised = naiveSanitise(q);
  const wrapped = `<table>${sanitised}</table>`;
  mxssPage(res,
    "mXSS: Table Foster Parenting",
    "Input is wrapped in &lt;table&gt;. The HTML5 parser moves non-table content out via foster parenting. " +
    "Content that appears inside the table tag ends up in the document body.",
    q, wrapped,
    "Try: &lt;img src=x onerror=alert(1)&gt; — the server wraps it in &lt;table&gt;, " +
    "but the parser ejects it into the body where onerror fires.");
});

app.get("/mxss/namespace", (req, res) => {
  const q = req.query.q || "";
  const sanitised = naiveSanitise(q);
  mxssPage(res,
    "mXSS: SVG Namespace Boundary",
    "SVG and HTML parsers interpret content differently. " +
    "A payload inert in SVG context may become active when re-inserted in HTML context.",
    q, sanitised,
    "Classic: &lt;svg&gt;&lt;style&gt;&lt;/style&gt;&lt;img src=x onerror=alert(1)&gt;&lt;/svg&gt; — " +
    "style in SVG is raw text; serialised and re-parsed in HTML it ends at &lt;/style&gt;.");
});

app.get("/mxss/noscript", (req, res) => {
  const q = req.query.q || "";
  const sanitised = naiveSanitise(q);
  const wrapped = `<noscript>${sanitised}</noscript>`;
  mxssPage(res,
    "mXSS: &lt;noscript&gt; Scripting Context",
    "&lt;noscript&gt; is parsed as HTML when scripting is OFF, as raw text when scripting is ON. " +
    "A sanitiser and target browser may disagree on which mode applies.",
    q, wrapped,
    "Observe: with JS on, &lt;noscript&gt; content is raw text. With JS off, tags inside execute.");
});

app.get("/mxss/template", (req, res) => {
  const q = req.query.q || "";
  const sanitised = naiveSanitise(q);
  const wrapped = `<template>${sanitised}</template>`;
  mxssPage(res,
    "mXSS: &lt;template&gt; Inert vs Active Context",
    "&lt;template&gt; content is inert — scripts/event handlers do not fire on parse. " +
    "When template content is cloned and appended to the document, payloads activate.",
    q, wrapped,
    "Observe the DOM dump. Then use the clone button to activate the template content.");
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 13 (mXSS)`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  /mxss/innerHTML  /mxss/table  /mxss/namespace`);
  console.log(`  /mxss/noscript   /mxss/template\n`);
});
