/**
 * XSS Mastery Lab — Module 12
 * Cumulative: M01–M11 + filter evasion and obfuscation endpoints.
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
textarea{height:80px;resize:vertical}
button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#fb923c}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}`;

const page = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>${CSS}</style></head>
<body><a class="back" href="/">← Lab Home</a>${body}</body></html>`;

// ── M01–M11 condensed ─────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:12}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/api/search", (req,res) => res.json({query:req.query.q||"",results:[],count:0}));
app.get("/board", (req,res) => { const items=comments.length?comments.map(c=>`<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700">${c.author}</span><p style="margin-top:6px;font-size:14px">${c.text}</p></div>`).join(""):`<p style="color:#7a9bbf">No comments.</p>`; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Board",`<h2>Board</h2><div class="box"><form method="POST" action="/board/post"><input name="author" placeholder="Name" required><textarea name="text" placeholder="Comment…" required></textarea><button type="submit">Post</button></form></div>${items}`)); });
app.post("/board/post", (req,res) => { comments.push({author:req.body.author||"Anon",text:req.body.text||""}); res.redirect("/board"); });
app.get("/board/clear", (req,res) => { comments.length=0; res.redirect("/board"); });
app.get("/admin", (req,res) => { const rows=profiles.map(p=>`<tr><td style="padding:8px;color:#f5c842">${p.username}</td><td style="padding:8px">${p.bio}</td><td style="padding:8px"><a href="${p.website}">${p.website||"—"}</a></td></tr>`).join(""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Admin",`<h2 style="color:#f5c842">Admin Panel</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th></tr></thead><tbody>${rows}</tbody></table></div>`)); });
app.get("/admin/profile", (req,res) => { res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Register",`<h2>Register</h2><div class="box"><form method="POST"><input name="username" placeholder="Username" required><textarea name="bio" placeholder="Bio…"></textarea><input name="website" placeholder="Website"><button type="submit">Register</button></form></div>`)); });
app.post("/admin/profile", (req,res) => { profiles.push({username:req.body.username||"",bio:req.body.bio||"",website:req.body.website||""}); res.redirect("/admin"); });
app.get("/admin/clear", (req,res) => { profiles.length=0; res.redirect("/admin"); });
app.get("/oob", (req,res) => { oobHits.push({ts:new Date().toISOString().slice(0,19),ip:req.ip,ua:req.headers["user-agent"]||"",origin:req.headers["origin"]||"",referer:req.headers["referer"]||"",params:req.query}); const gif=Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7","base64"); res.setHeader("Content-Type","image/gif"); res.setHeader("Cache-Control","no-store"); res.send(gif); });
app.get("/oob/log", (req,res) => res.json({count:oobHits.length,hits:oobHits}));
app.get("/oob/clear", (req,res) => { oobHits.length=0; res.json({cleared:true}); });
app.get("/log-viewer", (req,res) => { const rows=logEntries.length?logEntries.map(e=>`<tr><td style="padding:6px 10px;font-size:11px;color:#7a9bbf">${e.ts}</td><td style="padding:6px 10px;font-size:11px">${e.level}</td><td style="padding:6px 10px;font-size:12px">${e.message}</td></tr>`).join(""):`<tr><td colspan="3" style="padding:8px;color:#7a9bbf">No entries.</td></tr>`; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Log Viewer",`<h2 style="color:#f5c842">Log Viewer</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th></tr></thead><tbody>${rows}</tbody></table></div>`)); });
app.post("/log-entry", (req,res) => { logEntries.push({ts:new Date().toTimeString().slice(0,8),level:req.body.level||"INFO",message:req.body.message||""}); res.json({stored:true,count:logEntries.length}); });
app.get("/log-viewer/clear", (req,res) => { logEntries.length=0; res.redirect("/log-viewer"); });
app.get("/pdf-preview", (req,res) => { const c=req.query.content||"Your report here."; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("PDF Preview",`<h2>PDF Preview</h2><div class="box"><div style="background:#fff;color:#111;padding:40px;font-family:Georgia,serif;font-size:14px;line-height:1.8"><h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:16px">Security Report</h1><div id="report-content">${c}</div></div></div>`)); });
app.get("/email-preview", (req,res) => { const to=req.query.to||"user@example.com",sub=req.query.subject||"Notification",body=req.query.body||"Thank you!"; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Email Preview",`<h2>Email Preview</h2><div class="box" style="padding:0;overflow:hidden"><div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;border-bottom:1px solid #1e3a5f">To: <strong style="color:#e2e8f0">${to}</strong> · Subject: <strong style="color:#e2e8f0">${sub}</strong></div><div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;font-size:14px;line-height:1.7">${body}</div></div>`)); });

// ── M12 helpers ───────────────────────────────────────────────────────────────

function renderFilter(res, title, label, q, filtered, resultHtml) {
  const badge = filtered !== q ? '<span style="color:#f5c842;font-weight:700">BLOCKED/MODIFIED</span>'
                               : '<span style="color:#4ade80;font-weight:700">PASSED</span>';
  const body = `
<h2>${title}</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">${label}</p>
  <form method="GET">
    <input name="q" value="${q.replace(/"/g,'&quot;')}" placeholder="Payload">
    <button type="submit">Submit</button>
  </form>
  <p style="font-size:12px;margin-top:10px;color:#7a9bbf">Filter result: ${badge}</p>
  <p style="font-size:12px;color:#7a9bbf">After filter: <code style="color:#fb923c">${filtered.slice(0,300)}</code></p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rendered output ↓</p>
  ${resultHtml}
</div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page(title, body));
}

// ── M12 — Filter evasion routes ───────────────────────────────────────────────

app.get("/filter/blocklist", (req, res) => {
  const q = req.query.q || "";
  const blocked = ["script","alert","onerror","onload","javascript"];
  let filtered = q;
  blocked.forEach(kw => { filtered = filtered.split(kw).join("***"); });
  renderFilter(res, "Filter: Keyword Blocklist",
    "Blocks: script, alert, onerror, onload, javascript (case-sensitive). Try: onfocus, confirm(), svg onload.",
    q, filtered, `<div style="font-size:14px">${filtered}</div>`);
});

app.get("/filter/stripping", (req, res) => {
  const q = req.query.q || "";
  const filtered = q.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  renderFilter(res, "Filter: Script Tag Stripping",
    "Strips &lt;script&gt;…&lt;/script&gt; (one pass). Try: nested tags or non-script vectors.",
    q, filtered, `<div style="font-size:14px">${filtered}</div>`);
});

app.get("/filter/case", (req, res) => {
  const q = req.query.q || "";
  let filtered = q.replace(/script/gi, "***").replace(/alert/gi, "***");
  renderFilter(res, "Filter: Case-Insensitive Block",
    "Blocks 'script' and 'alert' regardless of case. Try: confirm(1), onfocus, img onerror.",
    q, filtered, `<div style="font-size:14px">${filtered}</div>`);
});

app.get("/filter/encoding", (req, res) => {
  const q = req.query.q || "";
  const filtered = (q.includes("<") || q.includes(">"))
    ? "[BLOCKED: raw angle brackets detected]" : q;
  renderFilter(res, "Filter: Raw Angle Bracket Block",
    "Blocks literal &lt; or &gt; but not HTML entity forms. Try: &amp;lt;img src=x onerror=alert(1)&amp;gt;",
    q, filtered, `<div style="font-size:14px">${filtered}</div>`);
});

app.get("/filter/length", (req, res) => {
  const q = req.query.q || "";
  const MAX = 30;
  const filtered = q.length > MAX ? `[BLOCKED: ${q.length} chars > ${MAX}]` : q;
  renderFilter(res, `Filter: Length Limit (${MAX} chars)`,
    `Rejects input over ${MAX} chars. Try: &lt;svg onload=alert(1)&gt; (22 chars).`,
    q, filtered, `<div style="font-size:14px">${filtered}</div>`);
});

app.get("/waf-sim", (req, res) => {
  const q = req.query.q || "";
  const steps = [];
  let current = q;

  const r1 = current.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  steps.push(["R1: strip &lt;script&gt;", current.slice(0,80), r1.slice(0,80)]);
  current = r1;

  const r2 = current.split("alert").join("***");
  steps.push(["R2: block 'alert'", current.slice(0,80), r2.slice(0,80)]);
  current = r2;

  const r3 = current.replace(/javascript\s*:/gi, "[JS-BLOCKED]:");
  steps.push(["R3: block javascript:", current.slice(0,80), r3.slice(0,80)]);
  current = r3;

  const rows = steps.map(s =>
    `<tr><td style="padding:5px 8px;font-size:11px;color:#38bdf8">${s[0]}</td>` +
    `<td style="padding:5px 8px;font-size:11px;color:#7a9bbf;word-break:break-all">${s[1]}</td>` +
    `<td style="padding:5px 8px;font-size:11px;color:#fb923c;word-break:break-all">${s[2]}</td></tr>`
  ).join("");

  const table = `<table style="width:100%;border-collapse:collapse;margin-bottom:12px">
    <thead><tr>
      <th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Rule</th>
      <th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Input</th>
      <th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Output</th>
    </tr></thead><tbody>${rows}</tbody></table>`;

  const body = `
<h2>WAF Simulator</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    Three rules applied in sequence: strip &lt;script&gt; · block 'alert' · block 'javascript:'.
  </p>
  <form method="GET">
    <input name="q" value="${q.replace(/"/g,'&quot;')}" placeholder="Payload">
    <button type="submit">Submit</button>
  </form>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rule trace:</p>
  ${table}
  <p style="font-size:12px;color:#7a9bbf">Final: <code style="color:#fb923c">${current.slice(0,300)}</code></p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rendered ↓</p>
  <div style="font-size:14px">${current}</div>
</div>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("WAF Simulator", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 12`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  /filter/blocklist  /filter/stripping  /filter/case`);
  console.log(`  /filter/encoding   /filter/length     /waf-sim\n`);
});
