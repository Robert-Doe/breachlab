/**
 * XSS Mastery Lab — Module 11
 * Cumulative: M01–M10 + OOB receiver, log viewer, PDF/email preview surfaces.
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
label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:6px}
input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;box-sizing:border-box}
textarea{height:80px;resize:vertical;font-family:inherit}
button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#fb923c}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}`;

const page = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>${CSS}</style></head>
<body><a class="back" href="/">← Lab Home</a>${body}</body></html>`;

// ── M01–M10 (condensed) ───────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:11}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/api/search", (req,res) => res.json({query:req.query.q||"",results:[],count:0}));
app.get("/board", (req,res) => { const items=comments.length?comments.map(c=>`<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700;font-size:13px">${c.author}</span><p style="margin-top:6px;font-size:14px">${c.text}</p></div>`).join(""):`<p style="color:#7a9bbf">No comments.</p>`; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Board",`<h2>Comment Board</h2><div class="box"><form method="POST" action="/board/post"><input name="author" placeholder="Name" required><textarea name="text" placeholder="Comment…" required></textarea><button type="submit">Post</button></form></div>${items}`)); });
app.post("/board/post", (req,res) => { comments.push({author:req.body.author||"Anon",text:req.body.text||""}); res.redirect("/board"); });
app.get("/board/clear", (req,res) => { comments.length=0; res.redirect("/board"); });
app.get("/admin", (req,res) => { const rows=profiles.map(p=>`<tr><td style="padding:8px;font-size:13px;color:#f5c842">${p.username}</td><td style="padding:8px;font-size:13px">${p.bio}</td><td style="padding:8px;font-size:13px"><a href="${p.website}">${p.website||"—"}</a></td></tr>`).join(""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Admin",`<h2 style="color:#f5c842">Admin Panel</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th></tr></thead><tbody>${rows}</tbody></table></div>`)); });
app.get("/admin/profile", (req,res) => { res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(page("Register",`<h2>Register Profile</h2><div class="box"><form method="POST"><input name="username" placeholder="Username" required><textarea name="bio" placeholder="Bio…"></textarea><input name="website" placeholder="Website"><button type="submit">Register</button></form></div>`)); });
app.post("/admin/profile", (req,res) => { profiles.push({username:req.body.username||"",bio:req.body.bio||"",website:req.body.website||""}); res.redirect("/admin"); });
app.get("/admin/clear", (req,res) => { profiles.length=0; res.redirect("/admin"); });

// ── M11 — OOB receiver ────────────────────────────────────────────────────────

app.get("/oob", (req, res) => {
  oobHits.push({
    ts:      new Date().toISOString().slice(0, 19),
    ip:      req.ip,
    ua:      req.headers["user-agent"] || "",
    origin:  req.headers["origin"] || "",
    referer: req.headers["referer"] || "",
    params:  req.query,
  });
  // Return 1x1 transparent GIF
  const gif = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");
  res.setHeader("Content-Type", "image/gif");
  res.setHeader("Cache-Control", "no-store");
  res.send(gif);
});

app.get("/oob/log", (req, res) => res.json({ count: oobHits.length, hits: oobHits }));
app.get("/oob/clear", (req, res) => { oobHits.length = 0; res.json({ cleared: true }); });

// ── M11 — Log viewer (blind XSS sink) ────────────────────────────────────────

app.get("/log-viewer", (req, res) => {
  const rows = logEntries.length
    ? logEntries.map(e => {
        const color = {INFO:"#38bdf8",WARN:"#f5c842",ERROR:"#f87171"}[e.level] || "#e2e8f0";
        return `<tr style="border-bottom:1px solid #1e3a5f">
          <td style="padding:6px 10px;font-size:11px;color:#7a9bbf;white-space:nowrap">${e.ts}</td>
          <td style="padding:6px 10px;font-size:11px;color:${color}">${e.level}</td>
          <td style="padding:6px 10px;font-size:12px">${e.message}</td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="3" style="padding:8px;color:#7a9bbf;font-size:13px">No log entries.</td></tr>`;

  const body = `
<h2 style="color:#f5c842">Application Log Viewer</h2>
<div class="box">
  <table style="width:100%;border-collapse:collapse">
    <thead><tr>
      <th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th>
      <th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th>
      <th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>
<p style="font-size:12px;color:#7a9bbf;margin-top:12px">
  <a href="/oob/log">View OOB callbacks</a> &nbsp;·&nbsp;
  <a href="/log-viewer/clear" style="color:#f87171">Clear logs</a>
</p>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Log Viewer", body));
});

app.post("/log-entry", (req, res) => {
  const { level = "INFO", message = "" } = req.body;
  logEntries.push({ ts: new Date().toTimeString().slice(0, 8), level, message });
  res.json({ stored: true, count: logEntries.length });
});

app.get("/log-viewer/clear", (req, res) => { logEntries.length = 0; res.redirect("/log-viewer"); });

// ── M11 — PDF preview ─────────────────────────────────────────────────────────

app.get("/pdf-preview", (req, res) => {
  const content = req.query.content || "Your report content here.";
  const ts = new Date().toISOString().slice(0, 16).replace("T", " ");
  const body = `
<h2>PDF Preview</h2>
<div class="box" style="padding:0;overflow:hidden">
  <div style="background:#fff;color:#111;padding:40px;font-family:Georgia,serif;
              font-size:14px;line-height:1.8;min-height:200px">
    <h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:16px">Security Report</h1>
    <div id="report-content">${content}</div>
    <p style="font-size:11px;color:#666;margin-top:40px;border-top:1px solid #ccc;padding-top:8px">Generated: ${ts}</p>
  </div>
</div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("PDF Preview", body));
});

// ── M11 — Email preview ───────────────────────────────────────────────────────

app.get("/email-preview", (req, res) => {
  const to      = req.query.to      || "user@example.com";
  const subject = req.query.subject || "Your account notification";
  const bodyText = req.query.body   || "Thank you for signing up!";

  const body = `
<h2>Email Preview</h2>
<div class="box" style="padding:0;overflow:hidden">
  <div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;border-bottom:1px solid #1e3a5f">
    To: <strong style="color:#e2e8f0">${to}</strong> &nbsp;·&nbsp;
    Subject: <strong style="color:#e2e8f0">${subject}</strong>
  </div>
  <div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;
              font-size:14px;line-height:1.7;min-height:120px">
    ${bodyText}
  </div>
</div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Email Preview", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 11`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  OOB receiver:  /oob  (view at /oob/log)`);
  console.log(`  Log viewer:    /log-viewer`);
  console.log(`  PDF preview:   /pdf-preview?content=...`);
  console.log(`  Email preview: /email-preview?body=...\n`);
});
