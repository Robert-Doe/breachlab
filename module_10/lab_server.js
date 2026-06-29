/**
 * XSS Mastery Lab — Module 10
 * Cumulative: M01–M09 + in-memory comment board and admin panel.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── In-memory stores ──────────────────────────────────────────────────────────

const comments = [];  // { author, text, ts }
const profiles = [];  // { username, bio, website }

// ── Shared shell ──────────────────────────────────────────────────────────────

const CSS = `body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;padding:32px;max-width:760px}
h2{color:#38bdf8;margin-bottom:10px}.box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:6px}
input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;box-sizing:border-box}
textarea{height:80px;resize:vertical;font-family:inherit}
button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
.nav-links{display:flex;gap:16px;margin-bottom:24px;font-size:13px}.util{font-size:12px;color:#7a9bbf}.util a{color:#f87171}`;

const page = (title, body, nav = "board") => {
  const navHtml = nav === "admin"
    ? `<div class="nav-links"><a href="/board">📋 Comment Board</a><a href="/admin" style="color:#f5c842">🛡 Admin Panel</a></div>`
    : `<div class="nav-links"><a href="/board">📋 Comment Board</a><a href="/admin">🛡 Admin Panel</a></div>`;
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>${CSS}</style></head>
<body>
<a class="back" href="/">← Lab Home</a>
${navHtml}
${body}
</body></html>`;
};

// ── M01–M09 (condensed) ───────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:10}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/api/search", (req,res) => res.json({query:req.query.q||"",results:[],count:0}));

// ── M10 — Comment board ───────────────────────────────────────────────────────

app.get("/board", (req, res) => {
  const items = comments.length
    ? comments.map(c => `
      <div class="box" style="padding:14px 18px">
        <span style="color:#f5c842;font-weight:700;font-size:13px">${c.author}</span>
        <span style="color:#7a9bbf;font-size:11px;margin-left:8px">${c.ts}</span>
        <p style="margin-top:6px;font-size:14px">${c.text}</p>
      </div>`).join("\n")
    : '<p style="color:#7a9bbf;font-size:13px">No comments yet.</p>';

  const body = `
<h2>Comment Board</h2>
<div class="box">
  <label>Post a comment:</label>
  <form method="POST" action="/board/post">
    <input name="author" placeholder="Your name" required>
    <textarea name="text" placeholder="Comment text…" required></textarea>
    <button type="submit">Post Comment</button>
  </form>
</div>
<h2 style="margin-top:28px">Comments (${comments.length})</h2>
${items}
<p class="util" style="margin-top:20px">Lab utility: <a href="/board/clear">Clear all comments</a></p>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Comment Board", body, "board"));
});

app.post("/board/post", (req, res) => {
  const { author = "Anonymous", text = "" } = req.body;
  const ts = new Date().toTimeString().slice(0, 8);
  comments.push({ author, text, ts });
  res.redirect("/board");
});

app.get("/board/clear", (req, res) => { comments.length = 0; res.redirect("/board"); });

// ── M10 — Admin panel (second-order stored XSS) ───────────────────────────────

app.get("/admin", (req, res) => {
  const rows = profiles.length
    ? profiles.map(p => `
      <tr>
        <td style="color:#f5c842;font-family:'Courier New',monospace;font-size:13px;padding:8px;border-bottom:1px solid #1e3a5f">${p.username}</td>
        <td style="font-size:13px;padding:8px;border-bottom:1px solid #1e3a5f">${p.bio}</td>
        <td style="font-size:13px;padding:8px;border-bottom:1px solid #1e3a5f"><a href="${p.website}">${p.website || "—"}</a></td>
      </tr>`).join("\n")
    : `<tr><td colspan="3" style="color:#7a9bbf;padding:8px;font-size:13px">No profiles yet.</td></tr>`;

  const table = `<table style="width:100%;border-collapse:collapse">
    <thead><tr>
      <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Username</th>
      <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Bio</th>
      <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Website</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;

  const body = `
<h2 style="color:#f5c842">🛡 Admin Panel</h2>
<p style="color:#7a9bbf;font-size:13px;margin-bottom:16px">
  Registered user profiles — for admin review only.
</p>
<div class="box"><label>Stored profiles (${profiles.length}):</label>${table}</div>
<p class="util" style="margin-top:20px">
  <a href="/admin/clear">Clear all profiles</a> &nbsp;·&nbsp;
  <a href="/admin/profile" style="color:#38bdf8">Register a profile</a>
</p>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Admin Panel", body, "admin"));
});

app.get("/admin/profile", (req, res) => {
  const body = `
<h2>Register Profile</h2>
<div class="box">
  <label>Create a user profile (submitted for admin review):</label>
  <form method="POST" action="/admin/profile">
    <input name="username" placeholder="Username" required>
    <textarea name="bio" placeholder="Short bio…"></textarea>
    <input name="website" placeholder="Website URL (optional)">
    <button type="submit">Register</button>
  </form>
</div>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Register Profile", body));
});

app.post("/admin/profile", (req, res) => {
  const { username = "", bio = "", website = "" } = req.body;
  profiles.push({ username, bio, website });
  const body = `
<h2>Profile Registered</h2>
<div class="box">
  <p>Username: <strong>${username}</strong></p>
  <p>Bio: ${bio}</p>
  <p>Website: <a href="${website}">${website || "—"}</a></p>
  <p style="color:#7a9bbf;font-size:13px;margin-top:12px">Your profile will appear in the admin review panel.</p>
</div>
<p style="margin-top:16px"><a href="/admin/profile">Register another</a></p>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(page("Profile Registered", body));
});

app.get("/admin/clear", (req, res) => { profiles.length = 0; res.redirect("/admin"); });

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 10`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  Comment board: /board`);
  console.log(`  Admin panel:   /admin`);
  console.log(`  Profile form:  /admin/profile\n`);
});
