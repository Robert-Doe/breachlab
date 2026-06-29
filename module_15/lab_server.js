/**
 * Module 15 — Attack Chaining Lab (Node.js / Express)
 * Mirrors the Python server for students who prefer Node.
 * Run: node lab_server.js
 */
const express = require('express');
const cookieSession = require('cookie-session');
const crypto = require('crypto');
const http = require('http');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieSession({ name: 'sess', secret: 'xss-lab-insecure-key', maxAge: 24 * 3600 * 1000 }));

const USERS = {
  alice: { password: 'password123', email: 'alice@example.com', bio: '', role: 'user' },
  admin: { password: 'admin123', email: 'admin@example.com', bio: '', role: 'admin' },
};

function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(16).toString('hex');
  return req.session.csrf;
}
function checkCsrf(req) { return req.body.csrf === req.session.csrf; }

const page = (title, nav, body) => `<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>ChainBank — ${title}</title>
<style>
:root{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--warn:#f5c842;--danger:#f87171}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif}
nav{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:16px}
nav a{color:var(--accent);text-decoration:none;font-size:13px}
.brand{font-weight:800;color:var(--accent);font-size:16px;margin-right:auto}
main{padding:36px 32px;max-width:700px}
h1{font-size:20px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:24px;margin-bottom:20px}
input,textarea{width:100%;padding:9px 12px;background:#060d1a;border:1px solid var(--border);border-radius:5px;color:var(--text);font-size:14px;margin-bottom:12px}
button{padding:9px 20px;background:var(--accent);color:#0b0f1a;font-weight:700;border:none;border-radius:5px;cursor:pointer;font-size:14px}
.flash{padding:10px 16px;border-radius:5px;margin-bottom:16px;font-size:13px}
.ok{background:#013020;border:1px solid var(--ok);color:var(--ok)}
.err{background:#2a0000;border:1px solid var(--danger);color:var(--danger)}
label{font-size:13px;color:var(--muted);display:block;margin-bottom:4px}
.field{margin-bottom:14px}
</style></head><body>
<nav><span class="brand">ChainBank</span>${nav}</nav>
<main>${body}</main>
</body></html>`;

const navAuth = u => `<a href="/auth/profile">Profile</a><a href="/auth/settings">Settings</a><a href="/auth/logout">Logout (${u})</a>`;
const navAnon = '<a href="/auth/login">Login</a>';

app.get('/', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  res.send(page('Home', navAuth(u), `<h1>Welcome, ${u}</h1><p style="color:var(--muted);font-size:14px">Logged in as <strong>${u}</strong> (${USERS[u].role}).</p>`));
});

app.get('/auth/login', (req, res) => {
  const csrf = csrfToken(req);
  res.send(page('Login', navAnon, `<div class="card"><h1 style="margin-bottom:16px">Sign In</h1>
    <form method=POST action=/auth/login>
      <input type=hidden name=csrf value="${csrf}">
      <div class="field"><label>Username</label><input name=username placeholder="alice or admin"></div>
      <div class="field"><label>Password</label><input type=password name=password placeholder="password123"></div>
      <button type=submit>Login</button>
    </form></div>`));
});

app.post('/auth/login', (req, res) => {
  const { username: u, password: p } = req.body;
  if (USERS[u] && USERS[u].password === p) {
    req.session.user = u;
    req.session.csrf = undefined;
    return res.redirect('/');
  }
  res.send(page('Login', navAnon, '<div class="flash err">Invalid credentials.</div><a href="/auth/login">Try again</a>'));
});

app.get('/auth/logout', (req, res) => { req.session = null; res.redirect('/auth/login'); });

app.get('/auth/profile', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  const csrf = csrfToken(req);
  // bio rendered WITHOUT escaping — stored XSS sink
  res.send(page('Profile', navAuth(u), `<div class="card"><h1>Your Profile</h1>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px">Bio (displayed to all visitors):</p>
    <div style="background:#060d1a;border:1px solid var(--border);padding:14px;border-radius:5px;margin-bottom:16px;min-height:40px">${USERS[u].bio}</div>
    <form method=POST><input type=hidden name=csrf value="${csrf}">
      <div class="field"><label>Update Bio</label><textarea name=bio rows=4>${USERS[u].bio}</textarea></div>
      <button type=submit>Save</button></form></div>`));
});

app.post('/auth/profile', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  if (!checkCsrf(req)) return res.status(403).send('CSRF failed');
  USERS[u].bio = req.body.bio || '';
  res.redirect('/auth/profile');
});

app.get('/auth/settings', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  const csrf = csrfToken(req);
  res.send(page('Settings', navAuth(u), `<div class="card"><h1>Account Settings</h1>
    <form method=POST><input type=hidden name=csrf value="${csrf}">
      <div class="field"><label>Email</label><input name=email value="${USERS[u].email}"></div>
      <button type=submit>Update</button></form></div>`));
});

app.post('/auth/settings', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  if (!checkCsrf(req)) return res.status(403).send('CSRF failed');
  if (req.body.email) USERS[u].email = req.body.email;
  res.redirect('/auth/settings');
});

app.post('/auth/change-password', (req, res) => {
  const u = req.session.user;
  if (!u) return res.status(401).json({ error: 'not authenticated' });
  if (!checkCsrf(req)) return res.status(403).json({ error: 'csrf' });
  const pw = req.body.new_password || '';
  if (pw.length < 4) return res.status(400).json({ error: 'too short' });
  USERS[u].password = pw;
  res.json({ ok: true, message: `Password changed for ${u}` });
});

app.get('/auth/users', (req, res) => {
  const u = req.session.user;
  if (!u) return res.redirect('/auth/login');
  if (USERS[u].role !== 'admin') return res.status(403).send('Forbidden');
  const rows = Object.entries(USERS).map(([name, d]) =>
    `<tr><td style="padding:8px">${name}</td><td style="padding:8px">${d.email}</td><td style="padding:8px;max-width:300px">${d.bio}</td></tr>`).join('');
  res.send(page('Admin Users', navAuth(u), `<h1>User Management</h1>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="color:var(--muted)"><th style="text-align:left;padding:8px">User</th><th style="text-align:left;padding:8px">Email</th><th style="text-align:left;padding:8px">Bio</th></tr>
      ${rows}</table>`));
});

// OOB receiver on port 5001
const oob = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    console.log('\n[OOB RECEIVED]', req.url);
    const params = new URLSearchParams(req.url.split('?')[1]);
    for (const [k, v] of params) console.log(`  ${k}: ${decodeURIComponent(v).slice(0, 200)}`);
    if (body) { try { console.log(JSON.stringify(JSON.parse(body), null, 2).slice(0, 400)); } catch { console.log(body.slice(0, 400)); } }
    res.writeHead(200, { 'Access-Control-Allow-Origin': '*' });
    res.end('ok');
  });
});

app.listen(5000, () => {
  console.log('ChainBank lab server — http://localhost:5000');
  console.log('Users: alice/password123, admin/admin123');
});
oob.listen(5001, () => console.log('OOB receiver       — http://localhost:5001'));
