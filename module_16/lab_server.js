/**
 * Module 16 — Real-World Incidents Lab (Node.js)
 * SocialDemo worm propagation server.
 */
const express = require('express');
const cookieSession = require('cookie-session');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({ name: 'sess', secret: 'xss-lab-key', maxAge: 86400000 }));
app.use('/cases', express.static(path.join(__dirname, 'case_studies')));

const profiles = {
  alice: 'Hi, I am alice.',
  bob: 'Hi, I am bob.',
  charlie: 'Hi, I am charlie.',
  dave: 'Hi, I am dave.',
};

const page = (title, body) => `<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>SocialDemo — ${title}</title>
<style>
:root{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--danger:#f87171}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif}
nav{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;gap:16px;align-items:center}
.brand{font-weight:800;color:var(--accent);margin-right:auto}
nav a{color:var(--accent);text-decoration:none;font-size:13px}
main{padding:32px;max-width:700px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
input,textarea{width:100%;padding:9px;background:#060d1a;border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:13px;margin-bottom:10px}
button{padding:8px 18px;background:var(--accent);color:#0b0f1a;font-weight:700;border:none;border-radius:4px;cursor:pointer}
</style></head><body>
<nav><span class="brand">SocialDemo</span><a href="/">Home</a><a href="/profiles">Profiles</a><a href="/cases/samy_worm.html">Case Studies</a></nav>
<main>${body}</main></body></html>`;

app.get('/', (req, res) => {
  const user = req.session.user || 'guest';
  res.send(page('Home', `<div class="card"><h2 style="margin-bottom:12px;color:var(--accent)">Worm Propagation Demo</h2>
    <p style="font-size:13px;color:var(--muted);margin-bottom:12px">Set your profile message. A worm payload replicates into every visitor's profile.</p>
    <p style="font-size:12px;color:var(--muted)">Current user: <strong>${user}</strong></p>
    <a href="/login" style="color:var(--accent);font-size:13px">Switch user</a> &nbsp;|&nbsp;
    <a href="/profiles" style="color:var(--accent);font-size:13px">View all profiles</a></div>`));
});

app.get('/login', (req, res) => res.send(page('Login', `<div class="card"><h2 style="margin-bottom:12px">Set Username</h2>
  <form method=POST action=/login><input name=username placeholder="alice, bob, charlie, dave"><button>Enter</button></form></div>`)));

app.post('/login', (req, res) => {
  req.session.user = (req.body.username || 'guest').slice(0, 20);
  res.redirect('/');
});

app.get('/profile/view/:username', (req, res) => {
  const { username } = req.params;
  const bio = profiles[username] || '<em style="color:var(--muted)">No message set.</em>';
  // bio rendered WITHOUT encoding — worm replication sink
  res.send(page(`${username} profile`, `<div class="card">
    <h2 style="margin-bottom:8px;color:var(--accent)">${username}'s Profile</h2>
    <div style="min-height:40px">${bio}</div></div>
    <a href="/profiles" style="font-size:12px;color:var(--muted)">← All profiles</a>`));
});

app.get('/profile/edit', (req, res) => {
  const user = req.session.user || 'guest';
  const csrf = crypto.randomBytes(8).toString('hex');
  req.session.csrf = csrf;
  res.send(page('Edit profile', `<div class="card"><h2 style="margin-bottom:12px">Edit Your Profile (${user})</h2>
    <form method=POST action=/profile/update>
      <input type=hidden name=csrf value="${csrf}">
      <textarea name=bio rows=4 placeholder="Enter your message...">${profiles[user] || ''}</textarea>
      <button type=submit>Save</button></form></div>`));
});

app.post('/profile/update', (req, res) => {
  const user = req.session.user || 'guest';
  profiles[user] = req.body.bio || '';
  if (req.headers['content-type'] === 'application/x-www-form-urlencoded' && !req.headers['x-requested-with']) {
    return res.redirect(`/profile/view/${user}`);
  }
  res.status(204).end();
});

app.get('/profiles', (req, res) => {
  const viewer = req.session.user || 'guest';
  const rows = Object.keys(profiles).map(u =>
    `<li style="margin-bottom:8px"><a href="/profile/view/${u}" style="color:var(--accent)">${u}</a></li>`).join('');
  res.send(page('Profiles', `<div class="card"><h2 style="margin-bottom:12px">All Profiles</h2>
    <ul style="list-style:none">${rows}</ul></div>
    <a href="/profile/edit" style="font-size:13px;color:var(--accent)">Edit your profile (${viewer})</a>`));
});

app.listen(5000, () => {
  console.log('SocialDemo worm lab — http://localhost:5000');
  console.log('Pre-seeded profiles: alice, bob, charlie, dave');
});
