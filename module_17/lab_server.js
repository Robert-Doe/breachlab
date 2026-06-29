/**
 * Module 17 — Defenses Lab (Node.js / Express)
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

const he = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const page = (title, body) => `<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>Defense Lab — ${title}</title>
<style>
:root{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--danger:#f87171;--warn:#f5c842;--orange:#fb923c}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif}
nav{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;gap:16px;align-items:center}
.brand{font-weight:800;color:var(--accent);margin-right:auto}
nav a{color:var(--accent);text-decoration:none;font-size:13px}
main{padding:32px;max-width:900px}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:var(--orange);padding:2px 6px;border-radius:3px}
</style></head><body>
<nav><span class="brand">DefenseLab M17</span>
<a href="/">Home</a><a href="/csp-demo">CSP Demo</a><a href="/tt-demo">Trusted Types</a>
<a href="/sanitizer-demo">Sanitizer</a><a href="/encoding-demo">Encoding</a></nav>
<main>${body}</main></body></html>`;

app.get('/', (req, res) => res.send(page('Home', `
<h1 style="color:var(--accent);font-size:22px;margin-bottom:16px">M17 Defense Lab</h1>
<ul style="list-style:none;font-size:14px;line-height:2.4">
  <li><a href="/csp-demo?q=${encodeURIComponent('<img src=x onerror=alert(1)>')}" style="color:var(--accent)">/csp-demo</a> — CSP enforcement</li>
  <li><a href="/csp-demo-nonce?q=${encodeURIComponent('<img src=x onerror=alert(1)>')}" style="color:var(--accent)">/csp-demo-nonce</a> — Nonce-based CSP</li>
  <li><a href="/tt-demo" style="color:var(--accent)">/tt-demo</a> — Trusted Types</li>
  <li><a href="/sanitizer-demo" style="color:var(--accent)">/sanitizer-demo</a> — Sanitizer comparison</li>
  <li><a href="/encoding-demo" style="color:var(--accent)">/encoding-demo</a> — Encoding contexts</li>
</ul>`)));

app.get('/csp-demo', (req, res) => {
  const q = req.query.q || '<img src=x onerror=alert(1)>';
  res.send(page('CSP Demo', `
  <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">CSP Demo</h1>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
    <div style="background:var(--panel);border:1px solid var(--danger);border-radius:8px;padding:20px">
      <h2 style="font-size:13px;color:var(--danger);margin-bottom:8px">No CSP (vulnerable)</h2>
      <div id="vuln" style="background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px"></div>
      <script>document.getElementById('vuln').innerHTML = ${JSON.stringify(q)};</script>
    </div>
    <div style="background:var(--panel);border:1px solid var(--ok);border-radius:8px;padding:20px">
      <h2 style="font-size:13px;color:var(--ok);margin-bottom:8px">Output Encoding (safe)</h2>
      <div style="background:#060d1a;padding:10px;border-radius:4px;font-size:12px">${he(q)}</div>
    </div>
  </div>`));
});

app.get('/csp-demo-nonce', (req, res) => {
  const q = req.query.q || '<img src=x onerror=alert(1)>';
  const nonce = crypto.randomBytes(16).toString('base64');
  const html = page('CSP Nonce', `
  <h1 style="color:var(--accent);font-size:18px;margin-bottom:12px">Nonce-based CSP</h1>
  <p style="font-size:12px;color:var(--muted);margin-bottom:16px">
    Policy: <code>script-src 'nonce-${nonce}'</code> — only &lt;script nonce="${nonce}"&gt; executes.
  </p>
  <div id="out" style="background:#060d1a;padding:12px;border-radius:4px;min-height:30px;font-size:12px"></div>
  <script nonce="${nonce}">
    document.getElementById('out').innerHTML = ${JSON.stringify(q)};
  </script>`);
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'nonce-${nonce}'; report-uri /csp-report`);
  res.send(html);
});

app.post('/csp-report', (req, res) => {
  console.log('[CSP VIOLATION]', JSON.stringify(req.body, null, 2).slice(0, 300));
  res.status(204).end();
});

app.get('/tt-demo', (req, res) => {
  const html = page('Trusted Types', `
  <h1 style="color:var(--accent);font-size:18px;margin-bottom:12px">Trusted Types Demo</h1>
  <p style="font-size:12px;color:var(--muted);margin-bottom:16px">CSP enforces require-trusted-types-for 'script'. Check the Console.</p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    <div style="background:var(--panel);border:1px solid var(--danger);border-radius:8px;padding:16px">
      <h2 style="font-size:12px;color:var(--danger);margin-bottom:8px">Direct innerHTML (blocked)</h2>
      <div id="bad" style="background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px"></div>
      <p id="bad-out" style="font-size:11px;color:var(--danger);margin-top:6px"></p>
    </div>
    <div style="background:var(--panel);border:1px solid var(--ok);border-radius:8px;padding:16px">
      <h2 style="font-size:12px;color:var(--ok);margin-bottom:8px">Via TT Policy (allowed)</h2>
      <div id="good" style="background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px"></div>
      <p id="good-out" style="font-size:11px;color:var(--ok);margin-top:6px"></p>
    </div>
  </div>
  <script>
    try {
      document.getElementById('bad').innerHTML = '<img src=x onerror=alert(1)>';
      document.getElementById('bad-out').textContent = 'TT not enforced';
    } catch(e) {
      document.getElementById('bad-out').textContent = 'Blocked: ' + e.message.slice(0,80);
    }
    if (window.trustedTypes && trustedTypes.createPolicy) {
      const p = trustedTypes.createPolicy('safe', {
        createHTML: s => s.replace(/\\s+on\\w+\\s*=\\s*["'][^"']*["']/gi,'').replace(/\\s+on\\w+=[^\\s>]*/gi,'')
      });
      document.getElementById('good').innerHTML = p.createHTML('<b>Bold</b> <img src=x onerror=alert(1)>');
      document.getElementById('good-out').textContent = 'Event handlers stripped by policy';
    }
  </script>`);
  res.setHeader('Content-Security-Policy', "require-trusted-types-for 'script'");
  res.send(html);
});

app.get('/sanitizer-demo', (req, res) => {
  const q = req.query.q || '<img src=x onerror=alert(1)><b>bold</b>';
  res.send(page('Sanitizer Compare', `
  <h1 style="color:var(--accent);font-size:18px;margin-bottom:8px">Sanitizer Comparison</h1>
  <p style="font-size:12px;color:var(--muted);margin-bottom:16px">Input: <code>${he(q)}</code></p>
  <div id="results" style="display:grid;grid-template-columns:1fr 1fr;gap:14px"></div>
  <script>
    const q = ${JSON.stringify(q)};
    [
      {label:'No sanitizer',color:'var(--danger)',fn:s=>s},
      {label:'Strip <script> only',color:'var(--warn)',fn:s=>s.replace(/<script[\\s\\S]*?<\\/script>/gi,'')},
      {label:'textContent (always safe)',color:'var(--ok)',fn:null},
      {label:'DOMPurify (if loaded)',color:'var(--ok)',fn:s=>typeof DOMPurify!=='undefined'?DOMPurify.sanitize(s):'Load DOMPurify first'}
    ].forEach(c=>{
      const d=document.createElement('div');
      d.style.cssText='background:var(--panel);border:1px solid '+c.color+';border-radius:8px;padding:16px';
      const h=document.createElement('h2');
      h.style.cssText='font-size:12px;color:'+c.color+';margin-bottom:8px';
      h.textContent=c.label;
      const o=document.createElement('div');
      o.style.cssText='background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px';
      if(c.fn===null){o.textContent=q;}else{o.innerHTML=c.fn(q);}
      d.appendChild(h);d.appendChild(o);
      document.getElementById('results').appendChild(d);
    });
  </script>`));
});

app.get('/encoding-demo', (req, res) => {
  const q = req.query.q || '<script>alert(1)</script>';
  res.send(page('Encoding Contexts', `
  <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">Output Encoding Contexts</h1>
  <table style="width:100%;border-collapse:collapse;font-size:12px">
    <tr style="color:var(--muted)"><th style="text-align:left;padding:8px;border-bottom:1px solid var(--border)">Context</th><th style="padding:8px;border-bottom:1px solid var(--border)">Result</th><th style="padding:8px;border-bottom:1px solid var(--border)">Method</th></tr>
    <tr><td style="padding:8px;border-bottom:1px solid var(--border)">HTML body</td><td style="padding:8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--orange)">${he(q)}</td><td style="padding:8px;border-bottom:1px solid var(--border);color:var(--ok)">he() — escape &lt; &gt; &amp; &quot;</td></tr>
    <tr><td style="padding:8px;border-bottom:1px solid var(--border)">JS string</td><td style="padding:8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--orange)">${he(JSON.stringify(q))}</td><td style="padding:8px;border-bottom:1px solid var(--border);color:var(--ok)">JSON.stringify()</td></tr>
    <tr><td style="padding:8px">URL param</td><td style="padding:8px;font-family:monospace;color:var(--orange)">${he(encodeURIComponent(q))}</td><td style="padding:8px;color:var(--ok)">encodeURIComponent()</td></tr>
  </table>`));
});

app.listen(5000, () => {
  console.log('Defense lab — http://localhost:5000');
});
