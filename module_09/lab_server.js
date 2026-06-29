/**
 * XSS Mastery Lab — Module 09
 * Cumulative: M01–M08 + /api/search and /message endpoints.
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Shell ─────────────────────────────────────────────────────────────────────

const shell = (title, body) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${title}</title>
<style>body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;padding:32px;max-width:720px}
h2{color:#38bdf8;margin-bottom:10px}.box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}a{color:#38bdf8}
code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}
.back{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#fb923c}
input{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px;font-size:14px}</style>
</head><body><a class="back" href="/dom_lab.html">← DOM XSS Lab</a>${body}</body></html>`;

// ── M01–M08 ───────────────────────────────────────────────────────────────────

app.get("/", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/ping", (req,res) => res.json({status:"ok",module:9}));
app.get("/parse-demo", (req,res) => { const r=req.query.html||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${r}</body></html>`); });
app.get("/reflect", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(`<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">${q}</body></html>`); });
app.get("/search", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search",`<h2>Search</h2><div class="box"><div>${q}</div></div>`)); });
app.get("/search-attr", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search Attr",`<h2>Search Attr</h2><div class="box"><input value="${q}"></div>`)); });
app.get("/search-js", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Search JS",`<h2>Search JS</h2><div id="r" class="box"></div><script>var q="${q}";document.getElementById("r").textContent="Searched: "+q<\/script>`)); });
app.get("/vuln-display", (req,res) => { const c=req.query.content||""; const f=c.replace(/<script[\s\S]*?<\/script>/gi,""); res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Vuln Display",`<h2>Vuln Display</h2><div class="box"><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">${f}</div></div>`)); });
app.get("/filter-demo", (req,res) => {
  let q=req.query.q||"";
  const rules=[[/<script/gi,"stripped &lt;script"],[/javascript:/gi,"stripped javascript:"],[/onerror/gi,"stripped onerror"],[/onload/gi,"stripped onload"],[/onclick/gi,"stripped onclick"]];
  const applied=[];for(const [re,label] of rules){if(re.test(q)){q=q.replace(re,"");applied.push(label);}}
  const rh=applied.length?applied.map(r=>`<li style="color:#f87171">${r}</li>`).join(""):`<li style="color:#4ade80">No rules</li>`;
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(shell("Filter Demo",`<h2>Filter Demo</h2><div class="box"><ul style="padding-left:18px">${rh}</ul></div><div class="box"><div style="border:2px dashed #f5c842;padding:10px">${q}</div></div>`));
});
app.get("/redirect", (req,res) => res.redirect(req.query.url||"/"));
app.get("/link-preview", (req,res) => { const url=req.query.url||""; const label=req.query.label||"Visit"; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Link Preview",`<h2>Link Preview</h2><div class="box"><a href="${url}" style="font-size:18px;color:#f5c842">${label}</a></div>`)); });
app.get("/profile", (req,res) => {
  const u=req.query.username||"alice",b=req.query.bio||"Researcher",s=req.query.site||"",av=req.query.avatar||"";
  const avH=av?`<img src="${av}" style="width:80px;height:80px;border-radius:50%">`:`<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;font-size:32px;display:flex;align-items:center;justify-content:center">👤</div>`;
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(shell(`Profile — ${u}`,`<h2>Profile</h2><div class="box" style="display:flex;gap:20px">${avH}<div><p style="font-size:20px;font-weight:700">${u}</p><p style="color:#7a9bbf">${b}</p>${s?`<p>Site: <a href="${s}">${s}</a></p>`:""}</div></div>`));
});
app.get("/svg-inject", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("SVG",`<h2>SVG</h2><div class="box"><svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" style="background:#060d1a;display:block"><text x="10" y="25" fill="#38bdf8" font-size="13">SVG:</text>${q}</svg></div>`)); });
app.get("/math-inject", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("MathML",`<h2>MathML</h2><div class="box"><math xmlns="http://www.w3.org/1998/Math/MathML"><mrow><mi>x</mi><mo>=</mo><mn>42</mn>${q}</mrow></math></div>`)); });
app.get("/iframe-inject", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("iframe",`<h2>iframe</h2><div class="box"><iframe srcdoc="<html><body style='background:#0b0f1a;color:#e2e8f0;padding:10px'>${q}</body></html>" style="width:100%;height:90px;border:2px dashed #38bdf8" sandbox="allow-scripts allow-same-origin"></iframe></div>`)); });
app.get("/attr-double", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Attr Double",`<h2>Attr Double</h2><div class="box"><input value="${q}"><pre>value="${q}"</pre></div>`)); });
app.get("/attr-single", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Attr Single",`<h2>Attr Single</h2><div class="box"><input value='${q}'><pre>value='${q}'</pre></div>`)); });
app.get("/attr-unquoted", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Attr Unquoted",`<h2>Attr Unquoted</h2><div class="box"><input value=${q}><pre>value=${q}</pre></div>`)); });
app.get("/attr-data", (req,res) => { const q=req.query.q||""; res.setHeader("Content-Type","text/html; charset=utf-8"); res.send(shell("Data Attr",`<h2>Data Attr</h2><div class="box"><div id="w" data-query="${q}" style="padding:8px;border:1px solid #1e3a5f;border-radius:4px;min-height:32px"></div></div><script>(function(){const w=document.getElementById("w");w.innerHTML="Results: "+w.dataset.query;})()</script>`)); });

// ── M09 — JSON API source ─────────────────────────────────────────────────────

app.get("/api/search", (req, res) => {
  const q = req.query.q || "";
  // Query is echoed in JSON — safe as JSON but dangerous if client uses innerHTML
  res.json({
    query: q,
    results: [
      { title: "Result 1", url: "/page/1" },
      { title: "Result 2", url: "/page/2" },
    ],
    count: 2,
  });
});

// ── M09 — postMessage receiver ────────────────────────────────────────────────

app.get("/message", (req, res) => {
  const body = `
  <h2>postMessage Receiver</h2>
  <div class="box">
    <label>Messages received via postMessage:</label>
    <div id="msg-display" style="min-height:50px;padding:10px;
         border:2px dashed #38bdf8;border-radius:4px;font-size:13px">
      Waiting for messages…
    </div>
  </div>
  <div class="box">
    <label>Vulnerable event listener:</label>
    <pre>window.addEventListener('message', function(e) {
  // No origin check, no sanitisation
  document.getElementById('msg-display').innerHTML = e.data;
});</pre>
  </div>
  <script>
    window.addEventListener('message', function(e) {
      document.getElementById('msg-display').innerHTML = e.data;
    });
  <\/script>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(shell("postMessage Receiver", body));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 09`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  DOM XSS lab:  /dom_lab.html`);
  console.log(`  API source:   /api/search?q=<img src=x onerror=alert(1)>`);
  console.log(`  postMessage:  /message\n`);
});
