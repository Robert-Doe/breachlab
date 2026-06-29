"""
XSS Mastery Lab — Module 14
Cumulative: M01–M13 + prototype pollution → DOM XSS endpoints.

Prototype pollution allows an attacker to inject properties into Object.prototype,
the root of every JavaScript object's inheritance chain. When application code reads
a property from an object and that property does not exist on the object itself,
JavaScript walks the prototype chain — finding the attacker's injected value on
Object.prototype instead of undefined.

If that lookup feeds a DOM sink (innerHTML, eval, location.href…), prototype
pollution becomes DOM XSS without any direct user-input-to-sink path visible
in the code.

New routes:
  GET /pp/merge?__proto__[x]=y   — vulnerable deep-merge util reads query params
  GET /pp/config?settings=JSON   — config object reads query, merges into app config
  GET /pp/template               — Handlebars-style template reads prototype props
  GET /pp/gadget                 — jQuery-like gadget: $.html() reads innerHTML prop
"""

import json, re, datetime, base64
from flask import Flask, request, make_response, redirect, jsonify

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["DEBUG"] = True

# ── In-memory stores ──────────────────────────────────────────────────────────
oob_hits    = []
log_entries = []
comments    = []
profiles    = []

# ── Shared helpers ────────────────────────────────────────────────────────────
CSS = ("body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;"
       "padding:32px;max-width:780px}h2{color:#38bdf8;margin-bottom:10px}"
       ".box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}"
       "input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;"
       "border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;box-sizing:border-box}"
       "button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;"
       "border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}"
       "a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}"
       "pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;"
       "white-space:pre-wrap;color:#fb923c}"
       "code{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;"
       "color:#38bdf8;padding:2px 5px;border-radius:3px}")

def page(title, body):
    return (f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>'
            f'<style>{CSS}</style></head>'
            f'<body><a class="back" href="/">← Lab Home</a>{body}</body></html>')


# ── M01–M13 condensed cumulative routes ──────────────────────────────────────

@app.route("/");
def index(): return app.send_static_file("index.html")
@app.route("/ping")
def ping(): return {"status":"ok","module":14}
@app.route("/parse-demo")
def parse_demo():
    r=make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{request.args.get("html","")}</body></html>')
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/reflect")
def reflect():
    r=make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{request.args.get("q","")}</body></html>')
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/redirect")
def vuln_redirect(): return redirect(request.args.get("url","/"))
@app.route("/api/search")
def api_search(): return jsonify({"query":request.args.get("q",""),"results":[],"count":0})
@app.route("/board")
def board():
    items="".join(f'<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700">{c["author"]}</span><p style="margin-top:6px">{c["text"]}</p></div>' for c in comments) if comments else '<p style="color:#7a9bbf">No comments.</p>'
    r=make_response(page("Board",f'<h2>Board</h2><div class="box"><form method="POST" action="/board/post"><input name="author" placeholder="Name" required><textarea name="text" placeholder="Comment…" required></textarea><button type="submit">Post</button></form></div>{items}'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/board/post",methods=["POST"])
def board_post(): comments.append({"author":request.form.get("author","Anon"),"text":request.form.get("text","")}); return redirect("/board")
@app.route("/board/clear")
def board_clear(): comments.clear(); return redirect("/board")
@app.route("/admin")
def admin():
    rows="".join(f'<tr><td style="padding:8px;color:#f5c842">{p["username"]}</td><td style="padding:8px">{p["bio"]}</td><td style="padding:8px"><a href="{p["website"]}">{p["website"] or "—"}</a></td></tr>' for p in profiles)
    r=make_response(page("Admin",f'<h2 style="color:#f5c842">Admin</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th></tr></thead><tbody>{rows}</tbody></table></div>'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/admin/profile",methods=["GET","POST"])
def admin_profile():
    if request.method=="POST": profiles.append({"username":request.form.get("username",""),"bio":request.form.get("bio",""),"website":request.form.get("website","")}); return redirect("/admin")
    r=make_response(page("Register",'<h2>Register</h2><div class="box"><form method="POST"><input name="username" placeholder="Username" required><textarea name="bio" placeholder="Bio…"></textarea><input name="website" placeholder="Website"><button type="submit">Register</button></form></div>'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/admin/clear")
def admin_clear(): profiles.clear(); return redirect("/admin")
@app.route("/oob")
def oob_receive():
    oob_hits.append({"ts":datetime.datetime.now().isoformat(timespec="seconds"),"ip":request.remote_addr,"ua":request.headers.get("User-Agent",""),"origin":request.headers.get("Origin",""),"referer":request.headers.get("Referer",""),"params":dict(request.args)})
    gif=base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    r=make_response(gif); r.headers["Content-Type"]="image/gif"; r.headers["Cache-Control"]="no-store"; return r
@app.route("/oob/log")
def oob_log(): return jsonify({"count":len(oob_hits),"hits":oob_hits})
@app.route("/oob/clear")
def oob_clear(): oob_hits.clear(); return jsonify({"cleared":True})
@app.route("/log-viewer")
def log_viewer():
    rows="".join(f'<tr><td style="padding:6px 10px;font-size:11px;color:#7a9bbf">{e["ts"]}</td><td style="padding:6px 10px;font-size:11px">{e["level"]}</td><td style="padding:6px 10px;font-size:12px">{e["message"]}</td></tr>' for e in log_entries) if log_entries else '<tr><td colspan="3" style="padding:8px;color:#7a9bbf">No entries.</td></tr>'
    r=make_response(page("Log Viewer",f'<h2 style="color:#f5c842">Log Viewer</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th></tr></thead><tbody>{rows}</tbody></table></div>'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r
@app.route("/log-entry",methods=["POST"])
def log_entry():
    data=request.get_json(silent=True) or {}; log_entries.append({"ts":datetime.datetime.now().strftime("%H:%M:%S"),"level":data.get("level","INFO"),"message":data.get("message","")}); return jsonify({"stored":True,"count":len(log_entries)})
@app.route("/log-viewer/clear")
def log_viewer_clear(): log_entries.clear(); return redirect("/log-viewer")


# ── M14 — Prototype pollution endpoints ──────────────────────────────────────

@app.route("/pp/merge")
def pp_merge():
    """
    Demonstrates prototype pollution via a URL-based deep merge.
    The JavaScript running on this page implements a vulnerable deepMerge()
    that processes query parameters including __proto__ keys.
    The server just serves the page — all pollution happens client-side.
    """
    body = """
<h2>Prototype Pollution: Deep Merge</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    This page runs a vulnerable <code>deepMerge()</code> that reads URL query params
    into an object. Try: <code>?__proto__[innerHTML]=&lt;img src=x onerror=alert(1)&gt;</code>
  </p>
  <p style="font-size:12px;color:#7a9bbf">Current URL query params merged into object:</p>
  <pre id="merge-result">loading…</pre>
  <p style="font-size:12px;color:#7a9bbf;margin-top:10px">Object.prototype check:</p>
  <pre id="proto-check">loading…</pre>
  <p style="font-size:12px;color:#7a9bbf;margin-top:10px">Gadget output (reads obj.innerHTML → div.innerHTML):</p>
  <div id="gadget-output" style="font-size:14px;margin-top:8px;padding:10px;background:#060d1a;border-radius:4px;min-height:30px"></div>
</div>
<script>
// Vulnerable deep merge — processes __proto__ keys
function deepMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__') {
      // VULNERABLE: merges into prototype
      Object.assign(Object.prototype, source[key]);
    } else if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Parse query params into nested object (?a[b]=c → {a:{b:'c'}})
function parseQuery(search) {
  const obj = {};
  new URLSearchParams(search).forEach((val, key) => {
    const parts = key.split(/[\[\]]+/).filter(Boolean);
    let cur = obj;
    parts.forEach((p, i) => {
      if (i === parts.length - 1) cur[p] = val;
      else { cur[p] = cur[p] || {}; cur = cur[p]; }
    });
  });
  return obj;
}

const params = parseQuery(location.search);
const merged = deepMerge({}, params);
document.getElementById('merge-result').textContent = JSON.stringify(merged, null, 2);

// Check if Object.prototype was polluted
const check = {};
document.getElementById('proto-check').textContent =
  'new {}.innerHTML = ' + JSON.stringify(check.innerHTML) +
  '\\nnew {}.onerror = ' + JSON.stringify(check.onerror);

// Gadget: app code reads obj.innerHTML without owning it
const config = {};  // empty config — but prototype may be polluted
if (config.innerHTML !== undefined) {
  document.getElementById('gadget-output').innerHTML = config.innerHTML;
} else {
  document.getElementById('gadget-output').textContent = '(no pollution — config.innerHTML is undefined)';
}
</script>"""
    r = make_response(page("PP: Deep Merge", body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


@app.route("/pp/config")
def pp_config():
    """
    Config merge via JSON in query string.
    The settings= param is parsed as JSON and merged into the app config.
    Demonstrates pollution via JSON.parse() + merge.
    """
    settings_raw = request.args.get("settings", "{}")
    body = f"""
<h2>Prototype Pollution: JSON Config Merge</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    The <code>settings=</code> query param is JSON-parsed and merged into the app config.
    Try: <code>?settings={{"__proto__":{{"innerHTML":"&lt;img src=x onerror=alert(1)&gt;"}}}}</code>
  </p>
  <p style="font-size:12px;color:#7a9bbf">Raw settings param:</p>
  <pre>{settings_raw[:500]}</pre>
  <p style="font-size:12px;color:#7a9bbf;margin-top:8px">After config merge — gadget output:</p>
  <div id="gadget-out" style="font-size:14px;margin-top:8px;padding:10px;background:#060d1a;border-radius:4px;min-height:30px"></div>
</div>
<script>
const settingsRaw = {json.dumps(settings_raw)};

function deepMerge(target, source) {{
  if (typeof source !== 'object' || source === null) return target;
  for (const key in source) {{
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {{
      // VULNERABLE — merges restricted keys
      const desc = Object.getOwnPropertyDescriptor(source, key);
      if (desc) Object.defineProperty(Object.prototype, key, desc);
    }} else if (typeof source[key] === 'object' && source[key] !== null) {{
      target[key] = target[key] || {{}};
      deepMerge(target[key], source[key]);
    }} else {{
      target[key] = source[key];
    }}
  }}
  return target;
}}

let settings = {{}};
try {{ settings = JSON.parse(settingsRaw); }} catch(e) {{}}

const appConfig = {{ theme: 'dark', lang: 'en' }};
deepMerge(appConfig, settings);

// Gadget: reads innerHTML from config (may be on prototype)
const widget = {{}};
const out = document.getElementById('gadget-out');
if (widget.innerHTML !== undefined) {{
  out.innerHTML = widget.innerHTML;
}} else {{
  out.textContent = '(no pollution — widget.innerHTML = undefined)\\nappConfig = ' + JSON.stringify(appConfig);
}}
</script>"""
    r = make_response(page("PP: Config Merge", body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


@app.route("/pp/template")
def pp_template():
    """
    Template gadget: a simple template engine reads properties from a data object.
    If Object.prototype is polluted, the template reads attacker-controlled values
    for properties the template author assumed would be undefined or default.
    """
    body = """
<h2>Prototype Pollution: Template Gadget</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    A template engine renders a "user profile" by reading properties from a data object.
    The data object does not have an <code>extraHtml</code> property — but if
    Object.prototype is polluted via the deep merge, the template finds it there.
    Try: <code>?__proto__[extraHtml]=&lt;img src=x onerror=alert(1)&gt;</code>
  </p>
  <p style="font-size:12px;color:#7a9bbf">Template render output:</p>
  <div id="template-out" style="margin-top:8px"></div>
</div>
<script>
// Vulnerable deep merge (same as /pp/merge)
function deepMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__') { Object.assign(Object.prototype, source[key]); }
    else if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else { target[key] = source[key]; }
  }
}

// Parse query → pollute prototype
function parseQuery(s) {
  const obj = {};
  new URLSearchParams(s).forEach((v, k) => {
    const parts = k.split(/[\[\]]+/).filter(Boolean);
    let cur = obj;
    parts.forEach((p, i) => {
      if (i === parts.length-1) cur[p] = v;
      else { cur[p] = cur[p] || {}; cur = cur[p]; }
    });
  });
  return obj;
}
deepMerge({}, parseQuery(location.search));

// "Safe" template engine — renders a user profile card
function renderProfile(data) {
  const name    = data.name    || 'Anonymous';
  const bio     = data.bio     || 'No bio provided.';
  const extra   = data.extraHtml; // developer assumes this is always undefined
  const container = document.getElementById('template-out');
  container.innerHTML =
    '<div style="background:#1a2235;padding:16px;border-radius:6px">' +
    '<h3 style="color:#38bdf8;margin-bottom:6px">' + name + '</h3>' +
    '<p style="color:#7a9bbf;font-size:13px">' + bio + '</p>' +
    (extra ? '<div class="extra">' + extra + '</div>' : '') +
    '</div>';
}

// App calls renderProfile with a fixed data object — no extraHtml
renderProfile({ name: 'Alice', bio: 'Security researcher.' });
</script>"""
    r = make_response(page("PP: Template Gadget", body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


@app.route("/pp/gadget")
def pp_gadget():
    """
    jQuery-like gadget: a $ helper reads 'html' option from a config object.
    Demonstrates a realistic library gadget pattern.
    """
    body = """
<h2>Prototype Pollution: Library Gadget (jQuery-like)</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    A jQuery-like <code>$.html()</code> helper reads options from a settings object.
    If <code>options.html</code> is not own-property defined, it reads from prototype.
    Pollution: <code>?__proto__[html]=&lt;img src=x onerror=alert(1)&gt;</code>
  </p>
  <p style="font-size:12px;color:#7a9bbf">Library gadget output:</p>
  <div id="gadget-out" style="margin-top:8px;padding:10px;background:#060d1a;border-radius:4px;min-height:30px"></div>
  <p style="font-size:12px;color:#7a9bbf;margin-top:10px">Prototype pollution state:</p>
  <pre id="proto-state">checking…</pre>
</div>
<script>
// Vulnerable deep merge
function deepMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__') { Object.assign(Object.prototype, source[key]); }
    else if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else { target[key] = source[key]; }
  }
}

function parseQuery(s) {
  const obj = {};
  new URLSearchParams(s).forEach((v, k) => {
    const parts = k.split(/[\[\]]+/).filter(Boolean);
    let cur = obj;
    parts.forEach((p, i) => {
      if (i === parts.length-1) cur[p] = v;
      else { cur[p] = cur[p] || {}; cur = cur[p]; }
    });
  });
  return obj;
}
deepMerge({}, parseQuery(location.search));

// jQuery-like gadget — reads options.html
const $ = {
  html: function(selector, options) {
    options = options || {};
    const el = document.querySelector(selector);
    if (!el) return;
    // VULNERABLE: reads options.html — could be on prototype
    if (options.html !== undefined) {
      el.innerHTML = options.html;
    } else {
      el.textContent = '(html option not set)';
    }
  }
};

// App calls $.html with an empty options object
$.html('#gadget-out', {});

// Show prototype state
const probe = {};
document.getElementById('proto-state').textContent =
  '{}.html = ' + JSON.stringify(probe.html) +
  '\\n{}.innerHTML = ' + JSON.stringify(probe.innerHTML) +
  '\\n{}.src = ' + JSON.stringify(probe.src);
</script>"""
    r = make_response(page("PP: Library Gadget", body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 14 (Prototype Pollution → DOM XSS)")
    print("  http://localhost:5000")
    print("  /pp/merge    /pp/config    /pp/template    /pp/gadget\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
