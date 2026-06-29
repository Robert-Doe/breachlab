"""
XSS Mastery Lab — Module 13
Cumulative: M01–M12 + mutation XSS (mXSS) lab endpoints.

mXSS occurs when a sanitiser produces "clean" HTML that the browser's HTML parser
then mutates into a form that contains executable content. The browser's parsing
rules (namespace switching, optional-tag inference, foreign-content rules) transform
the sanitised string into a different DOM tree that re-introduces XSS.

New routes:
  GET /mxss/innerHTML?q=    — sanitise server-side with regex, insert via innerHTML
  GET /mxss/table?q=        — table context: content injected inside <table> is moved
  GET /mxss/namespace?q=    — SVG/HTML namespace switch triggers re-parsing
  GET /mxss/noscript?q=     — <noscript> parsing differs when JS is on vs off
  GET /mxss/template?q=     — <template> element inert vs active context
"""

import re, json, datetime, base64
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

def naive_sanitise(html):
    """Weak server-side 'sanitiser': strips script tags and javascript: URIs."""
    out = re.sub(r'<script[\s\S]*?>[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
    out = re.sub(r'javascript\s*:', '[blocked]:', out, flags=re.IGNORECASE)
    return out


# ── M01–M12 cumulative routes ─────────────────────────────────────────────────

@app.route("/")
def index(): return app.send_static_file("index.html")

@app.route("/ping")
def ping(): return {"status": "ok", "module": 13}

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html","")
    r = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>')
    r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/reflect")
def reflect():
    q = request.args.get("q","")
    r = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>')
    r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/redirect")
def vuln_redirect(): return redirect(request.args.get("url","/"))

@app.route("/api/search")
def api_search(): return jsonify({"query":request.args.get("q",""),"results":[],"count":0})

@app.route("/board")
def board():
    items = "".join(
        f'<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700;font-size:13px">{c["author"]}</span>'
        f'<p style="margin-top:6px;font-size:14px">{c["text"]}</p></div>'
        for c in comments
    ) if comments else '<p style="color:#7a9bbf">No comments.</p>'
    body = (f'<h2>Board</h2><div class="box"><form method="POST" action="/board/post">'
            f'<input name="author" placeholder="Name" required>'
            f'<textarea name="text" placeholder="Comment…" required></textarea>'
            f'<button type="submit">Post</button></form></div>{items}')
    r = make_response(page("Board",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/board/post", methods=["POST"])
def board_post():
    comments.append({"author":request.form.get("author","Anon"),"text":request.form.get("text","")})
    return redirect("/board")

@app.route("/board/clear")
def board_clear(): comments.clear(); return redirect("/board")

@app.route("/admin")
def admin():
    rows = "".join(
        f'<tr><td style="padding:8px;color:#f5c842">{p["username"]}</td>'
        f'<td style="padding:8px">{p["bio"]}</td>'
        f'<td style="padding:8px"><a href="{p["website"]}">{p["website"] or "—"}</a></td></tr>'
        for p in profiles)
    body = (f'<h2 style="color:#f5c842">Admin Panel</h2><div class="box">'
            f'<table style="width:100%;border-collapse:collapse"><thead><tr>'
            f'<th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th>'
            f'<th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th>'
            f'<th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>')
    r = make_response(page("Admin",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/admin/profile", methods=["GET","POST"])
def admin_profile():
    if request.method=="POST":
        profiles.append({"username":request.form.get("username",""),"bio":request.form.get("bio",""),"website":request.form.get("website","")})
        return redirect("/admin")
    body = ('<h2>Register</h2><div class="box"><form method="POST">'
            '<input name="username" placeholder="Username" required>'
            '<textarea name="bio" placeholder="Bio…"></textarea>'
            '<input name="website" placeholder="Website">'
            '<button type="submit">Register</button></form></div>')
    r = make_response(page("Register",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/admin/clear")
def admin_clear(): profiles.clear(); return redirect("/admin")

@app.route("/oob")
def oob_receive():
    oob_hits.append({"ts":datetime.datetime.now().isoformat(timespec="seconds"),
                     "ip":request.remote_addr,"ua":request.headers.get("User-Agent",""),
                     "origin":request.headers.get("Origin",""),"referer":request.headers.get("Referer",""),
                     "params":dict(request.args)})
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    r = make_response(gif); r.headers["Content-Type"]="image/gif"; r.headers["Cache-Control"]="no-store"; return r

@app.route("/oob/log")
def oob_log(): return jsonify({"count":len(oob_hits),"hits":oob_hits})

@app.route("/oob/clear")
def oob_clear(): oob_hits.clear(); return jsonify({"cleared":True})

@app.route("/log-viewer")
def log_viewer():
    rows = "".join(
        f'<tr><td style="padding:6px 10px;font-size:11px;color:#7a9bbf">{e["ts"]}</td>'
        f'<td style="padding:6px 10px;font-size:11px">{e["level"]}</td>'
        f'<td style="padding:6px 10px;font-size:12px">{e["message"]}</td></tr>'
        for e in log_entries
    ) if log_entries else '<tr><td colspan="3" style="padding:8px;color:#7a9bbf">No entries.</td></tr>'
    body = (f'<h2 style="color:#f5c842">Log Viewer</h2><div class="box">'
            f'<table style="width:100%;border-collapse:collapse"><thead><tr>'
            f'<th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th>'
            f'<th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th>'
            f'<th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>')
    r = make_response(page("Log Viewer",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/log-entry", methods=["POST"])
def log_entry():
    data = request.get_json(silent=True) or {}
    log_entries.append({"ts":datetime.datetime.now().strftime("%H:%M:%S"),"level":data.get("level","INFO"),"message":data.get("message","")})
    return jsonify({"stored":True,"count":len(log_entries)})

@app.route("/log-viewer/clear")
def log_viewer_clear(): log_entries.clear(); return redirect("/log-viewer")

@app.route("/pdf-preview")
def pdf_preview():
    content = request.args.get("content","Report content.")
    body = (f'<h2>PDF Preview</h2><div class="box">'
            f'<div style="background:#fff;color:#111;padding:40px;font-family:Georgia,serif;font-size:14px;line-height:1.8">'
            f'<h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:16px">Security Report</h1>'
            f'<div>{content}</div></div></div>')
    r = make_response(page("PDF Preview",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/email-preview")
def email_preview():
    to=request.args.get("to","user@example.com"); subject=request.args.get("subject","Notification"); body_text=request.args.get("body","Thank you!")
    body=(f'<h2>Email Preview</h2><div class="box" style="padding:0;overflow:hidden">'
          f'<div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;border-bottom:1px solid #1e3a5f">'
          f'To: <strong style="color:#e2e8f0">{to}</strong> · Subject: <strong style="color:#e2e8f0">{subject}</strong></div>'
          f'<div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;font-size:14px;line-height:1.7">{body_text}</div></div>')
    r = make_response(page("Email Preview",body)); r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/filter/blocklist")
def filter_blocklist():
    q=request.args.get("q",""); filtered=q
    for kw in ["script","alert","onerror","onload","javascript"]: filtered=filtered.replace(kw,"***")
    r=make_response(page("Blocklist Filter",f'<h2>Blocklist Filter</h2><div class="box"><form method="GET"><input name="q" value="{q.replace(chr(34),"&quot;")}"><button type="submit">Submit</button></form><p style="font-size:12px;margin-top:10px;color:#7a9bbf">After filter: <code style="color:#fb923c">{filtered[:300]}</code></p></div><div class="box">{filtered}</div>'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r

@app.route("/waf-sim")
def waf_sim():
    q=request.args.get("q",""); current=q
    current=re.sub(r'<script[\s\S]*?>[\s\S]*?</script>','',current,flags=re.IGNORECASE|re.DOTALL)
    current=current.replace("alert","***")
    current=re.sub(r'javascript\s*:','[JS-BLOCKED]:',current,flags=re.IGNORECASE)
    r=make_response(page("WAF Sim",f'<h2>WAF Simulator</h2><div class="box"><form method="GET"><input name="q" value="{q.replace(chr(34),"&quot;")}"><button type="submit">Submit</button></form><p style="font-size:12px;margin-top:10px;color:#7a9bbf">Final: <code style="color:#fb923c">{current[:300]}</code></p></div><div class="box"><div style="font-size:14px">{current}</div></div>'))
    r.headers["Content-Type"]="text/html; charset=utf-8"; return r


# ── M13 — mXSS endpoints ──────────────────────────────────────────────────────

def _mxss_page(title, desc, q, sanitised, note):
    """
    The server sanitises the input and sends the sanitised string to the client.
    The CLIENT then inserts it via innerHTML — this is the mXSS pattern.
    The browser's parser may mutate the sanitised string when it re-parses it
    in a different context (table, namespace, noscript, template).
    """
    body = f"""
<h2>{title}</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">{desc}</p>
  <form method="GET">
    <input name="q" value="{q.replace('"', '&quot;')}" placeholder="Payload">
    <button type="submit">Submit</button>
  </form>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf">Server-sanitised output (what the sanitiser returns):</p>
  <pre id="sanitised-display"></pre>
  <p style="font-size:12px;color:#7a9bbf;margin-top:10px">{note}</p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Client renders the sanitised string via innerHTML ↓</p>
  <div id="mxss-target" style="font-size:14px"></div>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Actual DOM after innerHTML insertion (innerHTML of target):</p>
  <pre id="dom-dump" style="color:#4ade80"></pre>
</div>
<script>
  const sanitised = {json.dumps(sanitised)};
  document.getElementById('sanitised-display').textContent = sanitised;
  const target = document.getElementById('mxss-target');
  target.innerHTML = sanitised;
  document.getElementById('dom-dump').textContent = target.innerHTML;
</script>"""
    r = make_response(page(title, body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


@app.route("/mxss/innerHTML")
def mxss_inner_html():
    q = request.args.get("q", "")
    sanitised = naive_sanitise(q)
    return _mxss_page(
        "mXSS: Basic innerHTML Insertion",
        "The server strips &lt;script&gt; tags and javascript: URIs. "
        "The sanitised string is inserted via innerHTML on the client. "
        "Observe how the browser DOM differs from the sanitised string.",
        q, sanitised,
        "mXSS opportunity: the sanitiser's output may be mutated by innerHTML parsing "
        "rules that the sanitiser does not model.")


@app.route("/mxss/table")
def mxss_table():
    """
    Table context mXSS: content injected inside a <table> element is moved
    by the HTML parser to before the table (foster parenting). This means
    a sanitiser that serialises <table>XSS payload</table> produces safe-looking
    HTML, but when the browser re-parses it via innerHTML, the XSS payload
    escapes the table and lands in the document body where it executes.
    """
    q = request.args.get("q", "")
    # The server wraps the input in a table — looks safe
    sanitised = naive_sanitise(q)
    # Wrap in table the way a vulnerable template might
    table_wrapped = f"<table>{sanitised}</table>"
    return _mxss_page(
        "mXSS: Table Foster Parenting",
        "The server wraps user content in &lt;table&gt;…&lt;/table&gt;. "
        "The HTML5 parser moves non-table content OUT of the table (foster parenting). "
        "Content that appears inside the table tag ends up in the document body — "
        "outside the intended containment.",
        q, table_wrapped,
        "Try: inject &lt;img src=x onerror=alert(1)&gt; — the server wraps it in &lt;table&gt;, "
        "which looks contained, but the browser moves it to the body where onerror fires.")


@app.route("/mxss/namespace")
def mxss_namespace():
    """
    Namespace switch mXSS: in SVG context, content is parsed in the SVG namespace.
    When that content is serialised back to a string and re-inserted into the HTML
    namespace via innerHTML, the parser re-interprets it differently.
    Classic example: <svg><style><a id="</style><img src=x onerror=alert(1)>">
    The <style> in SVG context treats everything as text. The serialiser produces
    a string. When re-inserted to HTML, <style> ends at the first </style>, and
    the trailing content is interpreted as HTML — including the img tag.
    """
    q = request.args.get("q", "")
    sanitised = naive_sanitise(q)
    return _mxss_page(
        "mXSS: SVG Namespace Boundary",
        "SVG and HTML parsers have different rules for what is text vs markup. "
        "A payload that is inert in SVG context may become active when serialised "
        "and re-inserted in HTML context. "
        "The sanitiser sees the SVG-namespace interpretation; innerHTML sees HTML.",
        q, sanitised,
        "Classic payload: <code>&lt;svg&gt;&lt;style&gt;&lt;a id=\"&lt;/style&gt;"
        "&lt;img src=x onerror=alert(1)&gt;\"&gt;</code> — "
        "in SVG, style content is raw text; serialised and re-parsed in HTML, "
        "the style ends at &lt;/style&gt; and the img is HTML markup.")


@app.route("/mxss/noscript")
def mxss_noscript():
    """
    <noscript> mXSS: when scripting is DISABLED, <noscript> content is parsed
    as HTML. When scripting is ENABLED, <noscript> content is raw text (opaque).
    A sanitiser running with scripting disabled sees the noscript content as HTML
    and sanitises it correctly. But when served to a browser with scripting enabled,
    the noscript content is treated as raw text — and a payload inside it is not
    sanitised because the sanitiser already processed it differently.
    The reverse also causes issues: a sanitiser that treats noscript as opaque
    will not sanitise its content, which then executes in browsers where scripting
    is disabled.
    """
    q = request.args.get("q", "")
    sanitised = naive_sanitise(q)
    noscript_wrapped = f"<noscript>{sanitised}</noscript>"
    return _mxss_page(
        "mXSS: &lt;noscript&gt; Scripting Context",
        "&lt;noscript&gt; content is parsed differently depending on whether "
        "scripting is enabled. A sanitiser and the target browser may disagree "
        "on whether the content is HTML or raw text.",
        q, noscript_wrapped,
        "Observe: with scripting ON, &lt;noscript&gt; content is raw text — "
        "tags inside are not parsed as HTML. With scripting OFF, they are. "
        "A sanitiser that runs with one setting may leave content unsafe for the other.")


@app.route("/mxss/template")
def mxss_template():
    """
    <template> element mXSS: the <template> element's content is parsed into
    a separate document fragment (inert context) — scripts and event handlers
    in a template are NOT executed when the template is defined. However, if
    that template content is later cloned and inserted into the main document
    (document.importNode or template.content.cloneNode), it becomes active.
    A sanitiser that sees the template content as inert may not sanitise it.
    When the template is activated, the payload executes.
    """
    q = request.args.get("q", "")
    sanitised = naive_sanitise(q)
    template_wrapped = f"<template>{sanitised}</template>"
    return _mxss_page(
        "mXSS: &lt;template&gt; Inert vs Active Context",
        "&lt;template&gt; content is parsed into an inert document fragment — "
        "event handlers do not fire during parsing. If template content is later "
        "activated (cloneNode + appendChild), payloads become live.",
        q, template_wrapped,
        "The DOM dump shows what innerHTML contains after the &lt;template&gt; is parsed. "
        "Click the button below to clone and activate the template content.")


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 13 (mXSS)")
    print("  http://localhost:5000")
    print("  /mxss/innerHTML  /mxss/table  /mxss/namespace")
    print("  /mxss/noscript   /mxss/template\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
