"""
XSS Mastery Lab — Module 12
Cumulative: M01–M11 + filter evasion and obfuscation lab endpoints.

New routes:
  GET  /filter/blocklist?q=   — naive keyword blocklist (script, alert, onerror…)
  GET  /filter/stripping?q=   — strips <script> tags (once, not recursively)
  GET  /filter/case?q=        — case-insensitive block that can be evaded with mixed case
  GET  /filter/encoding?q=    — blocks raw < > but not HTML entity forms
  GET  /filter/length?q=      — allows only q <= 30 chars (bypass with short payloads)
  GET  /waf-sim?q=            — combined "WAF" applying several weak rules in sequence
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
       "textarea{height:80px;resize:vertical}"
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


# ── M01–M11 cumulative routes ─────────────────────────────────────────────────

@app.route("/")
def index(): return app.send_static_file("index.html")

@app.route("/ping")
def ping(): return {"status": "ok", "module": 12}

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "")
    r = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>')
    r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    r = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>')
    r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/redirect")
def vuln_redirect(): return redirect(request.args.get("url", "/"))

@app.route("/api/search")
def api_search():
    return jsonify({"query": request.args.get("q",""), "results":[], "count":0})

@app.route("/board")
def board():
    items = "".join(
        f'<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700;font-size:13px">{c["author"]}</span>'
        f'<p style="margin-top:6px;font-size:14px">{c["text"]}</p></div>'
        for c in comments
    ) if comments else '<p style="color:#7a9bbf">No comments.</p>'
    body = (f'<h2>Comment Board</h2><div class="box"><form method="POST" action="/board/post">'
            f'<input name="author" placeholder="Name" required>'
            f'<textarea name="text" placeholder="Comment…" required></textarea>'
            f'<button type="submit">Post</button></form></div>{items}')
    r = make_response(page("Board", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/board/post", methods=["POST"])
def board_post():
    comments.append({"author": request.form.get("author","Anon"), "text": request.form.get("text","")})
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
    r = make_response(page("Admin", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/admin/profile", methods=["GET","POST"])
def admin_profile():
    if request.method == "POST":
        profiles.append({"username": request.form.get("username",""),
                          "bio": request.form.get("bio",""),
                          "website": request.form.get("website","")})
        return redirect("/admin")
    body = ('<h2>Register Profile</h2><div class="box"><form method="POST">'
            '<input name="username" placeholder="Username" required>'
            '<textarea name="bio" placeholder="Bio…"></textarea>'
            '<input name="website" placeholder="Website">'
            '<button type="submit">Register</button></form></div>')
    r = make_response(page("Register", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/admin/clear")
def admin_clear(): profiles.clear(); return redirect("/admin")

@app.route("/oob")
def oob_receive():
    oob_hits.append({"ts": datetime.datetime.now().isoformat(timespec="seconds"),
                     "ip": request.remote_addr, "ua": request.headers.get("User-Agent",""),
                     "origin": request.headers.get("Origin",""), "referer": request.headers.get("Referer",""),
                     "params": dict(request.args)})
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    r = make_response(gif); r.headers["Content-Type"] = "image/gif"; r.headers["Cache-Control"] = "no-store"; return r

@app.route("/oob/log")
def oob_log(): return jsonify({"count": len(oob_hits), "hits": oob_hits})

@app.route("/oob/clear")
def oob_clear(): oob_hits.clear(); return jsonify({"cleared": True})

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
            f'</tr></thead><tbody>{rows}</tbody></table></div>'
            f'<p style="font-size:12px;color:#7a9bbf;margin-top:12px">'
            f'<a href="/log-viewer/clear" style="color:#f87171">Clear logs</a></p>')
    r = make_response(page("Log Viewer", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/log-entry", methods=["POST"])
def log_entry():
    data = request.get_json(silent=True) or {}
    log_entries.append({"ts": datetime.datetime.now().strftime("%H:%M:%S"),
                         "level": data.get("level","INFO"), "message": data.get("message","")})
    return jsonify({"stored": True, "count": len(log_entries)})

@app.route("/log-viewer/clear")
def log_viewer_clear(): log_entries.clear(); return redirect("/log-viewer")

@app.route("/pdf-preview")
def pdf_preview():
    content = request.args.get("content", "Your report content here.")
    body = (f'<h2>PDF Preview</h2><div class="box">'
            f'<div style="background:#fff;color:#111;padding:40px;font-family:Georgia,serif;font-size:14px;line-height:1.8">'
            f'<h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:16px">Security Report</h1>'
            f'<div id="report-content">{content}</div>'
            f'<p style="font-size:11px;color:#666;margin-top:40px">Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}</p>'
            f'</div></div>')
    r = make_response(page("PDF Preview", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r

@app.route("/email-preview")
def email_preview():
    to = request.args.get("to","user@example.com")
    subject = request.args.get("subject","Notification")
    body_text = request.args.get("body","Thank you for signing up!")
    body = (f'<h2>Email Preview</h2><div class="box" style="padding:0;overflow:hidden">'
            f'<div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;border-bottom:1px solid #1e3a5f">'
            f'To: <strong style="color:#e2e8f0">{to}</strong> · Subject: <strong style="color:#e2e8f0">{subject}</strong></div>'
            f'<div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;font-size:14px;line-height:1.7">'
            f'{body_text}</div></div>')
    r = make_response(page("Email Preview", body)); r.headers["Content-Type"] = "text/html; charset=utf-8"; return r


# ── M12 — Filter evasion endpoints ───────────────────────────────────────────

def _render(title, label, q, filtered, result_html):
    """Shared render helper: shows filter applied, input, and rendered output side by side."""
    badge_color = "#f5c842" if filtered != q else "#4ade80"
    badge_text = "BLOCKED/MODIFIED" if filtered != q else "PASSED"
    body = f"""
<h2>{title}</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">{label}</p>
  <form method="GET">
    <input name="q" value="{q.replace('"','&quot;')}" placeholder="Payload">
    <button type="submit">Submit</button>
  </form>
  <p style="font-size:12px;margin-top:10px;color:#7a9bbf">
    Filter result: <span style="color:{badge_color};font-weight:700">{badge_text}</span>
  </p>
  <p style="font-size:12px;color:#7a9bbf">After filter: <code style="color:#fb923c">{filtered[:300]}</code></p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rendered output ↓</p>
  {result_html}
</div>"""
    r = make_response(page(title, body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


@app.route("/filter/blocklist")
def filter_blocklist():
    """
    Blocks specific keywords: script, alert, onerror, onload, javascript.
    Bypass: use synonyms, event handlers not on the list, or encoding.
    """
    q = request.args.get("q", "")
    # Case-sensitive keyword blocklist (deliberately incomplete)
    blocked = ["script", "alert", "onerror", "onload", "javascript"]
    filtered = q
    for kw in blocked:
        filtered = filtered.replace(kw, "***")
    result = f'<div style="font-size:14px">{filtered}</div>'
    return _render(
        "Filter: Keyword Blocklist",
        "Blocks: script, alert, onerror, onload, javascript (case-sensitive). "
        "Try: onfocus, onerror with mixed case, svg onload, img src, confirm(), prompt().",
        q, filtered, result)


@app.route("/filter/stripping")
def filter_stripping():
    """
    Strips <script>...</script> tags (non-recursive, non-greedy).
    Bypass: nested tags <scr<script>ipt>, other vectors entirely.
    """
    q = request.args.get("q", "")
    # Strip script tags — single pass, non-recursive
    filtered = re.sub(r'<script.*?>.*?</script>', '', q, flags=re.IGNORECASE | re.DOTALL)
    result = f'<div style="font-size:14px">{filtered}</div>'
    return _render(
        "Filter: Script Tag Stripping",
        "Strips &lt;script&gt;…&lt;/script&gt; (one pass, case-insensitive). "
        "Try: nested tags &lt;scr&lt;script&gt;ipt&gt;alert(1)&lt;/scr&lt;/script&gt;ipt&gt; or img/svg vectors.",
        q, filtered, result)


@app.route("/filter/case")
def filter_case():
    """
    Case-insensitive block of 'script' and 'alert' as whole strings.
    Bypass: split with comments <!-->, HTML entity insertion, or event handlers.
    """
    q = request.args.get("q", "")
    filtered = re.sub(r'script', '***', q, flags=re.IGNORECASE)
    filtered = re.sub(r'alert', '***', filtered, flags=re.IGNORECASE)
    result = f'<div style="font-size:14px">{filtered}</div>'
    return _render(
        "Filter: Case-Insensitive Block",
        "Blocks 'script' and 'alert' regardless of case. "
        "Try: confirm(1), prompt(1), event handlers like onfocus, or split payloads.",
        q, filtered, result)


@app.route("/filter/encoding")
def filter_encoding():
    """
    Blocks raw < and > characters but not HTML entity forms.
    Bypass: HTML entity encoding, decimal/hex character references.
    Note: HTML parser decodes entities BEFORE attribute context — entities work in attributes,
    but here we render the output directly so the browser itself decodes them.
    """
    q = request.args.get("q", "")
    # Block literal < and > but not entity forms
    if "<" in q or ">" in q:
        filtered = "[BLOCKED: raw angle brackets detected]"
    else:
        filtered = q
    result = f'<div style="font-size:14px">{filtered}</div>'
    return _render(
        "Filter: Raw Angle Bracket Block",
        "Blocks input containing literal &lt; or &gt;. Does NOT block HTML entity forms. "
        "Try: &amp;lt;img src=x onerror=alert(1)&amp;gt; — the browser decodes entities after the filter runs.",
        q, filtered, result)


@app.route("/filter/length")
def filter_length():
    """
    Enforces a maximum input length of 30 characters.
    Bypass: short payloads — <svg onload=alert(1)> is 24 chars.
    """
    q = request.args.get("q", "")
    MAX = 30
    if len(q) > MAX:
        filtered = f"[BLOCKED: input exceeds {MAX} chars (got {len(q)})]"
    else:
        filtered = q
    result = f'<div style="font-size:14px">{filtered}</div>'
    return _render(
        f"Filter: Length Limit ({MAX} chars)",
        f"Rejects input longer than {MAX} characters. "
        f"Try: &lt;svg onload=alert(1)&gt; (22 chars), &lt;img src=x onerror=alert(1)&gt; (32 chars — too long).",
        q, filtered, result)


@app.route("/waf-sim")
def waf_sim():
    """
    Simulated WAF applying multiple weak rules in sequence.
    Rule order matters — earlier rules can be bypassed after later rules run.
    Rules: strip <script>, block 'alert', lowercase input, block 'javascript:'.
    The weakness: rules are applied to the already-modified string, not the original.
    """
    q = request.args.get("q", "")

    steps = []
    current = q

    # Rule 1: strip <script> tags
    r1 = re.sub(r'<script.*?>.*?</script>', '', current, flags=re.IGNORECASE | re.DOTALL)
    steps.append(("R1: strip &lt;script&gt;", current, r1))
    current = r1

    # Rule 2: block 'alert' keyword
    r2 = current.replace("alert", "***")
    steps.append(("R2: block 'alert'", current, r2))
    current = r2

    # Rule 3: block 'javascript:' URI scheme (case-insensitive)
    r3 = re.sub(r'javascript\s*:', '[JS-BLOCKED]:', current, flags=re.IGNORECASE)
    steps.append(("R3: block javascript:", current, r3))
    current = r3

    # Build step table
    rows = "".join(
        f'<tr><td style="padding:5px 8px;font-size:11px;color:#38bdf8">{s[0]}</td>'
        f'<td style="padding:5px 8px;font-size:11px;color:#7a9bbf;word-break:break-all">{s[1][:80]}</td>'
        f'<td style="padding:5px 8px;font-size:11px;color:#fb923c;word-break:break-all">{s[2][:80]}</td></tr>'
        for s in steps)
    table = (f'<table style="width:100%;border-collapse:collapse;margin-bottom:12px"><thead><tr>'
             f'<th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Rule</th>'
             f'<th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Input</th>'
             f'<th style="text-align:left;padding:5px 8px;font-size:11px;background:#060d1a;color:#38bdf8">Output</th>'
             f'</tr></thead><tbody>{rows}</tbody></table>')

    body = f"""
<h2>WAF Simulator</h2>
<div class="box">
  <p style="font-size:13px;color:#7a9bbf;margin-bottom:12px">
    Three rules applied in order: strip &lt;script&gt; · block 'alert' · block 'javascript:'.
    Each rule sees the output of the previous rule. Rule interactions create bypass opportunities.
  </p>
  <form method="GET"><input name="q" value="{q.replace('"','&quot;')}" placeholder="Payload"><button type="submit">Submit</button></form>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rule application trace:</p>
  {table}
  <p style="font-size:12px;color:#7a9bbf">Final output: <code style="color:#fb923c">{current[:300]}</code></p>
</div>
<div class="box">
  <p style="font-size:12px;color:#7a9bbf;margin-bottom:8px">Rendered ↓</p>
  <div style="font-size:14px">{current}</div>
</div>"""

    r = make_response(page("WAF Simulator", body))
    r.headers["Content-Type"] = "text/html; charset=utf-8"
    return r


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 12")
    print("  http://localhost:5000")
    print("  /filter/blocklist  /filter/stripping  /filter/case")
    print("  /filter/encoding   /filter/length     /waf-sim\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
