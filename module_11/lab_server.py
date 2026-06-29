"""
XSS Mastery Lab — Module 11
Cumulative: M01–M10 + out-of-band callback collector and blind rendering surfaces.

New routes:
  GET  /oob                  — out-of-band callback receiver (logs all hits)
  GET  /oob/log              — view collected OOB callbacks (JSON)
  GET  /oob/clear            — clear OOB log
  GET  /log-viewer           — admin log viewer (renders log entries raw — blind XSS sink)
  POST /log-entry            — accepts a log entry (stores raw — blind storage point)
  GET  /pdf-preview?content= — simulates a PDF generator (renders content into a "report")
  GET  /email-preview?body=  — simulates an email template renderer
"""

import re, json, datetime
from flask import Flask, request, make_response, redirect, jsonify

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["DEBUG"] = True

# ── In-memory stores ──────────────────────────────────────────────────────────

oob_hits   = []   # out-of-band callbacks: {ts, ip, ua, params}
log_entries = []  # application log entries: {ts, level, message}
comments   = []
profiles   = []


# ── Shared helpers ────────────────────────────────────────────────────────────

CSS = """body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
padding:32px;max-width:780px}h2{color:#38bdf8;margin-bottom:10px}
.box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:6px}
input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;box-sizing:border-box}
textarea{height:80px;resize:vertical;font-family:inherit}
button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;
border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
a{color:#38bdf8;text-decoration:none}.back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
pre{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;overflow-x:auto;
white-space:pre-wrap;color:#fb923c}code{font-family:'Courier New',monospace;font-size:12px;
background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}"""

def page(title, body):
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<style>{CSS}</style></head>
<body><a class="back" href="/">← Lab Home</a>{body}</body></html>"""


# ── M01 ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 11}

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "")
    resp = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>')
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    resp = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>')
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/redirect")
def vuln_redirect():
    return redirect(request.args.get("url", "/"))

@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": [], "count": 0})

@app.route("/board")
def board():
    items = "\n".join(
        f'<div class="box" style="padding:12px 16px"><span style="color:#f5c842;font-weight:700;font-size:13px">{c["author"]}</span><p style="margin-top:6px;font-size:14px">{c["text"]}</p></div>'
        for c in comments
    ) if comments else '<p style="color:#7a9bbf;font-size:13px">No comments.</p>'
    body = f'<h2>Comment Board</h2><div class="box"><form method="POST" action="/board/post"><input name="author" placeholder="Name" required><textarea name="text" placeholder="Comment…" required></textarea><button type="submit">Post</button></form></div><h2 style="margin-top:24px">Comments</h2>{items}'
    resp = make_response(page("Board", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/board/post", methods=["POST"])
def board_post():
    comments.append({"author": request.form.get("author","Anon"), "text": request.form.get("text","")})
    return redirect("/board")

@app.route("/board/clear")
def board_clear():
    comments.clear(); return redirect("/board")

@app.route("/admin")
def admin():
    rows = "".join(
        f'<tr><td style="padding:8px;font-size:13px;color:#f5c842">{p["username"]}</td>'
        f'<td style="padding:8px;font-size:13px">{p["bio"]}</td>'
        f'<td style="padding:8px;font-size:13px"><a href="{p["website"]}">{p["website"] or "—"}</a></td></tr>'
        for p in profiles
    )
    body = f'<h2 style="color:#f5c842">Admin Panel</h2><div class="box"><table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">User</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Bio</th><th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8">Site</th></tr></thead><tbody>{rows}</tbody></table></div>'
    resp = make_response(page("Admin", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/admin/profile", methods=["GET","POST"])
def admin_profile():
    if request.method == "POST":
        profiles.append({"username": request.form.get("username",""), "bio": request.form.get("bio",""), "website": request.form.get("website","")})
        return redirect("/admin")
    body = '<h2>Register Profile</h2><div class="box"><form method="POST"><input name="username" placeholder="Username" required><textarea name="bio" placeholder="Bio…"></textarea><input name="website" placeholder="Website"><button type="submit">Register</button></form></div>'
    resp = make_response(page("Register", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/admin/clear")
def admin_clear():
    profiles.clear(); return redirect("/admin")


# ── M11 — Out-of-band callback receiver ───────────────────────────────────────

@app.route("/oob")
def oob_receive():
    """
    Simulates an attacker-controlled callback server.
    Any request to /oob is logged with full context — this is what a real
    XSS Hunter / Burp Collaborator callback server captures.

    In a real attack, this would be hosted at a domain the attacker controls.
    In the lab, localhost:5000/oob stands in for that server.
    """
    hit = {
        "ts":     datetime.datetime.now().isoformat(timespec="seconds"),
        "ip":     request.remote_addr,
        "ua":     request.headers.get("User-Agent", ""),
        "origin": request.headers.get("Origin", ""),
        "referer":request.headers.get("Referer", ""),
        "params": dict(request.args),
    }
    oob_hits.append(hit)

    # Return a 1x1 transparent GIF — common technique for img-based OOB beacons
    import base64
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    resp = make_response(gif)
    resp.headers["Content-Type"] = "image/gif"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/oob/log")
def oob_log():
    """Returns all captured OOB callbacks as JSON."""
    return jsonify({"count": len(oob_hits), "hits": oob_hits})


@app.route("/oob/clear")
def oob_clear():
    oob_hits.clear()
    return jsonify({"cleared": True})


# ── M11 — Application log viewer (blind XSS surface) ─────────────────────────

@app.route("/log-viewer")
def log_viewer():
    """
    Admin log viewer — renders stored log entries without sanitisation.
    This models logging systems (ELK, Splunk, custom dashboards) that render
    raw log data in a browser. If user-supplied data reaches the logs,
    and the log viewer renders HTML, blind XSS is possible.
    """
    if log_entries:
        rows = "".join(
            f'<tr style="border-bottom:1px solid #1e3a5f">'
            f'<td style="padding:6px 10px;font-size:11px;color:#7a9bbf;white-space:nowrap">{e["ts"]}</td>'
            f'<td style="padding:6px 10px;font-size:11px;color:{{"INFO":"#38bdf8","WARN":"#f5c842","ERROR":"#f87171"}.get(e["level"],"#e2e8f0")}">{e["level"]}</td>'
            f'<td style="padding:6px 10px;font-size:12px">{e["message"]}</td>'
            f'</tr>'
            for e in log_entries
        )
        table = f'<table style="width:100%;border-collapse:collapse"><thead><tr><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Time</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Level</th><th style="text-align:left;padding:6px 10px;font-size:11px;background:#060d1a;color:#38bdf8">Message</th></tr></thead><tbody>{rows}</tbody></table>'
    else:
        table = '<p style="color:#7a9bbf;font-size:13px">No log entries.</p>'

    body = f"""
<h2 style="color:#f5c842">Application Log Viewer</h2>
<p style="color:#7a9bbf;font-size:13px;margin-bottom:16px">
  Internal log dashboard — entries rendered without sanitisation.
</p>
<div class="box">{table}</div>
<p style="font-size:12px;color:#7a9bbf;margin-top:12px">
  Utility: <a href="/oob/log" style="color:#38bdf8">View OOB callbacks</a>
  &nbsp;·&nbsp; <a href="/log-viewer/clear" style="color:#f87171">Clear logs</a>
</p>"""

    resp = make_response(page("Log Viewer", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/log-entry", methods=["POST"])
def log_entry():
    """
    Accepts a log entry — simulates an application that logs user-supplied
    data (search terms, error messages, usernames) into a log store that
    is later viewed by admins in the log viewer.
    """
    data = request.get_json(silent=True) or {}
    level   = data.get("level", "INFO")
    message = data.get("message", "")
    log_entries.append({
        "ts":      datetime.datetime.now().strftime("%H:%M:%S"),
        "level":   level,
        "message": message,
    })
    return jsonify({"stored": True, "count": len(log_entries)})


@app.route("/log-viewer/clear")
def log_viewer_clear():
    log_entries.clear()
    return redirect("/log-viewer")


# ── M11 — PDF preview (delayed/server-side rendering surface) ─────────────────

@app.route("/pdf-preview")
def pdf_preview():
    """
    Simulates a server-side PDF generator that renders user content into a
    'report'. In real applications (wkhtmltopdf, Puppeteer, headless Chrome)
    HTML injected here executes in the rendering engine — potentially enabling
    SSRF, local file read, or XSS in the preview.

    This endpoint renders the content= parameter into an HTML "report"
    that the PDF engine would process. The XSS payload executes in the
    preview browser context.
    """
    content = request.args.get("content", "Your report content here.")
    body = f"""
<h2>PDF Preview</h2>
<p style="color:#7a9bbf;font-size:13px;margin-bottom:16px">
  Simulated PDF generator output — HTML rendered before conversion.
</p>
<div class="box">
  <div style="background:#fff;color:#111;padding:40px;border-radius:4px;
              font-family:Georgia,serif;min-height:200px;line-height:1.8">
    <h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:16px">
      Security Report
    </h1>
    <div id="report-content">{content}</div>
    <p style="font-size:11px;color:#666;margin-top:40px;border-top:1px solid #ccc;padding-top:8px">
      Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
    </p>
  </div>
</div>
<p style="font-size:12px;color:#7a9bbf;margin-top:12px">
  In a real PDF generator (wkhtmltopdf, Puppeteer), this HTML is rendered
  by a headless browser — XSS executes in that context.
</p>"""
    resp = make_response(page("PDF Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M11 — Email preview (template rendering surface) ──────────────────────────

@app.route("/email-preview")
def email_preview():
    """
    Simulates an HTML email template renderer. Applications that generate
    HTML emails from user-supplied content and preview them in a webmail-style
    interface can be blind XSS surfaces if the preview renders in a browser
    without sanitisation.
    """
    recipient = request.args.get("to", "user@example.com")
    subject   = request.args.get("subject", "Your account notification")
    body_text  = request.args.get("body", "Thank you for signing up!")

    body = f"""
<h2>Email Preview</h2>
<div class="box" style="padding:0;overflow:hidden">
  <div style="background:#1a2235;padding:10px 16px;font-size:12px;color:#7a9bbf;
              border-bottom:1px solid #1e3a5f">
    <span>To: <strong style="color:#e2e8f0">{recipient}</strong></span>
    &nbsp;·&nbsp;
    <span>Subject: <strong style="color:#e2e8f0">{subject}</strong></span>
  </div>
  <div style="background:#fff;color:#111;padding:32px;font-family:Arial,sans-serif;
              font-size:14px;line-height:1.7;min-height:120px">
    {body_text}
  </div>
</div>
<p style="font-size:12px;color:#7a9bbf;margin-top:12px">
  In webmail clients that render HTML directly (early Gmail, Outlook Web),
  user-supplied content in email bodies was a major XSS surface.
  Modern clients sandbox email content; older enterprise webmail often does not.
</p>"""
    resp = make_response(page("Email Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 11")
    print("  http://localhost:5000")
    print("  OOB receiver:  /oob?data=test  (view at /oob/log)")
    print("  Log viewer:    /log-viewer  (blind XSS surface)")
    print("  PDF preview:   /pdf-preview?content=<img src=x onerror=alert(1)>")
    print("  Email preview: /email-preview?body=<img src=x onerror=alert(1)>\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
