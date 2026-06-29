"""
XSS Mastery Lab — Module 10
Cumulative: M01–M09 + in-memory "database" for stored XSS scenarios.

New routes:
  GET  /board               — public comment board (renders stored comments)
  POST /board/post          — accepts new comment (stores raw, no sanitisation)
  GET  /board/clear         — clears all comments (lab utility)
  GET  /admin               — admin panel (renders stored user profiles — second-order)
  POST /admin/profile       — stores a user profile (username + bio)
  GET  /admin/clear         — clears profiles (lab utility)
"""

import re, json
from flask import Flask, request, make_response, redirect, jsonify

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["DEBUG"] = True

# ── In-memory stores (reset on server restart) ────────────────────────────────

comments = []   # list of {"author": str, "text": str}
profiles = []   # list of {"username": str, "bio": str, "website": str}


# ── Shared helpers ────────────────────────────────────────────────────────────

COMMON_CSS = """
  body{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
       padding:32px;max-width:760px}
  h2{color:#38bdf8;margin-bottom:10px}
  .box{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}
  label{color:#7a9bbf;font-size:12px;display:block;margin-bottom:6px}
  input,textarea{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
    border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-bottom:8px;
    box-sizing:border-box}
  textarea{height:80px;resize:vertical;font-family:inherit}
  button{padding:9px 20px;background:#1e3a5f;color:#38bdf8;border:1px solid #38bdf8;
    border-radius:4px;cursor:pointer;font-size:13px;font-weight:600}
  button:hover{background:#0a2a4a}
  a{color:#38bdf8;text-decoration:none}
  .back{font-size:13px;color:#7a9bbf;display:block;margin-bottom:20px}
  .nav-links{display:flex;gap:16px;margin-bottom:24px;font-size:13px}
  .util{font-size:12px;color:#7a9bbf}
  .util a{color:#f87171}
"""

def page(title, body, nav="board"):
    nav_html = {
        "board": '<div class="nav-links"><a href="/board">📋 Comment Board</a><a href="/admin">🛡 Admin Panel</a></div>',
        "admin": '<div class="nav-links"><a href="/board">📋 Comment Board</a><a href="/admin" style="color:#f5c842">🛡 Admin Panel</a></div>',
    }.get(nav, "")
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<style>{COMMON_CSS}</style></head>
<body>
<a class="back" href="/">← Lab Home</a>
{nav_html}
{body}
</body></html>"""


# ── M01–M09 (condensed) ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 10}

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

@app.route("/message")
def message_page():
    body = '<h2>postMessage Receiver</h2><div class="box"><div id="d" style="min-height:40px;border:2px dashed #38bdf8;padding:8px;border-radius:4px">Waiting…</div></div><script>window.addEventListener("message",function(e){document.getElementById("d").innerHTML=e.data;});</script>'
    resp = make_response(page("postMessage", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M10 — Comment board (stored XSS) ─────────────────────────────────────────

@app.route("/board")
def board():
    """
    Public comment board. Renders all stored comments by interpolating
    author and text directly into HTML — no sanitisation.

    Every visitor to this page executes any stored payload.
    This is the canonical stored XSS scenario.
    """
    if comments:
        comment_items = "\n".join(
            f'<div class="box" style="padding:14px 18px">'
            f'<span style="color:#f5c842;font-weight:700;font-size:13px">{c["author"]}</span>'
            f'<span style="color:#7a9bbf;font-size:11px;margin-left:8px">{c.get("ts","")}</span>'
            f'<p style="margin-top:6px;font-size:14px">{c["text"]}</p>'
            f'</div>'
            for c in comments
        )
    else:
        comment_items = '<p style="color:#7a9bbf;font-size:13px">No comments yet.</p>'

    body = f"""
<h2>Comment Board</h2>
<div class="box">
  <label>Post a comment:</label>
  <form method="POST" action="/board/post">
    <input name="author" placeholder="Your name" required>
    <textarea name="text" placeholder="Comment text…" required></textarea>
    <button type="submit">Post Comment</button>
  </form>
</div>

<h2 style="margin-top:28px">Comments ({len(comments)})</h2>
{comment_items}

<p class="util" style="margin-top:20px">
  Lab utility: <a href="/board/clear">Clear all comments</a>
</p>"""

    resp = make_response(page("Comment Board", body, "board"))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/board/post", methods=["POST"])
def board_post():
    """
    Stores comment without sanitisation.
    Author and text are stored raw and rendered raw into board HTML.
    Both fields are injection points.
    """
    import datetime
    author = request.form.get("author", "Anonymous")
    text   = request.form.get("text", "")
    comments.append({
        "author": author,
        "text": text,
        "ts": datetime.datetime.now().strftime("%H:%M:%S"),
    })
    return redirect("/board")


@app.route("/board/clear")
def board_clear():
    comments.clear()
    return redirect("/board")


# ── M10 — Admin panel (second-order stored XSS) ───────────────────────────────

@app.route("/admin")
def admin():
    """
    Admin panel — renders stored user profiles.

    Second-order pattern:
      1. User submits profile via /admin/profile (stored, not immediately rendered)
      2. Admin visits /admin to review profiles
      3. Payload stored in username/bio executes in admin's browser

    The payload is stored in one context (profile submission) and renders
    in a different, more privileged context (admin panel).
    """
    if profiles:
        profile_rows = "\n".join(
            f'<tr>'
            f'<td style="color:#f5c842;font-family:\'Courier New\',monospace;font-size:13px">{p["username"]}</td>'
            f'<td style="font-size:13px">{p["bio"]}</td>'
            f'<td style="font-size:13px"><a href="{p["website"]}">{p["website"] or "—"}</a></td>'
            f'</tr>'
            for p in profiles
        )
        table = f"""
<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px">
  <thead><tr>
    <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Username</th>
    <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Bio</th>
    <th style="text-align:left;padding:8px;background:#060d1a;color:#38bdf8;border-bottom:1px solid #1e3a5f">Website</th>
  </tr></thead>
  <tbody>{profile_rows}</tbody>
</table>"""
    else:
        table = '<p style="color:#7a9bbf;font-size:13px">No profiles yet.</p>'

    body = f"""
<h2 style="color:#f5c842">🛡 Admin Panel</h2>
<p style="color:#7a9bbf;font-size:13px;margin-bottom:16px">
  Registered user profiles — for admin review only.
  This page is not linked from the public site.
</p>

<div class="box">
  <label>Stored profiles ({len(profiles)}):</label>
  {table}
</div>

<p class="util" style="margin-top:20px">
  Lab utility: <a href="/admin/clear">Clear all profiles</a>
  &nbsp;·&nbsp; <a href="/admin/profile" style="color:#38bdf8">Register a profile</a>
</p>"""

    resp = make_response(page("Admin Panel", body, "admin"))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/admin/profile", methods=["GET", "POST"])
def admin_profile():
    """
    GET:  show the profile registration form (public-facing)
    POST: store the profile (no sanitisation — second-order stored XSS)
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        bio      = request.form.get("bio", "")
        website  = request.form.get("website", "")
        profiles.append({"username": username, "bio": bio, "website": website})
        body = f"""
<h2>Profile Registered</h2>
<div class="box">
  <p>Username: <strong>{username}</strong></p>
  <p>Bio: {bio}</p>
  <p>Website: <a href="{website}">{website or "—"}</a></p>
  <p style="color:#7a9bbf;font-size:13px;margin-top:12px">
    Your profile will appear in the admin review panel.
  </p>
</div>
<p style="margin-top:16px"><a href="/admin/profile">Register another</a></p>"""
        resp = make_response(page("Profile Registered", body))
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    # GET — registration form
    body = """
<h2>Register Profile</h2>
<div class="box">
  <label>Create a user profile (submitted for admin review):</label>
  <form method="POST" action="/admin/profile">
    <input name="username" placeholder="Username" required>
    <textarea name="bio" placeholder="Short bio…"></textarea>
    <input name="website" placeholder="Website URL (optional)">
    <button type="submit">Register</button>
  </form>
</div>"""
    resp = make_response(page("Register Profile", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/admin/clear")
def admin_clear():
    profiles.clear()
    return redirect("/admin")


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 10")
    print("  http://localhost:5000")
    print("  Comment board: /board")
    print("  Admin panel:   /admin  (second-order stored XSS)")
    print("  Profile form:  /admin/profile\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
