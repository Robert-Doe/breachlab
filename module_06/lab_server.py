"""
XSS Mastery Lab — Module 06
Cumulative: M01–M05 + three new URI-scheme-focused endpoints.

New routes:
  GET /redirect?url=          — open redirect, passes url straight to Location header
  GET /link-preview?url=      — renders user-supplied URL in an anchor tag (href injection)
  GET /profile?bio=&site=     — profile page, site= placed in href without validation
"""

import re
from flask import Flask, request, make_response, redirect

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["DEBUG"] = True


# ── Shared helpers ────────────────────────────────────────────────────────────

def page(title, body):
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<style>
  body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
       padding:32px;max-width:720px}}
  h2{{color:#38bdf8;margin-bottom:10px}}
  .box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}}
  label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}
  a{{color:#38bdf8}}code{{font-family:'Courier New',monospace;font-size:12px;
  background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}}
  .back{{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}}
  pre{{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;
       overflow-x:auto;white-space:pre-wrap;color:#fb923c}}
</style></head>
<body><a class="back" href="/attack_03_uri.html">← Attack 03 Demo Page</a>
{body}</body></html>"""


# ── M01 ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 6}


# ── M02 ───────────────────────────────────────────────────────────────────────

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "")
    resp = make_response(
        f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>'
    )
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M03 ───────────────────────────────────────────────────────────────────────

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    resp = make_response(
        f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>'
    )
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M04 ───────────────────────────────────────────────────────────────────────

def page_shell(title, body):
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
<style>body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
padding:32px;max-width:720px}}h2{{color:#38bdf8;margin-bottom:10px}}
.box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}}
label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}
input{{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
border:1px solid #1e3a5f;border-radius:4px;font-size:14px}}</style>
</head><body>{body}</body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    body = f'<h2>Search</h2><div class="box"><label>Results for:</label><div>{q}</div></div>'
    resp = make_response(page_shell("Search", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/search-attr")
def search_attr():
    q = request.args.get("q", "")
    body = f'<h2>Search Attr</h2><div class="box"><input value="{q}"></div>'
    resp = make_response(page_shell("Search Attr", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/search-js")
def search_js():
    q = request.args.get("q", "")
    body = f'<h2>Search JS</h2><div class="box" id="r"></div><script>var q="{q}";document.getElementById("r").textContent="Searched: "+q</script>'
    resp = make_response(page_shell("Search JS", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M05 ───────────────────────────────────────────────────────────────────────

@app.route("/vuln-display")
def vuln_display():
    content = request.args.get("content", "")
    filtered = re.sub(r'<script[\s\S]*?</script>', '', content, flags=re.IGNORECASE)
    body = f"""
  <h2>Display with "Script Filter"</h2>
  <div class="box"><label>Original input:</label><pre>{content}</pre></div>
  <div class="box"><label>After removing &lt;script&gt; tags:</label><pre>{filtered}</pre></div>
  <div class="box">
    <label>Rendered (event handlers still execute):</label>
    <div id="rendered" style="min-height:40px;padding:8px;
         border:2px dashed #f5c842;border-radius:4px">{filtered}</div>
  </div>"""
    resp = make_response(page("Vuln Display", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/filter-demo")
def filter_demo():
    q = request.args.get("q", "")
    rules = [
        (re.compile(r'<script', re.IGNORECASE),    "stripped &lt;script"),
        (re.compile(r'javascript:', re.IGNORECASE), "stripped javascript:"),
        (re.compile(r'onerror', re.IGNORECASE),     "stripped onerror"),
        (re.compile(r'onload', re.IGNORECASE),      "stripped onload"),
        (re.compile(r'onclick', re.IGNORECASE),     "stripped onclick"),
    ]
    applied = []
    for pattern, label in rules:
        if pattern.search(q):
            q = pattern.sub("", q)
            applied.append(label)
    rules_html = "".join(f'<li style="color:#f87171">{r}</li>' for r in applied) \
                 or '<li style="color:#4ade80">No rules triggered</li>'
    body = f"""
  <h2>Filter Demo — Naive Blocklist</h2>
  <div class="box"><label>Rules applied:</label>
    <ul style="font-size:13px;padding-left:18px">{rules_html}</ul></div>
  <div class="box">
    <label>Output after filtering:</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px;min-height:40px">{q}</div>
  </div>"""
    resp = make_response(page("Filter Demo", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M06 — open redirect (no URL validation) ───────────────────────────────────

@app.route("/redirect")
def vuln_redirect():
    """
    Simulates an open redirect endpoint.
    The url= parameter is trusted completely — no scheme validation.
    When url=javascript:..., the browser executes the JS instead of navigating.

    Vulnerable pattern: redirect(url) with no allow-list or scheme check.
    Fix: validate that url starts with '/' or is in an explicit allow-list.
    """
    url = request.args.get("url", "/")
    return redirect(url)


# ── M06 — link preview (href injection) ───────────────────────────────────────

@app.route("/link-preview")
def link_preview():
    """
    Renders a user-supplied URL inside an <a href="..."> tag.
    No scheme validation — javascript: and data: both render and execute.

    Vulnerable pattern: f'<a href="{url}">Visit</a>'  with no sanitisation.
    Fix: ensure url starts with http:// or https:// before interpolating into href.
    """
    url = request.args.get("url", "")
    label = request.args.get("label", "Visit link")

    body = f"""
  <h2>Link Preview</h2>
  <div class="box">
    <label>URL supplied:</label>
    <pre>{url}</pre>
  </div>
  <div class="box">
    <label>Rendered link (click to execute):</label>
    <p style="margin-top:8px">
      <a href="{url}" style="font-size:18px;color:#f5c842">{label}</a>
    </p>
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Right-click → Copy Link Address to see the raw href value.
    </p>
  </div>
  <div class="box">
    <label>Server-side code that produced this:</label>
    <pre>url = request.args.get("url", "")
# NO scheme check — anything goes into href
body = f'&lt;a href="{{url}}"&gt;{label}&lt;/a&gt;'</pre>
  </div>"""

    resp = make_response(page("Link Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M06 — profile page (multiple URL-accepting attributes) ────────────────────

@app.route("/profile")
def profile():
    """
    Simulates a user profile page.
    bio= is reflected into the page body (event-handler injection from M05).
    site= is placed in an href attribute without scheme validation.

    This demonstrates that URL injection can appear in many attribute types:
    href, src, action, formaction, data (object/embed), xlink:href (SVG).
    """
    username = request.args.get("username", "alice")
    bio      = request.args.get("bio", "Security researcher")
    site     = request.args.get("site", "")
    avatar   = request.args.get("avatar", "")

    # avatar= is placed in img src — both data: and javascript: URIs are issues
    avatar_html = f'<img src="{avatar}" alt="avatar" style="width:80px;height:80px;border-radius:50%;object-fit:cover;border:2px solid #1e3a5f">' if avatar else '<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;font-size:32px">👤</div>'

    site_html = f'<a href="{site}" style="color:#38bdf8">{site}</a>' if site else '<em style="color:#7a9bbf">No website</em>'

    body = f"""
  <h2>User Profile</h2>
  <div class="box" style="display:flex;gap:24px;align-items:flex-start">
    {avatar_html}
    <div>
      <p style="font-size:22px;font-weight:700;margin-bottom:4px">{username}</p>
      <p style="color:#7a9bbf;margin-bottom:8px">{bio}</p>
      <p style="font-size:13px">Website: {site_html}</p>
    </div>
  </div>
  <div class="box">
    <label>Injection points in this page:</label>
    <ul style="font-size:13px;padding-left:18px">
      <li><code>bio=</code> → reflected into page body (try event handlers)</li>
      <li><code>site=</code> → placed in <code>href</code> attribute (try javascript: or data:)</li>
      <li><code>avatar=</code> → placed in <code>img src</code> (try onerror, data: URI)</li>
    </ul>
  </div>"""

    resp = make_response(page(f"Profile — {username}", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 06")
    print("  http://localhost:5000")
    print("  redirect:     /redirect?url=javascript:alert(document.origin)")
    print("  link-preview: /link-preview?url=javascript:alert(1)")
    print("  profile:      /profile?username=eve&site=javascript:alert(1)\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
