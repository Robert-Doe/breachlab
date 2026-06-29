"""
XSS Mastery Lab — Module 04
Cumulative: M01 + M02 + M03 routes, plus the new /search endpoint —
a realistic reflected XSS vulnerability modelled after real-world
search boxes that echo the user's query back into the results page.

New in this module:
  GET /search?q=...      → reflects q into HTML body (body context)
  GET /search-attr?q=... → reflects q into an attribute value (attr context)
  GET /search-js?q=...   → reflects q into a <script> block (script context)

Each endpoint represents a different injection context so the student
can observe how the same input behaves differently depending on context.
"""

from flask import Flask, request, send_from_directory, make_response
import os

app = Flask(__name__, static_folder="public")

# ── Shared page shell ─────────────────────────────────────────────────────────

def page_shell(title, body_content):
    """Returns a minimal full HTML page. Used by all vulnerable endpoints."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    body  {{ background:#0b0f1a; color:#e2e8f0;
             font-family:-apple-system,sans-serif; padding:32px; max-width:700px; }}
    h2    {{ color:#38bdf8; margin-bottom:8px; }}
    .box  {{ background:#141c2e; border:1px solid #1e3a5f; border-radius:6px;
             padding:18px; margin-top:16px; }}
    label {{ color:#7a9bbf; font-size:12px; display:block; margin-bottom:8px; }}
    form  {{ margin-bottom:20px; display:flex; gap:8px; }}
    input[type=text] {{ flex:1; background:#060d1a; color:#e2e8f0;
                        border:1px solid #1e3a5f; border-radius:4px;
                        padding:8px 12px; font-size:14px; }}
    button {{ background:#38bdf8; color:#0b0f1a; border:none; border-radius:4px;
              padding:8px 16px; font-weight:700; cursor:pointer; }}
    .back {{ font-size:13px; color:#7a9bbf; margin-bottom:20px; display:block; }}
    a     {{ color:#38bdf8; }}
  </style>
</head>
<body>
  <a class="back" href="/attack_01_script.html">← Attack 01 Demo Page</a>
  {body_content}
</body>
</html>"""

# ── M01-M03 routes (unchanged) ────────────────────────────────────────────────

@app.route("/")
def home():
    return send_from_directory("public", "index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 4}

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "")
    return make_response(f'<div style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</div>',
                         200, {"Content-Type": "text/html; charset=utf-8"})

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    return make_response(
        f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>',
        200, {"Content-Type": "text/html; charset=utf-8"})

# ── M04 — Vulnerable search endpoints ────────────────────────────────────────

@app.route("/search")
def search():
    """
    VULNERABILITY: Body-context reflection.
    The query string is inserted directly into the HTML body.
    Injection context: HTML body — attacker can inject any tag.
    Real-world analogue: search results page that says "Results for: [query]"
    """
    q = request.args.get("q", "")

    # DELIBERATE VULNERABILITY: f-string interpolation with no escaping.
    # In production this should be: html.escape(q) or a templating engine
    # with auto-escaping enabled (Jinja2, React JSX, etc.).
    body = f"""
  <h2>Search Results</h2>
  <form method="GET" action="/search">
    <input type="text" name="q" value="{q}" placeholder="Search...">
    <button type="submit">Search</button>
  </form>
  <div class="box">
    <label>Results for:</label>
    <div id="query-echo">{q}</div>
  </div>
  <div class="box">
    <label>Injection context: HTML BODY — your input lands here ↓</label>
    <div style="border:2px dashed #f5c842; padding:10px; border-radius:4px">
      {q}
    </div>
  </div>
  <p style="color:#7a9bbf; font-size:12px; margin-top:16px">
    Open DevTools Elements panel to inspect the DOM.
    Try: <code>?q=&lt;b&gt;bold&lt;/b&gt;</code> then
    <code>?q=&lt;script&gt;alert(document.domain)&lt;/script&gt;</code>
  </p>"""

    resp = make_response(page_shell("Search — Body Context", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    # Deliberately omitting X-XSS-Protection (removed from Chrome anyway)
    # and Content-Security-Policy so the full attack is visible.
    return resp


@app.route("/search-attr")
def search_attr():
    """
    VULNERABILITY: Attribute-value-context reflection.
    The query is placed inside an HTML attribute value.
    Injection context: attribute — attacker needs " to break out.
    Real-world analogue: search box where query is pre-filled into input value.
    """
    q = request.args.get("q", "")

    body = f"""
  <h2>Search — Attribute Context</h2>
  <div class="box">
    <label>Your query is pre-filled into the input value attribute:</label>
    <input type="text" name="q" value="{q}" style="width:100%;padding:8px;
           background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px">
  </div>
  <div class="box">
    <label>Raw HTML being generated (see View Source for the real thing):</label>
    <pre style="background:#060d1a;padding:10px;border-radius:4px;
                font-size:12px;overflow-x:auto;white-space:pre-wrap">
&lt;input type="text" name="q" value="<b style="color:#f5c842">{q}</b>"&gt;</pre>
  </div>
  <p style="color:#7a9bbf; font-size:12px; margin-top:12px">
    Try: <code>?q=" onmouseover="alert(document.domain)" x="</code><br>
    The " closes the value attribute. Then onmouseover becomes a new attribute.
  </p>"""

    resp = make_response(page_shell("Search — Attribute Context", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/search-js")
def search_js():
    """
    VULNERABILITY: Script-context reflection.
    The query is embedded inside a <script> block as a JS string value.
    Injection context: script — attacker needs </script> to break out,
    or a JS string escape to inject code within the existing script block.
    Real-world analogue: server-side rendering that passes data into JS:
      var config = { query: "[USER_INPUT]" };
    """
    q = request.args.get("q", "")

    # The query is embedded in a JavaScript string. This is a common
    # pattern in legacy server-side rendering — passing data from the
    # server into a JS variable for use by client-side code.
    body = f"""
  <h2>Search — Script Context</h2>
  <div class="box">
    <label>Your query is embedded in a JavaScript variable:</label>
    <pre style="background:#060d1a;padding:10px;border-radius:4px;font-size:12px">
var searchQuery = "<b style="color:#f5c842">{q}</b>";
document.getElementById('result').textContent = 'You searched for: ' + searchQuery;</pre>
  </div>
  <div class="box" id="result"><!-- JS will populate this --></div>
  <p style="color:#7a9bbf; font-size:12px; margin-top:12px">
    Try: <code>?q=";alert(document.domain);//</code><br>
    The " closes the JS string. alert() executes. // comments out the rest.
  </p>
  <script>
    // DELIBERATE VULNERABILITY: user input embedded in JS via server-side template
    var searchQuery = "{q}";
    document.getElementById('result').textContent = 'You searched for: ' + searchQuery;
  </script>"""

    resp = make_response(page_shell("Search — Script Context", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XSS Mastery Lab — Module 04")
    print(f"  http://localhost:{port}")
    print(f"  Body context:    /search?q=test")
    print(f"  Attr context:    /search-attr?q=test")
    print(f"  Script context:  /search-js?q=test")
    print(f"  Attack demo:     /attack_01_script.html")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=True)
