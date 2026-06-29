"""
XSS Mastery Lab — Module 05
Cumulative: M01–M04 routes, plus two new endpoints demonstrating
event-handler injection specifically:

  GET  /vuln-display?content=...   reflects into innerHTML of a div
                                   (simulates a "sanitiser" that strips
                                   <script> but leaves everything else)
  GET  /filter-demo?q=...          naive script-tag filter — blocks <script>
                                   but event handlers still execute

These endpoints show why blocking <script> alone is not a defence.
"""

from flask import Flask, request, send_from_directory, make_response
import re, os

app = Flask(__name__, static_folder="public")

# ── Shared helpers ────────────────────────────────────────────────────────────

def page(title, body, extra_head=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>{title}</title>{extra_head}
  <style>
    body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
         padding:32px;max-width:720px}}
    h2{{color:#38bdf8;margin-bottom:10px}}
    .box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;
          padding:18px;margin-top:16px}}
    label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}
    a{{color:#38bdf8}} code{{font-family:'Courier New',monospace;font-size:12px;
    background:#060d1a;color:#38bdf8;padding:2px 5px;border-radius:3px}}
    .back{{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}}
    pre{{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;
         overflow-x:auto;white-space:pre-wrap;color:#fb923c}}
  </style>
</head>
<body>
  <a class="back" href="/attack_02_events.html">← Attack 02 Demo Page</a>
  {body}
</body>
</html>"""

# ── M01–M04 routes (condensed, unchanged) ────────────────────────────────────

@app.route("/")
def home(): return send_from_directory("public","index.html")

@app.route("/ping")
def ping(): return {"status":"ok","module":5}

@app.route("/parse-demo")
def parse_demo():
    raw=request.args.get("html","")
    return make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>',200,{"Content-Type":"text/html; charset=utf-8"})

@app.route("/reflect")
def reflect():
    q=request.args.get("q","")
    return make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>',200,{"Content-Type":"text/html; charset=utf-8"})

@app.route("/search")
def search():
    q=request.args.get("q","")
    return make_response(page("Search",f'<h2>Search</h2><div class="box"><label>Results for:</label><div>{q}</div></div>'),200,{"Content-Type":"text/html; charset=utf-8"})

@app.route("/search-attr")
def search_attr():
    q=request.args.get("q","")
    return make_response(page("Search Attr",f'<h2>Search — Attr</h2><div class="box"><input value="{q}" style="width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;border-radius:4px"></div>'),200,{"Content-Type":"text/html; charset=utf-8"})

@app.route("/search-js")
def search_js():
    q=request.args.get("q","")
    b=f'<h2>Search — JS</h2><div class="box" id="r"></div><script>var q="{q}";document.getElementById("r").textContent="Searched: "+q</script>'
    return make_response(page("Search JS",b),200,{"Content-Type":"text/html; charset=utf-8"})

# ── M05 — vuln-display: strips <script> but leaves event handlers ─────────────

@app.route("/vuln-display")
def vuln_display():
    """
    Simulates a 'sanitiser' that only strips <script> tags.
    Demonstrates that event handlers execute without any <script> tag.

    This is a realistic representation of naive server-side filtering:
    many real legacy applications perform regex replacements on <script>
    while leaving all other HTML intact — a completely ineffective defence.
    """
    content = request.args.get("content", "")

    # THE "SANITISER": removes <script>...</script> blocks (case-insensitive).
    # This is the kind of filter a developer writes after their first XSS report.
    # It stops exactly one vector while leaving 149 others open.
    filtered = re.sub(r'<script[\s\S]*?</script>', '', content, flags=re.IGNORECASE)

    body = f"""
  <h2>Display with "Script Filter"</h2>
  <div class="box">
    <label>Original input:</label>
    <pre>{content}</pre>
  </div>
  <div class="box">
    <label>After removing &lt;script&gt; tags:</label>
    <pre>{filtered}</pre>
  </div>
  <div class="box">
    <label>Rendered (event handlers still execute here):</label>
    <div id="rendered" style="min-height:40px;padding:8px;
         border:2px dashed #f5c842;border-radius:4px">{filtered}</div>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Try: <code>?content=&lt;img src=x onerror=alert(document.domain)&gt;</code><br>
    The filter sees no &lt;script&gt; tag. The browser sees an img with an event handler.
  </p>"""

    resp = make_response(page("Vuln Display", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M05 — filter-demo: a slightly better (but still broken) filter ────────────

@app.route("/filter-demo")
def filter_demo():
    """
    A multi-rule naive filter that blocks several patterns.
    Still bypassable via the long tail of event handlers.
    """
    q = request.args.get("q", "")

    # Naive blocklist — typical of hand-rolled filters in legacy code.
    # Each rule patches one specific bypass but creates new gaps.
    blocked_patterns = [
        (r'<script', 'stripped &lt;script'),
        (r'javascript:', 'stripped javascript:'),
        (r'onerror', 'stripped onerror'),
        (r'onload', 'stripped onload'),
        (r'onclick', 'stripped onclick'),
    ]

    filtered = q
    rules_applied = []
    for pattern, label in blocked_patterns:
        new = re.sub(pattern, '', filtered, flags=re.IGNORECASE)
        if new != filtered:
            rules_applied.append(label)
            filtered = new

    rules_html = ''.join(f'<li style="color:#f87171">{r}</li>' for r in rules_applied) if rules_applied else '<li style="color:#4ade80">No rules triggered</li>'

    body = f"""
  <h2>Filter Demo — Naive Blocklist</h2>
  <div class="box">
    <label>Rules applied:</label>
    <ul style="font-size:13px;padding-left:18px">{rules_html}</ul>
  </div>
  <div class="box">
    <label>Output after filtering (still rendered as HTML):</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px;min-height:40px">
      {filtered}
    </div>
  </div>
  <p style="color:#7a9bbf;font-size:12px;margin-top:12px">
    Bypasses: <code>ontoggle</code>, <code>onfocus</code>, <code>onmouseover</code>,
    <code>onanimationstart</code>, <code>onpointerover</code> — none of these are in the blocklist.
  </p>"""

    resp = make_response(page("Filter Demo", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XSS Mastery Lab — Module 05")
    print(f"  http://localhost:{port}")
    print(f"  vuln-display: /vuln-display?content=<img src=x onerror=alert(1)>")
    print(f"  filter-demo:  /filter-demo?q=<details open ontoggle=alert(1)>")
    print(f"  Attack demo:  /attack_02_events.html\n")
    app.run(host="0.0.0.0", port=port, debug=True)
