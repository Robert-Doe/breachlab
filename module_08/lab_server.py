"""
XSS Mastery Lab — Module 08
Cumulative: M01–M07 + four new attribute-context injection endpoints.

New routes:
  GET /attr-double?q=     — q= placed in double-quoted attribute value
  GET /attr-single?q=     — q= placed in single-quoted attribute value
  GET /attr-unquoted?q=   — q= placed in unquoted attribute value
  GET /attr-data?q=       — q= placed in HTML5 data-* attribute (show benign→breakout path)
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
  a{{color:#38bdf8}}
  code{{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;
        color:#38bdf8;padding:2px 5px;border-radius:3px}}
  .back{{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}}
  pre{{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;
       overflow-x:auto;white-space:pre-wrap;color:#fb923c}}
  input{{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
         border:1px solid #1e3a5f;border-radius:4px;font-size:14px;margin-top:4px}}
</style></head>
<body><a class="back" href="/attack_05_attr.html">← Attack 05 Demo Page</a>
{body}</body></html>"""


def page_shell(title, body):
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
<style>body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
padding:32px;max-width:720px}}h2{{color:#38bdf8}}
.box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}}
label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}
input{{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;border:1px solid #1e3a5f;
border-radius:4px;font-size:14px}}</style></head><body>{body}</body></html>"""


# ── M01 ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 8}


# ── M02 ───────────────────────────────────────────────────────────────────────

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "")
    resp = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{raw}</body></html>')
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M03 ───────────────────────────────────────────────────────────────────────

@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    resp = make_response(f'<html><body style="background:#0b0f1a;color:#e2e8f0;padding:20px">{q}</body></html>')
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M04 ───────────────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    q = request.args.get("q", "")
    resp = make_response(page_shell("Search", f'<h2>Search</h2><div class="box"><div>{q}</div></div>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/search-attr")
def search_attr():
    q = request.args.get("q", "")
    resp = make_response(page_shell("Search Attr", f'<h2>Search Attr</h2><div class="box"><input value="{q}"></div>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/search-js")
def search_js():
    q = request.args.get("q", "")
    resp = make_response(page_shell("Search JS", f'<h2>Search JS</h2><div class="box" id="r"></div><script>var q="{q}";document.getElementById("r").textContent="Searched: "+q</script>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M05 ───────────────────────────────────────────────────────────────────────

@app.route("/vuln-display")
def vuln_display():
    content = request.args.get("content", "")
    filtered = re.sub(r'<script[\s\S]*?</script>', '', content, flags=re.IGNORECASE)
    body = f'<h2>Vuln Display</h2><div class="box"><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">{filtered}</div></div>'
    resp = make_response(page("Vuln Display", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/filter-demo")
def filter_demo():
    q = request.args.get("q", "")
    rules = [
        (re.compile(r'<script', re.IGNORECASE), "stripped &lt;script"),
        (re.compile(r'javascript:', re.IGNORECASE), "stripped javascript:"),
        (re.compile(r'onerror', re.IGNORECASE), "stripped onerror"),
        (re.compile(r'onload', re.IGNORECASE), "stripped onload"),
        (re.compile(r'onclick', re.IGNORECASE), "stripped onclick"),
    ]
    applied = []
    for pattern, label in rules:
        if pattern.search(q):
            q = pattern.sub("", q)
            applied.append(label)
    rules_html = "".join(f'<li style="color:#f87171">{r}</li>' for r in applied) or '<li style="color:#4ade80">No rules triggered</li>'
    body = f'<h2>Filter Demo</h2><div class="box"><ul style="font-size:13px;padding-left:18px">{rules_html}</ul></div><div class="box"><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">{q}</div></div>'
    resp = make_response(page("Filter Demo", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M06 ───────────────────────────────────────────────────────────────────────

@app.route("/redirect")
def vuln_redirect():
    return redirect(request.args.get("url", "/"))

@app.route("/link-preview")
def link_preview():
    url = request.args.get("url", "")
    label = request.args.get("label", "Visit link")
    body = f'<h2>Link Preview</h2><div class="box"><a href="{url}" style="font-size:18px;color:#f5c842">{label}</a></div>'
    resp = make_response(page("Link Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/profile")
def profile():
    username = request.args.get("username", "alice")
    bio = request.args.get("bio", "Security researcher")
    site = request.args.get("site", "")
    avatar = request.args.get("avatar", "")
    av = f'<img src="{avatar}" style="width:80px;height:80px;border-radius:50%">' if avatar else '<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;font-size:32px;display:flex;align-items:center;justify-content:center">👤</div>'
    sh = f'<a href="{site}">{site}</a>' if site else '<em style="color:#7a9bbf">none</em>'
    body = f'<h2>Profile</h2><div class="box" style="display:flex;gap:20px">{av}<div><p style="font-size:20px;font-weight:700">{username}</p><p style="color:#7a9bbf">{bio}</p><p>Site: {sh}</p></div></div>'
    resp = make_response(page(f"Profile — {username}", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M07 ───────────────────────────────────────────────────────────────────────

@app.route("/svg-inject")
def svg_inject():
    q = request.args.get("q", "")
    body = f'<h2>SVG Inject</h2><div class="box"><svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" style="background:#060d1a;display:block"><text x="10" y="25" fill="#38bdf8" font-size="13">SVG context:</text>{q}</svg></div>'
    resp = make_response(page("SVG Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/math-inject")
def math_inject():
    q = request.args.get("q", "")
    body = f'<h2>MathML Inject</h2><div class="box"><math xmlns="http://www.w3.org/1998/Math/MathML"><mrow><mi>x</mi><mo>=</mo><mn>42</mn>{q}</mrow></math></div>'
    resp = make_response(page("MathML Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/iframe-inject")
def iframe_inject():
    q = request.args.get("q", "")
    body = f'<h2>iframe srcdoc</h2><div class="box"><iframe srcdoc="<html><body style=\'background:#0b0f1a;color:#e2e8f0;padding:10px\'><p>iframe</p>{q}</body></html>" style="width:100%;height:90px;border:2px dashed #38bdf8;border-radius:4px" sandbox="allow-scripts allow-same-origin"></iframe></div>'
    resp = make_response(page("iframe srcdoc", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M08 — double-quoted attribute ────────────────────────────────────────────

@app.route("/attr-double")
def attr_double():
    """
    q= is placed inside a double-quoted HTML attribute value.
    The attacker must inject a double-quote to close the attribute,
    then inject new attributes or close the tag entirely.

    Vulnerable pattern: value="{q}"
    Break-out payload:  " onmouseover="alert(1)" x="
    Zero-interaction:   " autofocus onfocus="alert(1)" x="
    Tag-close payload:  "><img src=x onerror=alert(1)><input x="
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>Double-Quoted Attribute Injection</h2>
  <div class="box">
    <label>Input field — q= injected into value= attribute:</label>
    <input type="text" value="{q}" placeholder="search here">
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Server template: <code>value="{'{q}'"}"</code>
    </p>
  </div>
  <div class="box">
    <label>Raw HTML produced (view source to verify):</label>
    <pre>value="{q}"</pre>
  </div>"""
    resp = make_response(page("Attr Double", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M08 — single-quoted attribute ────────────────────────────────────────────

@app.route("/attr-single")
def attr_single():
    """
    q= is placed inside a single-quoted HTML attribute value.
    Break-out requires a single-quote instead of a double-quote.
    Note: if a developer "fixed" the double-quote endpoint by escaping "
    but forgot to also escape ', this endpoint is still vulnerable.

    Vulnerable pattern: value='{q}'
    Break-out payload:  ' onmouseover='alert(1)' x='
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>Single-Quoted Attribute Injection</h2>
  <div class="box">
    <label>Input — q= in single-quoted attribute:</label>
    <input type="text" value='{q}' placeholder="search here">
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Server template: <code>value='{"{q}"}'</code>
    </p>
  </div>
  <div class="box">
    <label>Raw HTML produced:</label>
    <pre>value='{q}'</pre>
  </div>"""
    resp = make_response(page("Attr Single", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M08 — unquoted attribute ──────────────────────────────────────────────────

@app.route("/attr-unquoted")
def attr_unquoted():
    """
    q= is placed in an unquoted attribute value.
    Any whitespace character terminates the attribute value in this context —
    no quote character is needed for breakout.

    Vulnerable pattern: value={q}
    Break-out payload:  x onmouseover=alert(1)
                        (the space after 'x' ends the value,
                         onmouseover starts a new attribute)
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>Unquoted Attribute Injection</h2>
  <div class="box">
    <label>Input — q= in unquoted attribute:</label>
    <input type="text" value={q} placeholder="search">
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Server template: <code>value={"{q}"}</code> (no quotes!)
    </p>
  </div>
  <div class="box">
    <label>Raw HTML produced:</label>
    <pre>value={q}</pre>
  </div>
  <div class="box">
    <label>Note — unquoted attribute terminators:</label>
    <p style="font-size:13px;color:#7a9bbf">
      Space, tab, newline, form-feed, carriage-return, and
      <code>&gt;</code> all end an unquoted attribute value.
      No quote character needed at all.
    </p>
  </div>"""
    resp = make_response(page("Attr Unquoted", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M08 — data attribute (read via JS, then used unsafely) ───────────────────

@app.route("/attr-data")
def attr_data():
    """
    q= is placed in a data-* attribute, which is safe on its own.
    The page's JavaScript reads data-query via dataset and passes it to
    innerHTML — creating a DOM XSS sink downstream of a "safe" attribute.

    This models the common pattern where:
      1. Server correctly places user input in a data attribute (safe)
      2. Client JS reads the data attribute and uses it unsafely (vulnerable)

    The injection happens client-side, not server-side — this is DOM XSS.
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>Data Attribute → DOM Sink</h2>
  <div class="box">
    <label>Server places q= in data-query (safe at server level):</label>
    <div id="widget" data-query="{q}"
         style="background:#060d1a;padding:10px;border-radius:4px;
                font-family:'Courier New',monospace;font-size:12px;color:#38bdf8">
      Loading…
    </div>
    <p style="font-size:12px;color:#7a9bbf;margin-top:8px">
      Server template: <code>data-query="{'{q}'"}"</code> — value is in attribute, not rendered body.
    </p>
  </div>
  <div class="box">
    <label>Client JS reads data-query and sets innerHTML (vulnerable):</label>
    <pre id="dom-sink-code">const widget = document.getElementById('widget');
const query = widget.dataset.query;   // reads data-query attribute
widget.innerHTML = 'Results for: ' + query;  // DOM XSS sink</pre>
  </div>
  <div class="box">
    <label>Result of innerHTML assignment:</label>
    <div id="result-display" style="padding:10px;border:2px dashed #f5c842;border-radius:4px;min-height:36px"></div>
  </div>
  <script>
    (function() {{
      const widget = document.getElementById('widget');
      const query  = widget.dataset.query;
      // Intentionally vulnerable — this is the DOM XSS sink being demonstrated
      widget.innerHTML = 'Results for: ' + query;
      document.getElementById('result-display').innerHTML = 'Results for: ' + query;
    }})();
  </script>"""
    resp = make_response(page("Data Attr DOM Sink", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 08")
    print("  http://localhost:5000")
    print('  attr-double:   /attr-double?q=" onmouseover="alert(1)" x="')
    print("  attr-single:   /attr-single?q=' onmouseover='alert(1)' x='")
    print("  attr-unquoted: /attr-unquoted?q=x onmouseover=alert(1)")
    print('  attr-data:     /attr-data?q=<img src=x onerror=alert(1)>\n')
    app.run(host="0.0.0.0", port=5000, debug=True)
