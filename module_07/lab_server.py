"""
XSS Mastery Lab — Module 07
Cumulative: M01–M06 + three new namespace-confusion endpoints.

New routes:
  GET /svg-inject?q=       — reflects q inside an SVG element (svg parsing context)
  GET /math-inject?q=      — reflects q inside a MathML element
  GET /iframe-inject?q=    — reflects q into an iframe srcdoc attribute
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
</style></head>
<body><a class="back" href="/attack_04_namespace.html">← Attack 04 Demo Page</a>
{body}</body></html>"""


def page_shell(title, body):
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
<style>body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
padding:32px;max-width:720px}}h2{{color:#38bdf8;margin-bottom:10px}}
.box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}}
label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}
input{{width:100%;padding:8px;background:#060d1a;color:#e2e8f0;
border:1px solid #1e3a5f;border-radius:4px;font-size:14px}}</style>
</head><body>{body}</body></html>"""


# ── M01 ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 7}


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
  <div class="box"><label>Filtered:</label><pre>{filtered}</pre></div>
  <div class="box"><label>Rendered:</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">{filtered}</div></div>"""
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
  <div class="box"><label>Output:</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">{q}</div></div>"""
    resp = make_response(page("Filter Demo", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M06 ───────────────────────────────────────────────────────────────────────

@app.route("/redirect")
def vuln_redirect():
    url = request.args.get("url", "/")
    return redirect(url)

@app.route("/link-preview")
def link_preview():
    url   = request.args.get("url", "")
    label = request.args.get("label", "Visit link")
    body  = f'<h2>Link Preview</h2><div class="box"><a href="{url}" style="font-size:18px;color:#f5c842">{label}</a></div>'
    resp  = make_response(page("Link Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/profile")
def profile():
    username = request.args.get("username", "alice")
    bio      = request.args.get("bio", "Security researcher")
    site     = request.args.get("site", "")
    avatar   = request.args.get("avatar", "")
    avatar_html = f'<img src="{avatar}" alt="avatar" style="width:80px;height:80px;border-radius:50%;object-fit:cover">' if avatar else '<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;display:flex;align-items:center;justify-content:center;font-size:32px">👤</div>'
    site_html   = f'<a href="{site}" style="color:#38bdf8">{site}</a>' if site else '<em style="color:#7a9bbf">No website</em>'
    body = f'<h2>Profile</h2><div class="box" style="display:flex;gap:20px">{avatar_html}<div><p style="font-size:20px;font-weight:700">{username}</p><p style="color:#7a9bbf">{bio}</p><p style="font-size:13px">Site: {site_html}</p></div></div>'
    resp = make_response(page(f"Profile — {username}", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M07 — SVG namespace injection ────────────────────────────────────────────

@app.route("/svg-inject")
def svg_inject():
    """
    Reflects q= inside an SVG element in an HTML document.

    The HTML parser switches to SVG parsing rules when it encounters <svg>.
    Inside SVG context, some tags that are "safe" in HTML (like <script>) are
    interpreted differently, and new vectors like <animate>, <set>, and
    <foreignObject> become available.

    Key vector: <svg> switches the HTML5 parser to foreign content mode.
    A <script> tag INSIDE <svg> executes — unlike a <script> injected via
    innerHTML into an HTML context.
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>SVG Injection</h2>
  <div class="box">
    <label>SVG output (q= injected inside &lt;svg&gt;):</label>
    <div style="border:2px dashed #a78bfa;padding:10px;border-radius:4px;min-height:60px">
      <svg xmlns="http://www.w3.org/2000/svg" width="400" height="100"
           style="background:#060d1a;display:block;border-radius:4px">
        <text x="10" y="30" fill="#38bdf8" font-size="14">SVG context — injection below:</text>
        {q}
      </svg>
    </div>
  </div>
  <div class="box">
    <label>Injection context:</label>
    <pre>&lt;svg ...&gt;
  &lt;text ...&gt;SVG context:&lt;/text&gt;
  <span style="color:#f5c842">{q}</span>   &lt;!-- injected here --&gt;
&lt;/svg&gt;</pre>
  </div>"""
    resp = make_response(page("SVG Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M07 — MathML namespace injection ─────────────────────────────────────────

@app.route("/math-inject")
def math_inject():
    """
    Reflects q= inside a MathML element.

    MathML is the third parsing namespace in HTML5 (alongside HTML and SVG).
    The parser switches to MathML mode on <math>. Inside MathML, a
    <mtext> element containing HTML can break back out to HTML context —
    the foundation of many mXSS attacks.

    Key vector: <math><mtext><table><mglyph><style>  — classic mXSS chain
    (studied in depth in Module 13). Here we show the basic namespace switch
    and simple event-handler injection in MathML context.
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>MathML Injection</h2>
  <div class="box">
    <label>MathML output (q= injected inside &lt;math&gt;):</label>
    <div style="border:2px dashed #f5c842;padding:10px;border-radius:4px;min-height:40px">
      <math xmlns="http://www.w3.org/1998/Math/MathML">
        <mrow>
          <mi>x</mi><mo>=</mo><mn>42</mn>
          {q}
        </mrow>
      </math>
    </div>
  </div>
  <div class="box">
    <label>Injection context:</label>
    <pre>&lt;math ...&gt;
  &lt;mrow&gt;
    &lt;mi&gt;x&lt;/mi&gt;&lt;mo&gt;=&lt;/mo&gt;&lt;mn&gt;42&lt;/mn&gt;
    <span style="color:#f5c842">{q}</span>   &lt;!-- injected here --&gt;
  &lt;/mrow&gt;
&lt;/math&gt;</pre>
  </div>"""
    resp = make_response(page("MathML Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M07 — iframe srcdoc injection ────────────────────────────────────────────

@app.route("/iframe-inject")
def iframe_inject():
    """
    Reflects q= into the srcdoc attribute of an iframe.

    srcdoc is an HTML attribute that specifies an inline HTML document for the
    iframe to render. It is HTML-parsed twice: once as an attribute value
    (HTML entities decoded), once as the srcdoc document. A sanitiser that
    only processes the outer HTML may not process the inner srcdoc document.

    The iframe runs in the same origin as the parent page if no sandbox
    attribute is present — giving any script in srcdoc full same-origin access.
    """
    q = request.args.get("q", "")
    body = f"""
  <h2>iframe srcdoc Injection</h2>
  <div class="box">
    <label>iframe rendered (srcdoc contains injected content):</label>
    <iframe srcdoc="<html><body style='background:#0b0f1a;color:#e2e8f0;padding:10px;font-family:sans-serif'><p>iframe document</p>{q}</body></html>"
            style="width:100%;height:100px;border:2px dashed #38bdf8;border-radius:4px;background:#060d1a"
            sandbox="allow-scripts allow-same-origin"></iframe>
  </div>
  <div class="box">
    <label>Injection context (srcdoc attribute value):</label>
    <pre>srcdoc="&lt;html&gt;&lt;body&gt;&lt;p&gt;iframe doc&lt;/p&gt;<span style="color:#f5c842">{q}</span>&lt;/body&gt;&lt;/html&gt;"</pre>
  </div>"""
    resp = make_response(page("iframe srcdoc Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 07")
    print("  http://localhost:5000")
    print("  svg-inject:    /svg-inject?q=<script>alert(1)</script>")
    print("  math-inject:   /math-inject?q=<mtext><img src=x onerror=alert(1)></mtext>")
    print("  iframe-inject: /iframe-inject?q=<img src=x onerror=alert(1)>\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
