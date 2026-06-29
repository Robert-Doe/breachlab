"""
XSS Mastery Lab — Module 09
Cumulative: M01–M08 + minimal new server routes.

Module 09 is primarily client-side — the DOM XSS lab lives in
public/dom_lab.html and executes entirely in the browser.

New server routes:
  GET /api/search?q=   — returns JSON {query, results} — used as a source
                         by the vulnerable client-side search widget
  GET /message         — page with postMessage listener (DOM XSS via postMessage source)
"""

import re, json
from flask import Flask, request, make_response, redirect, jsonify

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["DEBUG"] = True


# ── Shared helpers ────────────────────────────────────────────────────────────

def page(title, body):
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<style>body{{background:#0b0f1a;color:#e2e8f0;font-family:-apple-system,sans-serif;
padding:32px;max-width:720px}}h2{{color:#38bdf8;margin-bottom:10px}}
.box{{background:#141c2e;border:1px solid #1e3a5f;border-radius:6px;padding:18px;margin-top:16px}}
label{{color:#7a9bbf;font-size:12px;display:block;margin-bottom:8px}}a{{color:#38bdf8}}
code{{font-family:'Courier New',monospace;font-size:12px;background:#060d1a;
color:#38bdf8;padding:2px 5px;border-radius:3px}}
.back{{font-size:13px;color:#7a9bbf;margin-bottom:20px;display:block}}
pre{{background:#060d1a;padding:10px;border-radius:4px;font-size:12px;
overflow-x:auto;white-space:pre-wrap;color:#fb923c}}</style>
</head><body><a class="back" href="/dom_lab.html">← DOM XSS Lab</a>{body}</body></html>"""


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
    return {"status": "ok", "module": 9}


# ── M02–M08 (condensed cumulative routes) ─────────────────────────────────────

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
    rules = [(re.compile(r'<script', re.IGNORECASE), "stripped &lt;script"),
             (re.compile(r'javascript:', re.IGNORECASE), "stripped javascript:"),
             (re.compile(r'onerror', re.IGNORECASE), "stripped onerror"),
             (re.compile(r'onload', re.IGNORECASE), "stripped onload"),
             (re.compile(r'onclick', re.IGNORECASE), "stripped onclick")]
    applied = []
    for pattern, label in rules:
        if pattern.search(q):
            q = pattern.sub("", q); applied.append(label)
    rules_html = "".join(f'<li style="color:#f87171">{r}</li>' for r in applied) or '<li style="color:#4ade80">No rules triggered</li>'
    body = f'<h2>Filter Demo</h2><div class="box"><ul style="font-size:13px;padding-left:18px">{rules_html}</ul></div><div class="box"><div style="border:2px dashed #f5c842;padding:10px;border-radius:4px">{q}</div></div>'
    resp = make_response(page("Filter Demo", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/redirect")
def vuln_redirect():
    return redirect(request.args.get("url", "/"))

@app.route("/link-preview")
def link_preview():
    url = request.args.get("url", ""); label = request.args.get("label", "Visit link")
    body = f'<h2>Link Preview</h2><div class="box"><a href="{url}" style="font-size:18px;color:#f5c842">{label}</a></div>'
    resp = make_response(page("Link Preview", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/profile")
def profile():
    u = request.args.get("username", "alice"); b = request.args.get("bio", "Researcher")
    s = request.args.get("site", ""); av = request.args.get("avatar", "")
    avH = f'<img src="{av}" style="width:80px;height:80px;border-radius:50%">' if av else '<div style="width:80px;height:80px;border-radius:50%;background:#1e3a5f;font-size:32px;display:flex;align-items:center;justify-content:center">👤</div>'
    sH = f'<a href="{s}">{s}</a>' if s else '<em style="color:#7a9bbf">none</em>'
    body = f'<h2>Profile</h2><div class="box" style="display:flex;gap:20px">{avH}<div><p style="font-size:20px;font-weight:700">{u}</p><p style="color:#7a9bbf">{b}</p><p>Site: {sH}</p></div></div>'
    resp = make_response(page(f"Profile — {u}", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/svg-inject")
def svg_inject():
    q = request.args.get("q", "")
    body = f'<h2>SVG Inject</h2><div class="box"><svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" style="background:#060d1a;display:block"><text x="10" y="25" fill="#38bdf8" font-size="13">SVG:</text>{q}</svg></div>'
    resp = make_response(page("SVG Inject", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/math-inject")
def math_inject():
    q = request.args.get("q", "")
    body = f'<h2>MathML</h2><div class="box"><math xmlns="http://www.w3.org/1998/Math/MathML"><mrow><mi>x</mi><mo>=</mo><mn>42</mn>{q}</mrow></math></div>'
    resp = make_response(page("MathML", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/iframe-inject")
def iframe_inject():
    q = request.args.get("q", "")
    body = f'<h2>iframe srcdoc</h2><div class="box"><iframe srcdoc="<html><body style=\'background:#0b0f1a;color:#e2e8f0;padding:10px\'><p>iframe</p>{q}</body></html>" style="width:100%;height:90px;border:2px dashed #38bdf8" sandbox="allow-scripts allow-same-origin"></iframe></div>'
    resp = make_response(page("iframe srcdoc", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/attr-double")
def attr_double():
    q = request.args.get("q", "")
    resp = make_response(page("Attr Double", f'<h2>Attr Double</h2><div class="box"><input value="{q}"><pre>value="{q}"</pre></div>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/attr-single")
def attr_single():
    q = request.args.get("q", "")
    resp = make_response(page("Attr Single", f"<h2>Attr Single</h2><div class='box'><input value='{q}'><pre>value='{q}'</pre></div>"))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/attr-unquoted")
def attr_unquoted():
    q = request.args.get("q", "")
    resp = make_response(page("Attr Unquoted", f'<h2>Attr Unquoted</h2><div class="box"><input value={q}><pre>value={q}</pre></div>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/attr-data")
def attr_data():
    q = request.args.get("q", "")
    resp = make_response(page("Data Attr", f'<h2>Data Attr</h2><div class="box"><div id="w" data-query="{q}" style="padding:8px;border:1px solid #1e3a5f;border-radius:4px;min-height:32px"></div></div><script>(function(){{const w=document.getElementById("w");w.innerHTML="Results: "+w.dataset.query;}})();</script>'))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── M09 — JSON API (source for DOM XSS widget) ───────────────────────────────

@app.route("/api/search")
def api_search():
    """
    Returns search results as JSON.
    The query string is echoed back in the JSON response.
    The vulnerable client-side widget reads response.query and passes it
    to innerHTML without sanitisation — DOM XSS via JSON API source.
    """
    q = request.args.get("q", "")
    results = [
        {"title": "Result 1", "url": "/page/1"},
        {"title": "Result 2", "url": "/page/2"},
    ]
    return jsonify({"query": q, "results": results, "count": len(results)})


# ── M09 — postMessage DOM XSS ────────────────────────────────────────────────

@app.route("/message")
def message_page():
    """
    A page with a postMessage event listener that passes received messages
    to innerHTML without validation. An attacker-controlled parent frame
    (or window.open()) can postMessage a payload and trigger XSS.
    """
    body = """
  <h2>postMessage Receiver</h2>
  <div class="box">
    <label>Messages received via postMessage:</label>
    <div id="msg-display" style="min-height:50px;padding:10px;
         border:2px dashed #38bdf8;border-radius:4px;font-size:13px">
      Waiting for messages…
    </div>
  </div>
  <div class="box">
    <label>Vulnerable event listener (source of DOM XSS):</label>
    <pre>window.addEventListener('message', function(e) {
  // No origin check — accepts messages from any sender
  // No sanitisation — passes data directly to innerHTML
  document.getElementById('msg-display').innerHTML = e.data;
});</pre>
  </div>
  <script>
    window.addEventListener('message', function(e) {
      // Intentionally vulnerable: no origin check, no sanitisation
      document.getElementById('msg-display').innerHTML = e.data;
    });
  </script>"""
    resp = make_response(page("postMessage Receiver", body))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  XSS Mastery Lab — Module 09")
    print("  http://localhost:5000")
    print("  DOM XSS lab:  /dom_lab.html")
    print("  API source:   /api/search?q=<img src=x onerror=alert(1)>")
    print("  postMessage:  /message\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
