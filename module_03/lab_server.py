"""
XSS Mastery Lab — Module 03
Cumulative: M01 + M02 routes, plus /mechanism-demo for serving the
mechanisms page and a minimal /reflect endpoint for Mechanism 1 demos.
"""

from flask import Flask, request, send_from_directory, make_response
import os

app = Flask(__name__, static_folder="public")

# ── M01 routes ────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return send_from_directory("public", "index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 3}

# ── M02 routes ────────────────────────────────────────────────────────────────

@app.route("/parse-demo")
def parse_demo():
    raw = request.args.get("html", "<!-- supply ?html=... -->")
    page = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#0b0f1a;color:#e2e8f0;font-family:sans-serif;padding:24px}}
.injected{{background:#141c2e;border:1px solid #1e3a5f;padding:16px;border-radius:6px;margin-top:16px}}</style>
</head><body><h2 style="color:#38bdf8">Parser Demo</h2>
<div class="injected">{raw}</div></body></html>"""
    resp = make_response(page)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# ── M03 routes ────────────────────────────────────────────────────────────────

@app.route("/reflect")
def reflect():
    """
    Minimal reflector used by the mechanisms demo page.
    Reflects the 'q' parameter raw into an HTML body context.
    Used only for Mechanism 1 (tag parsing) demonstrations in M03.
    Fully exploitable — this is intentional.
    """
    q = request.args.get("q", "")
    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Reflect — Mechanism Demo</title>
  <style>
    body {{ background:#0b0f1a; color:#e2e8f0;
            font-family:sans-serif; padding:24px; }}
    .result {{ background:#141c2e; border:1px solid #1e3a5f;
               padding:16px; border-radius:6px; margin-top:16px; }}
    label {{ color:#7a9bbf; font-size:12px; display:block; margin-bottom:6px; }}
  </style>
</head>
<body>
  <h2 style="color:#38bdf8">Mechanism 1 — Tag Parsing Reflector</h2>
  <label>Your input reflected raw into the HTML body:</label>
  <div class="result">
    {q}
  </div>
  <p style="color:#7a9bbf; font-size:13px; margin-top:16px">
    Open DevTools Elements panel to inspect the DOM.
    Check the Console for any script execution.
  </p>
</body>
</html>"""
    resp = make_response(page)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XSS Mastery Lab — Module 03")
    print(f"  http://localhost:{port}")
    print(f"  Mechanisms demo: http://localhost:{port}/mechanisms_demo.html")
    print(f"  Reflector: http://localhost:{port}/reflect?q=<b>test</b>")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=True)
