"""
XSS Mastery Lab — Module 02
Cumulative: everything from Module 01, plus a new /parse-demo route that
echoes raw HTML input back to the browser so the student can observe how
the parser handles adversarial markup.

NOTE: The /parse-demo route is INTENTIONALLY vulnerable — it reflects
unsanitised user input. This is the point: we are studying what the
browser does with malformed HTML, not building a safe application yet.
"""

from flask import Flask, request, send_from_directory, make_response
import os

app = Flask(__name__, static_folder="public")

# ── Module 01 routes (carried forward) ───────────────────────────────────────

@app.route("/")
def home():
    return send_from_directory("public", "index.html")

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 2}

# ── Module 02 — Raw HTML echo endpoint ───────────────────────────────────────

@app.route("/parse-demo")
def parse_demo():
    """
    Takes a 'html' query parameter and reflects it directly into a full
    HTML page with NO sanitisation whatsoever.

    Why we do this: to observe the browser's parser recovery behaviour.
    The student supplies broken/adversarial HTML and watches the Elements
    panel to see what the browser constructs from it.

    Security note: this is a textbook Reflected XSS endpoint. In every
    module from M04 onward we will add endpoints like this that model
    specific real-world vulnerability patterns.
    """
    raw = request.args.get("html", "<!-- supply ?html=... to inject markup -->")

    # We deliberately do NOT escape 'raw' — that is the entire point.
    # render_template_string would auto-escape; we bypass that with make_response.
    page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Parser Demo — Module 02</title>
  <style>
    body {{ background:#0b0f1a; color:#e2e8f0; font-family:sans-serif; padding:24px; }}
    .injected {{ background:#141c2e; border:1px solid #1e3a5f; padding:16px;
                 border-radius:6px; margin-top:16px; }}
  </style>
</head>
<body>
  <h2 style="color:#38bdf8">Browser Parser Output</h2>
  <p style="color:#7a9bbf">The markup below was injected raw. Open DevTools Elements panel
     to see how the browser parsed it.</p>
  <div class="injected">
    {raw}
  </div>
</body>
</html>"""

    resp = make_response(page)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    # Deliberately omitting X-Content-Type-Options and CSP headers here
    # so the student can see the browser behave without restrictions.
    return resp

# ── Security headers helper (used from M04 onward for the SAFE routes) ───────

def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XSS Mastery Lab — Module 02")
    print(f"  Listening on http://localhost:{port}")
    print(f"  Parser demo: http://localhost:{port}/parse-demo?html=<b>test</b>")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=True)
