"""
XSS Mastery Lab — Module 01
Flask lab server: minimal home page only.
Vulnerable endpoints are added in later modules — this module is about
getting the environment running and understanding what we are setting up.

Run:
    pip install -r requirements.txt
    python lab_server.py

Then open: http://localhost:5000
"""

from flask import Flask, render_template_string, send_from_directory
import os

app = Flask(__name__, static_folder="public")

# ─── Home ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    """
    Serves the lab home page from public/index.html.
    In later modules we will add routes that are deliberately vulnerable.
    For now this just confirms the server is alive.
    """
    return send_from_directory("public", "index.html")


# ─── Health check — useful for scripting later ───────────────────────────────

@app.route("/ping")
def ping():
    return {"status": "ok", "module": 1}


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XSS Mastery Lab — Module 01")
    print(f"  Listening on http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")
    # debug=True gives auto-reload and detailed error pages.
    # NEVER use debug=True in production — error pages leak internals.
    app.run(host="0.0.0.0", port=port, debug=True)
