"""
Module 17 — Defenses Lab Server
Demonstrates CSP, Trusted Types, and sanitizer behavior.
Each endpoint has a vulnerable and a defended variant side-by-side.
Run: python lab_server.py  (port 5000)
"""
from flask import Flask, request, make_response

app = Flask(__name__, static_folder='public', static_url_path='/public')

PAGE = """<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>Defense Lab — {title}</title>
<style>
:root{{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--danger:#f87171}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:0}}
nav{{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;gap:16px;align-items:center}}
.brand{{font-weight:800;color:var(--accent);margin-right:auto;font-size:15px}}
nav a{{color:var(--accent);text-decoration:none;font-size:13px}}
main{{padding:32px;max-width:900px}}
</style></head><body>
<nav>
  <span class="brand">DefenseLab M17</span>
  <a href="/">Home</a>
  <a href="/csp-demo">CSP Demo</a>
  <a href="/tt-demo">Trusted Types</a>
  <a href="/sanitizer-demo">Sanitizer Compare</a>
  <a href="/public/defense_csp.html">CSP Interactive</a>
</nav>
<main>{body}</main></body></html>"""

@app.route('/')
def index():
    return PAGE.format(title='Home', body="""
    <h1 style="color:var(--accent);font-size:22px;margin-bottom:16px">M17 Defense Lab</h1>
    <p style="color:var(--muted);font-size:14px;margin-bottom:20px">
      Each demo shows the same input rendered with and without a specific defense.
      Open browser DevTools → Console to see CSP violation reports and Trusted Types errors.
    </p>
    <ul style="list-style:none;font-size:14px;line-height:2.2">
      <li><a href="/csp-demo?q=&lt;img src=x onerror=alert(1)&gt;" style="color:var(--accent)">/csp-demo</a> — CSP enforcement vs. no-CSP</li>
      <li><a href="/tt-demo" style="color:var(--accent)">/tt-demo</a> — Trusted Types enforcement</li>
      <li><a href="/sanitizer-demo?q=&lt;img src=x onerror=alert(1)&gt;" style="color:var(--accent)">/sanitizer-demo</a> — DOMPurify vs. naive allowlist vs. nothing</li>
      <li><a href="/encoding-demo?q=&lt;script&gt;alert(1)&lt;/script&gt;" style="color:var(--accent)">/encoding-demo</a> — Output encoding contexts</li>
    </ul>""")

# ── CSP Demo ─────────────────────────────────────────────────────────────────

@app.route('/csp-demo')
def csp_demo():
    q = request.args.get('q', '<img src=x onerror=alert(1)>')
    import html as h
    body = f"""
    <h1 style="color:var(--accent);font-size:18px;margin-bottom:20px">CSP Demo</h1>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <div style="background:var(--panel);border:1px solid var(--danger);border-radius:8px;padding:20px">
        <h2 style="font-size:14px;color:var(--danger);margin-bottom:10px">No CSP (vulnerable)</h2>
        <p style="font-size:12px;color:var(--muted);margin-bottom:10px">Input reflected into innerHTML. No CSP policy.</p>
        <div id="vuln" style="min-height:30px;background:#060d1a;padding:10px;border-radius:4px;font-size:12px">
          loading…
        </div>
        <script>document.getElementById('vuln').innerHTML = {repr(q)};</script>
      </div>
      <div style="background:var(--panel);border:1px solid var(--ok);border-radius:8px;padding:20px">
        <h2 style="font-size:14px;color:var(--ok);margin-bottom:10px">With Output Encoding (safe)</h2>
        <p style="font-size:12px;color:var(--muted);margin-bottom:10px">Same input, HTML-escaped before insertion.</p>
        <div style="background:#060d1a;padding:10px;border-radius:4px;font-size:12px">{h.escape(q)}</div>
      </div>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-top:16px">
      Try: <code>/csp-demo?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> vs <code>/csp-demo-nonce?q=...</code>
    </p>"""
    return PAGE.format(title='CSP Demo', body=body)

@app.route('/csp-demo-nonce')
def csp_demo_nonce():
    """Same page but with a strict nonce-based CSP."""
    import secrets, html as h
    q = request.args.get('q', '<img src=x onerror=alert(1)>')
    nonce = secrets.token_hex(16)
    body = f"""
    <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">CSP + Nonce Demo</h1>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px">
      This page has: <code>Content-Security-Policy: script-src 'nonce-{nonce}'; default-src 'self'</code><br>
      Injected scripts without the nonce are blocked. Check the Console for CSP violation reports.
    </p>
    <div style="background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px">
      <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Reflected input (via innerHTML):</p>
      <div id="out" style="background:#060d1a;padding:10px;border-radius:4px;font-size:12px;min-height:30px"></div>
      <script nonce="{nonce}">
        // This script has the nonce — executes OK
        document.getElementById('out').innerHTML = {repr(q)};
        // The injected payload (if it contains <script>) has no nonce — blocked
      </script>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-top:12px">
      Note: inline event handlers (onerror=) are still blocked by <code>script-src 'nonce-...'</code>
      because the nonce applies to &lt;script&gt; elements only — inline handlers require <code>'unsafe-hashes'</code>
      or are blocked by default.
    </p>"""
    resp = make_response(PAGE.format(title='CSP Nonce', body=body))
    resp.headers['Content-Security-Policy'] = (
        f"default-src 'self'; script-src 'nonce-{nonce}'; "
        f"report-uri /csp-report"
    )
    return resp

@app.route('/csp-report', methods=['POST'])
def csp_report():
    import json
    data = request.get_json(force=True, silent=True) or {}
    print(f'[CSP VIOLATION] {json.dumps(data, indent=2)[:300]}')
    return ('', 204)

# ── Trusted Types Demo ────────────────────────────────────────────────────────

@app.route('/tt-demo')
def tt_demo():
    resp = make_response(PAGE.format(title='Trusted Types', body="""
    <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">Trusted Types Demo</h1>
    <p style="font-size:13px;color:var(--muted);margin-bottom:20px">
      This page enforces <code>require-trusted-types-for 'script'</code>. Open DevTools Console.<br>
      Any assignment to <code>innerHTML</code> without a Trusted Types policy throws a TypeError.
    </p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div style="background:var(--panel);border:1px solid var(--danger);border-radius:8px;padding:16px">
        <h2 style="font-size:13px;color:var(--danger);margin-bottom:8px">Direct innerHTML (throws)</h2>
        <div id="bad" style="background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px"></div>
        <p id="bad-out" style="font-size:11px;color:var(--danger);margin-top:6px"></p>
      </div>
      <div style="background:var(--panel);border:1px solid var(--ok);border-radius:8px;padding:16px">
        <h2 style="font-size:13px;color:var(--ok);margin-bottom:8px">Via TT Policy (safe)</h2>
        <div id="good" style="background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px"></div>
        <p id="good-out" style="font-size:11px;color:var(--ok);margin-top:6px"></p>
      </div>
    </div>
    <script>
      // Attempt 1: direct innerHTML — should throw under TT
      try {
        document.getElementById('bad').innerHTML = '<img src=x onerror=alert(1)>';
        document.getElementById('bad-out').textContent = 'No TT enforced — executed!';
      } catch(e) {
        document.getElementById('bad-out').textContent = 'Blocked: ' + e.message.slice(0, 100);
      }

      // Attempt 2: via a Trusted Types policy that sanitises
      if (window.trustedTypes && trustedTypes.createPolicy) {
        const policy = trustedTypes.createPolicy('sanitize', {
          createHTML: (s) => {
            // Minimal sanitizer: strip event handlers and script tags
            return s.replace(/<script[\s\S]*?<\/script>/gi, '')
                    .replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '')
                    .replace(/\s+on\w+\s*=[^\s>]*/gi, '');
          }
        });
        document.getElementById('good').innerHTML =
          policy.createHTML('<b>Bold text</b> <img src=x onerror=alert(1)> <em>italic</em>');
        document.getElementById('good-out').textContent = 'Policy applied — event handler stripped';
      } else {
        document.getElementById('good-out').textContent = 'Trusted Types not supported in this browser';
      }
    </script>"""))
    resp.headers['Content-Security-Policy'] = "require-trusted-types-for 'script'"
    return resp

# ── Sanitizer Compare ─────────────────────────────────────────────────────────

@app.route('/sanitizer-demo')
def sanitizer_demo():
    q = request.args.get('q', '<img src=x onerror=alert(1)><b>bold</b><script>alert(2)</script>')
    import html as h
    body = f"""
    <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">Sanitizer Comparison</h1>
    <p style="font-size:12px;color:var(--muted);margin-bottom:4px">Input: <code>{h.escape(q)}</code></p>
    <p style="font-size:12px;color:var(--muted);margin-bottom:20px">
      Try: <a href="/sanitizer-demo?q=%3Cmath%3E%3Cmtext%3E%3Ctable%3E%3Cmglyph%3E%3Cstyle%3E%3C/style%3E%3C/mglyph%3E%3C/table%3E%3C/mtext%3E%3C/math%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
         style="color:var(--accent)">mXSS payload (MathML foster parent)</a>
    </p>
    <div id="results" style="display:grid;grid-template-columns:1fr 1fr;gap:14px"></div>
    <script>
      const q = {repr(q)};
      const cases = [
        {{
          label: 'No sanitizer (innerHTML)',
          color: 'var(--danger)',
          fn: (s) => s
        }},
        {{
          label: 'Naive blocklist (strip <script>)',
          color: 'var(--warn)',
          fn: (s) => s.replace(/<script[\\s\\S]*?<\\/script>/gi, '')
        }},
        {{
          label: 'DOMPurify (use via CDN in real use)',
          color: 'var(--ok)',
          fn: (s) => typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(s) : 'DOMPurify not loaded'
        }},
        {{
          label: 'textContent (not innerHTML)',
          color: 'var(--ok)',
          fn: null  // special case
        }}
      ];

      const container = document.getElementById('results');
      cases.forEach(c => {{
        const div = document.createElement('div');
        div.style.cssText = 'background:var(--panel);border:1px solid ' + c.color + ';border-radius:8px;padding:16px';
        const h2 = document.createElement('h2');
        h2.style.cssText = 'font-size:12px;font-weight:700;color:' + c.color + ';margin-bottom:10px';
        h2.textContent = c.label;
        const out = document.createElement('div');
        out.style.cssText = 'background:#060d1a;padding:10px;border-radius:4px;min-height:30px;font-size:12px';
        if (c.fn === null) {{
          out.textContent = q;  // textContent — always safe
        }} else {{
          out.innerHTML = c.fn(q);
        }}
        div.appendChild(h2);
        div.appendChild(out);
        container.appendChild(div);
      }});
    </script>"""
    return PAGE.format(title='Sanitizer Compare', body=body)

# ── Encoding Context Demo ─────────────────────────────────────────────────────

@app.route('/encoding-demo')
def encoding_demo():
    import html as h, json
    q = request.args.get('q', '<script>alert(1)</script>')
    body = f"""
    <h1 style="color:var(--accent);font-size:18px;margin-bottom:16px">Output Encoding Contexts</h1>
    <p style="font-size:12px;color:var(--muted);margin-bottom:20px">Input: <code>{h.escape(q)}</code></p>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <tr style="color:var(--muted)">
        <th style="text-align:left;padding:8px;border-bottom:1px solid var(--border)">Context</th>
        <th style="text-align:left;padding:8px;border-bottom:1px solid var(--border)">Encoded output</th>
        <th style="text-align:left;padding:8px;border-bottom:1px solid var(--border)">Method</th>
      </tr>
      <tr>
        <td style="padding:8px;border-bottom:1px solid var(--border)">HTML body</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--orange)">{h.escape(q)}</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);color:var(--ok)">html.escape()</td>
      </tr>
      <tr>
        <td style="padding:8px;border-bottom:1px solid var(--border)">HTML attribute</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--orange)">{h.escape(q, quote=True)}</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);color:var(--ok)">html.escape(q, quote=True)</td>
      </tr>
      <tr>
        <td style="padding:8px;border-bottom:1px solid var(--border)">JavaScript string</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);font-family:monospace;color:var(--orange)">{json.dumps(q)}</td>
        <td style="padding:8px;border-bottom:1px solid var(--border);color:var(--ok)">json.dumps(q) — produces quoted JS string</td>
      </tr>
      <tr>
        <td style="padding:8px">URL parameter</td>
        <td style="padding:8px;font-family:monospace;color:var(--orange)">{__import__('urllib.parse', fromlist=['quote']).quote(q)}</td>
        <td style="padding:8px;color:var(--ok)">urllib.parse.quote(q)</td>
      </tr>
    </table>"""
    return PAGE.format(title='Encoding Contexts', body=body)

if __name__ == '__main__':
    print('Defense lab — http://localhost:5000')
    print('Endpoints: /, /csp-demo, /csp-demo-nonce, /tt-demo, /sanitizer-demo, /encoding-demo')
    app.run(port=5000, debug=False)
