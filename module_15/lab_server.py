"""
Module 15 — Attack Chaining Lab Server
Provides a realistic authenticated app with session management, CSRF tokens,
and endpoints that demonstrate XSS → CSRF → account takeover chains.
Run: python lab_server.py  (port 5000)
OOB receiver runs on port 5001 to capture exfiltrated data.
"""
import os, json, secrets, threading
from flask import Flask, request, session, redirect, render_template_string, jsonify, make_response
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
app.secret_key = 'xss-lab-insecure-key'

# In-memory user store
USERS = {
    'alice': {'password': 'password123', 'email': 'alice@example.com', 'bio': '', 'role': 'user'},
    'admin': {'password': 'admin123', 'email': 'admin@example.com', 'bio': '', 'role': 'admin'},
}

def get_csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']

def check_csrf(form_token):
    return form_token == session.get('csrf', '')

PAGE = """<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>ChainBank — {title}</title>
<style>
:root{{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--warn:#f5c842;--danger:#f87171}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:0}}
nav{{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:16px}}
nav a{{color:var(--accent);text-decoration:none;font-size:13px}}
.brand{{font-weight:800;color:var(--accent);font-size:16px;margin-right:auto}}
main{{padding:36px 32px;max-width:700px}}
h1{{font-size:20px;margin-bottom:20px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:24px;margin-bottom:20px}}
input,textarea{{width:100%;padding:9px 12px;background:#060d1a;border:1px solid var(--border);border-radius:5px;color:var(--text);font-size:14px;margin-bottom:12px}}
button,input[type=submit]{{padding:9px 20px;background:var(--accent);color:#0b0f1a;font-weight:700;border:none;border-radius:5px;cursor:pointer;font-size:14px}}
.flash{{padding:10px 16px;border-radius:5px;margin-bottom:16px;font-size:13px}}
.flash.ok{{background:#013020;border:1px solid var(--ok);color:var(--ok)}}
.flash.err{{background:#2a0000;border:1px solid var(--danger);color:var(--danger)}}
label{{font-size:13px;color:var(--muted);display:block;margin-bottom:4px}}
.field{{margin-bottom:14px}}
</style></head>
<body>
<nav>
  <span class="brand">ChainBank</span>
  {nav}
</nav>
<main>{body}</main>
</body></html>"""

def nav_auth(user):
    return f'<a href="/auth/profile">Profile</a><a href="/auth/settings">Settings</a><a href="/auth/logout">Logout ({user})</a>'

def nav_anon():
    return '<a href="/auth/login">Login</a>'

@app.route('/')
def index():
    user = session.get('user')
    if user:
        body = f'<h1>Welcome, {user}</h1><p style="color:var(--muted);font-size:14px">Logged in as <strong>{user}</strong> ({USERS[user]["role"]}). Use the nav to access your profile and settings.</p>'
        return PAGE.format(title='Home', nav=nav_auth(user), body=body)
    return redirect('/auth/login')

# ── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/auth/login', methods=['GET','POST'])
def login():
    flash = ''
    if request.method == 'POST':
        u = request.form.get('username','')
        p = request.form.get('password','')
        if u in USERS and USERS[u]['password'] == p:
            session['user'] = u
            session.pop('csrf', None)
            return redirect('/')
        flash = '<div class="flash err">Invalid credentials.</div>'
    csrf = get_csrf()
    form = f"""
    {flash}
    <div class="card">
      <h1 style="margin-bottom:16px">Sign In</h1>
      <form method=POST>
        <input type=hidden name=csrf value="{csrf}">
        <div class="field"><label>Username</label><input name=username placeholder="alice or admin"></div>
        <div class="field"><label>Password</label><input type=password name=password placeholder="password123"></div>
        <button type=submit>Login</button>
      </form>
    </div>"""
    return PAGE.format(title='Login', nav=nav_anon(), body=form)

@app.route('/auth/logout')
def logout():
    session.clear()
    return redirect('/auth/login')

@app.route('/auth/profile', methods=['GET','POST'])
def profile():
    user = session.get('user')
    if not user: return redirect('/auth/login')
    flash = ''
    if request.method == 'POST':
        if not check_csrf(request.form.get('csrf','')):
            flash = '<div class="flash err">CSRF check failed.</div>'
        else:
            bio = request.form.get('bio','')
            USERS[user]['bio'] = bio  # stored WITHOUT encoding — stored XSS sink
            flash = '<div class="flash ok">Profile updated.</div>'
    csrf = get_csrf()
    bio = USERS[user]['bio']
    # bio rendered WITHOUT escaping — demonstrates stored XSS
    form = f"""
    {flash}
    <div class="card">
      <h1>Your Profile</h1>
      <p style="font-size:13px;color:var(--muted);margin-bottom:16px">Bio (displayed to all visitors):</p>
      <div style="background:#060d1a;border:1px solid var(--border);padding:14px;border-radius:5px;margin-bottom:16px;min-height:40px">
        {bio}
      </div>
      <form method=POST>
        <input type=hidden name=csrf value="{csrf}">
        <div class="field"><label>Update Bio</label><textarea name=bio rows=4>{bio}</textarea></div>
        <button type=submit>Save</button>
      </form>
    </div>"""
    return PAGE.format(title='Profile', nav=nav_auth(user), body=form)

@app.route('/auth/settings', methods=['GET','POST'])
def settings():
    user = session.get('user')
    if not user: return redirect('/auth/login')
    flash = ''
    if request.method == 'POST':
        if not check_csrf(request.form.get('csrf','')):
            flash = '<div class="flash err">CSRF check failed.</div>'
        else:
            # change email (no current-password re-auth — intentionally vulnerable)
            email = request.form.get('email','')
            if email:
                USERS[user]['email'] = email
                flash = '<div class="flash ok">Email updated.</div>'
    csrf = get_csrf()
    form = f"""
    {flash}
    <div class="card">
      <h1>Account Settings</h1>
      <form method=POST>
        <input type=hidden name=csrf value="{csrf}">
        <div class="field"><label>Email</label><input name=email value="{USERS[user]['email']}"></div>
        <button type=submit>Update</button>
      </form>
    </div>"""
    return PAGE.format(title='Settings', nav=nav_auth(user), body=form)

@app.route('/auth/change-password', methods=['POST'])
def change_password():
    user = session.get('user')
    if not user: return jsonify(error='not authenticated'), 401
    if not check_csrf(request.form.get('csrf','')):
        return jsonify(error='csrf'), 403
    new_pw = request.form.get('new_password','')
    if len(new_pw) < 4:
        return jsonify(error='too short'), 400
    USERS[user]['password'] = new_pw
    return jsonify(ok=True, message=f'Password changed for {user}')

@app.route('/auth/users')
def list_users():
    """Admin-only endpoint showing all users — XSS here affects admin context"""
    user = session.get('user')
    if not user: return redirect('/auth/login')
    if USERS[user]['role'] != 'admin':
        return 'Forbidden', 403
    rows = ''
    for u, data in USERS.items():
        # bio rendered WITHOUT encoding — admin-context stored XSS
        rows += f'<tr><td>{u}</td><td>{data["email"]}</td><td style="max-width:300px">{data["bio"]}</td></tr>'
    body = f"""
    <h1>User Management</h1>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <tr style="color:var(--muted)"><th style="text-align:left;padding:8px">User</th><th style="text-align:left;padding:8px">Email</th><th style="text-align:left;padding:8px">Bio</th></tr>
      {rows}
    </table>"""
    return PAGE.format(title='Admin Users', nav=nav_auth(user), body=body)

# ── OOB receiver (port 5001) ─────────────────────────────────────────────────

class OOBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        print(f'\n[OOB RECEIVED] {self.path}')
        for k, v in params.items():
            print(f'  {k}: {v[0][:200]}')
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'ok')
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        print(f'\n[OOB POST] {self.path}')
        try: print(f'  {json.dumps(json.loads(body), indent=2)[:400]}')
        except: print(f'  {body[:400]}')
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *_): pass

def start_oob():
    HTTPServer(('0.0.0.0', 5001), OOBHandler).serve_forever()

if __name__ == '__main__':
    print('ChainBank lab server — http://localhost:5000')
    print('OOB receiver       — http://localhost:5001')
    print('Users: alice/password123, admin/admin123')
    threading.Thread(target=start_oob, daemon=True).start()
    app.run(port=5000, debug=False)
