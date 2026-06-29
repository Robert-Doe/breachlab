"""
Module 16 — Real-World Incidents Lab Server
Serves the case study files and provides a minimal simulation endpoint
for the worm propagation demo.
Run: python lab_server.py  (port 5000)
"""
import os, secrets
from flask import Flask, request, session, redirect, render_template_string, send_from_directory

app = Flask(__name__, static_folder='case_studies', static_url_path='/cases')

PROFILES = {}  # username -> bio/message (for worm demo)

PAGE = """<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<title>SocialDemo — {title}</title>
<style>
:root{{--bg:#0b0f1a;--panel:#141c2e;--border:#1e3a5f;--text:#e2e8f0;--muted:#7a9bbf;--accent:#38bdf8;--ok:#4ade80;--danger:#f87171}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:0}}
nav{{background:var(--panel);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;gap:16px;align-items:center}}
.brand{{font-weight:800;color:var(--accent);margin-right:auto}}
nav a{{color:var(--accent);text-decoration:none;font-size:13px}}
main{{padding:32px;max-width:700px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
input,textarea{{width:100%;padding:9px;background:#060d1a;border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:13px;margin-bottom:10px}}
button{{padding:8px 18px;background:var(--accent);color:#0b0f1a;font-weight:700;border:none;border-radius:4px;cursor:pointer}}
</style></head><body>
<nav><span class="brand">SocialDemo</span><a href="/">Home</a><a href="/profiles">Profiles</a><a href="/cases/samy_worm.html">Case Studies</a></nav>
<main>{body}</main></body></html>"""

@app.route('/')
def index():
    user = session.get('user', 'guest')
    return PAGE.format(title='Home', body=f"""
    <div class="card"><h2 style="margin-bottom:12px;color:var(--accent)">Worm Propagation Demo</h2>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px">
      Set your profile message. If a message contains XSS, it fires for every visitor — and the worm variant replicates itself into their profile.
    </p>
    <p style="font-size:12px;color:var(--muted)">Current user: <strong>{user}</strong></p>
    <a href="/login" style="color:var(--accent);font-size:13px">Switch user</a> &nbsp;|&nbsp;
    <a href="/profiles" style="color:var(--accent);font-size:13px">View all profiles</a>
    </div>""")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        session['user'] = request.form.get('username','guest')[:20]
        return redirect('/')
    return PAGE.format(title='Login', body="""
    <div class="card"><h2 style="margin-bottom:12px">Set Username</h2>
    <form method=POST><input name=username placeholder="alice, bob, etc."><button>Enter</button></form></div>""")

@app.route('/profile/view/<username>')
def view_profile(username):
    bio = PROFILES.get(username, '<em style="color:var(--muted)">No message set.</em>')
    # bio rendered WITHOUT encoding — the worm replication sink
    return PAGE.format(title=f'{username} profile', body=f"""
    <div class="card">
      <h2 style="margin-bottom:8px;color:var(--accent)">{username}'s Profile</h2>
      <div style="min-height:40px">{bio}</div>
    </div>
    <a href="/profiles" style="font-size:12px;color:var(--muted)">← All profiles</a>""")

@app.route('/profile/edit', methods=['GET','POST'])
def edit_profile():
    user = session.get('user','guest')
    if request.method == 'POST':
        PROFILES[user] = request.form.get('bio','')
        return redirect(f'/profile/view/{user}')
    csrf = secrets.token_hex(8)
    session['csrf'] = csrf
    return PAGE.format(title='Edit profile', body=f"""
    <div class="card"><h2 style="margin-bottom:12px">Edit Your Profile</h2>
    <form method=POST>
      <input type=hidden name=csrf value="{csrf}">
      <textarea name=bio rows=4 placeholder="Enter your message...">{PROFILES.get(user,'')}</textarea>
      <button type=submit>Save</button>
    </form></div>""")

@app.route('/profile/update', methods=['POST'])
def update_profile():
    """API endpoint used by worm payloads to replicate."""
    user = session.get('user','guest')
    PROFILES[user] = request.form.get('bio','')
    return ('', 204)

@app.route('/profiles')
def all_profiles():
    rows = ''.join(f'<li style="margin-bottom:8px"><a href="/profile/view/{u}" style="color:var(--accent)">{u}</a></li>'
                   for u in PROFILES) or '<li style="color:var(--muted);font-size:13px">No profiles yet.</li>'
    viewer = session.get('user','guest')
    # Render each bio summary — XSS fires here when listing
    return PAGE.format(title='Profiles', body=f"""
    <div class="card"><h2 style="margin-bottom:12px">All Profiles</h2><ul style="list-style:none">{rows}</ul></div>
    <a href="/profile/edit" style="font-size:13px;color:var(--accent)">Edit your profile ({viewer})</a>""")

if __name__ == '__main__':
    session_users = ['alice','bob','charlie','dave']
    for u in session_users:
        PROFILES.setdefault(u, f'Hi, I am {u}.')
    print('SocialDemo worm lab — http://localhost:5000')
    print('Pre-seeded profiles: alice, bob, charlie, dave')
    app.run(port=5000, debug=False)
