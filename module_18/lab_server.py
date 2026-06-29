"""
Module 18 — Threat Model Lab Server
Serves the interactive threat model and gap analysis tools.
Provides an API endpoint for the interactive gap table.
Run: python lab_server.py  (port 5000)
"""
import json
from flask import Flask, request, jsonify

app = Flask(__name__, static_folder='public', static_url_path='/public')

# Defense × Attack coverage data — used by the gap analysis tool
# Values: "CLOSED", "PARTIAL", "OPEN"
COVERAGE = {
    "Output Encoding": {
        "Reflected XSS": "CLOSED", "Stored XSS": "CLOSED",
        "DOM XSS": "OPEN", "mXSS": "PARTIAL",
        "Prototype Pollution": "OPEN", "URI Schemes": "CLOSED",
        "Filter Evasion": "CLOSED", "Supply Chain": "OPEN",
    },
    "CSP (nonce)": {
        "Reflected XSS": "CLOSED", "Stored XSS": "CLOSED",
        "DOM XSS": "PARTIAL", "mXSS": "PARTIAL",
        "Prototype Pollution": "PARTIAL", "URI Schemes": "PARTIAL",
        "Filter Evasion": "CLOSED", "Supply Chain": "PARTIAL",
    },
    "Trusted Types": {
        "Reflected XSS": "CLOSED", "Stored XSS": "CLOSED",
        "DOM XSS": "CLOSED", "mXSS": "PARTIAL",
        "Prototype Pollution": "PARTIAL", "URI Schemes": "PARTIAL",
        "Filter Evasion": "CLOSED", "Supply Chain": "OPEN",
    },
    "DOMPurify": {
        "Reflected XSS": "CLOSED", "Stored XSS": "CLOSED",
        "DOM XSS": "OPEN", "mXSS": "PARTIAL",
        "Prototype Pollution": "OPEN", "URI Schemes": "PARTIAL",
        "Filter Evasion": "CLOSED", "Supply Chain": "OPEN",
    },
    "HttpOnly Cookie": {
        "Reflected XSS": "PARTIAL", "Stored XSS": "PARTIAL",
        "DOM XSS": "PARTIAL", "mXSS": "PARTIAL",
        "Prototype Pollution": "PARTIAL", "URI Schemes": "PARTIAL",
        "Filter Evasion": "PARTIAL", "Supply Chain": "PARTIAL",
    },
    "SRI": {
        "Reflected XSS": "OPEN", "Stored XSS": "OPEN",
        "DOM XSS": "OPEN", "mXSS": "OPEN",
        "Prototype Pollution": "OPEN", "URI Schemes": "OPEN",
        "Filter Evasion": "OPEN", "Supply Chain": "CLOSED",
    },
}

@app.route('/')
def index():
    return app.send_static_file('threat_model.html')

@app.route('/api/coverage')
def coverage():
    return jsonify(COVERAGE)

@app.route('/api/coverage', methods=['POST'])
def update_coverage():
    """Allow the interactive tool to submit custom coverage assessments."""
    data = request.get_json(silent=True) or {}
    defense = data.get('defense')
    attack = data.get('attack')
    value = data.get('value')
    if defense in COVERAGE and attack in COVERAGE[defense] and value in ('OPEN','PARTIAL','CLOSED'):
        COVERAGE[defense][attack] = value
        return jsonify(ok=True)
    return jsonify(error='invalid'), 400

@app.route('/api/gaps')
def gaps():
    """Return all OPEN and PARTIAL cells as research gaps."""
    gaps_list = []
    for defense, attacks in COVERAGE.items():
        for attack, status in attacks.items():
            if status in ('OPEN', 'PARTIAL'):
                gaps_list.append({'defense': defense, 'attack': attack, 'status': status})
    return jsonify(gaps_list)

if __name__ == '__main__':
    print('Threat model lab — http://localhost:5000')
    print('API: GET /api/coverage, GET /api/gaps, POST /api/coverage')
    app.run(port=5000, debug=False)
