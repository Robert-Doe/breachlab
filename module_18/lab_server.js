/**
 * Module 18 — Threat Model Lab (Node.js)
 */
const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const COVERAGE = {
  'Output Encoding': { 'Reflected XSS':'CLOSED','Stored XSS':'CLOSED','DOM XSS':'OPEN','mXSS':'PARTIAL','Prototype Pollution':'OPEN','URI Schemes':'CLOSED','Filter Evasion':'CLOSED','Supply Chain':'OPEN' },
  'CSP (nonce)':     { 'Reflected XSS':'CLOSED','Stored XSS':'CLOSED','DOM XSS':'PARTIAL','mXSS':'PARTIAL','Prototype Pollution':'PARTIAL','URI Schemes':'PARTIAL','Filter Evasion':'CLOSED','Supply Chain':'PARTIAL' },
  'Trusted Types':   { 'Reflected XSS':'CLOSED','Stored XSS':'CLOSED','DOM XSS':'CLOSED','mXSS':'PARTIAL','Prototype Pollution':'PARTIAL','URI Schemes':'PARTIAL','Filter Evasion':'CLOSED','Supply Chain':'OPEN' },
  'DOMPurify':       { 'Reflected XSS':'CLOSED','Stored XSS':'CLOSED','DOM XSS':'OPEN','mXSS':'PARTIAL','Prototype Pollution':'OPEN','URI Schemes':'PARTIAL','Filter Evasion':'CLOSED','Supply Chain':'OPEN' },
  'HttpOnly Cookie': { 'Reflected XSS':'PARTIAL','Stored XSS':'PARTIAL','DOM XSS':'PARTIAL','mXSS':'PARTIAL','Prototype Pollution':'PARTIAL','URI Schemes':'PARTIAL','Filter Evasion':'PARTIAL','Supply Chain':'PARTIAL' },
  'SRI':             { 'Reflected XSS':'OPEN','Stored XSS':'OPEN','DOM XSS':'OPEN','mXSS':'OPEN','Prototype Pollution':'OPEN','URI Schemes':'OPEN','Filter Evasion':'OPEN','Supply Chain':'CLOSED' },
};

app.get('/api/coverage', (req, res) => res.json(COVERAGE));

app.post('/api/coverage', (req, res) => {
  const { defense, attack, value } = req.body;
  if (COVERAGE[defense] && COVERAGE[defense][attack] && ['OPEN','PARTIAL','CLOSED'].includes(value)) {
    COVERAGE[defense][attack] = value;
    return res.json({ ok: true });
  }
  res.status(400).json({ error: 'invalid' });
});

app.get('/api/gaps', (req, res) => {
  const gaps = [];
  for (const [defense, attacks] of Object.entries(COVERAGE)) {
    for (const [attack, status] of Object.entries(attacks)) {
      if (status !== 'CLOSED') gaps.push({ defense, attack, status });
    }
  }
  res.json(gaps);
});

app.listen(5000, () => {
  console.log('Threat model lab — http://localhost:5000');
  console.log('API: GET /api/coverage, GET /api/gaps, POST /api/coverage');
});
