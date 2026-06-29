# DECISIONS.md — Module 01: Environment Setup & How to Think Like an Attacker

---

## Decision 1: Dual runtime (Flask + Node.js) from the start

**Decision:** Both a Python/Flask server and a Node.js/Express server are provided and kept in sync across every module.

**Why:** XSS is a browser-side vulnerability — the server language is irrelevant to the attack. But defenders must understand the server context because output encoding, header setting, and templating differ between runtimes. Providing both teaches that the attack surface is identical regardless of backend, while the defensive code differs. Many real-world targets are Node.js; many security tools and CTF platforms are Python.

**Trade-off:** A production course would pick one runtime and go deep. We maintain both because the PhD goal is to understand the full landscape — seeing the same vulnerability implemented in two different ways reinforces that XSS is a browser problem, not a language problem.

---

## Decision 2: debug=True in Flask / no authentication

**Decision:** The Flask server runs with `debug=True` and no authentication on any route.

**Why:** `debug=True` gives auto-reload and the Werkzeug interactive debugger. For a local lab this is acceptable and speeds up iteration. No authentication keeps the lab simple — we are studying injection, not access control.

**Trade-off:** In production, `debug=True` exposes an interactive Python shell to anyone who can trigger an error — it is a remote code execution vulnerability in itself. A real deployment uses `debug=False`, a proper WSGI server (Gunicorn, uWSGI), and authentication. We will address authentication surfaces in Module 15 when we study CSRF chaining.

---

## Decision 3: Static files served directly from /public

**Decision:** The lab home page and later attack demo pages live in a `public/` directory served as static files.

**Why:** Separates static content (demos, tutorials) from dynamic routes (vulnerable endpoints). This mirrors how real web apps are structured — a static asset server (CDN, nginx) in front of a dynamic application server. Understanding this split matters for XSS because static files can sometimes be injected via filename or metadata even when the dynamic routes are protected.

**Trade-off:** A production setup would serve static files via a CDN with strict Content-Type headers and Content-Security-Policy. Serving HTML from the same origin as the API means a stored XSS in any route has access to API cookies. We exploit this in Module 10 (Stored XSS) and defend it in Module 17 (CSP).

---

## Decision 4: Single flat port (5000) with no TLS

**Decision:** Both servers listen on `localhost:5000` over plain HTTP, not HTTPS.

**Why:** TLS adds certificate management complexity that is irrelevant to learning XSS injection mechanics. All XSS concepts studied here apply equally to HTTPS targets — the transport layer does not protect against injection in page content.

**Trade-off:** In practice, modern browsers enforce increasingly strict rules on insecure origins — some APIs (Service Workers, WebRTC, Clipboard) require HTTPS. Module 16 (real-world incidents) will note where HTTPS was present and still did not prevent the attack. Module 17 discusses the `Secure` cookie flag, which requires HTTPS.

---

## Decision 5: No database in Module 01

**Decision:** Module 01 has no persistent storage — it only serves static files.

**Why:** Adding a database before establishing the attack surface creates cognitive overhead without payoff. The student needs to first understand what an injection point looks like before seeing how persistence amplifies it.

**Trade-off:** Real XSS targets almost always involve persistent storage. Module 10 introduces SQLite to simulate a comment system where stored XSS payloads persist across requests — the simplest possible model that still demonstrates second-order attacks. Module 15 (chaining) will add session storage.
