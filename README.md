# breachlab

## Safety and scope, read this first

This is an authorized, localhost-only security research lab. Every server in this repository binds to `localhost:5000`, and every payload, demo page, and exercise here targets that local instance and nothing else. There is no remote target, no scanning infrastructure, and nothing in this repo is meant to touch a system its operator doesn't own.

Do not point any technique in here at a system you don't own or don't have explicit written authorization to test. Do not deploy the vulnerable lab servers outside of localhost. They're deliberately unsafe by design, no auth, `debug=True`, unsanitized sinks, because that's what makes them useful for study, and that same thing makes them dangerous anywhere else.

I built this to train defenders. Understanding an attack precisely, right down to the parser quirk or event handler that makes it fire, is what actually lets you build a defense that closes it, instead of one that just looks like it does. If you're here as a student, run everything against your own local instance, in a browser profile you don't mind resetting, and treat every payload here as something to understand, not something to ship.

## What this is

`breachlab` is the finished, mature build-out of a PhD-level XSS curriculum I put together. It's deliberately attack-first. Every module opens by making a real script execute in a real browser through a specific mechanism, then spends its second half on why that mechanism exists at all and what actually closes it. I organized the whole thing around a five-mechanism taxonomy that I'd argue covers every documented XSS technique out there:

1. Tag parsing: raw markup reaching the HTML parser as new elements
2. Event handler attributes: `onerror`, `onload`, `onfocus` plus `autofocus`, and the long tail of 150-plus attributes that can fire code
3. URI scheme evaluation: `javascript:`, `data:`, and the quirks in how browsers actually parse a URL
4. DOM sink assignment: `innerHTML`, `document.write`, and other sinks that server-side encoding never even sees
5. Context escape and re-parse: attribute and namespace breakouts, and mutation XSS, where a second parse produces a different, dangerous tree from the first

Later modules build outward from that spine into filter evasion, prototype pollution, real-world incident reconstruction, and only once the attack surface is fully mapped, the defense layer model: encoding, CSP, Trusted Types, sanitizers, SRI, and how to actually find the gaps a novel intervention should target.

## Module map

| # | Module | Focus |
|---|--------|-------|
| 01 | Environment Setup | Lab architecture, dual-runtime servers, thinking like an attacker |
| 02 | Browser Parsing | The HTML parser as a recovery engine; four injection contexts; parser quirks |
| 03 | Five Execution Mechanisms | The taxonomy spine: tag parsing, event handlers, URI schemes, DOM sinks, context escape |
| 04 | Script Tag Injection | Reflected XSS via `<script>`, the three script-execution contexts, the `innerHTML` exception |
| 05 | Event Handler Injection | `onerror`/`autofocus`+`onfocus`, zero-interaction events, why blocklists always fail |
| 06 | URI Scheme Injection | `javascript:` and `data:` URIs, URL-parser obfuscation |
| 07 | Tag & Namespace Confusion | SVG/MathML vectors, HTML integration points, `iframe srcdoc` |
| 08 | Attribute Injection | Attribute breakout anatomy, encoding-context mismatches, the `data-*`/DOM sink split |
| 09 | DOM-Based XSS | Sources, sinks, `postMessage` as a DOM XSS source, why server defenses can't see any of it |
| 10 | Stored XSS | Persistent storage model, second-order (blind) XSS, CSRF token theft through stored payloads |
| 11 | Blind XSS & Out-of-Band | Out-of-band callback mechanics, XSS Hunter and Burp Collaborator, the dwell-time advantage |
| 12 | Filter Evasion & Obfuscation | Blocklist bypass taxonomy, encoding bypasses, WAF bypass methodology |
| 13 | Mutation XSS (mXSS) | Two-parse divergence, foster parenting, namespace mutation, DOMPurify's own history with this |
| 14 | Prototype Pollution to DOM XSS | Prototype chain attacks, vulnerable `deepMerge` patterns, real vulnerable libraries |
| 15 | Attack Chaining | XSS to account takeover: cookie theft, localStorage exfiltration, credential overlays |
| 16 | Real-World Incidents | The Samy worm, the Twitter onMouseOver worm, the Magecart/British Airways supply-chain XSS |
| 17 | Defenses | Output encoding, CSP, Trusted Types, sanitizers, SRI, and a defense coverage matrix |
| 18 | Threat Model & Defense Gaps | Formal threat modeling, open research gaps, positioning a novel intervention |
| 19 | XSS Payload Bank | Over 100 annotated attack payloads, indexed against the five-mechanism taxonomy |

## Tech stack

Every module ships two interchangeable lab server implementations, kept in sync with each other on purpose: Python with Flask (`lab_server.py`) and Node.js with Express (`lab_server.js`). Both listen on `localhost:5000` and serve the identical vulnerable and defended surface for that module. I did the dual implementation deliberately, XSS is a browser-side vulnerability, so the same attack surface exists no matter which backend language is running it, while the defensive code itself (output encoding, header setting, templating) differs in meaningful ways between the two runtimes. Later modules add SQLite for the stored and second-order XSS demos. Each module also has a `tutorial.html` walkthrough, a `DECISIONS.md` on the design trade-offs, and hands-on exercises.

## Running a module

```bash
cd module_XX

# Python / Flask
pip install -r requirements.txt
python lab_server.py

# or, Node.js / Express
npm install
npm start
```

Then open `http://localhost:5000`. Every module is self-contained. There's no server process shared across modules.

## Where this stands

All 19 modules are built out: tutorials, dual-runtime lab servers, exercises, and design-decision notes. This is the finished course. There's an earlier scratch prototype of the same curriculum living in the sibling project `sparkbench`, which I stopped after Module 01. This repository is its completed successor.
