# breachlab

**XSS Attack & Defense Lab — a 19-module, hands-on course in Cross-Site Scripting, built attack-first so the defenses actually mean something.**

## Safety & scope

This is an **authorized, localhost-only security research lab**. Every server in this repository binds to `localhost:5000` and every payload, demo page, and exercise here targets that local instance and nothing else. There is no remote target, no scanning infrastructure, and no code here is intended to touch a system its operator does not own.

- **Do not point any technique in this repository at a system you do not own or do not have explicit written authorization to test.**
- **Do not deploy the vulnerable lab servers outside of localhost.** They are deliberately unsafe (no auth, `debug=True`, unsanitized sinks) by design, for study.
- This material exists to train defenders. Understanding an attack precisely — down to the parser quirk or event handler that makes it fire — is the prerequisite for building a defense that actually closes it, rather than one that merely looks like it does.

If you are here as a student: run everything against your own local instance, in a browser profile you don't mind resetting, and treat every payload as something to understand, not to ship.

## What this is

`breachlab` is the mature, complete build-out of a PhD-level XSS curriculum. It is deliberately **attack-first**: every module opens by making a real script execute in a real browser via a specific mechanism, then spends the second half of the module studying why that mechanism exists and what actually closes it. The course is organized around a five-mechanism taxonomy that the author argues covers every documented XSS technique:

1. **Tag parsing** — raw markup reaching the HTML parser as new elements
2. **Event handler attributes** — `onerror`, `onload`, `onfocus`+`autofocus`, and the 150+-attribute long tail
3. **URI scheme evaluation** — `javascript:`, `data:`, and browser URL-parser quirks
4. **DOM sink assignment** — `innerHTML`, `document.write`, and other sinks that server-side encoding never sees
5. **Context escape & re-parse** — attribute/namespace breakouts and mutation XSS, where a second parse produces a different (and dangerous) tree from the first

Later modules build outward from that spine into filter evasion, prototype pollution, real-world incident reconstruction, and — only once the attack surface is fully mapped — the defense layer model (encoding, CSP, Trusted Types, sanitizers, SRI) and how to find the gaps a novel intervention should target.

## Module map

| # | Module | Focus |
|---|--------|-------|
| 01 | Environment Setup | Lab architecture, dual-runtime servers, thinking like an attacker |
| 02 | Browser Parsing | The HTML parser as a recovery engine; four injection contexts; parser quirks |
| 03 | Five Execution Mechanisms | The taxonomy spine — tag parsing, event handlers, URI schemes, DOM sinks, context escape |
| 04 | Script Tag Injection | Reflected XSS via `<script>`, the three script-execution contexts, the `innerHTML` exception |
| 05 | Event Handler Injection | `onerror`/`autofocus`+`onfocus`, zero-interaction events, why blocklists always fail |
| 06 | URI Scheme Injection | `javascript:` and `data:` URIs, URL-parser obfuscation |
| 07 | Tag & Namespace Confusion | SVG/MathML vectors, HTML integration points, `iframe srcdoc` |
| 08 | Attribute Injection | Attribute breakout anatomy, encoding-context mismatches, `data-*`/DOM sink split |
| 09 | DOM-Based XSS | Sources, sinks, `postMessage` as a DOM XSS source, why server defenses can't see it |
| 10 | Stored XSS | Persistent storage model, second-order (blind) XSS, CSRF token theft via stored payloads |
| 11 | Blind XSS & Out-of-Band | OOB callback mechanics, XSS Hunter / Burp Collaborator, dwell-time advantage |
| 12 | Filter Evasion & Obfuscation | Blocklist bypass taxonomy, encoding bypasses, WAF bypass methodology |
| 13 | Mutation XSS (mXSS) | Two-parse divergence, foster parenting, namespace mutation, DOMPurify history |
| 14 | Prototype Pollution → DOM XSS | Prototype chain attacks, vulnerable `deepMerge` patterns, real vulnerable libraries |
| 15 | Attack Chaining | XSS → account takeover: cookie theft, localStorage exfiltration, credential overlays |
| 16 | Real-World Incidents | Samy worm, Twitter onMouseOver worm, Magecart/British Airways supply-chain XSS |
| 17 | Defenses | Output encoding, CSP, Trusted Types, sanitizers, SRI, and a defense coverage matrix |
| 18 | Threat Model & Defense Gaps | Formal threat modeling, open research gaps, positioning a novel intervention |
| 19 | XSS Payload Bank | 100+ annotated attack payloads, indexed against the five-mechanism taxonomy |

## Tech stack

Every module ships **two interchangeable lab server implementations that are kept in sync**:

- **Python** — Flask (`lab_server.py`)
- **Node.js** — Express (`lab_server.js`)

Both listen on `localhost:5000` and serve the identical vulnerable/defended surface for that module. The dual implementation is intentional: XSS is a browser-side vulnerability, so the same attack surface exists regardless of backend language, while the defensive code (output encoding, header setting, templating) differs meaningfully between runtimes. Later modules add SQLite for stored/second-order XSS demos. Each module includes a `tutorial.html` walkthrough, a `DECISIONS.md` documenting design trade-offs, and hands-on exercises.

## Running a module

```bash
cd module_XX

# Python / Flask
pip install -r requirements.txt
python lab_server.py

# — or — Node.js / Express
npm install
npm start
```

Then open `http://localhost:5000`. Each module is self-contained; there is no shared server process across modules.

## Status

All 19 modules are built out: tutorials, dual-runtime lab servers, exercises, and design-decision notes. This is the completed course. A separate, earlier scratch/prototype of this same curriculum exists under the sibling project `sparkbench` and stopped after Module 01 — this repository is its finished successor.
