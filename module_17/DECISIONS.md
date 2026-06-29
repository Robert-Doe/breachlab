# Module 17 — Design Decisions

## Why side-by-side vulnerable vs. defended rendering?
The fastest way to internalise a defense is to see the same input produce different outcomes. Side-by-side rendering in the same page makes the before/after immediately visible without switching tabs or endpoints.

## Why a CSP report-uri endpoint in the lab server?
CSP violations are invisible without a report-uri. Teaching students to set up report-uri and observe violations in real time is as important as understanding what the policy syntax means. The lab prints violations to the terminal.

## Why not load DOMPurify from CDN in the sanitizer demo?
Irony: loading a security library from a CDN without SRI is itself a supply chain XSS risk. The demo uses a locally bundled copy (students run `npm install` or download it). If DOMPurify isn't loaded, the demo notes it — making the dependency explicit.

## Why include the mXSS payload link in the sanitizer demo?
The MathML foster-parent mXSS bypass (CVE-2019-20374) shows that even good sanitizers have had bypass vulnerabilities. Students should test the payload against DOMPurify to see: (a) old versions are vulnerable, (b) current version is fixed, (c) the fix requires keeping the library updated — SRI-pinning to a specific version helps.

## Why include the Trusted Types demo if only Chrome supports it?
Trusted Types shipped in Chrome 83+ and Edge 83+. At ~70% desktop browser share, Chrome-first deployment is viable. The demo gracefully degrades — the code checks for `window.trustedTypes` before using the API. The goal is to teach the concept and show the enforcement model, not to require specific browsers.
