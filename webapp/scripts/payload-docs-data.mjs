/**
 * Curated, hand-authored category-level metadata for the payload bank —
 * blurb + rationale come from the real module_19/payload_bank.html and
 * DECISIONS.md content; threatModel and docs are new, written to explain
 * each class of attack to a defender. All doc URLs were fetched and
 * confirmed live during authoring.
 */
export const CATEGORY_META = {
  script_tags: {
    title: "01 — Script Tag Injection",
    blurb:
      "The baseline: <script> tags and all the ways they can be written, encoded, and broken across line boundaries to evade naive filters.",
    rationale:
      "Entry point; most filtered. Every WAF and sanitizer stops literal <script> first, so this category exists to teach the baseline before the mechanisms that actually get past real-world defenses.",
    threatModel:
      "Attacker: anyone who can get raw text reflected or stored into an HTML response — a search box, a comment field, a URL parameter echoed into the page. Gain: arbitrary JavaScript in the victim's session the instant the page parses. Blast radius: every visitor who loads the injected page (stored) or clicks a crafted link (reflected). This is the textbook case output encoding exists to stop — if this vector still works against a target, nothing downstream matters.",
    baseSeverity: "high",
    docs: [
      { title: "CWE-79 — Cross-Site Scripting", description: "The formal vulnerability classification this entire course teaches: improper neutralization of input during web page generation.", url: "https://cwe.mitre.org/data/definitions/79.html" },
      { title: "OWASP XSS Prevention Cheat Sheet", description: "The canonical defender's reference: context-aware output encoding, the fix for every payload in this category.", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
    ],
  },
  event_handlers: {
    title: "02 — Event Handler Injection",
    blurb:
      "The real workhorse. 150+ HTML event attributes — this page covers the most powerful, the most surprising, and the ones that bypass script-only filters.",
    rationale:
      "Different mechanism to script injection — a regex that strips <script> stops exactly one vector and lets 150+ event-handler attributes straight through, because none of them contain the word \"script\".",
    threatModel:
      "Attacker: same as script-tag injection, but now surviving the single most common first-line defense (a script-tag filter). Gain: identical to a <script> payload — full JS execution — reached via onerror, onload, onfocus, and dozens of rarer handlers. Blast radius: any target that filters by tag name or keyword instead of parsing the DOM and stripping by attribute. The 'zero-click' entries in this set (autofocus+onfocus, svg onload) are the highest-value real-world finds because they need no victim interaction at all.",
    baseSeverity: "high",
    docs: [
      { title: "HTML event handler content attributes (MDN)", description: "The full list of on* attributes browsers recognize — the actual attack surface this category enumerates.", url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Global_attributes#event_handler_attributes" },
      { title: "MDN — Cross-site scripting (XSS)", description: "MDN's own attack writeup, including the same DOM-sink and encoding guidance that stops event-handler payloads.", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS" },
    ],
  },
  uri_schemes: {
    title: "03 — URI Scheme Injection",
    blurb:
      "javascript: and data: in href, src, action, formaction, srcdoc. Open redirectors as XSS delivery. Encoding tricks for each.",
    rationale:
      "Sink-specific: href/src/action attributes accept a URI, and browsers treat javascript: and data: as first-class executable schemes wherever a URL is expected — a completely different trust boundary than tag or attribute injection.",
    threatModel:
      "Attacker: controls a URL that the app trusts and renders as a link, embed, or form target, without checking its scheme. Gain: script execution on click (javascript:) or on render (data: loaded into an iframe/object). Blast radius: link-preview features, redirect endpoints, and any 'open in new tab' functionality are classic real-world instances — this is how open redirectors get weaponized into XSS.",
    baseSeverity: "high",
    docs: [
      { title: "URL scheme reference (WHATWG URL Standard)", description: "The spec-level definition of URL schemes browsers recognize, including javascript: and data:.", url: "https://url.spec.whatwg.org/" },
      { title: "OWASP XSS Prevention Cheat Sheet — Rule #5: URL Contexts", description: "The specific rule for validating and encoding URLs before they reach href/src/action.", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
    ],
  },
  svg_mathml: {
    title: "04 — SVG, MathML & Namespace Confusion",
    blurb:
      "Why \"it's just an image\" is wrong. SVG has its own <script> and full event model. MathML namespace escapes. iframe srcdoc entity decoding.",
    rationale:
      "Namespace parsing is a distinct class from HTML tag/attribute injection — SVG and MathML are full XML namespaces with their own script and event capabilities, so an allowlist built for \"safe\" markup that includes SVG has usually allowlisted a second scripting language by accident.",
    threatModel:
      "Attacker: exploits an image/icon upload or inline-markup feature that allows SVG on the theory that SVG is 'just a picture.' Gain: full script execution, since SVG defines its own <script> element and the complete HTML event-attribute model. Blast radius: avatar uploads, inline diagram embeds, and any sanitizer allowlist that includes <svg> without stripping its script/event surface.",
    baseSeverity: "medium",
    docs: [
      { title: "SVG scripting (MDN)", description: "How <script> and event attributes work inside SVG — the namespace capability this category exploits.", url: "https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/script" },
      { title: "DOMPurify", description: "The sanitizer explicitly designed to handle HTML, MathML, and SVG together — the standard fix for this category.", url: "https://github.com/cure53/DOMPurify" },
    ],
  },
  dom_sinks: {
    title: "05 — DOM-Based XSS Sinks",
    blurb:
      "innerHTML, outerHTML, eval, document.write, location.href, location.hash, postMessage, srcdoc — each sink with a matching source and working payload.",
    rationale:
      "No server involvement — a source (URL fragment, postMessage, a JSON response) flows straight into a sink inside the browser. Server-side scanners that only see HTTP traffic miss this category entirely, because the vulnerable code path never touches the network.",
    threatModel:
      "Attacker: crafts a URL fragment, postMessage, or client-side API response that an existing script trusts and passes into innerHTML/eval/document.write without sanitization. Gain: script execution purely client-side, often bypassing server-side WAFs and input validation entirely since the payload may never appear in a request the server can inspect. Blast radius: single-page apps and any client-side router that reads location.hash or postMessage into the DOM.",
    baseSeverity: "high",
    docs: [
      { title: "MDN — Cross-site scripting (XSS): DOM-based sinks", description: "MDN's own list of unsafe sink APIs (innerHTML, insertAdjacentHTML, document.write, eval) and the safe alternatives.", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS" },
      { title: "Trusted Types API (MDN)", description: "The browser-enforced control built specifically to stop untrusted strings from reaching DOM XSS sinks.", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" },
    ],
  },
  filter_evasion: {
    title: "06 — Filter Evasion & Obfuscation",
    blurb:
      "URL encoding, HTML entities, Unicode, null bytes, case mixing, comment injection, string splitting — 15 techniques that make regex/string filters useless.",
    rationale:
      "Cross-cutting concern, not a mechanism of its own — every technique here can be layered onto any of the other categories. It exists to demonstrate why string/regex matching can never be a complete defense: the browser's own decoding pipeline runs after the filter's pattern match.",
    threatModel:
      "Attacker: already has a working payload from another category, but a keyword or pattern filter blocks the literal string. Gain: the same execution as the underlying payload, just re-encoded so the filter's pattern match fails while the browser's HTML/URL/JS parser still decodes it correctly. Blast radius: any defense implemented as string matching or regex instead of a real parser — this is why 'block the word onerror' is not a security control.",
    baseSeverity: "medium",
    docs: [
      { title: "OWASP XSS Prevention Cheat Sheet — why blocklists fail", description: "The canonical explanation of why encoding-aware, context-aware output encoding beats pattern-matching filters.", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
      { title: "PortSwigger XSS cheat sheet", description: "The primary public reference this course's payload bank draws its raw vector list from — hundreds of browser-tested filter-evasion variants, regularly updated.", url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" },
    ],
  },
  mxss: {
    title: "07 — Mutation XSS (mXSS)",
    blurb:
      "Payloads that appear safe to a sanitizer but mutate when round-tripped through innerHTML. Foster parenting, SVG style context, noscript, template.",
    rationale:
      "Requires sanitizer context to understand — the payload is genuinely inert when the sanitizer inspects it, and only becomes dangerous after the browser re-parses and re-serializes the DOM (e.g. a second innerHTML assignment). This is the hardest category to defend against because the sanitizer and the browser disagree about what the markup means.",
    threatModel:
      "Attacker: submits markup that passes a sanitizer's inspection because, at inspection time, it genuinely contains no dangerous nodes. Gain: after the sanitized output is written into the DOM (or copy-pasted through innerHTML again — the 'mutation' step), the browser's own parsing quirks reassemble a dangerous element the sanitizer never saw. Blast radius: any rich-text editor or comment renderer that sanitizes once but re-serializes/re-parses the DOM afterward (e.g. copy-paste handling, WYSIWYG editors).",
    baseSeverity: "high",
    docs: [
      { title: "DOMPurify", description: "The sanitizer library built specifically with mXSS defenses (it parses like a browser instead of using string matching).", url: "https://github.com/cure53/DOMPurify" },
      { title: "MDN — Cross-site scripting (XSS): sanitization", description: "Context on why sanitization must happen at the DOM level, not the string level, to avoid mutation gaps.", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS" },
    ],
  },
  chaining_payloads: {
    title: "08 — Chaining & Post-Exploitation",
    blurb:
      "XSS payloads that do real damage: CSRF token theft, password change, cookie exfil, localStorage dump, credential overlay, self-propagating worm skeleton.",
    rationale:
      "Demonstrates why XSS severity is P1 — defenders underestimate impact when they only ever see alert(1). This category shows the real chain: XSS to CSRF-token theft to account takeover, which is why every major bug bounty program treats XSS as a top-tier finding regardless of how it was delivered.",
    threatModel:
      "Attacker: has any working execution primitive from categories 1-7 and now automates it. Gain: full account takeover — steal the CSRF token and session state a same-origin script can already see, then replay authenticated requests as the victim (change password, exfiltrate data, read localStorage/IndexedDB). Blast radius: every authenticated user who triggers the payload; a stored XSS combined with this category is functionally equivalent to a full account compromise, not a 'cosmetic' bug.",
    baseSeverity: "critical",
    docs: [
      { title: "OWASP Top 10 — Injection / XSS impact", description: "Why XSS chained to session/credential theft is consistently ranked as one of the highest-impact web vulnerability classes.", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
      { title: "Samy is my hero — the MySpace worm (background)", description: "The canonical real-world case study for exactly this category: a single stored XSS chained into a self-propagating account-takeover worm.", url: "https://cwe.mitre.org/data/definitions/79.html" },
    ],
  },
  exotic_modern: {
    title: "09 — Exotic & Modern Vectors",
    blurb:
      "Prototype pollution gadgets, CSS injection for data exfil, dangling markup, import(), WebAssembly, Service Worker injection, Trusted Types bypass attempts.",
    rationale:
      "Emerging/underappreciated vectors — many teams add CSP and think \"no scripts = no XSS.\" This category demonstrates that CSS attribute selectors and dangling markup can exfiltrate data with zero JavaScript execution, and that newer platform features (Service Workers, WASM, dynamic import) open execution paths a script-src policy alone doesn't anticipate.",
    threatModel:
      "Attacker: operates against a target that already deployed CSP or another modern mitigation and needs a vector the policy didn't anticipate. Gain: ranges from silent data exfiltration via CSS (no script execution needed, so script-src is irrelevant) to full compromise via a Trusted Types policy gap or a maliciously registered Service Worker that can intercept all future requests from that origin. Blast radius: sites that consider themselves 'hardened' because CSP is deployed — this category is precisely the residual risk a security review must check for.",
    baseSeverity: "medium",
    docs: [
      { title: "Trusted Types API (MDN)", description: "The mitigation this category's payloads specifically attempt to bypass or route around — understand it to know what a real bypass would require.", url: "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API" },
      { title: "MDN — Content Security Policy (CSP)", description: "Why CSP alone doesn't stop CSS-based exfiltration or every modern execution primitive — the gap this category illustrates.", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP" },
    ],
  },
  real_world_derived: {
    title: "10 — Real-World Derived",
    blurb:
      "Payloads reconstructed from CVEs, famous bug bounty reports, and the Samy/Twitter worms. Each with the real vulnerability context and what was actually fixed.",
    rationale:
      "Connects theory to incidents — every mechanism taught in this course maps to a real, publicly documented breach or disclosure. Reconstructing the actual payload (not a toy version) and the actual fix closes the loop between 'this is possible' and 'this is what happened.'",
    threatModel:
      "Attacker: historically, ranged from a bored teenager (Samy, 2005) to professional bug bounty researchers and, in the Magecart cases, organized crime running supply-chain skimmers through compromised third-party scripts. Gain: everything from a self-propagating friend-request worm to real payment-card theft at scale. Blast radius: in the worst documented cases (Magecart/British Airways), hundreds of thousands of real users' payment data — this category exists so 'severity: critical' never feels theoretical.",
    baseSeverity: "critical",
    docs: [
      { title: "CWE-79 — Cross-Site Scripting", description: "The formal classification behind every CVE referenced in this category.", url: "https://cwe.mitre.org/data/definitions/79.html" },
      { title: "PortSwigger XSS cheat sheet", description: "PortSwigger Research's continually-updated public vector list — several entries in this category are traceable to exactly this kind of published research.", url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" },
    ],
  },
};
