# DECISIONS.md — Module 02: How Browsers Parse HTML

---

## Decision 1: /parse-demo reflects input with zero sanitisation

**Decision:** The `/parse-demo` server route echoes user-supplied HTML directly into a page with no escaping, encoding, or filtering.

**Why:** The module's goal is to let students observe the browser's parser in isolation. Any sanitisation would hide the raw behaviour we need to study. A student who cannot see what the browser does with `<b>unclosed` or `<xss onmouseover=...>` cannot reason about why sanitisers fail on edge cases.

**Trade-off:** In a real application, every user-supplied string that appears in HTML output must be HTML-encoded before insertion. The production pattern is to use a templating engine that encodes by default (Jinja2 with `autoescape=True`, React JSX, Handlebars). We introduce safe output in Module 11 (CSP) and Module 17 (defences). The deliberate vulnerability here is load-bearing for learning.

---

## Decision 2: quirks.js builds the DOM programmatically instead of static HTML

**Decision:** The five parser-quirk demonstrations in `quirks.js` create DOM nodes via `document.createElement` and assign to `innerHTML` at runtime, rather than being written as static HTML in `parser_demo.html`.

**Why:** This makes the input string explicit and readable as a JavaScript string literal, which is easier to annotate and reason about than escaped HTML-inside-HTML. It also means each demo card is identical in structure — title, input code, rendered output, notes — making comparison straightforward.

**Trade-off:** A production educational platform would use a server-side rendering pipeline (MDX, Astro, etc.) that keeps content and presentation separate. We keep it client-side for now to avoid adding a build step. Module 09 (DOM XSS) will examine the security implications of exactly this pattern: building DOM nodes from strings at runtime.

---

## Decision 3: Four injection contexts shown as a visual grid, not prose

**Decision:** The four HTML injection contexts (body, attribute value, script, style) are shown as a 2×2 card grid in `parser_demo.html` rather than listed in prose.

**Why:** The visual parallel structure forces the student to compare contexts side-by-side. The key insight — that the same character has different meanings in each context — is clearer when the four cases are literally adjacent on screen. This is the mental model that all subsequent modules rely on.

**Trade-off:** A production reference would include all context variants (attribute without quotes, URL context, JSON context, CSS value context, etc.) which are covered incrementally in Modules 06, 08, and 12. We show the minimal four to avoid overloading Module 02.

---

## Decision 4: Live injector uses innerHTML directly, with a visible warning

**Decision:** The live injector box on `parser_demo.html` uses raw `innerHTML` assignment and includes a prominent red warning rather than sandboxing the output.

**Why:** The student needs to experience executing their own payloads in a controlled environment as early as possible. Sandboxing (e.g., a cross-origin iframe) would prevent `alert()` from firing and remove the visceral feedback that makes the lesson memorable. The warning makes the risk explicit and reinforces the lesson: `innerHTML` is dangerous, even locally.

**Trade-off:** A production learning platform (e.g., PortSwigger Web Security Academy) runs student payloads in isolated iframes on separate subdomains so a student cannot accidentally steal their own session cookie. For this local lab that risk is trivial, but Module 09 (DOM XSS) explicitly studies sandboxed vs. unsandboxed iframe behaviour as part of the same-origin policy discussion.

---

## Decision 5: Server-side echo links use pre-encoded URLs

**Decision:** The "Server-Side Echo" links in `parser_demo.html` are pre-encoded in the source rather than generated dynamically from a form input.

**Why:** Pre-encoded links let the student first read the URL, decode it manually, and predict what will be injected before clicking — building the skill of reading encoded payloads that is essential for analysing real XSS in the wild (bug bounty reports, CVE write-ups).

**Trade-off:** A form-based interface (type HTML, click "Reflect") would be more ergonomic. We add a proper form-based reflector in Module 04 (Reflected XSS) once the student understands what the server is doing with the input. The form in M04 also introduces Burp Suite interception, which requires a form submission.
