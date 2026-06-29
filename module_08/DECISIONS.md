# DECISIONS.md — Module 08: Attribute Injection & Context Breaking

---

## Decision 1: Four separate attribute-context endpoints instead of one configurable endpoint

**Decision:** `/attr-double`, `/attr-single`, `/attr-unquoted`, and `/attr-data` are separate routes, each modelling a distinct attribute quoting pattern.

**Why:** Each quoting style has a different break-out character and appears in real codebases for different reasons. Double-quoted attributes are the default in HTML5. Single-quoted attributes appear frequently in PHP-generated HTML and in older JSP/ASP.NET templates. Unquoted attributes appear in minified HTML and certain legacy template engines. data-* attributes are "safe" at the server level and the vulnerability only manifests client-side via a DOM sink. Collapsing these into one endpoint would obscure the context-specific breakout technique that the student must learn to recognise.

**Trade-off:** Four routes further grows the cumulative server. The server is now ~200+ lines. This is still acceptable; the file is well-commented and each route is short.

---

## Decision 2: The data-attribute endpoint creates a server-side safe / client-side vulnerable split

**Decision:** `/attr-data` deliberately places user input into a `data-query` HTML attribute (which is syntactically safe server-side) and then has inline JavaScript read it via `dataset.query` and assign it to `innerHTML`.

**Why:** This models one of the most common real-world DOM XSS patterns: a developer correctly avoids putting user input into the body or a dangerous attribute, but then client-side code reads that value and processes it unsafely. This pattern appears in SPA frameworks, jQuery plugins, and any application where server-rendered data attributes are the bridge between server-generated content and client-side rendering. It also establishes the conceptual foundation for Module 09 (DOM-Based XSS) — here the student sees the DOM sink for the first time in an attribute-injection context.

**Trade-off:** The server-side component of the vulnerability is technically not exploitable (data-* attributes don't render HTML). This might confuse students who test the endpoint with a naive script-tag payload and don't see server-side execution. The tutorial and demo page explain explicitly that the server HTML is safe and the vulnerability is entirely client-side.

---

## Decision 3: The step 3 "tag-close" breakout uses `<input x="` as the repair suffix

**Decision:** The tag-close payload ends with `<input x="` to absorb the trailing `"` from the template and close the injected HTML cleanly.

**Why:** In a real injection, the page HTML after the injection point still needs to be valid enough to not break the page's rendering. A payload that leaves dangling quotes or unclosed tags may cause parsing errors that make the attack visible or prevent the page from loading. The repair suffix `<input x="` is a clean generic repair: `<input>` is a void element (no closing tag needed), `x` is a harmless unknown attribute, and the `"` at the end absorbs the trailing template quote. Teaching the repair pattern alongside the breakout technique is essential for crafting real-world payloads that don't break the surrounding page.

**Trade-off:** Including the repair suffix makes the payload longer and harder to read. The annotation display in the demo page colour-codes the payload into break-out, payload, and repair sections to make the structure visible.

---

## Decision 4: Step 4 demo shows the partial-fix scenario in the DOM (not server-side)

**Decision:** The `demoPartialFix()` function in the demo page injects the partial-fix scenario client-side rather than pointing to a separate server endpoint.

**Why:** The partial-fix pattern (escape `"` but not `'`) is best illustrated by showing the transformation in real time: the student can see the raw input, the after-escaping value, and the resulting DOM element side-by-side. A separate server endpoint would require a page load and would not show the transformation as clearly. The client-side demo also reinforces that attribute injection can happen in JavaScript (via DOM API) as well as server-side — relevant to Module 09.

**Trade-off:** The client-side demo puts a live injectable input in the DOM of the attack demo page itself. This is intentional — the demo page is a lab environment. A note in the tutorial warns students not to copy this pattern into production code.

---

## Decision 5: style= attribute injection is mentioned in the reference table but not given a dedicated step

**Decision:** The reference table in Step 7 includes `style="..."` as an injection context, but no dedicated demo step exists for it.

**Why:** Style attribute injection is a real but narrower vector. Modern browsers block CSS expression() (IE-only), leaving animation-based execution as the primary style-attribute vector. This is covered in the event-handler catalog (Module 05, `onanimationstart`). Adding a full demo step here would duplicate that material. The reference table entry points the student toward the right mechanism; Module 12 (Filter Evasion) covers CSS-based evasion in depth for students who need to go further.

**Trade-off:** Students who want to practice style= injection in this module will need to construct their own payloads from the reference table. The tutorial exercise section includes this as a stretch exercise to fill the gap.
