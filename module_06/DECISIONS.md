# DECISIONS.md — Module 06: URI Scheme Injection

---

## Decision 1: Three separate endpoints (redirect, link-preview, profile) instead of one

**Decision:** Module 06 introduces three new routes rather than a single catch-all vulnerable endpoint.

**Why:** Each endpoint models a distinct real-world pattern where URI injection occurs. `/redirect` models open redirect abuse — a common misconfiguration in OAuth and SSO flows. `/link-preview` models the pattern of reflecting user-supplied URLs into anchor tags — found in link-sharing features, bookmark managers, and user profile pages. `/profile` models a surface with *multiple* URL-accepting fields simultaneously, demonstrating that URI injection is rarely isolated to one attribute. Teaching each pattern separately before combining them gives the student a richer threat model vocabulary.

**Trade-off:** Three endpoints increases the server size. The cumulative server is now 120+ lines of Python. This is acceptable — each route is short, well-commented, and maps directly to a step in the attack demo.

---

## Decision 2: The /redirect endpoint uses Flask's redirect() directly

**Decision:** The open redirect uses Flask's `redirect(url)` helper with the attacker URL passed directly, rather than constructing a raw Location header.

**Why:** This is the exact pattern a developer would write when building a "return URL after login" feature. `redirect()` sets the Location header, which is what the browser follows. Showing the real Flask API makes the vulnerability recognisable in production code rather than a contrived raw-header example. Node.js mirrors with `res.redirect(url)`.

**Trade-off:** Flask's `redirect()` in some versions will reject non-HTTP schemes. Students running older Flask versions may find the javascript: redirect blocked by Flask itself — a teachable moment: the framework can be a partial defence, but it is not consistent across versions and cannot be relied upon. The correct fix is still explicit scheme validation before calling redirect().

---

## Decision 3: The URI reference catalog covers legacy vectors (vbscript:, dynsrc) explicitly

**Decision:** `uri_reference.html` includes IE-only and legacy vectors alongside modern ones, flagged with a "LEGACY" badge.

**Why:** A PhD threat model must be historically grounded. Enterprise environments still run Internet Explorer-based WebViews in line-of-business applications. Security papers cite vbscript: and dynsrc: attacks from the 2000s that are still relevant to embedded browser components in thick clients. Excluding these would produce an incomplete threat surface for a researcher writing about the full history of URI-based XSS.

**Trade-off:** Including legacy vectors could confuse students into testing them on modern targets where they won't fire. The LEGACY badge and explicit notes ("IE only", "not applicable to modern browsers") are the mitigation.

---

## Decision 4: Step 7 demonstrates the location DOM sink directly in the demo page

**Decision:** The `demoLocationSink()` button in `attack_03_uri.html` actually executes `location.href = "javascript:..."` on the current page rather than pointing to a server endpoint.

**Why:** This demonstrates that URI scheme injection requires no server participation — the vulnerability is entirely client-side. The browser executes the javascript: scheme whenever any code assigns an attacker-controlled value to a navigation sink. Showing this as a pure DOM operation reinforces the distinction between reflected/stored XSS (server-side injection) and DOM XSS (client-side injection) that becomes central in Module 09.

**Trade-off:** The button navigates away from the demo page (via location.href), which means the student must use the back button to return. A more polished implementation would use a sandboxed iframe to contain the navigation. Kept simple here to keep focus on the mechanism.

---

## Decision 5: javascript: obfuscation table uses innerHTML to inject the link

**Decision:** The obfuscation demo in Step 6 uses `a.setAttribute("href", "\x09javascript:...")` to set the href via DOM API rather than as an HTML string.

**Why:** This demonstrates that the obfuscation bypass is a *browser URL parser* property, not an HTML parser property. Even when the href is set via JavaScript (bypassing HTML parsing entirely), the browser's URL normalisation strips leading whitespace before evaluating the scheme. This is a subtle but important point: defences that sanitise the *HTML* before it's parsed are insufficient if the href value is set by JavaScript afterward. Context-aware output encoding is not enough — you must also validate URL values in JavaScript code that handles navigation.

**Trade-off:** Most students will encounter this in HTML injection contexts (server-side reflected), not DOM API contexts. The more common variant (HTML entity in href string) is shown in the reference table. The setAttribute demo adds depth for the DOM XSS follow-up in Module 09.
