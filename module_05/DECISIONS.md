# DECISIONS.md — Module 05: Event Handler Injection

---

## Decision 1: The "sanitiser" strips only <script> tags

**Decision:** `/vuln-display` uses a single regex to remove `<script>...</script>` blocks and nothing else, presenting it as a "filter" that the student must bypass.

**Why:** This is the most common naive mitigation found in real legacy codebases — a developer receives an XSS report, patches it by stripping script tags, and closes the ticket. Modelling this exactly teaches the student to recognise the pattern in real audits and immediately know it is ineffective. The gap between "we have a filter" and "the filter actually works" is one of the most dangerous misconceptions in production security.

**Trade-off:** A production-quality sanitiser (DOMPurify, OWASP Java HTML Sanitizer) uses an allowlist of permitted tags and attributes parsed through a proper HTML parser. We introduce DOMPurify in Module 17 and demonstrate that even allowlist sanitisers can be bypassed via mXSS (Module 13). The naive regex is here specifically to be broken by the student in the first five minutes.

---

## Decision 2: Event catalog is a separate page (event_catalog.html), not embedded in the tutorial

**Decision:** The 40-entry event handler reference lives in its own page with a live search filter rather than being a static table in the tutorial.

**Why:** The catalog is a reference tool the student will return to throughout the course — when stuck on a bypass in Module 12, when building payloads in Module 19. A separate filterable page is more useful as a persistent reference than a table buried in a tutorial. The search-by-keyword feature also lets the student discover patterns ("all events containing 'pointer'") that a static table would not surface easily.

**Trade-off:** A production security reference (like PortSwigger's XSS cheat sheet) would include test links for each payload pointing at a live vulnerable target. We keep the catalog as a reference-only page to avoid creating 40 separate server routes. Modules 12 and 19 build the interactive payload-testing infrastructure.

---

## Decision 3: Step 3 explicitly contrasts script-tag injection vs. onerror injection in the same output box

**Decision:** The two innerHTML injection buttons in Step 3 write into adjacent result boxes so the student sees both results simultaneously.

**Why:** The innerHTML/script-tag exception is the single most important technical distinction in this module. Showing both results side-by-side makes the contrast impossible to miss. Many developers believe that "innerHTML doesn't execute scripts" means "innerHTML is safe for user content." The adjacent onerror result disproves that belief immediately and viscerally.

**Trade-off:** A more sophisticated demo would use a MutationObserver to log every DOM change as it happens, making the script-tag node creation visible even though it doesn't execute. This is worth adding as a stretch exercise. We keep the demo simple here to focus on the conceptual point.

---

## Decision 4: The filter-demo blocklist contains exactly five rules

**Decision:** `/filter-demo` blocks `<script`, `javascript:`, `onerror`, `onload`, and `onclick` — five specific patterns chosen to match what a developer would add after fixing five separate bug reports.

**Why:** Five rules is realistic: it represents a codebase that has had five XSS reports filed and patched one at a time. The student can see exactly which rules apply (they are listed in the page output) and choose a payload that uses none of them. This directly teaches the "blocklist is unwinnable" lesson — for every rule added, there is at least one bypass.

**Trade-off:** A real WAF (ModSecurity, Cloudflare) has hundreds of rules and uses heuristic scoring. Module 12 (Filter Evasion) studies WAF-grade filters. This module's five-rule filter is intentionally trivial to bypass so the student focuses on the event-handler taxonomy rather than evasion technique.

---

## Decision 5: onanimationstart payload requires an inline style + keyframe

**Decision:** The animation-based payload in Step 7 includes a `<style>` block defining the keyframe rather than relying on an existing stylesheet.

**Why:** This models the realistic attack scenario where the attacker cannot rely on page-specific CSS classes existing in the target. A self-contained payload that injects both the keyframe definition and the element is more portable. It also teaches the student that style injection and event-handler injection can be combined — a pattern that appears in real mXSS bypasses where CSS namespace handling differs between sanitiser and browser.

**Trade-off:** Injecting a `<style>` block changes the page's global CSS, which could interfere with other elements on the same page. In a real stored XSS this is an advantage for the attacker (they can restyle the page for phishing). In the lab this is harmless. Module 10 (Stored XSS) explores the phishing angle.
