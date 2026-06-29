# DECISIONS.md — Module 03: The Five Execution Mechanisms

---

## Decision 1: Taxonomy is mechanism-based, not attack-class-based

**Decision:** The five categories are defined by *how code executes* (tag parsing, event attributes, URI schemes, DOM sinks, context escape) rather than by the traditional reflected/stored/DOM classification.

**Why:** The reflected/stored/DOM taxonomy describes *where the payload lives*, not *how it runs*. A stored XSS can use any of the five mechanisms; a DOM XSS almost always uses Mechanism 2 or 4. For a PhD threat model, the mechanism taxonomy is more useful because it maps directly to what a defence must intercept. A defence that "blocks reflected XSS" is ambiguous — it says nothing about which mechanisms it covers. A defence that "controls all DOM sink assignments" is precise and falsifiable.

**Trade-off:** The mechanism taxonomy is less familiar to practitioners who learned XSS from OWASP's reflected/stored/DOM framing. In your paper, you will need to define both taxonomies and explain the mapping between them. The traditional taxonomy appears in the related-work section; the mechanism taxonomy drives your threat model.

---

## Decision 2: The coverage summary table shows gaps, not checkmarks

**Decision:** The mechanism-vs-defence table in `mechanisms_demo.html` shows ✗ (doesn't cover) prominently rather than only highlighting what works.

**Why:** Security education that only shows what defences do well produces practitioners who are overconfident in partial controls. The gaps are more important than the coverages for a defender — you need to know what is *not* protected. The ✗ entries in the table are the research opportunities your PhD intervention is filling.

**Trade-off:** A practitioner-facing reference would present the table differently — leading with "what to deploy" rather than "what each fails to cover." We optimise for research insight over operational guidance here.

---

## Decision 3: Mechanism 4 (DOM sinks) uses eval() as the demonstration sink

**Decision:** The `mech4_eval()` demo uses `eval()` directly rather than the more common `innerHTML` sink.

**Why:** `innerHTML` is demonstrated in both the innerHTML button and in Mechanism 2 (event handlers fire from innerHTML-injected content). Using `eval()` for the explicit Mechanism 4 demo makes clear that DOM sinks include both HTML-parsing sinks (`innerHTML`, `document.write`) and code-evaluation sinks (`eval`, `setTimeout(string)`, `new Function()`). These are distinct sub-categories with different defences. Trusted Types covers HTML sinks natively; eval sinks require separate `script-src` CSP restrictions.

**Trade-off:** Production DOM XSS most commonly uses `innerHTML` as the sink, not `eval()`. Module 09 (DOM XSS) covers the complete source–sink catalogue with `innerHTML` as the primary example. Using `eval()` here prevents the student from conflating "DOM XSS = innerHTML" which is a common and limiting misconception.

---

## Decision 4: Mechanism 5 includes both a context-break demo AND a namespace-mutation demo

**Decision:** The two sub-demos in Mechanism 5 cover attribute-context escape (simple) and MathML namespace escape (complex, mXSS preview).

**Why:** Context escape exists on a spectrum from "trivially simple" (inject a quote to break out of an attribute) to "requires deep parser knowledge" (mXSS via namespace transitions). Showing both ends of the spectrum in the same card makes the connection explicit: they are the same mechanism at different levels of sophistication. A student who grasps the attribute-escape demo will eventually understand mXSS as its logical extreme.

**Trade-off:** The MathML demo is a preview — it fires but the full explanation is deferred to Module 13. Some students may find the preview frustrating without the full context. We add a clear "Full mXSS coverage in Module 13" note to set the expectation. Foreshadowing here motivates studying Module 13 carefully.

---

## Decision 5: FIRE buttons execute real JS; SAFE DEMO buttons produce only visual output

**Decision:** Interactive demos are split into "FIRE" (real execution, uses `alert` or DOM mutation) and "SAFE DEMO" (visual output only, no payload execution).

**Why:** The student must experience real execution as early as possible — seeing `document.domain` appear in an output box after clicking FIRE is viscerally different from reading about it. At the same time, some mechanisms (location= navigation, remote script load) would disrupt the demo page itself if triggered. SAFE DEMO buttons explain what *would* happen without causing it. This mirrors the difference between a proof-of-concept XSS (fires `alert(1)` to demonstrate execution) and a weaponised payload (exfiltrates data) — a distinction the student will need when reporting vulnerabilities.

**Trade-off:** In Module 09 (DOM XSS) and Module 11 (Blind XSS), we introduce callback-based demos where the "proof" of execution is a network request to a listener rather than a visible alert. That is a more realistic demonstration model. We keep alert-style feedback here to keep the feedback loop tight while the student is still learning the fundamentals.
