# DECISIONS.md — Module 10: Stored XSS & Second-Order Attacks

---

## Decision 1: In-memory store instead of a database

**Decision:** Comments and profiles are stored in Python lists / JavaScript arrays that reset on server restart. No SQLite, no file persistence.

**Why:** A real database would add setup friction (migrations, schema, connection strings) that distracts from the XSS concepts being taught. The in-memory store provides all the behaviour needed to demonstrate stored XSS: write once, read many times, survives multiple HTTP requests within a session. The "clear" utility endpoints replace database DELETE operations for lab resets. Students who want to extend to a real database for realism can swap in SQLite with one import.

**Trade-off:** Payloads disappear on server restart, which means the student cannot demonstrate the dwell-time concept across multiple days without keeping the server running. The tutorial addresses this explicitly: the in-memory model is pedagogically equivalent; real-world implications of durable storage are discussed in text rather than demonstrated.

---

## Decision 2: Two separate storage surfaces with different privilege levels

**Decision:** The comment board (`/board`) is "public" and the admin panel (`/admin`) is "privileged" — different rendering contexts for the same storage mechanism.

**Why:** Second-order XSS requires two distinct contexts: storage context (where the attacker writes) and execution context (where the payload runs). Making these clearly separate pages with different visual styling (the admin panel has a gold header) helps the student internalise why second-order XSS is conceptually distinct from ordinary stored XSS. The privilege difference (anyone can post profiles; only "admins" visit `/admin`) models the real-world pattern where the impact of second-order XSS is proportional to the privilege level of the execution context.

**Trade-off:** There is no actual authentication — any student can visit `/admin`. This is intentional for the lab: authentication would add complexity without adding XSS concepts. The tutorial notes that in a real application, `/admin` would require a privileged session, making the second-order attack's impact even higher.

---

## Decision 3: Both author field and text field are injection points

**Decision:** The comment board reflects both the `author` name and the `text` content unsanitised.

**Why:** Real stored XSS vulnerabilities rarely exist in just the "body" field. Any user-supplied field that appears in rendered HTML is a potential injection point. Having two injection points teaches the student to look beyond the obvious "comment box" to secondary fields like usernames, titles, and metadata. The author-field injection (Step 2 in the demo) also demonstrates that a payload fires once per card rendered — so if one author has five comments, the payload fires five times, which has implications for cookie theft timing.

**Trade-off:** Having two injection points in the same form could confuse students about which field triggered the XSS. The demo page labels each payload clearly with which field it targets.

---

## Decision 4: Step 4 demonstrates XSS → CSRF chaining

**Decision:** The stored payload in Step 4 uses `fetch()` to make a credentialed GET request to `/board/clear` — simulating a CSRF action performed by the stored XSS payload in the admin's browser.

**Why:** Module 10 is the first point in the course where the student has all the tools needed to demonstrate attack chaining: stored XSS (persistence) + CSRF (authenticated action without credentials). This is the pattern behind real high-severity vulnerabilities: an attacker who achieves stored XSS in an admin panel can perform any admin action the browser can perform. The clear-board action is the lab's stand-in for "delete all users", "change admin password", or "export the database". The chaining concept is established here and deepened in Module 15.

**Trade-off:** `/board/clear` accepts GET requests (not POST with a CSRF token) — making the CSRF trivially easy. This is intentional: the module focuses on the XSS-as-CSRF-enabler concept. Module 15 specifically studies anti-CSRF tokens and how stored XSS bypasses them via same-origin token exfiltration.

---

## Decision 5: "Dwell time" is Step 5 — a conceptual discussion, not a demo

**Decision:** Step 5 in the attack demo is text-only — it explains the dwell-time implication of database-stored XSS without a code demo.

**Why:** Dwell time cannot be demonstrated in a lab with an in-memory store. Rather than skipping the concept, the demo page includes it as a structured discussion with concrete implications. This models PhD-level research thinking: not all threat properties can be demonstrated in a lab, but they must still be included in the threat model. The discussion of 18+ month dwell times for real-world stored XSS is grounded in published incident reports that students can look up.

**Trade-off:** Students who learn primarily through doing rather than reading may find Step 5 less engaging. The tutorial's Exercise 4 compensates by having the student write a threat model entry for stored XSS that explicitly quantifies dwell time as a severity multiplier.
