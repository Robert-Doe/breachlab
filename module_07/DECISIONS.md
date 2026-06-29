# DECISIONS.md — Module 07: Tag & Namespace Confusion

---

## Decision 1: Three namespace endpoints rather than one combined endpoint

**Decision:** `/svg-inject`, `/math-inject`, and `/iframe-inject` are separate routes rather than a single `?namespace=svg` parameter.

**Why:** Each namespace has a distinct parsing model and a distinct set of available vectors. Keeping them as separate endpoints lets the student navigate directly to the relevant context and see the injection point labelled in the response HTML. A combined endpoint would obscure which vectors belong to which namespace, which is precisely the distinction this module is teaching.

**Trade-off:** Three routes means the cumulative server grows further. The server is now ~180 lines of Python. Still acceptable — each route is short, self-contained, and commented.

---

## Decision 2: SVG script tag demonstration is split between server-rendered and innerHTML

**Decision:** Step 1 in the attack demo shows the SVG `<script>` vector both via a server link (fires) and via a client-side innerHTML demo (blocked), with adjacent result boxes.

**Why:** The innerHTML/script-tag exception studied in Module 05 does not extend to all contexts. Inside an SVG element in **server-rendered HTML**, a `<script>` tag executes as expected. Via `innerHTML`, it is still blocked. Showing both side-by-side prevents the student from over-generalising the M05 lesson — "script tags never execute" is wrong; "script tags injected via innerHTML never execute" is correct. This nuance is important for threat modelling: server-side injection in an SVG context is more dangerous than the same payload injected client-side.

**Trade-off:** The DOM demo using innerHTML for the SVG script does not visually fire (by design), which might confuse students who expect it to. The adjacent labels ("Via innerHTML — blocked" vs "Via server-rendered HTML — fires") and the explanation in the tutorial clarify this.

---

## Decision 3: foreignObject demo uses inline HTML with onerror

**Decision:** The foreignObject payload uses `<img src=x onerror=...>` inside the embedded HTML body, not a `<script>` tag.

**Why:** This demonstrates that foreignObject creates a genuine HTML parsing context inside SVG — not just a namespace label, but a context where HTML-specific execution mechanisms (event handlers) work. Using onerror also connects back to Mechanism 2 (Module 05) and reinforces the cumulative nature of the course. A script tag would also work in this context but would add the confounding factor of the innerHTML restriction if the student tests it in the wrong way.

**Trade-off:** The script tag in foreignObject is a valid and common vector — omitting it from the demo leaves a gap. It is covered in the tutorial text and listed in the reference table.

---

## Decision 4: iframe srcdoc uses sandbox="allow-scripts allow-same-origin"

**Decision:** The `/iframe-inject` endpoint includes `sandbox="allow-scripts allow-same-origin"` on the iframe rather than no sandbox at all.

**Why:** This models the most dangerous realistic configuration: a developer adds a sandbox thinking it's safer (it is, marginally) but retains both `allow-scripts` and `allow-same-origin` — which together completely negate each other's security value. A sandboxed iframe with both flags has the same script privileges as a non-sandboxed same-origin iframe. This is a common misconfiguration found in real codebases where developers cargo-cult the sandbox attribute without understanding that `allow-same-origin` must not be combined with `allow-scripts`.

**Trade-off:** A non-sandboxed iframe would be simpler to explain but less instructive. The module comment and tutorial explain why this specific flag combination is the dangerous real-world pattern.

---

## Decision 5: SVG animate demo targets href (not an event handler attribute)

**Decision:** The SVG `<animate>` payload mutates the `href` attribute of an `<a>` element rather than injecting an event handler directly.

**Why:** Targeting `href` via animate demonstrates Mechanism 3 (URI scheme injection) applied post-parse via SVG animation — a cross-mechanism combination. It also shows that animate can mutate any attribute, not just event handlers, which is relevant for understanding the attack surface. The student must click the element to fire the javascript: href, which reinforces the interaction model. Module 13 (mXSS) covers the version where animate injects event handler attributes into HTML elements, bypassing sanitisers.

**Trade-off:** The interaction requirement (click) means this is not a zero-interaction vector in its current form. The `onbegin` attribute on `<animate>` can make it zero-interaction in some browsers. This is noted in the tutorial as a stretch vector.
