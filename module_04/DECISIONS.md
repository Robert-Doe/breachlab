# DECISIONS.md — Module 04: Script Tag Injection

---

## Decision 1: Three separate endpoints for three injection contexts

**Decision:** `/search` (body), `/search-attr` (attribute), and `/search-js` (script) are separate routes rather than one route with a context toggle.

**Why:** Each context has a different URL so the student can share or bookmark a specific context for study. More importantly, the URL itself is part of the attack — in a real reflected XSS, the attacker crafts a URL and sends it to the victim. Having three distinct URLs reinforces that each is a separate attack surface, not just a UI variation. The student will use Burp Repeater on each URL independently.

**Trade-off:** A production teaching platform might use a single configurable endpoint. We use separate routes because it maps more directly to real-world target enumeration: an auditor discovers multiple endpoints and tests each independently for injection context.

---

## Decision 2: `page_shell()` / `pageShell()` helper builds HTML via string interpolation

**Decision:** The shared page template is a function that string-interpolates its arguments, making the vulnerability structural rather than accidental.

**Why:** Real-world reflected XSS vulnerabilities almost always arise from exactly this pattern: a helper or template function that concatenates user input into HTML. By making it a function, we show the student that the vulnerability isn't caused by one bad line — it's caused by an architectural pattern (string concatenation for HTML generation) that is wrong everywhere it's used. The fix is not to sanitise inside `page_shell()` but to replace the entire pattern with a safe templating engine.

**Trade-off:** In production, the correct pattern is a templating engine with auto-escaping enabled by default (Jinja2 with `autoescape=True`, Handlebars, React JSX). We introduce the safe version in Module 17. Keeping the unsafe version here preserves the ability to fire all attack payloads in later modules that build on this server.

---

## Decision 3: The script-context endpoint embeds input in a `var` declaration

**Decision:** `/search-js` uses `var searchQuery = "[INPUT]"` rather than a more exotic pattern.

**Why:** This is the single most common script-context injection pattern in the wild. Server-side code that passes data to client JavaScript via inline variable declarations (rather than a separate JSON API endpoint) is everywhere in legacy codebases. The student needs to recognise this pattern immediately on sight. JSON.parse-based injection, template literal injection, and event handler string injection are covered in Module 12 (evasion) once the basic pattern is mastered.

**Trade-off:** The production fix is not to HTML-encode the value inside the script block (encoding rules differ in JS context) but to use `JSON.stringify()` to safely serialise the value, or better, to remove inline data embedding entirely and serve data via a JSON API. `JSON.stringify()` escapes characters that are dangerous in JS string context (`"`, `\`, and crucially `</script>`). Module 17 demonstrates this fix.

---

## Decision 4: Attack demo page opens payloads in new tabs rather than iframing them

**Decision:** `attack_01_script.html` opens the vulnerable endpoints in new browser tabs rather than embedding them in iframes.

**Why:** Same-origin iframes would work, but new tabs more accurately simulate the real attack scenario — the victim receives a link and opens it. New tabs also give the student a clean, full-page DevTools experience for each payload test, making it easier to inspect the Elements panel and Console without interference from the demo page itself. The distinction between "attacker sends a URL" and "page loads malicious content inline" is architecturally important — we want the student to internalise the former model.

**Trade-off:** iframes would allow showing before/after side-by-side. Module 07 (namespace injection) uses iframes deliberately as part of the attack mechanism, giving the student direct experience with the iframe model there.

---

## Decision 5: The zero-interaction autofocus payload is shown in the attribute section

**Decision:** `" autofocus onfocus="alert(1)` is included in the attribute-context section rather than the event-handlers module (Module 05).

**Why:** This payload works via an attribute-context break followed by an event handler — it combines both techniques. Showing it here, where the student has just learned attribute-context injection, teaches that context breaks enable event handler injection. The conceptual link is tighter here than it would be in Module 05, where the focus is on zero-interaction events in general. Module 05 will reference this payload and extend it.

**Trade-off:** There is some overlap with Module 05 material. We keep it here because the module's learning goal is "attribute context injection enables these attacks" — the specific event handler is secondary. A student reading both modules will see complementary framing rather than repetition.
