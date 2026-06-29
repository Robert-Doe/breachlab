# DECISIONS.md — Module 09: DOM-Based XSS & Client-Side Sinks

---

## Decision 1: DOM XSS lab is a standalone client-side page, not a server endpoint

**Decision:** `dom_lab.html` contains all the vulnerable JavaScript inline — no server routes generate the vulnerable code. The server only provides `/api/search` and `/message` as supporting endpoints.

**Why:** DOM XSS is definitionally a client-side vulnerability. The server is not involved in the exploitation path. Making the lab client-side reinforces this: the student can see in DevTools that no network request is made when firing most sinks (innerHTML, eval, setTimeout, location). This is the key conceptual distinction from reflected/stored XSS. A server-rendered vulnerable page would undermine that lesson by making the server appear involved.

**Trade-off:** Without server involvement, the student cannot use Burp Suite to intercept and modify the injection point in the traditional way. DevTools is the right tool for DOM XSS analysis. The tutorial explicitly redirects students from Burp to DevTools → Sources and the DOM Breakpoints panel for this module.

---

## Decision 2: Six distinct sinks are demonstrated with separate interactive cards

**Decision:** innerHTML, insertAdjacentHTML, document.write, eval(), setTimeout(string), and location.href each get their own card with independent fire/clear controls.

**Why:** Each sink has meaningfully different behaviour that warrants individual demonstration. innerHTML and insertAdjacentHTML both parse HTML but have different insertion positions. document.write replaces the document and executes script tags (unlike innerHTML). eval() and setTimeout(string) execute raw JavaScript without any HTML parsing — the payload syntax is entirely different. location.href executes javascript: URIs without any HTML. Collapsing these into one demo would obscure the payload syntax differences that the student must internalise for real-world exploitation.

**Trade-off:** Six cards makes the page long. The section headers ("Sinks — innerHTML family", "Sinks — JavaScript execution") provide visual organisation.

---

## Decision 3: The JSON API sink (S7) demonstrates the AJAX DOM XSS pattern

**Decision:** The /api/search endpoint returns the query in JSON, and the client-side code renders data.query via innerHTML — creating DOM XSS despite the server returning safe JSON.

**Why:** This is one of the most common DOM XSS patterns in modern SPAs. The server-side code is correct (JSON encoding is safe for JSON), but the client-side rendering is the vulnerability. Developers who review only server-side code will miss this entirely. The demo makes the chain explicit: safe JSON → unsafe innerHTML. This bridges Module 08's data-attribute pattern to a realistic AJAX scenario.

**Trade-off:** The /api/search endpoint is also a valid reflected XSS vector if its output were rendered server-side as HTML (which it isn't here — it returns application/json). Keeping it JSON-only ensures the demo is clean and only the client-side vulnerability is exercised.

---

## Decision 4: Source taxonomy is interactive, showing current page values

**Decision:** The source inspector buttons show the actual value of each DOM source (location.search, location.hash, etc.) for the current page.

**Why:** Students often have a theoretical understanding of DOM sources but have never actually read their values in a real browser. Clicking "location.hash" and seeing "(empty)" or the actual fragment value makes the source concept concrete. The student can then append a fragment to the URL and see location.hash update — directly reinforcing how an attacker controls the source value.

**Trade-off:** The displayed values are specific to the current page context, which may not have interesting values. The tutorial instructs students to add ?q=test#fragment to the URL before clicking the source buttons to see non-empty values.

---

## Decision 5: document.write sink replaces the page entirely

**Decision:** The document.write demo writes to the current page rather than to a separate iframe or sandboxed element.

**Why:** document.write after document loading is complete (called from an event handler) implicitly calls document.open(), which clears the entire current document. This side effect is part of the vulnerability model — an attacker can use document.write to completely replace a page's content for phishing purposes. Showing this in an iframe would hide the replacement behaviour. The tutorial warns students they will need to use the browser Back button to return, and explains why this is a more severe impact than innerHTML (which only modifies a portion of the DOM).

**Trade-off:** This makes the document.write demo the most disruptive in the lab. A cautionary note is displayed before the fire button.
