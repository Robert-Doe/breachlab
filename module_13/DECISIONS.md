# Module 13 — Design Decisions

## D1: Server sanitises, client inserts via innerHTML — intentionally split
The mXSS pattern only manifests when the sanitiser runs in a different parse context than the final insertion point. Splitting the work — server strips obvious patterns, client does innerHTML — is the exact architecture where mXSS attacks succeed. Students must see that "the server sanitised it" is not a sufficient guarantee when the client re-parses the sanitised string in a different context.

## D2: The live DOM readback panels (innerHTML readback) are the core pedagogical tool
mXSS is invisible without a before/after view. The split between "what the sanitiser sent" and "what the browser's DOM actually contains" is the entire lesson. Each endpoint shows the sanitised string (orange), the DOM after innerHTML insertion (green), and the rendered output — making mutation visible rather than just theoretically described.

## D3: naiveSanitise() is intentionally weak and identical between Python and Node
The weakness of the server sanitiser is not the point of this module — the HTML parser's mutation behaviour is. Using a sophisticated sanitiser would hide the parser mutations behind sanitiser-specific fixes. A simple regex sanitiser shows that parser mutation happens independent of how good the sanitiser is at pattern matching.

## D4: The double-parse simulation (Step 06) is client-side only
The historical DOMPurify mXSS vulnerability involved a client-side double-parse. Demonstrating it client-side is more accurate than trying to simulate it server-side. The browser running the demo is itself the parser being studied — no simulation needed.

## D5: MathML annotation-xml is in the reference table but not a dedicated endpoint
The annotation-xml namespace switch is a real mXSS vector (CVE-2020-26870 and others) but requires specific browser version conditions to reproduce reliably. Including it in the reference table is enough for threat modelling purposes; a dedicated endpoint would either not reproduce or would require browser-specific instructions that would date the module quickly.
