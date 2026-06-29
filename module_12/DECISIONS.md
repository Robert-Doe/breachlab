# Module 12 — Design Decisions

## D1: Five separate filter endpoints instead of one configurable endpoint
Each filter demonstrates a distinct failure mode. Combining them would obscure which rule is being bypassed. The separate endpoints let students isolate the exact mechanism — blocklist incompleteness vs. stripping non-recursion vs. encoding transparency — before tackling the compound WAF simulator where interactions between rules matter.

## D2: /waf-sim shows the rule trace (input → output per rule)
A real WAF is a black box. Making the trace visible here is a deliberate pedagogical inversion: students can see exactly which rule each payload survives. This builds the mental model needed to reason about real WAF bypass systematically, rather than through blind trial and error.

## D3: The blocklist is intentionally case-sensitive and incomplete
A case-insensitive blocklist of all HTML event handlers would be closer to a real (bad) defence. A case-sensitive, short list exaggerates the failure to make the lesson obvious: no list is ever complete, and case sensitivity is a trivially exploitable property. Students observe both dimensions in the same endpoint.

## D4: /filter/encoding renders the filtered output as raw HTML
This is the key condition that makes the entity-bypass work: the filter runs on the string, then the string is embedded directly in the response HTML. The browser's HTML parser then decodes `&lt;` back to `<`. If the output were HTML-encoded again before embedding, the bypass would fail. The endpoint documents this explicitly in the UI label.

## D5: The JavaScript obfuscation reference (Step 07) includes JSFuck/Hieroglyphy
These are not realistic attack payloads in most contexts (they produce enormous strings), but they illustrate the theoretical boundary: any JavaScript can be encoded using only 6 characters because the JS engine's evaluation pipeline is Turing-complete over its own encoding primitives. Including them anchors the student's understanding that content-level filtering of JavaScript is fundamentally undecidable.
