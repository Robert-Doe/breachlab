# Module 19 — Design Decisions

## Why 110+ payloads across 10 categories?
XSS mastery requires pattern recognition. A defender who has seen 100 payloads can recognise attack variants on sight; one who has seen 10 cannot. The categories map to the 5 execution mechanisms from M04 plus cross-cutting concerns (evasion, chaining, real-world).

## Category structure rationale
| File | Focus | Why separate |
|------|-------|--------------|
| 01_script_tags | Basic/encoded `<script>` | Entry point; most filtered |
| 02_event_handlers | onerror, onfocus, etc. | Different mechanism to script injection |
| 03_uri_schemes | `javascript:` and `data:` | Sink-specific: href/src/action attributes |
| 04_svg_mathml | Namespace-based vectors | Namespace parsing is a distinct class |
| 05_dom_sinks | Client-side JS sinks | No server involvement; scanner misses |
| 06_filter_evasion | Encoding/obfuscation | Cross-cutting concern, not a mechanism |
| 07_mxss | Sanitiser divergence | Requires sanitiser context to understand |
| 08_chaining | Post-exploitation | Demonstrates why XSS severity is P1 |
| 09_exotic_modern | CSS/WASM/workers/PP | Emerging/underappreciated vectors |
| 10_real_world | CVE/worm/BB derived | Connects theory to incidents |

## Annotation format
Every payload has: copy button, Context, Mechanism, Bypasses (red), Stopped by (green), Origin/Note. The "Stopped by" field deliberately points to the minimum fix — not "prevent XSS" but the specific control that addresses each variant. This trains defenders to match controls to attack classes.

## Why include attack chaining (M19/08)?
Defenders underestimate XSS severity when they see only `alert(1)`. The chaining section shows the real impact chain: XSS → CSRF token theft → account takeover. This is why XSS is a P1 bug in every major bug bounty program.

## Why include CSS injection and dangling markup (no JS)?
Many teams add CSP thinking "no scripts = no XSS." CSS attribute selectors and dangling markup demonstrate that data can be exfiltrated without any JavaScript execution. Defenders need to understand this to write complete CSP policies.
