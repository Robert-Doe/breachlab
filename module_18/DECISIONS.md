# Module 18 — Design Decisions

## Why an API endpoint for the coverage matrix?
The gap analysis tool fetches live coverage data from the server, allowing students to POST custom assessments (marking their own understanding of what's covered). This makes the threat model interactive rather than a static table — students can experiment with the coverage matrix and see how adding or removing a defense changes the gap profile.

## Why 6 defenses × 8 attack classes?
This is the minimum viable threat model that covers all course modules without becoming unwieldy. Each row (defense) corresponds to a control introduced in M17. Each column (attack) corresponds to a module (M04–M16). The matrix is sparse enough to reason about but rich enough to reveal gaps.

## Why include HttpOnly Cookie as a defense with PARTIAL coverage everywhere?
HttpOnly prevents cookie theft via document.cookie — but XSS can still forge requests, use credentials, and exfiltrate non-cookie data. Marking it PARTIAL everywhere illustrates that it's a useful hardening measure, not an XSS defense. This combats the common misconception that HttpOnly prevents XSS impact.

## Why intervention_template.md?
PhD students need to position their research contributions clearly. The template in intervention_template.md provides a fill-in-the-blank structure for mapping a gap in the coverage matrix to a research contribution, then to evaluation criteria. This bridges the gap table to a paper abstract.

## Why separate public/threat_model.html and public/gap_analysis.html?
The threat model page is the high-level summary (all defenses, all attack classes, quick reference). The gap analysis page is the interactive deep-dive (editable cells, filter by gap type, export as JSON/CSV). Separating them keeps each page focused.
