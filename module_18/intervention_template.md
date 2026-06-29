# PhD Research Contribution Template — XSS Defenses

Use this template to position your research contribution relative to the gap table in M18.

---

## 1. Gap Identification

**Attack class:** [e.g., mXSS / DOM XSS / Prototype Pollution]

**Defense class:** [e.g., HTML Sanitizers / CSP / Trusted Types]

**Current coverage:** OPEN / PARTIAL *(circle one)*

**Evidence of gap:**
- [Cite the specific CVE, bypass technique, or research paper that demonstrates the gap]
- [e.g., "CVE-2019-20374 shows that DOMPurify was bypassable via MathML foster parenting — a class of mXSS not covered by any existing formal sanitizer model"]

---

## 2. Proposed Intervention

**What I will build/prove:**
[One sentence: "I will develop X that addresses Y by doing Z."]

**Novelty relative to prior work:**
| Prior work | What it does | What it misses |
|------------|-------------|----------------|
| [Author, Year] | [Brief description] | [The specific gap your work fills] |

**Formal framing (if applicable):**
- Input model: [e.g., "all HTML strings that are valid according to the HTML5 parsing spec"]
- Property: [e.g., "no sanitised string, when re-parsed, produces an active script execution context"]
- Method: [e.g., "grammar-based fuzzing", "static taint analysis", "formal proof in Coq"]

---

## 3. Expected Contribution

**Coverage after intervention:**

| | Before | After |
|--|--------|-------|
| [Attack class] vs [Defense class] | OPEN | CLOSED (claimed) |

**Evaluation criteria:**

| Criterion | How you will measure it | Target |
|-----------|------------------------|--------|
| Coverage | % of known bypass variants detected/blocked | ≥ 95% |
| Soundness | False positive rate | < 1% |
| Performance | Overhead vs. baseline | < 5ms p99 |
| Deployability | Lines of code change to adopt | < 50 LOC |

---

## 4. One-Paragraph Abstract (draft)

> [Paste your draft abstract here. It should: state the problem (gap + evidence), state your approach (method), state your contribution (coverage + evaluation), state why it matters (threat model + real-world relevance). Target: 150 words.]

---

## 5. Related Gap Table Entries

List all coverage matrix cells that your work touches (directly or indirectly):

- [ ] [Defense] × [Attack] — OPEN → CLOSED
- [ ] [Defense] × [Attack] — PARTIAL → CLOSED
- [ ] [Defense] × [Attack] — OPEN → PARTIAL (acknowledge if partial)

---

## Example (filled in)

**Gap:** DOMPurify (HTML Sanitizers) × mXSS — PARTIAL
**Evidence:** CVE-2019-20374; ongoing Cure53 research showing new bypass variants each year.
**Intervention:** Formal grammar-theoretic model of HTML sanitizer completeness under all browser re-parsing scenarios.
**Abstract draft:** "HTML sanitizers such as DOMPurify protect against XSS by removing dangerous content from HTML strings. However, mutation XSS (mXSS) exploits divergences between how the sanitizer parses a string and how the browser re-parses the sanitized output, leading to active XSS payloads that survive sanitization. We present [Name], a formal model of the HTML5 parsing specification for sanitizer-relevant constructs, and use it to derive a completeness criterion for sanitizer implementations. We implement [Name] as a fuzzing harness and discover [N] previously unknown mXSS bypass variants across four major sanitizers. Our model provides the first provably complete characterisation of the mXSS attack surface under the HTML5 specification."
