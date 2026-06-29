/**
 * quirks.js — Module 02
 *
 * Demonstrates five browser HTML-parsing quirks that directly create XSS
 * attack surfaces. Each function builds a demonstration case and appends
 * it to the page. Called from parser_demo.html on DOMContentLoaded.
 *
 * IMPORTANT: These are educational demonstrations. The innerHTML assignments
 * below are intentional — they show how the browser processes each quirk.
 * In production code, never use innerHTML with user-supplied data.
 */

"use strict";

// ── Helper: append a demo card to #results ────────────────────────────────────

function addDemo(title, inputHTML, notes) {
  const container = document.getElementById("results");

  // Create a card
  const card = document.createElement("div");
  card.className = "demo-card";

  // Title
  const h = document.createElement("h3");
  h.textContent = title;
  card.appendChild(h);

  // "Input HTML" label + code block
  const inputLabel = document.createElement("p");
  inputLabel.className = "label";
  inputLabel.textContent = "Input HTML (what we gave the parser):";
  card.appendChild(inputLabel);

  const inputCode = document.createElement("pre");
  // textContent encodes the HTML as text — safe display of the raw string
  inputCode.textContent = inputHTML;
  card.appendChild(inputCode);

  // Parsed result container — we use innerHTML deliberately here
  const resultLabel = document.createElement("p");
  resultLabel.className = "label";
  resultLabel.textContent = "Parsed result (open Elements panel to inspect):";
  card.appendChild(resultLabel);

  const resultBox = document.createElement("div");
  resultBox.className = "result-box";

  // THIS is the key line in each demo: we assign malformed HTML to innerHTML
  // and let the browser's parser handle it. The browser will silently repair
  // the markup according to the HTML5 spec. Open DevTools > Elements to see
  // what it produced vs. what we gave it.
  resultBox.innerHTML = inputHTML;
  card.appendChild(resultBox);

  // Notes
  const notesEl = document.createElement("div");
  notesEl.className = "notes";
  notesEl.textContent = notes;
  card.appendChild(notesEl);

  container.appendChild(card);
}

// ── Quirk 1: Unclosed tags ─────────────────────────────────────────────────

function demoUnclosedTags() {
  addDemo(
    "Quirk 1 — Unclosed Tags Are Silently Completed",

    // The parser will close <b> and <i> automatically.
    // An attacker who injects "<b>bold" gets a real <b> element in the DOM
    // even without a closing tag. The DOM tree is always well-formed even
    // when the HTML is not.
    "<b>bold text without closing tag <i>italic",

    "XSS relevance: A filter that looks for matching open/close tag pairs " +
    "will not see </b> and may decide this is 'safe unclosed markup'. The " +
    "browser disagrees — it builds a real element tree from it."
  );
}

// ── Quirk 2: Mismatched nesting ────────────────────────────────────────────

function demoMismatchedNesting() {
  addDemo(
    "Quirk 2 — Mismatched Nesting Is Reorganised",

    // The parser will restructure this into valid nesting.
    // Malformed nesting is used in mXSS (Module 13) to cause payloads to
    // appear in unexpected places after a sanitiser round-trips them through
    // innerHTML.
    "<b><i>text</b></i>",

    "XSS relevance: Sanitisers that serialise then re-parse may produce " +
    "different nesting than the original input. A payload that looks " +
    "harmless in the sanitiser's parse tree can become dangerous after " +
    "the browser re-parses the serialised output (mutation XSS)."
  );
}

// ── Quirk 3: Unknown / future tags are preserved as generic elements ─────────

function demoUnknownTags() {
  addDemo(
    "Quirk 3 — Unknown Tags Become Generic HTMLElements",

    // The browser creates a real DOM node for <xss> even though it is not a
    // real HTML element. It still executes event handlers on it.
    // This is how <xss onmouseover=alert(1)> works — the tag name is irrelevant.
    '<xss onmouseover="this.style.color=\'red\'">hover over this text</xss>',

    "XSS relevance: Filters that only block known dangerous tags " +
    "(<script>, <iframe>, etc.) miss this entirely. The tag name does not " +
    "matter — only the attributes do. Any tag can carry event handlers."
  );
}

// ── Quirk 4: Attribute values without quotes ─────────────────────────────────

function demoUnquotedAttributes() {
  addDemo(
    "Quirk 4 — Unquoted Attribute Values Are Accepted",

    // HTML5 allows attribute values without quotes if they contain no spaces.
    // Filters that only look for quoted injection patterns miss this.
    // Note: we use a safe event here (onmouseover = colour change) to keep
    // the demo visible without triggering security warnings.
    "<img src=x onerror=this.style.outline='3px_solid_red' width=60 height=60>",

    "XSS relevance: A filter checking for onerror=\"...\" (with quotes) " +
    "does not match onerror=... (without quotes). HTML5 permits both. " +
    "The attacker uses the form the filter does not check."
  );
}

// ── Quirk 5: Tag soup — broken tags inside attribute values ─────────────────

function demoTagSoup() {
  addDemo(
    "Quirk 5 — The Parser Recovers From Tag Soup",

    // This string looks like it closes the div and opens a new b tag inside
    // what was supposed to be an attribute value. The browser resolves the
    // ambiguity by its spec-defined error-recovery algorithm.
    // Study the Elements panel carefully — where does each part end up?
    '<div title="</div><b>I escaped the attribute</b>">original div</div>',

    "XSS relevance: If user input lands inside an HTML attribute value and " +
    "the closing delimiter (quote or >) can be injected, the attacker can " +
    "break out of the attribute context into the tag body or even the " +
    "document body — creating new tags. This is attribute-context injection " +
    "(Module 08)."
  );
}

// ── Run all demos on page load ─────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  demoUnclosedTags();
  demoMismatchedNesting();
  demoUnknownTags();
  demoUnquotedAttributes();
  demoTagSoup();
});
