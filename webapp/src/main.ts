import "./style.css";
import { PAYLOAD_BANK, type PayloadCategory, type PayloadEntry } from "./payloadBank.generated";

/**
 * Breachlab — Sandboxed XSS Playground
 *
 * A safe, 100% client-side reimplementation of the attack scenarios taught
 * across the breachlab course modules. Every "vulnerable" sink below runs
 * inside an <iframe sandbox="allow-scripts allow-same-origin"> fed via
 * `srcdoc`. A payload genuinely executes AND genuinely shares this page's
 * origin, so alert()/confirm()/prompt() pop real browser dialogs (not a
 * simulated report) and document.cookie reads this page's real —
 * but entirely fake and disposable — demo session cookie. Nothing here
 * is real user data: there is no backend, no account system, and nothing
 * you do ever leaves your own browser tab or reaches any other visitor.
 * Sandboxing still blocks top-level navigation and popups regardless of
 * allow-same-origin, so the worst case is "you alert() yourself."
 */

// A clearly-fake demo session, regenerated on every page load, so a
// cookie-stealing payload has something genuine (but worthless) to steal.
function seedDemoCookie(): string {
  const token = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const value = `lab_${token}`;
  document.cookie = `demo_session=${value}; path=/; samesite=lax`;
  return value;
}

const demoCookieValue = seedDemoCookie();

// ── Escaping helpers used by the "harden this sink" toggle ────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(str: string): string {
  // Attribute-value encoding: only the quote character matters for
  // breaking out of value="...", but a real hardening pass encodes the
  // full dangerous set the same way escapeHtml does.
  return escapeHtml(str);
}

function sanitizeUrl(url: string): string {
  const trimmed = url.trim();
  try {
    // A relative URL has no scheme — allow it.
    if (/^\/(?!\/)/.test(trimmed)) return trimmed;
    const u = new URL(trimmed, "https://example.invalid/");
    if (u.protocol === "http:" || u.protocol === "https:") return trimmed;
  } catch {
    /* fall through to rejection */
  }
  return "#blocked-by-scheme-allowlist";
}

// The tiny reporting shim injected into every sandboxed srcdoc. It does NOT
// block or replace alert/confirm/prompt — a payload that calls them still
// pops a real, native browser dialog in your tab, exactly like a real XSS
// would. It only additionally reports back to the lab page so the on-page
// status badge can reflect what just happened.
const HARNESS_SCRIPT = `<script>
(function () {
  function report(via, detail) {
    try {
      // top (not parent) so this still reaches the lab page even when this
      // harness is running two frames deep (e.g. inside a data: URI preview
      // frame nested inside the sandboxed srcdoc frame).
      top.postMessage({ __breachlab: true, status: "fired", via: via, detail: String(detail).slice(0, 200) }, "*");
    } catch (e) {}
  }
  var realAlert = window.alert, realConfirm = window.confirm, realPrompt = window.prompt;
  window.alert = function (msg) { report("alert", msg); return realAlert.call(window, msg); };
  window.confirm = function (msg) { report("confirm", msg); return realConfirm.call(window, msg); };
  window.prompt = function (msg, def) { report("prompt", msg); return realPrompt.call(window, msg, def); };
  window.addEventListener("error", function () { /* parse errors are not a fire */ });
})();
<\/script>`;

// ── Mechanism definitions ──────────────────────────────────────────────────

interface Mechanism {
  id: string;
  label: string;
  title: string;
  moduleRef: string;
  explanation: string;
  defaultPayload: string;
  hardenLabel: string;
  sinkCode: (payload: string) => string;
  buildBody: (payload: string, hardened: boolean) => string;
}

const mechanisms: Mechanism[] = [
  {
    id: "tag-parsing",
    label: "Tag Parsing",
    title: "Tag Parsing — Script Tag Injection",
    moduleRef: "Module 04 — /search?q=… (body context)",
    explanation:
      "When user input is concatenated straight into an HTML document body, the parser doesn't know the difference between \"page content\" and \"a new tag.\" A <script> tag placed in that position parses like any other markup and its contents execute during the initial document parse.",
    defaultPayload: "<script>alert('tag-parsing:fired')</script>",
    hardenLabel: "HTML-entity-encode before insertion",
    sinkCode: (p) =>
      `# Flask — module_04/lab_server.py — /search?q=...\n` +
      `q = request.args.get("q", "")\n\n` +
      `# DELIBERATE VULNERABILITY: f-string interpolation, no escaping\n` +
      `body = f'<div id="query-echo">{q}</div>'\n\n` +
      `# live payload:\n# q = ${JSON.stringify(p)}`,
    buildBody: (payload, hardened) =>
      `<div id="query-echo">${hardened ? escapeHtml(payload) : payload}</div>`
  },
  {
    id: "event-handlers",
    label: "Event Attributes",
    title: "Event Handler Attributes — Filter Bypass",
    moduleRef: "Module 05 — /vuln-display?content=… (naive script filter)",
    explanation:
      "A common first fix after an XSS report is a regex that strips <script> tags. It stops exactly one vector. Event-handler attributes — onerror, onload, onfocus, and 150+ others — run attacker JS without ever writing the word \"script\", so the filter lets them straight through.",
    defaultPayload: "<img src=x onerror=\"alert('event-handler:fired')\">",
    hardenLabel: "HTML-entity-encode instead of script-only filter",
    sinkCode: (p) =>
      `# Flask — module_05/lab_server.py — /vuln-display?content=...\n` +
      `content = request.args.get("content", "")\n\n` +
      `# THE "SANITISER": only strips <script>...</script>\n` +
      `filtered = re.sub(r'<script[\\s\\S]*?</script>', '', content, flags=re.I)\n` +
      `html = f'<div id="rendered">{filtered}</div>'\n\n` +
      `# live payload:\n# content = ${JSON.stringify(p)}`,
    buildBody: (payload, hardened) => {
      // Simulate the real, naive "script-only" filter from module 05 — it
      // always runs, vulnerable or not, because it's the actual bug being
      // taught. The harden toggle adds the fix layered on top of it.
      const scriptStripped = payload.replace(/<script[\s\S]*?<\/script>/gi, "");
      const finalContent = hardened ? escapeHtml(scriptStripped) : scriptStripped;
      return `<div id="rendered">${finalContent}</div>`;
    }
  },
  {
    id: "uri-schemes",
    label: "URI Schemes",
    title: "URI Scheme Injection — href/src",
    moduleRef: "Module 06 — /link-preview?url=… (no scheme allow-list)",
    explanation:
      "Browsers accept several executable URI schemes wherever a URL is expected — href, src, action, formaction. javascript: runs script on navigation; data: can smuggle an entire inline HTML document, script included, into anything that loads a URL as a nested document — such as a link-preview/embed feature. An app that trusts a URL parameter without checking its scheme hands the attacker a first-class execution point. Below, the payload you type becomes the body of an HTML document smuggled in through a data: URI and rendered as an embedded preview frame, exactly like /link-preview would render any URL you gave it.",
    defaultPayload: "<script>alert('uri-scheme:fired')</script>",
    hardenLabel: "Allow-list http(s) schemes only",
    sinkCode: (p) =>
      `# Flask — module_06/lab_server.py — /link-preview?url=...\n` +
      `url = request.args.get("url", "")\n\n` +
      `# NO scheme check — anything goes into href / preview src\n` +
      `body = f'<a href="{url}">Visit link</a>'\n` +
      `preview = f'<iframe src="{url}"></iframe>'   # rendered inline as a "preview"\n\n` +
      `# live payload smuggled via a data: URI:\n` +
      `# url = "data:text/html," + ${JSON.stringify(p)}`,
    buildBody: (payload, hardened) => {
      const src = hardened
        ? sanitizeUrl("data:text/html;charset=utf-8," + encodeURIComponent(payload))
        : "data:text/html;charset=utf-8," + encodeURIComponent(HARNESS_SCRIPT + payload);
      return (
        `<div style="font-size:11px;color:#555;margin-bottom:6px">Embedded link preview:</div>` +
        `<iframe id="prev" src="${escapeAttr(src)}" style="width:100%;height:70px;border:1px solid #ccc"></iframe>`
      );
    }
  },
  {
    id: "dom-sinks",
    label: "DOM Sinks",
    title: "DOM-Based XSS — postMessage → innerHTML",
    moduleRef: "Module 09 — /message (unchecked postMessage listener)",
    explanation:
      "DOM XSS never touches the server at all. A source (postMessage, location.hash, a JSON API response) flows straight into a sink (innerHTML, document.write, eval) inside the browser. Here, any frame — including a hostile one — can postMessage HTML into this page, and it lands in innerHTML with no origin check and no sanitisation.",
    defaultPayload: "<img src=x onerror=\"alert('dom-sink:fired')\">",
    hardenLabel: "Use textContent (no HTML parsing) instead of innerHTML",
    sinkCode: () =>
      `// module_09/public/dom_lab.html — postMessage receiver\n` +
      `window.addEventListener("message", function (e) {\n` +
      `  // No origin check, no sanitisation\n` +
      `  document.getElementById("msg-display").innerHTML = e.data;\n` +
      `});\n\n` +
      `// the lab harness (this page) then does:\n` +
      `// iframe.contentWindow.postMessage(payload, "*")`,
    buildBody: (_payload, hardened) =>
      `<div id="msg-display" style="min-height:32px">Waiting for a message…</div>` +
      `<script>
         window.addEventListener("message", function (e) {
           if (e.data && e.data.__breachlab) return; // ignore our own harness pings
           var el = document.getElementById("msg-display");
           ${
             hardened
               ? "el.textContent = e.data;"
               : "el.innerHTML = e.data;"
           }
         });
       <\/script>`
  },
  {
    id: "context-escape",
    label: "Context Escape",
    title: "Context Escape — Attribute Breakout",
    moduleRef: "Module 04 — /search-attr?q=… (attribute-value context)",
    explanation:
      "The same string can be safe in one HTML context and dangerous in another. Inside value=\"…\" a bare quote ends the attribute early; whatever follows becomes new markup — here, a fresh onfocus attribute that the browser honours the instant the field receives focus (in real life: the moment a visitor clicks or tabs into the search box; a real page would also often use autofocus to trigger it without any interaction at all). (Mutation XSS, mXSS, is this idea's harder cousin: a payload that a sanitizer judged safe gets mutated back into something executable when the browser re-parses/re-serializes the DOM, e.g. via a second innerHTML round-trip — covered in Module 13 of the full curriculum.)",
    defaultPayload: "\" onfocus=\"alert('context-escape:fired')\" x=\"",
    hardenLabel: "HTML-attribute-encode the value",
    sinkCode: (p) =>
      `# Flask — module_04/lab_server.py — /search-attr?q=...\n` +
      `q = request.args.get("q", "")\n\n` +
      `body = f'<input type="text" name="q" value="{q}">'\n\n` +
      `# live payload:\n# q = ${JSON.stringify(p)}`,
    buildBody: (payload, hardened) =>
      `<input id="inp" type="text" value="${hardened ? escapeAttr(payload) : payload}">` +
      `<script>
         // Lab harness only (not part of the payload): simulates a visitor
         // focusing the field, exactly like a real click or Tab keypress would.
         window.addEventListener("DOMContentLoaded", function () {
           var el = document.getElementById("inp");
           if (el) el.focus();
         });
       <\/script>`
  }
];

// ── State ────────────────────────────────────────────────────────────────

let activeId = mechanisms[0].id;
let hardened = false;
let payloadOverrides: Record<string, string> = {};
let runToken = 0;

// Payload library modal state
let modalCategoryId: string | null = null;
let modalTab: "payloads" | "attacker" | "threat" | "docs" = "payloads";

function activeCategory(): PayloadCategory | undefined {
  return PAYLOAD_BANK.find((c) => c.id === modalCategoryId);
}

const SEVERITY_ORDER: Record<PayloadEntry["severity"], number> = { critical: 3, high: 2, medium: 1, low: 0 };

function activeMechanism(): Mechanism {
  return mechanisms.find((m) => m.id === activeId)!;
}

function currentPayload(): string {
  const m = activeMechanism();
  return payloadOverrides[m.id] ?? m.defaultPayload;
}

// ── Rendering ────────────────────────────────────────────────────────────

const app = document.getElementById("app")!;

function render() {
  const m = activeMechanism();

  app.innerHTML = `
    <header class="topbar">
      <div class="brand"><span class="dot"></span>breachlab</div>
      <div class="links">
        <a href="https://github.com/Robert-Doe/breachlab" target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href="https://robertdoe.com" target="_blank" rel="noopener noreferrer">&larr; robertdoe.com</a>
      </div>
    </header>

    <section class="hero">
      <span class="eyebrow">Sandboxed &middot; Client-Only &middot; No Backend</span>
      <h1>Breachlab<br />Sandboxed XSS Playground</h1>
      <p class="tagline">
        Five real cross-site-scripting execution mechanisms, pulled straight from the
        breachlab course modules, running live in your browser — for real. Popups really
        pop, and a genuine (but fake) session cookie is really there to steal. Attack it,
        then flip the switch and watch the same payload get neutralised.
      </p>
      <div class="safety-banner">
        <span class="icon">[!]</span>
        <div>
          <strong>Authorized, client-side lab — real execution, fake stakes.</strong>
          Every "vulnerable" page below runs inside an
          <code style="font-family:var(--mono)">&lt;iframe sandbox="allow-scripts allow-same-origin"&gt;</code>
          loaded via <code style="font-family:var(--mono)">srcdoc</code>. That means a payload
          genuinely executes and can genuinely read this page's
          <code style="font-family:var(--mono)">document.cookie</code> — try editing a payload
          to <code style="font-family:var(--mono)">alert(document.cookie)</code>. The sandbox
          still blocks top-level navigation and new windows either way. There is no backend,
          no real account, and no real cookie: the value below is generated fresh in your
          browser on every page load and never leaves it.
          <div class="fake-cookie">document.cookie on this page right now: <code>demo_session=${escapeHtml(
            demoCookieValue
          )}</code></div>
        </div>
      </div>
    </section>

    <main class="demo">
      <div class="mechanism-tabs" role="tablist">
        ${mechanisms
          .map(
            (mech) => `
          <button class="mechanism-tab ${mech.id === activeId ? "active" : ""}" data-id="${mech.id}">
            ${mech.label}
          </button>`
          )
          .join("")}
      </div>

      <div class="card">
        <span class="module-ref">${escapeHtml(m.moduleRef)}</span>
        <h2>${escapeHtml(m.title)}</h2>
        <p>${escapeHtml(m.explanation)}</p>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="panel-label">Vulnerable sink (real code, module-accurate)</div>
          <div class="code-panel" id="sink-code"></div>
        </div>
        <div class="card">
          <div class="panel-label">
            <span>Sandboxed output</span>
            <span class="status-badge idle" id="status-badge">idle</span>
          </div>
          <div class="output-frame-wrap">
            <iframe id="output-frame" sandbox="allow-scripts allow-same-origin" srcdoc=""></iframe>
            <div class="log-line" id="log-line">Press Run to inject the payload into the sandbox.</div>
          </div>
        </div>
      </div>

      <div class="card">
        <label class="harden-toggle" id="harden-toggle">
          <span class="switch ${hardened ? "on" : ""}"></span>
          <span><strong>Harden this sink</strong> — ${escapeHtml(m.hardenLabel)}</span>
        </label>

        <div class="payload-row">
          <input class="payload-input" id="payload-input" type="text" spellcheck="false" value="${escapeHtml(
            currentPayload()
          )}" />
          <button class="btn secondary" id="reset-btn">Reset payload</button>
          <button class="btn" id="run-btn">Run ▶</button>
        </div>
        <p class="hint">
          Edit the payload freely — it only ever runs inside this page, in your own browser.
          Try <code>alert(document.cookie)</code> to see real cookie theft against the fake
          session above, then toggle "harden this sink" and run the exact same payload again.
        </p>
      </div>
    </main>

    <section class="library">
      <div class="library-head">
        <h2>Attack Payload Library</h2>
        <p>
          122 real, annotated payloads from the breachlab course's Module 19 payload bank, grouped into
          10 classes of attack. Open a category for the code, the attacker's thought process, the threat
          model, and links to primary sources — pick a payload and try it live in the sandbox above.
        </p>
      </div>
      <div class="library-grid">
        ${PAYLOAD_BANK.map((cat) => {
          const counts: Record<string, number> = {};
          for (const e of cat.entries) counts[e.severity] = (counts[e.severity] ?? 0) + 1;
          return `
          <button class="cat-card" data-cat="${cat.id}" type="button">
            <div class="cat-card-top">
              <h3>${escapeHtml(cat.title)}</h3>
              <span class="sev-badge sev-${cat.baseSeverity}">${cat.baseSeverity}</span>
            </div>
            <p>${escapeHtml(cat.blurb)}</p>
            <div class="cat-card-foot">
              <span class="count">${cat.entries.length} payloads</span>
              <span class="sev-mini">
                ${(["critical", "high", "medium", "low"] as const)
                  .filter((s) => counts[s])
                  .map((s) => `<span class="dot sev-${s}" title="${counts[s]} ${s}"></span>`)
                  .join("")}
              </span>
            </div>
          </button>`;
        }).join("")}
      </div>
    </section>

    <footer class="site-footer">
      <p class="footer-safety">
        This is an authorized, 100% client-side educational demo. Execution is real — alerts
        really pop, document.cookie really reads a real value — but nothing here is: there is
        no backend, no real account, no real cookie, and no payload is ever sent to a server,
        persisted, or relayed to any other visitor. Every "attack" lives and dies in your own
        browser tab.
      </p>
      <div class="footer-meta">breachlab — 19-module XSS course &middot; webapp is a safe reimplementation, not the local lab</div>
    </footer>

    ${renderModal()}
  `;

  renderSinkCode();
  wireEvents();
}

// ── Payload library modal ──────────────────────────────────────────────

function renderModal(): string {
  const cat = activeCategory();
  if (!cat) return "";

  const tabs: { id: typeof modalTab; label: string }[] = [
    { id: "payloads", label: `Payloads (${cat.entries.length})` },
    { id: "attacker", label: "Attacker's Thought Process" },
    { id: "threat", label: "Threat Model" },
    { id: "docs", label: "Docs & Further Reading" },
  ];

  let body = "";
  if (modalTab === "payloads") {
    const sorted = [...cat.entries].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.num - b.num);
    let lastSection = "";
    body = sorted
      .map((e) => {
        const sectionHeader = e.section !== lastSection ? ((lastSection = e.section), `<div class="entry-section">${escapeHtml(e.section)}</div>`) : "";
        return `
        ${sectionHeader}
        <div class="payload-entry">
          <div class="payload-entry-head">
            <span class="sev-badge sev-${e.severity}">${e.severity}</span>
            ${e.tags.map((t) => `<span class="p-tag">${escapeHtml(t.label)}</span>`).join("")}
          </div>
          <pre class="payload-code">${escapeHtml(e.payload)}</pre>
          <div class="payload-meta">
            ${e.meta.map((m) => `<div class="pm-row"><span class="pm-key">${escapeHtml(m.key)}</span><span class="pm-val">${escapeHtml(m.value)}</span></div>`).join("")}
          </div>
          ${
            e.sandboxMechanism
              ? `<button class="btn secondary try-btn" data-mech="${e.sandboxMechanism}" data-payload="${escapeAttr(e.payload)}">Try it in the sandbox ▶</button>`
              : `<div class="hint" style="margin-top:8px">Not directly runnable in the 5-mechanism sandbox above — see Module 19 for the full lab context.</div>`
          }
        </div>`;
      })
      .join("");
  } else if (modalTab === "attacker") {
    body = `<p class="modal-prose">${escapeHtml(cat.rationale)}</p>`;
  } else if (modalTab === "threat") {
    body = `<p class="modal-prose">${escapeHtml(cat.threatModel)}</p>`;
  } else {
    body = cat.docs
      .map(
        (d) => `
      <div class="doc-card">
        <span class="doc-card-icon">📄</span>
        <div class="doc-card-body">
          <strong>${escapeHtml(d.title)}</strong> — ${escapeHtml(d.description)}<br>
          <a href="${d.url}" target="_blank" rel="noopener noreferrer">${d.url}</a>
        </div>
      </div>`
      )
      .join("");
  }

  return `
    <div class="modal-backdrop" id="modal-backdrop">
      <div class="modal-panel" role="dialog" aria-modal="true">
        <div class="modal-head">
          <div>
            <div class="modal-eyebrow">${escapeHtml(cat.title)}</div>
            <h2>${escapeHtml(cat.blurb)}</h2>
          </div>
          <button class="modal-close" id="modal-close" type="button" aria-label="Close">✕</button>
        </div>
        <div class="modal-tabs">
          ${tabs.map((t) => `<button class="modal-tab ${t.id === modalTab ? "active" : ""}" data-tab="${t.id}" type="button">${t.label}</button>`).join("")}
        </div>
        <div class="modal-body">${body}</div>
      </div>
    </div>`;
}

function renderSinkCode() {
  const m = activeMechanism();
  const codeEl = document.getElementById("sink-code")!;
  codeEl.textContent = m.sinkCode(currentPayload());
}

function setStatus(status: "idle" | "fired" | "blocked", message: string) {
  const badge = document.getElementById("status-badge")!;
  const log = document.getElementById("log-line")!;
  badge.className = `status-badge ${status}`;
  badge.textContent = status;
  log.className = `log-line ${status === "idle" ? "" : status}`;
  log.textContent = message;
}

function wireEvents() {
  document.querySelectorAll<HTMLButtonElement>(".mechanism-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeId = btn.dataset.id!;
      render();
    });
  });

  const toggle = document.getElementById("harden-toggle")!;
  toggle.addEventListener("click", () => {
    hardened = !hardened;
    render();
  });

  const input = document.getElementById("payload-input") as HTMLInputElement;
  input.addEventListener("input", () => {
    payloadOverrides[activeMechanism().id] = input.value;
    renderSinkCode();
  });

  document.getElementById("reset-btn")!.addEventListener("click", () => {
    delete payloadOverrides[activeMechanism().id];
    render();
  });

  document.getElementById("run-btn")!.addEventListener("click", runPayload);

  document.querySelectorAll<HTMLButtonElement>(".cat-card").forEach((card) => {
    card.addEventListener("click", () => {
      modalCategoryId = card.dataset.cat!;
      modalTab = "payloads";
      render();
    });
  });

  const backdrop = document.getElementById("modal-backdrop");
  if (backdrop) {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) closeModal();
    });
    document.getElementById("modal-close")!.addEventListener("click", closeModal);

    document.querySelectorAll<HTMLButtonElement>(".modal-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        modalTab = btn.dataset.tab as typeof modalTab;
        render();
      });
    });

    document.querySelectorAll<HTMLButtonElement>(".try-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mech = btn.dataset.mech!;
        const payload = btn.dataset.payload!;
        activeId = mech;
        payloadOverrides[mech] = payload;
        hardened = false;
        modalCategoryId = null;
        render();
        document.querySelector(".demo")?.scrollIntoView({ behavior: "smooth", block: "start" });
        window.setTimeout(runPayload, 400);
      });
    });
  }
}

function closeModal() {
  modalCategoryId = null;
  render();
}

// ── Running a payload in the sandbox ────────────────────────────────────

function runPayload() {
  const m = activeMechanism();
  const payload = currentPayload();
  const token = ++runToken;

  setStatus("idle", "Running…");

  const iframe = document.getElementById("output-frame") as HTMLIFrameElement;
  const bodyHtml = m.buildBody(payload, hardened);
  const srcdoc = `<!doctype html><html><head><meta charset="utf-8">${HARNESS_SCRIPT}</head><body style="font-family:sans-serif;font-size:13px;padding:10px;color:#111">${bodyHtml}</body></html>`;

  // Fresh listener per run so stale runs can't report into a new one.
  const listener = (event: MessageEvent) => {
    if (token !== runToken) return;
    const data = event.data;
    if (data && typeof data === "object" && data.__breachlab && data.status === "fired") {
      window.removeEventListener("message", listener);
      setStatus("fired", `Fired via ${data.via}("${data.detail}") — the payload executed inside the sandbox.`);
    }
  };
  window.addEventListener("message", listener);

  iframe.srcdoc = srcdoc;

  // For the DOM-sink mechanism, the "attack" is a hostile frame posting a
  // message into the vulnerable listener — simulate that delivery once the
  // sandboxed document has loaded.
  if (m.id === "dom-sinks") {
    iframe.onload = () => {
      if (token !== runToken) return;
      iframe.contentWindow?.postMessage(payload, "*");
    };
  }

  window.setTimeout(() => {
    if (token !== runToken) return;
    // If nothing reported "fired" by now, either the payload never called
    // alert/confirm/prompt, or the hardening transform neutralised it.
    const badge = document.getElementById("status-badge");
    if (badge && badge.textContent === "idle") {
      setStatus("blocked", hardened
        ? "Blocked — the hardening transform neutralised this payload."
        : "No execution detected — this payload didn't trigger alert/confirm/prompt.");
    }
  }, 900);
}

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && modalCategoryId) closeModal();
});

render();
