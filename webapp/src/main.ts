import "./style.css";

/**
 * Breachlab — Sandboxed XSS Playground
 *
 * A safe, 100% client-side reimplementation of the attack scenarios taught
 * across the breachlab course modules. Every "vulnerable" sink below runs
 * inside a sandboxed <iframe sandbox="allow-scripts"> (deliberately WITHOUT
 * allow-same-origin) fed via `srcdoc`. That combination gives the injected
 * script an opaque, cross-origin sandbox with no access to this page's real
 * cookies, storage, or DOM — so a payload can genuinely execute and still
 * touch nothing real. Execution is observed only because the sandboxed
 * frame chooses to `postMessage` a report back to its parent — the one
 * channel sandbox-without-same-origin frames are still allowed to use.
 *
 * There is no backend here. Nothing typed into this page is ever sent
 * anywhere, stored anywhere, or shown to any other visitor.
 */

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

// The tiny reporting shim injected into every sandboxed srcdoc. It does not
// touch the vulnerable sink at all — it only overrides the alert/confirm/
// prompt family so a payload that "fires" reports back instead of opening
// a real blocking dialog, and relays uncaught script errors too.
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
  window.alert = function (msg) { report("alert", msg); };
  window.confirm = function (msg) { report("confirm", msg); return true; };
  window.prompt = function (msg) { report("prompt", msg); return null; };
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
        breachlab course modules, running live in your browser — inside an isolated
        sandbox that can't touch anything real. Attack it, then flip the switch and
        watch the same payload get neutralised.
      </p>
      <div class="safety-banner">
        <span class="icon">[!]</span>
        <div>
          <strong>Authorized, sandboxed, client-side lab.</strong>
          Every "vulnerable" page below runs inside an
          <code style="font-family:var(--mono)">&lt;iframe sandbox="allow-scripts"&gt;</code>
          with no <code style="font-family:var(--mono)">allow-same-origin</code>, loaded via
          <code style="font-family:var(--mono)">srcdoc</code>. Nothing you type is sent to a
          server, stored, or shown to anyone else — it only ever runs in an opaque, isolated
          frame in your own browser.
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
            <iframe id="output-frame" sandbox="allow-scripts" srcdoc=""></iframe>
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
          Edit the payload freely — it only ever runs inside the sandboxed frame above.
          Try toggling "harden this sink" and running the exact same payload again.
        </p>
      </div>
    </main>

    <footer class="site-footer">
      <p class="footer-safety">
        This is an authorized, sandboxed, 100% client-side educational demo. No payload is ever
        sent to a server, persisted, or relayed to any other visitor — every "attack" here runs
        and dies inside a single isolated <code style="font-family:var(--mono)">&lt;iframe&gt;</code>
        in your own browser.
      </p>
      <div class="footer-meta">breachlab — 19-module XSS course &middot; webapp is a safe reimplementation, not the local lab</div>
    </footer>
  `;

  renderSinkCode();
  wireEvents();
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

render();
