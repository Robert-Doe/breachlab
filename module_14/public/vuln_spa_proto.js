/**
 * vuln_spa_proto.js — Vulnerable SPA utility used in Module 14
 *
 * This file ships with a deliberately insecure deepMerge and a URL-param
 * parser that feeds into it.  The SPA reads "theme config" from the URL
 * and merges it — allowing prototype pollution via the query string.
 *
 * The polluted property reaches a DOM sink in renderWidget() below.
 *
 * Usage: include this script in any HTML page, then call:
 *   VulnSPA.init()   → runs on DOMContentLoaded
 *   VulnSPA.render() → re-renders the widget
 */

const VulnSPA = (() => {

  // ── Vulnerable deepMerge ─────────────────────────────────────────────────
  function deepMerge(target, source) {
    if (typeof source !== 'object' || source === null) return target;
    for (const key in source) {
      if (key === '__proto__') {
        // VULNERABLE: writes to Object.prototype
        Object.assign(Object.prototype, source[key]);
        continue;
      }
      if (typeof source[key] === 'object' && source[key] !== null) {
        target[key] = target[key] || {};
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  // ── URL param parser → nested object ────────────────────────────────────
  function parseQueryToNested(search) {
    const result = {};
    new URLSearchParams(search).forEach((val, key) => {
      const parts = key.split(/[\[\]]+/).filter(Boolean);
      let cur = result;
      parts.forEach((part, idx) => {
        if (idx === parts.length - 1) {
          cur[part] = val;
        } else {
          cur[part] = cur[part] || {};
          cur = cur[part];
        }
      });
    });
    return result;
  }

  // ── App config (app assumes these are the only props) ───────────────────
  const defaultConfig = {
    theme: 'dark',
    lang: 'en',
    pageTitle: 'Lab SPA',
  };

  // ── DOM sink — GADGET ────────────────────────────────────────────────────
  // Renders a "widget" by reading config properties.
  // If Object.prototype.extraContent is polluted, it injects into innerHTML.
  function renderWidget(config) {
    const container = document.getElementById('spa-widget');
    if (!container) return;

    const title = config.pageTitle || defaultConfig.pageTitle;
    const theme = config.theme || defaultConfig.theme;

    // Developer writes: "extraContent is only ever set by our own code"
    // But it can be inherited from a polluted Object.prototype
    const extra = config.extraContent; // ← DOM sink gadget

    container.innerHTML =
      '<div style="background:' + (theme === 'dark' ? '#141c2e' : '#f8f9fa') + ';' +
      'color:' + (theme === 'dark' ? '#e2e8f0' : '#1a1a2e') + ';' +
      'padding:16px;border-radius:6px;border:1px solid #1e3a5f">' +
      '<h3 style="margin-bottom:8px;color:#38bdf8">' + title + '</h3>' +
      '<p style="font-size:13px;color:#7a9bbf">Theme: ' + theme + ' | Lang: ' + (config.lang || 'en') + '</p>' +
      (extra ? '<div class="extra-content">' + extra + '</div>' : '') +
      '</div>';
  }

  // ── Public API ───────────────────────────────────────────────────────────
  function init() {
    // Parse URL query string into nested object
    const urlParams = parseQueryToNested(window.location.search);

    // Merge into app config — VULNERABILITY: deepMerge allows prototype pollution
    const appConfig = {};
    deepMerge(appConfig, defaultConfig);
    deepMerge(appConfig, urlParams);

    // Log for debug visibility
    console.log('[VulnSPA] URL params parsed:', JSON.stringify(urlParams));
    console.log('[VulnSPA] Merged config:', JSON.stringify(appConfig));
    console.log('[VulnSPA] Object.prototype.extraContent:', ({}).extraContent);

    renderWidget(appConfig);
  }

  function render() {
    const appConfig = {};
    deepMerge(appConfig, defaultConfig);
    renderWidget(appConfig);
  }

  return { init, render, deepMerge, parseQueryToNested };
})();

// Auto-init on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', VulnSPA.init);
} else {
  VulnSPA.init();
}
