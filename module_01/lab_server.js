/**
 * XSS Mastery Lab — Module 01
 * Node.js / Express lab server: minimal home page only.
 * Mirrors lab_server.py exactly — choose whichever runtime you prefer.
 * Both servers stay in sync across every module.
 *
 * Run:
 *   npm install
 *   node lab_server.js        (or: npm start)
 *   npm run dev               (auto-reload with nodemon)
 *
 * Then open: http://localhost:5000
 */

const express = require("express");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 5000;

// ── Serve everything inside /public as static files ─────────────────────────
// express.static is the Node equivalent of Flask's send_from_directory.
// In later modules we will add route handlers BEFORE this line so that
// dynamic vulnerable routes take priority over static files.
app.use(express.static(path.join(__dirname, "public")));

// Parse URL-encoded form bodies (needed from Module 04 onward)
app.use(express.urlencoded({ extended: false }));

// Parse JSON bodies (needed from Module 09 onward)
app.use(express.json());

// ── Home ─────────────────────────────────────────────────────────────────────
// express.static already handles GET / → public/index.html automatically,
// but we add an explicit route so later modules can override it cleanly.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/ping", (req, res) => {
  res.json({ status: "ok", module: 1 });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  XSS Mastery Lab — Module 01`);
  console.log(`  Listening on http://localhost:${PORT}`);
  console.log(`  Press Ctrl+C to stop\n`);
});
