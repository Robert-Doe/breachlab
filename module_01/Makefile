# XSS Mastery Lab — Module 01
# Works on Linux, macOS, and Windows (Git Bash / MSYS2).
# On native Windows CMD/PowerShell, use the run.bat equivalents documented
# in tutorial.html instead.

.PHONY: run-py run-node install-py install-node clean help

# ── Default target ────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  XSS Mastery Lab — Module 01"
	@echo ""
	@echo "  make install-py    Install Python dependencies"
	@echo "  make install-node  Install Node.js dependencies"
	@echo "  make run-py        Start the Flask lab server"
	@echo "  make run-node      Start the Node.js lab server"
	@echo "  make clean         Remove generated artifacts"
	@echo ""

# ── Python / Flask ────────────────────────────────────────────────────────────
install-py:
	pip install -r requirements.txt

run-py:
	python lab_server.py

# ── Node.js / Express ─────────────────────────────────────────────────────────
install-node:
	npm install

run-node:
	node lab_server.js

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf node_modules 2>/dev/null || true
