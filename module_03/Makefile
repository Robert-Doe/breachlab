.PHONY: run-py run-node install-py install-node clean help
help:
	@echo "XSS Mastery Lab — Module 03"
	@echo "  make run-py   / make run-node"
	@echo "  make install-py / make install-node"
install-py:
	pip install -r requirements.txt
run-py:
	python lab_server.py
install-node:
	npm install
run-node:
	node lab_server.js
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf node_modules 2>/dev/null || true
