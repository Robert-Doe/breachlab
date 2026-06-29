.PHONY: run-py run-node install-py install-node clean
run-py:
	python lab_server.py
run-node:
	node lab_server.js
install-py:
	pip install -r requirements.txt
install-node:
	npm install
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf node_modules 2>/dev/null || true
