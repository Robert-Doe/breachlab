.PHONY: py node install clean

py:
	python lab_server.py

node:
	node lab_server.js

install:
	pip install -r requirements.txt
	npm install

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; \
	rm -rf node_modules
