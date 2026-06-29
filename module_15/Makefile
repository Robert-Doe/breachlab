.PHONY: py node install-py install-node

py: install-py
	python lab_server.py

node: install-node
	node lab_server.js

install-py:
	pip install -r requirements.txt -q

install-node:
	npm install --silent
