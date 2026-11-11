SHELL := /bin/bash -euo pipefail
.PHONY: install uninstall test venv clean

install:
	pipx list --short | grep -q '^rpcpeek ' && pipx uninstall rpcpeek || true
	pipx install .

uninstall:
	pipx uninstall rpcpeek

venv:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test: venv
	.venv/bin/pytest -v

clean:
	rm -rf .venv build dist src/*.egg-info .pytest_cache
