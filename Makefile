# Dopo un clone nuovo, attiva gli hook locali:
#   git config core.hooksPath .githooks
.PHONY: hooks secret-scan test

hooks:
	git config core.hooksPath .githooks
	@echo "Hook attivi: core.hooksPath=.githooks (pre-commit e pre-push)."

secret-scan:
	python3 scripts/secret_scan.py --ci

test:
	python3 -m pytest -q
