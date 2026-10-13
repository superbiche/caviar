# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

PYTHON ?= python3
export GOTOOLCHAIN = local
export GOPROXY = off

.PHONY: test build
build:
	$(PYTHON) scripts/build.py

test:
	$(PYTHON) scripts/prepare.py
	$(PYTHON) scripts/check_provenance.py
	go test ./...
	go vet ./...
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) scripts/test_node.py
