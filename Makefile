# sarifix developer tasks. `make check` runs everything CI runs.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

BIN       := bin/sarifix
PKG       := github.com/rossedman/sarifix
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
COVER_MIN := 90
FUZZTIME  ?= 30s
MKDOCS    := uv run --no-project --with-requirements requirements-docs.txt mkdocs

.PHONY: build test cover bench bench-smoke fuzz lint fmt docs docs-build docs-serve docs-check check-cmds doccheck vuln release-check scan check clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/sarifix

test:
	go test -race -coverprofile=coverage.out ./...

# Coverage gate on hand-written code: generated files and examples/ are
# filtered out of the profile before totaling.
cover: test
	{ head -1 coverage.out; grep -v '^mode:' coverage.out | grep -vFf <(go run ./tools/generated ./...) | grep -v '/examples/' || true; } > coverage.hand.out
	go tool cover -func=coverage.hand.out | tail -1
	go tool cover -func=coverage.hand.out | awk '/^total:/ {sub("%","",$$3); if ($$3+0 < $(COVER_MIN)) {print "coverage " $$3 "% < $(COVER_MIN)%"; exit 1}}'

# Saves results so runs can be compared with benchstat.
bench:
	mkdir -p bench
	go test -run='^$$' -bench=. -benchmem -count=6 ./... | tee bench/$(shell date -u +%Y%m%dT%H%M%S).txt

bench-smoke:
	go test -run='^$$' -bench=. -benchtime=1x ./...

# Runs every Fuzz target for FUZZTIME.
fuzz:
	for pkg in $$(go list ./...); do \
	  for t in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
	    echo "== $$pkg $$t"; go test -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) $$pkg; \
	  done; \
	done

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

check-cmds:
	./tools/check-cmds.sh

doccheck:
	go run ./tools/doccheck ./...

vuln:
	govulncheck ./...

docs:
	go run ./tools/gendocs

# Fails when the generated reference pages differ from what is staged or
# committed, or when a page is new and untracked.
docs-check: docs
	@if ! git diff --quiet -- docs/reference || [ -n "$$(git ls-files --others --exclude-standard -- docs/reference)" ]; then \
	  git status --short -- docs/reference; \
	  echo "docs/reference is stale: run 'make docs' and commit the result"; exit 1; \
	fi

docs-build: docs
	$(MKDOCS) build --strict

docs-serve: docs
	$(MKDOCS) serve

release-check:
	goreleaser check
	goreleaser release --snapshot --clean --skip=sign,docker

# Runs the configured scanners over this repo (see sarifix.yaml).
scan: build
	$(BIN) scan

check: build lint cover check-cmds doccheck vuln bench-smoke docs-check docs-build release-check
	FUZZTIME=5s $(MAKE) fuzz

clean:
	rm -rf bin dist site coverage.out coverage.hand.out
