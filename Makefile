BINARY      := otscout
CMD         := ./cmd/otscout
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/yoyowpuw/OTScout/internal/version.Version=$(VERSION) \
	-X github.com/yoyowpuw/OTScout/internal/version.Commit=$(COMMIT) \
	-X github.com/yoyowpuw/OTScout/internal/version.BuildDate=$(BUILD_DATE)

WEB_DIST := internal/server/webdist

.PHONY: all
all: check build

.PHONY: build
build: web
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

# build-nofront skips the frontend, which keeps the Go feedback loop fast while
# working on the backend. The embedded assets fall back to a placeholder page.
.PHONY: build-nofront
build-nofront:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

.PHONY: web
web:
	cd web && npm ci && npm run build
	rm -rf $(WEB_DIST)
	mkdir -p $(WEB_DIST)
	cp -r web/dist/* $(WEB_DIST)/

.PHONY: test
test:
	go test ./... -race -count=1

.PHONY: cover
cover:
	go test ./... -coverprofile=coverage.txt -covermode=atomic
	go tool cover -func=coverage.txt | tail -n 1

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -l -w .

.PHONY: fmt-check
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

.PHONY: check-text
check-text:
	go run ./scripts/check-text

.PHONY: check
check: fmt-check vet check-text test

.PHONY: web-check
web-check:
	cd web && npm ci && npm run typecheck && npm run lint && npm run test

.PHONY: hooks
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled from .githooks"

.PHONY: clean
clean:
	rm -rf bin dist coverage.txt $(WEB_DIST) web/dist web/node_modules
