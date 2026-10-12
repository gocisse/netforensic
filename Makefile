# netforensic Makefile
# Single-binary Go forensic tool with an embedded React web UI (web/dist).

BINARY      := netforensic
GO          := go
NPM         := npm
WEB_DIR     := web
DIST_DIR    := $(WEB_DIR)/dist
BUILD_DIR   := build
RELEASE_DIR := release
LDFLAGS     := -s -w
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The module is pure Go (no cgo), so release builds cross-compile cleanly.
PLATFORMS   := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "netforensic - pcap forensic analyzer"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

# ------------------------------------------------------------------ build

.PHONY: build
build: frontend backend ## Build the frontend, then the single binary

.PHONY: frontend
frontend: $(WEB_DIR)/node_modules ## Build the React UI into web/dist
	cd $(WEB_DIR) && $(NPM) run build

$(WEB_DIR)/node_modules: $(WEB_DIR)/package-lock.json
	cd $(WEB_DIR) && $(NPM) ci
	@touch $@

.PHONY: backend
backend: ## Build the Go binary (embeds whatever is in web/dist)
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/netforensic

.PHONY: dev
dev: $(WEB_DIR)/node_modules ## Run the Vite dev server
	cd $(WEB_DIR) && $(NPM) run dev

.PHONY: run
run: build ## Build and serve the web UI on :8181
	./$(BINARY) --web :8181

.PHONY: run-cli
run-cli: backend ## Analyze a capture: make run-cli ARGS="testdata/SYN_Flood.pcap"
	./$(BINARY) $(ARGS)

# ------------------------------------------------------------------- test

.PHONY: test
test: test-go test-web ## Run all tests

.PHONY: test-go
test-go: ## Go tests with race detector and coverage
	$(GO) test -race -cover ./...

.PHONY: test-web
test-web: $(WEB_DIR)/node_modules ## Frontend unit tests
	cd $(WEB_DIR) && $(NPM) test

.PHONY: coverage
coverage: ## HTML coverage report in build/coverage.html
	@mkdir -p $(BUILD_DIR)
	$(GO) test -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "report: $(BUILD_DIR)/coverage.html"

# ---------------------------------------------------------------- quality

.PHONY: fmt
fmt: ## gofmt all Go files
	gofmt -w cmd internal $(WEB_DIR)/embed.go $(WEB_DIR)/embed_test.go

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is not gofmt-clean
	@out="$$(gofmt -l cmd internal $(WEB_DIR)/*.go)"; \
	if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint-web
lint-web: $(WEB_DIR)/node_modules ## oxlint and the spacing-scale check
	cd $(WEB_DIR) && $(NPM) run lint && $(NPM) run check:spacing

.PHONY: check
check: fmt-check vet lint-web test ## Everything CI should run

# ---------------------------------------------------------------- release

.PHONY: release
release: frontend ## Cross-compile and package one .zip per platform in release/
	@command -v zip >/dev/null || { echo "zip is required"; exit 1; }
	@rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = windows ] && ext=".exe"; \
		name=$(BINARY)-$(VERSION)-$$os-$$arch; \
		stage=$(RELEASE_DIR)/$$name; \
		echo "packaging $$name.zip"; \
		mkdir -p $$stage && \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" \
			-o $$stage/$(BINARY)$$ext ./cmd/netforensic && \
		cp README.md $$stage/ && \
		(cd $(RELEASE_DIR) && zip -qr $$name.zip $$name) && \
		rm -rf $$stage || exit 1; \
	done
	@cd $(RELEASE_DIR) && { command -v sha256sum >/dev/null && sha256sum *.zip || shasum -a 256 *.zip; } > SHA256SUMS
	@ls -lh $(RELEASE_DIR)

.PHONY: install
install: frontend ## go install the binary into GOPATH/bin
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/netforensic

# ------------------------------------------------------------------ clean

# web/dist/.gitkeep is tracked and keeps //go:embed compiling on a fresh clone,
# so clean removes the build output but never the directory or the keep file.
.PHONY: clean
clean: ## Remove the binary, build/, release/ and built UI assets
	rm -rf $(BINARY) $(BUILD_DIR) $(RELEASE_DIR)
	find $(DIST_DIR) -mindepth 1 ! -name .gitkeep -delete

.PHONY: clean-all
clean-all: clean ## Also remove web/node_modules
	rm -rf $(WEB_DIR)/node_modules
