# goup development Makefile.
#
# The headline target is `make demo`: it builds goup, runs the test suite,
# then launches goup against the example module in example/ so you can see
# the real UI with real (outdated, and in one case vulnerable) dependencies.

BINARY      := bin/goup
EXAMPLE_DIR := example
GO          ?= go

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the goup binary into bin/
	$(GO) build -o $(BINARY) ./cmd/goup
	@echo "built $(BINARY)"

.PHONY: test
test: ## Run the full test suite
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run the test suite with the race detector
	$(GO) test -race ./...

.PHONY: check
check: ## Format check, vet, and tests
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	$(GO) vet ./...
	$(GO) test ./...

# The example module pins deliberately old dependency versions so goup has
# something to show. This target restores that state, because running the
# demo and choosing "upgrade" rewrites example/go.mod.
.PHONY: example-reset
example-reset: ## Restore the example module's outdated pins
	cd $(EXAMPLE_DIR) && GOFLAGS=-mod=mod $(GO) get \
		github.com/google/uuid@v1.3.0 \
		github.com/sirupsen/logrus@v1.9.0 \
		github.com/spf13/cobra@v1.7.0 \
		github.com/stretchr/testify@v1.8.0 \
		github.com/rs/zerolog@v1.29.0 \
		github.com/joho/godotenv@v1.5.1 \
		golang.org/x/text@v0.3.7 >/dev/null
	@cd $(EXAMPLE_DIR) && GOFLAGS=-mod=mod $(GO) mod tidy >/dev/null 2>&1 || true
	@echo "example module pins restored"

.PHONY: demo
demo: build test ## Build, test, then run goup against the example module
	@echo
	@echo "──────────────────────────────────────────────────────────────"
	@echo " Launching goup against $(EXAMPLE_DIR)/"
	@echo " Keys: Space select · d security details · s skipped · q quit"
	@echo "──────────────────────────────────────────────────────────────"
	@echo
	@cd $(EXAMPLE_DIR) && ../$(BINARY)

.PHONY: demo-scripted
demo-scripted: build ## Non-interactive demo (scripted pty), prints the rendered UI
	@cd $(EXAMPLE_DIR) && ./demo.sh ../$(BINARY)

.PHONY: demo-security
demo-security: build ## Like demo, but filtered to vulnerable dependencies
	@cd $(EXAMPLE_DIR) && ../$(BINARY) --security

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin
