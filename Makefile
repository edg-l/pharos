#                                                                            #
# Pharos Makefile.                                                            #
#                                                                            #
# Conventions:                                                                #
# - `make` (no args) shows this help.                                         #
# - User-facing targets: build, run, install, fetch-spec-tests, conformance. #
# - Dev-facing targets: check, fmt, lint, test, ci, watch, doc, clean, pre-  #
#   commit, pre-push.                                                        #
#                                                                            #

CARGO         ?= cargo
DATA_DIR      ?= ./data
GENESIS_PATH  ?=
CONFIG_DIR    ?=
SPEC_TESTS_TAG?= v1.6.1

# Forward extra args after `--` to cargo. Example: `make run ARGS="--metrics"`.
ARGS ?=

.DEFAULT_GOAL := help

# ----- Help ----------------------------------------------------------------

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "; printf "Pharos targets\n\nUsage: make <target> [VAR=value]\n\n"} \
		/^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2} \
		/^## / {printf "\n\033[1m%s\033[0m\n", substr($$0, 4)}' $(MAKEFILE_LIST)

## ----- User targets -------------------------------------------------------

.PHONY: build
build: ## Release build of the beacon node + validator client.
	$(CARGO) build --release --bin pharos --bin pharos-vc

.PHONY: build-debug
build-debug: ## Debug build of the beacon node + validator client.
	$(CARGO) build --bin pharos --bin pharos-vc

.PHONY: install
install: ## Install pharos + pharos-vc into ~/.cargo/bin.
	$(CARGO) install --path crates/pharos-node --bin pharos
	$(CARGO) install --path crates/pharos-validator --bin pharos-vc

.PHONY: run
run: ## Run the beacon node. Requires GENESIS_PATH=<file.ssz>. Optional: DATA_DIR, CONFIG_DIR, ARGS.
	@test -n "$(GENESIS_PATH)" || { echo "error: set GENESIS_PATH=<beacon-state.ssz>"; exit 1; }
	$(CARGO) run --release -p pharos-node -- \
		--data-dir $(DATA_DIR) \
		--genesis-state-path $(GENESIS_PATH) \
		$(if $(CONFIG_DIR),--config-dir $(CONFIG_DIR)) \
		$(ARGS)

.PHONY: run-vc
run-vc: ## Run the validator client. Pass-through ARGS.
	$(CARGO) run --release -p pharos-validator -- $(ARGS)

.PHONY: fetch-spec-tests
fetch-spec-tests: ## Download consensus-spec-tests fixtures to ~/.cache/pharos-spec-tests.
	SPEC_TESTS_TAG=$(SPEC_TESTS_TAG) ./scripts/fetch-spec-tests.sh

.PHONY: conformance
conformance: ## Run the conformance suite and write docs/conformance.md.
	$(CARGO) run --release -p pharos-conformance -- --write

## ----- Dev targets --------------------------------------------------------

.PHONY: check
check: ## cargo check the whole workspace (all targets).
	$(CARGO) check --workspace --all-targets

.PHONY: fmt
fmt: ## Apply rustfmt to the whole workspace.
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify rustfmt is satisfied (CI gate).
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint: ## clippy --workspace --all-targets -D warnings.
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: lint-fix
lint-fix: ## clippy --fix.
	$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

.PHONY: test
test: ## Run the full test suite.
	$(CARGO) test --workspace

.PHONY: test-quick
test-quick: ## Run library + bin unit tests only (skip integration tests).
	$(CARGO) test --workspace --lib --bins

.PHONY: test-crate
test-crate: ## Run tests for one crate. CRATE=<name>.
	@test -n "$(CRATE)" || { echo "error: set CRATE=<crate-name>"; exit 1; }
	$(CARGO) test -p $(CRATE)

.PHONY: doc
doc: ## Build rustdoc with all features and open it.
	$(CARGO) doc --workspace --no-deps --open

.PHONY: doc-check
doc-check: ## Build rustdoc with -D warnings (CI gate).
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps

.PHONY: watch
watch: ## cargo-watch: rerun `check` on every save. Install: cargo install cargo-watch.
	$(CARGO) watch -x "check --workspace --all-targets"

.PHONY: watch-test
watch-test: ## cargo-watch: rerun tests on every save. CRATE=<name> narrows the scope.
	$(CARGO) watch -x "test $(if $(CRATE),-p $(CRATE),--workspace)"

.PHONY: bench
bench: ## Run criterion benches. (No benches yet; M11.)
	$(CARGO) bench --workspace

.PHONY: clean
clean: ## Clear the cargo target directory.
	$(CARGO) clean

## ----- CI / pre-commit ----------------------------------------------------

.PHONY: ci
ci: fmt-check lint check test ## Full CI gate: fmt, clippy, check, test.

.PHONY: pre-commit
pre-commit: fmt lint test-quick ## Fast pre-commit gate: fmt + clippy + unit tests.

.PHONY: pre-push
pre-push: fmt-check lint test ## Pre-push gate: same as CI without the doc-check.

## ----- Utility ------------------------------------------------------------

.PHONY: tree
tree: ## Show the workspace crate graph.
	$(CARGO) tree --workspace --depth 1

.PHONY: outdated
outdated: ## Report outdated dependencies. Install: cargo install cargo-outdated.
	$(CARGO) outdated --workspace --root-deps-only

.PHONY: audit
audit: ## Run cargo-audit against the lockfile. Install: cargo install cargo-audit.
	$(CARGO) audit

.PHONY: deny
deny: ## Run cargo-deny (licenses, advisories, bans). Install: cargo install cargo-deny.
	$(CARGO) deny check

.PHONY: unused
unused: ## Find unused dependencies. Install: cargo install cargo-machete.
	$(CARGO) machete

## ----- Docker -------------------------------------------------------------

DOCKER_IMAGE ?= pharos
DOCKER_TAG   ?= dev

.PHONY: docker-build
docker-build: ## Build the docker image. Override with DOCKER_IMAGE / DOCKER_TAG.
	DOCKER_BUILDKIT=1 docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-run
docker-run: ## Run the container. Requires GENESIS_PATH=<file>. Forwards ARGS.
	@test -n "$(GENESIS_PATH)" || { echo "error: set GENESIS_PATH=<beacon-state.ssz>"; exit 1; }
	docker run --rm -it \
		-v $(CURDIR)/data:/var/lib/pharos \
		-v $(GENESIS_PATH):/genesis.ssz:ro \
		-p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		--genesis-state-path /genesis.ssz \
		$(ARGS)

.PHONY: print-vars
print-vars: ## Print the Makefile variables (for debugging).
	@echo "CARGO          = $(CARGO)"
	@echo "DATA_DIR       = $(DATA_DIR)"
	@echo "GENESIS_PATH   = $(GENESIS_PATH)"
	@echo "CONFIG_DIR     = $(CONFIG_DIR)"
	@echo "SPEC_TESTS_TAG = $(SPEC_TESTS_TAG)"
	@echo "ARGS           = $(ARGS)"
	@echo "DOCKER_IMAGE   = $(DOCKER_IMAGE)"
	@echo "DOCKER_TAG     = $(DOCKER_TAG)"
