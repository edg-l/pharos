#                                                                            #
# Pharos Makefile.                                                            #
#                                                                            #
# Conventions:                                                                #
# - `make` (no args) shows this help.                                         #
# - User-facing targets: build, run, install, fetch-spec-tests, conformance. #
# - Dev-facing targets: check, fmt, lint, test, ci, watch, doc, clean, pre-  #
#   commit, pre-push.                                                        #
#                                                                            #

# pipefail propagates failure from `cargo` through `| tee` so target exits
# nonzero on test failure. Required for long-running targets that capture
# output to a log file (CLAUDE.md long-running-tests policy).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO         ?= cargo
DATA_DIR      ?= ./data
GENESIS_PATH  ?=
CONFIG_DIR    ?=
SPEC_TESTS_TAG?= v1.6.1
LOGS          := target/test-logs

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
conformance: ## Run the conformance suite and write docs/conformance.md. Captured to $(LOGS)/conformance.log.
	@mkdir -p $(LOGS)
	$(CARGO) run --release -p pharos-conformance -- --write 2>&1 | tee $(LOGS)/conformance.log

## ----- Dev targets --------------------------------------------------------

.PHONY: check
check: ## cargo check the whole workspace (all targets). Captured to $(LOGS)/check.log.
	@mkdir -p $(LOGS)
	$(CARGO) check --workspace --all-targets 2>&1 | tee $(LOGS)/check.log

.PHONY: fmt
fmt: ## Apply rustfmt to the whole workspace.
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify rustfmt is satisfied (CI gate).
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint: ## clippy --workspace --all-targets -D warnings. Captured to $(LOGS)/lint.log.
	@mkdir -p $(LOGS)
	$(CARGO) clippy --workspace --all-targets -- -D warnings 2>&1 | tee $(LOGS)/lint.log

.PHONY: lint-fix
lint-fix: ## clippy --fix.
	$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

# --- Test targets ------------------------------------------------------------
# `make test`        — fast: workspace tests minus the slow m0_acceptance walk
# `make test-all`    — workspace tests INCLUDING m0_acceptance (use before commit/push)
# `make test-conf`   — m0_acceptance only
# `make test-crate`  — tests for one crate (CRATE=<name>)
#
# All long-running test targets capture full stdout+stderr to $(LOGS)/<name>.log
# per CLAUDE.md long-running-tests policy. NEVER run two of these concurrently.

.PHONY: test
test: ## Workspace tests minus m0_acceptance (fast). Captured to $(LOGS)/test.log.
	@mkdir -p $(LOGS)
	$(CARGO) test --workspace -- --skip m0_acceptance 2>&1 | tee $(LOGS)/test.log

.PHONY: test-all
test-all: ## Workspace tests INCLUDING m0_acceptance (slow). Captured to $(LOGS)/test-all.log.
	@mkdir -p $(LOGS)
	$(CARGO) test --workspace 2>&1 | tee $(LOGS)/test-all.log

.PHONY: test-conf
test-conf: ## Just the m0_acceptance conformance walk. Captured to $(LOGS)/test-conf.log.
	@mkdir -p $(LOGS)
	$(CARGO) test -p pharos-conformance --test m0_acceptance 2>&1 | tee $(LOGS)/test-conf.log

.PHONY: test-quick
test-quick: ## Library + bin unit tests only (no integration tests). Captured to $(LOGS)/test-quick.log.
	@mkdir -p $(LOGS)
	$(CARGO) test --workspace --lib --bins 2>&1 | tee $(LOGS)/test-quick.log

.PHONY: test-crate
test-crate: ## Run tests for one crate. CRATE=<name>. Captured to $(LOGS)/test-$(CRATE).log.
	@test -n "$(CRATE)" || { echo "error: set CRATE=<crate-name>"; exit 1; }
	@mkdir -p $(LOGS)
	$(CARGO) test -p $(CRATE) 2>&1 | tee $(LOGS)/test-$(CRATE).log

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
bench: ## Run criterion benches. Captured to $(LOGS)/bench.log. Records bench-history/<sha>.json.
	@mkdir -p $(LOGS) bench-history
	@: > $(LOGS)/bench.log
	$(CARGO) bench -p pharos-stf --bench process_block 2>&1 | tee -a $(LOGS)/bench.log
	$(CARGO) bench -p pharos-ssz --bench tree_hash_beacon_state 2>&1 | tee -a $(LOGS)/bench.log
	$(CARGO) bench -p pharos-node --bench gossip_validation 2>&1 | tee -a $(LOGS)/bench.log
	$(CARGO) bench -p pharos-network --bench rpc_roundtrip 2>&1 | tee -a $(LOGS)/bench.log
	./scripts/bench-summary.sh

.PHONY: bench-check
bench-check: ## Compare HEAD's bench-history/<sha>.json vs the latest baseline; fail on regression. Run on PERF_HOST after `make bench`. Tune with REGRESSION_PCT / NOISE_SIGMA. NOT part of `make ci` (benches are slow + PERF_HOST-only).
	./scripts/bench-check.sh

.PHONY: clean
clean: ## Clear the cargo target directory.
	$(CARGO) clean

## ----- CI / pre-commit ----------------------------------------------------

.PHONY: ci
ci: fmt-check lint check test-all ## Full CI gate: fmt + clippy + check + ALL tests (slow).

.PHONY: pre-commit
pre-commit: fmt lint test ## Pre-commit gate: fmt + clippy + fast workspace tests (skips m0_acceptance).

.PHONY: pre-push
pre-push: fmt-check lint test-all ## Pre-push gate: full workspace tests including m0_acceptance.

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
