#!/usr/bin/env bash

set -Eeuo pipefail

run_step() {
    printf '\n==> %s\n' "$*"
    "$@"
}

run_step cargo fmt --all -- --check
run_step cargo metadata --locked --no-deps --format-version 1
run_step cargo check --locked --all-targets
run_step cargo test --locked --test level2_storage_spike -- --nocapture
run_step cargo test --locked --all-targets
run_step python3 -m py_compile scripts/verify_contract.py scripts/verify_meta.py
run_step python3 scripts/verify_contract.py --strict-coverage
