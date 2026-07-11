#!/usr/bin/env bash
# Integration tests: the canister inside PocketIC (docs/build-plan.md G2+).
# Builds the release wasm, finds the pocket-ic server that ships with dfx,
# and runs the #[ignore]-marked tests against it.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --target wasm32-unknown-unknown --release -p conditional-tasks

if [ -z "${POCKET_IC_BIN:-}" ]; then
    POCKET_IC_BIN="$(ls -d "$HOME"/.cache/dfinity/versions/*/pocket-ic 2>/dev/null | sort -V | tail -1)"
    export POCKET_IC_BIN
fi
[ -x "${POCKET_IC_BIN:-}" ] || {
    echo "pocket-ic binary not found; install dfx or set POCKET_IC_BIN" >&2
    exit 1
}

cargo test -p conditional-tasks --test g2 -- --include-ignored
