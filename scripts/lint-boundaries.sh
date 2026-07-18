#!/usr/bin/env bash
# Structural lints: the machine-checked boundaries from docs/standards.md.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. logic has zero dependencies: its tree is exactly one line — itself.
tree="$(cargo tree -p conditional-tasks-logic --edges normal --prefix none)"
if [ "$(printf '%s\n' "$tree" | wc -l)" -ne 1 ]; then
    echo "FAIL: conditional-tasks-logic must have zero dependencies, got:" >&2
    printf '%s\n' "$tree" >&2
    exit 1
fi

# 2. logic sources never touch I/O or the IC SDK.
if grep -rEn 'ic_cdk|std::(fs|net|time)|reqwest' logic/src/; then
    echo "FAIL: forbidden I/O reference in logic/src" >&2
    exit 1
fi

# 3. logic knows nothing about the chain or cryptography.
if grep -riEn 'solana|ed25519|sha256|candid' logic/src/; then
    echo "FAIL: chain or crypto reference in logic/src" >&2
    exit 1
fi

# 4. the canister moves no money and reads no external chains.
if grep -riEn 'transfer|approve|splitter|treasury' canister/src/; then
    echo "FAIL: money reference in canister/src" >&2
    exit 1
fi
if grep -rn 'http_request' canister/src/; then
    echo "FAIL: HTTPS outcall in canister/src" >&2
    exit 1
fi

# 5. the update surface is frozen: every non-query .did method is allowlisted.
allow='register_task|accept|decline|ready|vote|set_profile|operator_refund'
if grep '\->' canister/conditional-tasks.did | grep -v 'service :' | grep -v 'query' \
    | grep -vE "^[[:space:]]*($allow)[[:space:]]*:"; then
    echo "FAIL: update method outside the allowlist in conditional-tasks.did" >&2
    exit 1
fi

# 6. authorization is never by caller principal.
if grep -rn 'caller' canister/src/; then
    echo "FAIL: caller-based reference in canister/src" >&2
    exit 1
fi

echo "boundaries OK"
