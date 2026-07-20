#!/usr/bin/env bash
# G4 e2e (docs/build-plan.md): canister verdicts against the real devnet.
#
# One local replica runs both crown-index (reading the real devnet) and the
# game canister (the replica's threshold key). Three acts, strictly one
# escrow at a time — that keeps the peak USDC and SOL-rent draw minimal:
#   1. a direct donate gives the donor the reputation they later vote with;
#   2. task B: register → decline → cancel verdict; the cancel signature
#      does not open settle (a negative test against the contract);
#      claim(1) — the money returns, no Settled;
#   3. escrow C (outside the game, short deadline): refund() — no Settled;
#   4. task A: register → accept → done → vote → settle verdict →
#      claim(0) with the canister's signature → Settled → the book credits
#      the DONOR;
#   5. the book total is exact, zero anomalies.
#
# With the testnet profile (voting_period = 120 s) and devnet finality in
# seconds the full run takes ~10 minutes.
#
# Usage: scripts/e2e-devnet.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SOL_RPC_URL=${SOL_RPC_URL:-https://api.devnet.solana.com}
SOL_DONOR_KEYPAIR=${SOL_DONOR_KEYPAIR:-$HOME/.cache/crown-e2e/donor.json}
# The recipient's permanent key: payouts and its ATA rent stay recoverable
# between runs instead of burning with a throwaway key.
SOL_RECIPIENT_KEYPAIR=${SOL_RECIPIENT_KEYPAIR:-$HOME/.cache/crown-e2e/recipient.json}
CORE=$(cd ../../Crown-Core && pwd)

VOTING_PERIOD=$(grep "^voting_period" config/testnet.toml | cut -d"=" -f2 | tr -d " ")
FEE_BPS=$(grep "^fee_bps" config/testnet.toml | cut -d"=" -f2 | tr -d " ")
FEE_WALLET=$(grep "^fee_wallet" config/testnet.toml | cut -d'"' -f2)
MARGIN=259200
# Amounts are sized to the devnet wallet; the donate sits exactly at the
# vote weight floor.
SOL_DONATE=100000
A_GROSS=30000
B_GROSS=10000
C_GROSS=5000
DURATION=3600
NONCE=$(date +%s)

# ---- tooling ------------------------------------------------------------

participant() { cargo run -q -p conditional-tasks --example participant -- "$@"; }
driver() { (cd e2e/solana-driver && cargo run -q -- "$@"); }

blob_hex() { # hex -> candid-блоб \xx
    python3 -c "import sys; h=sys.argv[1]; print(''.join(f'\\\\{h[i:i+2]}' for i in range(0,len(h),2)))" "$1"
}
b58_hex() { # base58 -> hex
    python3 - "$1" <<'EOF'
import sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
s = sys.argv[1]; n = 0
for c in s: n = n * 58 + A.index(c)
b = n.to_bytes(32, "big")
print(b.hex())
EOF
}
opt_blob_hex() { # candid json (opt blob) со stdin -> hex или пусто
    python3 -c "
import json, sys
v = json.load(sys.stdin)
while isinstance(v, list) and len(v) == 1 and isinstance(v[0], (list, dict)): v = v[0]
if not v: print(); sys.exit()
if isinstance(v, list) and all(isinstance(b, int) for b in v):
    print(''.join(f'{b:02x}' for b in v))
elif isinstance(v, str):
    print(v.removeprefix('0x'))
else:
    print()
"
}

game_call() { dfx canister call conditional-tasks "$@"; }
resolver_hex() { game_call get_resolver '("solana-devnet")' --query --output json | opt_blob_hex; }
reputation() { # payer_blob recipient_blob
    dfx canister call crown-index get_reputation "(\"solana-devnet\", blob \"$1\", blob \"$2\")" \
        --query | tr -d '(_ )' | sed 's/:nat//'
}
verdict_json() { # task_id_hex
    game_call get_verdict "(\"solana-devnet\", blob \"$(blob_hex "$1")\")" --query --output json
}
verdict_signature() { # task_id_hex -> sig hex или пусто
    verdict_json "$1" | python3 -c "
import json, sys
v = json.load(sys.stdin)
while isinstance(v, list) and len(v) == 1: v = v[0]
if not isinstance(v, dict): print(); sys.exit()
sig = v.get('signature')
while isinstance(sig, list) and len(sig) == 1 and isinstance(sig[0], list): sig = sig[0]
if isinstance(sig, list) and sig and all(isinstance(b, int) for b in sig):
    print(''.join(f'{b:02x}' for b in sig))
else:
    print()
"
}

# The protocol message is UTF-8 text with newlines (auth.rs), so it travels
# by file: a shell argument would mangle it, and one stray byte is a different
# message.
sign_and_call() { # method task_id_hex signer_keypair   (method == action word)
    local method=$1 task_id=$2 keypair=$3
    local msg sig
    msg=$(mktemp); trap 'rm -f "$msg"' RETURN
    participant task-message solana-devnet "$GAME_ID" "$task_id" "$method" > "$msg"
    sig=$(participant sol-sign "$keypair" "$msg")
    game_call "$method" "(record { chain = \"solana-devnet\"; task_id = blob \"$(blob_hex "$task_id")\"; signature = blob \"$(blob_hex "$sig")\" })"
}

# ---- config -------------------------------------------------------------

core_value() { grep "^$1" "$CORE/config/testnet.toml" | head -1 | cut -d'=' -f2- | tr -d ' "[]'; }
SPLITTER=$(core_value splitter)

[ -f "$SOL_RECIPIENT_KEYPAIR" ] || solana-keygen new --no-bip39-passphrase --silent -o "$SOL_RECIPIENT_KEYPAIR"
RECIPIENT=$(solana-keygen pubkey "$SOL_RECIPIENT_KEYPAIR")
DONOR=$(solana-keygen pubkey "$SOL_DONOR_KEYPAIR")
DONOR_HEX=$(b58_hex "$DONOR")
RECIPIENT_HEX=$(b58_hex "$RECIPIENT")

echo "donor=$DONOR recipient=$RECIPIENT"

# ---- replica and canisters ------------------------------------------------

echo "== build crown-index (local profile) and start the replica"
SOL_SEED=$(curl -s "$SOL_RPC_URL" -X POST -H "Content-Type: application/json" -d "{
    \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",
    \"params\":[\"$SPLITTER\", {\"limit\": 1}]}" \
    | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(r[0]['signature'] if r else '')")
# Empty when the splitter has no signatures the RPC still serves (fresh or
# pruned devnet): start ingest with no cursor and read the run's own donates.
if [ -n "$SOL_SEED" ]; then
    SEED_FIELD="cursor_seed = opt vec { record { \"solana-devnet\"; \"$SOL_SEED\" } };"
else
    SEED_FIELD=""
fi
echo "cursor seed: ${SOL_SEED:-<none, ingest from scratch>}"

cat > "$CORE/config/local.toml" <<EOF
# Generated by conditional-tasks/scripts/e2e-devnet.sh; never committed.
[[chain]]
id        = "solana-devnet"
source    = "Custom:$SOL_RPC_URL"
consensus = "equality"
splitter  = "$SPLITTER"
usdc      = "$(core_value usdc)"
factories = ["$(core_value factories)"]
EOF
(cd "$CORE" && CROWN_PROFILE=local \
    CC_wasm32_unknown_unknown="$CORE/scripts/wasm-cc.sh" \
    AR_wasm32_unknown_unknown="${AR_WASM32:-$HOME/.cache/solana/v1.53/platform-tools/llvm/bin/llvm-ar}" \
    cargo build --target wasm32-unknown-unknown --release -p crown-index)

# THE LOCAL REPLICA IS SHARED AND IS NEVER WIPED HERE: threshold keys born by
# earlier runs may still resolve live devnet escrows. Reuse a running replica
# or start one over the existing state, and leave it up.
if ! dfx ping >/dev/null 2>&1; then
    echo "== starting the local replica over the EXISTING state (no --clean)"
    dfx start --background >/dev/null 2>&1
    for _ in $(seq 1 30); do dfx ping >/dev/null 2>&1 && break; sleep 1; done
fi
dfx ping >/dev/null 2>&1 || { echo "FAIL: replica did not come up" >&2; exit 1; }

dfx deploy sol_rpc
dfx deploy crown-index --argument "(opt record {
    sol_rpc = opt principal \"$(dfx canister id sol_rpc)\";
    $SEED_FIELD })"
dfx ledger fabricate-cycles --canister crown-index --t 100 >/dev/null
dfx deploy conditional-tasks --argument "(opt record {
    crown_index = opt principal \"$(dfx canister id crown-index)\" })"
dfx ledger fabricate-cycles --canister conditional-tasks --t 100 >/dev/null
GAME_ID=$(dfx canister id conditional-tasks)

echo "== resolver key"
RESOLVER=""
for _ in $(seq 1 60); do
    RESOLVER=$(resolver_hex)
    [ -n "$RESOLVER" ] && break
    sleep 2
done
[ -n "$RESOLVER" ] || { echo "FAIL: resolver key never warmed"; exit 1; }
echo "resolver=$RESOLVER"

# ---- chain helpers ---------------------------------------------------------

register_task() { # gross deadline task_id_hex nonce
    local gross=$1 deadline=$2 task_id=$3 nonce=$4
    local text_hash msg sig
    text_hash=$(python3 -c "import hashlib; print(hashlib.sha256(b'e2e task $NONCE \x00 salt').hexdigest())")
    msg=$(mktemp); trap 'rm -f "$msg"' RETURN
    participant task-message solana-devnet "$GAME_ID" "$task_id" register "$text_hash" "$DURATION" > "$msg"
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$msg")
    game_call register_task "(record {
        chain = \"solana-devnet\";
        donor = blob \"$(blob_hex "$DONOR_HEX")\";
        recipient = blob \"$(blob_hex "$RECIPIENT_HEX")\";
        gross = $gross;
        deadline = $deadline;
        resolver = blob \"$(blob_hex "$RESOLVER")\";
        nonce = $nonce;
        duration = $DURATION;
        text_hash = blob \"$(blob_hex "$text_hash")\";
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}
vote_done() { # task_id_hex
    local task_id=$1 msg sig
    msg=$(mktemp); trap 'rm -f "$msg"' RETURN
    participant task-message solana-devnet "$GAME_ID" "$task_id" vote done > "$msg"
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$msg")
    game_call vote "(record { chain = \"solana-devnet\"; task_id = blob \"$(blob_hex "$task_id")\";
        voter = blob \"$(blob_hex "$DONOR_HEX")\"; choice = variant { done };
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}

# ---- acts -----------------------------------------------------------------

echo "== direct donate: the reputation the donor will vote with"
driver donate "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$SOL_DONATE"
DONOR_BLOB=$(blob_hex "$DONOR_HEX"); RECIPIENT_BLOB=$(blob_hex "$RECIPIENT_HEX")

DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))

echo "== act B (cancel): create, register, decline"
B=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$B_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" "$NONCE")
B_HEX=$(b58_hex "$B")
echo "escrow B=$B"
register_task "$B_GROSS" "$DEADLINE" "$B_HEX" "$NONCE"
sign_and_call decline "$B_HEX" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok

SIG_B=""
for _ in $(seq 1 20); do
    SIG_B=$(verdict_signature "$B_HEX")
    [ -n "$SIG_B" ] && break
    sleep 10
done
[ -n "$SIG_B" ] || { echo "FAIL: cancel signature never appeared"; exit 1; }

echo "== negative: the cancel signature does not open settle, on the real contract"
if driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$B" 0 "$SIG_B" "$RESOLVER" >/dev/null 2>&1; then
    echo "FAIL: the cancel signature opened outcome 0"; exit 1
fi

echo "== claim(1): the money returns, no Settled"
BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$B" 1 "$SIG_B" "$RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$DONOR")" = "$((BEFORE + B_GROSS))" ] || { echo "FAIL: cancel refund"; exit 1; }

echo "== act C, outside the game: refund() moves money, never the book"
C=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$C_GROSS" $(($(date +%s) + 25)) "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 1)))
echo "escrow C=$C"
sleep 30
driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$C"

echo "== the donate ingest must land before the vote"
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")
    echo "reputation: $REP/$SOL_DONATE"
    [ "$REP" = "$SOL_DONATE" ] && break
    sleep 10
done
[ "$REP" = "$SOL_DONATE" ] || { echo "FAIL: donate not ingested"; exit 1; }

echo "== act A (settle): create, register, accept, ready, vote"
DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))
A=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$A_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 2)))
A_HEX=$(b58_hex "$A")
echo "escrow A=$A"
register_task "$A_GROSS" "$DEADLINE" "$A_HEX" $((NONCE + 2))
sign_and_call accept "$A_HEX" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok
sign_and_call ready "$A_HEX" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok
VOTING_STARTED=$(date +%s)
vote_done "$A_HEX"

echo "== wait out the voting period, then the settle signature"
ELAPSED=$(($(date +%s) - VOTING_STARTED))
[ "$ELAPSED" -lt "$VOTING_PERIOD" ] && { echo "sleeping $((VOTING_PERIOD - ELAPSED + 60))s"; sleep $((VOTING_PERIOD - ELAPSED + 60)); }
SIG_A=""
for _ in $(seq 1 30); do
    SIG_A=$(verdict_signature "$A_HEX")
    [ -n "$SIG_A" ] && break
    sleep 10
done
[ -n "$SIG_A" ] || { echo "FAIL: settle signature never appeared"; exit 1; }
verdict_json "$A_HEX" | grep -q settle || { echo "FAIL: verdict is not settle"; exit 1; }

echo "== claim(0): the canister's signature moves real money through the splitter"
RECIPIENT_BEFORE=$(driver balance "$SOL_RPC_URL" "$RECIPIENT")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$A" 0 "$SIG_A" "$RESOLVER"
A_FEE=$((A_GROSS * FEE_BPS / 10000))
A_PAYOUT=$((A_GROSS - A_FEE))
[ "$(driver balance "$SOL_RPC_URL" "$RECIPIENT")" = "$((RECIPIENT_BEFORE + A_PAYOUT))" ] || { echo "FAIL: payout"; exit 1; }

echo "== the book credits the DONOR for the game settlement"
# The book sees exactly what reached the recipient: the direct donate whole,
# the game settlement net of the game's fee.
TOTAL=$((SOL_DONATE + A_GROSS - A_GROSS * FEE_BPS / 10000))
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")
    echo "book: $REP/$TOTAL"
    [ "$REP" = "$TOTAL" ] && break
    sleep 10
done
[ "$REP" = "$TOTAL" ] || { echo "FAIL: settlement not attributed to the donor"; exit 1; }

ANOMALIES=$(dfx canister call crown-index get_anomaly_count --query | tr -d '(_ )' | sed 's/:nat64//')
[ "$ANOMALIES" = "0" ] || { echo "FAIL: anomaly count = $ANOMALIES"; exit 1; }

echo "e2e devnet OK"
