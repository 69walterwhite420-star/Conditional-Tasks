#!/usr/bin/env bash
# G4 e2e (docs/build-plan.md): вердикты канистры против реального devnet.
#
# На одной локальной реплике: crown-index (читает реальный devnet) и игровая
# канистра (threshold-ключ локальной реплики). Три акта, строго по одному
# эскроу за раз — так пик по USDC и SOL-ренте минимален:
#   1. прямой донат даёт донору репутацию — ей он потом голосует;
#   2. задание B: register → decline → вердикт cancel; подпись cancel не
#      открывает settle (негативный тест против контракта); claim(1) —
#      деньги вернулись, Settled нет;
#   3. эскроу C (вне игры, короткий дедлайн): refund() — Settled нет;
#   4. задание A: register → accept → done → голос → вердикт settle →
#      claim(0) с подписью канистры → Settled → книга начисляет ДОНОРУ;
#   5. итог книги точен, аномалий ноль.
#
# С testnet-профилем (voting_period = 120 с) и финальностью devnet в секунды
# полный прогон занимает ~10 минут.
#
# Usage: scripts/e2e-devnet.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SOL_RPC_URL=${SOL_RPC_URL:-https://api.devnet.solana.com}
SOL_DONOR_KEYPAIR=${SOL_DONOR_KEYPAIR:-$HOME/.cache/crown-e2e/donor.json}
# Постоянный ключ стримера: выплаты и рента его ATA остаются возвращаемыми
# между прогонами, а не сгорают с одноразовым ключом.
SOL_STREAMER_KEYPAIR=${SOL_STREAMER_KEYPAIR:-$HOME/.cache/crown-e2e/streamer.json}
CORE=$(cd ../../Crown-Core && pwd)

VOTING_PERIOD=$(grep "^voting_period" config/testnet.toml | cut -d"=" -f2 | tr -d " ")
MARGIN=259200
# Суммы ужаты под остаток devnet-кошелька; донат ровно на пороге веса голоса.
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
reputation() { # payer_blob streamer_blob
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

sign_and_call() { # method task_id_hex action payload_hex signer_keypair
    local method=$1 task_id=$2 action=$3 payload=$4 keypair=$5
    local message sig
    message=$(participant task-message solana-devnet "$GAME_ID" "$task_id" "$action" "$payload")
    sig=$(participant sol-sign "$keypair" "$message")
    game_call "$method" "(record { chain = \"solana-devnet\"; task_id = blob \"$(blob_hex "$task_id")\"; signature = blob \"$(blob_hex "$sig")\" })"
}

# ---- config -------------------------------------------------------------

core_value() { grep "^$1" "$CORE/config/testnet.toml" | head -1 | cut -d'=' -f2- | tr -d ' "[]'; }
SPLITTER=$(core_value splitter)

[ -f "$SOL_STREAMER_KEYPAIR" ] || solana-keygen new --no-bip39-passphrase --silent -o "$SOL_STREAMER_KEYPAIR"
STREAMER=$(solana-keygen pubkey "$SOL_STREAMER_KEYPAIR")
DONOR=$(solana-keygen pubkey "$SOL_DONOR_KEYPAIR")
DONOR_HEX=$(b58_hex "$DONOR")
STREAMER_HEX=$(b58_hex "$STREAMER")

echo "donor=$DONOR streamer=$STREAMER"

# ---- replica and canisters ------------------------------------------------

echo "== build crown-index (local profile) and start the replica"
SOL_SEED=$(curl -s "$SOL_RPC_URL" -X POST -H "Content-Type: application/json" -d "{
    \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",
    \"params\":[\"$SPLITTER\", {\"limit\": 1}]}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['result'][0]['signature'])")
echo "cursor seed: $SOL_SEED"

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

dfx stop >/dev/null 2>&1 || true
dfx start --clean --background
trap 'dfx stop >/dev/null 2>&1 || true' EXIT
dfx deploy sol_rpc
dfx deploy crown-index --argument "(opt record {
    sol_rpc = opt principal \"$(dfx canister id sol_rpc)\";
    cursor_seed = opt vec { record { \"solana-devnet\"; \"$SOL_SEED\" } } })"
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
    local text_hash payload message sig
    text_hash=$(python3 -c "import hashlib; print(hashlib.sha256(b'e2e task $NONCE \x00 salt').hexdigest())")
    payload=$(participant register-payload "$text_hash" "$DURATION")
    message=$(participant task-message solana-devnet "$GAME_ID" "$task_id" 0 "$payload")
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$message")
    game_call register_task "(record {
        chain = \"solana-devnet\";
        donor = blob \"$(blob_hex "$DONOR_HEX")\";
        streamer = blob \"$(blob_hex "$STREAMER_HEX")\";
        gross = $gross;
        deadline = $deadline;
        resolver = blob \"$(blob_hex "$RESOLVER")\";
        nonce = $nonce;
        duration = $DURATION;
        text_hash = blob \"$(blob_hex "$text_hash")\";
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}
vote_done() { # task_id_hex
    local task_id=$1 message sig
    message=$(participant task-message solana-devnet "$GAME_ID" "$task_id" 4 "00")
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$message")
    game_call vote "(record { chain = \"solana-devnet\"; task_id = blob \"$(blob_hex "$task_id")\";
        voter = blob \"$(blob_hex "$DONOR_HEX")\"; choice = variant { done };
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}

# ---- acts -----------------------------------------------------------------

echo "== direct donate: the reputation the donor will vote with"
driver donate "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$STREAMER" "$SOL_DONATE"
DONOR_BLOB=$(blob_hex "$DONOR_HEX"); STREAMER_BLOB=$(blob_hex "$STREAMER_HEX")

DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))

echo "== act B (cancel): create, register, decline"
B=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$STREAMER" "$B_GROSS" "$DEADLINE" "$RESOLVER" "$NONCE")
B_HEX=$(b58_hex "$B")
echo "escrow B=$B"
register_task "$B_GROSS" "$DEADLINE" "$B_HEX" "$NONCE"
sign_and_call decline "$B_HEX" 2 "" "$SOL_STREAMER_KEYPAIR" | grep -q Ok

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
C=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$STREAMER" "$C_GROSS" $(($(date +%s) + 25)) "$RESOLVER" $((NONCE + 1)))
echo "escrow C=$C"
sleep 30
driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$C"

echo "== the donate ingest must land before the vote"
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$STREAMER_BLOB")
    echo "reputation: $REP/$SOL_DONATE"
    [ "$REP" = "$SOL_DONATE" ] && break
    sleep 10
done
[ "$REP" = "$SOL_DONATE" ] || { echo "FAIL: donate not ingested"; exit 1; }

echo "== act A (settle): create, register, accept, done, vote"
DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))
A=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$STREAMER" "$A_GROSS" "$DEADLINE" "$RESOLVER" $((NONCE + 2)))
A_HEX=$(b58_hex "$A")
echo "escrow A=$A"
register_task "$A_GROSS" "$DEADLINE" "$A_HEX" $((NONCE + 2))
sign_and_call accept "$A_HEX" 1 "" "$SOL_STREAMER_KEYPAIR" | grep -q Ok
sign_and_call done "$A_HEX" 3 "" "$SOL_STREAMER_KEYPAIR" | grep -q Ok
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
STREAMER_BEFORE=$(driver balance "$SOL_RPC_URL" "$STREAMER")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$A" 0 "$SIG_A" "$RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$STREAMER")" = "$((STREAMER_BEFORE + A_GROSS * 97 / 100))" ] || { echo "FAIL: payout"; exit 1; }

echo "== the book credits the DONOR for the game settlement"
TOTAL=$((SOL_DONATE + A_GROSS))
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$STREAMER_BLOB")
    echo "book: $REP/$TOTAL"
    [ "$REP" = "$TOTAL" ] && break
    sleep 10
done
[ "$REP" = "$TOTAL" ] || { echo "FAIL: settlement not attributed to the donor"; exit 1; }

ANOMALIES=$(dfx canister call crown-index get_anomaly_count --query | tr -d '(_ )' | sed 's/:nat64//')
[ "$ANOMALIES" = "0" ] || { echo "FAIL: anomaly count = $ANOMALIES"; exit 1; }

echo "e2e devnet OK"
