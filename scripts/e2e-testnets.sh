#!/usr/bin/env bash
# G4 e2e (docs/build-plan.md): вердикты канистры против реальных сетей.
#
# На одной локальной реплике: crown-index (читает реальные Sepolia и devnet)
# и игровая канистра (threshold-ключи локальной реплики). На каждой сети:
#   1. прямой донат даёт донору репутацию — ей он потом голосует;
#   2. задание A: register → accept → done → голос → вердикт settle →
#      claim(0) с подписью канистры → Settled → книга начисляет ДОНОРУ;
#   3. задание B: register → decline → вердикт cancel → claim(1) —
#      деньги вернулись, Settled нет;
#   4. эскроу C (вне игры, короткий дедлайн): refund() — Settled нет;
#   5. подпись A не открывает B (негативный тест против контракта);
#   6. итог книги точен, аномалий ноль.
#
# Долгие ожидания: финальность Sepolia (~15 мин, дважды) и voting_period
# testnet-профиля; обе сети идут параллельно, полный прогон ~35–45 минут.
#
# Usage: scripts/e2e-testnets.sh
set -euo pipefail
cd "$(dirname "$0")/.."

EVM_RPC_URL=${EVM_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}
SOL_RPC_URL=${SOL_RPC_URL:-https://api.devnet.solana.com}
EVM_KEY_FILE=${EVM_KEY_FILE:-$HOME/.cache/crown-e2e/evm-deployer.key}
SOL_DONOR_KEYPAIR=${SOL_DONOR_KEYPAIR:-$HOME/.cache/crown-e2e/donor.json}
CORE=$(cd ../../Crown-Core && pwd)

VOTING_PERIOD=$(grep "^voting_period" config/testnet.toml | cut -d"=" -f2 | tr -d " ")
MARGIN=259200
# Суммы devnet ужаты под остаток кошелька; EVM-стороне хватает с запасом.
SOL_DONATE=150000
SOL_A_GROSS=200000
SOL_B_GROSS=100000
SOL_C_GROSS=100000
DURATION=3600
NONCE=$(date +%s)

# ---- tooling ------------------------------------------------------------

participant() { cargo run -q -p conditional-tasks --example participant -- "$@"; }
driver() { (cd e2e/solana-driver && cargo run -q -- "$@"); }

blob_hex() { # 0x-hex или hex -> candid-блоб \xx
    python3 -c "import sys; h=sys.argv[1].removeprefix('0x'); print(''.join(f'\\\\{h[i:i+2]}' for i in range(0,len(h),2)))" "$1"
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
resolver_hex() { game_call get_resolver "(\"$1\")" --query --output json | opt_blob_hex; }
reputation() { # chain payer_blob streamer_blob
    dfx canister call crown-index get_reputation "(\"$1\", blob \"$2\", blob \"$3\")" \
        --query | tr -d '(_ )' | sed 's/:nat//'
}
verdict_json() { # chain task_id_hex
    game_call get_verdict "(\"$1\", blob \"$(blob_hex "$2")\")" --query --output json
}
verdict_signature() { # chain task_id_hex -> sig hex или пусто
    verdict_json "$1" "$2" | python3 -c "
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

sign_and_call() { # method chain task_id_hex action payload_hex signer_kind signer_key
    local method=$1 chain=$2 task_id=$3 action=$4 payload=$5 kind=$6 key=$7
    local message sig
    message=$(participant task-message "$chain" "$GAME_ID" "$task_id" "$action" "$payload")
    if [ "$kind" = evm ]; then
        sig=$(participant evm-sign "$key" "$message")
    else
        sig=$(participant sol-sign "$key" "$message")
    fi
    game_call "$method" "(record { chain = \"$chain\"; task_id = blob \"$(blob_hex "$task_id")\"; signature = blob \"$(blob_hex "$sig")\" })"
}

# ---- config -------------------------------------------------------------

core_chain() { grep "^$1" "$CORE/config/testnet.toml" | sed -n "$2p" | cut -d'=' -f2- | tr -d ' "[]'; }
SOL_SPLITTER=$(core_chain splitter 1)
EVM_SPLITTER=$(core_chain splitter 2)
EVM_USDC=$(core_chain usdc 2)
game_chain() { grep "^$1" config/testnet.toml | sed -n "$2p" | cut -d'=' -f2- | tr -d ' "'; }
EVM_FACTORY=$(game_chain factory 1)

EVM_KEY=$(cat "$EVM_KEY_FILE")
EVM_DONOR=0x$(participant evm-address "$EVM_KEY")
EVM_STREAMER_KEY=$(openssl rand -hex 32)
EVM_STREAMER=0x$(participant evm-address "$EVM_STREAMER_KEY")

TMP=$(mktemp -d)
solana-keygen new --no-bip39-passphrase --silent --force -o "$TMP/streamer.json"
SOL_STREAMER=$(solana-keygen pubkey "$TMP/streamer.json")
SOL_DONOR=$(solana-keygen pubkey "$SOL_DONOR_KEYPAIR")
SOL_DONOR_HEX=$(b58_hex "$SOL_DONOR")
SOL_STREAMER_HEX=$(b58_hex "$SOL_STREAMER")

echo "evm donor=$EVM_DONOR streamer=$EVM_STREAMER"
echo "sol donor=$SOL_DONOR streamer=$SOL_STREAMER"

# ---- replica and canisters ------------------------------------------------

echo "== build crown-index (local profile) and start the replica"
EVM_SEED=$(cast block-number --rpc-url "$EVM_RPC_URL")
SOL_SEED=$(curl -s "$SOL_RPC_URL" -X POST -H "Content-Type: application/json" -d "{
    \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",
    \"params\":[\"$SOL_SPLITTER\", {\"limit\": 1}]}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['result'][0]['signature'])")
echo "cursor seeds: evm=$EVM_SEED sol=$SOL_SEED"

cat > "$CORE/config/local.toml" <<EOF
# Generated by conditional-tasks/scripts/e2e-testnets.sh; never committed.
[[chain]]
id        = "solana-devnet"
source    = "Custom:$SOL_RPC_URL"
consensus = "equality"
splitter  = "$SOL_SPLITTER"
usdc      = "$(core_chain usdc 1)"
factories = ["$(core_chain factories 1)"]

[[chain]]
id        = "eth-sepolia"
source    = "Custom:11155111:$EVM_RPC_URL"
consensus = "equality"
splitter  = "$EVM_SPLITTER"
usdc      = "$EVM_USDC"
factories = ["$(game_chain factory 1)"]
EOF
(cd "$CORE" && CROWN_PROFILE=local \
    CC_wasm32_unknown_unknown="$CORE/scripts/wasm-cc.sh" \
    AR_wasm32_unknown_unknown="${AR_WASM32:-$HOME/.cache/solana/v1.53/platform-tools/llvm/bin/llvm-ar}" \
    cargo build --target wasm32-unknown-unknown --release -p crown-index)

dfx stop >/dev/null 2>&1 || true
dfx start --clean --background
trap 'dfx stop >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
dfx deploy sol_rpc
dfx deploy evm_rpc
dfx deploy crown-index --argument "(opt record {
    sol_rpc = opt principal \"$(dfx canister id sol_rpc)\";
    evm_rpc = opt principal \"$(dfx canister id evm_rpc)\";
    cursor_seed = opt vec {
        record { \"solana-devnet\"; \"$SOL_SEED\" };
        record { \"eth-sepolia\"; \"$EVM_SEED\" };
    } })"
dfx ledger fabricate-cycles --canister crown-index --t 100 >/dev/null
dfx deploy conditional-tasks --argument "(opt record {
    crown_index = opt principal \"$(dfx canister id crown-index)\" })"
dfx ledger fabricate-cycles --canister conditional-tasks --t 100 >/dev/null
GAME_ID=$(dfx canister id conditional-tasks)

echo "== resolver keys"
EVM_RESOLVER=""; SOL_RESOLVER=""
for _ in $(seq 1 60); do
    EVM_RESOLVER=$(resolver_hex eth-sepolia)
    SOL_RESOLVER=$(resolver_hex solana-devnet)
    [ -n "$EVM_RESOLVER" ] && [ -n "$SOL_RESOLVER" ] && break
    sleep 2
done
[ -n "$EVM_RESOLVER" ] && [ -n "$SOL_RESOLVER" ] || { echo "FAIL: resolver keys never warmed"; exit 1; }
echo "evm resolver=0x$EVM_RESOLVER"
echo "sol resolver=$SOL_RESOLVER"

# ---- chain helpers ---------------------------------------------------------

evm_send() { cast send --rpc-url "$EVM_RPC_URL" --private-key "$EVM_KEY" "$@" >/dev/null; }
evm_balance() { cast call "$EVM_USDC" "balanceOf(address)(uint256)" "$1" --rpc-url "$EVM_RPC_URL" | cut -d' ' -f1; }
FROM_BLOCK=$EVM_SEED
settled_count_for() { # payer -> число Settled с этим payer
    local topic=0x000000000000000000000000${1#0x}
    cast rpc --rpc-url "$EVM_RPC_URL" eth_getLogs "{
        \"address\": \"$EVM_SPLITTER\",
        \"topics\": [\"0x16c41a749cf94bd479b1fc5d82a6eb4557d71262f15dc382d2cf6f1eb3d68e8e\", \"$topic\"],
        \"fromBlock\": \"$(printf '0x%x' "$FROM_BLOCK")\", \"toBlock\": \"latest\"
    }" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))"
}
evm_birth() { # gross deadline nonce -> escrow
    local gross=$1 deadline=$2 nonce=$3 escrow
    evm_send "$EVM_USDC" "approve(address,uint256)" "$EVM_FACTORY" "$gross"
    escrow=$(cast call "$EVM_FACTORY" \
        "createEscrow(address,uint256,uint64,address,uint256)(address)" \
        "$EVM_STREAMER" "$gross" "$deadline" "0x$EVM_RESOLVER" "$nonce" \
        --from "$EVM_DONOR" --rpc-url "$EVM_RPC_URL")
    evm_send "$EVM_FACTORY" "createEscrow(address,uint256,uint64,address,uint256)" \
        "$EVM_STREAMER" "$gross" "$deadline" "0x$EVM_RESOLVER" "$nonce"
    echo "$escrow"
}
register_task() { # chain donor_hex streamer_hex gross deadline task_id_hex signer_kind signer_key
    local chain=$1 donor=$2 streamer=$3 gross=$4 deadline=$5 task_id=$6 kind=$7 key=$8
    local text_hash payload message sig
    text_hash=$(python3 -c "import hashlib; print(hashlib.sha256(b'e2e task $chain $NONCE \x00 salt').hexdigest())")
    payload=$(participant register-payload "$text_hash" "$DURATION")
    message=$(participant task-message "$chain" "$GAME_ID" "$task_id" 0 "$payload")
    if [ "$kind" = evm ]; then sig=$(participant evm-sign "$key" "$message"); else sig=$(participant sol-sign "$key" "$message"); fi
    game_call register_task "(record {
        chain = \"$chain\";
        donor = blob \"$(blob_hex "$donor")\";
        streamer = blob \"$(blob_hex "$streamer")\";
        gross = $gross;
        deadline = $deadline;
        resolver = blob \"$(blob_hex "$9")\";
        nonce = ${10};
        duration = $DURATION;
        text_hash = blob \"$(blob_hex "$text_hash")\";
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}
vote_done() { # chain task_id_hex voter_hex signer_kind signer_key
    local chain=$1 task_id=$2 voter=$3 kind=$4 key=$5
    local message sig
    message=$(participant task-message "$chain" "$GAME_ID" "$task_id" 4 "00")
    if [ "$kind" = evm ]; then sig=$(participant evm-sign "$key" "$message"); else sig=$(participant sol-sign "$key" "$message"); fi
    game_call vote "(record { chain = \"$chain\"; task_id = blob \"$(blob_hex "$task_id")\";
        voter = blob \"$(blob_hex "$voter")\"; choice = variant { done };
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}

# ---- reputation donates ------------------------------------------------------

echo "== direct donates: the reputation the donors will vote with"
evm_send "$EVM_USDC" "approve(address,uint256)" "$EVM_SPLITTER" 200000
evm_send "$EVM_SPLITTER" "donate(address,uint256)" "$EVM_STREAMER" 200000
driver donate "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_STREAMER" "$SOL_DONATE"

# ---- tasks --------------------------------------------------------------------

NOW=$(date +%s)
DEADLINE=$((NOW + DURATION + VOTING_PERIOD + MARGIN + 600))

echo "== task A (settle) and B (cancel), both chains"
EVM_A=$(evm_birth 1000000 "$DEADLINE" "$NONCE")
EVM_B=$(evm_birth 300000 "$DEADLINE" $((NONCE + 1)))
echo "evm escrows: A=$EVM_A B=$EVM_B"
SOL_A=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_STREAMER" "$SOL_A_GROSS" "$DEADLINE" "$SOL_RESOLVER" "$NONCE")
SOL_B=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_STREAMER" "$SOL_B_GROSS" "$DEADLINE" "$SOL_RESOLVER" $((NONCE + 1)))
echo "sol escrows: A=$SOL_A B=$SOL_B"
SOL_A_HEX=$(b58_hex "$SOL_A"); SOL_B_HEX=$(b58_hex "$SOL_B")

register_task eth-sepolia "$EVM_DONOR" "$EVM_STREAMER" 1000000 "$DEADLINE" "$EVM_A" evm "$EVM_KEY" "$EVM_RESOLVER" "$NONCE"
register_task eth-sepolia "$EVM_DONOR" "$EVM_STREAMER" 300000 "$DEADLINE" "$EVM_B" evm "$EVM_KEY" "$EVM_RESOLVER" $((NONCE + 1))
register_task solana-devnet "$SOL_DONOR_HEX" "$SOL_STREAMER_HEX" "$SOL_A_GROSS" "$DEADLINE" "$SOL_A_HEX" sol "$SOL_DONOR_KEYPAIR" "$SOL_RESOLVER" "$NONCE"
register_task solana-devnet "$SOL_DONOR_HEX" "$SOL_STREAMER_HEX" "$SOL_B_GROSS" "$DEADLINE" "$SOL_B_HEX" sol "$SOL_DONOR_KEYPAIR" "$SOL_RESOLVER" $((NONCE + 1))

echo "== wait for the donate ingest (the vote weight comes first: the window is short)"
EVM_DONOR_BLOB=$(blob_hex "$EVM_DONOR"); EVM_STREAMER_BLOB=$(blob_hex "$EVM_STREAMER")
SOL_DONOR_BLOB=$(blob_hex "$SOL_DONOR_HEX"); SOL_STREAMER_BLOB=$(blob_hex "$SOL_STREAMER_HEX")
for _ in $(seq 1 90); do
    EVM_REP=$(reputation eth-sepolia "$EVM_DONOR_BLOB" "$EVM_STREAMER_BLOB")
    SOL_REP=$(reputation solana-devnet "$SOL_DONOR_BLOB" "$SOL_STREAMER_BLOB")
    echo "reputation: evm=$EVM_REP/200000 sol=$SOL_REP/$SOL_DONATE"
    [ "$EVM_REP" = "200000" ] && [ "$SOL_REP" = "$SOL_DONATE" ] && break
    sleep 30
done
[ "$EVM_REP" = "200000" ] && [ "$SOL_REP" = "$SOL_DONATE" ] || { echo "FAIL: donate not ingested"; exit 1; }

echo "== streamer: accept + done on A, decline on B; donors vote at once"
sign_and_call accept eth-sepolia "$EVM_A" 1 "" evm "$EVM_STREAMER_KEY" | grep -q Ok
sign_and_call done eth-sepolia "$EVM_A" 3 "" evm "$EVM_STREAMER_KEY" | grep -q Ok
sign_and_call decline eth-sepolia "$EVM_B" 2 "" evm "$EVM_STREAMER_KEY" | grep -q Ok
sign_and_call accept solana-devnet "$SOL_A_HEX" 1 "" sol "$TMP/streamer.json" | grep -q Ok
sign_and_call done solana-devnet "$SOL_A_HEX" 3 "" sol "$TMP/streamer.json" | grep -q Ok
sign_and_call decline solana-devnet "$SOL_B_HEX" 2 "" sol "$TMP/streamer.json" | grep -q Ok
VOTING_STARTED=$(date +%s)
vote_done eth-sepolia "$EVM_A" "$EVM_DONOR" evm "$EVM_KEY"
vote_done solana-devnet "$SOL_A_HEX" "$SOL_DONOR_HEX" sol "$SOL_DONOR_KEYPAIR"

echo "== cancel verdicts: claim(1) returns the money, no Settled"
EVM_SIG_B=""; SOL_SIG_B=""
for _ in $(seq 1 20); do
    EVM_SIG_B=$(verdict_signature eth-sepolia "$EVM_B")
    SOL_SIG_B=$(verdict_signature solana-devnet "$SOL_B_HEX")
    [ -n "$EVM_SIG_B" ] && [ -n "$SOL_SIG_B" ] && break
    sleep 10
done
[ -n "$EVM_SIG_B" ] && [ -n "$SOL_SIG_B" ] || { echo "FAIL: cancel signatures never appeared"; exit 1; }

echo "== negative: the cancel signature of B does not open A, on the real contract"
if cast call "$EVM_A" "claim(uint8,bytes)" 1 "0x$EVM_SIG_B" --rpc-url "$EVM_RPC_URL" >/dev/null 2>&1; then
    echo "FAIL: B's signature was accepted by escrow A"; exit 1
fi

EVM_BEFORE=$(evm_balance "$EVM_DONOR")
evm_send "$EVM_B" "claim(uint8,bytes)" 1 "0x$EVM_SIG_B"
[ "$(evm_balance "$EVM_DONOR")" = "$((EVM_BEFORE + 300000))" ] || { echo "FAIL: evm cancel refund"; exit 1; }
[ "$(settled_count_for "$EVM_B")" = "0" ] || { echo "FAIL: Settled on evm cancel"; exit 1; }

SOL_BEFORE=$(driver balance "$SOL_RPC_URL" "$SOL_DONOR")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_B" 1 "$SOL_SIG_B" "$SOL_RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$SOL_DONOR")" = "$((SOL_BEFORE + SOL_B_GROSS))" ] || { echo "FAIL: sol cancel refund"; exit 1; }

echo "== escrow C outside the game: refund() moves money, never the book"
NOWC=$(cast block latest --field timestamp --rpc-url "$EVM_RPC_URL")
EVM_C=$(evm_birth 200000 $((NOWC + 48)) $((NONCE + 2)))
SOL_C=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_STREAMER" "$SOL_C_GROSS" $(($(date +%s) + 25)) "$SOL_RESOLVER" $((NONCE + 2)))
while [ "$(cast block latest --field timestamp --rpc-url "$EVM_RPC_URL")" -le $((NOWC + 48)) ]; do sleep 12; done
evm_send "$EVM_C" "refund()"
[ "$(settled_count_for "$EVM_C")" = "0" ] || { echo "FAIL: Settled on evm refund"; exit 1; }
sleep 30
driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_C"

echo "== wait out the voting period, then the settle signatures"
ELAPSED=$(($(date +%s) - VOTING_STARTED))
[ "$ELAPSED" -lt "$VOTING_PERIOD" ] && { echo "sleeping $((VOTING_PERIOD - ELAPSED + 60))s"; sleep $((VOTING_PERIOD - ELAPSED + 60)); }
EVM_SIG_A=""; SOL_SIG_A=""
for _ in $(seq 1 30); do
    EVM_SIG_A=$(verdict_signature eth-sepolia "$EVM_A")
    SOL_SIG_A=$(verdict_signature solana-devnet "$SOL_A_HEX")
    [ -n "$EVM_SIG_A" ] && [ -n "$SOL_SIG_A" ] && break
    sleep 10
done
[ -n "$EVM_SIG_A" ] && [ -n "$SOL_SIG_A" ] || { echo "FAIL: settle signatures never appeared"; exit 1; }
verdict_json eth-sepolia "$EVM_A" | grep -q settle || { echo "FAIL: evm verdict is not settle"; exit 1; }
verdict_json solana-devnet "$SOL_A_HEX" | grep -q settle || { echo "FAIL: sol verdict is not settle"; exit 1; }

echo "== claim(0): the canister's signature moves real money through the splitter"
evm_send "$EVM_A" "claim(uint8,bytes)" 0 "0x$EVM_SIG_A"
[ "$(evm_balance "$EVM_STREAMER")" = "$((194000 + 970000))" ] || { echo "FAIL: evm payout"; exit 1; }
[ "$(settled_count_for "$EVM_A")" = "1" ] || { echo "FAIL: no Settled from evm escrow A"; exit 1; }

SOL_STREAMER_BEFORE=$(driver balance "$SOL_RPC_URL" "$SOL_STREAMER")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$SOL_A" 0 "$SOL_SIG_A" "$SOL_RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$SOL_STREAMER")" = "$((SOL_STREAMER_BEFORE + SOL_A_GROSS * 97 / 100))" ] || { echo "FAIL: sol payout"; exit 1; }

echo "== the book credits the DONOR for the game settlements"
for _ in $(seq 1 90); do
    EVM_REP=$(reputation eth-sepolia "$EVM_DONOR_BLOB" "$EVM_STREAMER_BLOB")
    SOL_REP=$(reputation solana-devnet "$SOL_DONOR_BLOB" "$SOL_STREAMER_BLOB")
    SOL_TOTAL=$((SOL_DONATE + SOL_A_GROSS))
    echo "book: evm=$EVM_REP/1200000 sol=$SOL_REP/$SOL_TOTAL"
    [ "$EVM_REP" = "1200000" ] && [ "$SOL_REP" = "$SOL_TOTAL" ] && break
    sleep 30
done
[ "$EVM_REP" = "1200000" ] || { echo "FAIL: evm settlement not attributed to the donor"; exit 1; }
[ "$SOL_REP" = "$((SOL_DONATE + SOL_A_GROSS))" ] || { echo "FAIL: sol settlement not attributed to the donor"; exit 1; }

ANOMALIES=$(dfx canister call crown-index get_anomaly_count --query | tr -d '(_ )' | sed 's/:nat64//')
[ "$ANOMALIES" = "0" ] || { echo "FAIL: anomaly count = $ANOMALIES"; exit 1; }

echo "e2e testnets OK"
