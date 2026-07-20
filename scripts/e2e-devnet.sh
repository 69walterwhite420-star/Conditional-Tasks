#!/usr/bin/env bash
# G4 e2e (docs/build-plan.md): canister verdicts against the real devnet.
#
# One local replica runs both crown-index (reading the real devnet) and the
# game canister (the replica's threshold key). Acts:
#   1. a direct donate gives the donor the reputation they later vote with;
#   2. task B: register → decline → cancel verdict; the cancel signature
#      does not open settle (a negative against the contract);
#      claim(1) — the money returns whole, no Settled;
#   3. escrow C (outside the game, short DEADLINE): refund() returns the
#      gross, closes the escrow for good — a second refund() is refused —
#      and never touches the book;
#   4. task A: register → accept → ready → vote done → settle verdict →
#      claim(0) with the canister's signature → Settled → the recipient gets
#      the payout, the fee wallet its cut, the book credits the DONOR;
#   5. task D: the same road, voted DOWN — the tally itself yields cancel
#      (§6), claim(1) returns 100 % to the donor and the fee wallet stays
#      untouched: a refund is fee-free;
#   6. task S (§11.10): the settle verdict is signed and deliberately NOT
#      executed. The escrow keeps the whole gross, refund() before its
#      DEADLINE is refused by the contract, the canister keeps issuing the
#      same standing signature — and the book credits nothing, because
#      reputation comes from an executed claim, never from a signed verdict;
#   7. the book delta is exact, stable after the refunds, zero anomalies.
#
# Every book assertion is a DELTA from the baseline read at startup: the
# local replica is shared and never wiped, so what earlier runs credited
# these wallets is still there.
#
# §11.10's other half — refund() beating an already signed settle after the
# DEADLINE — is not reachable here: register_task refuses any deadline
# tighter than duration + voting_period + DEADLINE_MARGIN (72 h), so every
# escrow a task ever names is a three-day wait away from refund(). Act 6
# asserts the ordering from the near side (refund is refused while the
# settle stands), act 3 the far side (after the DEADLINE refund closes the
# escrow for good).
#
# With the testnet profile (voting_period = 120 s) and devnet finality in
# seconds the full run takes ~12 minutes.
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
D_GROSS=6000
# The task whose settle verdict nobody ever executes (act 6): its gross stays
# on-chain for good, so it is the smallest of the five.
S_GROSS=4000
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
verdict_outcome() { # task_id_hex -> settle|cancel или пусто
    verdict_json "$1" | python3 -c "
import json, sys
v = json.load(sys.stdin)
while isinstance(v, list) and len(v) == 1: v = v[0]
if not isinstance(v, dict): print(); sys.exit()
outcome = v.get('outcome')
print(next(iter(outcome)) if isinstance(outcome, dict) and outcome else '')
"
}
# The verdict is recorded before the threshold signature is requested, so the
# signature is what tells us the canister is done with the task.
await_verdict() { # task_id_hex expected_outcome -> sig hex
    local sig outcome
    for _ in $(seq 1 30); do
        sig=$(verdict_signature "$1")
        if [ -n "$sig" ]; then
            outcome=$(verdict_outcome "$1")
            [ "$outcome" = "$2" ] || { echo "FAIL: outcome $outcome, expected $2" >&2; exit 1; }
            echo "$sig"
            return
        fi
        sleep 10
    done
    echo "FAIL: the $2 signature for $1 never appeared" >&2
    exit 1
}

# The protocol message is UTF-8 text with newlines (auth.rs), so it travels
# by file: a shell argument would mangle it, and one stray byte is a different
# message. The temp file is removed inline, never by a RETURN trap: such a
# trap outlives the function that set it and fires again on the return of any
# caller — where `msg` is unbound and `set -u` kills the run.
sign_and_call() { # method task_id_hex signer_keypair   (method == action word)
    local method=$1 task_id=$2 keypair=$3
    local msg sig
    msg=$(mktemp)
    participant task-message solana-devnet "$GAME_ID" "$task_id" "$method" > "$msg"
    sig=$(participant sol-sign "$keypair" "$msg")
    rm -f "$msg"
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
    AR_wasm32_unknown_unknown="${AR_WASM32:-$(command -v llvm-ar || ls -d "$HOME"/.cache/solana/*/platform-tools/llvm/bin/llvm-ar 2>/dev/null | sort -V | tail -1 | grep . || echo "$HOME/.cache/zig/zig-ar")}" \
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
    text_hash=$(python3 -c "import hashlib; print(hashlib.sha256(b'e2e task $nonce \x00 salt').hexdigest())")
    msg=$(mktemp)
    participant task-message solana-devnet "$GAME_ID" "$task_id" register "$text_hash" "$DURATION" > "$msg"
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$msg")
    rm -f "$msg"
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
cast_vote() { # task_id_hex done|not_done
    local task_id=$1 choice=$2 msg sig
    msg=$(mktemp)
    participant task-message solana-devnet "$GAME_ID" "$task_id" vote "$choice" > "$msg"
    sig=$(participant sol-sign "$SOL_DONOR_KEYPAIR" "$msg")
    rm -f "$msg"
    game_call vote "(record { chain = \"solana-devnet\"; task_id = blob \"$(blob_hex "$task_id")\";
        voter = blob \"$(blob_hex "$DONOR_HEX")\"; choice = variant { $choice };
        signature = blob \"$(blob_hex "$sig")\" })" | tee /dev/stderr | grep -q Ok
}
# register → accept → ready → vote, the whole road to a tally in one step.
play_task() { # gross deadline escrow_b58 nonce done|not_done
    local task_id
    task_id=$(b58_hex "$3")
    register_task "$1" "$2" "$task_id" "$4"
    sign_and_call accept "$task_id" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok
    sign_and_call ready "$task_id" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok
    cast_vote "$task_id" "$5"
}

# ---- acts -----------------------------------------------------------------

DONOR_BLOB=$(blob_hex "$DONOR_HEX"); RECIPIENT_BLOB=$(blob_hex "$RECIPIENT_HEX")
# The book survives an upgrade of crown-index and the replica is never wiped,
# so what earlier runs credited this wallet is the baseline of this one. Every
# assertion below is a delta from it.
BASE_REP=$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")
echo "book baseline: donor $BASE_REP"

echo "== direct donate: the reputation the donor will vote with"
driver donate "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$SOL_DONATE"

DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))

echo "== act B (cancel by decline): create, register, decline"
B=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$B_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" "$NONCE")
B_HEX=$(b58_hex "$B")
echo "escrow B=$B"
register_task "$B_GROSS" "$DEADLINE" "$B_HEX" "$NONCE"
sign_and_call decline "$B_HEX" "$SOL_RECIPIENT_KEYPAIR" | grep -q Ok
SIG_B=$(await_verdict "$B_HEX" cancel)

echo "== negative: the cancel signature does not open settle, on the real contract"
if driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$B" 0 "$SIG_B" "$RESOLVER" >/dev/null 2>&1; then
    echo "FAIL: the cancel signature opened outcome 0"; exit 1
fi

echo "== claim(1): the money returns whole, no Settled"
BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$B" 1 "$SIG_B" "$RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$DONOR")" = "$((BEFORE + B_GROSS))" ] || { echo "FAIL: cancel refund"; exit 1; }

echo "== act C, outside the game: refund() moves money, never the book"
C=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$C_GROSS" $(($(date +%s) + 25)) "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 1)))
echo "escrow C=$C"
sleep 30
BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$C"
[ "$(driver balance "$SOL_RPC_URL" "$DONOR")" = "$((BEFORE + C_GROSS))" ] \
    || { echo "FAIL: refund did not return C's gross"; exit 1; }
read -r C_CLOSED _ <<<"$(driver state "$SOL_RPC_URL" "$C")"
[ "$C_CLOSED" = "true" ] || { echo "FAIL: C not terminal after refund"; exit 1; }
# Terminal means terminal: the money leaves an escrow exactly once.
if driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$C" >/dev/null 2>&1; then
    echo "FAIL: a refunded escrow paid out twice"; exit 1
fi

echo "== the donate ingest must land before the vote"
DONATED=$((BASE_REP + SOL_DONATE))
REP=""
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")
    echo "reputation: $REP/$DONATED"
    [ "$REP" = "$DONATED" ] && break
    sleep 10
done
[ "$REP" = "$DONATED" ] || { echo "FAIL: donate not ingested"; exit 1; }

# The three voted tasks share one voting period: they are independent
# machines, and waiting them out one by one buys nothing but minutes.
echo "== acts A, D, S: three escrows, three votes, one voting period"
DEADLINE=$(($(date +%s) + DURATION + VOTING_PERIOD + MARGIN + 600))
A=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$A_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 2)))
D=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$D_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 3)))
S=$(driver create "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$RECIPIENT" "$S_GROSS" "$DEADLINE" "$RESOLVER" "$FEE_BPS" "$FEE_WALLET" $((NONCE + 4)))
A_HEX=$(b58_hex "$A"); D_HEX=$(b58_hex "$D"); S_HEX=$(b58_hex "$S")
echo "escrow A=$A (voted done) D=$D (voted down) S=$S (settle, never executed)"
play_task "$A_GROSS" "$DEADLINE" "$A" $((NONCE + 2)) done
play_task "$D_GROSS" "$DEADLINE" "$D" $((NONCE + 3)) not_done
play_task "$S_GROSS" "$DEADLINE" "$S" $((NONCE + 4)) done

# Each task's period runs from its own `ready`; sleeping the period from the
# last of them clears all three.
echo "== wait out the voting period, then the three verdicts"
sleep $((VOTING_PERIOD + 30))
SIG_A=$(await_verdict "$A_HEX" settle)
SIG_D=$(await_verdict "$D_HEX" cancel)
SIG_S=$(await_verdict "$S_HEX" settle)

echo "== act A: claim(0) — the payout and the game's fee, split by the escrow"
A_FEE=$((A_GROSS * FEE_BPS / 10000))
A_PAYOUT=$((A_GROSS - A_FEE))
RECIPIENT_BEFORE=$(driver balance "$SOL_RPC_URL" "$RECIPIENT")
FEE_BEFORE=$(driver balance "$SOL_RPC_URL" "$FEE_WALLET")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$A" 0 "$SIG_A" "$RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$RECIPIENT")" = "$((RECIPIENT_BEFORE + A_PAYOUT))" ] \
    || { echo "FAIL: payout"; exit 1; }
[ "$(driver balance "$SOL_RPC_URL" "$FEE_WALLET")" = "$((FEE_BEFORE + A_FEE))" ] \
    || { echo "FAIL: the game's fee did not reach its wallet"; exit 1; }

echo "== act D: the tally itself cancels — claim(1) returns 100 %, fee-free"
# The only voter voted not_done, so Σdone (0) never exceeds Σnot_done: a
# cancel earned through the real contract, not through a decline.
DONOR_BEFORE=$(driver balance "$SOL_RPC_URL" "$DONOR")
FEE_BEFORE=$(driver balance "$SOL_RPC_URL" "$FEE_WALLET")
driver claim "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$D" 1 "$SIG_D" "$RESOLVER"
[ "$(driver balance "$SOL_RPC_URL" "$DONOR")" = "$((DONOR_BEFORE + D_GROSS))" ] \
    || { echo "FAIL: the voted cancel did not return the whole gross"; exit 1; }
[ "$(driver balance "$SOL_RPC_URL" "$FEE_WALLET")" = "$FEE_BEFORE" ] \
    || { echo "FAIL: a refund paid the game's fee"; exit 1; }
read -r D_CLOSED _ <<<"$(driver state "$SOL_RPC_URL" "$D")"
[ "$D_CLOSED" = "true" ] || { echo "FAIL: D not terminal after claim(1)"; exit 1; }

echo "== act S (§11.10): a signed settle nobody executed"
# The verdict is a signature, not a payment: nobody is obliged to send the
# transaction. The escrow therefore stands untouched with its whole gross.
read -r S_CLOSED S_STATE_GROSS <<<"$(driver state "$SOL_RPC_URL" "$S")"
[ "$S_CLOSED" = "false" ] || { echo "FAIL: S closed without a claim"; exit 1; }
[ "$S_STATE_GROSS" = "$S_GROSS" ] || { echo "FAIL: S gross $S_STATE_GROSS"; exit 1; }
[ "$(driver balance "$SOL_RPC_URL" "$S")" = "$S_GROSS" ] \
    || { echo "FAIL: S's money left its ATA"; exit 1; }
# refund() is the deadline's door and nothing else: while the DEADLINE stands,
# the signed settle cannot be undercut. The other side of §11.10 — refund()
# winning after the DEADLINE — is act C: register_task refuses any deadline
# tighter than duration + voting_period + 72 h, so no task the game knows can
# reach its own DEADLINE inside a run.
if driver refund "$SOL_RPC_URL" "$SOL_DONOR_KEYPAIR" "$S" >/dev/null 2>&1; then
    echo "FAIL: refund() beat the DEADLINE"; exit 1
fi
# One escrow, one verdict, forever: the canister keeps handing out the same
# bytes, so the money stays one transaction away from moving.
[ "$(verdict_signature "$S_HEX")" = "$SIG_S" ] \
    || { echo "FAIL: the standing verdict changed its signature"; exit 1; }
[ "$(verdict_outcome "$S_HEX")" = "settle" ] \
    || { echo "FAIL: the standing verdict changed its outcome"; exit 1; }

echo "== the book credits the DONOR for executed claims only"
# The book sees exactly what reached the recipient: the direct donate whole,
# act A's settlement net of the game's fee. B and D were cancelled, C was
# refunded, S was signed but never executed — none of them may show up.
TOTAL=$((BASE_REP + SOL_DONATE + A_PAYOUT))
REP=""
for _ in $(seq 1 90); do
    REP=$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")
    echo "book: $REP/$TOTAL"
    [ "$REP" = "$TOTAL" ] && break
    sleep 10
done
[ "$REP" = "$TOTAL" ] || { echo "FAIL: settlement not attributed to the donor"; exit 1; }

echo "== the cancels and the refund left the book untouched; zero anomalies"
sleep 30
[ "$(reputation "$DONOR_BLOB" "$RECIPIENT_BLOB")" = "$TOTAL" ] \
    || { echo "FAIL: the book moved after the cancels"; exit 1; }
ANOMALIES=$(dfx canister call crown-index get_anomaly_count --query | tr -d '(_ )' | sed 's/:nat64//')
[ "$ANOMALIES" = "0" ] || { echo "FAIL: anomaly count = $ANOMALIES"; exit 1; }

echo "e2e devnet OK"
