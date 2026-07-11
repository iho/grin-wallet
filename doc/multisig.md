# Multisig (experimental)

Wallet-layer M-of-N threshold multisig primitives live in
`grin_wallet_libwallet::multisig`.

## Status

**Experimental — not safe for real funds.**

This is the first implementation slice of RFC-0023 style multisig:

| Done | Not done |
| --- | --- |
| Joint Feldman DKG (degree = threshold−1) | DKG-as-session + multi-process CLI |
| PoP on coefficient commitments | Production key rotation / epochs |
| Share verify against public poly | External crypto audit |
| Lagrange partial keys + reconstruction | Chain-aware UTXO tracking |
| δ-masked add-actor (local) | Networked multi-wallet slatepack orchestration |
| Coin id derivation (number + value) | |
| LMDB + export AEAD-sealed (C-08); Debug redacts secrets | |
| Multiparty Bulletproof (T1/T2/τ + verifiable τ) | |
| Threshold kernel signing (**FROST** + excess check) | |
| Slatepack wire messages (DKG / RP / kernel) | |
| CLI + Owner API + JSON-RPC + post-tx | Session CLI/RPC lifecycle |
| E2E tx build (multiparty RP + kernel, validates) | |
| Durable negotiator (CreateOutput + Spend, crash-resume) | |
| Session CLI + Owner RPC (`multisig_session_*`) | Multi-process soak tests |
| Unit / integration tests | |

## Design choices vs draft RFC

1. **Polynomial degree = `threshold * shares_per_actor − 1`**  
   (fixes inconsistent degree-M with M shares in the draft).

2. **`recommended_shares_per_actor`** raises degree when M is small  
   (PTE / Wagner hardening).

3. **View mix is not claimed to hide the polynomial** if full blinds leak  
   (fixes incorrect HKDF security argument).

4. **Add-actor is not in the v1 public API** (C-13 / F-03). Membership change =
   full re-DKG + on-chain sweep.

5. **Canonical quorum order** (C-07): actors sorted by x-coordinate; index 0 is
   the mix/offset role. `canonical_quorum` / `quorum_from_states` enforce this.

6. **PTE degree floor** (C-11): production params require
   `num_coefficients() ≥ 4`; tests use `new_allow_low_degree`.

## Quick API

```rust
use grin_wallet_libwallet::multisig::{
    run_dkg_local, ActorId, CeremonyId, ThresholdParams,
};
use grin_util::secp::{ContextFlag, Secp256k1};

let secp = Secp256k1::with_caps(ContextFlag::Commit);
let k = ThresholdParams::recommended_shares_per_actor(2);
let params = ThresholdParams::with_shares_per_actor(2, 3, k)?;
let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
let states = run_dkg_local(&secp, CeremonyId::new(), params, actors)?;
// states[i].shares must be backed up — not seed-restorable alone
```

## Persistence API

```rust
// Write (inside a wallet batch; requires keychain for share XOR)
batch.save_multisig_state(&state)?;
batch.commit()?;

// Read (decrypts shares with keychain)
let state = wallet.get_multisig_state(keychain_mask, &ceremony_id)?;

// List / delete
let ids = wallet.list_multisig_ceremonies()?;
batch.delete_multisig_state(&ceremony_id)?;
```

Ceremony state is **ChaCha20-Poly1305 sealed** under a keychain-derived key
before LMDB write and for `export-state` (C-08). Pending DKG uses the same
cipher with a separate domain key (C-03). Debug formatting redacts share
material.

## Tests

```bash
cargo test -p grin_wallet_libwallet multisig
cargo test -p grin_wallet_impls multisig_store
```

## Multiparty rangeproof API

```rust
use grin_wallet_libwallet::multisig::{
    run_rangeproof_local, rangeproof_round1, aggregate_round1,
    rangeproof_round2, aggregate_tau, rangeproof_finalize, verify_rangeproof,
};

// In-process (tests / same-host quorum); verifies each partial τ (C-06):
let (proof, params) = run_rangeproof_local(secp, &public_poly, &quorum, &coin, None)?;

// Networked-style rounds (each actor):
let (secrets, r1) = rangeproof_round1(secp, &params, &partial_blind)?;
let agg = aggregate_round1(secp, &all_r1_shares)?;
let tau_j = rangeproof_round2(secp, &params, &secrets, &agg)?;
// Verify before summing — bad τ fails with actor index (identifiable abort):
let tau = aggregate_tau_verified(
    secp, &params, &agg, &all_r1_shares, &all_tau, &pub_blinds,
)?;
let proof = rangeproof_finalize(secp, &params, &secrets, &agg, &tau)?;
verify_rangeproof(secp, params.commit, proof, None)?;
```

Shared view seed → `shared_nonce` (scan/rewind). Per-actor CSPRNG → `private_nonce`.
Partial τ check: `τ·G = x·T1 + x²·T2 + z²·P` with `P` from the public poly.

## Threshold kernel signing API

**FROST** (Komlo–Goldberg two-round threshold Schnorr) over Lagrange partial
excess keys. Each actor samples two nonces `(d, e)`, broadcasts
`(D, E, X)`, derives binding factors `ρ_j`, and signs with effective nonce
`k_j = d_j + ρ_j·e_j`. Partials aggregate into an ordinary Grin kernel
signature that `TxKernel::verify()` accepts unchanged.

```rust
use grin_wallet_libwallet::multisig::run_kernel_sign_local;

let (sig, agg, session) = run_kernel_sign_local(
    secp, &public_poly, &quorum, b"session-id", fee, inputs, outputs,
)?;
// sig verifies against agg.excess_sum for the kernel message
```

Per-actor flow: `kernel_round1` → exchange `SigningCommitment`s →
`aggregate_frost` → `kernel_partial_sign` → `kernel_aggregate_sigs`.
Rogue-key protection: each claimed `X_j` is checked against the public
polynomial via `verify_partial_excess` before use.

## Slatepack wire format

Versioned JSON envelopes (`MultisigEnvelope`) with magic prefix `GMS1`,
carried in standard Slatepack payloads. Sensitive messages (e.g. DKG partial
shares) should use age encryption to recipients.

| Body type | Use |
| --- | --- |
| `DkgContribution` | Broadcast Feldman commitments + PoP |
| `DkgPartialShare` | Private share to one actor (**encrypt**) |
| `DkgPublicPoly` | Optional joint public poly announce |
| `RpRound1` / `RpRound2` / `RpFinal` | Multiparty rangeproof rounds |
| `KernelSigningCommit` | FROST round-1 `(D_j, E_j, X_j)` |
| `KernelPartialSig` / `KernelFinal` | Partial + aggregated kernel sig |

```rust
use grin_wallet_libwallet::multisig::{
    MultisigEnvelope, build_dkg_contribution, build_kernel_final,
};

let env = build_dkg_contribution(secp, ceremony_id, sender, params, &contrib)?;
// plaintext slatepack
let sp = env.to_slatepack(None)?;
// or encrypted to recipients
let sp = env.to_encrypted_slatepack(None, recipients)?;
// armored string for file/email transport
let armored = env.to_armored_string(None, vec![])?;
```

## CLI

```bash
# Dev: full DKG on one machine, store this actor in wallet DB
grin-wallet multisig init --local-sim -m 2 -n 3 --index 0

# Multi-party DKG.
# Each actor first publishes their index-0 slatepack address:
grin-wallet address    # -> grin1... / tgrin1...
# The initiator passes the full ordered roster of addresses so shares can be
# encrypted to each actor (C-02). Every party must pass the SAME --addresses
# list in the SAME order, and the same ceremony-id.
grin-wallet multisig init -m 2 -n 3 --index 0 \
  --addresses tgrin1aaa...,tgrin1bbb...,tgrin1ccc... -o contrib0.json
# peers (same roster + ceremony-id, their own index):
grin-wallet multisig init -m 2 -n 3 --index 1 --ceremony-id <UUID> \
  --addresses tgrin1aaa...,tgrin1bbb...,tgrin1ccc... -o contrib1.json
grin-wallet multisig import-contrib -i contrib1.json   # each imports others (public)
grin-wallet multisig export-shares -d shares/          # writes *.slatepack, age-encrypted
grin-wallet multisig import-share -i shares/share_to_actor0_s0.slatepack
grin-wallet multisig finalize

grin-wallet multisig list
grin-wallet multisig show -c <UUID>
grin-wallet multisig pending
grin-wallet multisig export-state -c <UUID> -o backup.json   # SENSITIVE
grin-wallet multisig delete -c <UUID>
```

## End-to-end transactions (`tx` module)

Local-quorum path builds a full Grin `Transaction` that **validates**:

```rust
use grin_wallet_libwallet::multisig::{
    demo_fund_and_spend, build_multisig_spend, create_multisig_output,
};

// DKG → fund coin → self-spend with multiparty rangeproof + kernel
let (funding, spend) = demo_fund_and_spend(secp, &state, &quorum, fund_coin, 2, fee)?;
spend.tx.validate(Weighting::AsTransaction)?;
```

CLI demo (in-process, no chain):

```bash
grin-wallet multisig demo-tx -m 2 -n 3
```

Kernel excess sign fixed to Grin convention:  
`excess + offset = out_blinds − in_blinds`.

## Owner API / JSON-RPC

| Method | Purpose |
| --- | --- |
| `multisig_list` | List stored ceremonies |
| `multisig_init_local_sim` | Local-sim DKG, returns ceremony UUID |
| `multisig_delete` | Delete ceremony |
| `multisig_demo_tx` | E2E DKG→fund→spend; returns `tx_hex` |
| `multisig_post_tx` | Post hex transaction to node |

```bash
# Demo + optional export of tx hex
grin-wallet multisig demo-tx -m 2 -n 2 -o /tmp/msig_tx.hex

# Post to node (only useful if inputs exist on-chain)
grin-wallet multisig post-tx -i /tmp/msig_tx.hex
```

## Session negotiator (WS4)

After DKG, multiparty CreateOutput / Spend run as durable sessions:

```bash
# All parties use the same --session-tag; exchange envelope JSON files.
grin-wallet multisig session-create-output -c <ceremony-uuid> \
  --coin-number 1 --coin-value 1000000000 --session-tag my-out -o r1.json
# Peer applies and may emit the next round:
grin-wallet multisig session-apply -s <session-id-hex> -i r1.json -d out/
grin-wallet multisig session-list
grin-wallet multisig session-status -s <session-id-hex>
grin-wallet multisig session-abort -s <session-id-hex> --reason "cancel" --delete
```

Spend: `session-create-spend -c ... --input 1:1000000000 --output 2:999000000 --fee 1000000`

Owner JSON-RPC (experimental, token required):

| Method | Role |
| --- | --- |
| `multisig_session_list` | List sealed sessions |
| `multisig_session_status` | One session status |
| `multisig_session_create_output` | Start CreateOutput; returns envelope JSON |
| `multisig_session_create_spend` | Start Spend; returns envelope JSON |
| `multisig_session_apply` | Apply peer envelope JSON |
| `multisig_session_abort` | Abort + wipe secrets |

## Next implementation steps

1. ~~Persist `MultisigWalletState` in the wallet backend.~~
2. ~~Multiparty rangeproof (τ path).~~
3. ~~Threshold kernel signing (FROST).~~
4. ~~Slatepack message types for DKG / BP / sign rounds.~~
5. ~~CLI: `grin-wallet multisig ...`.~~
6. ~~Owner API JSON-RPC surface.~~
7. ~~End-to-end send/receive using multisig RP + kernel (local quorum).~~
8. ~~Post hex tx to node (`multisig_post_tx` / CLI).~~
9. ~~Durable session negotiator + session CLI.~~
10. ~~Owner RPC for session lifecycle.~~
11. Chain-aware UTXO selection + wallet output tracking
12. Multi-process soak tests
