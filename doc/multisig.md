# Multisig (experimental)

Wallet-layer M-of-N threshold multisig primitives live in
`grin_wallet_libwallet::multisig`.

## Status

**Experimental — not safe for real funds.**

This is the first implementation slice of RFC-0023 style multisig:

| Done | Not done |
| --- | --- |
| Joint Feldman DKG (degree = threshold−1) | Owner/Foreign API + CLI |
| PoP on coefficient commitments | Production key rotation / epochs |
| Share verify against public poly | External crypto audit |
| Lagrange partial keys + reconstruction | Full FROST (optional upgrade) |
| δ-masked add-actor (local) | End-to-end slatepack orchestration CLI |
| Coin id derivation (number + value) | |
| LMDB persistence (XOR-obfuscated shares) | |
| Multiparty Bulletproof (T1/T2/τ rounds) | |
| Threshold kernel signing (additive aggsig + nonce commit) | |
| Slatepack wire messages (DKG / RP / kernel) | |
| CLI (`grin-wallet multisig ...`) | |
| E2E tx build (multiparty RP + kernel, validates) | |
| Owner API + JSON-RPC + post-tx | |
| Unit / integration tests | |

## Design choices vs draft RFC

1. **Polynomial degree = `threshold * shares_per_actor − 1`**  
   (fixes inconsistent degree-M with M shares in the draft).

2. **`recommended_shares_per_actor`** raises degree when M is small  
   (PTE / Wagner hardening).

3. **View mix is not claimed to hide the polynomial** if full blinds leak  
   (fixes incorrect HKDF security argument).

4. **Add-actor is implemented but documented as dangerous** under near-quorum  
   collusion; prefer full re-DKG for membership changes.

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

Shares are XOR-obfuscated with a keychain-derived key before LMDB write
(same idea as private tx context). This is **not** full encryption at rest
if the seed is unlocked in the same process.

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

// In-process (tests / same-host quorum):
let (proof, params) = run_rangeproof_local(secp, &public_poly, &quorum, &coin, None)?;

// Networked-style rounds (each actor):
let (secrets, r1) = rangeproof_round1(secp, &params, &partial_blind)?;
let agg = aggregate_round1(secp, &all_r1_shares)?;
let tau_j = rangeproof_round2(secp, &params, &secrets, &agg)?;
let tau = aggregate_tau(secp, &all_tau)?;
let proof = rangeproof_finalize(secp, &params, &secrets, &agg, &tau)?;
verify_rangeproof(secp, params.commit, proof, None)?;
```

Shared view seed → `shared_nonce` (scan/rewind). Per-actor CSPRNG → `private_nonce`.

## Threshold kernel signing API

Uses Grin’s additive aggsig (same family as sender/receiver), with **nonce
commitments** before reveal. Not full FROST; suitable for a known interactive
quorum.

```rust
use grin_wallet_libwallet::multisig::run_kernel_sign_local;

let (sig, agg, session) = run_kernel_sign_local(
    secp, &public_poly, &quorum, b"session-id", fee, inputs, outputs,
)?;
// sig verifies against agg.excess_sum for the kernel message
```

Per-actor flow: `kernel_prepare` → exchange commitments → reveal nonces →
`kernel_partial_sign` → `kernel_aggregate_sigs`.

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
| `KernelNonceCommit` / `KernelNonceReveal` | Kernel nonce commit-reveal |
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

## Next implementation steps

1. ~~Persist `MultisigWalletState` in the wallet backend.~~
2. ~~Multiparty rangeproof (τ path).~~
3. ~~Threshold kernel signing (additive aggsig + nonce commit).~~
4. ~~Slatepack message types for DKG / BP / sign rounds.~~
5. ~~CLI: `grin-wallet multisig ...`.~~
6. ~~Owner API JSON-RPC surface.~~
7. ~~End-to-end send/receive using multisig RP + kernel (local quorum).~~
8. ~~Post hex tx to node (`multisig_post_tx` / CLI).~~
9. Chain-aware UTXO selection + wallet output tracking (optional)
10. Networked multi-wallet orchestration over slatepack messages (optional)
