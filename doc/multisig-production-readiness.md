# Grin Multisig — Production Readiness Document

**Date:** 2026-07-11
**Branch:** `feat/multisig-wallet` (grin-wallet, uncommitted working tree)
**Scope:** Everything required to take the current `libwallet/src/multisig/` implementation from experimental prototype to production custody of real funds.
**Audience:** Implementers, reviewers, and auditors.

This is the **master engineering document** for the effort. It consolidates and supersedes the planning content of the companion documents, which remain the source for their own domains:

| Document | Role |
| --- | --- |
| `grin/doc/multisig-implementation.md` | RFC-0023 design synthesis (protocol theory) |
| `grin/doc/multisig-crypto-review.md` | Design-level crypto review, findings F-01…F-15 |
| `grin-wallet/doc/multisig-production-plan.md` | Beam architecture comparison + phase plan |
| `grin-wallet/doc/multisig.md` | Current-status / API quickstart |
| **This document** | Code-verified gap analysis + definition of done + work plan |

---

## 1. Definition of "production ready"

Multisig is production ready when **all** of the following gates pass. Everything else in this document exists to make these gates achievable.

### Gate G1 — Cryptographic soundness
- [ ] RFC-0023 revision frozen with: degree/threshold rule, multi-share policy, named DKG variant, named threshold-signing scheme, PoP transcript, hash-to-scalar spec, wire transcripts.
- [x] Kernel signing uses FROST (Komlo–Goldberg two-round threshold Schnorr) over Lagrange partial excess keys — implementation complete in `kernel.rs`; residual: external specialist review + concurrent-session stress tests.
- [ ] Partial contributions (τ, partial sigs, DKG shares) are **verifiable before use**, with identifiable abort.
- [ ] External review by ≥1 threshold-cryptography specialist with no open Critical/High findings.

### Gate G2 — Secrets hygiene
- [ ] No secret (share, dealer coefficient, nonce seed) ever written to disk in plaintext.
- [ ] All secrets zeroized on drop; no secrets pass through `serde_json` strings.
- [ ] Share backup is an explicit, encrypted, documented artifact with a tested restore path.

### Gate G3 — Protocol robustness
- [ ] Durable session state machine: crash mid-round → resume or safe abort, never a stuck half-signed state that leaks nonce reuse.
- [ ] All wire messages authenticated (sender-signed), replay-protected (session + round + sequence), and size-bounded.
- [ ] Malicious-peer test suite passes: bad PoP, bad share, bad τ, bad partial sig, duplicate/equivocating messages, threshold inflation, abort-at-every-round.

### Gate G4 — Wallet integration
- [ ] Multisig UTXOs tracked in the wallet DB (commit, coin number, epoch, status, height, proof) and updated from chain scans.
- [ ] Coin-number allocation is coordinated (no two concurrent sessions can allocate the same number), and reorg-safe.
- [ ] Send/receive/sweep flows work over slatepack between ≥3 separate wallet processes on testnet.
- [ ] No test-only global state reachable from production APIs (see C-01).

### Gate G5 — Operations
- [ ] 30+ days on testnet with a 2-of-3 and a 3-of-5 wallet, no fund-loss bugs.
- [ ] Written runbooks: backup, restore, epoch rotation, compromise response ("suspected M-share leak ⇒ rotate + sweep immediately").
- [ ] Feature-flagged rollout (experimental → testnet → mainnet) and a scoped bug bounty.

---

## 2. Current state — verified inventory

`libwallet/src/multisig/` is ~4,600 lines across 13 modules, with working unit tests (32+) and an in-process end-to-end path that produces a fully valid Grin `Transaction` (multiparty bulletproof + threshold-signed kernel, passes `tx.validate(Weighting::AsTransaction)`).

### What demonstrably works (in-process)

| Capability | Where | Evidence |
| --- | --- | --- |
| Joint Feldman DKG, degree = `threshold × shares_per_actor − 1` | `dkg.rs`, `types.rs` | `dkg_2_of_3`, coeff-count (threshold-inflation) rejection test |
| PoP per coefficient, domain-separated transcript | `dkg.rs::pop_message` (binds ceremony id, actor id, coeff index, commitment) | verified on import in `ops.rs::dkg_import_contrib` |
| Lagrange partials / reconstruction / δ-mask algebra | `share.rs` | cancel + reconstruction tests |
| Coin derivation `x_coin = H("coin"‖number‖value)`, view mix | `coin.rs` | same-number-different-value test |
| Multiparty bulletproof T1/T2 → τ → finalize over `bullet_proof_multisig` | `rangeproof.rs` | 2-of-3 and 3-of-3 proofs verify; rewind recovers value + coin number |
| Threshold kernel sign (**FROST** + poly excess check) | `kernel.rs` | 2-of-3 / 3-of-3 sign+verify, binding-factor, `TxKernel::verify` |
| E2E tx build + validation, hex round-trip | `tx.rs` | `e2e_fund_and_spend_validates`, `demo_tx_hex_roundtrip` |
| LMDB persistence with XOR-obfuscated shares | `store.rs`, `impls/backends/lmdb.rs` | round-trip test |
| Slatepack JSON envelopes (`GMS1`, versioned) for DKG/RP/kernel rounds | `messages.rs` | round-trip tests |
| File-based multi-party DKG orchestration + CLI + Owner RPC | `ops.rs`, `controller/command.rs`, `api/owner*.rs` | manual flow documented in `multisig.md` |

### What does not exist yet

- Networked multi-wallet **transaction** ceremonies (rangeproof/kernel rounds exist as APIs and message types, but only the DKG has file-based orchestration; there is no session runner).
- Chain awareness: no UTXO tracking, no coin-number allocator, no scan/rewind integration, no lock/unlock, no confirmation handling (`tx.rs` header: "Does not consult the chain").
- Durable session state machine (Beam `Negotiator` analog) with crash recovery.
- Epoch rotation / re-DKG migration flow.
- Any hardware-signer path.

---

## 3. Code-level findings (this review)

These are **new findings from reading the working-tree code**, complementary to the design-level review (F-01…F-15). Ordered by severity. Fix column names the owning workstream (§5).

### C-01 — Production Owner API mutates global chain type — **Critical (safety)** — ✅ FIXED
`tx.rs:305` (`run_demo_tx`) called `global::set_local_chain_type(ChainTypes::AutomatedTesting)`, reachable from the **Owner JSON-RPC** via `multisig_demo_tx`. On a live wallet handler thread this installed a thread-local override that silently reconfigured consensus parameters for every subsequent operation on that thread.
**Resolution:** the global mutation was removed from `run_demo_tx`; the demo now runs under whatever chain type the host already configured (always set inside a running wallet). Chain-type setup moved into the unit test that needed it; the Owner API method carries an explicit dev-only warning. Verified: 32/32 multisig tests pass.

### C-02 — DKG partial shares written to disk in plaintext — **Critical (secrets)** — ✅ FIXED
`ops.rs::dkg_export_shares` wrote raw dealer partial evaluations (`share_hex`) as plaintext JSON files; age encryption existed in `messages.rs` but was unused, because index-based actor ids carried no recipient key.
**Resolution:** adopted the RFC-0023 identity model — actors in a multi-party ceremony are identified by their **Slatepack address** (`ActorId::from_slatepack_address` / `slatepack_address()`; `from_index` remains dev/local-sim only). `dkg_export_shares` now resolves each recipient's address and writes an **age-encrypted, armored Slatepack** (`share_to_actor{i}_s{k}.slatepack`), refusing to run at all on an index-only roster — so a plaintext share can no longer be written. Import decrypts with the wallet's Slatepack secret key (`read_encrypted_share_file` → `MultisigEnvelope::from_armored_string`). The roster is supplied via `multisig init --addresses` (each actor's index-0 address, same ordered list for all parties). Verified: encrypt→decrypt roundtrip recovers the exact share, the armored blob does not contain the plaintext, and index actors are rejected (37/37 multisig tests).
**Residual (tracked under WS2):** δ-masking is still not applied to the delivered partials (defense against a malicious near-quorum during add-actor, F-03); envelope authentication/replay protection is C-04.

### C-03 — Dealer secret coefficients persisted in plaintext pending file — **Critical (secrets)** — ✅ FIXED
`PendingDkg` stored `my_coeff_hexes` (the dealer's secret polynomial) and accumulated share sums (`my_share_ys_hex`) as hex in a JSON file in the wallet data dir. A file-system read during the (possibly days-long) ceremony window leaked the dealer's entire contribution.
**Resolution:** the pending file is now AEAD-encrypted (ChaCha20-Poly1305, `store::seal_pending`/`open_pending`) under a keychain-derived key (`store::derive_pending_key`, domain-separated from the share-obfuscation key). File renamed to `pending_dkg.enc`; every pending-touching CLI command now unlocks the wallet to derive the key, so the file can neither be read nor written without wallet access. Legacy plaintext file removed on `clear`. Verified: seal/open roundtrip, wrong-key rejection, and tamper rejection tests pass (35/35 multisig tests).
**Residual:** none material for C-03; LMDB/export AEAD completed under C-08.

### C-04 — Wire envelopes are unauthenticated — **High** — ✅ FIXED
`MultisigEnvelope.sender` was attacker-controlled, checked against the roster by id with no signature; a re-imported contribution silently overwrote `contributions[idx]`, and a replayed share was **summed twice** into the accumulator (a silent corruption, not just a nuisance).
**Resolution:**
- **Authentication:** `MultisigEnvelope` carries a detached ed25519 `sig_hex` over a canonical transcript — `magic ‖ version ‖ ceremony_id ‖ session_id ‖ sender.id ‖ SHA256(body)` — signed by the sender's Slatepack key (`sign`/`verify_signature`). The signing key must match the declared sender address, so a wallet cannot sign as an actor it is not. `dkg_start` and `dkg_export_shares` sign; `dkg_import_contrib`/`dkg_import_share` verify against the **trusted roster** entry (address-based ceremonies require a valid signature; index/dev rosters, which cannot be authenticated, stay unsigned). Shares are signed **then** encrypted.
- **Equivocation:** a second, *different* contribution from an actor is rejected (identical re-import is idempotent).
- **Replay:** `PendingDkg.applied_share_dealers` tracks which dealer indices have been summed per share; a duplicate/replayed share is refused instead of double-counted.
Verified by unit tests (sign/verify, tamper, wrong-sender, key-mismatch) and a full 2-of-2 authenticated DKG exchange over the file API that also asserts replay rejection (41/41 multisig tests).
**Residual (WS2/WS5):** transcript binds sender+ceremony+session+body but not an explicit round/sequence counter (contribution/share replay is covered structurally; kernel/rangeproof round messages will need per-round sequence binding when the session engine lands). δ-masking of delivered shares (F-03) is still open.

### C-05 — Kernel nonce commitment binds too little — **High** — ✅ FIXED (FROST)
The prior additive aggsig path used a weak hash commit to a single nonce and did not bind claimed `pub_excess` (rogue-key / adaptive last-mover risk).
**Resolution — FROST kernel signing (`kernel.rs`):**
- Each actor samples **two** nonces `(d_j, e_j)` and broadcasts `SigningCommitment = (D_j, E_j, X_j)` in one round (`kernel_round1`).
- Per-actor **binding factor** `ρ_j = H_s("grin-msig/frost-rho" ‖ session ‖ offset ‖ all commitments ‖ j)` (`binding_factor`) feeds group nonce `R = Σ (D_j + ρ_j·E_j)` (`aggregate_frost`).
- Partial sign uses effective nonce `k_j = d_j + ρ_j·e_j`; aggregates via existing `aggsig` into a normal Grin kernel signature.
- **Rogue-key guard retained:** `expected_pub_excess_for_actor` / `verify_partial_excess` check every claimed `X_j` against the public polynomial before signing.
- Wire: `KernelSigningCommit` replaces `KernelNonceCommit` / `KernelNonceReveal`.
Verified by multiparty sign, binding-factor context tests, bad-partial rejection, and `TxKernel::verify()` on the aggregated sig.
**Residual:** external specialist review of FROST composition with multiparty BP over the same shares; concurrent multi-session stress tests.

### C-06 — Partial τ contributions are unverifiable — **High** (review F-07) — ✅ FIXED
`aggregate_tau` previously summed τ shares blindly; a garbage `τ_j` failed only at finalize with no attribution.
**Resolution (`rangeproof.rs`):**
- libsecp multiparty BP satisfies `τ_j = τ1_j·x + τ2_j·x² + z²·blind_j` with round-1 exports `T1_j = τ1_j·G`, `T2_j = τ2_j·G`.
- Challenges `(x, z²)` are recovered by local **probe** step-2 runs against the same aggregated T1/T2 (same Fiat–Shamir transcript); probe `(τ1,τ2)` pairs are re-derived via bit-compatible `scalar_chacha20`.
- `expected_pub_blind_for_actor` predicts `P_j = blind_j·G` from the public polynomial (+ actor-0 view mix).
- `verify_tau_share` checks `τ·G = x·T1 + x²·T2 + z²·P`; `aggregate_tau_verified` attributes failures to the actor index (identifiable abort).
- `run_rangeproof_local` always verifies before summing.
Verified: chacha20 matches round-1 T1/T2, honest τ accepted, corrupted τ from actor 1 rejected with that index, full multiparty proofs still verify.

### C-07 — Quorum ordering and the actor-0 special role are un-transcripted — **High (protocol fragility)** — ✅ FIXED
`partial_excess_for_actor` and `quorum_partial_blinds` used positional index 0 for mix/offset with no canonical order.
**Resolution:**
- `canonical_quorum` sorts by x-coordinate (big-endian); index 0 is the **mix/offset role**.
- `quorum_partial_blinds`, `partial_excess_for_actor`, `expected_pub_*`, `run_*_local`, and `quorum_from_states` always canonicalize.
- Kernel sessions bind `quorum_transcript` (canonical x-list) into the session id / offset context.
Verified: reverse-order quorums produce the same excess and valid rangeproofs.

### C-08 — Secrets pass through JSON and are never zeroized — **Medium/High** — ✅ FIXED (core hygiene)
**Resolution:**
- **LMDB ceremony state** sealed with ChaCha20-Poly1305 (`MSAE` magic + keychain-derived `state-key-v1`); XOR-only path removed (no integrity).
- **Export/import** is the same AEAD blob (`export_state_sealed` / `import_state_sealed`); plaintext JSON export removed.
- **Pending DKG** already AEAD (C-03); plaintext buffers zeroized after seal/open.
- **Debug redaction** for `SecretShare`, `MultisigWalletState`, `ActorPoint`, `SecretPoly`, `DealerSecrets`, `ActorKernelSecrets`, `ActorRpSecrets`, `PendingDkg`, `TauChallenges`.
- `SecretKey` already uses `zeroize` on drop (secp crate).
**Residual:** clones of secrets in hot paths still exist (hard to eliminate without larger API redesign); optional `ZeroizeOnDrop` wrappers later.

### C-09 — Deterministic public offset — **Medium (privacy)** — ✅ DECIDED (v1)
`tx_offset` derives from the **public** `S_0` + session context.
**v1 product decision:** **Accept and document.** Offset secrecy is **not** part of the co-owner threat model: co-owners (and anyone with `MultisigConfig`) can recompute offsets for known sessions. Unlinkability against external chain observers remains (they lack `S_0` unless a config leak). A future epoch may bind offsets to a shared secret if product requires co-owner privacy of the offset itself.

### C-10 — Rewind/view capability equals "has the public poly" — **Medium** — ✅ DECIDED (strategy A for v1)
View mix / shared BP nonce derive from `S_0` (public poly constant term).
**v1 product decision: RFC strategy A.** Holding `MultisigConfig` (or any actor backup containing the public poly) grants **permanent view/rewind** of that epoch's outputs, including after an actor is removed. Product UX must warn: export/backup of config = view key; rotation requires re-DKG + sweep, not just roster change. Strategy B (epoch view keys) is deferred post-v1.

### C-11 — `ThresholdParams::new` does not enforce the PTE floor — **Medium** (review F-08) — ✅ FIXED (floor enforced; cryptanalysis residual)
**Resolution:**
- Production constructors `new` / `with_shares_per_actor` reject `num_coefficients() < MIN_SHARES_FOR_DEGREE` (4).
- Tests/dev use `new_allow_low_degree` / `with_shares_per_actor_allow_low_degree`.
- CLI/DKG default remains `recommended_shares_per_actor` (already floor-compliant).
**Residual:** commission PTE cryptanalysis to justify the numeric floor value.

### C-12 — No DoS bounds on message parsing — **Medium** — ✅ FIXED
**Resolution (`messages.rs`):**
- Max JSON size `MAX_ENVELOPE_JSON_BYTES` (256 KiB) checked **before** full structural use (`from_payload_bytes`, `from_json_str`, file stat in `read_envelope_file`).
- After parse: `validate_limits()` caps list lengths (`MAX_LIST_LEN` = 64), actor id/label size, hex field lengths, and rejects non-hex characters.
- Session negotiator already had a parallel size check; both paths now consistent.
Tests: oversized payload rejected; too many coefficients rejected; non-hex τ rejected.

### C-13 — Add-actor remains exposed — **Medium** (review F-03) — ✅ FIXED (v1)
**Resolution:** `add_actor_masked_share` is no longer re-exported from the crate root and is `#[cfg(test)]` only. v1 membership change = re-DKG new epoch + on-chain sweep.

### C-14 — DKG is joint-Feldman "v0" by design — **Medium** (review F-04, open)
`dkg.rs` header admits: "Joint-Feldman can be biased by last movers; acceptable for v0 research." No complaint round, no commit-then-reveal of contributions, no abort rules for missing dealers (F-10: share assembly assumes all N dealers deliver; `dkg_finalize` verifies the sum against the public poly, which detects but cannot attribute failures).
**Fix (WS2):** adopt a named robust DKG (Gennaro et al. or a modern FROST-DKG); add contribution commit-reveal to kill last-mover bias; define complaint/abort with attribution.

### Positive code-level notes

- `scalar.rs::hash_to_scalar` uses **rejection sampling with domain tags**, not Ed25519 clamping — F-09's main hazard is correctly avoided (cross-curve DH → scalar path must keep this property when real slatepack DH lands).
- Threshold-inflation (coefficient-count) checks exist and are tested — the Trail-of-Bits DKG bug class is covered.
- Degree = `t−1` (F-01) is fixed and structurally enforced via `num_coefficients()` checks in `verify_pop` and `MultisigConfig::validate`.
- The false HKDF claim (F-02) is honestly re-documented in `coin.rs`.
- Value-in-derivation (F-14) implemented and tested.

---

## 4. Crypto-review findings → implementation status

| Finding | Severity | Status in code | Remaining work |
| --- | --- | --- | --- |
| F-01 degree/threshold | Critical | **Fixed** (`types.rs`, enforced) | Freeze in RFC text; cross-impl vectors |
| F-02 HKDF claim | High | **Documented honestly** (`coin.rs`) | RFC text fix; decide C-09/C-10 |
| F-03 add-actor exfiltration | High | **Gated** (not public API; C-13) | Re-DKG + sweep for membership |
| F-04 robust DKG | High/Med | **Open** ("v0" joint-Feldman) | WS2: named DKG + complaints (C-14) |
| F-05 PoP underspecified | Medium | Largely fixed (`pop_message` binds ceremony/actor/index/commitment) | Bind full coefficient vector + params into each PoP msg; RFC transcript |
| F-06 kernel signing scheme | High | **Fixed in code** (FROST + excess check; C-05) | External audit still required |
| F-07 BP partial verification | Med/High | **Fixed in code** (C-06 verifiable τ + actor index) | External audit residual |
| F-08 PTE parameters | High (small M) | **Floor enforced** (C-11) | Cryptanalysis to justify floor value |
| F-09 hash-to-scalar | Medium | **Fixed** (rejection sampling) | Keep property for real DH; test vectors |
| F-10 δ-mask / all-N delivery | Medium | Algebra implemented; abort rules missing | WS2 session rules |
| F-11 backup model | Medium | **Sealed export** (C-08 AEAD) | Restore drill + runbook (WS7) |
| F-12 M-shares ⇒ total compromise | High (inherent) | Documented | Runbooks (WS7); UX warnings |
| F-13 address grinding | Low/Med | `ActorId::from_index` avoids it; address-based ids possible | Commit-reveal when real addresses used |
| F-14 value in derivation | Low/Med | **Fixed + tested** | Bind concrete commitment list into signing transcript (with C-05 fix) |
| F-15 editorial | Low | n/a (code diverged deliberately, documented in `multisig.md`) | Sync RFC text |

---

## 5. Workstreams

Ordered so that each unblocks the next. Effort assumes 1–2 senior engineers plus an external reviewer.

### WS1 — Spec freeze (2–4 weeks, blocks everything crypto)

1. Revise RFC-0023 to match code reality and close the design decisions this document flags:
   - degree rule + enforced PTE floor (C-11), FROST as the kernel scheme, named DKG variant (C-14), PoP transcript, hash-to-scalar spec, canonical quorum/session transcript (C-07), offset derivation decision (C-09), view-key strategy A/B (C-10), add-actor removed for v1 (C-13).
2. Write the explicit **threat model** (the crypto review §3 "missing goals" list is the checklist: identifiable abort, concurrency, adaptive corruption stance, rotation security).
3. Publish cross-implementation **test vectors**: 2-of-3 and 3-of-5 DKG transcripts, coin derivations, kernel transcripts.

**Exit:** RFC accepted; external reviewer signed off on the spec (not yet the code).

### WS2 — Crypto hardening (4–8 weeks)

| Task | Files | Acceptance |
| --- | --- | --- |
| ✅ FROST kernel over Lagrange excess (hand-rolled on Grin `aggsig`; not ZF-FROST crate) | `kernel.rs` | Sign/verify, binding-factor, `TxKernel::verify`; residual: concurrent-session stress + specialist audit |
| Verify partial excess pubkeys against the public poly (`λ_j`-weighted `P(x)` sums) | `kernel.rs` | Wrong-excess partial rejected with attribution |
| Verifiable τ contributions + identifiable abort | `rangeproof.rs` | Bad τ_j rejected, culprit named; negative tests |
| Robust DKG: contribution commit-reveal, complaint round, abort rules | `dkg.rs` | Last-mover bias test; missing-dealer abort test |
| Canonical session transcript (quorum set, ordering, coin lists, commitments, fee, epoch) hashed into every signature and commitment | `kernel.rs`, `messages.rs` | Transcript mismatch ⇒ abort before secret reveal |
| Enforce PTE floor; commission degree cryptanalysis | `types.rs` | Low-degree construction impossible without dev flag |
| Port Beam's multiparty-BP test structure (N = 2..5, phased CoSign discipline, external-randomness-per-ritual rule) as golden vectors | `rangeproof.rs` tests | Deterministic vectors in repo; N=5 passes |

**Beam references to mirror:** `core/ecc_bulletproof.cpp` (`MultiSig::CoSignPart`, phased `Step2`/`Finalize`), `core/ecc.h` nonce-hygiene comments, `core/unittest/ecc_test.cpp` 5-signer BP test.

### WS3 — Secrets hygiene (2–4 weeks, parallel with WS2) — mostly done

1. ✅ AEAD-encrypt: LMDB state + state export (C-08), pending-DKG file (C-03).
2. ✅ Age-encrypted DKG share delivery (C-02); residual: δ-masking.
3. ✅ Debug redaction + plaintext buffer zeroize after seal/open; `SecretKey` zeroizes on drop.
4. Residual: scripted restore drill / runbook for sealed backup objects (F-11 / WS7).

### WS4 — Session engine / negotiator (6–10 weeks) — **foundation landed**

Core negotiator is implemented in `libwallet/src/multisig/session.rs`:

```
SessionStore (filesystem AEAD: wallet_data/multisig/sessions/*.enc)
  session_id, ceremony_id, kind (CreateOutput | Spend), phase
  canonical quorum x-list, roster, my_index
  secrets (hex, wiped on Complete/Abort) — sealed with session key
  seen_body_hashes (replay), collected round contributions

Negotiator
  create_output / create_spend  → first outbound envelope
  apply(envelope) → Vec<outbound>   // idempotent, replay-safe, size-capped
  tick()                            // emit when barriers clear
  resume(record)                    // crash recovery
  abort(reason)                     // wipe secrets
```

**Barriers:** never send τ until all T1/T2 in; never send kernel partial until all FROST commits in. Sender index checked against canonical quorum x (C-07).

**Tests (in-module):** 2-of-2 CreateOutput + Spend complete; crash-resume mid-CreateOutput after R1; abort wipes secrets; exact-message replay is idempotent.

**Still open for full WS4 exit:**
- ✅ DKG as session kind (index + address roster; signed contribs; age share export)
- ✅ Multi-process CLI session create/apply/status/abort + Owner RPC (+ session-dkg-*)
- 3-process slatepack file/socket integration with kill-resume at every boundary
- ✅ Deadlines / timeout abort; files are AEAD (LMDB session store optional)
- ✅ Combined CreateOutput+Spend MultiTx session (`SessionKind::MultiTx`)

### WS5 — Wire format & transport (3–5 weeks, overlaps WS4)

1. Envelope authentication: ed25519 signature by sender's slatepack key over the full header+body (C-04); duplicate/equivocation detection.
2. Round/sequence numbers + session binding in every message; replay cache per ceremony.
3. Size/count caps before parse (C-12); fuzz the parser (`cargo-fuzz` target for `MultisigEnvelope`).
4. Freeze the v1 format (keep JSON if frozen and fuzzed, or move to binary ser like the rest of Grin — decide once, in WS1).

### WS6 — Wallet & API integration (6–12 weeks) — **UTXO foundation landed**

1. ✅ C-01 removed earlier.
2. ✅ Multisig UTXO tracking: `MultisigUtxo` in LMDB (`U` prefix), status lifecycle, height/mmr fields; CLI `list-utxos` / `register-utxo` / `recognize-utxo` / `scan-utxos`; Owner RPC counterparts.
3. ✅ Coin-number allocator: high-water meta (`N` prefix) + `allocate_coin` → Reserved UTXO; next = max(known, high_water)+1.
4. ✅ Recognition via shared-nonce rewind (`try_recognize_output`) without enumerating coin numbers.
5. ✅ Session ↔ UTXO coupling: CreateOutput links/registers on start+complete; Spend locks inputs and marks Spent on complete; Abort unlocks; `scan_ceremony_utxos` PMMR walk via node client.
6. ✅ Light `refresh_multisig_utxos` + `expire_stale_sessions` hooked into `update_wallet_state` / owner updater (soft-fail).
7. ✅ Session deadlines (default 24h TTL); apply after deadline aborts + unlocks.
8. ✅ `select_spendable_utxos` greedy selection; `plan_epoch_sweep` for re-DKG migration inventory.
9. ✅ Tx assembly from completed Spend + proofs (`assemble_from_kernel_results` / `assemble-tx`); local `build_epoch_sweep_local` consolidation.
10. ✅ Envelope fuzz targets under `libwallet/fuzz`; v1 JSON wire freeze notes + ops runbook in `doc/multisig.md`.
11. ✅ DKG-as-session (index + address roster, signed contribs, age share export) + file harness crash-resume + share replay/equivocation tests.
12. ✅ Cross-epoch MultiTx local builder (`build_cross_epoch_spend` / FROST with dual polys) + multiparty soak unit rounds.
13. ✅ MultiTx durable session + 2-of-3 sealed-file MultiTx soak harness.
14. Residual: multi-process soak on real wallets; networked cross-epoch session kind; slate nesting in standard send flow.

### WS7 — Testing, audit, launch (4–8 weeks, gates G1/G3/G5)

- Malicious-peer suite (every C-finding gets a regression test).
- Multi-process testnet soak: 2-of-3 and 3-of-5, ≥30 days, scripted crash/restore/rotate drills.
- Fuzzing: envelope parser, DKG aggregation, τ aggregation, session resume.
- External audit of `crypto/*` + negotiator; treat as consensus-adjacent.
- Runbooks: backup, restore-from-M-shares, compromise response (rotate + sweep), removed-actor privacy caveats (C-10).
- Bug bounty scoped to the multisig module before mainnet flag flips.

---

## 6. Prioritized backlog

**P0 — before any real value (testnet with meaningful amounts included):**
1. ✅ C-01 chain-type footgun removal.
2. ✅ C-02/C-03 plaintext secrets on disk (pending file AEAD-encrypted; share export age-encrypted to recipient addresses).
3. ✅ C-04 envelope authentication + replay protection.
4. ✅ C-07 canonical quorum + mix/offset role; C-11 PTE floor; C-13 add-actor gated.
5. ✅ C-05 FROST kernel (binding factors + excess poly check).
6. ✅ C-06 verifiable multiparty τ (identifiable abort).
7. ✅ C-09/C-10 v1 product decisions + formal wire freeze text in `doc/multisig.md`.
8. ✅ WS4 negotiator + CLI + Owner RPC + DKG session. Residual: multi-process soak.
9. ✅ C-12 envelope DoS caps.
9b. ✅ Session TTL/deadline + expire path; updater light refresh.

**P1 — before mainnet flag:**
10. ✅ WS6 UTXO foundation + assemble-tx + same-epoch sweep + **cross-epoch** local MultiTx.
11. ✅ C-08 AEAD state + Debug redaction; restore/compromise runbook in `doc/multisig.md`.
12. ✅ WS5: v1 JSON freeze + C-finding regression map + `libwallet/fuzz`. Residual: continuous fuzz CI.
13. External audit + expanded malicious suite + 30-day soak.

**P2 — quality/optional:**
11. Hardware-keykeeper interface design (Beam `private_key_keeper` pattern).
12. Beam-style additive 2-of-2 cosign track for swaps/channels (separate product; avoids F-12 for those use cases).
13. Async mailbox transport (SBBS analog) beyond file/slatepack exchange.

---

## 7. Timeline (indicative)

```
Month 0–1   WS1 spec freeze  +  C-01/C-02/C-03 hotfixes  + external review kickoff
Month 1–3   WS2 crypto hardening  ‖  WS3 secrets hygiene
Month 2–5   WS4 negotiator  ‖  WS5 wire format
Month 4–7   WS6 wallet integration → testnet
Month 6–9   WS7 audit, soak, bounty → mainnet feature flag
```

~6–9 months with 1–2 senior engineers plus an external cryptographer, consistent with the earlier plan's estimate — the code base is further along on crypto primitives than the plan assumed, but the session engine and integration remain green-field.

---

## 8. Appendix — file map (current → target)

| Current file | Verdict | Target |
| --- | --- | --- |
| `types.rs` | Keep; enforce degree floor | `multisig/types.rs` |
| `scalar.rs` | Keep (correct rejection sampling) | `crypto/scalar.rs` |
| `poly.rs`, `share.rs` | Keep; drop public add-actor | `crypto/shamir.rs` |
| `dkg.rs` | Rework (robust DKG, commit-reveal, complaints) | `crypto/dkg.rs` |
| `kernel.rs` | ✅ FROST core landed; keep hardening + concurrent-session tests | (optional later split) `session/kernel.rs` |
| `rangeproof.rs` | Keep structure; add τ verification + golden vectors | `crypto/mp_bp.rs` |
| `coin.rs` | Keep; document C-09/C-10 decisions | `multisig/coin.rs` |
| `messages.rs` | Add signatures, rounds, caps; freeze v1 | `wire/v1.rs` |
| `ops.rs` | Split: crypto-free glue → CLI; ceremony logic → negotiator | `session/*` |
| `tx.rs` | Keep as validation harness; demo paths test-gated | `session/spend.rs` |
| `store.rs` | AEAD instead of XOR; add session store | `store/*` |
| `api/owner*.rs`, CLI | Replace demo endpoints with session lifecycle | — |

### References
- Design: `grin/doc/multisig-implementation.md`; review: `grin/doc/multisig-crypto-review.md`; Beam comparison: `doc/multisig-production-plan.md`; status: `doc/multisig.md`.
- RFC thread: https://forum.grin.mw/t/multisig-wallet-rfc/12316
- FROST (Komlo–Goldberg, ePrint 2020/852); MuSig2; Gennaro et al. DKG; Bünz et al. Bulletproofs §4.5.
- Beam @ `4e01b68`: `core/negotiator.{h,cpp}`, `core/ecc_bulletproof.cpp`, `core/unittest/ecc_test.cpp`, `wallet/laser/*`.
