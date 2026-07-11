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
- [ ] Kernel signing uses a scheme with published security analysis (FROST for M-of-N; MuSig2 acceptable for an N-of-N cosign track) — **not** the current ad-hoc additive aggsig + hash-commit.
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
| Threshold kernel sign (additive aggsig + nonce hash-commit) | `kernel.rs` | 2-of-3 / 3-of-3 sign+verify, partial-sums test |
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

### C-02 — DKG partial shares written to disk in plaintext — **Critical (secrets)**
`ops.rs::dkg_export_shares` (lines 383–426) writes raw dealer partial evaluations (`share_hex`) as plaintext JSON files. δ-masking is implemented in `share.rs` but **not applied** in this path, and age encryption exists in `messages.rs::to_encrypted_slatepack` but is not used. Anyone who reads the export directory (or the files in transit) learns dealer partials; M of them reconstruct shares.
**Fix (WS3/WS5):** exporting a `DkgPartialShare` must be impossible without age encryption to the recipient; apply δ-masking to production share delivery; shred plaintext temp files.

### C-03 — Dealer secret coefficients persisted in plaintext pending file — **Critical (secrets)** — ✅ FIXED
`PendingDkg` stored `my_coeff_hexes` (the dealer's secret polynomial) and accumulated share sums (`my_share_ys_hex`) as hex in a JSON file in the wallet data dir. A file-system read during the (possibly days-long) ceremony window leaked the dealer's entire contribution.
**Resolution:** the pending file is now AEAD-encrypted (ChaCha20-Poly1305, `store::seal_pending`/`open_pending`) under a keychain-derived key (`store::derive_pending_key`, domain-separated from the share-obfuscation key). File renamed to `pending_dkg.enc`; every pending-touching CLI command now unlocks the wallet to derive the key, so the file can neither be read nor written without wallet access. Legacy plaintext file removed on `clear`. Verified: seal/open roundtrip, wrong-key rejection, and tamper rejection tests pass (35/35 multisig tests).
**Residual (tracked under WS3):** `zeroize` on the in-memory secret buffers is still pending; AEAD is not yet applied to `export_state_json` (C-08) or the LMDB XOR path.

### C-04 — Wire envelopes are unauthenticated — **High**
`MultisigEnvelope.sender` is attacker-controlled: `dkg_import_contrib` (`ops.rs:317`) looks up the actor roster by `envelope.sender.id` with no signature check. Any party who can place a file/slatepack can impersonate any actor, substitute contributions, or replay a previous ceremony's messages (there is no round/sequence number, only ceremony-id match; a re-imported contribution silently overwrites `contributions[idx]`).
**Fix (WS5):** sign every envelope with the sender's slatepack ed25519 key over `(magic ‖ version ‖ ceremony_id ‖ session_id ‖ round ‖ seq ‖ body_hash)`; reject duplicates/equivocation explicitly (two different signed round-r messages from one actor = abort with proof).

### C-05 — Kernel nonce commitment binds too little — **High**
`kernel.rs::commit_nonce` (line 236) commits to `SHA256(tag‖pub_nonce)` only. It does not bind the actor identity, session id, or the actor's `pub_excess`. Consequences: (a) commitments are replayable across sessions; (b) the last revealer chooses/claims `pub_excess` **after** seeing everyone's nonces and excess keys — the classic adaptive-key setting the commit-reveal was meant to prevent (rogue-key style cancellation on `excess_sum` is checked nowhere; correctness currently relies on tx balance failing, which is detection-by-DoS, not security).
**Fix (WS2):** superseded by the FROST migration (which has its own binding factors). If additive aggsig is retained short-term: commit to `H(tag‖session_id‖actor_id‖pub_nonce‖pub_excess)`; verify each `pub_excess` equals the Lagrange-predicted public partial `λ_j·P(x_coin)` combination — this is computable from public data and is a **must** even under FROST for the excess key itself.

### C-06 — Partial τ contributions are unverifiable — **High** (review F-07, still open)
`rangeproof.rs::aggregate_tau` sums τ shares blindly. A malicious quorum member can submit garbage τ_j; failure appears only at `rangeproof_finalize`, with no attribution (no identifiable abort), enabling untraceable griefing and repeated-session probing.
**Fix (WS2):** add per-actor τ verification (linear relation of τ_j against that actor's published T1_j/T2_j and partial-blind commitment, or a DLEQ proof), matching Beam's ability to validate cosign parts; add negative tests ("bad τ rejected, culprit identified").

### C-07 — Quorum ordering and the actor-0 special role are un-transcripted — **High (protocol fragility)**
`partial_excess_for_actor` and `quorum_partial_blinds` give index 0 the view-mix and the offset subtraction. Nothing in the wire format canonicalizes quorum membership or ordering; if two actors order the quorum differently, partials silently don't sum to the excess (stuck sessions), and "who is actor 0" is implicit.
**Fix (WS2/WS5):** define a canonical quorum encoding (sorted by x-coordinate) inside the signed session transcript; make the mix/offset assignment explicit in the session record rather than positional.

### C-08 — Secrets pass through JSON and are never zeroized — **Medium/High**
`MultisigWalletState` (containing `SecretShare.y`) is serialized with `serde_json` for LMDB (`store.rs:108-119`), export (`export_state_json` — documented "SENSITIVE" but plaintext), and the pending file. `SecretKey` values are cloned freely throughout; nothing implements `Zeroize`. XOR obfuscation in `store.rs` has no integrity (bit-flips silently corrupt shares) and is not applied to `export_state_json`.
**Fix (WS3):** AEAD (e.g. `age` or ChaCha20-Poly1305 under a keychain-derived key) for stored + exported state; `zeroize` on all secret-bearing types; keep secrets out of `Debug` derives (`ActorKernelSecrets`, `ActorRpSecrets`, `DealerSecrets`, `SecretShare` all derive/expose `Debug` today).

### C-09 — Deterministic public offset — **Medium (privacy/documented trade-off)**
`coin.rs::tx_offset` derives the kernel offset from the **public** `S_0` + session context. Anyone holding the (public) ceremony config — including removed actors, or a thief of any actor's wallet file — can recompute offsets and strip them from kernels for known sessions, weakening the offset's unlinkability role for this wallet's transactions.
**Fix (WS1):** either accept and document (offset secrecy is not part of the threat model between co-owners), or derive from a shared *secret* session value (e.g. bound into the DKG output rather than S_0).

### C-10 — Rewind/view capability equals "has the public poly" — **Medium (design decision needed)**
`derive_shared_nonce` and `view_mix` derive from `S_0`. Every actor (and anyone who obtains a wallet-state backup, and every **removed** actor forever) can rewind all wallet outputs. This matches RFC "strategy A" but is nowhere surfaced as a product decision; there is no per-epoch view-key option.
**Fix (WS1):** decide strategy A vs B per the RFC discussion; document that exporting `MultisigConfig` = granting permanent view access for the epoch.

### C-11 — `ThresholdParams::new` does not enforce the PTE floor — **Medium** (review F-08 partially addressed)
`MIN_SHARES_FOR_DEGREE = 4` and `recommended_shares_per_actor` exist (`types.rs`), but plain `ThresholdParams::new(2, 3)` (degree 1) is accepted everywhere, including the CLI and the kernel/rangeproof test setups. The mitigation exists but is opt-in.
**Fix (WS1/WS2):** enforce `effective_degree + 1 ≥ MIN_SHARES_FOR_DEGREE` in `with_shares_per_actor` for non-test builds (or require an explicit `allow_low_degree` dev flag); commission the actual PTE cryptanalysis to justify the floor value.

### C-12 — No DoS bounds on message parsing — **Medium**
JSON envelopes are parsed without size limits, count limits (e.g. `commitment_hexes` length is checked against params only after parse), or streaming caps. Malicious peers can send megabyte envelopes or 10⁶ coefficients.
**Fix (WS5):** hard caps (max actors, max coefficients, max message size) enforced before deserialization of inner fields.

### C-13 — Add-actor remains exposed — **Medium** (review F-03, acknowledged in code)
`share.rs::add_actor_masked_share` is exported from the crate root with a doc warning. Warnings don't gate anything; a wallet UI built on this API can invoke the share-exfiltration-prone flow.
**Fix (WS1):** for v1, remove from the public API or hide behind a feature flag; membership change = re-DKG new epoch + on-chain sweep.

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
| F-03 add-actor exfiltration | High | Implemented w/ warning only | Gate/remove (C-13) |
| F-04 robust DKG | High/Med | **Open** ("v0" joint-Feldman) | WS2: named DKG + complaints (C-14) |
| F-05 PoP underspecified | Medium | Largely fixed (`pop_message` binds ceremony/actor/index/commitment) | Bind full coefficient vector + params into each PoP msg; RFC transcript |
| F-06 kernel signing scheme | High | **Open** (additive aggsig + weak commit; C-05) | WS2: FROST |
| F-07 BP partial verification | Med/High | **Open** (C-06) | WS2: verifiable τ + identifiable abort |
| F-08 PTE parameters | High (small M) | Partial (floor exists, unenforced; C-11) | Enforce + cryptanalysis |
| F-09 hash-to-scalar | Medium | **Fixed** (rejection sampling) | Keep property for real DH; test vectors |
| F-10 δ-mask / all-N delivery | Medium | Algebra implemented; abort rules missing | WS2 session rules |
| F-11 backup model | Medium | State export exists but plaintext (C-08) | WS3: encrypted backup object + restore drill |
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
| Replace kernel signing with **FROST** over the Lagrange-evaluated excess key (audited crate, e.g. ZF FROST, adapted to secp256k1-zkp types) | `kernel.rs` → `crypto/frost.rs` | Forgeability tests; concurrent-session tests; nonce-reuse impossible by construction |
| Verify partial excess pubkeys against the public poly (`λ_j`-weighted `P(x)` sums) | `kernel.rs` | Wrong-excess partial rejected with attribution |
| Verifiable τ contributions + identifiable abort | `rangeproof.rs` | Bad τ_j rejected, culprit named; negative tests |
| Robust DKG: contribution commit-reveal, complaint round, abort rules | `dkg.rs` | Last-mover bias test; missing-dealer abort test |
| Canonical session transcript (quorum set, ordering, coin lists, commitments, fee, epoch) hashed into every signature and commitment | `kernel.rs`, `messages.rs` | Transcript mismatch ⇒ abort before secret reveal |
| Enforce PTE floor; commission degree cryptanalysis | `types.rs` | Low-degree construction impossible without dev flag |
| Port Beam's multiparty-BP test structure (N = 2..5, phased CoSign discipline, external-randomness-per-ritual rule) as golden vectors | `rangeproof.rs` tests | Deterministic vectors in repo; N=5 passes |

**Beam references to mirror:** `core/ecc_bulletproof.cpp` (`MultiSig::CoSignPart`, phased `Step2`/`Finalize`), `core/ecc.h` nonce-hygiene comments, `core/unittest/ecc_test.cpp` 5-signer BP test.

### WS3 — Secrets hygiene (2–4 weeks, parallel with WS2)

1. AEAD-encrypt: LMDB state, pending-DKG file (C-03), state export (C-08); delete `export_state_json` plaintext path.
2. Mandatory age encryption + δ-masking for `DkgPartialShare` delivery (C-02); refuse to write plaintext share files.
3. `zeroize` on `SecretShare`, `DealerSecrets`, `ActorKernelSecrets`, `ActorRpSecrets`, pending buffers; strip `Debug` from secret-bearing types or redact.
4. Defined **backup object** `{ceremony_id, params, roster, public_poly, shares, epoch}`, encrypted, with a scripted restore drill (F-11).

### WS4 — Session engine / negotiator (6–10 weeks)

Build the Beam-`Negotiator` analog — the largest product gap. Design before code:

```
SessionStore (LMDB, encrypted)
  session_id, ceremony_id, kind (Dkg | CreateOutput | Spend)
  round, canonical quorum, role, peer roster, deadlines
  secrets (nonce seeds, partials) — AEAD
  inbound log (all signed envelopes), outbound queue

Negotiator
  apply(envelope) -> Vec<outbound envelope>   // idempotent, replay-safe
  state() -> Round / Complete / Aborted(reason, culprit?)
  resume()                                    // crash recovery from store
```

Rules to adopt from Beam `MultiTx`: barriers (never reveal a finalizable secret before the counterparty is equally committed), input/output restriction between rounds, explicit roles for who finalizes/broadcasts.

**Exit:** 3-process integration test over real slatepack files/sockets: DKG → create output → spend, with kill-and-resume at every round boundary, and abort-at-every-round leaving no reusable nonce state.

### WS5 — Wire format & transport (3–5 weeks, overlaps WS4)

1. Envelope authentication: ed25519 signature by sender's slatepack key over the full header+body (C-04); duplicate/equivocation detection.
2. Round/sequence numbers + session binding in every message; replay cache per ceremony.
3. Size/count caps before parse (C-12); fuzz the parser (`cargo-fuzz` target for `MultisigEnvelope`).
4. Freeze the v1 format (keep JSON if frozen and fuzzed, or move to binary ser like the rest of Grin — decide once, in WS1).

### WS6 — Wallet & API integration (6–12 weeks)

1. **Remove C-01 immediately** (first PR of the effort): no `set_local_chain_type` outside tests; `multisig_demo_tx` behind a dev feature.
2. Multisig UTXO tracking: new wallet DB records (commit, coin number, value, epoch, status, confirming height, proof); update from chain scan using the shared-nonce rewind path already proven in `rangeproof.rs::rewind_rangeproof`.
3. Coin-number allocator: proposer picks `max(known)+1`, quorum **confirms** inside the signed session transcript; reorg handling = coin identity is (number, value), commitment recomputable, never reuse a number across concurrent sessions (persist reservations).
4. Send/receive against external parties: nest the quorum MPC inside the standard sender/receiver slate flow (`[Alice actors MPC] ↔ slatepack ↔ [Bob actors MPC]`); payjoin support per RFC §10.
5. Epoch rotation: re-DKG under new roster + sweep command that spends all old-epoch UTXOs to new-epoch coins.
6. CLI/Owner API: replace demo commands with session lifecycle (`create/advance/status/abort`), quorum status display, backup/restore commands.

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
1. C-01 chain-type footgun removal.
2. C-02/C-03 plaintext secrets on disk.
3. C-04 envelope authentication + replay protection.
4. WS1 spec freeze (incl. C-07 canonical transcript, C-11 degree floor, C-13 add-actor removal).
5. WS2 FROST kernel + verifiable τ (C-05/C-06).
6. WS4 durable negotiator with crash recovery.

**P1 — before mainnet flag:**
7. WS6 UTXO tracking + coin allocator + rotation sweep.
8. WS3 zeroization/AEAD everywhere; backup/restore drill.
9. WS5 fuzzed, frozen wire format; DoS caps (C-12).
10. External audit + malicious-peer suite + 30-day soak.

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
| `kernel.rs` | **Replace** signing core with FROST; keep session/offset plumbing | `crypto/frost.rs` + `session/kernel.rs` |
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
