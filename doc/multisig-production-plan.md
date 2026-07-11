# Grin Multisig: Beam Comparison & Production Plan

**Date:** 2026-07-11  
**Branch:** `feat/multisig-wallet` (grin-wallet)  
**Beam source:** [BeamMW/beam](https://github.com/BeamMW/beam) @ `4e01b68` (shallow clone)  
**Status:** Planning document — not a security audit

---

## 1. Executive summary

| | **Beam (production)** | **Grin (this branch)** |
| --- | --- | --- |
| **Maturity** | Battle-tested in wallet, Laser channels, swaps, BVM | Experimental library + CLI + Owner RPC |
| **Crypto focus** | N-of-N additive multi-sig UTXOs + multiparty BP | M-of-N threshold via Feldman DKG + multiparty BP + aggsig |
| **Key model** | Each party holds own `sk`; commitment = sum of pubs | Shared secret polynomial; Lagrange partials |
| **Rangeproofs** | First-class `RangeProof::Confidential::MultiSig` + phased `CoSign` | Wraps `secp256k1zkp::bullet_proof_multisig` |
| **Kernel / excess** | Multiparty Schnorr with explicit nonces; documented pitfalls | Additive aggsig + nonce hash-commit |
| **Session machine** | `Negotiator` state machine (codes, RaiseTo, persistence) | Round APIs + JSON envelopes; no durable session runner |
| **Messaging** | SBBS / BBS + Laser channel transport | Slatepack age encryption; no session router |
| **Apps** | Swaps, Laser LN, BVM multisigned contracts | Local-sim E2E demo only |
| **Threshold M-of-N** | Not the same problem (mostly 2-of-2 / N-of-N cosign) | Primary design goal of RFC-0023 |

**Bottom line:** Beam is a **production multiparty wallet crypto stack for additive (N-of-N) co-ownership**, especially **2-of-2** for channels and swaps. Grin’s branch is a **prototype M-of-N threshold wallet** with the right building blocks but missing production session management, hardened crypto parameters, and product integration.

To ship production Grin multisig:

1. **Do not copy Beam’s key model blindly** — decide product: M-of-N treasury vs 2-of-2 channels.  
2. **Do copy Beam’s multiparty BP and Schnorr discipline** (phased CoSign, explicit nonces, oracle transcripts).  
3. **Build a Beam-style negotiator / session store** on top of Grin slatepack.  
4. **Complete crypto review fixes** (degree params, FROST or MuSig2-class kernel, add-actor policy).  
5. **Ship in phases** with explicit security bars before real funds.

---

## 2. Beam architecture (what they actually built)

### 2.1 Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Apps: Laser channels, atomic swaps, BVM MultiSigRitual     │
├─────────────────────────────────────────────────────────────┤
│  wallet/: MultiTx, base_tx_builder, private_key_keeper      │
├─────────────────────────────────────────────────────────────┤
│  core/negotiator: Multisig | MultiTx | WithdrawTx state m/c │
├─────────────────────────────────────────────────────────────┤
│  core/ecc: MultiSig Schnorr, RangeProof::Confidential::MS   │
├─────────────────────────────────────────────────────────────┤
│  Messaging: SBBS/BBS, Laser connection, BroadcastRouter     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Multiparty rangeproof (`core/ecc_bulletproof.cpp`, `ecc.h`)

Beam’s confidential rangeproof supports **explicit multiparty phases**:

| Phase | Behavior |
| --- | --- |
| `SinglePass` | Normal single-prover BP |
| `Step2` | Aggregate Part2 (T1/T2 path); stop before τ |
| `Finalize` | Finish after aggregated τ (Part3) |

API surface:

```cpp
// ecc.h — RangeProof::Confidential
struct MultiSig {
  Part1 m_Part1;
  Part2 m_Part2;
  static bool CoSignPart(const Nonces&, Part2&);           // T1/T2 share
  void CoSignPart(const Nonces&, sk, Oracle&, Part3&) const; // τ share
};
bool CoSign(..., Phase::Enum, ...);
```

**Unit test** (`core/unittest/ecc_test.cpp`): **5-signer** multiparty BP:

1. Each peer has independent `sk[i]`; aggregate commitment `C = H*v + Σ G*sk[i]`.  
2. Peers aggregate Part2 via `MultiSig::CoSignPart`.  
3. Last peer runs `CoSign(..., Step2)`.  
4. Peers produce Part3 (τ); last peer `Finalize`.  
5. `IsValid(comm, ...)`.

**Nonces:** Explicit seed per cosigner; comment in `ecc.h` requires **external randomness per ritual** for multiparty (no pure RFC-6979 from key+msg alone — key-leak risk).

### 2.3 Multisig UTXO ritual (`core/negotiator.{h,cpp}`)

`Negotiator::Multisig` is a **durable state machine** to create a multi-signed UTXO:

| Round (RaiseTo) | Action |
| --- | --- |
| 1 | Generate nonces; send **BpPart2** (T1/T2) |
| 2 | Send **PubKey** (`G * sk` for this party’s share of the blind) |
| 3 | After peer BP parts + scheme height: aggregate commitment, run Step2, send **τ (BpPart3)** |
| Final | Finalize BP, validate output, store **OutputTxo** |

Key properties:

- **Additive keys:** each party derives `sk` from `CoinID` via wallet KDF; `C = G*(sk0+sk1) + H*value` (plus worker value tagging).  
- **Roles:** sender/receiver (`Codes::Role`) control who must receive final result.  
- **Storage codes:** peer variables for PubKey, BpPart2, BpPart3; local Nonce, Cid, Commitment.  
- **Used by:** Laser-style `WithdrawTx` (msig0 → msig1 → withdraw with relative lock).

This is **2-of-2 / N-of-N co-signing**, not threshold M-of-N secret sharing.

### 2.4 MultiTx — multiparty full transaction

`Negotiator::MultiTx`:

- Arbitrary inputs/outputs.  
- Optional **one multisig UTXO** on input and/or output side.  
- Kernel params (fee, height range, relative lock).  
- Peer exchange: **KrnCommitment, KrnNonce, KrnSig, TxPartial**.  
- Barriers (`Barrier`, `RestrictInputs/Outputs`) so peers can’t inflate or abandon unfairly.  
- Outputs final `TxFinal` + `KernelID`.

Kernel signing uses Beam’s generalized Schnorr (`SignatureBase`) with partial nonces and careful comments on:

1. Rogue-key / key cancellation  
2. Nonce reuse / key leak if challenges differ with deterministic nonces  

### 2.5 Messaging & product

| Component | Role |
| --- | --- |
| **SBBS / BBS** | Encrypted wallet messaging; channels for offers, dex, etc. |
| **Laser** | Payment-channel style state (`wallet/laser/*`) using multisig UTXOs |
| **Swaps** | Adaptor / multiparty builders under `wallet/transactions/swaps` |
| **BVM** | `SetMultisignedTx`, shader `MultiSigProto` / `MultiSigRitual` for contracts |

Nodes can also run **validator multisig** (PBFT-related, `node/node.cpp`) — separate from wallet UTXO multisig.

### 2.6 What Beam does *not* primarily solve

- **M-of-N threshold wallets** where any M of N can move funds without the others (Shamir/Feldman DKG).  
- Beam “multisig” = **all designated cosigners** participate (or contract-level approvers for upgrades), not SSS threshold spend of a single master poly.

---

## 3. Grin implementation (this branch) — map to Beam

### 3.1 Module map

| Grin (`libwallet/src/multisig/`) | Closest Beam analog | Gap |
| --- | --- | --- |
| `dkg.rs` Feldman DKG + PoP | *None* (different model) | Unique to Grin RFC; needs robust DKG / params |
| `poly.rs` / `share.rs` Lagrange | N/A (additive sk sum) | PTE / multi-share degree rules |
| `rangeproof.rs` | `RangeProof::Confidential::MultiSig` + `CoSign` phases | Beam’s is deeper (oracle/version/hGen, multi-signer tested to 5) |
| `kernel.rs` additive aggsig + nonce hash-commit | `Signature` / MultiTx kernel exchange | Beam warns explicitly; Grin needs MuSig2/FROST or proven nonce protocol |
| `negotiator` *missing* | `core/negotiator` state machine | **Largest product gap** |
| `messages.rs` JSON envelopes | Negotiator codes + serialization_adapters | Need versioned binary + session IDs + timeouts |
| Slatepack age | SBBS | Need multi-round session routing |
| `tx.rs` local E2E validate | MultiTx full path | No chain UTXO selection / lock / post lifecycle |
| `ops.rs` + CLI | wallet CLI + Laser apps | Production UX, recovery, audits |
| LMDB XOR store | wallet_db + keykeeper | Hardware keykeeper path; stronger encryption |

### 3.2 Cryptographic comparison

| Topic | Beam | Grin branch | Production recommendation |
| --- | --- | --- | --- |
| **Ownership model** | Additive N-of-N (each `sk_i`) | Threshold M-of-N (SSS poly) | Keep M-of-N for treasury; add **optional 2-of-2 additive path** for channels/swaps (Beam-like) |
| **BP multiparty** | Native phased API, oracle, asset tag | `bullet_proof_multisig` via secp256k1-zkp | Align phases/transcripts with Beam unit test structure; test N=2..5 |
| **Nonces** | Explicit random seeds per ritual; documented leak risk | CSPRNG + shared view nonce for BP | Adopt Beam’s rule: **external random nonces for all multiparty sig/BP** |
| **Schnorr multiparty** | Generalized + partial; comments on pitfalls | Grin aggsig + commit-hash | Prefer **MuSig2** (N-of-N) or **FROST** (M-of-N) over ad-hoc sums |
| **DKG** | Not used for UTXO ownership | Feldman + PoP | Specify robust DKG (Gennaro et al. / modern); fix degree = t−1 (already); set min degree |
| **Add actor / rotation** | New msig UTXO + on-chain migrate (Laser) | Add-actor share eval (exfil risk) | Prefer **epoch re-DKG + on-chain migrate** like Beam channels |
| **Validation** | Output/IsValid after finalize | `tx.validate()` in demo | Same bar; plus regression vectors from Beam tests |

### 3.3 Engineering comparison

| Topic | Beam | Grin branch |
| --- | --- | --- |
| State machine | First-class `RaiseTo`, codes, persistent storage map | Round functions; pending DKG JSON only |
| Failure handling | Status codes, Barrier, Restrict* | Mostly return `Error::Multisig` |
| Persistence | Wallet DB + negotiator variable store | LMDB XOR for final shares; pending file |
| HW support | Keykeeper interfaces | None |
| Tests | ECC unit tests for multiparty BP | 32 unit tests; no multi-process integration |
| Docs | Implicit in code + product | RFC thread + local docs |

### 3.4 Security review findings still open (Grin)

From earlier crypto review — **blockers for production**:

1. **Polynomial degree / multi-share** policy must be fixed and tested (PTE).  
2. **HKDF/view-seed** not a poly-hiding defense — document and design for share compromise.  
3. **Add-actor share exfiltration** — gate or remove for v1.  
4. **Kernel multiparty** underspecified vs modern multi-sig papers.  
5. **External audit** required before treasury funds.

Beam does not remove these for M-of-N; it **avoids** SSS, so those particular issues don’t apply to their N-of-N cosign model.

---

## 4. Product decision (required before production code freeze)

Choose primary product (can do both as phases):

### Option A — **Threshold treasury wallet (M-of-N)**  
RFC-0023 path. Best for community funds, org custody.

- Requires solid DKG, session runner for M parties, share backup UX.  
- Harder crypto story; higher audit cost.

### Option B — **Beam-style 2-of-2 / N-of-N cosign UTXOs**  
Closer to Beam Multisig + MultiTx. Best for swaps, escrow, payment channels.

- Faster path using existing multiparty BP + MuSig2.  
- Does **not** give “any 2 of 3 can spend without the third.”

### Option C — **Both** (recommended long-term)

| Phase | Ship |
| --- | --- |
| P1 | 2-of-2 cosign (Beam-aligned) for interoperability with known patterns |
| P2 | M-of-N threshold treasury (RFC-0023, hardened) |

Grin’s current code is closer to **P2**. Production plan below covers **P2 as primary** with **P1 as optional track** borrowing Beam heavily.

---

## 5. Production plan

### Phase 0 — Spec freeze (2–4 weeks)

**Deliverables**

1. **RFC-0023 revision** incorporating:  
   - Degree `t−1`, multi-share rule (e.g. effective shares ≥ 4)  
   - Feldman/Gennaro DKG citation + PoP transcript  
   - Kernel scheme: **FROST** (threshold) or document N-of-N **MuSig2**  
   - Remove or heavily gate add-actor; prefer re-DKG + migrate  
   - Nonce policy aligned with Beam (external RNG per ritual)  
2. **Wire format v1** (binary preferred over JSON for production):  
   - Session ID, party index, round number, timeout, abort  
   - Message types: DKG, BP, Kernel, Abort, Ack  
3. **Threat model** document (honest majority? adaptive corruptions? network adversary?).  
4. **Crypto review** by 1–2 external reviewers (threshold + MW experience).

**Exit criteria:** Accepted RFC + written security model + parameter table.

---

### Phase 1 — Crypto library hardening (4–8 weeks)

**Align with Beam where it wins**

| Task | Beam reference | Work |
| --- | --- | --- |
| BP multiparty API wrapper | `ecc_bulletproof.cpp` MultiSig + unit test 5-way | Structured phases Step1/2/Finalize; vectors N=2..5; optional switch commit / hGen if Grin uses them |
| Explicit nonce objects | `Nonces` + seed storage | Persist nonce seeds per session (encrypted); never recompute from key alone |
| Kernel multiparty | `SignatureBase` notes + MultiTx | Integrate **FROST** (recommended for M-of-N) *or* MuSig2 for N-of-N cosign path |
| DKG | — | Fix robust DKG; complaint/abort; threshold inflation checks (coeff length) |
| Property tests | `ecc_test.cpp` multiparty BP | Deterministic test vectors checked into repo |

**Files (grin-wallet)**

- Harden `rangeproof.rs`, `kernel.rs`, `dkg.rs`  
- Add `session.rs` (nonce + round state)  
- Possibly `frost.rs` / dependency on audited FROST crate  

**Exit criteria:** All vectors pass; fuzz BP/kernel partial aggregation; no known critical issues from review F-01..F-08.

---

### Phase 2 — Negotiator / session engine (Beam Multisig + MultiTx pattern) (6–10 weeks)

**Goal:** Beam-quality **durable multiparty session machine**.

```
SessionStore (LMDB)
  - session_id, ceremony_id, kind (Dkg|CreateOutput|Spend)
  - round, role, peer list, timeouts
  - encrypted secrets (nonces, partials)
  - outbound queue / inbound log

Negotiator
  - raise_to(round)
  - apply_message(env)
  - next_messages() -> Vec<MultisigEnvelope>
  - is_complete() / abort(reason)
```

Map Beam codes → Grin messages:

| Beam Multisig | Grin envelope |
| --- | --- |
| BpPart2 | `RpRound1` |
| PubKey | partial excess / commitment share |
| BpPart3 | `RpRound2` |
| OutputTxo | `RpFinal` + local store |
| MultiTx Krn* | `KernelNonce*`, `KernelPartialSig`, `KernelFinal` |

**Features Beam has that Grin needs**

- Barriers (don’t reveal finalizable state unfairly)  
- Restrict peer-added inputs/outputs for cosign spends  
- Role-based “who finalizes / who must get result”  
- Resume after crash (read codes from storage)

**Exit criteria:** Multi-process integration test: 3 processes, real slatepack files or sockets, complete DKG + create output + spend, crash-resume mid-round.

---

### Phase 3 — Wallet product integration (6–12 weeks)

| Area | Work |
| --- | --- |
| **UTXO tracking** | Multisig outputs in wallet DB (commit, coin number, epoch, status, proof) |
| **Receive** | Create multisig output via negotiator; scan with shared view material |
| **Send** | Select multisig UTXOs; run spend negotiator with quorum; lock/unlock like normal txs |
| **Post** | Already have `multisig_post_tx`; wire after finalize + confirm |
| **Backup** | Export/import ceremony (encrypted); recovery runbook if M shares survive |
| **CLI** | Production subcommands (not just demo-tx); status of sessions |
| **Owner API** | Expand beyond list/demo; session create/advance/status (RPC already scaffolded) |
| **Messaging** | Slatepack multi-round; optional Tor; document offline air-gap path |

**Beam patterns to copy for UX**

- Laser: clear states (open channel / update / close)  
- Fail with user-visible codes (`FailedToCreateMultiSig` style)  

**Exit criteria:** Manual testnet: 2-of-3 on three machines, receive coins, spend to external address, restore from share backup after wiping one wallet.

---

### Phase 4 — Optional Beam-aligned 2-of-2 cosign path (parallel, 4–8 weeks)

If product wants channels/swaps sooner:

1. Additive 2-of-2 keys (each party’s blind share) — **Beam Multisig model**.  
2. Reuse multiparty BP phases (same as Beam unit test with nSigners=2).  
3. MuSig2 kernel excess for 2 parties.  
4. Relative lock / NRD kernels as needed for Grin channels.  

This can ship **before** full M-of-N treasury if community prioritizes swaps/channels.

---

### Phase 5 — Hardening & launch (4–8 weeks)

| Workstream | Details |
| --- | --- |
| **Audit** | Crypto + wallet session code; treat negotiator like consensus-adjacent |
| **Fuzzing** | Message parser, DKG, BP aggregation, session resume |
| **Red team** | Malicious peer: abort, inflate inputs, grind addresses, reorg coin numbers |
| **Docs** | Operator guide, backup, incident response (M-share compromise = full poly) |
| **Feature flag** | `multisig` experimental → testnet → mainnet allowlist |
| **Bug bounty** | Scoped to multisig module |

**Launch bar (suggested)**

- [ ] External audit report with no open Critical/High  
- [ ] 30+ days testnet without fund loss bugs  
- [ ] Multi-share degree ≥ policy floor  
- [ ] No add-actor without re-DKG in v1  
- [ ] Hardware-signer design documented (even if not implemented)  

---

## 6. Suggested roadmap timeline

```
Month 0-1   Phase 0  Spec freeze + external review kickoff
Month 1-3   Phase 1  Crypto hardening (BP + FROST/MuSig2 + DKG)
Month 2-5   Phase 2  Negotiator / session engine (overlap with Phase 1)
Month 4-7   Phase 3  Wallet integration + testnet
Month 5-7   Phase 4  Optional 2-of-2 cosign (if prioritized)
Month 7-9   Phase 5  Audit, bounty, mainnet flag
```

Rough effort: **~1–2 senior eng + crypto reviewer**, 6–9 months to cautious mainnet.

---

## 7. Concrete work backlog (prioritized)

### P0 — Must have before real funds

1. Freeze RFC parameters (degree, multi-share, DKG, kernel scheme).  
2. External crypto review.  
3. Durable session negotiator (Beam-style) with crash recovery.  
4. FROST or MuSig2 for kernels (not raw aggsig invent).  
5. Multiparty BP tests N=2..5 + transcript vectors.  
6. Wallet UTXO tracking for multisig outputs.  
7. Multi-process integration tests.  
8. Remove/gate add-actor; epoch re-DKG + migrate.  

### P1 — Production quality

9. Binary wire format v1; deprecate free-form JSON or freeze it.  
10. Barriers / fairness for spend finalization.  
11. Backup/restore UX and runbooks.  
12. Owner RPC complete session lifecycle.  
13. Tor/offline dual paths.  
14. Metrics, logging (no secret leakage).  

### P2 — Nice to have

15. Hardware keykeeper interface (Beam-inspired).  
16. 2-of-2 cosign path for channels/swaps.  
17. WASM/programmable hooks (Beam BVM is different product choice — optional for Grin).  
18. SBBS-like async mailbox (beyond slatepack files).  

---

## 8. What to lift from Beam vs invent

| Lift from Beam (adapt) | Invent for Grin (threshold) |
| --- | --- |
| Phased multiparty BP API usage & tests | Feldman/FROST DKG + share lifecycle |
| Explicit multiparty nonces + oracle discipline | Coin number / view paint with shared S0 |
| Negotiator state machine + storage codes | Slatepack multiparty routing |
| MultiTx barriers & peer restrictions | M-of-N quorum selection UX |
| Laser migration of msig UTXOs on update | Epoch rotation without channels |
| Comments/tests on Schnorr multiparty pitfalls | PTE mitigations for poly-derived blinds |

**Do not** port Beam’s PBFT node multisig or BVM shader system unless Grin product goals change.

---

## 9. Mapping current Grin code → production modules

| Current | Becomes |
| --- | --- |
| `dkg.rs` | `crypto/dkg` + robust DKG |
| `rangeproof.rs` | `crypto/mp_bp` (Beam-aligned phases) |
| `kernel.rs` | `crypto/frost` or `crypto/musig2` |
| `messages.rs` | `wire/v1` binary + slatepack adapter |
| `ops.rs` | thin CLI glue over `session::Negotiator` |
| `tx.rs` | `session::Spend` / `session::Receive` using negotiator |
| `store.rs` | `store::Ceremony` + `store::Session` (encrypted) |
| CLI / Owner RPC | Keep; expand session advance APIs |

---

## 10. Risks

| Risk | Mitigation |
| --- | --- |
| M-of-N poly compromise is catastrophic | High M, multi-share degree, short epochs, clear user warnings |
| Under-audited multiparty Schnorr | Use FROST/MuSig2 libraries with existing analysis |
| Session desync / stuck funds | Timeouts, abort, force-migrate policies |
| Scope creep (BVM, Laser full stack) | Phase gates; P1 vs P2 product tracks |
| Diverging from Beam’s additive model confuses users | Docs: “threshold wallet” vs “cosign UTXO” |

---

## 11. Recommended immediate next engineering steps

1. **Decide P1 product:** treasury M-of-N vs 2-of-2 cosign first.  
2. **Port Beam multiparty BP test structure** into Grin as golden vectors (N=2,3,5).  
3. **Design `Negotiator` module** (state diagram + LMDB schema) before more CLI.  
4. **Replace `kernel.rs` target** with FROST design doc + dependency choice.  
5. **Schedule external review** on RFC + Phase 1 crypto only (not whole wallet).  

---

## 12. References

### Beam (cloned)

- `core/ecc.h` — `RangeProof::Confidential::MultiSig`, `CoSign` phases, Schnorr multiparty notes  
- `core/ecc_bulletproof.cpp` — `MultiSig::CoSignPart`, τ aggregation  
- `core/unittest/ecc_test.cpp` — 5-party multiparty BP test  
- `core/negotiator.h` / `negotiator.cpp` — `Multisig`, `MultiTx`, `WithdrawTx`  
- `wallet/laser/*` — channel product on multisig UTXOs  
- `wallet/core/common.h` — `FailedToCreateMultiSig`  

### Grin (this work)

- `libwallet/src/multisig/*`  
- `doc/multisig.md`  
- `doc/multisig-crypto-review.md` (if present in monorepo docs)  
- Forum RFC: https://forum.grin.mw/t/multisig-wallet-rfc/12316  

### Literature

- Bulletproofs multiparty section (Bünz et al.)  
- FROST (Komlo & Goldberg)  
- MuSig2 (Nick, Ruffing, Seurin)  
- Gennaro et al. secure DKG  

---

*Document generated from Beam source inspection and the experimental Grin multisig branch. Update after product decision and audit.*
