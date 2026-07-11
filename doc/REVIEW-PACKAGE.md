# Multisig Cryptographic Review Package

**Project:** Grin wallet-layer M-of-N threshold multisig (experimental)  
**Repository:** `grin-wallet`  
**Branch:** `feat/multisig-wallet`  
**Package date:** 2026-07-11  
**Audience:** Cryptography specialist / external reviewer  

| | |
| --- | --- |
| **Code status** | Research prototype — **not** production-ready |
| **Funds status** | **Do not** put real mainnet funds on this code until review + remediation |
| **Intent of package** | Single entry document so a reviewer can assess design soundness, attack surface, implementation fidelity, and any path to real-fund use |

---

## 1. How to use this package

| Step | Action |
| --- | --- |
| 1 | Read **§2 Review charter** (scope + deliverable). |
| 2 | Read **§3 Artifacts** in the listed order. |
| 3 | Skim **§4 Design snapshot** (self-contained; reduces need for full RFC first pass). |
| 4 | Review **§5 Code scope** (not the whole monorepo). |
| 5 | Use **§6 Known findings** as a starting checklist — **not** a complete audit. |
| 6 | Run **§7 Tests** if validating implementation claims. |
| 7 | Return findings per **§8 Report format**; answer **§9** explicitly. |

**Estimated time**

| Depth | Duration |
| --- | --- |
| Design-level (RFC + docs + architecture) | 1–2 days |
| Design + targeted code paths (DKG, coin, BP, kernel) | 2–4 days |
| Full module audit + adversarial protocol review | 1–2 weeks |

---

## 2. Review charter (copy for engagement letter)

### In scope

Wallet-layer **M-of-N threshold multisig** for Grin (Mimblewimble):

1. **Feldman-style DKG** and share distribution (including PoP on coefficient commitments).  
2. **Coin blinding-factor derivation** from the secret polynomial (`sk(x)` + view mix).  
3. **Multiparty Bulletproof** construction via `secp256k1zkp::bullet_proof_multisig`.  
4. **Multiparty kernel excess signing** — FROST (two-round, binding factors) over Lagrange partial excess keys, aggregated via Grin aggsig; **including its composition with the multiparty BP over the same shares** (§4.6 Q2).  
5. **Threat model**, including:  
   - fewer than M corrupted actors  
   - M share leak / collusion  
   - malicious co-signer in a quorum (input substitution / excess collision / Wagner–PTE)  
   - add-actor / key rotation  
   - network adversary (tamper, reorder, abort) as far as the protocol specifies  
6. Whether **any parameter set** (e.g. 2-of-3, multi-share degree) is appropriate for **real funds**, and under what operational constraints.

**Consensus / full nodes:** Multisig is intended to be **invisible on-chain** (standard commits, proofs, kernels). Review whether the wallet protocol correctly produces valid standard transactions.

### Out of scope (unless reviewer expands)

- CLI/UX polish  
- Payment-channel product design  
- Beam PBFT / BVM / Laser product ports  
- General Grin consensus security  
- Side channels / HSMs (note only if critical)

### Deliverable

Written report with severity-rated findings:

| Severity | Meaning |
| --- | --- |
| **Critical** | Fund theft or full key compromise under realistic assumptions |
| **High** | Serious weakness; fix before any real funds |
| **Medium** | Should fix before production; may need extra assumptions to exploit |
| **Low** | Hardening / clarity |
| **Info** | Observation |

And an overall recommendation (pick one):

- **Do not use with real funds**  
- **Fix listed items first, then re-review**  
- **Acceptable for limited test funds under constraints X** (state X explicitly)  
- **Production-ready** (unlikely for current code without major work)

---

## 3. Artifacts (read in this order)

### 3.1 Design specification (authoritative intent)

| # | Document | Location |
| --- | --- | --- |
| A | **RFC draft (updated, Feldman DKG)** | https://github.com/mimblewimble/grin-rfcs/blob/22c68fccd1596eec90aa394c8cee2ffa13a7c4d9/text/0023-multisig-wallet.md |
| B | **RFC draft (original)** | https://github.com/mimblewimble/grin-rfcs/blob/64fbe56735117512a9b3f2bc20d7c45c37fea379/text/0023-multisig-wallet.md |
| C | **Forum discussion** (design Q&A) | https://forum.grin.mw/t/multisig-wallet-rfc/12316 |

### 3.2 Implementation documentation (`grin-wallet`)

| # | Document | Path |
| --- | --- | --- |
| D | **Feature overview + API surface** | [`doc/multisig.md`](./multisig.md) |
| E | **Beam comparison + production roadmap** | [`doc/multisig-production-plan.md`](./multisig-production-plan.md) |
| F | **Production-readiness gates + code findings** | [`doc/multisig-production-readiness.md`](./multisig-production-readiness.md) |
| G | **This package** | [`doc/REVIEW-PACKAGE.md`](./REVIEW-PACKAGE.md) |

### 3.3 Prior design analysis (sibling `grin` monorepo — include in handoff bundle)

| # | Document | Path |
| --- | --- | --- |
| H | **Design-level crypto review** (findings **F-01…F-15**) | `grin/doc/multisig-crypto-review.md` |
| I | **Implementation synthesis / design notes** | `grin/doc/multisig-implementation.md` |

If the reviewer only receives `grin-wallet`, **attach H and I** (see **§11 Bundle**). High findings are summarized in **§6**.

### 3.4 External prior art (optional context)

| # | Resource | Note |
| --- | --- | --- |
| J | [BeamMW/beam](https://github.com/BeamMW/beam) | Production multiparty BP + N-of-N cosign negotiator — **not** M-of-N SSS |
| K | FROST (ePrint 2020/852), MuSig2 | Candidate kernel multi-sig schemes |
| L | Gennaro et al. secure DKG | DKG bias / robust DKG literature |
| M | Bünz et al. Bulletproofs / multiparty BP | Rangeproof multiparty practice |

---

## 4. Design snapshot (self-contained)

Enough context to start reviewing without reading every page of the RFC first.

### 4.1 Goal

M-of-N **wallet owners** jointly control Mimblewimble outputs:

- No consensus changes.  
- On-chain objects look like normal commits + rangeproofs + kernels.  
- No single party holds the full blinding factor in normal honest operation; a **quorum of M** can build BP + kernel for agreed I/O.

### 4.2 Core crypto objects

| Object | Role |
| --- | --- |
| Secret polynomial \(sk(x)\) | Joint Feldman sum of dealer polys; degree \(d\) |
| Public poly \(S_m = G\cdot s_m\) | Feldman verification + scan/view seed material |
| Actor shares \(sk(x_i)\) | Secret held by actor \(i\) (or multi-share per actor) |
| Coin id \((number, value)\) | Derives evaluation point \(x_{coin}\); value binds amount |
| Coin blind | \(sk(x_{coin}) + \mathrm{mix}(\ldots)\) → Pedersen commit |
| Multiparty BP | Shared view nonce from public poly; private nonces per actor; T1/T2/τ path |
| Kernel excess | \(out\_blinds - in\_blinds - offset\) (Grin convention); multiparty Schnorr |

### 4.3 Implementation choices vs draft RFC

These deliberately diverge from (or fix) draft RFC prose:

| Topic | Implementation stance |
| --- | --- |
| **Degree** | `degree = threshold × shares_per_actor − 1` (not “degree M with M points”) |
| **Multi-share** | `recommended_shares_per_actor(M)` raises degree for small M; production constructors enforce `num_coefficients ≥ MIN_SHARES_FOR_DEGREE = 4` (effective degree ≥ 3) — **the constant is asserted, not cryptanalyzed** |
| **View mix** | **Not** claimed to hide the polynomial if full blinds leak + public \(S_*\) known |
| **Add-actor** | Removed from v1: `#[cfg(test)]`-gated, no production callers; membership change = re-DKG + sweep |
| **Kernel scheme** | **FROST** (Komlo–Goldberg two-round, two nonces + binding factors) over Lagrange partial excess keys, aggregated via Grin `aggsig` — hand-rolled on `kernel.rs`, **not** the ZF-FROST crate |
| **BP** | `secp256k1zkp` multiparty bulletproof API (τ path), with per-actor τ verification against the public polynomial (identifiable abort) |

### 4.4 Inherent model limitation (must not be forgotten)

Any **M** shares (or enough partials to interpolate) reconstruct the **entire** polynomial → **all past and future** coin keys under that ceremony. This is a **global wallet master**, not independent keys per UTXO.

### 4.5 What “done experimentally” means

The branch implements a vertical slice:

DKG (file-based **and** durable session) → AEAD-sealed LMDB/session persistence → multiparty BP with verifiable τ → FROST kernel signing → authenticated, replay-protected, size-capped wire envelopes → durable session negotiator (crash-resume, deadlines, equivocation rejection) → UTXO tracking + coin-number allocation + PMMR scan → CLI + Owner RPC → local-quorum E2E `Transaction::validate` → cross-epoch (re-DKG migration) spends → envelope fuzz targets.

It does **not** mean: multi-process adversarial soak on real networks, a robust (bias-resistant) DKG, cryptanalysis behind the PTE degree floor, external validation of the FROST + multiparty-BP composition, or audited security.

### 4.6 The two headline questions (read §9 for the full list)

Everything mechanical that the internal reviews flagged has been implemented and regression-tested. What remains open — and what this review must primarily answer — are two **proof-shaped** questions no amount of unit testing can settle:

1. **Is `MIN_SHARES_FOR_DEGREE = 4` a sound floor?** The PTE/Wagner analysis (F-08) says polynomial-derived blinds admit excess-collision attacks whose cost depends on the effective polynomial degree. The code enforces `num_coefficients = threshold × shares_per_actor ≥ 4` (effective degree ≥ 3) and raises `shares_per_actor` for small M — but the constant 4 is an engineering guess. The review must either justify a concrete floor (for stated max inputs/outputs per tx and UTXO counts) or prescribe the correct one.
2. **Is the FROST + multiparty-bulletproof composition sound?** The same Lagrange shares of the same polynomial feed two interactive protocols — τ contributions to the multiparty BP and FROST partial signatures over the kernel excess — within one session and across concurrent sessions. Each protocol is individually standard; their **joint** use of shared key material (plus the deterministic public offset and view-mix terms on canonical actor 0) has no security argument. The review must confirm no cross-protocol leakage or forgery leverage exists, or specify the required domain separation.

---

## 5. Code scope

### 5.1 Primary (must review)

```text
libwallet/src/multisig/          (~13k LOC at package time)
├── mod.rs           # module surface / docs
├── types.rs         # threshold params (incl. MIN_SHARES_FOR_DEGREE floor), ceremony state
├── scalar.rs        # hash-to-scalar (rejection sampling), field ops
├── poly.rs          # secret/public polynomial eval, share verify
├── dkg.rs           # joint-Feldman DKG, PoP, local DKG (bias-resistance OPEN, C-14)
├── share.rs         # Lagrange partials, δ-masking; add-actor is #[cfg(test)]-gated
├── coin.rs          # coin id → x, blind, offset, view mix
├── rangeproof.rs    # multiparty BP (T1/T2/τ) + per-actor τ verification
├── kernel.rs        # FROST kernel signing (binding factors, rogue-key checks,
│                    #   cross-epoch dual-poly excess verification)
├── tx.rs            # E2E local-quorum Transaction build + validate
├── messages.rs      # signed/seq-stamped JSON wire envelopes, DoS caps
├── session.rs       # durable negotiator: DKG/CreateOutput/Spend/MultiTx/CrossEpoch,
│                    #   crash-resume, replay + equivocation rejection, TTL
├── utxo.rs          # multisig UTXO lifecycle, coin-number allocator, rewind recognition
├── store.rs         # ChaCha20-Poly1305 AEAD sealing (state, pending DKG, sessions)
└── ops.rs           # CLI/ops lifecycle, session orchestration, envelope signing
```

Fuzz targets: `libwallet/fuzz/fuzz_targets/multisig_envelope_{json,payload}.rs`.

### 5.2 Secondary (persistence / API glue)

```text
impls/src/backends/lmdb.rs          # save/get multisig state
impls/tests/multisig_store.rs       # LMDB roundtrip test
api/src/owner.rs                    # Owner::multisig_* methods
api/src/owner_rpc.rs                # JSON-RPC surface
controller/src/command.rs           # CLI: grin-wallet multisig ...
src/cmd/wallet_args.rs
src/bin/grin-wallet.yml             # CLI definitions
```

### 5.3 Out of primary scope

- Full `grin` node consensus  
- Unrelated wallet features  
- Full audit of third-party `secp256k1zkp` (except multiparty BP assumptions used here)

### 5.4 How to obtain the code

```bash
# grin-wallet (implementation under review)
git clone <grin-wallet-remote>
cd grin-wallet
git checkout feat/multisig-wallet
git log -1 --oneline
# Implementation frozen at: d4cd8215 ("multisig: authenticate tx-session
# envelopes, bind kernel final to session transcript"). This package document
# is committed immediately on top of it; see §10 for the pinned hash.

# Optional sibling docs (if not in the zip bundle)
# grin/doc/multisig-crypto-review.md
# grin/doc/multisig-implementation.md
```

**Note for reviewers:** confirm the frozen commit in §10 matches what you received; do not review a moving branch.

---

## 6. Known findings (pre-brief — not a complete audit)

Independent design review produced **F-01…F-15**. Implementation and readiness work produced additional **code-level** issues. Use these to prioritize; re-validate every claim.

### 6.1 Design / crypto (F-series)

| ID | Severity | Topic | Summary | Impl note (package time) |
| --- | --- | --- | --- | --- |
| **F-01** | Critical (spec) | Degree vs threshold | Draft RFC mixed degree M with M points; wrong for SSS | Fixed: `threshold × shares_per_actor − 1`, structurally enforced; **verify math + vectors** |
| **F-02** | High | View mix / HKDF | Public \(S_0\)-derived mix does **not** hide poly if blinds leak | Docs/code note: no poly-hiding claim |
| **F-03** | High | Add-actor | M−1 colluders + new actor can extract last honest share | **Gated off**: `#[cfg(test)]`, no production callers; v1 = re-DKG + sweep |
| **F-04** | High/Med | Joint Feldman | Bias / robust DKG literature not fully engaged | **OPEN** (C-14): classic joint Feldman + PoP, no commit-reveal / complaint round |
| **F-05** | Medium | PoP transcripts | PoP present; end-to-end binding must be checked | Present in `dkg.rs` (binds ceremony/actor/index/commitment) — audit transcript |
| **F-06** | High | Kernel multiparty | RFC prose underspecified threshold signing | **FROST implemented** in `kernel.rs` (two nonces, binding factors, rogue-key excess checks incl. cross-epoch) — specialist judgment on the hand-rolled composition required (§4.6 Q2) |
| **F-07** | Med/High | Multiparty BP | Spec incomplete vs full multiparty BP practice | secp multiparty API + **verifiable per-actor τ** with identifiable abort (`rangeproof.rs`) |
| **F-08** | High (small M) | Wagner / PTE | Excess collision risk for poly blinds; degree TBD | Floor enforced (`MIN_SHARES_FOR_DEGREE = 4`); **no cryptanalysis behind the constant** (§4.6 Q1) |
| **F-09** | Medium | Cross-curve | Slatepack ed25519 identity vs secp money keys | δ / hash-to-scalar path — check carefully |
| **F-10** | Medium | δ-masking | Algebra OK; “perfect hiding” overclaimed | Computational only |
| **F-11** | Medium | Backup model | Seed-only restore vs random DKG coeffs | Export-state JSON; not seed-restorable alone |
| **F-12** | High (model) | M-leak catastrophe | M shares → entire poly → all coins | Inherent; UX/ops critical |
| **F-13** | Low/Med | Address grinding | Prefer fixed indices / commit-reveal | Check actor id assignment |
| **F-14** | Low/Med | Value in coin id | Good; residual PTE still matters | Value in derivation implemented |
| **F-15** | Low | Notation | Spec typos become bugs | Prefer this package + code over draft prose |

Full write-ups: **`grin/doc/multisig-crypto-review.md`** (artifact H).

### 6.2 Attack scenarios (condensed)

| # | Adversary | Attack | Outcome | Finding |
| --- | --- | --- | --- | --- |
| A1 | M−1 + sockpuppet new member | Malicious add-actor | Steal honest share → full poly | F-03 |
| A2 | Malicious co-signer in quorum | I/O set with same excess (PTE), different economics | Value theft | F-08 |
| A3 | Naive sum-Schnorr under concurrency | Rogue / reused nonces | Key leak or forgery | F-06 |
| A4 | M leaked blinds + public \(S_*\) | Linear algebra | Full poly | F-02, F-12 |
| A5 | Last mover in weak DKG | Bias public poly | Algebraic leverage | F-04 |
| A6 | Missing degree check | Wrong threshold | Stuck or insecure wallet | F-01 |
| A7 | Broken hash-to-scalar | Weak δ or keys | Share leak / invalid keys | F-09 |

### 6.3 Implementation / product maturity (code-level)

The readiness review (`doc/multisig-production-readiness.md`) produced code findings **C-01…C-14**; all except C-14 are fixed or explicitly decided at package time. Re-validate the fixes — do not take the ✅ marks on trust:

| Finding | Status at package time |
| --- | --- |
| C-01 chain-type global mutation from Owner API | Fixed (removed) |
| C-02/C-03 plaintext shares / dealer coeffs on disk | Fixed (age-encrypted share slatepacks; AEAD pending file) |
| C-04 unauthenticated wire envelopes | Fixed: ed25519-signed transcript (incl. per-session `seq`) verified for **all** session kinds — DKG *and* RP/kernel/MultiTx/CrossEpoch |
| C-05 kernel nonce binding | Fixed: FROST + rogue-key excess checks (incl. cross-epoch dual-poly); `KernelFinal` bound to the session's own commitments; partials bound to round-1 commits |
| C-06 unverifiable τ | Fixed: per-actor τ verification, identifiable abort |
| C-07 quorum ordering | Fixed: canonical quorum, transcripted |
| C-08 secrets through JSON / no zeroize | Fixed (AEAD state, debug redaction); clones in hot paths remain |
| C-09/C-10 offset & view-key semantics | Decided + documented (v1 accepts; see readiness doc) |
| C-11 PTE floor | Enforced; **constant unjustified** (§4.6 Q1) |
| C-12 envelope DoS caps | Fixed + fuzz targets |
| C-13 add-actor exposure | Fixed (`#[cfg(test)]`) |
| C-14 joint-Feldman bias / no complaint round | **OPEN** — the one unfixed code finding |

**Package-time caveat:** the session-layer hardening (C-04 extension to transaction sessions, `KernelFinal`/partial binding, cross-epoch rogue-key check) landed **at package time** with regression tests but no soak period. Treat those paths as fresh code and probe them accordingly.

Remaining product gaps (not crypto): multi-process soak on real wallets, slate nesting in the standard send flow, continuous fuzz CI, hardware-signer path.

### 6.4 Beam comparison (one paragraph)

Beam production multisig is primarily **additive N-of-N cosign** of UTXOs (especially 2-of-2) with a mature multiparty BP API and a **Negotiator** state machine. It is **not** the same as Grin’s M-of-N SSS threshold design. Use Beam as a **BP / session-management** reference, not as a drop-in crypto clone. Details: [`multisig-production-plan.md`](./multisig-production-plan.md).

### 6.5 Prior design verdict (not binding on you)

Internal design review concluded: **REVISE (major)** — promising idea; **not safe for production funds** until blockers (degree, HKDF claims, kernel scheme, BP completeness, PTE params, add-actor) are resolved and re-reviewed.

Your job is independent confirmation, extension, or refutation of that verdict.

---

## 7. How to run tests

```bash
cd grin-wallet
git checkout feat/multisig-wallet

# Crypto + wire + E2E local-quorum
cargo test -p grin_wallet_libwallet multisig

# LMDB persistence roundtrip
cargo test -p grin_wallet_impls --test multisig_store

# Optional: CLI smoke
cargo build -p grin_wallet
./target/debug/grin-wallet multisig --help
./target/debug/grin-wallet multisig demo-tx -m 2 -n 2
```

87 multisig unit tests at package time (plus the LMDB store roundtrip). Fuzz targets: `cd libwallet/fuzz && cargo +nightly fuzz run multisig_envelope_json` (and `_payload`).

**Claims tests support**

- DKG share verification against public polynomial; threshold-inflation rejection  
- Multiparty rangeproof verify + rewind value; corrupted τ rejected with actor attribution  
- FROST kernel sign/verify incl. binding-factor context, bad-partial rejection, `TxKernel::verify`  
- Malicious-peer negatives: forged `KernelFinal` (internally consistent, foreign excess) rejected; partial/commit equivocation rejected; unsigned envelope from address roster rejected; cross-epoch rogue commit rejected; replay idempotent; deadline abort  
- Session crash-resume mid-round; abort wipes secrets  
- Full `Transaction::validate` for local fund→spend, MultiTx, cross-epoch sweep  
- AEAD seal/open with wrong-key and tamper rejection  

**Claims tests do *not* support**

- Security against malicious co-signers beyond the unit-level negatives above  
- Multi-process / network adversarial sessions (file-harness sims only)  
- Any parameter-level claim: the PTE floor constant and the FROST × multiparty-BP composition are untested by construction (§4.6)  
- On-chain confirmation of demo txs (inputs are synthetic)

---

## 8. Suggested report format

```markdown
# Multisig review — [Reviewer name] — [Date]

## Recommendation
[ Do not use | Fix then re-review | Limited test funds under constraints | ... ]

## Constraints (if any funds allowed)
- Threshold / multi-share parameters: ...
- Forbidden features (e.g. add-actor): ...
- Max amount / environment (testnet only?): ...

## Findings
### C-1 Title
Severity: Critical
Location: RFC §... / path/file.rs:line
Description: ...
Impact: ...
Recommendation: ...

## Spec vs implementation discrepancies
...

## Comparison to stated mitigations (F-01 … F-15)
| ID | Status | Notes |
| Confirmed / Refuted / Partial / N/A | ...

## Residual risks after recommended fixes
...

## Answers to package §9 questions
1. ...
```

---

## 9. Questions we explicitly want answered

**Primary (the two §4.6 headline questions — these decide go/no-go):**

1. **PTE floor:** What minimum effective polynomial degree / `shares_per_actor` is required against PTE-style excess collisions for realistic transaction shapes (state your assumed max inputs/outputs and UTXO count)? Is the enforced `MIN_SHARES_FOR_DEGREE = 4` (effective degree ≥ 3) adequate, and if not, what constant is?  
2. **Composition:** Is the hand-rolled FROST kernel signing sound when composed with the multiparty bulletproof over the **same** Lagrange shares of the same polynomial — within one session and across concurrent sessions, including the cross-epoch dual-poly variant? Is the domain separation (session ids, offsets, binding factors, τ challenges) sufficient, or is additional separation / a different key derivation required?

**Secondary:**

3. Is the **M-of-N polynomial key tree** acceptable for a treasury, given total compromise if M shares leak (F-12)?  
4. Does **joint-Feldman without commit-reveal / complaints** (C-14) create exploitable bias given how the public polynomial feeds coin derivation, view mix, and offsets — or is it only a robustness/DoS concern here?  
5. Are the **PoP transcript**, hash-to-scalar, and envelope-signing transcripts correctly bound (no cross-ceremony / cross-session replay)?  
6. For a **2-of-3** org wallet on mainnet, what is your **go / no-go** after reading this package and code?  
7. Which findings are **blockers for testnet value** vs **blockers for mainnet treasury** only?

---

## 10. Contact / ownership

| Role | Note |
| --- | --- |
| RFC author | Vladislav Gelfer (`valdok`) — forum RFC |
| Implementation under review | Experimental work on `feat/multisig-wallet` |
| Prior design review | Internal engineering analysis (F-01…F-15); not a paid audit |
| Reviewer | *to be filled* |
| Requesting party | *to be filled* |
| Frozen commit / tarball hash | `d4cd8215` (implementation) — branch `feat/multisig-wallet`, fork `iho/grin-wallet` |

---

## 11. Bundle checklist (what to send the specialist)

Zip or repo snapshot should include:

```text
grin-wallet/
  doc/REVIEW-PACKAGE.md          ← this file (start here)
  doc/multisig.md
  doc/multisig-production-plan.md
  doc/multisig-production-readiness.md
  libwallet/src/multisig/        ← full tree
  impls/src/backends/lmdb.rs     ← multisig-related diffs if not whole file
  impls/tests/multisig_store.rs
  api/src/owner.rs               ← multisig_* methods
  api/src/owner_rpc.rs
  controller/src/command.rs      ← multisig CLI (or whole file)
  src/cmd/wallet_args.rs
  src/bin/grin-wallet.yml

# Also attach (from sibling grin clone if not vendored):
grin/doc/multisig-crypto-review.md
grin/doc/multisig-implementation.md

# Links only (do not need offline):
# RFC A/B, forum C — see §3.1
```

Optional: `git archive` or a single commit hash + patch of all uncommitted multisig work.

---

## 12. One-page summary for the reviewer

- **What:** Threshold multisig wallet for Grin; co-owners hold shares; M of N can build rangeproofs and kernels without reconstructing the full secret in normal operation.  
- **What is solid (as engineering prototype):** Clear MW problem framing; FROST kernel signing with rogue-key checks; verifiable multiparty BP with identifiable abort; authenticated + replay-protected wire; AEAD secrets at rest; durable crash-resumable sessions; UTXO/chain integration; local E2E txs validate; malicious-peer regression tests.  
- **What is not solid — your job:** (1) the **PTE degree floor is an unjustified constant** (§4.6 Q1); (2) the **FROST × multiparty-BP composition over shared polynomial material has no security argument** (§4.6 Q2); (3) **joint-Feldman DKG bias** is unmitigated (C-14); plus the inherent M-leak model limit (F-12). **No external specialist audit until you.**  
- **Scope:** Independent judgment on **crypto correctness and fund-safety**, not product roadmap or CLI polish.  
- **Prior internal verdict:** Not production-ready; use the F-series and C-series as checklists, not as gospel.

---

*End of review package. Prefer citing file paths, function names, and RFC sections in findings.*
