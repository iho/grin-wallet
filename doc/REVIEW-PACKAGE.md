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
4. **Multiparty kernel excess signing** (additive partial Schnorr / Grin aggsig + nonce commitments).  
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
| **Multi-share** | `recommended_shares_per_actor(M)` raises degree for small M (PTE hardening intent) |
| **View mix** | **Not** claimed to hide the polynomial if full blinds leak + public \(S_*\) known |
| **Add-actor** | Implemented with δ-masking; **documented as dangerous** under near-quorum collusion |
| **Kernel scheme** | Grin additive aggsig + **nonce commit-then-reveal** — **not** FROST/MuSig2 |
| **BP** | `secp256k1zkp` multiparty bulletproof API (τ path) |

### 4.4 Inherent model limitation (must not be forgotten)

Any **M** shares (or enough partials to interpolate) reconstruct the **entire** polynomial → **all past and future** coin keys under that ceremony. This is a **global wallet master**, not independent keys per UTXO.

### 4.5 What “done experimentally” means

The branch implements a vertical slice:

DKG → LMDB persistence → multiparty BP → multiparty kernel → slatepack-style messages → CLI → local-quorum E2E `Transaction::validate` → Owner RPC / post-tx hex.

It does **not** mean: multi-machine adversarial sessions, durable negotiator, production encryption-at-rest, FROST, or audited security.

---

## 5. Code scope

### 5.1 Primary (must review)

```text
libwallet/src/multisig/          (~4.6k LOC at package time)
├── mod.rs           # module surface / docs
├── types.rs         # threshold params, ceremony state
├── scalar.rs        # hash-to-scalar, field ops
├── poly.rs          # secret/public polynomial eval, share verify
├── dkg.rs           # Feldman-style DKG, PoP, local DKG
├── share.rs         # Lagrange partials, δ-masking, add-actor
├── coin.rs          # coin id → x, blind, offset, view mix
├── rangeproof.rs    # multiparty BP (T1/T2/τ)
├── kernel.rs        # multiparty kernel excess (aggsig + nonce commit)
├── tx.rs            # E2E local-quorum Transaction build + validate
├── messages.rs      # slatepack/JSON wire envelopes
├── store.rs         # LMDB encrypt/decrypt helpers
└── ops.rs           # CLI/ops lifecycle (DKG pending files, etc.)
```

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
# Package-time tip was approximately: 7696dd1 — verify; work may be uncommitted
# on a local working tree. Prefer a tag or commit hash frozen for the review.

# Optional sibling docs (if not in the zip bundle)
# grin/doc/multisig-crypto-review.md
# grin/doc/multisig-implementation.md
```

**Note for reviewers:** At package time the multisig implementation may exist as a large **working-tree** delta on `feat/multisig-wallet` rather than a single clean published commit. Request a **frozen commit or tarball** from the requesting party if hashes must be pinned.

---

## 6. Known findings (pre-brief — not a complete audit)

Independent design review produced **F-01…F-15**. Implementation and readiness work produced additional **code-level** issues. Use these to prioritize; re-validate every claim.

### 6.1 Design / crypto (F-series)

| ID | Severity | Topic | Summary | Impl note (package time) |
| --- | --- | --- | --- | --- |
| **F-01** | Critical (spec) | Degree vs threshold | Draft RFC mixed degree M with M points; wrong for SSS | Aims at `threshold * shares_per_actor − 1`; **verify math + vectors** |
| **F-02** | High | View mix / HKDF | Public \(S_0\)-derived mix does **not** hide poly if blinds leak | Docs/code note: no poly-hiding claim |
| **F-03** | High | Add-actor | M−1 colluders + new actor can extract last honest share | API exists + warning; **not gated off** |
| **F-04** | High/Med | Joint Feldman | Bias / robust DKG literature not fully engaged | Classic joint Feldman + PoP |
| **F-05** | Medium | PoP transcripts | PoP present; end-to-end binding must be checked | Present in `dkg.rs` — audit transcript |
| **F-06** | High | Kernel multiparty | Additive aggsig + hash nonce commit — **not** FROST/MuSig2 | `kernel.rs` — specialist judgment required |
| **F-07** | Med/High | Multiparty BP | Spec incomplete vs full multiparty BP practice | Uses secp multiparty API; rounds in `rangeproof.rs` |
| **F-08** | High (small M) | Wagner / PTE | Excess collision risk for poly blinds; degree TBD | Multi-share helper exists; **no proven D_min** |
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

From readiness review (`doc/multisig-production-readiness.md`) and implementation work — examples (re-validate):

| Issue | Summary |
| --- | --- |
| No durable negotiator | Multi-round sessions not crash-resilient multi-process product |
| Local-sim E2E only | `tx.validate()` for in-process quorum; not multi-machine adversarial |
| Share export / temp files | Risk of plaintext share material on disk during multi-party DKG file flow |
| Add-actor not hard-gated | Doc warning only; UI/API can still call it |
| Demo / chain-type coupling | Ensure test-only global state cannot affect production APIs |
| Share XOR at rest | Keychain-derived XOR — not strong encryption if seed unlocked in-process |
| Experimental flag | CLI/docs warn: not for real funds without review + fixes |

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

**Claims tests support**

- DKG share verification against public polynomial  
- Multiparty rangeproof verify + rewind value  
- Multiparty kernel partial/final verify  
- Full `Transaction::validate` for local fund→spend  
- LMDB encrypt/decrypt of shares  

**Claims tests do *not* support**

- Security against malicious co-signers beyond unit checks  
- Multi-process / network adversarial sessions  
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

1. Is the **M-of-N polynomial key tree** acceptable for a treasury, given total compromise if M shares leak?  
2. Is **multiparty BP** usage (T1/T2/τ aggregation) consistent with known secure multiparty BP practice (e.g. Beam / Bünz et al.)?  
3. Is the **kernel multiparty** construction safe as implemented, or must it be replaced with FROST/MuSig2 before any funds?  
4. What **minimum polynomial degree / shares-per-actor** is required against PTE-style excess collisions for realistic UTXO counts?  
5. Should **add-actor** be removed from v1?  
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
| Frozen commit / tarball hash | *to be filled before engagement starts* |

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
- **What is solid (as engineering prototype):** Clear MW problem framing; multiparty BP is the right tool family; local E2E txs validate; LMDB persistence exists; Beam comparison clarifies product vs crypto gaps.  
- **What is not solid:** Kernel multi-sig scheme class (F-06), DKG robustness (F-04), PTE parameters (F-08), add-actor (F-03), session/product maturity, **no external specialist audit until you**.  
- **Your job:** Independent judgment on **crypto correctness and fund-safety**, not product roadmap or CLI polish.  
- **Prior internal verdict:** Not production-ready; use F-series as a checklist, not as gospel.

---

*End of review package. Prefer citing file paths, function names, and RFC sections in findings.*
