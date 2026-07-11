// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Multiparty Bulletproof rangeproofs (τ / T1 / T2 path).
//!
//! Wraps `secp256k1zkp::bullet_proof_multisig` for a quorum of M actors
//! that jointly own an output without reconstructing the full coin blind
//! on any single host during the interactive rounds (each actor only uses
//! its Lagrange partial blind; the shared view mix is added to actor 0).
//!
//! ## Protocol (matches libsecp multi-party BP)
//!
//! 1. **Setup** — agree on value, full commitment, common (view) nonce,
//!    optional message / extra_data. Each actor holds `partial_blind_j`
//!    and samples a private nonce.
//! 2. **Round 1** — each actor runs step=1 → `(T1_j, T2_j)` where
//!    `T1_j = τ1_j·G`, `T2_j = τ2_j·G`. Aggregate `Σ T1_j`, `Σ T2_j`.
//! 3. **Round 2** — each actor runs step=2 with aggregated T1/T2 →
//!    `τ_j = τ1_j·x + τ2_j·x² + z²·blind_j`. **Verify each `τ_j`**
//!    against the public relation (C-06) before summing.
//! 4. **Finalize** — any actor runs step=0 with `(τ, T1, T2)` → `RangeProof`.
//!
//! ## Verifiable partial τ (C-06)
//!
//! libsecp exports only `τ1·G` / `τ2·G` in round 1, so the Fiat–Shamir
//! challenges `(x, z)` are recovered by local **probe** step-2 runs against
//! the same aggregated T1/T2 (same transcript). Each claimed `τ_j` is then
//! checked as:
//!
//! ```text
//! τ_j · G  =?  x · T1_j  +  x² · T2_j  +  z² · P_j
//! ```
//!
//! where `P_j = blind_j · G` is predicted from the public polynomial
//! ([`expected_pub_blind_for_actor`]). A bad share fails with the actor
//! index (identifiable abort).
//!
//! ## Randomness split (RFC-0023)
//!
//! | Material | Source |
//! | --- | --- |
//! | Rewind / common nonce (scan/color) | Shared view seed (deterministic) |
//! | Private nonce (protects share) | Local CSPRNG per actor |
//!
//! **Status:** experimental. Network/slatepack transport not included;
//! use [`run_rangeproof_local`] for in-process quorum simulation.

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::{Commitment, ProofMessage, RangeProof};
use crate::grin_util::secp::Secp256k1;
use crate::Error;
use rand::thread_rng;

use super::coin::{
	coin_blinding_factor, coin_commitment_components, coin_x, view_mix, view_seed_from_public_poly,
	CoinId,
};
use super::poly::{eval_public_poly, PublicPoly};
use super::scalar::{
	hash_to_scalar, sk_add, sk_div, sk_from_bytes, sk_mul, sk_sub, HashDomain,
};
use super::share::{canonical_quorum, lagrange_coefficient, partial_key_at, ActorPoint};

/// Bulletproof multiparty step: finalize (produce RangeProof).
pub const BP_STEP_FINAL: u8 = 0;
/// Bulletproof multiparty step: generate partial T1/T2.
pub const BP_STEP_T1_T2: u8 = 1;
/// Bulletproof multiparty step: generate partial τ_x.
pub const BP_STEP_TAU: u8 = 2;

/// Shared parameters for a multiparty rangeproof session.
#[derive(Clone, Debug)]
pub struct RangeproofParams {
	/// Output value (nanogrins).
	pub value: u64,
	/// Full Pedersen commitment to (value, total_blind).
	pub commit: Commitment,
	/// Shared nonce passed as the BP `nonce` (rewind-capable; from view seed).
	///
	/// In `bullet_proof_multisig` this maps to the single-party *rewind_nonce*
	/// slot — all actors must use the same value. Private nonces stay local.
	pub shared_nonce: SecretKey,
	/// Optional extra data bound into the proof.
	pub extra_data: Option<Vec<u8>>,
	/// Optional proof message (e.g. coin number encoding).
	pub message: Option<ProofMessage>,
}

/// Round-1 public contribution from one actor.
#[derive(Clone, Debug)]
pub struct Round1Share {
	/// Partial T1.
	pub t_one: PublicKey,
	/// Partial T2.
	pub t_two: PublicKey,
}

/// Per-actor secret state kept between rounds (never broadcast).
#[derive(Clone)]
pub struct ActorRpSecrets {
	/// This actor's partial blinding factor.
	pub partial_blind: SecretKey,
	/// Local private nonce (protects the share).
	pub private_nonce: SecretKey,
	/// Round-1 T1 (copy for convenience).
	pub t_one: PublicKey,
	/// Round-1 T2.
	pub t_two: PublicKey,
}

impl std::fmt::Debug for ActorRpSecrets {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ActorRpSecrets")
			.field("partial_blind", &"[redacted]")
			.field("private_nonce", &"[redacted]")
			.field("t_one", &self.t_one)
			.field("t_two", &self.t_two)
			.finish()
	}
}

/// Aggregated T1/T2 after round 1.
#[derive(Clone, Debug)]
pub struct AggregatedT {
	/// Σ T1_j
	pub t_one: PublicKey,
	/// Σ T2_j
	pub t_two: PublicKey,
}

/// Build a proof message embedding the coin number (first 8 bytes).
pub fn coin_proof_message(coin: &CoinId) -> ProofMessage {
	let mut msg = coin.number.to_be_bytes().to_vec();
	// Pad with value bytes for recovery convenience (optional)
	msg.extend_from_slice(&coin.value.to_be_bytes());
	ProofMessage::from_bytes(&msg)
}

/// Derive shared BP nonce (rewind-capable) from view seed + commitment.
pub fn derive_shared_nonce(
	secp: &Secp256k1,
	view_seed: &[u8],
	commit: &Commitment,
) -> Result<SecretKey, Error> {
	let mut msg = view_seed.to_vec();
	msg.extend_from_slice(b"|bp-shared|");
	msg.extend_from_slice(&commit.0);
	hash_to_scalar(secp, HashDomain::Hkdf, &msg)
}

/// Partial blinds for a quorum: `blind_j = λ_j * y_j` at x_coin,
/// with the public view mix added to **canonical** actor index 0 (C-07).
///
/// The returned vector is aligned with [`canonical_quorum`] order.
pub fn quorum_partial_blinds(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<Vec<SecretKey>, Error> {
	let quorum = canonical_quorum(quorum)?;
	let x = coin_x(secp, coin)?;
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let mix = view_mix(secp, &seed, &x)?;

	let mut blinds = Vec::with_capacity(quorum.len());
	for j in 0..quorum.len() {
		let mut b = partial_key_at(secp, &quorum, j, &x)?;
		if j == 0 {
			b = sk_add(secp, &b, &mix)?;
		}
		blinds.push(b);
	}
	Ok(blinds)
}

/// Full Pedersen commitment for a coin from secret reconstruction (local sim).
pub fn coin_pedersen_commit(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<Commitment, Error> {
	let blind = coin_blinding_factor(secp, public_poly, quorum, coin)?;
	Ok(secp.commit(coin.value, blind)?)
}

/// Pedersen commitment from **public** poly only (no share secrets).
///
/// `C = v·H + (P(x_coin) + mix·G)`. Used by networked sessions where each
/// actor only holds its own y.
pub fn coin_pedersen_commit_public(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	coin: &CoinId,
) -> Result<Commitment, Error> {
	let value_c = secp.commit_value(coin.value)?;
	let (pk_blind, _) = coin_commitment_components(secp, public_poly, coin)?;
	let blind_c = Commitment::from_pubkey(secp, &pk_blind)?;
	secp.commit_sum(vec![value_c, blind_c], vec![])
		.map_err(|e| Error::Multisig(format!("public commit sum: {}", e)))
}

/// One actor's partial blind for a coin (only needs that actor's y in `quorum`).
pub fn partial_blind_for_actor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	coin: &CoinId,
) -> Result<SecretKey, Error> {
	let quorum = canonical_quorum(quorum)?;
	if j >= quorum.len() {
		return Err(Error::Multisig("actor index out of range".into()));
	}
	let x = coin_x(secp, coin)?;
	let mut b = partial_key_at(secp, &quorum, j, &x)?;
	if j == 0 {
		let seed = view_seed_from_public_poly(secp, public_poly)?;
		let mix = view_mix(secp, &seed, &x)?;
		b = sk_add(secp, &b, &mix)?;
	}
	Ok(b)
}

/// Build rangeproof params from multisig coin + public view material.
///
/// Does **not** require secret shares — commitment is derived from the public
/// polynomial (networked multiparty safe).
pub fn rangeproof_params_for_coin(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	coin: &CoinId,
	extra_data: Option<Vec<u8>>,
) -> Result<RangeproofParams, Error> {
	let commit = coin_pedersen_commit_public(secp, public_poly, coin)?;
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let shared_nonce = derive_shared_nonce(secp, &seed, &commit)?;
	Ok(RangeproofParams {
		value: coin.value,
		commit,
		shared_nonce,
		extra_data,
		message: Some(coin_proof_message(coin)),
	})
}

/// Round 1: produce T1/T2 for this actor's partial blind.
pub fn rangeproof_round1(
	secp: &Secp256k1,
	params: &RangeproofParams,
	partial_blind: &SecretKey,
) -> Result<(ActorRpSecrets, Round1Share), Error> {
	let private_nonce = SecretKey::new(secp, &mut thread_rng());
	let mut t_one = PublicKey::new();
	let mut t_two = PublicKey::new();

	let commits = vec![params.commit];
	let res = secp.bullet_proof_multisig(
		params.value,
		partial_blind.clone(),
		params.shared_nonce.clone(),
		params.extra_data.clone(),
		params.message.clone(),
		None,
		Some(&mut t_one),
		Some(&mut t_two),
		commits,
		Some(&private_nonce),
		BP_STEP_T1_T2,
	);
	// step 1 returns None for the proof
	if res.is_some() {
		return Err(Error::Multisig("unexpected rangeproof on round1".into()));
	}

	let secrets = ActorRpSecrets {
		partial_blind: partial_blind.clone(),
		private_nonce,
		t_one,
		t_two,
	};
	let share = Round1Share { t_one, t_two };
	Ok((secrets, share))
}

/// Aggregate round-1 T1/T2 shares.
pub fn aggregate_round1(secp: &Secp256k1, shares: &[Round1Share]) -> Result<AggregatedT, Error> {
	if shares.is_empty() {
		return Err(Error::Multisig("no round1 shares".into()));
	}
	let t1_refs: Vec<&PublicKey> = shares.iter().map(|s| &s.t_one).collect();
	let t2_refs: Vec<&PublicKey> = shares.iter().map(|s| &s.t_two).collect();
	Ok(AggregatedT {
		t_one: PublicKey::from_combination(secp, t1_refs)?,
		t_two: PublicKey::from_combination(secp, t2_refs)?,
	})
}

/// Round 2: produce partial τ_x given aggregated T1/T2.
pub fn rangeproof_round2(
	secp: &Secp256k1,
	params: &RangeproofParams,
	secrets: &ActorRpSecrets,
	agg: &AggregatedT,
) -> Result<SecretKey, Error> {
	bp_step2_tau(
		secp,
		params,
		&secrets.partial_blind,
		&secrets.private_nonce,
		agg,
	)
}

/// Expected public partial blind `P_j = blind_j · G` from the public polynomial.
///
/// `blind_j = λ_j(x_coin) · y_j` (+ view mix on actor 0), so
/// `P_j = λ_j · P_poly(x_j) [+ mix·G]`.
pub fn expected_pub_blind_for_actor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	coin: &CoinId,
) -> Result<PublicKey, Error> {
	let quorum = canonical_quorum(quorum)?;
	if j >= quorum.len() {
		return Err(Error::Multisig(format!("actor index {} out of quorum", j)));
	}
	let x_coin = coin_x(secp, coin)?;
	let xs: Vec<SecretKey> = quorum.iter().map(|p| p.x.clone()).collect();
	let lambda = lagrange_coefficient(secp, &xs, j, &x_coin)?;
	let g_y = eval_public_poly(secp, public_poly, &quorum[j].x)?;
	let mut term = g_y;
	term.mul_assign(secp, &lambda)?;
	if j == 0 {
		let seed = view_seed_from_public_poly(secp, public_poly)?;
		let mix = view_mix(secp, &seed, &x_coin)?;
		let g_mix = PublicKey::from_secret_key(secp, &mix)?;
		term = PublicKey::from_combination(secp, vec![&term, &g_mix])?;
	}
	Ok(term)
}

/// Fiat–Shamir challenges `(x, z²)` for the multiparty BP τ relation, recovered
/// by probe step-2 runs against the aggregated round-1 T1/T2 (C-06).
///
/// Matches libsecp: `τ = τ1·x + τ2·x² + z²·blind` with the same `(x,z)` for
/// every actor once T1/T2 are fixed.
pub fn derive_tau_challenges(
	secp: &Secp256k1,
	params: &RangeproofParams,
	agg: &AggregatedT,
) -> Result<TauChallenges, Error> {
	// --- Recover z²: same private_nonce, two different blinds ---
	let pn_z = SecretKey::new(secp, &mut thread_rng());
	let blind_a = SecretKey::new(secp, &mut thread_rng());
	let mut blind_b = SecretKey::new(secp, &mut thread_rng());
	// Ensure blinds differ (retry once if collision — astronomically rare).
	if blind_a.0 == blind_b.0 {
		blind_b = SecretKey::new(secp, &mut thread_rng());
	}
	let tau_a = bp_step2_tau(secp, params, &blind_a, &pn_z, agg)?;
	let tau_b = bp_step2_tau(secp, params, &blind_b, &pn_z, agg)?;
	let d_tau = sk_sub(secp, &tau_a, &tau_b)?;
	let d_blind = sk_sub(secp, &blind_a, &blind_b)?;
	let z_sq = sk_div(secp, &d_tau, &d_blind)?;

	// --- Recover (x, x²): two private_nonces, known (τ1,τ2) via chacha20 ---
	let mut x = None;
	let mut x_sq = None;
	for _attempt in 0..8 {
		let pn_c = SecretKey::new(secp, &mut thread_rng());
		let pn_d = SecretKey::new(secp, &mut thread_rng());
		let blind_c = SecretKey::new(secp, &mut thread_rng());
		let blind_d = SecretKey::new(secp, &mut thread_rng());
		let (t1_c, t2_c) = scalar_chacha20_pair(secp, &pn_c.0, 1)?;
		let (t1_d, t2_d) = scalar_chacha20_pair(secp, &pn_d.0, 1)?;
		let tau_c = bp_step2_tau(secp, params, &blind_c, &pn_c, agg)?;
		let tau_d = bp_step2_tau(secp, params, &blind_d, &pn_d, agg)?;
		// residual = τ − z²·blind = τ1·x + τ2·x²
		let z_b_c = sk_mul(secp, &z_sq, &blind_c)?;
		let z_b_d = sk_mul(secp, &z_sq, &blind_d)?;
		let r_c = sk_sub(secp, &tau_c, &z_b_c)?;
		let r_d = sk_sub(secp, &tau_d, &z_b_d)?;
		// 2×2: [t1_c t2_c; t1_d t2_d] · [x; x²] = [r_c; r_d]
		let det = sk_sub(
			secp,
			&sk_mul(secp, &t1_c, &t2_d)?,
			&sk_mul(secp, &t2_c, &t1_d)?,
		)?;
		// Skip singular draws.
		if det.0.iter().all(|&b| b == 0) {
			continue;
		}
		let x_num = sk_sub(
			secp,
			&sk_mul(secp, &r_c, &t2_d)?,
			&sk_mul(secp, &t2_c, &r_d)?,
		)?;
		let x2_num = sk_sub(
			secp,
			&sk_mul(secp, &t1_c, &r_d)?,
			&sk_mul(secp, &r_c, &t1_d)?,
		)?;
		let x_cand = sk_div(secp, &x_num, &det)?;
		let x2_cand = sk_div(secp, &x2_num, &det)?;
		// Consistency: x² must equal x·x.
		let x_sq_check = sk_mul(secp, &x_cand, &x_cand)?;
		if x_sq_check.0 != x2_cand.0 {
			continue;
		}
		x = Some(x_cand);
		x_sq = Some(x2_cand);
		break;
	}
	let (x, x_sq) = match (x, x_sq) {
		(Some(x), Some(x_sq)) => (x, x_sq),
		_ => {
			return Err(Error::Multisig(
				"failed to recover BP challenges (x, z²) from probes".into(),
			))
		}
	};
	Ok(TauChallenges { x, x_sq, z_sq })
}

/// Fiat–Shamir challenges used in the multiparty τ relation.
#[derive(Clone)]
pub struct TauChallenges {
	/// Challenge `x`.
	pub x: SecretKey,
	/// `x²` (cached; equals `x·x`).
	pub x_sq: SecretKey,
	/// Challenge `z²` (only `z²` appears in the τ formula).
	pub z_sq: SecretKey,
}

impl std::fmt::Debug for TauChallenges {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("TauChallenges { /* redacted */ }")
	}
}

/// Verify one actor's partial τ against its round-1 share and public blind
/// commitment (C-06 identifiable abort).
///
/// Checks `τ·G = x·T1 + x²·T2 + z²·P`.
pub fn verify_tau_share(
	secp: &Secp256k1,
	tau: &SecretKey,
	share: &Round1Share,
	pub_blind: &PublicKey,
	challenges: &TauChallenges,
) -> Result<(), Error> {
	let mut t1x = share.t_one;
	t1x.mul_assign(secp, &challenges.x)?;
	let mut t2x2 = share.t_two;
	t2x2.mul_assign(secp, &challenges.x_sq)?;
	let mut pz2 = *pub_blind;
	pz2.mul_assign(secp, &challenges.z_sq)?;
	let rhs = PublicKey::from_combination(secp, vec![&t1x, &t2x2, &pz2])?;
	let lhs = PublicKey::from_secret_key(secp, tau)?;
	if lhs != rhs {
		return Err(Error::Multisig(
			"partial τ does not match T1/T2/blind relation".into(),
		));
	}
	Ok(())
}

/// Verify each partial τ (with actor-index attribution) then sum.
pub fn aggregate_tau_verified(
	secp: &Secp256k1,
	params: &RangeproofParams,
	agg: &AggregatedT,
	r1_shares: &[Round1Share],
	tau_parts: &[SecretKey],
	pub_blinds: &[PublicKey],
) -> Result<SecretKey, Error> {
	if tau_parts.is_empty() {
		return Err(Error::Multisig("no tau parts".into()));
	}
	if r1_shares.len() != tau_parts.len() || pub_blinds.len() != tau_parts.len() {
		return Err(Error::Multisig(
			"tau/r1/pub_blind length mismatch".into(),
		));
	}
	let challenges = derive_tau_challenges(secp, params, agg)?;
	for (j, ((tau, share), pub_blind)) in tau_parts
		.iter()
		.zip(r1_shares.iter())
		.zip(pub_blinds.iter())
		.enumerate()
	{
		verify_tau_share(secp, tau, share, pub_blind, &challenges).map_err(|e| {
			Error::Multisig(format!(
				"bad partial τ from actor {} (identifiable abort): {}",
				j, e
			))
		})?;
	}
	aggregate_tau(secp, tau_parts)
}

/// Sum partial τ_x values (no verification — prefer [`aggregate_tau_verified`]).
pub fn aggregate_tau(secp: &Secp256k1, parts: &[SecretKey]) -> Result<SecretKey, Error> {
	if parts.is_empty() {
		return Err(Error::Multisig("no tau parts".into()));
	}
	let mut acc = parts[0].clone();
	for p in parts.iter().skip(1) {
		acc = sk_add(secp, &acc, p)?;
	}
	Ok(acc)
}

/// Internal: multiparty BP step 2 for a chosen (blind, private_nonce).
fn bp_step2_tau(
	secp: &Secp256k1,
	params: &RangeproofParams,
	blind: &SecretKey,
	private_nonce: &SecretKey,
	agg: &AggregatedT,
) -> Result<SecretKey, Error> {
	let mut tau_x = SecretKey::new(secp, &mut thread_rng());
	let mut t_one = agg.t_one;
	let mut t_two = agg.t_two;
	let commits = vec![params.commit];

	let res = secp.bullet_proof_multisig(
		params.value,
		blind.clone(),
		params.shared_nonce.clone(),
		params.extra_data.clone(),
		params.message.clone(),
		Some(&mut tau_x),
		Some(&mut t_one),
		Some(&mut t_two),
		commits,
		Some(private_nonce),
		BP_STEP_TAU,
	);
	if res.is_some() {
		return Err(Error::Multisig("unexpected rangeproof on round2".into()));
	}
	Ok(tau_x)
}

/// libsecp `secp256k1_scalar_chacha20` → two valid secret keys (big-endian).
///
/// Used only to recover probe `(τ1, τ2)` when deriving challenges; must match
/// the C implementation bit-for-bit (including overflow retry).
fn scalar_chacha20_pair(
	secp: &Secp256k1,
	seed: &[u8; 32],
	idx: u64,
) -> Result<(SecretKey, SecretKey), Error> {
	// secp256k1 order limbs (d[0] = low)
	const N0: u64 = 0xBFD25E8CD0364141;
	const N1: u64 = 0xBAAEDCE6AF48A03B;
	const N2: u64 = 0xFFFFFFFFFFFFFFFE;
	const N3: u64 = 0xFFFFFFFFFFFFFFFF;

	fn rotl32(x: u32, n: u32) -> u32 {
		x.rotate_left(n)
	}
	fn quarterround(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
		s[a] = s[a].wrapping_add(s[b]);
		s[d] = rotl32(s[d] ^ s[a], 16);
		s[c] = s[c].wrapping_add(s[d]);
		s[b] = rotl32(s[b] ^ s[c], 12);
		s[a] = s[a].wrapping_add(s[b]);
		s[d] = rotl32(s[d] ^ s[a], 8);
		s[c] = s[c].wrapping_add(s[d]);
		s[b] = rotl32(s[b] ^ s[c], 7);
	}
	// LE host (macOS/Linux x86_64/aarch64): LE32 = id, BE32 = bswap
	fn be32(p: u32) -> u32 {
		p.swap_bytes()
	}
	fn le32(p: u32) -> u32 {
		p
	}
	fn check_overflow(d: &[u64; 4]) -> bool {
		let mut no = false;
		let mut yes = false;
		if d[3] < N3 {
			no = true;
		}
		if d[2] < N2 {
			no = true;
		}
		if d[2] > N2 && !no {
			yes = true;
		}
		if d[1] < N1 {
			no = true;
		}
		if d[1] > N1 && !no {
			yes = true;
		}
		if d[0] >= N0 && !no {
			yes = true;
		}
		yes
	}
	fn limbs_to_b32(d: &[u64; 4]) -> [u8; 32] {
		let mut bin = [0u8; 32];
		for (i, &limb) in [d[3], d[2], d[1], d[0]].iter().enumerate() {
			for j in 0..8 {
				bin[i * 8 + j] = (limb >> (56 - 8 * j)) as u8;
			}
		}
		bin
	}

	// seed as 8 native u32 words (memcpy into uint32_t[8] on LE)
	let mut seed32 = [0u32; 8];
	for i in 0..8 {
		seed32[i] = u32::from_le_bytes(seed[i * 4..i * 4 + 4].try_into().unwrap());
	}

	for over_count in 0u32..1024 {
		let mut x = [0u32; 16];
		x[0] = 0x6170_7865;
		x[1] = 0x3320_646e;
		x[2] = 0x7962_2d32;
		x[3] = 0x6b20_6574;
		for i in 0..8 {
			x[4 + i] = le32(seed32[i]);
		}
		x[12] = idx as u32;
		x[13] = (idx >> 32) as u32;
		x[14] = 0;
		x[15] = over_count;

		for _ in 0..10 {
			quarterround(&mut x, 0, 4, 8, 12);
			quarterround(&mut x, 1, 5, 9, 13);
			quarterround(&mut x, 2, 6, 10, 14);
			quarterround(&mut x, 3, 7, 11, 15);
			quarterround(&mut x, 0, 5, 10, 15);
			quarterround(&mut x, 1, 6, 11, 12);
			quarterround(&mut x, 2, 7, 8, 13);
			quarterround(&mut x, 3, 4, 9, 14);
		}

		x[0] = x[0].wrapping_add(0x6170_7865);
		x[1] = x[1].wrapping_add(0x3320_646e);
		x[2] = x[2].wrapping_add(0x7962_2d32);
		x[3] = x[3].wrapping_add(0x6b20_6574);
		for i in 0..8 {
			x[4 + i] = x[4 + i].wrapping_add(le32(seed32[i]));
		}
		x[12] = x[12].wrapping_add(idx as u32);
		x[13] = x[13].wrapping_add((idx >> 32) as u32);
		x[15] = x[15].wrapping_add(over_count);

		let r1 = [
			((be32(x[6]) as u64) << 32) | (be32(x[7]) as u64),
			((be32(x[4]) as u64) << 32) | (be32(x[5]) as u64),
			((be32(x[2]) as u64) << 32) | (be32(x[3]) as u64),
			((be32(x[0]) as u64) << 32) | (be32(x[1]) as u64),
		];
		let r2 = [
			((be32(x[14]) as u64) << 32) | (be32(x[15]) as u64),
			((be32(x[12]) as u64) << 32) | (be32(x[13]) as u64),
			((be32(x[10]) as u64) << 32) | (be32(x[11]) as u64),
			((be32(x[8]) as u64) << 32) | (be32(x[9]) as u64),
		];
		if check_overflow(&r1) || check_overflow(&r2) {
			continue;
		}
		let b1 = limbs_to_b32(&r1);
		let b2 = limbs_to_b32(&r2);
		// Reject zero (invalid SecretKey); retry like overflow.
		let sk1 = match sk_from_bytes(secp, &b1) {
			Ok(s) => s,
			Err(_) => continue,
		};
		let sk2 = match sk_from_bytes(secp, &b2) {
			Ok(s) => s,
			Err(_) => continue,
		};
		return Ok((sk1, sk2));
	}
	Err(Error::Multisig(
		"scalar_chacha20 failed to produce valid scalars".into(),
	))
}

/// Final step: produce the RangeProof (any actor may run this).
pub fn rangeproof_finalize(
	secp: &Secp256k1,
	params: &RangeproofParams,
	secrets: &ActorRpSecrets,
	agg: &AggregatedT,
	tau_sum: &SecretKey,
) -> Result<RangeProof, Error> {
	let mut tau_x = tau_sum.clone();
	let mut t_one = agg.t_one;
	let mut t_two = agg.t_two;
	let commits = vec![params.commit];

	secp.bullet_proof_multisig(
		params.value,
		secrets.partial_blind.clone(),
		params.shared_nonce.clone(),
		params.extra_data.clone(),
		params.message.clone(),
		Some(&mut tau_x),
		Some(&mut t_one),
		Some(&mut t_two),
		commits,
		Some(&secrets.private_nonce),
		BP_STEP_FINAL,
	)
	.ok_or_else(|| Error::Multisig("rangeproof finalize failed".into()))
}

/// Verify a multiparty rangeproof against its commitment.
pub fn verify_rangeproof(
	secp: &Secp256k1,
	commit: Commitment,
	proof: RangeProof,
	extra_data: Option<Vec<u8>>,
) -> Result<(), Error> {
	secp.verify_bullet_proof(commit, proof, extra_data)
		.map(|_| ())
		.map_err(|e| Error::Multisig(format!("rangeproof verify failed: {:?}", e)))
}

/// Attempt to rewind a multisig rangeproof with the shared nonce.
///
/// Returns `(value, message_bytes)` on success. The recovered blinding factor
/// is **not** generally the full multisig coin blind (partials + mix); use
/// value/message for wallet recognition only.
pub fn rewind_rangeproof(
	secp: &Secp256k1,
	params: &RangeproofParams,
	proof: RangeProof,
) -> Result<(u64, Vec<u8>), Error> {
	let info = secp
		.rewind_bullet_proof(
			params.commit,
			params.shared_nonce.clone(),
			params.extra_data.clone(),
			proof,
		)
		.map_err(|e| Error::Multisig(format!("rewind failed: {:?}", e)))?;
	Ok((info.value, info.message.as_bytes().to_vec()))
}

/// In-process multiparty rangeproof for a full quorum (tests / local sim).
///
/// Each quorum member uses only its partial blind; T1/T2/τ are aggregated
/// as in the networked protocol. Partial τ values are verified (C-06) before
/// aggregation.
pub fn run_rangeproof_local(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
	extra_data: Option<Vec<u8>>,
) -> Result<(RangeProof, RangeproofParams), Error> {
	// C-07: work in canonical quorum order (mix role = index 0).
	let quorum = canonical_quorum(quorum)?;
	let params = rangeproof_params_for_coin(secp, public_poly, coin, extra_data)?;
	let blinds = quorum_partial_blinds(secp, public_poly, &quorum, coin)?;

	// Round 1
	let mut actor_secrets = Vec::new();
	let mut r1_shares = Vec::new();
	for blind in &blinds {
		let (sec, share) = rangeproof_round1(secp, &params, blind)?;
		actor_secrets.push(sec);
		r1_shares.push(share);
	}
	let agg = aggregate_round1(secp, &r1_shares)?;

	// Round 2 + C-06 verification of each partial τ
	let mut tau_parts = Vec::new();
	let mut pub_blinds = Vec::new();
	for (j, sec) in actor_secrets.iter().enumerate() {
		tau_parts.push(rangeproof_round2(secp, &params, sec, &agg)?);
		pub_blinds.push(expected_pub_blind_for_actor(
			secp,
			public_poly,
			&quorum,
			j,
			coin,
		)?);
	}
	let tau_sum =
		aggregate_tau_verified(secp, &params, &agg, &r1_shares, &tau_parts, &pub_blinds)?;

	// Finalize (actor 0)
	let proof = rangeproof_finalize(secp, &params, &actor_secrets[0], &agg, &tau_sum)?;
	verify_rangeproof(secp, params.commit, proof, params.extra_data.clone())?;
	Ok((proof, params))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	fn two_of_three_quorum(
		secp: &Secp256k1,
	) -> (crate::multisig::types::MultisigWalletState, Vec<ActorPoint>) {
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(secp, CeremonyId::new(), params, actors).unwrap();
		// Use actors 0 and 1 as quorum
		let q = vec![
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[1].shares[0]),
		];
		(states[0].clone(), q)
	}

	#[test]
	fn multiparty_rangeproof_verifies() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(7, 1_000_000_000);
		let (proof, params) =
			run_rangeproof_local(&secp, &state.config.public_poly, &q, &coin, None).unwrap();
		assert!(proof.plen > 0);
		verify_rangeproof(&secp, params.commit, proof, None).unwrap();
	}

	#[test]
	fn reversed_quorum_same_rangeproof() {
		// C-07: arbitrary quorum order must not change the resulting proof/commit.
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, mut q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(8, 77);
		let (p1, params1) =
			run_rangeproof_local(&secp, &state.config.public_poly, &q, &coin, None).unwrap();
		q.reverse();
		let (p2, params2) =
			run_rangeproof_local(&secp, &state.config.public_poly, &q, &coin, None).unwrap();
		assert_eq!(params1.commit, params2.commit);
		// Proofs are randomized per private nonces, but both must verify.
		verify_rangeproof(&secp, params1.commit, p1, None).unwrap();
		verify_rangeproof(&secp, params2.commit, p2, None).unwrap();
	}

	#[test]
	fn multiparty_rangeproof_with_extra_data() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(3, 42);
		let extra = Some(b"grin-msig-extra".to_vec());
		let (proof, params) =
			run_rangeproof_local(&secp, &state.config.public_poly, &q, &coin, extra.clone())
				.unwrap();
		verify_rangeproof(&secp, params.commit, proof, extra).unwrap();
	}

	#[test]
	fn partial_blinds_sum_to_full() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(1, 999);
		let blinds = quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		let mut sum = blinds[0].clone();
		for b in blinds.iter().skip(1) {
			sum = sk_add(&secp, &sum, b).unwrap();
		}
		let full = coin_blinding_factor(&secp, &state.config.public_poly, &q, &coin).unwrap();
		assert_eq!(sum.0, full.0);
	}

	#[test]
	fn different_quorum_same_commit() {
		// Any 2-of-3 quorum should produce the same full commitment
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let coin = CoinId::new(5, 12345);
		let q01 = vec![
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[1].shares[0]),
		];
		let q02 = vec![
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[2].shares[0]),
		];
		let c1 = coin_pedersen_commit(&secp, &states[0].config.public_poly, &q01, &coin).unwrap();
		let c2 = coin_pedersen_commit(&secp, &states[0].config.public_poly, &q02, &coin).unwrap();
		assert_eq!(c1, c2);
	}

	#[test]
	fn rewind_recovers_value() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(11, 55_000);
		let (proof, params) =
			run_rangeproof_local(&secp, &state.config.public_poly, &q, &coin, None).unwrap();
		let (value, msg) = rewind_rangeproof(&secp, &params, proof).unwrap();
		assert_eq!(value, coin.value);
		// Message starts with coin number (8 bytes BE)
		assert!(msg.len() >= 8);
		let mut num_bytes = [0u8; 8];
		num_bytes.copy_from_slice(&msg[0..8]);
		assert_eq!(u64::from_be_bytes(num_bytes), coin.number);
	}

	#[test]
	fn three_party_rangeproof() {
		// N-of-N style: all 3 actors participate as quorum of 3
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(3, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let coin = CoinId::new(100, 7);
		let (proof, p) =
			run_rangeproof_local(&secp, &states[0].config.public_poly, &q, &coin, None).unwrap();
		verify_rangeproof(&secp, p.commit, proof, None).unwrap();
	}

	#[test]
	fn chacha20_matches_round1_t1_t2() {
		// scalar_chacha20(private_nonce, 1) must produce (τ1, τ2) with T1=τ1·G, T2=τ2·G.
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(1, 100);
		let params =
			rangeproof_params_for_coin(&secp, &state.config.public_poly, &coin, None).unwrap();
		let blinds = quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		let (sec, share) = rangeproof_round1(&secp, &params, &blinds[0]).unwrap();
		let (tau1, tau2) = scalar_chacha20_pair(&secp, &sec.private_nonce.0, 1).unwrap();
		let g1 = PublicKey::from_secret_key(&secp, &tau1).unwrap();
		let g2 = PublicKey::from_secret_key(&secp, &tau2).unwrap();
		assert_eq!(g1, share.t_one);
		assert_eq!(g2, share.t_two);
	}

	#[test]
	fn pub_blind_matches_partial() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(9, 1234);
		let blinds = quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		for (j, blind) in blinds.iter().enumerate() {
			let expected =
				expected_pub_blind_for_actor(&secp, &state.config.public_poly, &q, j, &coin)
					.unwrap();
			let got = PublicKey::from_secret_key(&secp, blind).unwrap();
			assert_eq!(expected, got);
		}
	}

	#[test]
	fn honest_tau_verifies() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(2, 50_000);
		let params =
			rangeproof_params_for_coin(&secp, &state.config.public_poly, &coin, None).unwrap();
		let blinds = quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		let mut secrets = Vec::new();
		let mut r1 = Vec::new();
		for b in &blinds {
			let (s, share) = rangeproof_round1(&secp, &params, b).unwrap();
			secrets.push(s);
			r1.push(share);
		}
		let agg = aggregate_round1(&secp, &r1).unwrap();
		let mut taus = Vec::new();
		let mut pubs = Vec::new();
		for (j, s) in secrets.iter().enumerate() {
			taus.push(rangeproof_round2(&secp, &params, s, &agg).unwrap());
			pubs.push(
				expected_pub_blind_for_actor(&secp, &state.config.public_poly, &q, j, &coin)
					.unwrap(),
			);
		}
		// Must accept honest partials and produce a working sum.
		let tau_sum = aggregate_tau_verified(&secp, &params, &agg, &r1, &taus, &pubs).unwrap();
		let proof = rangeproof_finalize(&secp, &params, &secrets[0], &agg, &tau_sum).unwrap();
		verify_rangeproof(&secp, params.commit, proof, None).unwrap();
	}

	#[test]
	fn bad_tau_rejected_with_actor_index() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(3, 99);
		let params =
			rangeproof_params_for_coin(&secp, &state.config.public_poly, &coin, None).unwrap();
		let blinds = quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		let mut secrets = Vec::new();
		let mut r1 = Vec::new();
		for b in &blinds {
			let (s, share) = rangeproof_round1(&secp, &params, b).unwrap();
			secrets.push(s);
			r1.push(share);
		}
		let agg = aggregate_round1(&secp, &r1).unwrap();
		let mut taus = Vec::new();
		let mut pubs = Vec::new();
		for (j, s) in secrets.iter().enumerate() {
			taus.push(rangeproof_round2(&secp, &params, s, &agg).unwrap());
			pubs.push(
				expected_pub_blind_for_actor(&secp, &state.config.public_poly, &q, j, &coin)
					.unwrap(),
			);
		}
		// Corrupt actor 1's τ.
		taus[1] = SecretKey::new(&secp, &mut rand::thread_rng());
		let err = aggregate_tau_verified(&secp, &params, &agg, &r1, &taus, &pubs).unwrap_err();
		let msg = format!("{}", err);
		assert!(
			msg.contains("actor 1") || msg.contains("bad partial τ from actor 1"),
			"expected identifiable abort for actor 1, got: {}",
			msg
		);
	}
}
