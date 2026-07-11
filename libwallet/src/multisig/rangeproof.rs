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
//! 2. **Round 1** — each actor runs step=1 → `(T1_j, T2_j)`. Aggregate
//!    `T1 = Σ T1_j`, `T2 = Σ T2_j`.
//! 3. **Round 2** — each actor runs step=2 with aggregated T1/T2 →
//!    `τ_j`. Aggregate `τ = Σ τ_j`.
//! 4. **Finalize** — any actor runs step=0 with `(τ, T1, T2)` → `RangeProof`.
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
	coin_blinding_factor, coin_x, view_mix, view_seed_from_public_poly, CoinId,
};
use super::poly::PublicPoly;
use super::scalar::{hash_to_scalar, sk_add, HashDomain};
use super::share::{partial_key_at, ActorPoint};

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
#[derive(Clone, Debug)]
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
/// with the public view mix added to actor index 0.
pub fn quorum_partial_blinds(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<Vec<SecretKey>, Error> {
	if quorum.is_empty() {
		return Err(Error::Multisig("empty quorum for rangeproof".into()));
	}
	let x = coin_x(secp, coin)?;
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let mix = view_mix(secp, &seed, &x)?;

	let mut blinds = Vec::with_capacity(quorum.len());
	for j in 0..quorum.len() {
		let mut b = partial_key_at(secp, quorum, j, &x)?;
		if j == 0 {
			b = sk_add(secp, &b, &mix)?;
		}
		blinds.push(b);
	}
	Ok(blinds)
}

/// Full Pedersen commitment for a coin (requires a reconstructing quorum).
pub fn coin_pedersen_commit(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<Commitment, Error> {
	let blind = coin_blinding_factor(secp, public_poly, quorum, coin)?;
	Ok(secp.commit(coin.value, blind)?)
}

/// Build rangeproof params from multisig coin + public view material.
pub fn rangeproof_params_for_coin(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
	extra_data: Option<Vec<u8>>,
) -> Result<RangeproofParams, Error> {
	let commit = coin_pedersen_commit(secp, public_poly, quorum, coin)?;
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
		return Err(Error::Multisig(
			"unexpected rangeproof on round1".into(),
		));
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
	let mut tau_x = SecretKey::new(secp, &mut thread_rng());
	let mut t_one = agg.t_one;
	let mut t_two = agg.t_two;
	let commits = vec![params.commit];

	let res = secp.bullet_proof_multisig(
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
		BP_STEP_TAU,
	);
	if res.is_some() {
		return Err(Error::Multisig(
			"unexpected rangeproof on round2".into(),
		));
	}
	Ok(tau_x)
}

/// Sum partial τ_x values.
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
/// as in the networked protocol.
pub fn run_rangeproof_local(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
	extra_data: Option<Vec<u8>>,
) -> Result<(RangeProof, RangeproofParams), Error> {
	let params =
		rangeproof_params_for_coin(secp, public_poly, quorum, coin, extra_data)?;
	let blinds = quorum_partial_blinds(secp, public_poly, quorum, coin)?;

	// Round 1
	let mut actor_secrets = Vec::new();
	let mut r1_shares = Vec::new();
	for blind in &blinds {
		let (sec, share) = rangeproof_round1(secp, &params, blind)?;
		actor_secrets.push(sec);
		r1_shares.push(share);
	}
	let agg = aggregate_round1(secp, &r1_shares)?;

	// Round 2
	let mut tau_parts = Vec::new();
	for sec in &actor_secrets {
		tau_parts.push(rangeproof_round2(secp, &params, sec, &agg)?);
	}
	let tau_sum = aggregate_tau(secp, &tau_parts)?;

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
	) -> (
		crate::multisig::types::MultisigWalletState,
		Vec<ActorPoint>,
	) {
		let params = ThresholdParams::new(2, 3).unwrap();
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
	fn multiparty_rangeproof_with_extra_data() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(3, 42);
		let extra = Some(b"grin-msig-extra".to_vec());
		let (proof, params) = run_rangeproof_local(
			&secp,
			&state.config.public_poly,
			&q,
			&coin,
			extra.clone(),
		)
		.unwrap();
		verify_rangeproof(&secp, params.commit, proof, extra).unwrap();
	}

	#[test]
	fn partial_blinds_sum_to_full() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (state, q) = two_of_three_quorum(&secp);
		let coin = CoinId::new(1, 999);
		let blinds =
			quorum_partial_blinds(&secp, &state.config.public_poly, &q, &coin).unwrap();
		let mut sum = blinds[0].clone();
		for b in blinds.iter().skip(1) {
			sum = sk_add(&secp, &sum, b).unwrap();
		}
		let full =
			coin_blinding_factor(&secp, &state.config.public_poly, &q, &coin).unwrap();
		assert_eq!(sum.0, full.0);
	}

	#[test]
	fn different_quorum_same_commit() {
		// Any 2-of-3 quorum should produce the same full commitment
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(2, 3).unwrap();
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
		let c1 =
			coin_pedersen_commit(&secp, &states[0].config.public_poly, &q01, &coin).unwrap();
		let c2 =
			coin_pedersen_commit(&secp, &states[0].config.public_poly, &q02, &coin).unwrap();
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
		let params = ThresholdParams::new(3, 3).unwrap();
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
}
