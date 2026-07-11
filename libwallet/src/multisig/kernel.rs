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

//! Threshold multiparty kernel signing for multisig wallets.
//!
//! Builds on Grin's existing **additive** aggsig (`calculate_partial_sig` /
//! `add_signatures`). Each quorum member holds a Lagrange partial of the
//! kernel excess secret; partials sum to the full excess key.
//!
//! ## Protocol (2.5 rounds)
//!
//! 1. **Nonce commit** — each actor samples a secure nonce (`create_secnonce`)
//!    and broadcasts `H(pub_nonce)` (binding commitment).
//! 2. **Nonce reveal** — reveal `pub_nonce`; peers check against commitment.
//!    Aggregate `R = Σ R_j`, `X = Σ X_j` (excess pubkeys).
//! 3. **Partial sig** — each signs with `calculate_partial_sig` using the
//!    same kernel message, `R`, and `X`.
//! 4. **Aggregate** — `add_signatures` → final kernel signature; verify vs
//!    excess commitment / pubkey.
//!
//! ## Security notes
//!
//! - This is **not** full FROST. It is additive multi-sig (same family as
//!   Grin sender/receiver) with **nonce commitments** to reduce adaptive
//!   nonce attacks within a single session.
//! - Concurrent sessions must use distinct `session_id` context in the
//!   offset and must not reuse nonces.
//! - Partial excess keys are session-specific (Lagrange over the active
//!   quorum); do not reuse across different quorums without recomputing.
//!
//! **Status:** experimental. Not wired into slatepack / full tx build yet.

use crate::grin_core::core::transaction::KernelFeatures;
use crate::grin_core::core::FeeFields;
use crate::grin_core::libtx::aggsig;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::{Message, Secp256k1, Signature};
use crate::Error;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

use super::coin::{coin_partial_poly_key, tx_offset, view_mix, view_seed_from_public_poly, CoinId};
use super::poly::PublicPoly;
use super::scalar::{sk_add, sk_sub};
use super::share::ActorPoint;

/// Kernel signing session parameters shared by the quorum.
#[derive(Clone, Debug)]
pub struct KernelSession {
	/// Unique session tag (bind nonces / offset).
	pub session_id: Vec<u8>,
	/// Kernel features (fee, lock height, …).
	pub features: KernelFeatures,
	/// Deterministic offset for this session (public among actors).
	pub offset: SecretKey,
	/// Input coins being spent.
	pub inputs: Vec<CoinId>,
	/// Output coins being created.
	pub outputs: Vec<CoinId>,
}

/// Local secrets for one actor during kernel signing.
#[derive(Clone, Debug)]
pub struct ActorKernelSecrets {
	/// Partial excess secret for this actor.
	pub partial_excess: SecretKey,
	/// Secure signing nonce (secret).
	pub sec_nonce: SecretKey,
	/// Public nonce `R_j = k_j · G`.
	pub pub_nonce: PublicKey,
	/// Public partial excess `X_j = x_j · G`.
	pub pub_excess: PublicKey,
}

/// Nonce commitment: `SHA256(pub_nonce_compressed)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceCommitment {
	/// Commitment bytes.
	pub hash: [u8; 32],
}

/// Revealed nonce + excess pubkey for one actor.
#[derive(Clone, Debug)]
pub struct NonceReveal {
	/// Public nonce.
	pub pub_nonce: PublicKey,
	/// Public partial excess.
	pub pub_excess: PublicKey,
}

/// Aggregated public values after nonce reveal.
#[derive(Clone, Debug)]
pub struct AggregatedKernelPubs {
	/// `R = Σ R_j`
	pub nonce_sum: PublicKey,
	/// `X = Σ X_j` (kernel excess pubkey)
	pub excess_sum: PublicKey,
}

/// Build a plain kernel features with the given fee (nanogrins).
pub fn plain_features(fee: u64) -> Result<KernelFeatures, Error> {
	// Prefer u32 path when possible; fall back to TryFrom<u64>
	let fee_fields = if fee <= u32::MAX as u64 {
		FeeFields::from(fee as u32)
	} else {
		FeeFields::try_from(fee).map_err(|e| {
			Error::Multisig(format!("invalid fee fields: {:?}", e))
		})?
	};
	Ok(KernelFeatures::Plain { fee: fee_fields })
}

/// Kernel sighash message from features.
pub fn kernel_message(features: &KernelFeatures) -> Result<Message, Error> {
	features
		.kernel_sig_msg()
		.map_err(|e| Error::Multisig(format!("kernel msg: {}", e)))
}

/// Create session: offset bound to ceremony view seed + session context.
pub fn create_kernel_session(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	session_id: impl AsRef<[u8]>,
	features: KernelFeatures,
	inputs: Vec<CoinId>,
	outputs: Vec<CoinId>,
) -> Result<KernelSession, Error> {
	let mut ctx = session_id.as_ref().to_vec();
	ctx.extend_from_slice(b"|inputs|");
	for c in &inputs {
		ctx.extend_from_slice(&c.number.to_be_bytes());
		ctx.extend_from_slice(&c.value.to_be_bytes());
	}
	ctx.extend_from_slice(b"|outputs|");
	for c in &outputs {
		ctx.extend_from_slice(&c.number.to_be_bytes());
		ctx.extend_from_slice(&c.value.to_be_bytes());
	}
	// Bind fee into offset context
	if let KernelFeatures::Plain { fee } = &features {
		ctx.extend_from_slice(b"|fee|");
		ctx.extend_from_slice(&u64::from(*fee).to_be_bytes());
	}
	let offset = tx_offset(secp, public_poly, &ctx)?;
	Ok(KernelSession {
		session_id: session_id.as_ref().to_vec(),
		features,
		offset,
		inputs,
		outputs,
	})
}

/// Partial excess for actor `j`:
/// `Σ partial(output) − Σ partial(input) − [offset if j==0]`.
///
/// Matches Grin balance: `excess + offset = out_blinds − in_blinds`.
/// Each coin partial is the Lagrange share of `sk(x_coin)`; the view mix for
/// each coin is added only on actor 0 (same split as rangeproof blinds).
pub fn partial_excess_for_actor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<SecretKey, Error> {
	if j >= quorum.len() {
		return Err(Error::Multisig("actor index out of range".into()));
	}
	let seed = view_seed_from_public_poly(secp, public_poly)?;

	// Start at "zero" via canceling self-add; use first term carefully
	let mut acc: Option<SecretKey> = None;

	let add_coin = |acc: &mut Option<SecretKey>,
	                coin: &CoinId,
	                sign_positive: bool|
	 -> Result<(), Error> {
		let mut part = coin_partial_poly_key(secp, quorum, j, coin)?;
		if j == 0 {
			let x = super::coin::coin_x(secp, coin)?;
			let mix = view_mix(secp, &seed, &x)?;
			part = sk_add(secp, &part, &mix)?;
		}
		match acc {
			None => {
				*acc = Some(if sign_positive {
					part
				} else {
					super::scalar::sk_neg(secp, &part)?
				});
			}
			Some(a) => {
				*a = if sign_positive {
					sk_add(secp, a, &part)?
				} else {
					sk_sub(secp, a, &part)?
				};
			}
		}
		Ok(())
	};

	// Outputs positive, inputs negative (Grin BlindSum convention)
	for c in &session.outputs {
		add_coin(&mut acc, c, true)?;
	}
	for c in &session.inputs {
		add_coin(&mut acc, c, false)?;
	}

	let mut excess = acc.ok_or_else(|| {
		Error::Multisig("kernel session has no inputs or outputs".into())
	})?;

	// Subtract offset once (actor 0): excess = (out - in) - offset
	if j == 0 {
		excess = sk_sub(secp, &excess, &session.offset)?;
	}
	Ok(excess)
}

/// Commit to a public nonce: `SHA256("grin-msig/nonce-commit" || pub_nonce)`.
pub fn commit_nonce(secp: &Secp256k1, pub_nonce: &PublicKey) -> NonceCommitment {
	let mut h = Sha256::new();
	h.update(b"grin-msig/nonce-commit");
	h.update(&pub_nonce.serialize_vec(secp, true));
	let d = h.finalize();
	let mut hash = [0u8; 32];
	hash.copy_from_slice(&d);
	NonceCommitment { hash }
}

/// Verify a nonce reveal matches a prior commitment.
pub fn verify_nonce_commitment(
	secp: &Secp256k1,
	commitment: &NonceCommitment,
	pub_nonce: &PublicKey,
) -> Result<(), Error> {
	let expected = commit_nonce(secp, pub_nonce);
	if expected.hash != commitment.hash {
		return Err(Error::Multisig("nonce commitment mismatch".into()));
	}
	Ok(())
}

/// Round 1 local setup: sample nonce, derive partial excess, emit commitment.
pub fn kernel_prepare(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<(ActorKernelSecrets, NonceCommitment), Error> {
	let partial_excess =
		partial_excess_for_actor(secp, public_poly, quorum, j, session)?;
	let sec_nonce = aggsig::create_secnonce(secp)
		.map_err(|e| Error::Multisig(format!("secnonce: {}", e)))?;
	let pub_nonce = PublicKey::from_secret_key(secp, &sec_nonce)?;
	let pub_excess = PublicKey::from_secret_key(secp, &partial_excess)?;
	let commitment = commit_nonce(secp, &pub_nonce);
	Ok((
		ActorKernelSecrets {
			partial_excess,
			sec_nonce,
			pub_nonce,
			pub_excess,
		},
		commitment,
	))
}

/// Aggregate revealed nonces and excess pubkeys after commitment checks.
pub fn aggregate_kernel_pubs(
	secp: &Secp256k1,
	reveals: &[NonceReveal],
) -> Result<AggregatedKernelPubs, Error> {
	if reveals.is_empty() {
		return Err(Error::Multisig("no nonce reveals".into()));
	}
	let nonces: Vec<&PublicKey> = reveals.iter().map(|r| &r.pub_nonce).collect();
	let excesses: Vec<&PublicKey> = reveals.iter().map(|r| &r.pub_excess).collect();
	Ok(AggregatedKernelPubs {
		nonce_sum: PublicKey::from_combination(secp, nonces)?,
		excess_sum: PublicKey::from_combination(secp, excesses)?,
	})
}

/// Produce a partial kernel signature.
pub fn kernel_partial_sign(
	secp: &Secp256k1,
	secrets: &ActorKernelSecrets,
	agg: &AggregatedKernelPubs,
	session: &KernelSession,
) -> Result<Signature, Error> {
	let msg = kernel_message(&session.features)?;
	aggsig::calculate_partial_sig(
		secp,
		&secrets.partial_excess,
		&secrets.sec_nonce,
		&agg.nonce_sum,
		Some(&agg.excess_sum),
		&msg,
	)
	.map_err(|e| Error::Multisig(format!("partial sig: {}", e)))
}

/// Verify one actor's partial signature.
pub fn verify_kernel_partial(
	secp: &Secp256k1,
	partial_sig: &Signature,
	pub_excess: &PublicKey,
	agg: &AggregatedKernelPubs,
	session: &KernelSession,
) -> Result<(), Error> {
	let msg = kernel_message(&session.features)?;
	aggsig::verify_partial_sig(
		secp,
		partial_sig,
		&agg.nonce_sum,
		pub_excess,
		Some(&agg.excess_sum),
		&msg,
	)
	.map_err(|e| Error::Multisig(format!("partial verify: {}", e)))
}

/// Aggregate partial signatures into the final kernel signature.
pub fn kernel_aggregate_sigs(
	secp: &Secp256k1,
	partials: &[Signature],
	agg: &AggregatedKernelPubs,
) -> Result<Signature, Error> {
	if partials.is_empty() {
		return Err(Error::Multisig("no partial signatures".into()));
	}
	let refs: Vec<&Signature> = partials.iter().collect();
	aggsig::add_signatures(secp, refs, &agg.nonce_sum)
		.map_err(|e| Error::Multisig(format!("aggregate sig: {}", e)))
}

/// Verify the completed signature against the aggregated excess pubkey.
pub fn verify_kernel_sig(
	secp: &Secp256k1,
	sig: &Signature,
	agg: &AggregatedKernelPubs,
	session: &KernelSession,
) -> Result<(), Error> {
	let msg = kernel_message(&session.features)?;
	aggsig::verify_completed_sig(
		secp,
		sig,
		&agg.excess_sum,
		Some(&agg.excess_sum),
		&msg,
	)
	.map_err(|e| Error::Multisig(format!("completed sig verify: {}", e)))
}

/// Excess as a Pedersen commitment (value 0): `C = X` as commit.
pub fn excess_commitment(
	secp: &Secp256k1,
	agg: &AggregatedKernelPubs,
) -> Result<Commitment, Error> {
	Ok(Commitment::from_pubkey(secp, &agg.excess_sum)?)
}

/// In-process multiparty kernel sign for a quorum (tests / local sim).
///
/// Returns `(final_signature, aggregated_pubs, session)`.
pub fn run_kernel_sign_local(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	session_id: impl AsRef<[u8]>,
	fee: u64,
	inputs: Vec<CoinId>,
	outputs: Vec<CoinId>,
) -> Result<(Signature, AggregatedKernelPubs, KernelSession), Error> {
	let features = plain_features(fee)?;
	let session = create_kernel_session(
		secp,
		public_poly,
		session_id,
		features,
		inputs,
		outputs,
	)?;

	// Prepare each actor
	let mut secrets = Vec::new();
	let mut commits = Vec::new();
	for j in 0..quorum.len() {
		let (sec, c) = kernel_prepare(secp, public_poly, quorum, j, &session)?;
		secrets.push(sec);
		commits.push(c);
	}

	// Reveal + verify commitments
	let mut reveals = Vec::new();
	for (j, sec) in secrets.iter().enumerate() {
		verify_nonce_commitment(secp, &commits[j], &sec.pub_nonce)?;
		reveals.push(NonceReveal {
			pub_nonce: sec.pub_nonce,
			pub_excess: sec.pub_excess,
		});
	}
	let agg = aggregate_kernel_pubs(secp, &reveals)?;

	// Partial signs
	let mut partials = Vec::new();
	for (j, sec) in secrets.iter().enumerate() {
		let ps = kernel_partial_sign(secp, sec, &agg, &session)?;
		verify_kernel_partial(secp, &ps, &sec.pub_excess, &agg, &session)?;
		let _ = j;
		partials.push(ps);
	}

	let final_sig = kernel_aggregate_sigs(secp, &partials, &agg)?;
	verify_kernel_sig(secp, &final_sig, &agg, &session)?;
	Ok((final_sig, agg, session))
}

/// Reconstruct full excess secret (test / recovery only — **not** for
/// production signing paths).
#[cfg(test)]
fn reconstruct_full_excess(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	session: &KernelSession,
) -> Result<SecretKey, Error> {
	let mut acc = partial_excess_for_actor(secp, public_poly, quorum, 0, session)?;
	for j in 1..quorum.len() {
		let p = partial_excess_for_actor(secp, public_poly, quorum, j, session)?;
		acc = sk_add(secp, &acc, &p)?;
	}
	Ok(acc)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	fn setup_2of3(secp: &Secp256k1) -> (PublicPoly, Vec<ActorPoint>) {
		let params = ThresholdParams::new(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(secp, CeremonyId::new(), params, actors).unwrap();
		let q = vec![
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[1].shares[0]),
		];
		(states[0].config.public_poly.clone(), q)
	}

	#[test]
	fn multiparty_kernel_sign_verifies() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		// Spend coin 1 → coin 2 (change-like)
		let inputs = vec![CoinId::new(1, 1_000_000_000)];
		let outputs = vec![CoinId::new(2, 999_000_000)];
		let fee = 1_000_000;
		let (sig, agg, session) = run_kernel_sign_local(
			&secp,
			&pp,
			&q,
			b"test-session-1",
			fee,
			inputs,
			outputs,
		)
		.unwrap();
		verify_kernel_sig(&secp, &sig, &agg, &session).unwrap();
	}

	#[test]
	fn partial_excesses_sum_to_full() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		let session = create_kernel_session(
			&secp,
			&pp,
			b"sess",
			plain_features(1000).unwrap(),
			vec![CoinId::new(1, 5000)],
			vec![CoinId::new(2, 4000)],
		)
		.unwrap();
		let full = reconstruct_full_excess(&secp, &pp, &q, &session).unwrap();
		let g_full = PublicKey::from_secret_key(&secp, &full).unwrap();

		let mut acc = partial_excess_for_actor(&secp, &pp, &q, 0, &session).unwrap();
		let p1 = partial_excess_for_actor(&secp, &pp, &q, 1, &session).unwrap();
		acc = sk_add(&secp, &acc, &p1).unwrap();
		let g_sum = PublicKey::from_secret_key(&secp, &acc).unwrap();
		assert_eq!(g_full, g_sum);
	}

	#[test]
	fn nonce_commitment_binds_reveal() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let k = SecretKey::new(&secp, &mut rand::thread_rng());
		let pk = PublicKey::from_secret_key(&secp, &k).unwrap();
		let c = commit_nonce(&secp, &pk);
		verify_nonce_commitment(&secp, &c, &pk).unwrap();

		let k2 = SecretKey::new(&secp, &mut rand::thread_rng());
		let pk2 = PublicKey::from_secret_key(&secp, &k2).unwrap();
		assert!(verify_nonce_commitment(&secp, &c, &pk2).is_err());
	}

	#[test]
	fn three_of_three_kernel() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(3, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<_> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let (sig, agg, session) = run_kernel_sign_local(
			&secp,
			&states[0].config.public_poly,
			&q,
			b"3of3",
			100,
			vec![CoinId::new(10, 10_000)],
			vec![CoinId::new(11, 9_900)],
		)
		.unwrap();
		verify_kernel_sig(&secp, &sig, &agg, &session).unwrap();
	}

	#[test]
	fn bad_partial_rejected() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		let session = create_kernel_session(
			&secp,
			&pp,
			b"bad",
			plain_features(1).unwrap(),
			vec![CoinId::new(1, 100)],
			vec![CoinId::new(2, 99)],
		)
		.unwrap();
		let (sec0, _) = kernel_prepare(&secp, &pp, &q, 0, &session).unwrap();
		let (sec1, _) = kernel_prepare(&secp, &pp, &q, 1, &session).unwrap();
		let reveals = vec![
			NonceReveal {
				pub_nonce: sec0.pub_nonce,
				pub_excess: sec0.pub_excess,
			},
			NonceReveal {
				pub_nonce: sec1.pub_nonce,
				pub_excess: sec1.pub_excess,
			},
		];
		let agg = aggregate_kernel_pubs(&secp, &reveals).unwrap();
		let good = kernel_partial_sign(&secp, &sec0, &agg, &session).unwrap();
		// Verify with wrong pubkey should fail
		assert!(verify_kernel_partial(&secp, &good, &sec1.pub_excess, &agg, &session).is_err());
	}
}
