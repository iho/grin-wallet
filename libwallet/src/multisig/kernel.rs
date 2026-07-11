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

//! Threshold multiparty kernel signing for multisig wallets — **FROST**
//! (Komlo–Goldberg two-round threshold Schnorr) over Grin's kernel excess.
//!
//! Each quorum member holds a Lagrange partial of the kernel excess secret
//! (`partial_excess_for_actor`); the partials sum to the full excess key, whose
//! public form `X = Σ X_j` is the kernel's excess pubkey.
//!
//! ## Protocol (FROST, 2 rounds)
//!
//! 1. **Commit** — each actor `j` samples **two** nonces `(d_j, e_j)` and
//!    broadcasts `(D_j, E_j, X_j)` = `(d_j·G, e_j·G, X_j)` ([`kernel_round1`],
//!    [`SigningCommitment`]).
//! 2. **Sign** — everyone derives a per-actor **binding factor**
//!    `ρ_j = H(session ‖ offset ‖ all commitments ‖ j)` ([`binding_factor`]),
//!    forms the group nonce `R = Σ (D_j + ρ_j·E_j)` and excess `X = Σ X_j`
//!    ([`aggregate_frost`]), and each actor signs with its effective nonce
//!    `k_j = d_j + ρ_j·e_j` ([`kernel_partial_sign`]).
//! 3. **Aggregate** — `add_signatures` → the final Schnorr signature `(R, z)`,
//!    verified as an ordinary Grin kernel signature over `X`.
//!
//! The binding factor is what gives FROST its concurrent-session security
//! (resistance to the Drijvers/Wagner ROS attack that a naive
//! sum-of-single-nonces Schnorr is vulnerable to). Because the aggregate nonce
//! `R` and each effective nonce `k_j` satisfy `Σ G·k_j = R` exactly as in the
//! single-nonce case, this composes with Grin's proven `aggsig` signing and
//! `TxKernel::verify()` verification unchanged — only the nonce each actor uses
//! changes.
//!
//! ## Security notes
//!
//! - Rogue-key protection: every actor's claimed `X_j` is checked against the
//!   public polynomial before signing ([`verify_partial_excess`]).
//! - Nonces are single-use per session; never reuse `(d_j, e_j)` across
//!   sessions (a fresh pair is drawn each round).
//! - Partial excess keys are session-specific (Lagrange over the active
//!   quorum); do not reuse across different quorums without recomputing.

use crate::grin_core::core::transaction::KernelFeatures;
use crate::grin_core::core::FeeFields;
use crate::grin_core::libtx::aggsig;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::{Message, Secp256k1, Signature};
use crate::Error;
use std::convert::TryFrom;

use super::coin::{
	coin_partial_poly_key, coin_x, tx_offset, view_mix, view_seed_from_public_poly, CoinId,
};
use super::poly::{eval_public_poly, PublicPoly};
use super::scalar::{hash_to_scalar, sk_add, sk_from_u64, sk_mul, sk_neg, sk_sub, HashDomain};
use super::share::{canonical_quorum, lagrange_coefficient, quorum_transcript, ActorPoint};

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

/// Round-1 public commitment broadcast by one actor (FROST).
#[derive(Clone, Debug, PartialEq)]
pub struct SigningCommitment {
	/// Hiding-nonce commitment `D_j = d_j · G`.
	pub pub_d: PublicKey,
	/// Binding-nonce commitment `E_j = e_j · G`.
	pub pub_e: PublicKey,
	/// Public partial excess `X_j = x_j · G`.
	pub pub_excess: PublicKey,
}

/// Local secrets for one actor during FROST kernel signing.
#[derive(Clone)]
pub struct ActorKernelSecrets {
	/// Partial excess secret for this actor.
	pub partial_excess: SecretKey,
	/// Hiding nonce `d_j` (secret).
	pub d: SecretKey,
	/// Binding nonce `e_j` (secret).
	pub e: SecretKey,
	/// This actor's public round-1 commitment.
	pub commitment: SigningCommitment,
}

impl std::fmt::Debug for ActorKernelSecrets {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ActorKernelSecrets")
			.field("partial_excess", &"[redacted]")
			.field("d", &"[redacted]")
			.field("e", &"[redacted]")
			.field("commitment", &self.commitment)
			.finish()
	}
}

/// Aggregated public values after the commitment round.
#[derive(Clone, Debug)]
pub struct AggregatedKernelPubs {
	/// Group nonce `R = Σ (D_j + ρ_j · E_j)`
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
		FeeFields::try_from(fee)
			.map_err(|e| Error::Multisig(format!("invalid fee fields: {:?}", e)))?
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

/// Partial excess for actor `j` (index into the **canonical** quorum, C-07):
/// `Σ partial(output) − Σ partial(input) − [offset if j==0]`.
///
/// Matches Grin balance: `excess + offset = out_blinds − in_blinds`.
/// Each coin partial is the Lagrange share of `sk(x_coin)`; the view mix for
/// each coin and the offset subtraction apply only to **canonical index 0**
/// (smallest x-coordinate).
pub fn partial_excess_for_actor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<SecretKey, Error> {
	let quorum = canonical_quorum(quorum)?;
	if j >= quorum.len() {
		return Err(Error::Multisig("actor index out of range".into()));
	}
	let seed = view_seed_from_public_poly(secp, public_poly)?;

	// Start at "zero" via canceling self-add; use first term carefully
	let mut acc: Option<SecretKey> = None;

	let add_coin =
		|acc: &mut Option<SecretKey>, coin: &CoinId, sign_positive: bool| -> Result<(), Error> {
			let mut part = coin_partial_poly_key(secp, &quorum, j, coin)?;
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

	let mut excess =
		acc.ok_or_else(|| Error::Multisig("kernel session has no inputs or outputs".into()))?;

	// Subtract offset once (actor 0): excess = (out - in) - offset
	if j == 0 {
		excess = sk_sub(secp, &excess, &session.offset)?;
	}
	Ok(excess)
}

/// Expected **public** partial excess for actor `j`, computed purely from the
/// public polynomial and session (C-05).
///
/// This is the group-element analog of [`partial_excess_for_actor`]:
/// `X_j = Σ_out λ_j(x)·P(x_j) − Σ_in λ_j(x)·P(x_j) [+ mix·G terms − offset·G, on actor 0]`.
/// Because `P(x_j)` is fixed by the DKG public poly, an actor cannot claim a
/// partial excess pubkey it did not honestly derive — this is what stops
/// rogue-key manipulation of the aggregate excess (a valid signature over a
/// forged `excess_sum` would otherwise only be caught by the transaction
/// failing to balance, i.e. detection-by-DoS).
pub fn expected_pub_excess_for_actor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<PublicKey, Error> {
	let quorum = canonical_quorum(quorum)?;
	expected_pub_excess_for_actor_canonical(secp, public_poly, &quorum, j, session)
}

fn expected_pub_excess_for_actor_canonical(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<PublicKey, Error> {
	if j >= quorum.len() {
		return Err(Error::Multisig("actor index out of range".into()));
	}
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let x_j = &quorum[j].x;
	let p_xj = eval_public_poly(secp, public_poly, x_j)?; // P(x_j) = G·y_j
	let xs: Vec<SecretKey> = quorum.iter().map(|p| p.x.clone()).collect();
	let minus_one = sk_neg(secp, &sk_from_u64(secp, 1)?)?;

	let mut pos: Vec<PublicKey> = Vec::new();
	let mut neg: Vec<PublicKey> = Vec::new();

	let mut add_coin = |coin: &CoinId, positive: bool| -> Result<(), Error> {
		let x_coin = coin_x(secp, coin)?;
		let lambda = lagrange_coefficient(secp, &xs, j, &x_coin)?;
		let mut term = p_xj.clone();
		term.mul_assign(secp, &lambda)?;
		if positive {
			pos.push(term);
		} else {
			neg.push(term);
		}
		if j == 0 {
			let mix = view_mix(secp, &seed, &x_coin)?;
			let g_mix = PublicKey::from_secret_key(secp, &mix)?;
			if positive {
				pos.push(g_mix);
			} else {
				neg.push(g_mix);
			}
		}
		Ok(())
	};

	for c in &session.outputs {
		add_coin(c, true)?;
	}
	for c in &session.inputs {
		add_coin(c, false)?;
	}
	if j == 0 {
		// − offset·G
		neg.push(PublicKey::from_secret_key(secp, &session.offset)?);
	}

	let mut terms: Vec<PublicKey> = pos;
	for mut n in neg {
		n.mul_assign(secp, &minus_one)?;
		terms.push(n);
	}
	let refs: Vec<&PublicKey> = terms.iter().collect();
	PublicKey::from_combination(secp, refs)
		.map_err(|e| Error::Multisig(format!("expected excess combine: {}", e)))
}

/// Verify a claimed partial excess pubkey against the public-poly prediction.
pub fn verify_partial_excess(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
	claimed: &PublicKey,
) -> Result<(), Error> {
	let expected = expected_pub_excess_for_actor(secp, public_poly, quorum, j, session)?;
	if expected != *claimed {
		return Err(Error::Multisig(format!(
			"partial excess pubkey mismatch for actor {} (rogue key?)",
			j
		)));
	}
	Ok(())
}

/// Round 1: sample two FROST nonces, derive the partial excess, and emit the
/// public commitment `(D_j, E_j, X_j)`.
pub fn kernel_round1(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	j: usize,
	session: &KernelSession,
) -> Result<ActorKernelSecrets, Error> {
	let partial_excess = partial_excess_for_actor(secp, public_poly, quorum, j, session)?;
	let d = aggsig::create_secnonce(secp).map_err(|e| Error::Multisig(format!("secnonce d: {}", e)))?;
	let e = aggsig::create_secnonce(secp).map_err(|e| Error::Multisig(format!("secnonce e: {}", e)))?;
	let pub_d = PublicKey::from_secret_key(secp, &d)?;
	let pub_e = PublicKey::from_secret_key(secp, &e)?;
	let pub_excess = PublicKey::from_secret_key(secp, &partial_excess)?;
	Ok(ActorKernelSecrets {
		partial_excess,
		d,
		e,
		commitment: SigningCommitment {
			pub_d,
			pub_e,
			pub_excess,
		},
	})
}

/// FROST binding factor `ρ` for the actor at position `idx` in the ordered
/// commitment list.
///
/// Binds the whole signing context — session id, the deterministic offset
/// (which fixes inputs/outputs/fee), the full ordered commitment list, and the
/// actor position — so no participant can grind nonces to force a colliding
/// group nonce (Drijvers/Wagner ROS resistance).
pub fn binding_factor(
	secp: &Secp256k1,
	session: &KernelSession,
	commitments: &[SigningCommitment],
	idx: usize,
) -> Result<SecretKey, Error> {
	let mut m = Vec::new();
	m.extend_from_slice(&(session.session_id.len() as u32).to_be_bytes());
	m.extend_from_slice(&session.session_id);
	m.extend_from_slice(&session.offset.0);
	m.extend_from_slice(&(commitments.len() as u32).to_be_bytes());
	for c in commitments {
		m.extend_from_slice(&c.pub_d.serialize_vec(secp, true));
		m.extend_from_slice(&c.pub_e.serialize_vec(secp, true));
		m.extend_from_slice(&c.pub_excess.serialize_vec(secp, true));
	}
	m.extend_from_slice(&(idx as u32).to_be_bytes());
	hash_to_scalar(secp, HashDomain::Frost, &m)
}

/// Aggregate the group nonce `R = Σ (D_j + ρ_j·E_j)` and excess `X = Σ X_j`
/// from the ordered commitment list.
pub fn aggregate_frost(
	secp: &Secp256k1,
	session: &KernelSession,
	commitments: &[SigningCommitment],
) -> Result<AggregatedKernelPubs, Error> {
	if commitments.is_empty() {
		return Err(Error::Multisig("no signing commitments".into()));
	}
	let mut nonce_terms: Vec<PublicKey> = Vec::with_capacity(commitments.len());
	for (idx, c) in commitments.iter().enumerate() {
		let rho = binding_factor(secp, session, commitments, idx)?;
		let mut rho_e = c.pub_e.clone();
		rho_e.mul_assign(secp, &rho)?;
		let r_j = PublicKey::from_combination(secp, vec![&c.pub_d, &rho_e])?;
		nonce_terms.push(r_j);
	}
	let nonce_refs: Vec<&PublicKey> = nonce_terms.iter().collect();
	let excess_refs: Vec<&PublicKey> = commitments.iter().map(|c| &c.pub_excess).collect();
	Ok(AggregatedKernelPubs {
		nonce_sum: PublicKey::from_combination(secp, nonce_refs)?,
		excess_sum: PublicKey::from_combination(secp, excess_refs)?,
	})
}

/// Produce a FROST partial signature for the actor at `my_index`.
///
/// The effective nonce is `k_j = d_j + ρ_j·e_j`, so `k_j·G = D_j + ρ_j·E_j`
/// and the partials sum consistently to the group nonce `R`.
pub fn kernel_partial_sign(
	secp: &Secp256k1,
	secrets: &ActorKernelSecrets,
	commitments: &[SigningCommitment],
	my_index: usize,
	agg: &AggregatedKernelPubs,
	session: &KernelSession,
) -> Result<Signature, Error> {
	let rho = binding_factor(secp, session, commitments, my_index)?;
	let rho_e = sk_mul(secp, &rho, &secrets.e)?;
	let k_j = sk_add(secp, &secrets.d, &rho_e)?;
	let msg = kernel_message(&session.features)?;
	aggsig::calculate_partial_sig(
		secp,
		&secrets.partial_excess,
		&k_j,
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
	aggsig::verify_completed_sig(secp, sig, &agg.excess_sum, Some(&agg.excess_sum), &msg)
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
	// C-07: fix quorum order and bind it into the session tag / offset context.
	let quorum = canonical_quorum(quorum)?;
	let mut sid = session_id.as_ref().to_vec();
	sid.extend_from_slice(b"|quorum|");
	sid.extend_from_slice(&quorum_transcript(&quorum)?);

	let features = plain_features(fee)?;
	let session = create_kernel_session(secp, public_poly, &sid, features, inputs, outputs)?;

	// Round 1: each actor draws two nonces and publishes its commitment. Every
	// claimed partial excess is checked against the public polynomial before use
	// (rogue-key guard, C-05). Indices are canonical (mix/offset role = 0).
	let mut secrets = Vec::new();
	let mut commitments = Vec::new();
	for j in 0..quorum.len() {
		let sec = kernel_round1(secp, public_poly, &quorum, j, &session)?;
		verify_partial_excess(
			secp,
			public_poly,
			&quorum,
			j,
			&session,
			&sec.commitment.pub_excess,
		)?;
		commitments.push(sec.commitment.clone());
		secrets.push(sec);
	}

	// Round 2: derive the group nonce with binding factors, then sign.
	let agg = aggregate_frost(secp, &session, &commitments)?;
	let mut partials = Vec::new();
	for (j, sec) in secrets.iter().enumerate() {
		let ps = kernel_partial_sign(secp, sec, &commitments, j, &agg, &session)?;
		verify_kernel_partial(secp, &ps, &sec.commitment.pub_excess, &agg, &session)?;
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
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(secp, CeremonyId::new(), params, actors).unwrap();
		let q = canonical_quorum(&[
			ActorPoint::from(&states[0].shares[0]),
			ActorPoint::from(&states[1].shares[0]),
		])
		.unwrap();
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
		let (sig, agg, session) =
			run_kernel_sign_local(&secp, &pp, &q, b"test-session-1", fee, inputs, outputs).unwrap();
		verify_kernel_sig(&secp, &sig, &agg, &session).unwrap();
	}

	#[test]
	fn reversed_quorum_same_excess() {
		// C-07: reordering the quorum must not change the aggregated excess.
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, mut q) = setup_2of3(&secp);
		let inputs = vec![CoinId::new(1, 5000)];
		let outputs = vec![CoinId::new(2, 4000)];
		let fee = 1000;
		let (_s1, agg1, _) =
			run_kernel_sign_local(&secp, &pp, &q, b"ord", fee, inputs.clone(), outputs.clone())
				.unwrap();
		q.reverse();
		let (_s2, agg2, _) =
			run_kernel_sign_local(&secp, &pp, &q, b"ord", fee, inputs, outputs).unwrap();
		assert_eq!(agg1.excess_sum, agg2.excess_sum);
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
	fn binding_factor_binds_context() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		let session = create_kernel_session(
			&secp,
			&pp,
			b"bf",
			plain_features(5).unwrap(),
			vec![CoinId::new(1, 100)],
			vec![CoinId::new(2, 95)],
		)
		.unwrap();
		let c0 = kernel_round1(&secp, &pp, &q, 0, &session).unwrap().commitment;
		let c1 = kernel_round1(&secp, &pp, &q, 1, &session).unwrap().commitment;
		let commitments = vec![c0, c1];
		let r0 = binding_factor(&secp, &session, &commitments, 0).unwrap();
		let r1 = binding_factor(&secp, &session, &commitments, 1).unwrap();
		// Per-actor binding factors differ, and are deterministic.
		assert_ne!(r0.0, r1.0);
		let r0b = binding_factor(&secp, &session, &commitments, 0).unwrap();
		assert_eq!(r0.0, r0b.0);
		// Reordering the commitment list changes the binding factor (binds the set).
		let reordered = vec![commitments[1].clone(), commitments[0].clone()];
		let r0r = binding_factor(&secp, &session, &reordered, 0).unwrap();
		assert_ne!(r0.0, r0r.0);
	}

	#[test]
	fn partial_excess_matches_public_poly() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		let session = create_kernel_session(
			&secp,
			&pp,
			b"pe",
			plain_features(10).unwrap(),
			vec![CoinId::new(1, 5000)],
			vec![CoinId::new(2, 4990)],
		)
		.unwrap();
		for j in 0..q.len() {
			let sk = partial_excess_for_actor(&secp, &pp, &q, j, &session).unwrap();
			let pub_excess = PublicKey::from_secret_key(&secp, &sk).unwrap();
			// Honest partial excess matches the public-poly prediction.
			verify_partial_excess(&secp, &pp, &q, j, &session, &pub_excess).unwrap();
			// A tampered excess pubkey is rejected.
			let bad_sk = SecretKey::new(&secp, &mut rand::thread_rng());
			let bad = PublicKey::from_secret_key(&secp, &bad_sk).unwrap();
			assert!(verify_partial_excess(&secp, &pp, &q, j, &session, &bad).is_err());
		}
	}

	#[test]
	fn three_of_three_kernel() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(3, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<_> = canonical_quorum(
			&states
				.iter()
				.map(|s| ActorPoint::from(&s.shares[0]))
				.collect::<Vec<_>>(),
		)
		.unwrap();
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
		let sec0 = kernel_round1(&secp, &pp, &q, 0, &session).unwrap();
		let sec1 = kernel_round1(&secp, &pp, &q, 1, &session).unwrap();
		let commitments = vec![sec0.commitment.clone(), sec1.commitment.clone()];
		let agg = aggregate_frost(&secp, &session, &commitments).unwrap();
		let good = kernel_partial_sign(&secp, &sec0, &commitments, 0, &agg, &session).unwrap();
		// The partial verifies against its own excess...
		verify_kernel_partial(&secp, &good, &sec0.commitment.pub_excess, &agg, &session).unwrap();
		// ...but not against another actor's excess pubkey.
		assert!(
			verify_kernel_partial(&secp, &good, &sec1.commitment.pub_excess, &agg, &session).is_err()
		);
	}

	#[test]
	fn frost_signature_verifies_as_kernel() {
		use crate::grin_core::global;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q) = setup_2of3(&secp);
		let (sig, agg, session) = run_kernel_sign_local(
			&secp,
			&pp,
			&q,
			b"frost-sess",
			1_000,
			vec![CoinId::new(1, 1_000_000)],
			vec![CoinId::new(2, 999_000)],
		)
		.unwrap();
		// The aggregated FROST signature verifies under Grin's own kernel check.
		let kernel = crate::grin_core::core::TxKernel {
			features: session.features.clone(),
			excess: excess_commitment(&secp, &agg).unwrap(),
			excess_sig: sig,
		};
		kernel.verify().unwrap();
	}
}
