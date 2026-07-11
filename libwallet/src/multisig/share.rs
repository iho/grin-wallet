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

//! Lagrange partial keys, reconstruction, and (internal) δ-masked add-actor.
//!
//! ## Quorum ordering (C-07)
//!
//! All multiparty partials that assign a special role to "index 0" (view mix,
//! kernel offset) assume the quorum is in **canonical order**: sorted by
//! x-coordinate big-endian. Use [`canonical_quorum`] before indexing actors.
//!
//! ## Membership changes (F-03 / C-13)
//!
//! Interactive add-actor is **not part of the v1 public API**. A quorum of M
//! can exfiltrate an honest share via a sockpuppet. Membership change for v1 =
//! full re-DKG (new epoch) + on-chain sweep of old-epoch UTXOs.

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::Secp256k1;
use crate::Error;

use super::scalar::{hash_to_scalar, sk_add, sk_div, sk_mul, sk_neg, sk_sub, HashDomain};
use super::types::SecretShare;

/// One evaluation point used in Lagrange (x, y = sk(x)).
#[derive(Clone)]
pub struct ActorPoint {
	/// x-coordinate.
	pub x: SecretKey,
	/// y = sk(x).
	pub y: SecretKey,
}

impl std::fmt::Debug for ActorPoint {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ActorPoint")
			.field("x", &"[redacted]")
			.field("y", &"[redacted]")
			.finish()
	}
}

impl From<&SecretShare> for ActorPoint {
	fn from(s: &SecretShare) -> Self {
		Self {
			x: s.x.clone(),
			y: s.y.clone(),
		}
	}
}

/// Sort a quorum into **canonical order** (x-coordinate, big-endian) — C-07.
///
/// After this sort, index `0` is the **mix/offset role**: it alone applies the
/// public view-mix to coin blinds and subtracts the kernel offset. All parties
/// must use the same order or partial excesses / blinds will not sum.
///
/// Rejects empty quorums and duplicate x-coordinates.
pub fn canonical_quorum(quorum: &[ActorPoint]) -> Result<Vec<ActorPoint>, Error> {
	if quorum.is_empty() {
		return Err(Error::Multisig("empty quorum".into()));
	}
	let mut q = quorum.to_vec();
	q.sort_by(|a, b| a.x.0.cmp(&b.x.0));
	for w in q.windows(2) {
		if w[0].x.0 == w[1].x.0 {
			return Err(Error::Multisig(
				"duplicate actor x-coordinate in quorum".into(),
			));
		}
	}
	Ok(q)
}

/// Transcript bytes binding a canonical quorum (for session / offset context).
pub fn quorum_transcript(quorum: &[ActorPoint]) -> Result<Vec<u8>, Error> {
	let q = canonical_quorum(quorum)?;
	let mut out = Vec::with_capacity(4 + q.len() * 32);
	out.extend_from_slice(&(q.len() as u32).to_be_bytes());
	for p in &q {
		out.extend_from_slice(&p.x.0);
	}
	Ok(out)
}

/// Lagrange coefficient λ_j for point j in quorum, evaluated at target `x`:
/// `λ_j(x) = Π_{i≠j} (x − x_i) / (x_j − x_i)`.
pub fn lagrange_coefficient(
	secp: &Secp256k1,
	quorum_xs: &[SecretKey],
	j: usize,
	x: &SecretKey,
) -> Result<SecretKey, Error> {
	if j >= quorum_xs.len() {
		return Err(Error::Multisig("lagrange index out of range".into()));
	}
	// Start at 1
	let mut num = super::scalar::sk_from_u64(secp, 1)?;
	let mut den = super::scalar::sk_from_u64(secp, 1)?;
	let x_j = &quorum_xs[j];
	for (i, x_i) in quorum_xs.iter().enumerate() {
		if i == j {
			continue;
		}
		// num *= (x - x_i)
		let term_n = sk_sub(secp, x, x_i)?;
		num = sk_mul(secp, &num, &term_n)?;
		// den *= (x_j - x_i)
		let term_d = sk_sub(secp, x_j, x_i)?;
		den = sk_mul(secp, &den, &term_d)?;
	}
	sk_div(secp, &num, &den)
}

/// Partial key of one quorum member for evaluation at `x`:
/// `sk_{j,Q}(x) = y_j * λ_j(x)`.
pub fn partial_key_at(
	secp: &Secp256k1,
	quorum: &[ActorPoint],
	j: usize,
	x: &SecretKey,
) -> Result<SecretKey, Error> {
	let xs: Vec<SecretKey> = quorum.iter().map(|p| p.x.clone()).collect();
	let lambda = lagrange_coefficient(secp, &xs, j, x)?;
	sk_mul(secp, &quorum[j].y, &lambda)
}

/// Reconstruct sk(x) from a full quorum of shares (any threshold-sized set).
pub fn reconstruct_secret_at(
	secp: &Secp256k1,
	quorum: &[ActorPoint],
	x: &SecretKey,
) -> Result<SecretKey, Error> {
	if quorum.is_empty() {
		return Err(Error::Multisig("empty quorum".into()));
	}
	let mut acc = partial_key_at(secp, quorum, 0, x)?;
	for j in 1..quorum.len() {
		let p = partial_key_at(secp, quorum, j, x)?;
		acc = sk_add(secp, &acc, &p)?;
	}
	Ok(acc)
}

/// δ(i,j,context) = Hash_s(shared_secret || context) * (x_i − x_j)
///
/// `shared_secret` should be a DH result (or test stand-in) known only to i,j.
pub fn delta_mask(
	secp: &Secp256k1,
	shared_secret: &[u8],
	context: &[u8],
	x_i: &SecretKey,
	x_j: &SecretKey,
) -> Result<SecretKey, Error> {
	let mut msg = shared_secret.to_vec();
	msg.push(0xff);
	msg.extend_from_slice(context);
	let h = hash_to_scalar(secp, HashDomain::Delta, &msg)?;
	let dx = sk_sub(secp, x_i, x_j)?;
	sk_mul(secp, &h, &dx)
}

/// Masked share for add-actor from quorum member i (tests only; C-13).
///
/// **Not part of the v1 public API (F-03).** Prefer re-DKG + sweep.
///
/// `sk_share_i = sk_{i,Q}(x_new) + sum_{j≠i} δ(i,j,ctx)`.
/// `pairwise_secrets[j]` is the DH/shared secret between i and quorum[j]
/// (ignored at j == i).
#[cfg(test)]
pub(crate) fn add_actor_masked_share(
	secp: &Secp256k1,
	quorum: &[ActorPoint],
	i: usize,
	x_new: &SecretKey,
	context: &[u8],
	pairwise_secrets: &[Vec<u8>],
) -> Result<SecretKey, Error> {
	if pairwise_secrets.len() != quorum.len() {
		return Err(Error::Multisig(
			"pairwise_secrets length must match quorum".into(),
		));
	}
	let mut share = partial_key_at(secp, quorum, i, x_new)?;
	for j in 0..quorum.len() {
		if j == i {
			continue;
		}
		let d = delta_mask(
			secp,
			&pairwise_secrets[j],
			context,
			&quorum[i].x,
			&quorum[j].x,
		)?;
		share = sk_add(secp, &share, &d)?;
	}
	Ok(share)
}

/// Sum masked shares; δ terms cancel if all pairs used consistent secrets.
pub fn unmask_sum(secp: &Secp256k1, masked_shares: &[SecretKey]) -> Result<SecretKey, Error> {
	if masked_shares.is_empty() {
		return Err(Error::Multisig("no masked shares".into()));
	}
	let mut acc = masked_shares[0].clone();
	for s in masked_shares.iter().skip(1) {
		acc = sk_add(secp, &acc, s)?;
	}
	Ok(acc)
}

/// Negate helper exported for tests.
pub fn sk_neg_export(secp: &Secp256k1, a: &SecretKey) -> Result<SecretKey, Error> {
	sk_neg(secp, a)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::poly::{eval_public_poly, verify_share};
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	#[test]
	fn lagrange_reconstructs_at_new_point() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		// degree 1 => threshold 2, use 2-of-2 for simple reconstruction
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();

		// Take first share of each actor (shares_per_actor = 1)
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let q = canonical_quorum(&q).unwrap();

		// Evaluate at a fresh x
		let x_new = crate::multisig::scalar::hash_to_scalar(
			&secp,
			crate::multisig::scalar::HashDomain::Coin,
			b"test-point",
		)
		.unwrap();

		let y = reconstruct_secret_at(&secp, &q, &x_new).unwrap();
		assert!(verify_share(&secp, &states[0].config.public_poly, &x_new, &y).unwrap());

		// Public eval matches
		let p = eval_public_poly(&secp, &states[0].config.public_poly, &x_new).unwrap();
		let g_y = crate::grin_util::secp::key::PublicKey::from_secret_key(&secp, &y).unwrap();
		assert_eq!(p, g_y);
	}

	#[test]
	fn delta_masks_cancel() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let q = canonical_quorum(&q).unwrap();
		let x_new = crate::multisig::scalar::sk_from_u64(&secp, 99).unwrap();
		let ctx = b"add-actor-ctx";

		// Symmetric pairwise secrets (aligned with canonical order)
		let sec01 = b"shared-0-1".to_vec();
		let secrets_for_0 = vec![vec![], sec01.clone()];
		let secrets_for_1 = vec![sec01, vec![]];

		let m0 = add_actor_masked_share(&secp, &q, 0, &x_new, ctx, &secrets_for_0).unwrap();
		let m1 = add_actor_masked_share(&secp, &q, 1, &x_new, ctx, &secrets_for_1).unwrap();
		let y_new = unmask_sum(&secp, &[m0, m1]).unwrap();
		assert!(verify_share(&secp, &states[0].config.public_poly, &x_new, &y_new).unwrap());
	}

	#[test]
	fn canonical_quorum_sorts_by_x() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 3).unwrap();
		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let mut q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		// Reverse order, then canonicalize — result must be sorted and stable.
		q.reverse();
		let c1 = canonical_quorum(&q).unwrap();
		let c2 = canonical_quorum(&c1).unwrap();
		assert_eq!(c1.len(), 3);
		for w in c1.windows(2) {
			assert!(w[0].x.0 <= w[1].x.0);
		}
		assert_eq!(c1[0].x.0, c2[0].x.0);
		assert_eq!(c1[1].x.0, c2[1].x.0);
		assert_eq!(c1[2].x.0, c2[2].x.0);
	}
}
