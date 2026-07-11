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

//! Joint Feldman DKG (simplified, in-process friendly).
//!
//! Each of N dealers contributes a random polynomial of degree `t-1`
//! (threshold t, possibly raised via multi-share). The joint secret
//! polynomial is the sum of dealer polys. Shares are evaluations at each
//! actor's x-coordinates.
//!
//! **Security notes (see crypto review):**
//! - PoP is required on every coefficient commitment.
//! - Coefficient count must equal `degree + 1` (reject threshold inflation).
//! - Joint-Feldman can be biased by last movers; acceptable for v0 research.
//! - Production share delivery must encrypt partials and apply δ-masks.

use crate::grin_core::libtx::aggsig;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::{Message, Secp256k1, Signature};
use crate::Error;
use sha2::{Digest, Sha256};

use super::poly::{eval_secret_poly, PublicPoly, SecretPoly};
use super::scalar::{hash_to_scalar, sk_add, HashDomain};
use super::types::{
	ActorId, CeremonyId, MultisigConfig, MultisigWalletState, SecretShare, ThresholdParams,
};

/// Schnorr proof-of-possession for one coefficient commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopProof {
	/// Coefficient index.
	pub coeff_index: usize,
	/// DER-encoded signature bytes.
	pub sig: Vec<u8>,
}

/// One dealer's public contribution to DKG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealerContribution {
	/// Dealer actor identity.
	pub actor: ActorId,
	/// Commitments C_m = G * r_m (compressed).
	pub commitments: PublicPoly,
	/// PoP for each commitment.
	pub pops: Vec<PopProof>,
}

/// Local dealer state (secret polynomials — never leave the host).
pub struct DealerSecrets {
	/// This dealer's identity.
	pub actor: ActorId,
	/// Secret contribution polynomial.
	pub poly: SecretPoly,
}

fn pop_domain_tag() -> &'static [u8] {
	b"grin-msig/pop"
}

/// Build the PoP message for coefficient commitment.
fn pop_message(
	ceremony: &CeremonyId,
	actor: &ActorId,
	coeff_index: usize,
	commitment: &PublicKey,
	secp: &Secp256k1,
) -> Result<Message, Error> {
	let mut hasher = Sha256::new();
	hasher.update(pop_domain_tag());
	hasher.update(ceremony.0.as_bytes());
	hasher.update(&actor.id);
	hasher.update(&(coeff_index as u32).to_be_bytes());
	hasher.update(&commitment.serialize_vec(secp, true));
	let digest = hasher.finalize();
	Ok(Message::from_slice(&digest)?)
}

/// Generate a dealer's secret poly + public contribution with PoPs.
pub fn generate_dealer_contribution(
	secp: &Secp256k1,
	ceremony: &CeremonyId,
	actor: ActorId,
	params: &ThresholdParams,
) -> Result<(DealerSecrets, DealerContribution), Error> {
	let degree = params.effective_degree();
	let poly = SecretPoly::random(secp, degree)?;
	let commits = poly.commitments(secp)?;

	if commits.len() != params.num_coefficients() {
		return Err(Error::Multisig("internal coeff count mismatch".into()));
	}

	let mut pops = Vec::with_capacity(commits.len());
	for (m, c) in commits.iter().enumerate() {
		let msg = pop_message(ceremony, &actor, m, c, secp)?;
		let sk = &poly.coeffs[m];
		let sig = aggsig::sign_single(secp, &msg, sk, None, None)?;
		pops.push(PopProof {
			coeff_index: m,
			sig: sig.serialize_der(secp).to_vec(),
		});
	}

	let contribution = DealerContribution {
		actor: actor.clone(),
		commitments: PublicPoly::from_pubkeys(secp, &commits),
		pops,
	};
	Ok((DealerSecrets { actor, poly }, contribution))
}

/// Verify all PoPs on a dealer contribution.
pub fn verify_pop(
	secp: &Secp256k1,
	ceremony: &CeremonyId,
	contrib: &DealerContribution,
	expected_num_coeffs: usize,
) -> Result<(), Error> {
	if contrib.commitments.coefficients.len() != expected_num_coeffs {
		return Err(Error::Multisig(format!(
			"dealer {} published {} coeffs, expected {} (threshold inflation?)",
			contrib.actor.label,
			contrib.commitments.coefficients.len(),
			expected_num_coeffs
		)));
	}
	if contrib.pops.len() != expected_num_coeffs {
		return Err(Error::Multisig("missing PoP for some coefficients".into()));
	}
	for pop in &contrib.pops {
		let pk = contrib
			.commitments
			.coefficient_pubkey(secp, pop.coeff_index)?;
		let msg = pop_message(ceremony, &contrib.actor, pop.coeff_index, &pk, secp)?;
		let sig = Signature::from_der(secp, &pop.sig)
			.map_err(|e| Error::Multisig(format!("bad PoP der: {:?}", e)))?;
		let ok = aggsig::verify_single(secp, &sig, &msg, None, &pk, None, false);
		if !ok {
			return Err(Error::Multisig(format!(
				"PoP failed for actor {} coeff {}",
				contrib.actor.label, pop.coeff_index
			)));
		}
	}
	Ok(())
}

/// Dealer i computes unmasked partial share for recipient's x:
/// `sum_m r_{i,m} * x^m`.
pub fn dealer_partial_share(
	secp: &Secp256k1,
	secrets: &DealerSecrets,
	recipient_x: &SecretKey,
) -> Result<SecretKey, Error> {
	eval_secret_poly(secp, &secrets.poly, recipient_x)
}

/// Sum partial shares from all dealers into final share y = sk(x).
pub fn assemble_share(secp: &Secp256k1, partials: &[SecretKey]) -> Result<SecretKey, Error> {
	if partials.is_empty() {
		return Err(Error::Multisig("no partials to assemble".into()));
	}
	let mut acc = partials[0].clone();
	for p in partials.iter().skip(1) {
		acc = sk_add(secp, &acc, p)?;
	}
	Ok(acc)
}

/// Aggregate all dealer public contributions into the joint public polynomial.
pub fn aggregate_public_poly(
	secp: &Secp256k1,
	contributions: &[DealerContribution],
) -> Result<PublicPoly, Error> {
	if contributions.is_empty() {
		return Err(Error::Multisig("no contributions".into()));
	}
	let mut acc = contributions[0].commitments.clone();
	for c in contributions.iter().skip(1) {
		acc = acc.add(secp, &c.commitments)?;
	}
	Ok(acc)
}

/// Run a complete in-process DKG among the given actors (tests / local sim).
///
/// Returns one [`MultisigWalletState`] per actor. Share delivery is unmasked
/// here (same process); production must encrypt partials and apply δ-masks.
pub fn run_dkg_local(
	secp: &Secp256k1,
	ceremony: CeremonyId,
	params: ThresholdParams,
	actors: Vec<ActorId>,
) -> Result<Vec<MultisigWalletState>, Error> {
	if actors.len() != params.total_actors {
		return Err(Error::Multisig("actors len != total_actors".into()));
	}

	let mut secrets = Vec::new();
	let mut contribs = Vec::new();
	for a in &actors {
		let (s, c) = generate_dealer_contribution(secp, &ceremony, a.clone(), &params)?;
		verify_pop(secp, &ceremony, &c, params.num_coefficients())?;
		secrets.push(s);
		contribs.push(c);
	}

	let public_poly = aggregate_public_poly(secp, &contribs)?;

	let config = MultisigConfig {
		ceremony_id: ceremony,
		params: params.clone(),
		actors: actors.clone(),
		public_poly: public_poly.clone(),
	};
	config.validate()?;

	let mut states = Vec::new();
	for actor in &actors {
		let mut shares = Vec::new();
		for share_index in 0..params.shares_per_actor {
			let x = actor.x_coordinate_share(secp, share_index)?;
			let mut partials = Vec::new();
			for d in &secrets {
				partials.push(dealer_partial_share(secp, d, &x)?);
			}
			let y = assemble_share(secp, &partials)?;
			if !super::poly::verify_share(secp, &public_poly, &x, &y)? {
				return Err(Error::Multisig(format!(
					"share verification failed for {}",
					actor.label
				)));
			}
			shares.push(SecretShare {
				share_index,
				x,
				y,
			});
		}
		states.push(MultisigWalletState {
			config: config.clone(),
			my_actor: actor.clone(),
			shares,
		});
	}
	Ok(states)
}

/// Context hash binding a ceremony (for δ and similar).
pub fn ceremony_context_scalar(
	secp: &Secp256k1,
	ceremony: &CeremonyId,
	extra: &[u8],
) -> Result<SecretKey, Error> {
	let mut msg = ceremony.0.as_bytes().to_vec();
	msg.extend_from_slice(extra);
	hash_to_scalar(secp, HashDomain::Context, &msg)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};

	#[test]
	fn dkg_2_of_3() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let k = ThresholdParams::recommended_shares_per_actor(2);
		let params = ThresholdParams::with_shares_per_actor(2, 3, k).unwrap();
		assert!(params.effective_degree() + 1 >= 4);

		let actors: Vec<_> = (0..3).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		assert_eq!(states.len(), 3);
		assert_eq!(
			states[0].config.public_poly.coefficients,
			states[1].config.public_poly.coefficients
		);
	}

	#[test]
	fn reject_wrong_coeff_count() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(2, 2).unwrap();
		let ceremony = CeremonyId::new();
		let actor = ActorId::from_index(0);
		let (_s, mut c) =
			generate_dealer_contribution(&secp, &ceremony, actor, &params).unwrap();
		// Simulate threshold inflation: extra bogus commitment
		c.commitments.coefficients.push(c.commitments.coefficients[0].clone());
		let err = verify_pop(&secp, &ceremony, &c, params.num_coefficients()).unwrap_err();
		match err {
			Error::Multisig(msg) => assert!(msg.contains("threshold inflation") || msg.contains("coeffs")),
			_ => panic!("unexpected error"),
		}
	}
}
