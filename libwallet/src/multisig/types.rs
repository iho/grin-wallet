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

//! Multisig configuration and persistent actor state types.

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::Secp256k1;
use crate::slatepack::SlatepackAddress;
use crate::Error;
use std::convert::TryFrom;
use uuid::Uuid;

use super::poly::PublicPoly;
use super::scalar::{hash_to_scalar, HashDomain};

/// Recommended minimum polynomial degree for PTE/Wagner resistance when the
/// logical signing threshold is small. Callers may raise degree by issuing
/// multiple shares per actor (see [`ThresholdParams::effective_degree`]).
pub const MIN_SHARES_FOR_DEGREE: usize = 4;

/// Threshold parameters for an M-of-N multisig.
///
/// Cryptographic polynomial degree is always `threshold - 1` for a single
/// share per actor. When `shares_per_actor > 1`, effective degree becomes
/// `threshold * shares_per_actor - 1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParams {
	/// Minimum number of *actors* required to sign (M).
	pub threshold: usize,
	/// Total number of actors (N).
	pub total_actors: usize,
	/// Number of polynomial shares each actor holds (default 1).
	/// Used to raise degree when M is small.
	pub shares_per_actor: usize,
}

impl ThresholdParams {
	/// Create params with one share per actor (enforces the PTE degree floor, C-11).
	///
	/// For M < [`MIN_SHARES_FOR_DEGREE`], use
	/// [`with_shares_per_actor`] with [`recommended_shares_per_actor`], or
	/// [`new_allow_low_degree`] for tests only.
	pub fn new(threshold: usize, total_actors: usize) -> Result<Self, Error> {
		Self::with_shares_per_actor(threshold, total_actors, 1)
	}

	/// Create params with one share per actor **without** the PTE degree floor.
	///
	/// **Tests / local-sim only.** Production ceremonies must satisfy
	/// `effective_degree + 1 ≥ MIN_SHARES_FOR_DEGREE` (C-11 / F-08).
	pub fn new_allow_low_degree(threshold: usize, total_actors: usize) -> Result<Self, Error> {
		Self::with_shares_per_actor_allow_low_degree(threshold, total_actors, 1)
	}

	/// Create params, optionally with multiple shares per actor.
	///
	/// Rejects configurations where `num_coefficients() < MIN_SHARES_FOR_DEGREE`
	/// (C-11). Prefer [`recommended_shares_per_actor`] when M is small.
	pub fn with_shares_per_actor(
		threshold: usize,
		total_actors: usize,
		shares_per_actor: usize,
	) -> Result<Self, Error> {
		let p = Self::with_shares_per_actor_allow_low_degree(
			threshold,
			total_actors,
			shares_per_actor,
		)?;
		if p.num_coefficients() < MIN_SHARES_FOR_DEGREE {
			return Err(Error::Multisig(format!(
				"polynomial degree too low for production (num_coefficients={} < MIN_SHARES_FOR_DEGREE={}); \
				 raise shares_per_actor to {} (see ThresholdParams::recommended_shares_per_actor), \
				 or use with_shares_per_actor_allow_low_degree for tests only",
				p.num_coefficients(),
				MIN_SHARES_FOR_DEGREE,
				Self::recommended_shares_per_actor(threshold)
			)));
		}
		Ok(p)
	}

	/// Like [`with_shares_per_actor`] but skips the PTE degree floor (C-11).
	///
	/// **Tests / local-sim only** — not for ceremonies that hold real value.
	pub fn with_shares_per_actor_allow_low_degree(
		threshold: usize,
		total_actors: usize,
		shares_per_actor: usize,
	) -> Result<Self, Error> {
		if threshold == 0 || total_actors == 0 {
			return Err(Error::Multisig(
				"threshold and total_actors must be > 0".into(),
			));
		}
		if threshold > total_actors {
			return Err(Error::Multisig(
				"threshold cannot exceed total_actors".into(),
			));
		}
		if shares_per_actor == 0 {
			return Err(Error::Multisig("shares_per_actor must be > 0".into()));
		}
		Ok(Self {
			threshold,
			total_actors,
			shares_per_actor,
		})
	}

	/// Number of secret-polynomial coefficients (= degree + 1).
	pub fn num_coefficients(&self) -> usize {
		self.effective_degree() + 1
	}

	/// Polynomial degree: `threshold * shares_per_actor - 1`.
	pub fn effective_degree(&self) -> usize {
		self.threshold
			.saturating_mul(self.shares_per_actor)
			.saturating_sub(1)
	}

	/// Suggest raising shares_per_actor so degree+1 >= MIN_SHARES_FOR_DEGREE.
	pub fn recommended_shares_per_actor(threshold: usize) -> usize {
		if threshold == 0 {
			return 1;
		}
		// Need threshold * k >= MIN_SHARES_FOR_DEGREE  =>  k = ceil(MIN / threshold)
		let min = MIN_SHARES_FOR_DEGREE;
		(min + threshold - 1) / threshold
	}

	/// Whether this configuration meets the production PTE degree floor (C-11).
	pub fn meets_degree_floor(&self) -> bool {
		self.num_coefficients() >= MIN_SHARES_FOR_DEGREE
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn secret_share_debug_redacts() {
		let secp = crate::grin_util::secp::Secp256k1::with_caps(
			crate::grin_util::secp::ContextFlag::Commit,
		);
		let y = crate::multisig::scalar::sk_from_u64(&secp, 7).unwrap();
		let x = crate::multisig::scalar::sk_from_u64(&secp, 3).unwrap();
		let s = SecretShare {
			share_index: 0,
			x,
			y,
		};
		let dbg = format!("{:?}", s);
		assert!(dbg.contains("redacted"), "got: {}", dbg);
		// Must not dump raw secret-key Debug (which would include byte arrays).
		assert!(!dbg.contains("SecretKey("), "got: {}", dbg);
	}

	#[test]
	fn production_rejects_low_degree() {
		// 2-of-3 with 1 share ⇒ degree 1, coefficients 2 < 4
		assert!(ThresholdParams::new(2, 3).is_err());
		assert!(ThresholdParams::with_shares_per_actor(2, 3, 1).is_err());
		// Dev path still allowed
		assert!(ThresholdParams::new_allow_low_degree(2, 3).is_ok());
		// Recommended k for M=2 is 2 → coefficients = 4
		let k = ThresholdParams::recommended_shares_per_actor(2);
		assert_eq!(k, 2);
		let p = ThresholdParams::with_shares_per_actor(2, 3, k).unwrap();
		assert!(p.meets_degree_floor());
		assert_eq!(p.num_coefficients(), 4);
	}

	#[test]
	fn three_of_n_with_one_share_meets_floor() {
		// M=3, k=1 ⇒ coefficients 3 still < 4
		assert!(ThresholdParams::new(3, 5).is_err());
		let k = ThresholdParams::recommended_shares_per_actor(3);
		assert_eq!(k, 2);
		assert!(ThresholdParams::with_shares_per_actor(3, 5, k)
			.unwrap()
			.meets_degree_floor());
	}
}

/// Stable identifier for a DKG / epoch ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CeremonyId(pub Uuid);

impl CeremonyId {
	/// Fresh random ceremony id.
	pub fn new() -> Self {
		CeremonyId(Uuid::new_v4())
	}
}

impl Default for CeremonyId {
	fn default() -> Self {
		Self::new()
	}
}

/// Actor identity: opaque bytes (typically Slatepack address or index).
///
/// The x-coordinate on the secret polynomial is
/// `Hash_s("actor-" || actor_id_bytes)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId {
	/// Raw identity bytes (must be unique within a ceremony).
	pub id: Vec<u8>,
	/// Human-readable label for UX (optional).
	pub label: String,
}

impl ActorId {
	/// Create from label + unique bytes.
	pub fn new(label: impl Into<String>, id: impl AsRef<[u8]>) -> Self {
		Self {
			id: id.as_ref().to_vec(),
			label: label.into(),
		}
	}

	/// Deterministic id from a simple index (avoids address grinding).
	///
	/// **Dev / local-sim only.** Index-based actors have no Slatepack address,
	/// so they cannot receive encrypted share deliveries; real multi-party
	/// ceremonies must use [`ActorId::from_slatepack_address`].
	pub fn from_index(index: u32) -> Self {
		let mut id = b"actor-index:".to_vec();
		id.extend_from_slice(&index.to_be_bytes());
		Self {
			id,
			label: format!("actor-{}", index),
		}
	}

	/// Create an actor identity from a Slatepack address (production model).
	///
	/// The address's canonical bech32 encoding becomes the identity bytes, so
	/// the polynomial x-coordinate is `Hash_s("actor-" || addr)` per RFC-0023
	/// and the same bytes let peers age-encrypt share deliveries to this actor.
	pub fn from_slatepack_address(addr: &SlatepackAddress) -> Result<Self, Error> {
		let s = String::try_from(addr)
			.map_err(|e| Error::Multisig(format!("encode slatepack address: {}", e)))?;
		Ok(Self {
			id: s.clone().into_bytes(),
			label: s,
		})
	}

	/// Resolve this actor's Slatepack address, if the identity is address-backed.
	///
	/// Errors for index-based ids ([`ActorId::from_index`]), which cannot be a
	/// share-delivery recipient (C-02).
	pub fn slatepack_address(&self) -> Result<SlatepackAddress, Error> {
		let s = std::str::from_utf8(&self.id).map_err(|_| {
			Error::Multisig("actor id is not a slatepack address (non-utf8)".into())
		})?;
		SlatepackAddress::try_from(s).map_err(|e| {
			Error::Multisig(format!(
				"actor id is not a slatepack address ({}); \
				 encrypted share delivery requires an address-based roster",
				e
			))
		})
	}

	/// Polynomial x-coordinate for this actor (share index base).
	pub fn x_coordinate(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		hash_to_scalar(secp, HashDomain::Actor, &self.id)
	}

	/// x-coordinate for the `share_index`-th share of this actor
	/// (`share_index` in `0..shares_per_actor`).
	pub fn x_coordinate_share(
		&self,
		secp: &Secp256k1,
		share_index: usize,
	) -> Result<SecretKey, Error> {
		let mut msg = self.id.clone();
		msg.extend_from_slice(b"|share|");
		msg.extend_from_slice(&(share_index as u32).to_be_bytes());
		hash_to_scalar(secp, HashDomain::Actor, &msg)
	}
}

/// Static multisig configuration agreed at init.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigConfig {
	/// Ceremony / epoch id.
	pub ceremony_id: CeremonyId,
	/// Threshold parameters.
	pub params: ThresholdParams,
	/// Ordered actor roster.
	pub actors: Vec<ActorId>,
	/// Public polynomial coefficients S_m = G * s_m (compressed encodings).
	pub public_poly: PublicPoly,
}

impl MultisigConfig {
	/// Validate roster size matches params.
	pub fn validate(&self) -> Result<(), Error> {
		if self.actors.len() != self.params.total_actors {
			return Err(Error::Multisig(format!(
				"roster size {} != total_actors {}",
				self.actors.len(),
				self.params.total_actors
			)));
		}
		if self.public_poly.coefficients.len() != self.params.num_coefficients() {
			return Err(Error::Multisig(format!(
				"public poly has {} coeffs, expected {}",
				self.public_poly.coefficients.len(),
				self.params.num_coefficients()
			)));
		}
		// Distinct actor ids
		for i in 0..self.actors.len() {
			for j in (i + 1)..self.actors.len() {
				if self.actors[i].id == self.actors[j].id {
					return Err(Error::Multisig("duplicate actor id".into()));
				}
			}
		}
		Ok(())
	}
}

/// Local state held by one actor after DKG (must be backed up).
///
/// **Note:** Under Feldman DKG the share cannot be re-derived from a BIP39
/// seed alone; this structure is the backup unit. Persist only via AEAD-sealed
/// storage / export (C-08) — never log or print Debug in production.
#[derive(Clone, Serialize, Deserialize)]
pub struct MultisigWalletState {
	/// Shared configuration.
	pub config: MultisigConfig,
	/// This actor's identity.
	pub my_actor: ActorId,
	/// Secret shares held by this actor: one per `shares_per_actor`.
	/// Each is `sk(x)` at the corresponding x-coordinate.
	pub shares: Vec<SecretShare>,
}

impl std::fmt::Debug for MultisigWalletState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MultisigWalletState")
			.field("config", &self.config)
			.field("my_actor", &self.my_actor)
			.field("shares", &format_args!("[{} shares, redacted]", self.shares.len()))
			.finish()
	}
}

/// One secret share evaluation.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretShare {
	/// Share index for this actor (`0..shares_per_actor`).
	pub share_index: usize,
	/// x-coordinate used for this share.
	pub x: SecretKey,
	/// y = sk(x) secret evaluation.
	pub y: SecretKey,
}

impl std::fmt::Debug for SecretShare {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SecretShare")
			.field("share_index", &self.share_index)
			.field("x", &"[redacted]")
			.field("y", &"[redacted]")
			.finish()
	}
}

impl MultisigWalletState {
	/// Public key of the constant term S_0 (view-related material).
	pub fn s0_pubkey(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		self.config.public_poly.coefficient_pubkey(secp, 0)
	}
}
