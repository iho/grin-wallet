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

//! Coin number / blinding-factor derivation for multisig outputs.
//!
//! ```text
//! x_coin(number, value) = Hash_s("coin" || number || value)
//! sk_coin = sk(x_coin) + mix(view_seed, x_coin)
//! ```
//!
//! **Security note (review F-02):** `mix` uses public ceremony material and
//! does **not** prevent recovery of the secret polynomial if an adversary
//! learns M full coin blinding factors and the public poly. It remains useful
//! as domain separation between raw polynomial eval and wallet blinds.

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::Secp256k1;
use crate::Error;
use sha2::{Digest, Sha256};

use super::poly::{eval_public_poly, PublicPoly};
use super::scalar::{hash_to_scalar, sk_add, HashDomain};
use super::share::{partial_key_at, reconstruct_secret_at, ActorPoint};

/// Public coin identifier used in derivation (not secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinId {
	/// Monotonic (or epoch-tagged) coin number.
	pub number: u64,
	/// Value in nanogrins (included to prevent same-id different-value swaps).
	pub value: u64,
}

impl CoinId {
	/// Create a coin id.
	pub fn new(number: u64, value: u64) -> Self {
		Self { number, value }
	}

	fn encoding(&self) -> Vec<u8> {
		let mut v = Vec::with_capacity(16);
		v.extend_from_slice(&self.number.to_be_bytes());
		v.extend_from_slice(&self.value.to_be_bytes());
		v
	}
}

/// x_coin = Hash_s(number || value) under coin domain.
pub fn coin_x(secp: &Secp256k1, coin: &CoinId) -> Result<SecretKey, Error> {
	hash_to_scalar(secp, HashDomain::Coin, &coin.encoding())
}

/// Derive mix scalar from public view seed material and x_coin.
///
/// `view_seed` is typically the compressed encoding of S_0 (public).
pub fn view_mix(secp: &Secp256k1, view_seed: &[u8], x_coin: &SecretKey) -> Result<SecretKey, Error> {
	let mut msg = view_seed.to_vec();
	msg.extend_from_slice(&x_coin.0);
	hash_to_scalar(secp, HashDomain::Hkdf, &msg)
}

/// View seed bytes from public polynomial S_0.
pub fn view_seed_from_public_poly(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
) -> Result<Vec<u8>, Error> {
	let s0 = public_poly.coefficient_pubkey(secp, 0)?;
	Ok(s0.serialize_vec(secp, true).to_vec())
}

/// Full coin blinding factor given a quorum that can reconstruct sk(x).
pub fn coin_blinding_factor(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	quorum: &[ActorPoint],
	coin: &CoinId,
) -> Result<SecretKey, Error> {
	let x = coin_x(secp, coin)?;
	let sk_x = reconstruct_secret_at(secp, quorum, &x)?;
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let mix = view_mix(secp, &seed, &x)?;
	sk_add(secp, &sk_x, &mix)
}

/// One actor's partial contribution to the coin blind (before mix).
/// Mix is public and can be added by any party after aggregation.
pub fn coin_partial_poly_key(
	secp: &Secp256k1,
	quorum: &[ActorPoint],
	j: usize,
	coin: &CoinId,
) -> Result<SecretKey, Error> {
	let x = coin_x(secp, coin)?;
	partial_key_at(secp, quorum, j, &x)
}

/// Components needed to form Pedersen commitment without the secret:
/// `P(x) + G*mix`  (caller adds `H*value` via keychain/secp commit).
pub fn coin_commitment_components(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	coin: &CoinId,
) -> Result<(PublicKey, SecretKey), Error> {
	let x = coin_x(secp, coin)?;
	let p_x = eval_public_poly(secp, public_poly, &x)?;
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let mix = view_mix(secp, &seed, &x)?;
	// G * mix
	let g_mix = PublicKey::from_secret_key(secp, &mix)?;
	let pubkey = PublicKey::from_combination(secp, vec![&p_x, &g_mix])?;
	Ok((pubkey, mix))
}

/// Deterministic tx offset suggestion: Hash_s(view_seed || context).
pub fn tx_offset(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	context: &[u8],
) -> Result<SecretKey, Error> {
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let mut msg = seed;
	msg.extend_from_slice(context);
	hash_to_scalar(secp, HashDomain::Offset, &msg)
}

/// Simple non-cryptographic fingerprint for logs (not secret).
pub fn coin_fingerprint(coin: &CoinId) -> String {
	let mut h = Sha256::new();
	h.update(&coin.encoding());
	let d = h.finalize();
	format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	#[test]
	fn coin_blind_matches_public_components() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let coin = CoinId::new(1, 1_000_000_000);
		let blind = coin_blinding_factor(&secp, &states[0].config.public_poly, &q, &coin).unwrap();
		let (pk, _mix) =
			coin_commitment_components(&secp, &states[0].config.public_poly, &coin).unwrap();
		let g_blind = PublicKey::from_secret_key(&secp, &blind).unwrap();
		assert_eq!(pk, g_blind);
	}

	#[test]
	fn different_values_different_blinds() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let c1 = CoinId::new(1, 100);
		let c2 = CoinId::new(1, 200); // same number, different value
		let b1 = coin_blinding_factor(&secp, &states[0].config.public_poly, &q, &c1).unwrap();
		let b2 = coin_blinding_factor(&secp, &states[0].config.public_poly, &q, &c2).unwrap();
		assert_ne!(b1.0, b2.0);
	}
}
