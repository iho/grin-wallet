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

//! Domain-separated hash-to-scalar and secret-key field helpers.
//!
//! Uses **hash-to-scalar with rejection sampling** (not Ed25519 clamping).

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::Secp256k1;
use crate::Error;
use sha2::{Digest, Sha256};

/// Domain tags for `Hash_s` (prevents cross-protocol collisions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashDomain {
	/// Actor x-coordinate: `"grin-msig/actor"`.
	Actor,
	/// Coin x-coordinate: `"grin-msig/coin"`.
	Coin,
	/// Antisymmetric share mask δ: `"grin-msig/delta"`.
	Delta,
	/// Proof-of-possession transcript: `"grin-msig/pop"`.
	Pop,
	/// Transaction offset: `"grin-msig/offset"`.
	Offset,
	/// HKDF / view mixing: `"grin-msig/hkdf"`.
	Hkdf,
	/// Generic ceremony context: `"grin-msig/ctx"`.
	Context,
	/// FROST binding factor ρ: `"grin-msig/frost-rho"`.
	Frost,
}

impl HashDomain {
	fn tag(self) -> &'static [u8] {
		match self {
			HashDomain::Actor => b"grin-msig/actor",
			HashDomain::Coin => b"grin-msig/coin",
			HashDomain::Delta => b"grin-msig/delta",
			HashDomain::Pop => b"grin-msig/pop",
			HashDomain::Offset => b"grin-msig/offset",
			HashDomain::Hkdf => b"grin-msig/hkdf",
			HashDomain::Context => b"grin-msig/ctx",
			HashDomain::Frost => b"grin-msig/frost-rho",
		}
	}
}

/// Hash arbitrary message into a valid secp256k1 secret key (scalar).
///
/// Algorithm: `SHA256(tag || 0x00 || msg || counter_be32)` with counter
/// starting at 0, accepting the first 32-byte digest that is a valid key.
pub fn hash_to_scalar(
	secp: &Secp256k1,
	domain: HashDomain,
	msg: &[u8],
) -> Result<SecretKey, Error> {
	for counter in 0u32..1024u32 {
		let mut hasher = Sha256::new();
		hasher.update(domain.tag());
		hasher.update(&[0u8]);
		hasher.update(msg);
		hasher.update(&counter.to_be_bytes());
		let digest = hasher.finalize();
		if let Ok(sk) = SecretKey::from_slice(secp, &digest) {
			return Ok(sk);
		}
	}
	Err(Error::Multisig(
		"hash_to_scalar failed to produce valid scalar".into(),
	))
}

/// Construct a secret key from raw 32 bytes (must be valid).
pub fn sk_from_bytes(secp: &Secp256k1, bytes: &[u8]) -> Result<SecretKey, Error> {
	Ok(SecretKey::from_slice(secp, bytes)?)
}

/// a + b (mod n)
pub fn sk_add(secp: &Secp256k1, a: &SecretKey, b: &SecretKey) -> Result<SecretKey, Error> {
	let mut out = a.clone();
	out.add_assign(secp, b)?;
	Ok(out)
}

/// a - b (mod n)
pub fn sk_sub(secp: &Secp256k1, a: &SecretKey, b: &SecretKey) -> Result<SecretKey, Error> {
	let mut neg_b = b.clone();
	neg_b.neg_assign(secp)?;
	sk_add(secp, a, &neg_b)
}

/// a * b (mod n)
pub fn sk_mul(secp: &Secp256k1, a: &SecretKey, b: &SecretKey) -> Result<SecretKey, Error> {
	let mut out = a.clone();
	out.mul_assign(secp, b)?;
	Ok(out)
}

/// −a (mod n)
pub fn sk_neg(secp: &Secp256k1, a: &SecretKey) -> Result<SecretKey, Error> {
	let mut out = a.clone();
	out.neg_assign(secp)?;
	Ok(out)
}

/// a / b = a * b^{−1} (mod n)
pub fn sk_div(secp: &Secp256k1, a: &SecretKey, b: &SecretKey) -> Result<SecretKey, Error> {
	let mut inv = b.clone();
	inv.inv_assign(secp)?;
	sk_mul(secp, a, &inv)
}

/// Integer k as a scalar (k > 0, small).
pub fn sk_from_u64(secp: &Secp256k1, k: u64) -> Result<SecretKey, Error> {
	if k == 0 {
		return Err(Error::Multisig("scalar zero not allowed".into()));
	}
	let mut bytes = [0u8; 32];
	bytes[24..].copy_from_slice(&k.to_be_bytes());
	SecretKey::from_slice(secp, &bytes).map_err(|e| e.into())
}

/// Raise scalar base to power `exp` (exp as u32), via repeated squaring.
pub fn sk_pow_u32(secp: &Secp256k1, base: &SecretKey, exp: u32) -> Result<SecretKey, Error> {
	// result = 1
	let mut result = sk_from_u64(secp, 1)?;
	if exp == 0 {
		return Ok(result);
	}
	let mut b = base.clone();
	let mut e = exp;
	while e > 0 {
		if e & 1 == 1 {
			result = sk_mul(secp, &result, &b)?;
		}
		e >>= 1;
		if e > 0 {
			b = sk_mul(secp, &b, &b)?;
		}
	}
	Ok(result)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};

	#[test]
	fn hash_to_scalar_deterministic() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let a = hash_to_scalar(&secp, HashDomain::Actor, b"alice").unwrap();
		let b = hash_to_scalar(&secp, HashDomain::Actor, b"alice").unwrap();
		assert_eq!(a.0, b.0);
		let c = hash_to_scalar(&secp, HashDomain::Actor, b"bob").unwrap();
		assert_ne!(a.0, c.0);
	}

	#[test]
	fn field_ops_roundtrip() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let a = sk_from_u64(&secp, 7).unwrap();
		let b = sk_from_u64(&secp, 3).unwrap();
		let s = sk_add(&secp, &a, &b).unwrap();
		assert_eq!(s.0, sk_from_u64(&secp, 10).unwrap().0);
		let d = sk_sub(&secp, &s, &b).unwrap();
		assert_eq!(d.0, a.0);
		let p = sk_mul(&secp, &a, &b).unwrap();
		assert_eq!(p.0, sk_from_u64(&secp, 21).unwrap().0);
		let q = sk_div(&secp, &p, &b).unwrap();
		assert_eq!(q.0, a.0);
	}
}
