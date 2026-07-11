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

//! Secret and public polynomials for Feldman VSS / DKG.

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::Secp256k1;
use crate::Error;
use rand::thread_rng;

use super::scalar::{sk_add, sk_mul, sk_pow_u32};

/// Secret polynomial coefficients `r_0 + r_1 x + ... + r_d x^d`.
#[derive(Clone, Debug)]
pub struct SecretPoly {
	/// Coefficients low-degree first. Length = degree + 1.
	pub coeffs: Vec<SecretKey>,
}

impl SecretPoly {
	/// Random polynomial of given degree (inclusive degree).
	pub fn random(secp: &Secp256k1, degree: usize) -> Result<Self, Error> {
		let mut rng = thread_rng();
		let mut coeffs = Vec::with_capacity(degree + 1);
		for _ in 0..=degree {
			coeffs.push(SecretKey::new(secp, &mut rng));
		}
		Ok(Self { coeffs })
	}

	/// Degree of the polynomial.
	pub fn degree(&self) -> usize {
		self.coeffs.len().saturating_sub(1)
	}

	/// Commitments C_m = G * r_m.
	pub fn commitments(&self, secp: &Secp256k1) -> Result<Vec<PublicKey>, Error> {
		self.coeffs
			.iter()
			.map(|c| PublicKey::from_secret_key(secp, c).map_err(|e| e.into()))
			.collect()
	}
}

/// Evaluate secret polynomial at `x`: `sum r_m * x^m`.
pub fn eval_secret_poly(
	secp: &Secp256k1,
	poly: &SecretPoly,
	x: &SecretKey,
) -> Result<SecretKey, Error> {
	// Horner: (((r_d)*x + r_{d-1})*x + ... ) + r_0
	let mut acc = poly
		.coeffs
		.last()
		.ok_or_else(|| Error::Multisig("empty polynomial".into()))?
		.clone();
	if poly.coeffs.len() == 1 {
		return Ok(acc);
	}
	for c in poly.coeffs.iter().rev().skip(1) {
		acc = sk_mul(secp, &acc, x)?;
		acc = sk_add(secp, &acc, c)?;
	}
	Ok(acc)
}

/// Public polynomial coefficients S_m (as compressed pubkeys).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicPoly {
	/// Compressed public keys, low-degree first.
	pub coefficients: Vec<Vec<u8>>,
}

impl PublicPoly {
	/// Build from public keys.
	pub fn from_pubkeys(secp: &Secp256k1, keys: &[PublicKey]) -> Self {
		let coefficients = keys
			.iter()
			.map(|pk| pk.serialize_vec(secp, true).to_vec())
			.collect();
		Self { coefficients }
	}

	/// Decode coefficient m.
	pub fn coefficient_pubkey(&self, secp: &Secp256k1, m: usize) -> Result<PublicKey, Error> {
		let bytes = self
			.coefficients
			.get(m)
			.ok_or_else(|| Error::Multisig(format!("missing public coeff {}", m)))?;
		Ok(PublicKey::from_slice(secp, bytes)?)
	}

	/// All coefficients as public keys.
	pub fn pubkeys(&self, secp: &Secp256k1) -> Result<Vec<PublicKey>, Error> {
		(0..self.coefficients.len())
			.map(|m| self.coefficient_pubkey(secp, m))
			.collect()
	}

	/// Sum two public polynomials (point-wise).
	pub fn add(&self, secp: &Secp256k1, other: &PublicPoly) -> Result<PublicPoly, Error> {
		if self.coefficients.len() != other.coefficients.len() {
			return Err(Error::Multisig(
				"public poly degree mismatch on add".into(),
			));
		}
		let mut out = Vec::with_capacity(self.coefficients.len());
		for m in 0..self.coefficients.len() {
			let a = self.coefficient_pubkey(secp, m)?;
			let b = other.coefficient_pubkey(secp, m)?;
			let sum = PublicKey::from_combination(secp, vec![&a, &b])?;
			out.push(sum);
		}
		Ok(PublicPoly::from_pubkeys(secp, &out))
	}
}

/// Evaluate public polynomial: `P(x) = sum S_m * x^m` (as a curve point).
pub fn eval_public_poly(
	secp: &Secp256k1,
	poly: &PublicPoly,
	x: &SecretKey,
) -> Result<PublicKey, Error> {
	let keys = poly.pubkeys(secp)?;
	if keys.is_empty() {
		return Err(Error::Multisig("empty public poly".into()));
	}
	// term_m = S_m * x^m
	let mut terms: Vec<PublicKey> = Vec::with_capacity(keys.len());
	for (m, s_m) in keys.iter().enumerate() {
		let mut term = *s_m;
		if m > 0 {
			let x_m = sk_pow_u32(secp, x, m as u32)?;
			term.mul_assign(secp, &x_m)?;
		}
		terms.push(term);
	}
	let refs: Vec<&PublicKey> = terms.iter().collect();
	Ok(PublicKey::from_combination(secp, refs)?)
}

/// Verify that G * y == P(x) for a share (x, y).
pub fn verify_share(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	x: &SecretKey,
	y: &SecretKey,
) -> Result<bool, Error> {
	let expected = eval_public_poly(secp, public_poly, x)?;
	let got = PublicKey::from_secret_key(secp, y)?;
	Ok(expected == got)
}

/// Helper used only in tests: integer x as scalar.
#[cfg(test)]
pub fn test_x(secp: &Secp256k1, n: u64) -> SecretKey {
	super::scalar::sk_from_u64(secp, n).unwrap()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};

	#[test]
	fn secret_public_eval_consistent() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let poly = SecretPoly::random(&secp, 2).unwrap(); // degree 2
		let x = test_x(&secp, 5);
		let y = eval_secret_poly(&secp, &poly, &x).unwrap();
		let commits = poly.commitments(&secp).unwrap();
		let pp = PublicPoly::from_pubkeys(&secp, &commits);
		assert!(verify_share(&secp, &pp, &x, &y).unwrap());
	}
}
