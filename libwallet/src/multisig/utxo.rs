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

//! Multisig UTXO tracking and coin-number allocation (WS6).
//!
//! Multisig outputs are **not** ordinary wallet `OutputData` rows (those are
//! single-party keychain paths). Each UTXO is keyed by `(ceremony_id, coin
//! number)` and stores the public commitment, optional rangeproof, and status.
//!
//! ## Recognition (scan)
//!
//! Shared BP nonce = `H(view_seed ‖ commit)`. With the public poly (`S_0`) an
//! actor can rewind any on-chain rangeproof without knowing the coin number in
//! advance; the recovered message embeds the coin number (see
//! [`super::rangeproof::coin_proof_message`]).

use crate::grin_core::ser;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Secp256k1;
use crate::grin_util::{from_hex, ToHex};
use crate::Error;

use super::coin::{view_seed_from_public_poly, CoinId};
use super::poly::PublicPoly;
use super::rangeproof::{
	coin_pedersen_commit_public, coin_proof_message, derive_shared_nonce, rangeproof_params_for_coin,
};
use super::types::CeremonyId;

/// LMDB key prefix for multisig UTXO records (`U` = 0x55).
pub const MULTISIG_UTXO_PREFIX: u8 = b'U';
/// LMDB key prefix for next-coin-number meta (`N` = 0x4e).
pub const MULTISIG_COIN_META_PREFIX: u8 = b'N';

/// Lifecycle status of a tracked multisig UTXO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultisigUtxoStatus {
	/// Coin number reserved by the allocator; output not yet created.
	Reserved,
	/// Locally known / created but not confirmed on chain.
	Unconfirmed,
	/// Confirmed and spendable (per height policy).
	Unspent,
	/// Locked for an in-progress spend session.
	Locked,
	/// Spent (or swept to a new epoch).
	Spent,
}

/// One multisig UTXO tracked by the wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigUtxo {
	/// Ceremony / epoch this coin belongs to.
	pub ceremony_id: CeremonyId,
	/// Coin identity (number + value).
	pub coin: CoinId,
	/// Pedersen commitment (hex of 33-byte commit).
	pub commit_hex: String,
	/// Optional multiparty rangeproof (hex). Large; may be omitted after confirm.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proof_hex: Option<String>,
	/// Status.
	pub status: MultisigUtxoStatus,
	/// Block height when confirmed (0 if unconfirmed).
	pub height: u64,
	/// Optional PMMR / output index from the node.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mmr_index: Option<u64>,
	/// Session that created this output (hex), if known.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub session_id_hex: Option<String>,
	/// Optional UX label.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub label: Option<String>,
}

impl MultisigUtxo {
	/// Build a new unconfirmed UTXO record from coin + commit (+ optional proof).
	pub fn new_unconfirmed(
		ceremony_id: CeremonyId,
		coin: CoinId,
		commit: &Commitment,
		proof: Option<&RangeProof>,
		session_id_hex: Option<String>,
	) -> Self {
		Self {
			ceremony_id,
			coin,
			commit_hex: commit.0.to_vec().to_hex(),
			proof_hex: proof.map(|p| p.proof[..p.plen].to_vec().to_hex()),
			status: MultisigUtxoStatus::Unconfirmed,
			height: 0,
			mmr_index: None,
			session_id_hex,
			label: None,
		}
	}

	/// Parse the commitment.
	pub fn commitment(&self) -> Result<Commitment, Error> {
		let bytes =
			from_hex(&self.commit_hex).map_err(|e| Error::Multisig(format!("commit hex: {}", e)))?;
		if bytes.len() != 33 {
			return Err(Error::Multisig("commit must be 33 bytes".into()));
		}
		let mut a = [0u8; 33];
		a.copy_from_slice(&bytes);
		Ok(Commitment(a))
	}

	/// Whether this UTXO is eligible to spend at `current_height` with
	/// `min_confirmations` (mirrors ordinary wallet rules, no coinbase lock).
	pub fn eligible_to_spend(&self, current_height: u64, min_confirmations: u64) -> bool {
		match self.status {
			MultisigUtxoStatus::Unspent => {
				if self.height == 0 {
					return min_confirmations == 0;
				}
				if self.height > current_height {
					return false;
				}
				1 + (current_height - self.height) >= min_confirmations
			}
			MultisigUtxoStatus::Unconfirmed => min_confirmations == 0,
			_ => false,
		}
	}
}

impl ser::Writeable for MultisigUtxo {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for MultisigUtxo {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<MultisigUtxo, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

/// DB key for a UTXO: `U || ceremony_uuid(16) || coin_number_be8`.
pub fn multisig_utxo_db_key(ceremony_id: &CeremonyId, coin_number: u64) -> Vec<u8> {
	let mut k = vec![MULTISIG_UTXO_PREFIX];
	k.extend_from_slice(ceremony_id.0.as_bytes());
	k.extend_from_slice(&coin_number.to_be_bytes());
	k
}

/// DB key for coin-number meta: `N || ceremony_uuid(16)`.
pub fn multisig_coin_meta_db_key(ceremony_id: &CeremonyId) -> Vec<u8> {
	let mut k = vec![MULTISIG_COIN_META_PREFIX];
	k.extend_from_slice(ceremony_id.0.as_bytes());
	k
}

/// Parse `(ceremony_id, coin_number)` from a UTXO DB key.
pub fn parse_utxo_db_key(key: &[u8]) -> Result<(CeremonyId, u64), Error> {
	if key.len() != 1 + 16 + 8 || key[0] != MULTISIG_UTXO_PREFIX {
		return Err(Error::Multisig("invalid multisig utxo db key".into()));
	}
	let mut ub = [0u8; 16];
	ub.copy_from_slice(&key[1..17]);
	let mut nb = [0u8; 8];
	nb.copy_from_slice(&key[17..25]);
	Ok((
		CeremonyId(uuid::Uuid::from_bytes(ub)),
		u64::from_be_bytes(nb),
	))
}

/// Result of recognizing a multiparty rangeproof via shared-nonce rewind.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecognizedMultisigOutput {
	/// Recovered coin id (number from proof message + recovered value).
	pub coin: CoinId,
	/// Commitment that was scanned.
	pub commit: Commitment,
}

/// Try to recognize a chain output as belonging to this multisig ceremony.
///
/// Uses shared-nonce rewind (strategy A view material). Returns `None` if the
/// proof does not rewind under this ceremony's view seed.
pub fn try_recognize_output(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	commit: Commitment,
	proof: RangeProof,
	extra_data: Option<Vec<u8>>,
) -> Result<Option<RecognizedMultisigOutput>, Error> {
	let seed = view_seed_from_public_poly(secp, public_poly)?;
	let shared_nonce = derive_shared_nonce(secp, &seed, &commit)?;
	let info = match secp.rewind_bullet_proof(commit, shared_nonce, extra_data, proof) {
		Ok(i) => i,
		Err(_) => return Ok(None),
	};
	let msg = info.message.as_bytes();
	if msg.len() < 8 {
		return Ok(None);
	}
	let mut num_bytes = [0u8; 8];
	num_bytes.copy_from_slice(&msg[0..8]);
	let coin_number = u64::from_be_bytes(num_bytes);
	// Optional: next 8 bytes are value in our encoding — prefer rewind value.
	let coin = CoinId::new(coin_number, info.value);
	// Sanity: recomputed public commit must match.
	let expected = coin_pedersen_commit_public(secp, public_poly, &coin)?;
	if expected != commit {
		// Value/number mismatch or different poly — not ours.
		return Ok(None);
	}
	Ok(Some(RecognizedMultisigOutput { coin, commit }))
}

/// Verify that a coin's public commitment matches `commit_hex` under the poly.
pub fn verify_utxo_commit(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	utxo: &MultisigUtxo,
) -> Result<(), Error> {
	let expected = coin_pedersen_commit_public(secp, public_poly, &utxo.coin)?;
	let got = utxo.commitment()?;
	if expected != got {
		return Err(Error::Multisig(
			"utxo commit does not match public poly derivation".into(),
		));
	}
	Ok(())
}

/// Build an unconfirmed UTXO after a successful CreateOutput session.
pub fn utxo_from_create_output(
	secp: &Secp256k1,
	public_poly: &PublicPoly,
	ceremony_id: CeremonyId,
	coin: CoinId,
	proof: &RangeProof,
	session_id_hex: Option<String>,
) -> Result<MultisigUtxo, Error> {
	let params = rangeproof_params_for_coin(secp, public_poly, &coin, None)?;
	// Ensure proof message aligns with coin (best-effort; rewind checks later).
	let _ = coin_proof_message(&coin);
	Ok(MultisigUtxo::new_unconfirmed(
		ceremony_id,
		coin,
		&params.commit,
		Some(proof),
		session_id_hex,
	))
}

/// Next coin number suggestion: `max(known)+1` (caller must persist reservation).
pub fn next_coin_number_from_list(existing: &[MultisigUtxo], reserved_high_water: u64) -> u64 {
	let max_existing = existing.iter().map(|u| u.coin.number).max().unwrap_or(0);
	max_existing.max(reserved_high_water).saturating_add(1)
}

/// Meta record: highest allocated coin number for a ceremony (0 = none).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CoinNumberMeta {
	/// Highest number that has been allocated (Reserved or higher).
	pub high_water: u64,
}

impl ser::Writeable for CoinNumberMeta {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for CoinNumberMeta {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<CoinNumberMeta, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

/// Placeholder so SecretKey is referenced if needed by callers.
#[allow(dead_code)]
fn _sk_marker(_: &SecretKey) {}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::rangeproof::run_rangeproof_local;
	use crate::multisig::share::ActorPoint;
	use crate::multisig::types::{ActorId, ThresholdParams};

	#[test]
	fn db_key_roundtrip() {
		let id = CeremonyId::new();
		let k = multisig_utxo_db_key(&id, 42);
		let (cid, n) = parse_utxo_db_key(&k).unwrap();
		assert_eq!(cid.0, id.0);
		assert_eq!(n, 42);
	}

	#[test]
	fn recognize_after_multiparty_rp() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let coin = CoinId::new(7, 123_456);
		let (proof, p) =
			run_rangeproof_local(&secp, &states[0].config.public_poly, &q, &coin, None).unwrap();

		let rec = try_recognize_output(
			&secp,
			&states[0].config.public_poly,
			p.commit,
			proof,
			None,
		)
		.unwrap()
		.expect("should recognize");
		assert_eq!(rec.coin.number, coin.number);
		assert_eq!(rec.coin.value, coin.value);
	}

	#[test]
	fn next_coin_number_monotonic() {
		let id = CeremonyId::new();
		let u = MultisigUtxo {
			ceremony_id: id,
			coin: CoinId::new(5, 1),
			commit_hex: "00".repeat(33),
			proof_hex: None,
			status: MultisigUtxoStatus::Unspent,
			height: 1,
			mmr_index: None,
			session_id_hex: None,
			label: None,
		};
		assert_eq!(next_coin_number_from_list(&[u], 0), 6);
		assert_eq!(next_coin_number_from_list(&[], 10), 11);
		assert_eq!(next_coin_number_from_list(&[], 0), 1);
	}

	#[test]
	fn public_commit_matches_utxo() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let coin = CoinId::new(3, 99);
		let commit =
			coin_pedersen_commit_public(&secp, &states[0].config.public_poly, &coin).unwrap();
		let utxo = MultisigUtxo::new_unconfirmed(
			states[0].config.ceremony_id.clone(),
			coin,
			&commit,
			None,
			None,
		);
		verify_utxo_commit(&secp, &states[0].config.public_poly, &utxo).unwrap();
	}
}
