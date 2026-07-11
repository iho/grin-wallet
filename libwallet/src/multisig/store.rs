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

//! Persistence helpers for multisig wallet state.
//!
//! Secret shares are XOR-obfuscated with a keychain-derived key before
//! writing to LMDB (same pattern as private tx context). This is not a
//! substitute for full-disk encryption, but keeps share material from
//! sitting in plaintext next to other wallet metadata.

use crate::blake2::blake2b::Blake2b;
use crate::grin_core::ser;
use crate::grin_keychain::{Keychain, SwitchCommitmentType};
use crate::grin_util::secp::constants::SECRET_KEY_SIZE;
use crate::grin_util::secp::key::SecretKey;
use crate::Error;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use super::types::{CeremonyId, MultisigWalletState};

/// LMDB key prefix for multisig wallet states (`m` = 0x6d).
pub const MULTISIG_PREFIX: u8 = b'm';

/// Size of the symmetric key used for pending-ceremony AEAD (bytes).
pub const PENDING_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size (bytes).
const PENDING_NONCE_SIZE: usize = 12;
/// Poly1305 tag size (bytes).
const PENDING_TAG_SIZE: usize = 16;

/// Derive a 32-byte symmetric key from the wallet keychain for at-rest
/// encryption of pending DKG ceremony state.
///
/// The pending file holds this dealer's **secret** polynomial coefficients and
/// running share accumulators (C-03); it must never sit on disk in plaintext.
/// The key is domain-separated from the share-obfuscation key so the two never
/// collide.
pub fn derive_pending_key<K: Keychain>(keychain: &K) -> Result<[u8; PENDING_KEY_SIZE], Error> {
	let root_key = keychain.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;
	let mut hasher = Blake2b::new(PENDING_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(b"grin-msig/pending-key-v1");
	let out = hasher.finalize();
	let mut ret = [0u8; PENDING_KEY_SIZE];
	ret.copy_from_slice(&out.as_bytes()[0..PENDING_KEY_SIZE]);
	Ok(ret)
}

/// Encrypt pending-ceremony bytes: output is `nonce(12) || ciphertext || tag`.
pub fn seal_pending(key: &[u8; PENDING_KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
	let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
	let mut nonce_bytes = [0u8; PENDING_NONCE_SIZE];
	rand::thread_rng().fill_bytes(&mut nonce_bytes);
	let ct = cipher
		.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
		.map_err(|e| Error::Multisig(format!("pending seal failed: {:?}", e)))?;
	let mut out = Vec::with_capacity(PENDING_NONCE_SIZE + ct.len());
	out.extend_from_slice(&nonce_bytes);
	out.extend_from_slice(&ct);
	Ok(out)
}

/// Decrypt pending-ceremony bytes produced by [`seal_pending`].
pub fn open_pending(key: &[u8; PENDING_KEY_SIZE], blob: &[u8]) -> Result<Vec<u8>, Error> {
	if blob.len() < PENDING_NONCE_SIZE + PENDING_TAG_SIZE {
		return Err(Error::Multisig("pending blob too short".into()));
	}
	let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
	let nonce = Nonce::from_slice(&blob[0..PENDING_NONCE_SIZE]);
	cipher
		.decrypt(nonce, &blob[PENDING_NONCE_SIZE..])
		.map_err(|_| Error::Multisig("pending decrypt failed (wrong key or corrupt file)".into()))
}

/// Build DB key for a ceremony: `prefix || uuid_bytes`.
pub fn multisig_db_key(ceremony_id: &CeremonyId) -> Vec<u8> {
	let mut k = vec![MULTISIG_PREFIX];
	k.extend_from_slice(ceremony_id.0.as_bytes());
	k
}

/// Parse ceremony id from a full DB key (prefix + 16 uuid bytes).
pub fn ceremony_id_from_db_key(key: &[u8]) -> Result<CeremonyId, Error> {
	if key.len() != 1 + 16 || key[0] != MULTISIG_PREFIX {
		return Err(Error::Multisig("invalid multisig db key".into()));
	}
	let mut bytes = [0u8; 16];
	bytes.copy_from_slice(&key[1..]);
	Ok(CeremonyId(uuid::Uuid::from_bytes(bytes)))
}

/// Derive per-share XOR mask from the wallet master key material.
fn share_xor_key<K: Keychain>(
	keychain: &K,
	ceremony_id: &CeremonyId,
	share_index: usize,
	label: &[u8],
) -> Result<[u8; SECRET_KEY_SIZE], Error> {
	let root_key = keychain.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;
	let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(ceremony_id.0.as_bytes());
	hasher.update(label);
	hasher.update(&(share_index as u32).to_be_bytes());
	let out = hasher.finalize();
	let mut ret = [0u8; SECRET_KEY_SIZE];
	ret.copy_from_slice(&out.as_bytes()[0..SECRET_KEY_SIZE]);
	Ok(ret)
}

fn xor_secret(sk: &mut SecretKey, mask: &[u8; SECRET_KEY_SIZE]) {
	for i in 0..SECRET_KEY_SIZE {
		sk.0[i] ^= mask[i];
	}
}

/// Clone state and XOR-obfuscate all share secrets for storage.
pub fn encrypt_for_storage<K: Keychain>(
	keychain: &K,
	state: &MultisigWalletState,
) -> Result<MultisigWalletState, Error> {
	let mut stored = state.clone();
	let ceremony = &stored.config.ceremony_id;
	for share in &mut stored.shares {
		let x_mask = share_xor_key(keychain, ceremony, share.share_index, b"msig-x")?;
		let y_mask = share_xor_key(keychain, ceremony, share.share_index, b"msig-y")?;
		xor_secret(&mut share.x, &x_mask);
		xor_secret(&mut share.y, &y_mask);
	}
	Ok(stored)
}

/// Reverse XOR obfuscation after loading from storage.
pub fn decrypt_from_storage<K: Keychain>(
	keychain: &K,
	state: &mut MultisigWalletState,
) -> Result<(), Error> {
	// encrypt is its own inverse
	let ceremony = state.config.ceremony_id.clone();
	for share in &mut state.shares {
		let x_mask = share_xor_key(keychain, &ceremony, share.share_index, b"msig-x")?;
		let y_mask = share_xor_key(keychain, &ceremony, share.share_index, b"msig-y")?;
		xor_secret(&mut share.x, &x_mask);
		xor_secret(&mut share.y, &y_mask);
	}
	Ok(())
}

impl ser::Writeable for MultisigWalletState {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for MultisigWalletState {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<MultisigWalletState, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_keychain::ExtKeychain;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let original = states[0].clone();

		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let encrypted = encrypt_for_storage(&keychain, &original).unwrap();
		// Ciphertext should differ from plaintext shares
		assert_ne!(encrypted.shares[0].y.0, original.shares[0].y.0);

		let mut decrypted = encrypted;
		decrypt_from_storage(&keychain, &mut decrypted).unwrap();
		assert_eq!(decrypted.shares[0].y.0, original.shares[0].y.0);
		assert_eq!(decrypted.shares[0].x.0, original.shares[0].x.0);
	}

	#[test]
	fn db_key_roundtrip() {
		let id = CeremonyId::new();
		let key = multisig_db_key(&id);
		let parsed = ceremony_id_from_db_key(&key).unwrap();
		assert_eq!(parsed.0, id.0);
	}

	#[test]
	fn pending_seal_open_roundtrip() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key = derive_pending_key(&keychain).unwrap();
		let plaintext = b"secret dealer coefficients and share accumulators";
		let blob = seal_pending(&key, plaintext).unwrap();
		// Ciphertext must not contain the plaintext and must be longer (nonce + tag).
		assert!(blob.len() > plaintext.len() + PENDING_NONCE_SIZE);
		assert!(blob
			.windows(plaintext.len())
			.all(|w| w != &plaintext[..]));
		let recovered = open_pending(&key, &blob).unwrap();
		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn pending_wrong_key_rejected() {
		let kc1 = ExtKeychain::from_random_seed(false).unwrap();
		let kc2 = ExtKeychain::from_random_seed(false).unwrap();
		let k1 = derive_pending_key(&kc1).unwrap();
		let k2 = derive_pending_key(&kc2).unwrap();
		assert_ne!(k1, k2);
		let blob = seal_pending(&k1, b"payload").unwrap();
		// Decrypt with a different key must fail (AEAD tag mismatch), not silently corrupt.
		assert!(open_pending(&k2, &blob).is_err());
	}

	#[test]
	fn pending_tamper_rejected() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key = derive_pending_key(&keychain).unwrap();
		let mut blob = seal_pending(&key, b"payload").unwrap();
		// Flip a ciphertext byte; AEAD must reject.
		let last = blob.len() - 1;
		blob[last] ^= 0x01;
		assert!(open_pending(&key, &blob).is_err());
	}
}
