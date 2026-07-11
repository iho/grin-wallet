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
//! ## At-rest encryption (C-03 / C-08)
//!
//! - **Pending DKG file** and **LMDB ceremony state** are sealed with
//!   ChaCha20-Poly1305 under a keychain-derived key (authenticated encryption).
//! - Plaintext JSON is zeroized after sealing.
//! - XOR-only obfuscation of shares is **removed** — it had no integrity and
//!   bit-flips silently corrupted secrets.

use crate::blake2::blake2b::Blake2b;
use crate::grin_core::ser;
use crate::grin_keychain::{Keychain, SwitchCommitmentType};
use crate::Error;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use super::types::{CeremonyId, MultisigWalletState};

/// LMDB key prefix for multisig wallet states (`m` = 0x6d).
pub const MULTISIG_PREFIX: u8 = b'm';

/// Size of the symmetric key used for AEAD (bytes).
pub const PENDING_KEY_SIZE: usize = 32;
/// Alias for the state-storage key size (same cipher).
pub const STATE_KEY_SIZE: usize = PENDING_KEY_SIZE;
/// ChaCha20-Poly1305 nonce size (bytes).
const AEAD_NONCE_SIZE: usize = 12;
/// Poly1305 tag size (bytes).
const AEAD_TAG_SIZE: usize = 16;

/// Magic prefix for AEAD-sealed multisig state blobs in LMDB / export files.
pub const STATE_SEAL_MAGIC: &[u8; 4] = b"MSAE";
/// Sealed-state format version.
pub const STATE_SEAL_VERSION: u8 = 1;

/// Derive a 32-byte symmetric key from the wallet keychain for at-rest
/// encryption of pending DKG ceremony state (C-03).
pub fn derive_pending_key<K: Keychain>(keychain: &K) -> Result<[u8; PENDING_KEY_SIZE], Error> {
	derive_domain_key(keychain, b"grin-msig/pending-key-v1")
}

/// Derive a 32-byte key for LMDB / backup sealing of completed ceremony state (C-08).
pub fn derive_state_key<K: Keychain>(keychain: &K) -> Result<[u8; STATE_KEY_SIZE], Error> {
	derive_domain_key(keychain, b"grin-msig/state-key-v1")
}

fn derive_domain_key<K: Keychain>(
	keychain: &K,
	domain: &[u8],
) -> Result<[u8; PENDING_KEY_SIZE], Error> {
	let root_key = keychain.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;
	let mut hasher = Blake2b::new(PENDING_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(domain);
	let out = hasher.finalize();
	let mut ret = [0u8; PENDING_KEY_SIZE];
	ret.copy_from_slice(&out.as_bytes()[0..PENDING_KEY_SIZE]);
	Ok(ret)
}

/// Encrypt bytes: output is `nonce(12) || ciphertext || tag`.
pub fn seal_pending(key: &[u8; PENDING_KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
	seal_aead(key, plaintext)
}

/// Decrypt bytes produced by [`seal_pending`].
pub fn open_pending(key: &[u8; PENDING_KEY_SIZE], blob: &[u8]) -> Result<Vec<u8>, Error> {
	open_aead(key, blob)
}

fn seal_aead(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
	let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
	let mut nonce_bytes = [0u8; AEAD_NONCE_SIZE];
	rand::thread_rng().fill_bytes(&mut nonce_bytes);
	let ct = cipher
		.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
		.map_err(|e| Error::Multisig(format!("aead seal failed: {:?}", e)))?;
	let mut out = Vec::with_capacity(AEAD_NONCE_SIZE + ct.len());
	out.extend_from_slice(&nonce_bytes);
	out.extend_from_slice(&ct);
	Ok(out)
}

fn open_aead(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Error> {
	if blob.len() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
		return Err(Error::Multisig("aead blob too short".into()));
	}
	let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
	let nonce = Nonce::from_slice(&blob[0..AEAD_NONCE_SIZE]);
	cipher
		.decrypt(nonce, &blob[AEAD_NONCE_SIZE..])
		.map_err(|_| Error::Multisig("aead decrypt failed (wrong key or corrupt data)".into()))
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

/// AEAD-sealed multisig state for LMDB / file export (C-08).
///
/// On-disk layout: `magic(4) || version(1) || nonce||ct||tag`.
#[derive(Clone)]
pub struct EncryptedMultisigState {
	/// Full sealed blob including magic + version.
	pub sealed: Vec<u8>,
}

impl EncryptedMultisigState {
	/// Seal a wallet state under a keychain-derived state key.
	pub fn seal<K: Keychain>(
		keychain: &K,
		state: &MultisigWalletState,
	) -> Result<Self, Error> {
		let key = derive_state_key(keychain)?;
		Self::seal_with_key(&key, state)
	}

	/// Seal with an explicit 32-byte key (tests / export).
	pub fn seal_with_key(
		key: &[u8; STATE_KEY_SIZE],
		state: &MultisigWalletState,
	) -> Result<Self, Error> {
		let mut plaintext = serde_json::to_vec(state)
			.map_err(|e| Error::Multisig(format!("ser state for seal: {}", e)))?;
		let body = seal_aead(key, &plaintext)?;
		plaintext.zeroize();
		let mut sealed = Vec::with_capacity(5 + body.len());
		sealed.extend_from_slice(STATE_SEAL_MAGIC);
		sealed.push(STATE_SEAL_VERSION);
		sealed.extend_from_slice(&body);
		Ok(Self { sealed })
	}

	/// Open a sealed blob with a keychain-derived state key.
	pub fn open<K: Keychain>(&self, keychain: &K) -> Result<MultisigWalletState, Error> {
		let key = derive_state_key(keychain)?;
		self.open_with_key(&key)
	}

	/// Open with an explicit key.
	pub fn open_with_key(&self, key: &[u8; STATE_KEY_SIZE]) -> Result<MultisigWalletState, Error> {
		if self.sealed.len() < 5 + AEAD_NONCE_SIZE + AEAD_TAG_SIZE {
			return Err(Error::Multisig("sealed multisig state too short".into()));
		}
		if &self.sealed[0..4] != STATE_SEAL_MAGIC {
			return Err(Error::Multisig(
				"not an AEAD-sealed multisig state (missing MSAE magic); \
				 pre-C-08 XOR-obfuscated blobs are no longer supported"
					.into(),
			));
		}
		if self.sealed[4] != STATE_SEAL_VERSION {
			return Err(Error::Multisig(format!(
				"unsupported sealed multisig version {}",
				self.sealed[4]
			)));
		}
		let mut plaintext = open_aead(key, &self.sealed[5..])?;
		let state: MultisigWalletState = serde_json::from_slice(&plaintext)
			.map_err(|e| Error::Multisig(format!("parse sealed state: {}", e)))?;
		plaintext.zeroize();
		Ok(state)
	}
}

impl ser::Writeable for EncryptedMultisigState {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&self.sealed)
	}
}

impl ser::Readable for EncryptedMultisigState {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<EncryptedMultisigState, ser::Error> {
		let sealed = reader.read_bytes_len_prefix()?;
		Ok(EncryptedMultisigState { sealed })
	}
}

/// Encrypt ceremony state for LMDB (AEAD, C-08).
pub fn encrypt_for_storage<K: Keychain>(
	keychain: &K,
	state: &MultisigWalletState,
) -> Result<EncryptedMultisigState, Error> {
	EncryptedMultisigState::seal(keychain, state)
}

/// Decrypt ceremony state loaded from LMDB (AEAD, C-08).
pub fn decrypt_from_storage<K: Keychain>(
	keychain: &K,
	encrypted: &EncryptedMultisigState,
) -> Result<MultisigWalletState, Error> {
	encrypted.open(keychain)
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
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let original = states[0].clone();

		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let encrypted = encrypt_for_storage(&keychain, &original).unwrap();
		// Sealed blob must not contain raw share bytes.
		assert!(encrypted.sealed.windows(32).all(|w| w != &original.shares[0].y.0[..]));
		assert_eq!(&encrypted.sealed[0..4], STATE_SEAL_MAGIC);

		let decrypted = decrypt_from_storage(&keychain, &encrypted).unwrap();
		assert_eq!(decrypted.shares[0].y.0, original.shares[0].y.0);
		assert_eq!(decrypted.shares[0].x.0, original.shares[0].x.0);
		assert_eq!(decrypted.config.ceremony_id.0, original.config.ceremony_id.0);
	}

	#[test]
	fn sealed_state_wrong_key_rejected() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let kc1 = ExtKeychain::from_random_seed(false).unwrap();
		let kc2 = ExtKeychain::from_random_seed(false).unwrap();
		let sealed = encrypt_for_storage(&kc1, &states[0]).unwrap();
		assert!(decrypt_from_storage(&kc2, &sealed).is_err());
	}

	#[test]
	fn sealed_state_tamper_rejected() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, CeremonyId::new(), params, actors).unwrap();
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let mut sealed = encrypt_for_storage(&keychain, &states[0]).unwrap();
		let last = sealed.sealed.len() - 1;
		sealed.sealed[last] ^= 0x5a;
		assert!(decrypt_from_storage(&keychain, &sealed).is_err());
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
		assert!(blob.len() > plaintext.len() + AEAD_NONCE_SIZE);
		assert!(blob.windows(plaintext.len()).all(|w| w != &plaintext[..]));
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
		assert!(open_pending(&k2, &blob).is_err());
	}

	#[test]
	fn pending_tamper_rejected() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key = derive_pending_key(&keychain).unwrap();
		let mut blob = seal_pending(&key, b"payload").unwrap();
		let last = blob.len() - 1;
		blob[last] ^= 0x01;
		assert!(open_pending(&key, &blob).is_err());
	}

	#[test]
	fn state_and_pending_keys_differ() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let p = derive_pending_key(&keychain).unwrap();
		let s = derive_state_key(&keychain).unwrap();
		assert_ne!(p, s);
	}
}
