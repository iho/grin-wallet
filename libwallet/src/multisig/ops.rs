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

//! High-level multisig wallet operations used by the CLI / Owner API.
//!
//! Pending DKG sessions are stored **AEAD-encrypted** (ChaCha20-Poly1305 under
//! a keychain-derived key; see C-03) as `{wallet_data}/multisig/pending_dkg.enc`.
//! Reading or writing the pending file therefore requires an unlocked wallet.
//! Completed ceremonies are stored encrypted in LMDB via
//! [`WalletOutputBatch::save_multisig_state`].

use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::{ContextFlag, Secp256k1};
use crate::grin_util::ToHex;
use crate::slatepack::SlatepackAddress;
use crate::types::WalletBackend;
use crate::Error;
use ed25519_dalek::SecretKey as EdSecretKey;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::dkg::{
	dealer_partial_share, generate_dealer_contribution, run_dkg_local, verify_pop, DealerSecrets,
};
use super::messages::{
	build_dkg_contribution, build_dkg_partial_share, parse_dkg_contribution, seckey_from_hex,
	seckey_to_hex, MultisigBody, MultisigEnvelope,
};
use super::poly::{verify_share, PublicPoly, SecretPoly};
use super::types::{
	ActorId, CeremonyId, MultisigConfig, MultisigWalletState, SecretShare, ThresholdParams,
};

const MULTISIG_DIR: &str = "multisig";
/// Encrypted pending-DKG state (C-03). Older builds used a plaintext
/// `pending_dkg.json`; that path is no longer written and is removed on clear.
const PENDING_FILE: &str = "pending_dkg.enc";
const LEGACY_PENDING_FILE: &str = "pending_dkg.json";

/// Symmetric key for pending-ceremony encryption (keychain-derived).
pub type PendingKey = [u8; super::store::PENDING_KEY_SIZE];

/// Summary of a stored ceremony for listing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonySummary {
	/// Ceremony UUID string.
	pub ceremony_id: String,
	/// Threshold M.
	pub threshold: usize,
	/// Total actors N.
	pub total_actors: usize,
	/// This wallet's actor label.
	pub my_label: String,
	/// Number of shares held.
	pub num_shares: usize,
}

/// Pending multi-party DKG session (filesystem).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDkg {
	/// Ceremony id.
	pub ceremony_id: CeremonyId,
	/// Threshold params.
	pub params: ThresholdParams,
	/// Ordered actor roster (must match all parties).
	pub actors: Vec<ActorId>,
	/// This wallet's actor index in `actors`.
	pub my_index: usize,
	/// This dealer's secret coefficients (hex) — sensitive.
	pub my_coeff_hexes: Vec<String>,
	/// Collected contributions by actor index (None if not yet received).
	pub contributions: Vec<Option<StoredContribution>>,
	/// Received final share y values for my x-coordinates (hex), one per share_index.
	pub my_share_ys_hex: Vec<Option<String>>,
	/// Dealer actor indices whose partial share has already been summed into
	/// `my_share_ys_hex`, per share_index. Used to reject duplicate/replayed
	/// shares, which would otherwise double-count into the accumulator (C-04).
	#[serde(default)]
	pub applied_share_dealers: Vec<Vec<usize>>,
}

/// Stored public contribution for pending DKG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredContribution {
	/// Actor label.
	pub actor: ActorId,
	/// Commitment compressed hexes.
	pub commitment_hexes: Vec<String>,
	/// PoP DER hexes.
	pub pop_sig_hexes: Vec<String>,
}

fn multisig_dir(wallet_data_dir: &str) -> PathBuf {
	Path::new(wallet_data_dir).join(MULTISIG_DIR)
}

fn pending_path(wallet_data_dir: &str) -> PathBuf {
	multisig_dir(wallet_data_dir).join(PENDING_FILE)
}

/// Ensure multisig directory exists.
pub fn ensure_multisig_dir(wallet_data_dir: &str) -> Result<PathBuf, Error> {
	let d = multisig_dir(wallet_data_dir);
	fs::create_dir_all(&d).map_err(|e| Error::Multisig(format!("mkdir: {}", e)))?;
	Ok(d)
}

/// Load and decrypt pending DKG if present.
///
/// `key` is the keychain-derived pending key (see [`super::store::derive_pending_key`]);
/// the on-disk file is AEAD-encrypted (C-03).
pub fn load_pending(wallet_data_dir: &str, key: &PendingKey) -> Result<Option<PendingDkg>, Error> {
	let p = pending_path(wallet_data_dir);
	if !p.exists() {
		return Ok(None);
	}
	let mut f = File::open(&p).map_err(|e| Error::Multisig(format!("open pending: {}", e)))?;
	let mut blob = Vec::new();
	f.read_to_end(&mut blob)
		.map_err(|e| Error::Multisig(format!("read pending: {}", e)))?;
	let plaintext = super::store::open_pending(key, &blob)?;
	let pending: PendingDkg = serde_json::from_slice(&plaintext)
		.map_err(|e| Error::Multisig(format!("parse pending: {}", e)))?;
	Ok(Some(pending))
}

/// Encrypt and save pending DKG.
pub fn save_pending(
	wallet_data_dir: &str,
	key: &PendingKey,
	pending: &PendingDkg,
) -> Result<(), Error> {
	ensure_multisig_dir(wallet_data_dir)?;
	let p = pending_path(wallet_data_dir);
	let plaintext =
		serde_json::to_vec(pending).map_err(|e| Error::Multisig(format!("ser pending: {}", e)))?;
	let blob = super::store::seal_pending(key, &plaintext)?;
	let mut f = File::create(&p).map_err(|e| Error::Multisig(format!("create pending: {}", e)))?;
	f.write_all(&blob)
		.map_err(|e| Error::Multisig(format!("write pending: {}", e)))?;
	Ok(())
}

/// Clear pending DKG file (both current encrypted and any legacy plaintext).
pub fn clear_pending(wallet_data_dir: &str) -> Result<(), Error> {
	let p = pending_path(wallet_data_dir);
	if p.exists() {
		fs::remove_file(&p).map_err(|e| Error::Multisig(format!("rm pending: {}", e)))?;
	}
	let legacy = multisig_dir(wallet_data_dir).join(LEGACY_PENDING_FILE);
	if legacy.exists() {
		let _ = fs::remove_file(&legacy);
	}
	Ok(())
}

/// List completed ceremonies in LMDB.
pub fn list_ceremonies<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
) -> Result<Vec<CeremonySummary>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	// Touch keychain
	let _ = w.keychain(keychain_mask)?;
	let ids = w.list_multisig_ceremonies()?;
	let mut out = Vec::new();
	for id in ids {
		match w.get_multisig_state(keychain_mask, &id) {
			Ok(st) => out.push(CeremonySummary {
				ceremony_id: st.config.ceremony_id.0.to_string(),
				threshold: st.config.params.threshold,
				total_actors: st.config.params.total_actors,
				my_label: st.my_actor.label.clone(),
				num_shares: st.shares.len(),
			}),
			Err(e) => {
				warn!("skip ceremony {}: {}", id.0, e);
			}
		}
	}
	Ok(out)
}

/// Load and return a full multisig state.
pub fn get_state<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	ceremony_id: &CeremonyId,
) -> Result<MultisigWalletState, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	w.get_multisig_state(keychain_mask, ceremony_id)
}

/// Delete a completed ceremony from LMDB.
pub fn delete_ceremony<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	ceremony_id: &CeremonyId,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut batch = w.batch(keychain_mask)?;
	batch.delete_multisig_state(ceremony_id)?;
	batch.commit()?;
	Ok(())
}

/// Local simulation: run full DKG for N actors, save actor `my_index` to LMDB.
///
/// Intended for development / single-machine testing only.
pub fn init_local_sim<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	threshold: usize,
	total: usize,
	my_index: usize,
	shares_per_actor: Option<usize>,
) -> Result<MultisigWalletState, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	if my_index >= total {
		return Err(Error::Multisig("my_index out of range".into()));
	}
	let spa = shares_per_actor
		.unwrap_or_else(|| ThresholdParams::recommended_shares_per_actor(threshold));
	let params = ThresholdParams::with_shares_per_actor(threshold, total, spa)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let ceremony = CeremonyId::new();
	let actors: Vec<_> = (0..total as u32).map(ActorId::from_index).collect();
	let states = run_dkg_local(&secp, ceremony, params, actors)?;
	let mine = states[my_index].clone();
	let mut batch = w.batch(keychain_mask)?;
	batch.save_multisig_state(&mine)?;
	batch.commit()?;
	Ok(mine)
}

/// Start multi-party DKG: create this actor's contribution and pending session.
///
/// All participants must use the same `ceremony_id` (if provided) and the same
/// `(threshold, total, shares_per_actor)` so actor indices align.
///
/// Writes contribution envelope JSON to `out_contrib_path`.
pub fn dkg_start(
	wallet_data_dir: &str,
	key: &PendingKey,
	sign_key: Option<&EdSecretKey>,
	threshold: usize,
	total: usize,
	my_index: usize,
	shares_per_actor: Option<usize>,
	addresses: Option<Vec<String>>,
	ceremony_id: Option<CeremonyId>,
	out_contrib_path: &str,
) -> Result<PendingDkg, Error> {
	if my_index >= total {
		return Err(Error::Multisig("my_index out of range".into()));
	}
	if load_pending(wallet_data_dir, key)?.is_some() {
		return Err(Error::Multisig(
			"pending DKG already exists; finalize or clear first".into(),
		));
	}
	let spa = shares_per_actor
		.unwrap_or_else(|| ThresholdParams::recommended_shares_per_actor(threshold));
	let params = ThresholdParams::with_shares_per_actor(threshold, total, spa)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let ceremony = ceremony_id.unwrap_or_else(CeremonyId::new);
	// Address-based roster enables encrypted share delivery (C-02). All parties
	// must agree on the same ordered roster so x-coordinates align. The
	// index-only fallback is dev/local-sim and cannot export shares.
	let actors: Vec<ActorId> = match &addresses {
		Some(list) => {
			if list.len() != total {
				return Err(Error::Multisig(format!(
					"expected {} actor addresses, got {}",
					total,
					list.len()
				)));
			}
			let mut v = Vec::with_capacity(total);
			for s in list {
				let addr = SlatepackAddress::try_from(s.as_str())
					.map_err(|e| Error::Multisig(format!("bad actor address '{}': {}", s, e)))?;
				v.push(ActorId::from_slatepack_address(&addr)?);
			}
			v
		}
		None => (0..total as u32).map(ActorId::from_index).collect(),
	};
	let my_actor = actors[my_index].clone();

	let (secrets, contrib) =
		generate_dealer_contribution(&secp, &ceremony, my_actor.clone(), &params)?;
	verify_pop(&secp, &ceremony, &contrib, params.num_coefficients())?;

	let mut contributions = vec![None; total];
	contributions[my_index] = Some(StoredContribution {
		actor: my_actor.clone(),
		commitment_hexes: contrib
			.commitments
			.coefficients
			.iter()
			.map(|c| c.to_hex())
			.collect(),
		pop_sig_hexes: contrib.pops.iter().map(|p| p.sig.to_hex()).collect(),
	});

	let pending = PendingDkg {
		ceremony_id: ceremony.clone(),
		params: params.clone(),
		actors,
		my_index,
		my_coeff_hexes: secrets
			.poly
			.coeffs
			.iter()
			.map(|c| seckey_to_hex(c))
			.collect(),
		contributions,
		my_share_ys_hex: vec![None; params.shares_per_actor],
		applied_share_dealers: vec![Vec::new(); params.shares_per_actor],
	};
	save_pending(wallet_data_dir, key, &pending)?;

	let mut env = build_dkg_contribution(&secp, ceremony, my_actor.clone(), params, &contrib)?;
	// Authenticate the broadcast contribution when the roster is address-based
	// (C-04). Index/dev rosters cannot be signed and stay unsigned.
	if my_actor.slatepack_address().is_ok() {
		let sk = sign_key.ok_or_else(|| {
			Error::Multisig("address-based DKG requires the wallet slatepack key to sign".into())
		})?;
		env.sign(sk)?;
	}
	write_envelope_file(out_contrib_path, &env)?;
	Ok(pending)
}

/// Import another actor's DKG contribution into pending.
pub fn dkg_import_contrib(
	wallet_data_dir: &str,
	key: &PendingKey,
	envelope: &MultisigEnvelope,
) -> Result<PendingDkg, Error> {
	let mut pending = load_pending(wallet_data_dir, key)?
		.ok_or_else(|| Error::Multisig("no pending DKG; run dkg-start first".into()))?;
	if envelope.ceremony_id != pending.ceremony_id.0 {
		return Err(Error::Multisig("ceremony_id mismatch".into()));
	}
	let msg = match &envelope.body {
		MultisigBody::DkgContribution(m) => m,
		_ => return Err(Error::Multisig("envelope is not a DkgContribution".into())),
	};
	let actor = envelope.sender.clone();
	let idx = pending
		.actors
		.iter()
		.position(|a| a.id == actor.id)
		.ok_or_else(|| Error::Multisig(format!("unknown actor {}", actor.label)))?;

	// Authenticate the sender against the trusted roster entry (C-04). For an
	// address-based ceremony a valid signature is mandatory; index/dev rosters
	// cannot be authenticated and are accepted unsigned.
	if pending.actors[idx].slatepack_address().is_ok() {
		envelope.verify_signature()?;
	}

	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let contrib = parse_dkg_contribution(msg, actor.clone())?;
	verify_pop(
		&secp,
		&pending.ceremony_id,
		&contrib,
		pending.params.num_coefficients(),
	)?;

	let new_commit_hexes: Vec<String> = contrib
		.commitments
		.coefficients
		.iter()
		.map(|c| c.to_hex())
		.collect();

	// Reject equivocation: a second, *different* contribution from the same
	// actor must not silently overwrite the first (C-04).
	if let Some(existing) = &pending.contributions[idx] {
		if existing.commitment_hexes != new_commit_hexes {
			return Err(Error::Multisig(format!(
				"actor {} already submitted a different contribution (equivocation)",
				actor.label
			)));
		}
		return Ok(pending); // idempotent re-import of the identical contribution
	}

	pending.contributions[idx] = Some(StoredContribution {
		actor,
		commitment_hexes: new_commit_hexes,
		pop_sig_hexes: contrib.pops.iter().map(|p| p.sig.to_hex()).collect(),
	});
	save_pending(wallet_data_dir, key, &pending)?;
	Ok(pending)
}

fn restore_dealer_secrets(pending: &PendingDkg) -> Result<DealerSecrets, Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let mut coeffs = Vec::new();
	for h in &pending.my_coeff_hexes {
		coeffs.push(seckey_from_hex(&secp, h)?);
	}
	Ok(DealerSecrets {
		actor: pending.actors[pending.my_index].clone(),
		poly: SecretPoly { coeffs },
	})
}

fn all_contributions_ready(pending: &PendingDkg) -> bool {
	pending.contributions.iter().all(|c| c.is_some())
}

/// After all contributions are collected, export partial shares for every other actor.
///
/// Each partial share is a **secret** dealer evaluation, so it is written as an
/// age-encrypted, armored Slatepack addressed to the recipient actor
/// (`{out_dir}/share_to_actor{i}_s{k}.slatepack`) — never plaintext (C-02).
/// This requires an address-based roster; an index-only roster (dev/local-sim)
/// is rejected because such actors have no encryption key. `sender_address` is
/// this wallet's own Slatepack address, stamped on the outgoing packs;
/// `sign_key` is the matching secret key, used to authenticate each share
/// before it is encrypted (C-04, sign-then-encrypt).
pub fn dkg_export_shares(
	wallet_data_dir: &str,
	key: &PendingKey,
	sender_address: &SlatepackAddress,
	sign_key: &EdSecretKey,
	out_dir: &str,
) -> Result<Vec<String>, Error> {
	let pending = load_pending(wallet_data_dir, key)?
		.ok_or_else(|| Error::Multisig("no pending DKG".into()))?;
	if !all_contributions_ready(&pending) {
		return Err(Error::Multisig(
			"not all DKG contributions received yet".into(),
		));
	}

	// Fail before writing anything if any recipient lacks a Slatepack address.
	let mut recipients = Vec::with_capacity(pending.actors.len());
	for (i, actor) in pending.actors.iter().enumerate() {
		if i == pending.my_index {
			recipients.push(None);
			continue;
		}
		recipients.push(Some(actor.slatepack_address()?));
	}

	fs::create_dir_all(out_dir).map_err(|e| Error::Multisig(format!("mkdir: {}", e)))?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let secrets = restore_dealer_secrets(&pending)?;
	let sender = pending.actors[pending.my_index].clone();
	let mut paths = Vec::new();

	for (i, actor) in pending.actors.iter().enumerate() {
		if i == pending.my_index {
			continue;
		}
		let recipient_addr = recipients[i]
			.clone()
			.expect("recipient address resolved above");
		for share_index in 0..pending.params.shares_per_actor {
			let x = actor.x_coordinate_share(&secp, share_index)?;
			let y = dealer_partial_share(&secp, &secrets, &x)?;
			let mut env = build_dkg_partial_share(
				pending.ceremony_id.clone(),
				sender.clone(),
				actor.clone(),
				share_index,
				&y,
				&x,
			);
			env.sign(sign_key)?;
			let armored =
				env.to_armored_string(Some(sender_address.clone()), vec![recipient_addr.clone()])?;
			let path =
				Path::new(out_dir).join(format!("share_to_actor{}_s{}.slatepack", i, share_index));
			let mut f = File::create(&path)
				.map_err(|e| Error::Multisig(format!("create share file: {}", e)))?;
			f.write_all(armored.as_bytes())
				.map_err(|e| Error::Multisig(format!("write share file: {}", e)))?;
			paths.push(path.display().to_string());
		}
	}
	Ok(paths)
}

/// Import a partial share addressed to this actor (from another dealer).
pub fn dkg_import_share(
	wallet_data_dir: &str,
	key: &PendingKey,
	envelope: &MultisigEnvelope,
) -> Result<PendingDkg, Error> {
	let mut pending = load_pending(wallet_data_dir, key)?
		.ok_or_else(|| Error::Multisig("no pending DKG".into()))?;
	if envelope.ceremony_id != pending.ceremony_id.0 {
		return Err(Error::Multisig("ceremony_id mismatch".into()));
	}
	let msg = match &envelope.body {
		MultisigBody::DkgPartialShare(m) => m,
		_ => return Err(Error::Multisig("not a DkgPartialShare".into())),
	};
	let me = &pending.actors[pending.my_index];
	if msg.recipient.id != me.id {
		return Err(Error::Multisig("share not addressed to this actor".into()));
	}
	let share_index = msg.share_index;
	if share_index >= pending.params.shares_per_actor {
		return Err(Error::Multisig("share_index out of range".into()));
	}

	// Identify the dealer (sender) in the trusted roster and authenticate it.
	let dealer_idx = pending
		.actors
		.iter()
		.position(|a| a.id == envelope.sender.id)
		.ok_or_else(|| Error::Multisig(format!("unknown dealer {}", envelope.sender.label)))?;
	if pending.actors[dealer_idx].slatepack_address().is_ok() {
		envelope.verify_signature()?;
	}

	// Reject duplicate/replayed shares: applying the same dealer's partial twice
	// would double-count into the accumulator and corrupt the final share (C-04).
	if pending.applied_share_dealers.len() != pending.params.shares_per_actor {
		pending.applied_share_dealers = vec![Vec::new(); pending.params.shares_per_actor];
	}
	if pending.applied_share_dealers[share_index].contains(&dealer_idx) {
		return Err(Error::Multisig(format!(
			"duplicate share from dealer {} for share_index {} (replay)",
			envelope.sender.label, share_index
		)));
	}

	// Accumulate partials: running sum of received dealer partials.
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let part = seckey_from_hex(&secp, &msg.share_hex)?;
	let existing = &pending.my_share_ys_hex[share_index];
	let sum = match existing {
		Some(h) => {
			let prev = seckey_from_hex(&secp, h)?;
			super::scalar::sk_add(&secp, &prev, &part)?
		}
		None => part,
	};
	pending.my_share_ys_hex[share_index] = Some(seckey_to_hex(&sum));
	pending.applied_share_dealers[share_index].push(dealer_idx);
	save_pending(wallet_data_dir, key, &pending)?;
	Ok(pending)
}

/// After all shares received, also add our own dealer partials to ourselves, verify, save LMDB.
pub fn dkg_finalize<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
) -> Result<MultisigWalletState, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let key = {
		let keychain = w.keychain(keychain_mask)?;
		super::store::derive_pending_key(&keychain)?
	};
	let pending = load_pending(wallet_data_dir, &key)?
		.ok_or_else(|| Error::Multisig("no pending DKG".into()))?;
	if !all_contributions_ready(&pending) {
		return Err(Error::Multisig("missing contributions".into()));
	}
	for (i, s) in pending.my_share_ys_hex.iter().enumerate() {
		if s.is_none() && pending.params.total_actors > 1 {
			// Still need our own dealer contribution to ourselves
			let _ = i;
		}
	}

	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let secrets = restore_dealer_secrets(&pending)?;

	// Rebuild public poly from all contributions
	let mut public_poly: Option<PublicPoly> = None;
	for c in pending.contributions.iter() {
		let c = c.as_ref().unwrap();
		let coefficients: Result<Vec<Vec<u8>>, Error> = c
			.commitment_hexes
			.iter()
			.map(|h| {
				crate::grin_util::from_hex(h).map_err(|e| Error::Multisig(format!("hex: {}", e)))
			})
			.collect();
		let pp = PublicPoly {
			coefficients: coefficients?,
		};
		public_poly = Some(match public_poly {
			None => pp,
			Some(acc) => acc.add(&secp, &pp)?,
		});
	}
	let public_poly = public_poly.unwrap();

	// For each share_index, sum: all imported partials + our own dealer partial
	let me = &pending.actors[pending.my_index];
	let mut shares = Vec::new();
	for share_index in 0..pending.params.shares_per_actor {
		let x = me.x_coordinate_share(&secp, share_index)?;
		// Own dealer contribution to self
		let mut y = dealer_partial_share(&secp, &secrets, &x)?;
		// Plus accumulated from others (if any imported)
		if let Some(ref h) = pending.my_share_ys_hex[share_index] {
			let others = seckey_from_hex(&secp, h)?;
			y = super::scalar::sk_add(&secp, &y, &others)?;
		} else if pending.params.total_actors > 1 {
			return Err(Error::Multisig(format!(
				"missing imported shares for share_index {}",
				share_index
			)));
		}
		if !verify_share(&secp, &public_poly, &x, &y)? {
			return Err(Error::Multisig(format!(
				"share verification failed for share {}",
				share_index
			)));
		}
		shares.push(SecretShare { share_index, x, y });
	}

	let state = MultisigWalletState {
		config: MultisigConfig {
			ceremony_id: pending.ceremony_id.clone(),
			params: pending.params.clone(),
			actors: pending.actors.clone(),
			public_poly,
		},
		my_actor: me.clone(),
		shares,
	};
	state.config.validate()?;

	let mut batch = w.batch(keychain_mask)?;
	batch.save_multisig_state(&state)?;
	batch.commit()?;
	clear_pending(wallet_data_dir)?;
	Ok(state)
}

/// Write MultisigEnvelope JSON to path.
pub fn write_envelope_file(path: &str, env: &MultisigEnvelope) -> Result<(), Error> {
	let s = serde_json::to_string_pretty(env)
		.map_err(|e| Error::Multisig(format!("ser envelope: {}", e)))?;
	let mut f = File::create(path).map_err(|e| Error::Multisig(format!("create: {}", e)))?;
	f.write_all(s.as_bytes())
		.map_err(|e| Error::Multisig(format!("write: {}", e)))?;
	Ok(())
}

/// Read MultisigEnvelope JSON from path (also accepts raw GMS1 payload).
pub fn read_envelope_file(path: &str) -> Result<MultisigEnvelope, Error> {
	let mut f = File::open(path).map_err(|e| Error::Multisig(format!("open: {}", e)))?;
	let mut s = String::new();
	f.read_to_string(&mut s)
		.map_err(|e| Error::Multisig(format!("read: {}", e)))?;
	// Try plain JSON envelope first
	if let Ok(env) = serde_json::from_str::<MultisigEnvelope>(&s) {
		return Ok(env);
	}
	// Try GMS1 payload
	MultisigEnvelope::from_payload_bytes(s.trim().as_bytes())
		.or_else(|_| MultisigEnvelope::from_payload_bytes(s.as_bytes()))
}

/// Read an age-encrypted, armored Slatepack share file and decrypt it to the
/// underlying envelope using this wallet's Slatepack secret key (C-02).
pub fn read_encrypted_share_file(
	path: &str,
	dec_key: &EdSecretKey,
) -> Result<MultisigEnvelope, Error> {
	let mut f = File::open(path).map_err(|e| Error::Multisig(format!("open share: {}", e)))?;
	let mut s = String::new();
	f.read_to_string(&mut s)
		.map_err(|e| Error::Multisig(format!("read share: {}", e)))?;
	MultisigEnvelope::from_armored_string(&s, Some(dec_key))
}

/// Export a completed ceremony state as JSON (plaintext shares — sensitive!).
pub fn export_state_json(state: &MultisigWalletState, path: &str) -> Result<(), Error> {
	let s = serde_json::to_string_pretty(state)
		.map_err(|e| Error::Multisig(format!("ser state: {}", e)))?;
	let mut f = File::create(path).map_err(|e| Error::Multisig(format!("create: {}", e)))?;
	f.write_all(s.as_bytes())
		.map_err(|e| Error::Multisig(format!("write: {}", e)))?;
	Ok(())
}

/// Import ceremony state JSON into LMDB.
pub fn import_state_json<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	path: &str,
) -> Result<MultisigWalletState, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut f = File::open(path).map_err(|e| Error::Multisig(format!("open: {}", e)))?;
	let mut s = String::new();
	f.read_to_string(&mut s)
		.map_err(|e| Error::Multisig(format!("read: {}", e)))?;
	let state: MultisigWalletState =
		serde_json::from_str(&s).map_err(|e| Error::Multisig(format!("parse state: {}", e)))?;
	state.config.validate()?;
	let mut batch = w.batch(keychain_mask)?;
	batch.save_multisig_state(&state)?;
	batch.commit()?;
	Ok(state)
}

/// Resolve wallet_data directory from top-level directory.
pub fn wallet_data_dir(top_level: &str) -> PathBuf {
	// Match GRIN_WALLET_DIR constant used by lifecycle
	Path::new(top_level).join("wallet_data")
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_core::global;
	use std::convert::TryFrom;

	fn keypair(seed: u8) -> (EdSecretKey, SlatepackAddress) {
		let sk = EdSecretKey::from_bytes(&[seed; 32]).unwrap();
		let pk = ed25519_dalek::PublicKey::from(&sk);
		(sk, SlatepackAddress::new(&pk))
	}

	// Full 2-of-2 address-based DKG exchange over the file API, asserting the
	// C-04 properties: signed contributions verify, tampered/unsigned ones are
	// rejected, and a replayed share is refused instead of double-counted.
	#[test]
	fn dkg_exchange_authenticated_and_replay_safe() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let (sk0, addr0) = keypair(21);
		let (sk1, addr1) = keypair(22);
		let roster = vec![
			String::try_from(&addr0).unwrap(),
			String::try_from(&addr1).unwrap(),
		];

		let base = std::env::temp_dir().join(format!("msig_c04_{}", uuid::Uuid::new_v4()));
		let w0 = base.join("w0");
		let w1 = base.join("w1");
		std::fs::create_dir_all(&w0).unwrap();
		std::fs::create_dir_all(&w1).unwrap();
		let w0s = w0.to_str().unwrap();
		let w1s = w1.to_str().unwrap();
		let k0: PendingKey = [1u8; 32];
		let k1: PendingKey = [2u8; 32];
		let cid = CeremonyId::new();
		let c0 = w0.join("contrib0.json");
		let c1 = w1.join("contrib1.json");

		dkg_start(
			w0s,
			&k0,
			Some(&sk0),
			2,
			2,
			0,
			Some(1),
			Some(roster.clone()),
			Some(cid.clone()),
			c0.to_str().unwrap(),
		)
		.unwrap();
		dkg_start(
			w1s,
			&k1,
			Some(&sk1),
			2,
			2,
			1,
			Some(1),
			Some(roster.clone()),
			Some(cid.clone()),
			c1.to_str().unwrap(),
		)
		.unwrap();

		let env_c0 = read_envelope_file(c0.to_str().unwrap()).unwrap();
		let env_c1 = read_envelope_file(c1.to_str().unwrap()).unwrap();
		// The broadcast contribution is authenticated.
		env_c0.verify_signature().unwrap();

		// A tampered signature is rejected on import.
		let mut bad = env_c1.clone();
		bad.sig_hex = Some("00".repeat(64));
		assert!(dkg_import_contrib(w0s, &k0, &bad).is_err());
		// An unsigned contribution is rejected in an address-based ceremony.
		let mut unsigned = env_c1.clone();
		unsigned.sig_hex = None;
		assert!(dkg_import_contrib(w0s, &k0, &unsigned).is_err());

		// The genuine contributions import cleanly.
		dkg_import_contrib(w0s, &k0, &env_c1).unwrap();
		dkg_import_contrib(w1s, &k1, &env_c0).unwrap();

		// Actor 1 exports the share addressed to actor 0.
		let paths1 =
			dkg_export_shares(w1s, &k1, &addr1, &sk1, w1.join("out").to_str().unwrap()).unwrap();
		assert_eq!(paths1.len(), 1);

		let share_env = read_encrypted_share_file(&paths1[0], &sk0).unwrap();
		share_env.verify_signature().unwrap();
		dkg_import_share(w0s, &k0, &share_env).unwrap();
		// Replaying the same dealer's share must be rejected (no double-count).
		let err = dkg_import_share(w0s, &k0, &share_env).unwrap_err();
		match err {
			Error::Multisig(m) => assert!(m.contains("replay"), "unexpected: {}", m),
			_ => panic!("expected replay rejection"),
		}

		let _ = std::fs::remove_dir_all(&base);
	}
}
