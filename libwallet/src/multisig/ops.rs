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
// seckey_from_hex also used by rebuild_quorum_from_record
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
///
/// On disk this is always AEAD-encrypted (C-03). Debug redacts secret hex fields (C-08).
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for PendingDkg {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PendingDkg")
			.field("ceremony_id", &self.ceremony_id)
			.field("params", &self.params)
			.field("actors", &self.actors)
			.field("my_index", &self.my_index)
			.field("my_coeff_hexes", &"[redacted]")
			.field("contributions", &self.contributions)
			.field("my_share_ys_hex", &"[redacted]")
			.field("applied_share_dealers", &self.applied_share_dealers)
			.finish()
	}
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
	let mut plaintext = super::store::open_pending(key, &blob)?;
	let pending: PendingDkg = serde_json::from_slice(&plaintext)
		.map_err(|e| Error::Multisig(format!("parse pending: {}", e)))?;
	use zeroize::Zeroize;
	plaintext.zeroize();
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
	let mut plaintext =
		serde_json::to_vec(pending).map_err(|e| Error::Multisig(format!("ser pending: {}", e)))?;
	let blob = super::store::seal_pending(key, &plaintext)?;
	use zeroize::Zeroize;
	plaintext.zeroize();
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
///
/// Enforces C-12 size and structural caps.
pub fn read_envelope_file(path: &str) -> Result<MultisigEnvelope, Error> {
	let meta = fs::metadata(path).map_err(|e| Error::Multisig(format!("stat: {}", e)))?;
	if meta.len() as usize > super::messages::MAX_ENVELOPE_JSON_BYTES + 64 {
		return Err(Error::Multisig(format!(
			"envelope file too large ({} bytes)",
			meta.len()
		)));
	}
	let mut f = File::open(path).map_err(|e| Error::Multisig(format!("open: {}", e)))?;
	let mut s = String::new();
	f.read_to_string(&mut s)
		.map_err(|e| Error::Multisig(format!("read: {}", e)))?;
	// Try plain JSON envelope first (with C-12 caps).
	if let Ok(env) = MultisigEnvelope::from_json_str(&s) {
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

/// Export a completed ceremony state as an AEAD-sealed blob (C-08).
///
/// The file is binary: `MSAE || version || nonce||ciphertext||tag`, sealed under
/// a keychain-derived state key. **Plaintext share export is no longer offered.**
pub fn export_state_sealed<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	state: &MultisigWalletState,
	path: &str,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = w.keychain(keychain_mask)?;
	let sealed = super::store::EncryptedMultisigState::seal(&keychain, state)?;
	let mut f = File::create(path).map_err(|e| Error::Multisig(format!("create: {}", e)))?;
	f.write_all(&sealed.sealed)
		.map_err(|e| Error::Multisig(format!("write: {}", e)))?;
	Ok(())
}

/// Import an AEAD-sealed ceremony state into LMDB (C-08).
pub fn import_state_sealed<'a, T: ?Sized, C, K>(
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
	let mut sealed_bytes = Vec::new();
	f.read_to_end(&mut sealed_bytes)
		.map_err(|e| Error::Multisig(format!("read: {}", e)))?;
	let sealed = super::store::EncryptedMultisigState {
		sealed: sealed_bytes,
	};
	let keychain = w.keychain(keychain_mask)?;
	let state = sealed.open(&keychain)?;
	state.config.validate()?;
	let mut batch = w.batch(keychain_mask)?;
	batch.save_multisig_state(&state)?;
	batch.commit()?;
	Ok(state)
}

/// Backward-compatible name: sealed export (C-08). Prefer [`export_state_sealed`].
pub fn export_state_json<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	state: &MultisigWalletState,
	path: &str,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	export_state_sealed(w, keychain_mask, state, path)
}

/// Backward-compatible name: sealed import (C-08). Prefer [`import_state_sealed`].
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
	import_state_sealed(w, keychain_mask, path)
}

/// Resolve wallet_data directory from top-level directory.
pub fn wallet_data_dir(top_level: &str) -> PathBuf {
	// Match GRIN_WALLET_DIR constant used by lifecycle
	Path::new(top_level).join("wallet_data")
}

// ---------------------------------------------------------------------------
// Session lifecycle (WS4 CLI / API surface)
// ---------------------------------------------------------------------------

use super::session::{
	delete_session, list_session_ids, load_session, quorum_points_from_state, save_session,
	Negotiator, SessionKey, SessionStatus,
};
use super::store::derive_state_key;
use super::coin::CoinId;

/// Derive the session AEAD key (reuses state-key domain material).
pub fn derive_session_key<K: Keychain>(keychain: &K) -> Result<SessionKey, Error> {
	derive_state_key(keychain)
}

/// Result of starting a multiparty session (CreateOutput / Spend).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigSessionStartResult {
	/// Session status snapshot.
	pub status: SessionStatus,
	/// First outbound envelope as pretty JSON (exchange with peers).
	pub envelope_json: String,
}

/// Result of applying a peer envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigSessionApplyResult {
	/// Updated session status.
	pub status: SessionStatus,
	/// New outbound envelopes as pretty JSON (may be empty).
	pub outbound_json: Vec<String>,
}

/// Start a CreateOutput session; returns status + first envelope JSON.
pub fn session_create_output_raw<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	ceremony_id: &CeremonyId,
	coin_number: u64,
	coin_value: u64,
	session_tag: &str,
	quorum_indices: Option<&[usize]>,
) -> Result<MultisigSessionStartResult, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let state = get_state(w, keychain_mask, ceremony_id)?;
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let quorum = quorum_points_from_state(&secp, &state, quorum_indices)?;
	let coin = CoinId::new(coin_number, coin_value);
	let (neg, env) = Negotiator::create_output(
		&secp,
		&state.config.public_poly,
		&quorum,
		state.config.ceremony_id.clone(),
		state.config.actors.clone(),
		state.my_actor.clone(),
		coin,
		session_tag.as_bytes(),
	)?;
	save_session(wallet_data_dir, &session_key, &neg.record)?;
	let envelope_json = serde_json::to_string_pretty(&env)
		.map_err(|e| Error::Multisig(format!("ser envelope: {}", e)))?;
	Ok(MultisigSessionStartResult {
		status: neg.status(),
		envelope_json,
	})
}

/// Start a CreateOutput session; write our first outbound envelope to `out_path`.
pub fn session_create_output<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	ceremony_id: &CeremonyId,
	coin_number: u64,
	coin_value: u64,
	session_tag: &str,
	out_path: &str,
	quorum_indices: Option<&[usize]>,
) -> Result<SessionStatus, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let res = session_create_output_raw(
		w,
		keychain_mask,
		wallet_data_dir,
		ceremony_id,
		coin_number,
		coin_value,
		session_tag,
		quorum_indices,
	)?;
	let mut f = File::create(out_path).map_err(|e| Error::Multisig(format!("create: {}", e)))?;
	f.write_all(res.envelope_json.as_bytes())
		.map_err(|e| Error::Multisig(format!("write: {}", e)))?;
	Ok(res.status)
}

/// Start a Spend session; returns status + first envelope JSON.
pub fn session_create_spend_raw<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	ceremony_id: &CeremonyId,
	inputs: Vec<CoinId>,
	outputs: Vec<CoinId>,
	fee: u64,
	session_tag: &str,
	quorum_indices: Option<&[usize]>,
) -> Result<MultisigSessionStartResult, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let state = get_state(w, keychain_mask, ceremony_id)?;
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let quorum = quorum_points_from_state(&secp, &state, quorum_indices)?;
	let (neg, env) = Negotiator::create_spend(
		&secp,
		&state.config.public_poly,
		&quorum,
		state.config.ceremony_id.clone(),
		state.config.actors.clone(),
		state.my_actor.clone(),
		inputs,
		outputs,
		fee,
		session_tag.as_bytes(),
	)?;
	save_session(wallet_data_dir, &session_key, &neg.record)?;
	let envelope_json = serde_json::to_string_pretty(&env)
		.map_err(|e| Error::Multisig(format!("ser envelope: {}", e)))?;
	Ok(MultisigSessionStartResult {
		status: neg.status(),
		envelope_json,
	})
}

/// Start a Spend session; write our FROST commit to `out_path`.
pub fn session_create_spend<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	ceremony_id: &CeremonyId,
	inputs: Vec<CoinId>,
	outputs: Vec<CoinId>,
	fee: u64,
	session_tag: &str,
	out_path: &str,
	quorum_indices: Option<&[usize]>,
) -> Result<SessionStatus, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let res = session_create_spend_raw(
		w,
		keychain_mask,
		wallet_data_dir,
		ceremony_id,
		inputs,
		outputs,
		fee,
		session_tag,
		quorum_indices,
	)?;
	let mut f = File::create(out_path).map_err(|e| Error::Multisig(format!("create: {}", e)))?;
	f.write_all(res.envelope_json.as_bytes())
		.map_err(|e| Error::Multisig(format!("write: {}", e)))?;
	Ok(res.status)
}

/// Apply a peer envelope JSON string; returns status + outbound envelope JSONs.
pub fn session_apply_raw<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	session_id_hex: &str,
	peer_envelope_json: &str,
) -> Result<MultisigSessionApplyResult, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let session_id = crate::grin_util::from_hex(session_id_hex)
		.map_err(|e| Error::Multisig(format!("session id hex: {}", e)))?;
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let record = load_session(wallet_data_dir, &session_key, &session_id)?;
	let ceremony_id = record.ceremony_id.clone();
	let state = get_state(w, keychain_mask, &ceremony_id)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let quorum = rebuild_quorum_from_record(&secp, &state, &record)?;
	let mut neg = Negotiator::resume(&secp, &state.config.public_poly, &quorum, record)?;
	let env = MultisigEnvelope::from_json_str(peer_envelope_json)?;
	let outbound = neg.apply(&env)?;
	save_session(wallet_data_dir, &session_key, &neg.record)?;
	let mut outbound_json = Vec::new();
	for oenv in &outbound {
		outbound_json.push(
			serde_json::to_string_pretty(oenv)
				.map_err(|e| Error::Multisig(format!("ser outbound: {}", e)))?,
		);
	}
	Ok(MultisigSessionApplyResult {
		status: neg.status(),
		outbound_json,
	})
}

/// Apply a peer envelope file; write any new outbound messages to `out_dir`.
///
/// Returns `(status, paths of written outbound envelopes)`.
pub fn session_apply<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	session_id_hex: &str,
	peer_envelope_path: &str,
	out_dir: &str,
) -> Result<(SessionStatus, Vec<String>), Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut f = File::open(peer_envelope_path)
		.map_err(|e| Error::Multisig(format!("open peer envelope: {}", e)))?;
	let mut s = String::new();
	f.read_to_string(&mut s)
		.map_err(|e| Error::Multisig(format!("read peer envelope: {}", e)))?;
	let res = session_apply_raw(w, keychain_mask, wallet_data_dir, session_id_hex, &s)?;
	fs::create_dir_all(out_dir).map_err(|e| Error::Multisig(format!("mkdir out: {}", e)))?;
	let mut paths = Vec::new();
	for (i, json) in res.outbound_json.iter().enumerate() {
		let path = Path::new(out_dir).join(format!("out_{}_{}.json", session_id_hex, i));
		let mut of =
			File::create(&path).map_err(|e| Error::Multisig(format!("create out: {}", e)))?;
		of.write_all(json.as_bytes())
			.map_err(|e| Error::Multisig(format!("write out: {}", e)))?;
		paths.push(path.display().to_string());
	}
	Ok((res.status, paths))
}

/// List sealed session statuses (loads each record).
pub fn session_list<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
) -> Result<Vec<SessionStatus>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let ids = list_session_ids(wallet_data_dir)?;
	let mut out = Vec::new();
	for hex_id in ids {
		let sid = crate::grin_util::from_hex(&hex_id)
			.map_err(|e| Error::Multisig(format!("session id: {}", e)))?;
		match load_session(wallet_data_dir, &session_key, &sid) {
			Ok(rec) => {
				let collected = match &rec.phase {
					super::session::SessionPhase::RpRound1 => rec.rp_r1.len(),
					super::session::SessionPhase::RpRound2 => rec.rp_tau.len(),
					super::session::SessionPhase::KernelRound1 => rec.kern_commits.len(),
					super::session::SessionPhase::KernelRound2 => rec.kern_partials.len(),
					_ => 0,
				};
				out.push(SessionStatus {
					session_id_hex: hex_id,
					kind: rec.kind,
					phase: rec.phase,
					my_index: rec.my_index,
					quorum_size: rec.quorum_x_hexes.len(),
					collected,
					abort_reason: rec.abort_reason,
				});
			}
			Err(_) => continue,
		}
	}
	Ok(out)
}

/// Show one session status.
pub fn session_status<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	session_id_hex: &str,
) -> Result<SessionStatus, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let session_id = crate::grin_util::from_hex(session_id_hex)
		.map_err(|e| Error::Multisig(format!("session id hex: {}", e)))?;
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let record = load_session(wallet_data_dir, &session_key, &session_id)?;
	let ceremony_id = record.ceremony_id.clone();
	let state = get_state(w, keychain_mask, &ceremony_id)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let quorum = rebuild_quorum_from_record(&secp, &state, &record)?;
	let neg = Negotiator::resume(&secp, &state.config.public_poly, &quorum, record)?;
	Ok(neg.status())
}

/// Abort a session and wipe secrets; optionally delete the sealed file.
pub fn session_abort<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	wallet_data_dir: &str,
	session_id_hex: &str,
	reason: &str,
	delete_file: bool,
) -> Result<SessionStatus, Error>
where
	T: WalletBackend<'a, C, K>,
	C: crate::types::NodeClient + 'a,
	K: Keychain + 'a,
{
	let session_id = crate::grin_util::from_hex(session_id_hex)
		.map_err(|e| Error::Multisig(format!("session id hex: {}", e)))?;
	let keychain = w.keychain(keychain_mask)?;
	let session_key = derive_session_key(&keychain)?;
	let record = load_session(wallet_data_dir, &session_key, &session_id)?;
	let ceremony_id = record.ceremony_id.clone();
	let state = get_state(w, keychain_mask, &ceremony_id)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let quorum = rebuild_quorum_from_record(&secp, &state, &record)?;
	let mut neg = Negotiator::resume(&secp, &state.config.public_poly, &quorum, record)?;
	neg.abort(reason);
	let st = neg.status();
	if delete_file {
		delete_session(wallet_data_dir, &session_id)?;
	} else {
		save_session(wallet_data_dir, &session_key, &neg.record)?;
	}
	Ok(st)
}

fn rebuild_quorum_from_record(
	secp: &Secp256k1,
	state: &MultisigWalletState,
	record: &super::session::SessionRecord,
) -> Result<Vec<super::share::ActorPoint>, Error> {
	// Map sealed x-hexes back to roster actors (share 0).
	use super::scalar::sk_from_u64;
	use super::share::ActorPoint;
	let dummy_y = sk_from_u64(secp, 1)?;
	let mut points = Vec::new();
	for x_hex in &record.quorum_x_hexes {
		let x = seckey_from_hex(secp, x_hex)?;
		// Find matching roster actor.
		let mut found = None;
		for actor in &state.config.actors {
			let ax = actor.x_coordinate_share(secp, 0)?;
			if ax.0 == x.0 {
				let y = if actor.id == state.my_actor.id {
					state
						.shares
						.get(0)
						.map(|s| s.y.clone())
						.ok_or_else(|| Error::Multisig("no shares".into()))?
				} else {
					dummy_y.clone()
				};
				found = Some(ActorPoint { x, y });
				break;
			}
		}
		points.push(found.ok_or_else(|| {
			Error::Multisig(format!("quorum x {} not in ceremony roster", x_hex))
		})?);
	}
	Ok(points)
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

		// shares_per_actor = None → recommended (C-11 production floor).
		dkg_start(
			w0s,
			&k0,
			Some(&sk0),
			2,
			2,
			0,
			None,
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
			None,
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

		// Actor 1 exports shares addressed to actor 0 (one file per share index;
		// recommended shares_per_actor for M=2 is 2 under C-11).
		let paths1 =
			dkg_export_shares(w1s, &k1, &addr1, &sk1, w1.join("out").to_str().unwrap()).unwrap();
		assert_eq!(paths1.len(), 2);

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
