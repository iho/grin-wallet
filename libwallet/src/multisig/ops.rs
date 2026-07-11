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
use crate::types::WalletBackend;
use crate::Error;
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
	let plaintext = serde_json::to_vec(pending)
		.map_err(|e| Error::Multisig(format!("ser pending: {}", e)))?;
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
	threshold: usize,
	total: usize,
	my_index: usize,
	shares_per_actor: Option<usize>,
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
	let actors: Vec<_> = (0..total as u32).map(ActorId::from_index).collect();
	let my_actor = actors[my_index].clone();

	let (secrets, contrib) =
		generate_dealer_contribution(&secp, &ceremony, my_actor.clone(), &params)?;
	verify_pop(
		&secp,
		&ceremony,
		&contrib,
		params.num_coefficients(),
	)?;

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
	};
	save_pending(wallet_data_dir, key, &pending)?;

	let env = build_dkg_contribution(
		&secp,
		ceremony,
		my_actor,
		params,
		&contrib,
	)?;
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
		_ => {
			return Err(Error::Multisig(
				"envelope is not a DkgContribution".into(),
			))
		}
	};
	let actor = envelope.sender.clone();
	let idx = pending
		.actors
		.iter()
		.position(|a| a.id == actor.id)
		.ok_or_else(|| Error::Multisig(format!("unknown actor {}", actor.label)))?;

	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let contrib = parse_dkg_contribution(msg, actor.clone())?;
	verify_pop(
		&secp,
		&pending.ceremony_id,
		&contrib,
		pending.params.num_coefficients(),
	)?;

	pending.contributions[idx] = Some(StoredContribution {
		actor,
		commitment_hexes: contrib
			.commitments
			.coefficients
			.iter()
			.map(|c| c.to_hex())
			.collect(),
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
/// Writes one envelope JSON per recipient: `{out_dir}/share_to_{label}.json`.
pub fn dkg_export_shares(
	wallet_data_dir: &str,
	key: &PendingKey,
	out_dir: &str,
) -> Result<Vec<String>, Error> {
	let pending = load_pending(wallet_data_dir, key)?
		.ok_or_else(|| Error::Multisig("no pending DKG".into()))?;
	if !all_contributions_ready(&pending) {
		return Err(Error::Multisig(
			"not all DKG contributions received yet".into(),
		));
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
		// For multi-share actors, export one message per share_index (or pack together).
		// Export one combined file with first share only if shares_per_actor==1; else multiple.
		for share_index in 0..pending.params.shares_per_actor {
			let x = actor.x_coordinate_share(&secp, share_index)?;
			let y = dealer_partial_share(&secp, &secrets, &x)?;
			let env = build_dkg_partial_share(
				pending.ceremony_id.clone(),
				sender.clone(),
				actor.clone(),
				share_index,
				&y,
				&x,
			);
			let path = Path::new(out_dir).join(format!(
				"share_to_{}_s{}.json",
				actor.label, share_index
			));
			write_envelope_file(path.to_str().unwrap(), &env)?;
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
	if msg.share_index >= pending.params.shares_per_actor {
		return Err(Error::Multisig("share_index out of range".into()));
	}

	// Accumulate partials: store running sum of received dealer partials in my_share_ys_hex
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let part = seckey_from_hex(&secp, &msg.share_hex)?;
	let existing = &pending.my_share_ys_hex[msg.share_index];
	let sum = match existing {
		Some(h) => {
			let prev = seckey_from_hex(&secp, h)?;
			super::scalar::sk_add(&secp, &prev, &part)?
		}
		None => part,
	};
	pending.my_share_ys_hex[msg.share_index] = Some(seckey_to_hex(&sum));
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
				crate::grin_util::from_hex(h)
					.map_err(|e| Error::Multisig(format!("hex: {}", e)))
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
		shares.push(SecretShare {
			share_index,
			x,
			y,
		});
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
	let state: MultisigWalletState = serde_json::from_str(&s)
		.map_err(|e| Error::Multisig(format!("parse state: {}", e)))?;
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
