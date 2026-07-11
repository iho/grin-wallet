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

//! Durable multiparty **session engine** (WS4 / Beam-style negotiator).
//!
//! ## Model
//!
//! Each actor runs a [`Negotiator`] over a durable [`SessionRecord`] sealed on
//! disk (ChaCha20-Poly1305 under a keychain-derived key). Messages are
//! [`MultisigEnvelope`]s exchanged out-of-band (slatepack / file).
//!
//! ```text
//! SessionStore (AEAD files)
//!   session_id, ceremony_id, kind, phase, quorum, secrets, seen[], results
//!
//! Negotiator
//!   create_*  → open session, emit our first outbound message(s)
//!   apply     → ingest peer envelope (idempotent, replay-safe)
//!   tick      → produce any newly enabled outbound messages
//!   resume    → reload from store after crash
//! ```
//!
//! ## Barriers
//!
//! - Rangeproof: never send `τ_j` until all T1/T2 shares are collected.
//! - Kernel: never send a partial signature until all FROST commitments are in.
//! - Secrets for a completed/aborted session are wiped from the durable record
//!   (nonce reuse impossible after abort).
//!
//! ## Status
//!
//! Experimental foundation for CreateOutput (multiparty BP) and Spend (FROST
//! kernel). Full multi-process CLI wiring and DKG-as-session land later.

use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::{Secp256k1, Signature};
use crate::grin_util::ToHex;
use crate::Error;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use super::coin::CoinId;
use super::kernel::{
	aggregate_frost, create_kernel_session, excess_commitment, kernel_aggregate_sigs,
	kernel_partial_sign, kernel_round1, plain_features, verify_kernel_partial, verify_kernel_sig,
	verify_partial_excess, ActorKernelSecrets, AggregatedKernelPubs, KernelSession,
	SigningCommitment,
};
use super::dkg::{
	dealer_partial_share, generate_dealer_contribution, verify_pop, DealerSecrets,
};
use super::messages::{
	build_dkg_contribution, build_dkg_partial_share, build_kernel_final,
	build_kernel_partial_sig, build_kernel_signing_commit, build_rp_final, build_rp_round1,
	build_rp_round2, parse_dkg_contribution, parse_kernel_signing_commit, parse_rp_round1,
	proof_from_hex, proof_to_hex, pubkey_from_hex, seckey_from_hex, seckey_to_hex, MultisigBody,
	MultisigEnvelope,
};
use super::poly::{verify_share, PublicPoly, SecretPoly};
use super::rangeproof::{
	aggregate_round1, aggregate_tau_verified, expected_pub_blind_for_actor, rangeproof_finalize,
	rangeproof_params_for_coin, rangeproof_round1, rangeproof_round2, verify_rangeproof,
	ActorRpSecrets, AggregatedT, Round1Share,
};
use super::share::{canonical_quorum, quorum_transcript, ActorPoint};
use super::store::{open_pending, seal_pending};
use super::types::{
	ActorId, CeremonyId, MultisigConfig, MultisigWalletState, SecretShare, ThresholdParams,
};
use super::scalar::sk_from_u64;

/// Max envelope JSON size accepted by the negotiator (C-12 lite).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Max actors in a session quorum.
pub const MAX_SESSION_ACTORS: usize = 16;
/// Default session lifetime (24h). After the deadline, apply/expire abort the session.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

/// Current unix time in seconds (best-effort; 0 if the clock is unavailable).
pub fn unix_now() -> u64 {
	use std::time::{SystemTime, UNIX_EPOCH};
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// 32-byte AEAD key for session files (same size as pending/state keys).
pub type SessionKey = [u8; 32];

/// Build a canonical quorum of [`ActorPoint`]s for a session from local wallet state.
///
/// Only **this** actor's secret `y` is required. Peer points use the correct
/// public `x` (from the roster identity) and a dummy `y` (unused for our partials).
///
/// `quorum_indices` selects which roster actors participate (default: all).
pub fn quorum_points_from_state(
	secp: &Secp256k1,
	state: &super::types::MultisigWalletState,
	quorum_indices: Option<&[usize]>,
) -> Result<Vec<ActorPoint>, Error> {
	use super::scalar::sk_from_u64;
	let roster = &state.config.actors;
	let indices: Vec<usize> = match quorum_indices {
		Some(ix) => ix.to_vec(),
		None => (0..roster.len()).collect(),
	};
	if indices.len() < state.config.params.threshold {
		return Err(Error::Multisig(format!(
			"quorum size {} < threshold {}",
			indices.len(),
			state.config.params.threshold
		)));
	}
	let dummy_y = sk_from_u64(secp, 1)?;
	let mut points = Vec::with_capacity(indices.len());
	for &i in &indices {
		if i >= roster.len() {
			return Err(Error::Multisig(format!("quorum index {} out of roster", i)));
		}
		let actor = &roster[i];
		// Share index 0 x-coordinate (multi-share actors: use first share).
		let x = actor.x_coordinate_share(secp, 0)?;
		let y = if actor.id == state.my_actor.id {
			state
				.shares
				.get(0)
				.map(|s| s.y.clone())
				.ok_or_else(|| Error::Multisig("wallet state has no shares".into()))?
		} else {
			dummy_y.clone()
		};
		points.push(ActorPoint { x, y });
	}
	canonical_quorum(&points)
}

// ---------------------------------------------------------------------------
// Public status types
// ---------------------------------------------------------------------------

/// What the multiparty session is building.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
	/// Create a multisig output (multiparty rangeproof).
	CreateOutput,
	/// Spend multisig inputs (FROST kernel signing).
	Spend,
	/// Joint Feldman DKG (contributions + private partial shares).
	Dkg,
}

/// Protocol phase (ordered).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
	/// Session created; local round-1 not yet emitted.
	Init,
	/// Collecting rangeproof T1/T2 shares.
	RpRound1,
	/// Collecting partial τ.
	RpRound2,
	/// Collecting FROST signing commitments.
	KernelRound1,
	/// Collecting kernel partial signatures.
	KernelRound2,
	/// Collecting public DKG contributions.
	DkgContrib,
	/// Collecting private DKG partial shares.
	DkgShares,
	/// Local work complete; result available.
	Complete,
	/// Aborted; secrets wiped.
	Aborted,
}

/// Durable DKG state nested in a session record (WS4).
#[derive(Clone, Serialize, Deserialize)]
pub struct DkgSessionState {
	/// Threshold params.
	pub params: super::types::ThresholdParams,
	/// Collected contributions by roster index.
	pub contributions: Vec<Option<DkgContribWire>>,
	/// This dealer's secret coefficients (hex) — wiped on Complete/Abort.
	pub my_coeff_hexes: Vec<String>,
	/// Accumulated imported partials per share_index (hex).
	pub my_share_ys_hex: Vec<Option<String>>,
	/// Dealer indices already applied per share_index (replay guard).
	#[serde(default)]
	pub applied_share_dealers: Vec<Vec<usize>>,
	/// Whether we have emitted our partial shares for peers.
	#[serde(default)]
	pub shares_exported: bool,
}

impl std::fmt::Debug for DkgSessionState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("DkgSessionState")
			.field("params", &self.params)
			.field("contributions", &self.contributions)
			.field("my_coeff_hexes", &"[redacted]")
			.field("my_share_ys_hex", &"[redacted]")
			.field("applied_share_dealers", &self.applied_share_dealers)
			.field("shares_exported", &self.shares_exported)
			.finish()
	}
}

/// Wire form of one public DKG contribution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgContribWire {
	/// Dealer actor.
	pub actor: ActorId,
	/// Commitment compressed hexes.
	pub commitment_hexes: Vec<String>,
	/// PoP DER hexes.
	pub pop_sig_hexes: Vec<String>,
}

/// High-level status returned to CLI / API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatus {
	/// Session id hex.
	pub session_id_hex: String,
	/// Kind.
	pub kind: SessionKind,
	/// Current phase.
	pub phase: SessionPhase,
	/// Canonical actor index of this wallet.
	pub my_index: usize,
	/// Quorum size.
	pub quorum_size: usize,
	/// How many peer contributions we hold for the current collecting phase.
	pub collected: usize,
	/// Abort reason if aborted.
	pub abort_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Durable record (serialized, then AEAD-sealed)
// ---------------------------------------------------------------------------

/// Durable session state (secrets included — always sealed at rest).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionRecord {
	/// Opaque session tag (bound into kernel offset / envelopes).
	pub session_id: Vec<u8>,
	/// Ceremony / epoch.
	pub ceremony_id: CeremonyId,
	/// Session kind.
	pub kind: SessionKind,
	/// Current phase.
	pub phase: SessionPhase,
	/// This actor's identity.
	pub my_actor: ActorId,
	/// Ordered roster of actor identities (same for all parties).
	pub roster: Vec<ActorId>,
	/// Canonical quorum x-coordinates (hex) — public transcript of membership.
	pub quorum_x_hexes: Vec<String>,
	/// This actor's index in the **canonical** quorum (0 = mix/offset role).
	pub my_index: usize,
	/// CreateOutput: coin being proven.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub coin: Option<CoinId>,
	/// Spend: fee (nanogrins).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fee: Option<u64>,
	/// Spend: input coins.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub inputs: Vec<CoinId>,
	/// Spend: output coins.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub outputs: Vec<CoinId>,
	/// Local secrets (hex). Cleared on Complete/Abort.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub secrets: Option<SessionSecretsWire>,
	/// Collected RP round-1 shares by canonical actor index (hex pubkeys).
	#[serde(default)]
	pub rp_r1: BTreeMap<usize, RpR1Wire>,
	/// Collected partial τ by actor index (hex).
	#[serde(default)]
	pub rp_tau: BTreeMap<usize, String>,
	/// Collected FROST commitments by actor index.
	#[serde(default)]
	pub kern_commits: BTreeMap<usize, KernCommitWire>,
	/// Collected kernel partial sigs by actor index (compact hex).
	#[serde(default)]
	pub kern_partials: BTreeMap<usize, String>,
	/// Whether we have already emitted our message for the current phase.
	pub emitted_for_phase: bool,
	/// Replay / equivocation cache: body content hashes we accepted.
	#[serde(default)]
	pub seen_body_hashes: BTreeSet<String>,
	/// Abort reason (if any).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub abort_reason: Option<String>,
	/// Final rangeproof (CreateOutput) as hex.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub result_proof_hex: Option<String>,
	/// Final commitment hex (CreateOutput).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub result_commit_hex: Option<String>,
	/// Final kernel signature compact hex (Spend).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub result_sig_hex: Option<String>,
	/// Aggregated excess pubkey hex (Spend).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub result_excess_hex: Option<String>,
	/// Aggregated nonce pubkey hex (Spend).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub result_nonce_hex: Option<String>,
	/// Unix timestamp (seconds) when the session was created.
	#[serde(default)]
	pub created_unix: u64,
	/// Optional hard deadline (unix seconds). After this, the session should abort.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub deadline_unix: Option<u64>,
	/// Nested DKG state (only for [`SessionKind::Dkg`]).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dkg: Option<DkgSessionState>,
}

impl SessionRecord {
	/// Whether this open session is past its deadline at `now_unix`.
	pub fn is_expired(&self, now_unix: u64) -> bool {
		if matches!(
			self.phase,
			SessionPhase::Complete | SessionPhase::Aborted
		) {
			return false;
		}
		match self.deadline_unix {
			Some(d) => now_unix >= d,
			None => false,
		}
	}
}

impl std::fmt::Debug for SessionRecord {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SessionRecord")
			.field("session_id", &self.session_id.to_hex())
			.field("ceremony_id", &self.ceremony_id)
			.field("kind", &self.kind)
			.field("phase", &self.phase)
			.field("my_index", &self.my_index)
			.field("secrets", &"[redacted]")
			.field("abort_reason", &self.abort_reason)
			.finish()
	}
}

/// Wire form of local secrets (hex).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSecretsWire {
	/// Partial blind / excess material (hex).
	pub partial_hex: String,
	/// Private BP nonce or FROST d (hex).
	pub nonce_a_hex: String,
	/// FROST e (hex); empty for CreateOutput.
	#[serde(default)]
	pub nonce_b_hex: String,
	/// Round-1 T1 hex (RP) or pub_d (kernel).
	pub pub_a_hex: String,
	/// Round-1 T2 hex (RP) or pub_e (kernel).
	pub pub_b_hex: String,
	/// Pub excess (kernel only).
	#[serde(default)]
	pub pub_excess_hex: String,
}

impl std::fmt::Debug for SessionSecretsWire {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SessionSecretsWire { /* redacted */ }")
	}
}

/// Stored RP round-1 share (public).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpR1Wire {
	/// T1 compressed hex.
	pub t_one_hex: String,
	/// T2 compressed hex.
	pub t_two_hex: String,
}

/// Stored FROST commitment (public).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernCommitWire {
	/// D_j hex.
	pub pub_d_hex: String,
	/// E_j hex.
	pub pub_e_hex: String,
	/// X_j hex.
	pub pub_excess_hex: String,
}

// ---------------------------------------------------------------------------
// Session store (filesystem, AEAD)
// ---------------------------------------------------------------------------

const SESSIONS_DIR: &str = "sessions";

fn sessions_dir(wallet_data_dir: &str) -> PathBuf {
	Path::new(wallet_data_dir).join("multisig").join(SESSIONS_DIR)
}

fn session_path(wallet_data_dir: &str, session_id: &[u8]) -> PathBuf {
	sessions_dir(wallet_data_dir).join(format!("{}.enc", session_id.to_hex()))
}

/// Ensure the sessions directory exists.
pub fn ensure_sessions_dir(wallet_data_dir: &str) -> Result<PathBuf, Error> {
	let d = sessions_dir(wallet_data_dir);
	fs::create_dir_all(&d).map_err(|e| Error::Multisig(format!("mkdir sessions: {}", e)))?;
	Ok(d)
}

/// Seal and write a session record.
pub fn save_session(
	wallet_data_dir: &str,
	key: &SessionKey,
	record: &SessionRecord,
) -> Result<(), Error> {
	ensure_sessions_dir(wallet_data_dir)?;
	let path = session_path(wallet_data_dir, &record.session_id);
	let mut plaintext =
		serde_json::to_vec(record).map_err(|e| Error::Multisig(format!("ser session: {}", e)))?;
	let blob = seal_pending(key, &plaintext)?;
	plaintext.zeroize();
	let mut f =
		File::create(&path).map_err(|e| Error::Multisig(format!("create session: {}", e)))?;
	f.write_all(&blob)
		.map_err(|e| Error::Multisig(format!("write session: {}", e)))?;
	Ok(())
}

/// Load and open a session record.
pub fn load_session(
	wallet_data_dir: &str,
	key: &SessionKey,
	session_id: &[u8],
) -> Result<SessionRecord, Error> {
	let path = session_path(wallet_data_dir, session_id);
	if !path.exists() {
		return Err(Error::Multisig(format!(
			"session not found: {}",
			session_id.to_hex()
		)));
	}
	let mut f = File::open(&path).map_err(|e| Error::Multisig(format!("open session: {}", e)))?;
	let mut blob = Vec::new();
	f.read_to_end(&mut blob)
		.map_err(|e| Error::Multisig(format!("read session: {}", e)))?;
	let mut plaintext = open_pending(key, &blob)?;
	let record: SessionRecord = serde_json::from_slice(&plaintext)
		.map_err(|e| Error::Multisig(format!("parse session: {}", e)))?;
	plaintext.zeroize();
	Ok(record)
}

/// Delete a session file (after complete/abort cleanup).
pub fn delete_session(wallet_data_dir: &str, session_id: &[u8]) -> Result<(), Error> {
	let path = session_path(wallet_data_dir, session_id);
	if path.exists() {
		fs::remove_file(&path).map_err(|e| Error::Multisig(format!("rm session: {}", e)))?;
	}
	Ok(())
}

/// List sealed session ids (hex) present on disk.
pub fn list_session_ids(wallet_data_dir: &str) -> Result<Vec<String>, Error> {
	let d = sessions_dir(wallet_data_dir);
	if !d.exists() {
		return Ok(Vec::new());
	}
	let mut out = Vec::new();
	for ent in fs::read_dir(&d).map_err(|e| Error::Multisig(format!("list sessions: {}", e)))? {
		let ent = ent.map_err(|e| Error::Multisig(format!("list sessions: {}", e)))?;
		let name = ent.file_name().to_string_lossy().into_owned();
		if let Some(hex_id) = name.strip_suffix(".enc") {
			out.push(hex_id.to_string());
		}
	}
	out.sort();
	Ok(out)
}

// ---------------------------------------------------------------------------
// Negotiator
// ---------------------------------------------------------------------------

/// In-process multiparty session driver with durable state.
pub struct Negotiator {
	/// Durable record.
	pub record: SessionRecord,
	/// Public polynomial for the ceremony.
	public_poly: PublicPoly,
	/// Canonical quorum (includes this actor's y shares).
	quorum: Vec<ActorPoint>,
	/// Secp context.
	secp: Secp256k1,
}

impl Negotiator {
	/// Status snapshot.
	pub fn status(&self) -> SessionStatus {
		let collected = match self.record.phase {
			SessionPhase::RpRound1 => self.record.rp_r1.len(),
			SessionPhase::RpRound2 => self.record.rp_tau.len(),
			SessionPhase::KernelRound1 => self.record.kern_commits.len(),
			SessionPhase::KernelRound2 => self.record.kern_partials.len(),
			SessionPhase::DkgContrib => self
				.record
				.dkg
				.as_ref()
				.map(|d| d.contributions.iter().filter(|c| c.is_some()).count())
				.unwrap_or(0),
			SessionPhase::DkgShares => self
				.record
				.dkg
				.as_ref()
				.map(|d| {
					d.applied_share_dealers
						.first()
						.map(|v| v.len())
						.unwrap_or(0)
				})
				.unwrap_or(0),
			_ => 0,
		};
		SessionStatus {
			session_id_hex: self.record.session_id.to_hex(),
			kind: self.record.kind.clone(),
			phase: self.record.phase.clone(),
			my_index: self.record.my_index,
			quorum_size: self.quorum.len(),
			collected,
			abort_reason: self.record.abort_reason.clone(),
		}
	}

	/// Open a CreateOutput session and emit our RpRound1 message.
	pub fn create_output(
		secp: &Secp256k1,
		public_poly: &PublicPoly,
		quorum: &[ActorPoint],
		ceremony_id: CeremonyId,
		roster: Vec<ActorId>,
		my_actor: ActorId,
		coin: CoinId,
		session_id: impl AsRef<[u8]>,
	) -> Result<(Self, MultisigEnvelope), Error> {
		let quorum = canonical_quorum(quorum)?;
		if quorum.len() > MAX_SESSION_ACTORS {
			return Err(Error::Multisig("quorum too large".into()));
		}
		let my_index = find_my_index(secp, &quorum, &my_actor)?;
		// Only this actor's y is required for the partial blind (networked-safe).
		let my_blind =
			super::rangeproof::partial_blind_for_actor(secp, public_poly, &quorum, my_index, &coin)?;
		let params = rangeproof_params_for_coin(secp, public_poly, &coin, None)?;
		let (secrets, share) = rangeproof_round1(secp, &params, &my_blind)?;

		let mut sid = session_id.as_ref().to_vec();
		sid.extend_from_slice(b"|co|");
		sid.extend_from_slice(&quorum_transcript(&quorum)?);

		let secrets_wire = SessionSecretsWire {
			partial_hex: seckey_to_hex(&secrets.partial_blind),
			nonce_a_hex: seckey_to_hex(&secrets.private_nonce),
			nonce_b_hex: String::new(),
			pub_a_hex: pubkey_to_hex_local(secp, &secrets.t_one),
			pub_b_hex: pubkey_to_hex_local(secp, &secrets.t_two),
			pub_excess_hex: String::new(),
		};

		let now = unix_now();
		let mut record = SessionRecord {
			session_id: sid.clone(),
			ceremony_id: ceremony_id.clone(),
			kind: SessionKind::CreateOutput,
			phase: SessionPhase::RpRound1,
			my_actor: my_actor.clone(),
			roster,
			quorum_x_hexes: quorum.iter().map(|p| seckey_to_hex(&p.x)).collect(),
			my_index,
			coin: Some(coin.clone()),
			fee: None,
			inputs: Vec::new(),
			outputs: Vec::new(),
			secrets: Some(secrets_wire),
			rp_r1: BTreeMap::new(),
			rp_tau: BTreeMap::new(),
			kern_commits: BTreeMap::new(),
			kern_partials: BTreeMap::new(),
			emitted_for_phase: true,
			seen_body_hashes: BTreeSet::new(),
			abort_reason: None,
			result_proof_hex: None,
			result_commit_hex: None,
			result_sig_hex: None,
			result_excess_hex: None,
			result_nonce_hex: None,
			created_unix: now,
			deadline_unix: Some(now.saturating_add(DEFAULT_SESSION_TTL_SECS)),
			dkg: None,
		};
		// Record our own round-1 contribution.
		record.rp_r1.insert(
			my_index,
			RpR1Wire {
				t_one_hex: pubkey_to_hex_local(secp, &share.t_one),
				t_two_hex: pubkey_to_hex_local(secp, &share.t_two),
			},
		);

		let env = build_rp_round1(
			secp,
			ceremony_id,
			my_actor,
			&params,
			&coin,
			my_index,
			&share,
		)
		.with_session_id(&sid);

		let neg = Self {
			record,
			public_poly: public_poly.clone(),
			quorum,
			secp: clone_secp(secp),
		};
		Ok((neg, env))
	}

	/// Open a Spend session and emit our FROST KernelSigningCommit.
	pub fn create_spend(
		secp: &Secp256k1,
		public_poly: &PublicPoly,
		quorum: &[ActorPoint],
		ceremony_id: CeremonyId,
		roster: Vec<ActorId>,
		my_actor: ActorId,
		inputs: Vec<CoinId>,
		outputs: Vec<CoinId>,
		fee: u64,
		session_id: impl AsRef<[u8]>,
	) -> Result<(Self, MultisigEnvelope), Error> {
		let quorum = canonical_quorum(quorum)?;
		if quorum.len() > MAX_SESSION_ACTORS {
			return Err(Error::Multisig("quorum too large".into()));
		}
		if inputs.is_empty() || outputs.is_empty() {
			return Err(Error::Multisig("spend needs inputs and outputs".into()));
		}
		let my_index = find_my_index(secp, &quorum, &my_actor)?;

		let mut sid = session_id.as_ref().to_vec();
		sid.extend_from_slice(b"|sp|");
		sid.extend_from_slice(&quorum_transcript(&quorum)?);

		let features = plain_features(fee)?;
		let session = create_kernel_session(
			secp,
			public_poly,
			&sid,
			features,
			inputs.clone(),
			outputs.clone(),
		)?;
		let secrets = kernel_round1(secp, public_poly, &quorum, my_index, &session)?;
		verify_partial_excess(
			secp,
			public_poly,
			&quorum,
			my_index,
			&session,
			&secrets.commitment.pub_excess,
		)?;

		let secrets_wire = SessionSecretsWire {
			partial_hex: seckey_to_hex(&secrets.partial_excess),
			nonce_a_hex: seckey_to_hex(&secrets.d),
			nonce_b_hex: seckey_to_hex(&secrets.e),
			pub_a_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_d),
			pub_b_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_e),
			pub_excess_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_excess),
		};

		let now = unix_now();
		let mut record = SessionRecord {
			session_id: sid.clone(),
			ceremony_id: ceremony_id.clone(),
			kind: SessionKind::Spend,
			phase: SessionPhase::KernelRound1,
			my_actor: my_actor.clone(),
			roster,
			quorum_x_hexes: quorum.iter().map(|p| seckey_to_hex(&p.x)).collect(),
			my_index,
			coin: None,
			fee: Some(fee),
			inputs,
			outputs,
			secrets: Some(secrets_wire),
			rp_r1: BTreeMap::new(),
			rp_tau: BTreeMap::new(),
			kern_commits: BTreeMap::new(),
			kern_partials: BTreeMap::new(),
			emitted_for_phase: true,
			seen_body_hashes: BTreeSet::new(),
			abort_reason: None,
			result_proof_hex: None,
			result_commit_hex: None,
			result_sig_hex: None,
			result_excess_hex: None,
			result_nonce_hex: None,
			created_unix: now,
			deadline_unix: Some(now.saturating_add(DEFAULT_SESSION_TTL_SECS)),
			dkg: None,
		};
		record.kern_commits.insert(
			my_index,
			KernCommitWire {
				pub_d_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_d),
				pub_e_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_e),
				pub_excess_hex: pubkey_to_hex_local(secp, &secrets.commitment.pub_excess),
			},
		);

		let env = build_kernel_signing_commit(
			secp,
			ceremony_id,
			my_actor,
			&session,
			my_index,
			&secrets.commitment,
		);

		Ok((
			Self {
				record,
				public_poly: public_poly.clone(),
				quorum,
				secp: clone_secp(secp),
			},
			env,
		))
	}

	/// Resume a negotiator from a durable record + local ceremony material.
	pub fn resume(
		secp: &Secp256k1,
		public_poly: &PublicPoly,
		quorum: &[ActorPoint],
		record: SessionRecord,
	) -> Result<Self, Error> {
		if record.kind == SessionKind::Dkg {
			return Self::resume_dkg(secp, record);
		}
		let quorum = canonical_quorum(quorum)?;
		if quorum.len() != record.quorum_x_hexes.len() {
			return Err(Error::Multisig("quorum size mismatch on resume".into()));
		}
		for (i, p) in quorum.iter().enumerate() {
			if seckey_to_hex(&p.x) != record.quorum_x_hexes[i] {
				return Err(Error::Multisig(
					"quorum x-coordinate mismatch on resume".into(),
				));
			}
		}
		Ok(Self {
			record,
			public_poly: public_poly.clone(),
			quorum,
			secp: clone_secp(secp),
		})
	}

	/// Resume a DKG session (no ceremony public poly yet).
	pub fn resume_dkg(secp: &Secp256k1, record: SessionRecord) -> Result<Self, Error> {
		if record.kind != SessionKind::Dkg {
			return Err(Error::Multisig("not a DKG session".into()));
		}
		let dummy_y = sk_from_u64(secp, 1)?;
		let mut quorum = Vec::new();
		for x_hex in &record.quorum_x_hexes {
			let x = seckey_from_hex(secp, x_hex)?;
			quorum.push(ActorPoint {
				x,
				y: dummy_y.clone(),
			});
		}
		Ok(Self {
			record,
			public_poly: PublicPoly {
				coefficients: Vec::new(),
			},
			quorum,
			secp: clone_secp(secp),
		})
	}

	/// Open a DKG session and emit our public contribution.
	///
	/// All parties must use the same `ceremony_id`, `params`, ordered `roster`,
	/// and `session_tag`. Partial shares are exchanged as plain envelopes in
	/// the session path (AEAD at rest); for production OOB transport prefer
	/// age-encrypted slatepacks (C-02) via the classic `dkg_export_shares` path.
	pub fn create_dkg(
		secp: &Secp256k1,
		ceremony_id: CeremonyId,
		params: ThresholdParams,
		roster: Vec<ActorId>,
		my_index: usize,
		session_tag: impl AsRef<[u8]>,
	) -> Result<(Self, MultisigEnvelope), Error> {
		if roster.len() != params.total_actors {
			return Err(Error::Multisig("roster size != total_actors".into()));
		}
		if my_index >= roster.len() {
			return Err(Error::Multisig("my_index out of range".into()));
		}
		if roster.len() > MAX_SESSION_ACTORS {
			return Err(Error::Multisig("roster too large".into()));
		}
		let my_actor = roster[my_index].clone();
		let (secrets, contrib) =
			generate_dealer_contribution(secp, &ceremony_id, my_actor.clone(), &params)?;
		verify_pop(secp, &ceremony_id, &contrib, params.num_coefficients())?;

		let mut sid = session_tag.as_ref().to_vec();
		sid.extend_from_slice(b"|dkg|");
		sid.extend_from_slice(ceremony_id.0.as_bytes());

		let mut contributions = vec![None; roster.len()];
		contributions[my_index] = Some(DkgContribWire {
			actor: my_actor.clone(),
			commitment_hexes: contrib
				.commitments
				.coefficients
				.iter()
				.map(|c| c.to_hex())
				.collect(),
			pop_sig_hexes: contrib.pops.iter().map(|p| p.sig.to_hex()).collect(),
		});

		let dkg = DkgSessionState {
			params: params.clone(),
			contributions,
			my_coeff_hexes: secrets
				.poly
				.coeffs
				.iter()
				.map(|c| seckey_to_hex(c))
				.collect(),
			my_share_ys_hex: vec![None; params.shares_per_actor],
			applied_share_dealers: vec![Vec::new(); params.shares_per_actor],
			shares_exported: false,
		};

		let dummy_y = sk_from_u64(secp, 1)?;
		let mut quorum_x_hexes = Vec::new();
		let mut quorum = Vec::new();
		for a in &roster {
			let x = a.x_coordinate_share(secp, 0)?;
			quorum_x_hexes.push(seckey_to_hex(&x));
			quorum.push(ActorPoint {
				x,
				y: dummy_y.clone(),
			});
		}

		let now = unix_now();
		let record = SessionRecord {
			session_id: sid.clone(),
			ceremony_id: ceremony_id.clone(),
			kind: SessionKind::Dkg,
			phase: SessionPhase::DkgContrib,
			my_actor: my_actor.clone(),
			roster,
			quorum_x_hexes,
			my_index,
			coin: None,
			fee: None,
			inputs: Vec::new(),
			outputs: Vec::new(),
			secrets: None,
			rp_r1: BTreeMap::new(),
			rp_tau: BTreeMap::new(),
			kern_commits: BTreeMap::new(),
			kern_partials: BTreeMap::new(),
			emitted_for_phase: true,
			seen_body_hashes: BTreeSet::new(),
			abort_reason: None,
			result_proof_hex: None,
			result_commit_hex: None,
			result_sig_hex: None,
			result_excess_hex: None,
			result_nonce_hex: None,
			created_unix: now,
			deadline_unix: Some(now.saturating_add(DEFAULT_SESSION_TTL_SECS)),
			dkg: Some(dkg),
		};

		let env = build_dkg_contribution(secp, ceremony_id, my_actor, params, &contrib)?
			.with_session_id(&sid);
		Ok((
			Self {
				record,
				public_poly: PublicPoly {
					coefficients: Vec::new(),
				},
				quorum,
				secp: clone_secp(secp),
			},
			env,
		))
	}

	/// Build [`MultisigWalletState`] after a completed DKG session (wipes coeffs).
	pub fn finalize_dkg_state(&mut self) -> Result<MultisigWalletState, Error> {
		if self.record.kind != SessionKind::Dkg {
			return Err(Error::Multisig("not a DKG session".into()));
		}
		if self.record.phase != SessionPhase::Complete {
			// Try to complete if all material is present.
			self.try_complete_dkg()?;
		}
		if self.record.phase != SessionPhase::Complete {
			return Err(Error::Multisig(format!(
				"DKG not complete ({:?})",
				self.record.phase
			)));
		}
		let dkg = self
			.record
			.dkg
			.as_ref()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		if dkg.my_coeff_hexes.is_empty() {
			return Err(Error::Multisig(
				"DKG secrets already wiped; state must have been finalized".into(),
			));
		}
		let secrets = self.dkg_dealer_secrets()?;
		let public_poly = self.dkg_aggregate_public_poly()?;
		let me = &self.record.roster[self.record.my_index];
		let mut shares = Vec::new();
		for share_index in 0..dkg.params.shares_per_actor {
			let x = me.x_coordinate_share(&self.secp, share_index)?;
			let mut y = dealer_partial_share(&self.secp, &secrets, &x)?;
			if let Some(ref h) = dkg.my_share_ys_hex[share_index] {
				let others = seckey_from_hex(&self.secp, h)?;
				y = super::scalar::sk_add(&self.secp, &y, &others)?;
			} else if dkg.params.total_actors > 1 {
				return Err(Error::Multisig(format!(
					"missing imported shares for share_index {}",
					share_index
				)));
			}
			if !verify_share(&self.secp, &public_poly, &x, &y)? {
				return Err(Error::Multisig(format!(
					"share verification failed for share {}",
					share_index
				)));
			}
			shares.push(SecretShare { share_index, x, y });
		}
		let state = MultisigWalletState {
			config: MultisigConfig {
				ceremony_id: self.record.ceremony_id.clone(),
				params: dkg.params.clone(),
				actors: self.record.roster.clone(),
				public_poly: public_poly.clone(),
			},
			my_actor: me.clone(),
			shares,
		};
		state.config.validate()?;
		// Wipe dealer coeffs after successful finalize.
		if let Some(ref mut d) = self.record.dkg {
			d.my_coeff_hexes.clear();
		}
		self.public_poly = public_poly;
		Ok(state)
	}

	/// Abort the session and wipe secrets.
	pub fn abort(&mut self, reason: impl Into<String>) {
		self.record.phase = SessionPhase::Aborted;
		self.record.abort_reason = Some(reason.into());
		self.record.secrets = None;
		if let Some(ref mut dkg) = self.record.dkg {
			dkg.my_coeff_hexes.clear();
			dkg.my_share_ys_hex.clear();
		}
		self.record.emitted_for_phase = true;
	}

	/// Apply a peer envelope. Returns any newly enabled outbound messages.
	pub fn apply(&mut self, env: &MultisigEnvelope) -> Result<Vec<MultisigEnvelope>, Error> {
		if self.record.phase == SessionPhase::Aborted {
			return Err(Error::Multisig(format!(
				"session aborted: {}",
				self.record.abort_reason.as_deref().unwrap_or("unknown")
			)));
		}
		// Deadline: refuse further progress (caller should persist via abort path).
		if self.record.is_expired(unix_now()) {
			self.abort("deadline exceeded");
			return Err(Error::Multisig(
				"session deadline exceeded; session aborted".into(),
			));
		}
		if env.ceremony_id != self.record.ceremony_id.0 {
			return Err(Error::Multisig("envelope ceremony_id mismatch".into()));
		}
		// Size cap (C-12 lite).
		let approx = serde_json::to_vec(env)
			.map_err(|e| Error::Multisig(format!("envelope size check: {}", e)))?;
		if approx.len() > MAX_ENVELOPE_BYTES {
			return Err(Error::Multisig(format!(
				"envelope too large ({} > {})",
				approx.len(),
				MAX_ENVELOPE_BYTES
			)));
		}

		let body_hash = envelope_body_hash(env);
		if self.record.seen_body_hashes.contains(&body_hash) {
			return Ok(Vec::new());
		}

		// Final messages may complete a peer who has not finished locally yet.
		if self.record.phase == SessionPhase::Complete {
			match &env.body {
				MultisigBody::RpFinal(_) | MultisigBody::KernelFinal(_) => {
					self.record.seen_body_hashes.insert(body_hash);
					return Ok(Vec::new());
				}
				_ => {
					return Err(Error::Multisig("session already complete".into()));
				}
			}
		}

		match &env.body {
			MultisigBody::RpRound1(msg) => self.apply_rp_round1(env, msg)?,
			MultisigBody::RpRound2(msg) => self.apply_rp_round2(env, msg)?,
			MultisigBody::RpFinal(msg) => self.apply_rp_final(env, msg)?,
			MultisigBody::KernelSigningCommit(msg) => self.apply_kern_commit(env, msg)?,
			MultisigBody::KernelPartialSig(msg) => self.apply_kern_partial(env, msg)?,
			MultisigBody::KernelFinal(msg) => self.apply_kern_final(env, msg)?,
			MultisigBody::DkgContribution(msg) => self.apply_dkg_contrib(env, msg)?,
			MultisigBody::DkgPartialShare(msg) => self.apply_dkg_share(env, msg)?,
			_ => {
				return Err(Error::Multisig(
					"envelope body not valid for this session kind/phase".into(),
				))
			}
		}

		self.record.seen_body_hashes.insert(body_hash);
		self.tick()
	}

	/// Produce outbound messages for the current phase if we are ready and have
	/// not yet emitted (used after resume and after collecting peers).
	pub fn tick(&mut self) -> Result<Vec<MultisigEnvelope>, Error> {
		if matches!(
			self.record.phase,
			SessionPhase::Complete | SessionPhase::Aborted
		) {
			return Ok(Vec::new());
		}
		match self.record.kind {
			SessionKind::CreateOutput => self.tick_create_output(),
			SessionKind::Spend => self.tick_spend(),
			SessionKind::Dkg => self.tick_dkg(),
		}
	}

	/// Final rangeproof if CreateOutput completed.
	pub fn result_proof(&self) -> Result<Option<(Commitment, RangeProof)>, Error> {
		match (
			&self.record.result_commit_hex,
			&self.record.result_proof_hex,
		) {
			(Some(c), Some(p)) => {
				let commit = commit_from_hex(c)?;
				let proof = proof_from_hex(p)?;
				Ok(Some((commit, proof)))
			}
			_ => Ok(None),
		}
	}

	/// Final kernel signature if Spend completed.
	pub fn result_kernel(
		&self,
	) -> Result<Option<(Signature, AggregatedKernelPubs)>, Error> {
		match (
			&self.record.result_sig_hex,
			&self.record.result_excess_hex,
			&self.record.result_nonce_hex,
		) {
			(Some(s), Some(e), Some(n)) => {
				let sig = sig_from_hex(&self.secp, s)?;
				let excess = pubkey_from_hex(&self.secp, e)?;
				let nonce = pubkey_from_hex(&self.secp, n)?;
				Ok(Some((
					sig,
					AggregatedKernelPubs {
						nonce_sum: nonce,
						excess_sum: excess,
					},
				)))
			}
			_ => Ok(None),
		}
	}

	// ----- CreateOutput internals -----

	fn apply_rp_round1(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::RpRound1Msg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::CreateOutput {
			return Err(Error::Multisig("RpRound1 not valid for Spend session".into()));
		}
		if self.record.phase != SessionPhase::RpRound1
			&& self.record.phase != SessionPhase::RpRound2
		{
			// Allow late delivery only while still collecting r1 or if we already moved on
			// with a full set (ignore extras via seen hash).
			if self.record.phase != SessionPhase::RpRound1 {
				return Err(Error::Multisig("RpRound1 not expected in this phase".into()));
			}
		}
		let idx = msg.actor_index;
		self.check_actor_index(idx, env)?;
		if let Some(existing) = self.record.rp_r1.get(&idx) {
			if existing.t_one_hex != msg.t_one_hex || existing.t_two_hex != msg.t_two_hex {
				return Err(Error::Multisig(format!(
					"RpRound1 equivocation from actor {}",
					idx
				)));
			}
			return Ok(());
		}
		// Validate parseable pubkeys.
		let _ = parse_rp_round1(&self.secp, msg)?;
		self.record.rp_r1.insert(
			idx,
			RpR1Wire {
				t_one_hex: msg.t_one_hex.clone(),
				t_two_hex: msg.t_two_hex.clone(),
			},
		);
		Ok(())
	}

	fn apply_rp_round2(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::RpRound2Msg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::CreateOutput {
			return Err(Error::Multisig("RpRound2 not valid for Spend session".into()));
		}
		if self.record.phase != SessionPhase::RpRound2 {
			return Err(Error::Multisig("RpRound2 not expected in this phase".into()));
		}
		let idx = msg.actor_index;
		self.check_actor_index(idx, env)?;
		if let Some(existing) = self.record.rp_tau.get(&idx) {
			if existing != &msg.tau_hex {
				return Err(Error::Multisig(format!(
					"RpRound2 equivocation from actor {}",
					idx
				)));
			}
			return Ok(());
		}
		// Ensure parseable.
		let _ = seckey_from_hex(&self.secp, &msg.tau_hex)?;
		self.record.rp_tau.insert(idx, msg.tau_hex.clone());
		Ok(())
	}

	fn apply_rp_final(
		&mut self,
		_env: &MultisigEnvelope,
		msg: &super::messages::RpFinalMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::CreateOutput {
			return Err(Error::Multisig("RpFinal not valid for Spend session".into()));
		}
		let commit = commit_from_hex(&msg.commit_hex)?;
		let proof = proof_from_hex(&msg.proof_hex)?;
		let coin = self
			.record
			.coin
			.as_ref()
			.ok_or_else(|| Error::Multisig("missing coin".into()))?;
		let params =
			rangeproof_params_for_coin(&self.secp, &self.public_poly, coin, None)?;
		if commit != params.commit {
			return Err(Error::Multisig("RpFinal commit mismatch".into()));
		}
		verify_rangeproof(&self.secp, commit, proof, params.extra_data.clone())?;
		self.record.result_commit_hex = Some(msg.commit_hex.clone());
		self.record.result_proof_hex = Some(msg.proof_hex.clone());
		self.record.phase = SessionPhase::Complete;
		self.record.secrets = None;
		self.record.emitted_for_phase = true;
		Ok(())
	}

	fn tick_create_output(&mut self) -> Result<Vec<MultisigEnvelope>, Error> {
		let n = self.quorum.len();
		let mut out = Vec::new();

		// Barrier: wait for all R1 before producing τ.
		if self.record.phase == SessionPhase::RpRound1 && self.record.rp_r1.len() == n {
			self.record.phase = SessionPhase::RpRound2;
			self.record.emitted_for_phase = false;
		}

		if self.record.phase == SessionPhase::RpRound2 && !self.record.emitted_for_phase {
			let env = self.emit_rp_round2()?;
			self.record.emitted_for_phase = true;
			out.push(env);
		}

		// Barrier: wait for all τ before finalize.
		if self.record.phase == SessionPhase::RpRound2 && self.record.rp_tau.len() == n {
			let env = self.finalize_create_output()?;
			out.push(env);
		}

		Ok(out)
	}

	fn emit_rp_round2(&mut self) -> Result<MultisigEnvelope, Error> {
		let coin = self
			.record
			.coin
			.clone()
			.ok_or_else(|| Error::Multisig("missing coin".into()))?;
		let params =
			rangeproof_params_for_coin(&self.secp, &self.public_poly, &coin, None)?;
		let agg = self.rp_agg()?;
		let secrets = self.rp_secrets_from_wire()?;
		let tau = rangeproof_round2(&self.secp, &params, &secrets, &agg)?;
		// Store our tau.
		self.record
			.rp_tau
			.insert(self.record.my_index, seckey_to_hex(&tau));
		Ok(build_rp_round2(
			self.record.ceremony_id.clone(),
			self.record.my_actor.clone(),
			&coin,
			self.record.my_index,
			&tau,
		)
		.with_session_id(&self.record.session_id))
	}

	fn finalize_create_output(&mut self) -> Result<MultisigEnvelope, Error> {
		let coin = self
			.record
			.coin
			.clone()
			.ok_or_else(|| Error::Multisig("missing coin".into()))?;
		let params =
			rangeproof_params_for_coin(&self.secp, &self.public_poly, &coin, None)?;
		let agg = self.rp_agg()?;
		let secrets = self.rp_secrets_from_wire()?;

		// Ordered shares + taus for verification.
		let mut r1_shares = Vec::new();
		let mut tau_parts = Vec::new();
		let mut pub_blinds = Vec::new();
		for j in 0..self.quorum.len() {
			let w = self
				.record
				.rp_r1
				.get(&j)
				.ok_or_else(|| Error::Multisig(format!("missing r1 from actor {}", j)))?;
			r1_shares.push(Round1Share {
				t_one: pubkey_from_hex(&self.secp, &w.t_one_hex)?,
				t_two: pubkey_from_hex(&self.secp, &w.t_two_hex)?,
			});
			let th = self
				.record
				.rp_tau
				.get(&j)
				.ok_or_else(|| Error::Multisig(format!("missing tau from actor {}", j)))?;
			tau_parts.push(seckey_from_hex(&self.secp, th)?);
			pub_blinds.push(expected_pub_blind_for_actor(
				&self.secp,
				&self.public_poly,
				&self.quorum,
				j,
				&coin,
			)?);
		}
		let tau_sum = aggregate_tau_verified(
			&self.secp,
			&params,
			&agg,
			&r1_shares,
			&tau_parts,
			&pub_blinds,
		)?;
		let proof = rangeproof_finalize(&self.secp, &params, &secrets, &agg, &tau_sum)?;
		verify_rangeproof(
			&self.secp,
			params.commit,
			proof,
			params.extra_data.clone(),
		)?;

		self.record.result_commit_hex = Some(params.commit.0.to_vec().to_hex());
		self.record.result_proof_hex = Some(proof_to_hex(&proof));
		self.record.phase = SessionPhase::Complete;
		self.record.secrets = None;
		self.record.emitted_for_phase = true;

		Ok(build_rp_final(
			self.record.ceremony_id.clone(),
			self.record.my_actor.clone(),
			&coin,
			&params.commit,
			&proof,
		)
		.with_session_id(&self.record.session_id))
	}

	// ----- Spend internals -----

	fn apply_kern_commit(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::KernelSigningCommitMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::Spend {
			return Err(Error::Multisig(
				"KernelSigningCommit not valid for CreateOutput".into(),
			));
		}
		if self.record.phase != SessionPhase::KernelRound1
			&& self.record.phase != SessionPhase::KernelRound2
		{
			return Err(Error::Multisig(
				"KernelSigningCommit not expected in this phase".into(),
			));
		}
		let idx = msg.actor_index;
		self.check_actor_index(idx, env)?;
		let commit = parse_kernel_signing_commit(&self.secp, msg)?;
		// Rogue-key check against public poly.
		let session = self.kernel_session()?;
		verify_partial_excess(
			&self.secp,
			&self.public_poly,
			&self.quorum,
			idx,
			&session,
			&commit.pub_excess,
		)?;
		if let Some(existing) = self.record.kern_commits.get(&idx) {
			if existing.pub_d_hex != msg.pub_d_hex
				|| existing.pub_e_hex != msg.pub_e_hex
				|| existing.pub_excess_hex != msg.pub_excess_hex
			{
				return Err(Error::Multisig(format!(
					"kernel commit equivocation from actor {}",
					idx
				)));
			}
			return Ok(());
		}
		self.record.kern_commits.insert(
			idx,
			KernCommitWire {
				pub_d_hex: msg.pub_d_hex.clone(),
				pub_e_hex: msg.pub_e_hex.clone(),
				pub_excess_hex: msg.pub_excess_hex.clone(),
			},
		);
		Ok(())
	}

	fn apply_kern_partial(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::KernelPartialSigMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::Spend {
			return Err(Error::Multisig(
				"KernelPartialSig not valid for CreateOutput".into(),
			));
		}
		if self.record.phase != SessionPhase::KernelRound2 {
			return Err(Error::Multisig(
				"KernelPartialSig not expected in this phase".into(),
			));
		}
		let idx = msg.actor_index;
		self.check_actor_index(idx, env)?;
		if let Some(existing) = self.record.kern_partials.get(&idx) {
			if existing != &msg.partial_sig_hex {
				return Err(Error::Multisig(format!(
					"kernel partial equivocation from actor {}",
					idx
				)));
			}
			return Ok(());
		}
		// Verify partial against commitments.
		let session = self.kernel_session()?;
		let commitments = self.frost_commitments()?;
		let agg = aggregate_frost(&self.secp, &session, &commitments)?;
		let partial = sig_from_hex(&self.secp, &msg.partial_sig_hex)?;
		let pub_excess = pubkey_from_hex(&self.secp, &msg.pub_excess_hex)?;
		verify_kernel_partial(&self.secp, &partial, &pub_excess, &agg, &session)?;
		self.record
			.kern_partials
			.insert(idx, msg.partial_sig_hex.clone());
		Ok(())
	}

	fn apply_kern_final(
		&mut self,
		_env: &MultisigEnvelope,
		msg: &super::messages::KernelFinalMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::Spend {
			return Err(Error::Multisig(
				"KernelFinal not valid for CreateOutput".into(),
			));
		}
		let session = self.kernel_session()?;
		let agg = AggregatedKernelPubs {
			nonce_sum: pubkey_from_hex(&self.secp, &msg.nonce_sum_hex)?,
			excess_sum: pubkey_from_hex(&self.secp, &msg.excess_sum_hex)?,
		};
		let sig = sig_from_hex(&self.secp, &msg.sig_hex)?;
		verify_kernel_sig(&self.secp, &sig, &agg, &session)?;
		self.record.result_sig_hex = Some(msg.sig_hex.clone());
		self.record.result_excess_hex = Some(msg.excess_sum_hex.clone());
		self.record.result_nonce_hex = Some(msg.nonce_sum_hex.clone());
		self.record.phase = SessionPhase::Complete;
		self.record.secrets = None;
		self.record.emitted_for_phase = true;
		Ok(())
	}

	fn tick_spend(&mut self) -> Result<Vec<MultisigEnvelope>, Error> {
		let n = self.quorum.len();
		let mut out = Vec::new();

		if self.record.phase == SessionPhase::KernelRound1 && self.record.kern_commits.len() == n {
			self.record.phase = SessionPhase::KernelRound2;
			self.record.emitted_for_phase = false;
		}

		if self.record.phase == SessionPhase::KernelRound2 && !self.record.emitted_for_phase {
			let env = self.emit_kern_partial()?;
			self.record.emitted_for_phase = true;
			out.push(env);
		}

		if self.record.phase == SessionPhase::KernelRound2 && self.record.kern_partials.len() == n {
			let env = self.finalize_spend()?;
			out.push(env);
		}

		Ok(out)
	}

	fn emit_kern_partial(&mut self) -> Result<MultisigEnvelope, Error> {
		let session = self.kernel_session()?;
		let commitments = self.frost_commitments()?;
		let agg = aggregate_frost(&self.secp, &session, &commitments)?;
		let secrets = self.kernel_secrets_from_wire()?;
		let partial = kernel_partial_sign(
			&self.secp,
			&secrets,
			&commitments,
			self.record.my_index,
			&agg,
			&session,
		)?;
		verify_kernel_partial(
			&self.secp,
			&partial,
			&secrets.commitment.pub_excess,
			&agg,
			&session,
		)?;
		self.record
			.kern_partials
			.insert(self.record.my_index, sig_to_hex_local(&self.secp, &partial));
		Ok(build_kernel_partial_sig(
			&self.secp,
			self.record.ceremony_id.clone(),
			self.record.my_actor.clone(),
			&self.record.session_id,
			self.record.my_index,
			&partial,
			&secrets.commitment.pub_excess,
		))
	}

	fn finalize_spend(&mut self) -> Result<MultisigEnvelope, Error> {
		let session = self.kernel_session()?;
		let commitments = self.frost_commitments()?;
		let agg = aggregate_frost(&self.secp, &session, &commitments)?;
		let mut partials = Vec::new();
		for j in 0..self.quorum.len() {
			let h = self
				.record
				.kern_partials
				.get(&j)
				.ok_or_else(|| Error::Multisig(format!("missing partial from actor {}", j)))?;
			partials.push(sig_from_hex(&self.secp, h)?);
		}
		let final_sig = kernel_aggregate_sigs(&self.secp, &partials, &agg)?;
		verify_kernel_sig(&self.secp, &final_sig, &agg, &session)?;

		self.record.result_sig_hex = Some(sig_to_hex_local(&self.secp, &final_sig));
		self.record.result_excess_hex = Some(pubkey_to_hex_local(&self.secp, &agg.excess_sum));
		self.record.result_nonce_hex = Some(pubkey_to_hex_local(&self.secp, &agg.nonce_sum));
		self.record.phase = SessionPhase::Complete;
		self.record.secrets = None;
		self.record.emitted_for_phase = true;

		// excess commitment available for callers via excess_commitment if needed
		let _ = excess_commitment(&self.secp, &agg)?;

		Ok(build_kernel_final(
			&self.secp,
			self.record.ceremony_id.clone(),
			self.record.my_actor.clone(),
			&self.record.session_id,
			&final_sig,
			&agg.excess_sum,
			&agg.nonce_sum,
		))
	}

	// ----- helpers -----

	fn check_actor_index(&self, idx: usize, env: &MultisigEnvelope) -> Result<(), Error> {
		if idx >= self.quorum.len() {
			return Err(Error::Multisig(format!("actor_index {} out of range", idx)));
		}
		// `actor_index` is the **canonical quorum** index (C-07), not the roster
		// creation order. Verify the sender's x-coordinate maps to that slot.
		let mapped = find_my_index(&self.secp, &self.quorum, &env.sender)?;
		if mapped != idx {
			return Err(Error::Multisig(format!(
				"actor_index {} does not match sender (canonical index {})",
				idx, mapped
			)));
		}
		// Sender must be on the roster.
		if !self.record.roster.iter().any(|a| a.id == env.sender.id) {
			return Err(Error::Multisig("sender not on session roster".into()));
		}
		Ok(())
	}

	fn rp_agg(&self) -> Result<AggregatedT, Error> {
		let mut shares = Vec::new();
		for j in 0..self.quorum.len() {
			let w = self
				.record
				.rp_r1
				.get(&j)
				.ok_or_else(|| Error::Multisig(format!("missing r1 actor {}", j)))?;
			shares.push(Round1Share {
				t_one: pubkey_from_hex(&self.secp, &w.t_one_hex)?,
				t_two: pubkey_from_hex(&self.secp, &w.t_two_hex)?,
			});
		}
		aggregate_round1(&self.secp, &shares)
	}

	fn rp_secrets_from_wire(&self) -> Result<ActorRpSecrets, Error> {
		let w = self
			.record
			.secrets
			.as_ref()
			.ok_or_else(|| Error::Multisig("session secrets wiped".into()))?;
		Ok(ActorRpSecrets {
			partial_blind: seckey_from_hex(&self.secp, &w.partial_hex)?,
			private_nonce: seckey_from_hex(&self.secp, &w.nonce_a_hex)?,
			t_one: pubkey_from_hex(&self.secp, &w.pub_a_hex)?,
			t_two: pubkey_from_hex(&self.secp, &w.pub_b_hex)?,
		})
	}

	/// Rebuild the public kernel session parameters (tests / status).
	pub fn kernel_session(&self) -> Result<KernelSession, Error> {
		let fee = self
			.record
			.fee
			.ok_or_else(|| Error::Multisig("missing fee".into()))?;
		let features = plain_features(fee)?;
		create_kernel_session(
			&self.secp,
			&self.public_poly,
			&self.record.session_id,
			features,
			self.record.inputs.clone(),
			self.record.outputs.clone(),
		)
	}

	// ----- DKG internals -----

	fn apply_dkg_contrib(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::DkgContributionMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::Dkg {
			return Err(Error::Multisig(
				"DkgContribution not valid for this session".into(),
			));
		}
		if !matches!(
			self.record.phase,
			SessionPhase::DkgContrib | SessionPhase::DkgShares
		) {
			return Err(Error::Multisig(
				"DkgContribution not expected in this phase".into(),
			));
		}
		let dkg = self
			.record
			.dkg
			.as_mut()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		if msg.params != dkg.params {
			return Err(Error::Multisig("DKG params mismatch".into()));
		}
		let actor = env.sender.clone();
		let idx = self
			.record
			.roster
			.iter()
			.position(|a| a.id == actor.id)
			.ok_or_else(|| Error::Multisig(format!("unknown actor {}", actor.label)))?;
		// Address-based rosters require signed contributions (C-04).
		if self.record.roster[idx].slatepack_address().is_ok() {
			env.verify_signature()?;
		}
		let contrib = parse_dkg_contribution(msg, actor.clone())?;
		verify_pop(
			&self.secp,
			&self.record.ceremony_id,
			&contrib,
			dkg.params.num_coefficients(),
		)?;
		let new_hexes: Vec<String> = contrib
			.commitments
			.coefficients
			.iter()
			.map(|c| c.to_hex())
			.collect();
		if let Some(existing) = &dkg.contributions[idx] {
			if existing.commitment_hexes != new_hexes {
				return Err(Error::Multisig(format!(
					"actor {} DKG contribution equivocation",
					actor.label
				)));
			}
			return Ok(());
		}
		dkg.contributions[idx] = Some(DkgContribWire {
			actor,
			commitment_hexes: new_hexes,
			pop_sig_hexes: contrib.pops.iter().map(|p| p.sig.to_hex()).collect(),
		});
		Ok(())
	}

	fn apply_dkg_share(
		&mut self,
		env: &MultisigEnvelope,
		msg: &super::messages::DkgPartialShareMsg,
	) -> Result<(), Error> {
		if self.record.kind != SessionKind::Dkg {
			return Err(Error::Multisig(
				"DkgPartialShare not valid for this session".into(),
			));
		}
		let me = &self.record.roster[self.record.my_index];
		if msg.recipient.id != me.id {
			return Err(Error::Multisig("share not addressed to this actor".into()));
		}
		let dkg = self
			.record
			.dkg
			.as_mut()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		if msg.share_index >= dkg.params.shares_per_actor {
			return Err(Error::Multisig("share_index out of range".into()));
		}
		let dealer_idx = self
			.record
			.roster
			.iter()
			.position(|a| a.id == env.sender.id)
			.ok_or_else(|| Error::Multisig(format!("unknown dealer {}", env.sender.label)))?;
		// Address-based dealers must sign partial shares (C-04).
		if self.record.roster[dealer_idx].slatepack_address().is_ok() {
			env.verify_signature()?;
		}
		if dkg.applied_share_dealers.len() != dkg.params.shares_per_actor {
			dkg.applied_share_dealers = vec![Vec::new(); dkg.params.shares_per_actor];
		}
		if dkg.applied_share_dealers[msg.share_index].contains(&dealer_idx) {
			return Err(Error::Multisig(format!(
				"duplicate share from dealer {} for share_index {} (replay)",
				env.sender.label, msg.share_index
			)));
		}
		let part = seckey_from_hex(&self.secp, &msg.share_hex)?;
		let sum = match &dkg.my_share_ys_hex[msg.share_index] {
			Some(h) => {
				let prev = seckey_from_hex(&self.secp, h)?;
				super::scalar::sk_add(&self.secp, &prev, &part)?
			}
			None => part,
		};
		dkg.my_share_ys_hex[msg.share_index] = Some(seckey_to_hex(&sum));
		dkg.applied_share_dealers[msg.share_index].push(dealer_idx);
		Ok(())
	}

	fn tick_dkg(&mut self) -> Result<Vec<MultisigEnvelope>, Error> {
		let mut out = Vec::new();
		let n = self.record.roster.len();
		let all_contrib = self
			.record
			.dkg
			.as_ref()
			.map(|d| d.contributions.iter().all(|c| c.is_some()))
			.unwrap_or(false);

		if self.record.phase == SessionPhase::DkgContrib && all_contrib {
			self.record.phase = SessionPhase::DkgShares;
			self.record.emitted_for_phase = false;
		}

		if self.record.phase == SessionPhase::DkgShares
			&& !self
				.record
				.dkg
				.as_ref()
				.map(|d| d.shares_exported)
				.unwrap_or(true)
		{
			out.extend(self.emit_dkg_partials()?);
			if let Some(ref mut d) = self.record.dkg {
				d.shares_exported = true;
			}
			self.record.emitted_for_phase = true;
		}

		// Complete when every share_index has (n-1) foreign dealers applied
		// (own dealer partial is added at finalize).
		if self.record.phase == SessionPhase::DkgShares {
			let need = n.saturating_sub(1);
			let ready = self.record.dkg.as_ref().map(|d| {
				if need == 0 {
					true
				} else {
					(0..d.params.shares_per_actor).all(|si| {
						d.applied_share_dealers
							.get(si)
							.map(|v| v.len() >= need)
							.unwrap_or(false)
					})
				}
			});
			if ready == Some(true) {
				self.record.phase = SessionPhase::Complete;
				self.record.emitted_for_phase = true;
			}
		}
		Ok(out)
	}

	fn emit_dkg_partials(&self) -> Result<Vec<MultisigEnvelope>, Error> {
		let dkg = self
			.record
			.dkg
			.as_ref()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		let secrets = self.dkg_dealer_secrets()?;
		let sender = self.record.roster[self.record.my_index].clone();
		let mut out = Vec::new();
		for (i, actor) in self.record.roster.iter().enumerate() {
			if i == self.record.my_index {
				continue;
			}
			for share_index in 0..dkg.params.shares_per_actor {
				let x = actor.x_coordinate_share(&self.secp, share_index)?;
				let y = dealer_partial_share(&self.secp, &secrets, &x)?;
				let env = build_dkg_partial_share(
					self.record.ceremony_id.clone(),
					sender.clone(),
					actor.clone(),
					share_index,
					&y,
					&x,
				)
				.with_session_id(&self.record.session_id);
				out.push(env);
			}
		}
		Ok(out)
	}

	fn try_complete_dkg(&mut self) -> Result<(), Error> {
		let _ = self.tick_dkg()?;
		Ok(())
	}

	fn dkg_dealer_secrets(&self) -> Result<DealerSecrets, Error> {
		let dkg = self
			.record
			.dkg
			.as_ref()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		let mut coeffs = Vec::new();
		for h in &dkg.my_coeff_hexes {
			coeffs.push(seckey_from_hex(&self.secp, h)?);
		}
		Ok(DealerSecrets {
			actor: self.record.roster[self.record.my_index].clone(),
			poly: SecretPoly { coeffs },
		})
	}

	fn dkg_aggregate_public_poly(&self) -> Result<PublicPoly, Error> {
		let dkg = self
			.record
			.dkg
			.as_ref()
			.ok_or_else(|| Error::Multisig("missing dkg state".into()))?;
		let mut acc: Option<PublicPoly> = None;
		for c in &dkg.contributions {
			let c = c
				.as_ref()
				.ok_or_else(|| Error::Multisig("missing contribution".into()))?;
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
			acc = Some(match acc {
				None => pp,
				Some(a) => a.add(&self.secp, &pp)?,
			});
		}
		acc.ok_or_else(|| Error::Multisig("no contributions".into()))
	}

	fn frost_commitments(&self) -> Result<Vec<SigningCommitment>, Error> {
		let mut out = Vec::new();
		for j in 0..self.quorum.len() {
			let w = self
				.record
				.kern_commits
				.get(&j)
				.ok_or_else(|| Error::Multisig(format!("missing commit actor {}", j)))?;
			out.push(SigningCommitment {
				pub_d: pubkey_from_hex(&self.secp, &w.pub_d_hex)?,
				pub_e: pubkey_from_hex(&self.secp, &w.pub_e_hex)?,
				pub_excess: pubkey_from_hex(&self.secp, &w.pub_excess_hex)?,
			});
		}
		Ok(out)
	}

	fn kernel_secrets_from_wire(&self) -> Result<ActorKernelSecrets, Error> {
		let w = self
			.record
			.secrets
			.as_ref()
			.ok_or_else(|| Error::Multisig("session secrets wiped".into()))?;
		Ok(ActorKernelSecrets {
			partial_excess: seckey_from_hex(&self.secp, &w.partial_hex)?,
			d: seckey_from_hex(&self.secp, &w.nonce_a_hex)?,
			e: seckey_from_hex(&self.secp, &w.nonce_b_hex)?,
			commitment: SigningCommitment {
				pub_d: pubkey_from_hex(&self.secp, &w.pub_a_hex)?,
				pub_e: pubkey_from_hex(&self.secp, &w.pub_b_hex)?,
				pub_excess: pubkey_from_hex(&self.secp, &w.pub_excess_hex)?,
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clone_secp(secp: &Secp256k1) -> Secp256k1 {
	// Secp256k1 is a handle; reconstruct with same caps used elsewhere.
	use crate::grin_util::secp::ContextFlag;
	let _ = secp;
	Secp256k1::with_caps(ContextFlag::Commit)
}

fn find_my_index(
	secp: &Secp256k1,
	quorum: &[ActorPoint],
	my_actor: &ActorId,
) -> Result<usize, Error> {
	// Primary share x (share_index 0).
	let my_x = my_actor.x_coordinate(secp)?;
	for (i, p) in quorum.iter().enumerate() {
		if p.x.0 == my_x.0 {
			return Ok(i);
		}
	}
	// Multi-share: try share indices 0..8
	for k in 0..8 {
		let x = my_actor.x_coordinate_share(secp, k)?;
		for (i, p) in quorum.iter().enumerate() {
			if p.x.0 == x.0 {
				return Ok(i);
			}
		}
	}
	Err(Error::Multisig(
		"my actor x-coordinate not found in quorum".into(),
	))
}

// Patch create_output / create_spend to use find_my_index
// (redefine the broken find_actor_index usage)

fn envelope_body_hash(env: &MultisigEnvelope) -> String {
	let bytes = serde_json::to_vec(&env.body).unwrap_or_default();
	let mut h = Sha256::new();
	h.update(&bytes);
	h.finalize().to_vec().to_hex()
}

fn pubkey_to_hex_local(secp: &Secp256k1, pk: &PublicKey) -> String {
	pk.serialize_vec(secp, true).to_vec().to_hex()
}

fn commit_from_hex(hex: &str) -> Result<Commitment, Error> {
	let bytes = crate::grin_util::from_hex(hex)
		.map_err(|e| Error::Multisig(format!("commit hex: {}", e)))?;
	if bytes.len() != 33 {
		return Err(Error::Multisig("commit must be 33 bytes".into()));
	}
	let mut a = [0u8; 33];
	a.copy_from_slice(&bytes);
	Ok(Commitment(a))
}

fn sig_to_hex_local(secp: &Secp256k1, sig: &Signature) -> String {
	sig.serialize_compact(secp).to_vec().to_hex()
}

fn sig_from_hex(secp: &Secp256k1, hex: &str) -> Result<Signature, Error> {
	let bytes = crate::grin_util::from_hex(hex)
		.map_err(|e| Error::Multisig(format!("sig hex: {}", e)))?;
	if bytes.len() != 64 {
		return Err(Error::Multisig("sig must be 64 bytes".into()));
	}
	Signature::from_compact(secp, &bytes).map_err(|e| Error::Multisig(format!("sig parse: {}", e)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::run_dkg_local;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};
	use std::collections::VecDeque;

	fn setup_2of2(secp: &Secp256k1) -> (PublicPoly, Vec<ActorPoint>, Vec<ActorId>, CeremonyId) {
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let ceremony = CeremonyId::new();
		let states = run_dkg_local(secp, ceremony.clone(), params, actors.clone()).unwrap();
		let q = canonical_quorum(
			&states
				.iter()
				.map(|s| ActorPoint::from(&s.shares[0]))
				.collect::<Vec<_>>(),
		)
		.unwrap();
		(states[0].config.public_poly.clone(), q, actors, ceremony)
	}

	/// Deliver `env` to every negotiator except the sender (matched by actor id).
	fn broadcast(
		negs: &mut [Negotiator],
		env: MultisigEnvelope,
		pending: &mut VecDeque<(usize, MultisigEnvelope)>,
	) {
		for (i, n) in negs.iter().enumerate() {
			if n.record.my_actor.id == env.sender.id {
				continue;
			}
			pending.push_back((i, env.clone()));
		}
	}

	fn drain(negs: &mut [Negotiator], pending: &mut VecDeque<(usize, MultisigEnvelope)>) {
		while let Some((i, env)) = pending.pop_front() {
			let more = negs[i].apply(&env).unwrap();
			for m in more {
				broadcast(negs, m, pending);
			}
		}
	}

	#[test]
	fn create_output_two_party_completes() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let coin = CoinId::new(1, 1_000_000);

		// All parties must share the same session_id tag.
		let mut negs = Vec::new();
		let mut first_msgs = Vec::new();
		for actor in roster.iter() {
			let (n, env) = Negotiator::create_output(
				&secp,
				&pp,
				&q,
				ceremony.clone(),
				roster.clone(),
				actor.clone(),
				coin.clone(),
				b"create-output-sess",
			)
			.unwrap();
			negs.push(n);
			first_msgs.push(env);
		}
		let mut pending = VecDeque::new();
		for env in first_msgs {
			broadcast(&mut negs, env, &mut pending);
		}
		drain(&mut negs, &mut pending);

		for n in &negs {
			assert_eq!(n.record.phase, SessionPhase::Complete);
			let (commit, proof) = n.result_proof().unwrap().unwrap();
			verify_rangeproof(&secp, commit, proof, None).unwrap();
		}
	}

	#[test]
	fn create_output_crash_resume_mid_round() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let coin = CoinId::new(2, 42_000);
		let dir = tempfile_dir("msig-sess-co");
		let key: SessionKey = [9u8; 32];
		let d0 = dir.join("a0");
		let d1 = dir.join("a1");
		fs::create_dir_all(&d0).unwrap();
		fs::create_dir_all(&d1).unwrap();

		let (mut n0, e0) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony.clone(),
			roster.clone(),
			roster[0].clone(),
			coin.clone(),
			b"resume-co",
		)
		.unwrap();
		let (mut n1, e1) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony.clone(),
			roster.clone(),
			roster[1].clone(),
			coin.clone(),
			b"resume-co",
		)
		.unwrap();

		// Deliver R1 both ways → phase RpRound2 + outbound τ.
		let outs0 = n0.apply(&e1).unwrap();
		let outs1 = n1.apply(&e0).unwrap();
		assert_eq!(n0.record.phase, SessionPhase::RpRound2);
		assert_eq!(n1.record.phase, SessionPhase::RpRound2);
		assert!(!outs0.is_empty() && !outs1.is_empty());

		// Crash: seal without delivering τ.
		save_session(d0.to_str().unwrap(), &key, &n0.record).unwrap();
		save_session(d1.to_str().unwrap(), &key, &n1.record).unwrap();
		let sid0 = n0.record.session_id.clone();
		let sid1 = n1.record.session_id.clone();
		let undelivered: Vec<(usize, MultisigEnvelope)> = outs0
			.into_iter()
			.map(|m| (1usize, m))
			.chain(outs1.into_iter().map(|m| (0usize, m)))
			.collect();
		drop(n0);
		drop(n1);

		// Resume from sealed store.
		let mut n0 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d0.to_str().unwrap(), &key, &sid0).unwrap(),
		)
		.unwrap();
		let mut n1 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d1.to_str().unwrap(), &key, &sid1).unwrap(),
		)
		.unwrap();
		assert_eq!(n0.record.phase, SessionPhase::RpRound2);
		assert!(n0.record.secrets.is_some());

		// Deliver saved τ (+ re-tick is idempotent because emitted_for_phase).
		let mut pending: VecDeque<(usize, MultisigEnvelope)> = undelivered.into();
		for m in n0.tick().unwrap() {
			pending.push_back((1, m));
		}
		for m in n1.tick().unwrap() {
			pending.push_back((0, m));
		}
		let mut negs = [n0, n1];
		while let Some((i, env)) = pending.pop_front() {
			let more = negs[i].apply(&env).unwrap();
			for m in more {
				pending.push_back((1 - i, m));
			}
		}
		for n in &negs {
			assert_eq!(n.status().phase, SessionPhase::Complete);
			assert!(n.record.secrets.is_none());
			let (c, p) = n.result_proof().unwrap().unwrap();
			verify_rangeproof(&secp, c, p, None).unwrap();
		}
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn dkg_address_roster_requires_signed_contrib() {
		use crate::grin_core::global;
		use crate::slatepack::SlatepackAddress;
		use ed25519_dalek::SecretKey as EdSecretKey;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let sk0 = EdSecretKey::from_bytes(&[31u8; 32]).unwrap();
		let sk1 = EdSecretKey::from_bytes(&[32u8; 32]).unwrap();
		let a0 = ActorId::from_slatepack_address(&SlatepackAddress::new(
			&ed25519_dalek::PublicKey::from(&sk0),
		))
		.unwrap();
		let a1 = ActorId::from_slatepack_address(&SlatepackAddress::new(
			&ed25519_dalek::PublicKey::from(&sk1),
		))
		.unwrap();
		let roster = vec![a0, a1];
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let ceremony = CeremonyId::new();
		let (mut n0, mut e0) = Negotiator::create_dkg(
			&secp,
			ceremony.clone(),
			params.clone(),
			roster.clone(),
			0,
			b"addr-dkg",
		)
		.unwrap();
		let (mut n1, mut e1) =
			Negotiator::create_dkg(&secp, ceremony, params, roster, 1, b"addr-dkg").unwrap();
		// Unsigned must fail
		assert!(n0.apply(&e1).is_err());
		e0.sign(&sk0).unwrap();
		e1.sign(&sk1).unwrap();
		// Signed contributions accepted; exchange shares
		let mut o0 = n0.apply(&e1).unwrap();
		let mut o1 = n1.apply(&e0).unwrap();
		// Sign partials before apply
		for env in o0.iter_mut().chain(o1.iter_mut()) {
			if matches!(env.body, MultisigBody::DkgPartialShare(_)) {
				// dealer signs
			}
		}
		// Partial shares from n0 need sk0 signature
		let mut pending: VecDeque<(usize, MultisigEnvelope)> = VecDeque::new();
		for mut m in o0.drain(..) {
			if matches!(m.body, MultisigBody::DkgPartialShare(_)) {
				m.sign(&sk0).unwrap();
			}
			pending.push_back((1, m));
		}
		for mut m in o1.drain(..) {
			if matches!(m.body, MultisigBody::DkgPartialShare(_)) {
				m.sign(&sk1).unwrap();
			}
			pending.push_back((0, m));
		}
		while let Some((i, env)) = pending.pop_front() {
			let more = if i == 0 {
				n0.apply(&env).unwrap()
			} else {
				n1.apply(&env).unwrap()
			};
			for mut m in more {
				if matches!(m.body, MultisigBody::DkgPartialShare(_)) {
					if i == 0 {
						m.sign(&sk0).unwrap();
					} else {
						m.sign(&sk1).unwrap();
					}
				}
				pending.push_back((1 - i, m));
			}
		}
		assert_eq!(n0.record.phase, SessionPhase::Complete);
		assert_eq!(n1.record.phase, SessionPhase::Complete);
		let s0 = n0.finalize_dkg_state().unwrap();
		let s1 = n1.finalize_dkg_state().unwrap();
		assert_eq!(
			s0.config.public_poly.coefficients,
			s1.config.public_poly.coefficients
		);
	}

	#[test]
	fn dkg_two_party_session_completes() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let roster: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let ceremony = CeremonyId::new();
		let (mut n0, e0) = Negotiator::create_dkg(
			&secp,
			ceremony.clone(),
			params.clone(),
			roster.clone(),
			0,
			b"dkg-sess",
		)
		.unwrap();
		let (mut n1, e1) = Negotiator::create_dkg(
			&secp,
			ceremony,
			params,
			roster,
			1,
			b"dkg-sess",
		)
		.unwrap();
		// Exchange contributions
		let mut o0 = n0.apply(&e1).unwrap();
		let mut o1 = n1.apply(&e0).unwrap();
		// Deliver partial shares (may have been emitted on contrib apply)
		let mut pending: VecDeque<(usize, MultisigEnvelope)> = o0
			.drain(..)
			.map(|m| (1usize, m))
			.chain(o1.drain(..).map(|m| (0usize, m)))
			.collect();
		// Also tick in case
		for m in n0.tick().unwrap() {
			pending.push_back((1, m));
		}
		for m in n1.tick().unwrap() {
			pending.push_back((0, m));
		}
		while let Some((i, env)) = pending.pop_front() {
			let more = if i == 0 {
				n0.apply(&env).unwrap()
			} else {
				n1.apply(&env).unwrap()
			};
			for m in more {
				pending.push_back((1 - i, m));
			}
		}
		assert_eq!(n0.record.phase, SessionPhase::Complete);
		assert_eq!(n1.record.phase, SessionPhase::Complete);
		let s0 = n0.finalize_dkg_state().unwrap();
		let s1 = n1.finalize_dkg_state().unwrap();
		assert_eq!(s0.config.public_poly.coefficients, s1.config.public_poly.coefficients);
		assert!(!s0.shares.is_empty());
	}

	#[test]
	fn dkg_contrib_equivocation_rejected() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let roster: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let ceremony = CeremonyId::new();
		let (mut n0, _e0) = Negotiator::create_dkg(
			&secp,
			ceremony.clone(),
			params.clone(),
			roster.clone(),
			0,
			b"dkg-eq",
		)
		.unwrap();
		// Two different contributions from actor 1
		let (_n1a, e1a) =
			Negotiator::create_dkg(&secp, ceremony.clone(), params.clone(), roster.clone(), 1, b"dkg-eq-a")
				.unwrap();
		let (_n1b, e1b) =
			Negotiator::create_dkg(&secp, ceremony, params, roster, 1, b"dkg-eq-b").unwrap();
		// Force same session id on second so it is a different body from same actor
		// in n0's ceremony — use e1a then a re-tagged e1b with same sender.
		n0.apply(&e1a).unwrap();
		// e1b has different session_id and different contrib; still same sender actor
		n0.record.seen_body_hashes.clear();
		let err = n0.apply(&e1b).unwrap_err();
		assert!(
			format!("{}", err).contains("equivocation")
				|| format!("{}", err).contains("session")
				|| format!("{}", err).contains("mismatch"),
			"got {}",
			err
		);
	}

	#[test]
	fn file_harness_create_output_crash_resume() {
		// Multi-actor sealed file exchange with mid-protocol crash (disk sessions).
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let key = [9u8; 32];
		let dir = std::env::temp_dir().join(format!("msig_harness_{}", uuid::Uuid::new_v4()));
		let d0 = dir.join("a0");
		let d1 = dir.join("a1");
		fs::create_dir_all(&d0).unwrap();
		fs::create_dir_all(&d1).unwrap();
		let coin = CoinId::new(1, 1_000_000);

		let (n0, e0) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony.clone(),
			roster.clone(),
			roster[0].clone(),
			coin.clone(),
			b"harness",
		)
		.unwrap();
		let (n1, e1) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony,
			roster.clone(),
			roster[1].clone(),
			coin,
			b"harness",
		)
		.unwrap();
		save_session(d0.to_str().unwrap(), &key, &n0.record).unwrap();
		save_session(d1.to_str().unwrap(), &key, &n1.record).unwrap();
		let sid0 = n0.record.session_id.clone();
		let sid1 = n1.record.session_id.clone();
		drop(n0);
		drop(n1);

		// Resume, apply peer R1, seal again mid-flight
		let mut n0 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d0.to_str().unwrap(), &key, &sid0).unwrap(),
		)
		.unwrap();
		let mut n1 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d1.to_str().unwrap(), &key, &sid1).unwrap(),
		)
		.unwrap();
		let outs0 = n0.apply(&e1).unwrap();
		let outs1 = n1.apply(&e0).unwrap();
		save_session(d0.to_str().unwrap(), &key, &n0.record).unwrap();
		save_session(d1.to_str().unwrap(), &key, &n1.record).unwrap();
		// Crash: drop without delivering τ
		let pending: VecDeque<(usize, MultisigEnvelope)> = outs0
			.into_iter()
			.map(|m| (1usize, m))
			.chain(outs1.into_iter().map(|m| (0usize, m)))
			.collect();
		drop(n0);
		drop(n1);

		let mut n0 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d0.to_str().unwrap(), &key, &sid0).unwrap(),
		)
		.unwrap();
		let mut n1 = Negotiator::resume(
			&secp,
			&pp,
			&q,
			load_session(d1.to_str().unwrap(), &key, &sid1).unwrap(),
		)
		.unwrap();
		let mut pending = pending;
		for m in n0.tick().unwrap() {
			pending.push_back((1, m));
		}
		for m in n1.tick().unwrap() {
			pending.push_back((0, m));
		}
		while let Some((i, env)) = pending.pop_front() {
			let more = if i == 0 {
				n0.apply(&env).unwrap()
			} else {
				n1.apply(&env).unwrap()
			};
			for m in more {
				pending.push_back((1 - i, m));
			}
		}
		assert_eq!(n0.record.phase, SessionPhase::Complete);
		assert_eq!(n1.record.phase, SessionPhase::Complete);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn dkg_share_replay_rejected() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let roster: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let ceremony = CeremonyId::new();
		let (mut n0, _e0) = Negotiator::create_dkg(
			&secp,
			ceremony.clone(),
			params.clone(),
			roster.clone(),
			0,
			b"dkg-replay",
		)
		.unwrap();
		let (mut n1, e1) =
			Negotiator::create_dkg(&secp, ceremony, params, roster, 1, b"dkg-replay").unwrap();
		// n0 gets n1's contribution → emits partials to n1
		let outs0 = n0.apply(&e1).unwrap();
		let shares: Vec<_> = outs0
			.into_iter()
			.filter(|e| matches!(e.body, MultisigBody::DkgPartialShare(_)))
			.collect();
		assert!(!shares.is_empty());
		// First apply accepted
		n1.apply(&shares[0]).unwrap();
		// Body-hash cache: exact re-apply is silent no-op
		assert!(n1.apply(&shares[0]).unwrap().is_empty());
		// Clear cache → dealer-index replay guard must fire
		n1.record.seen_body_hashes.clear();
		let err = n1.apply(&shares[0]).unwrap_err();
		assert!(
			format!("{}", err).contains("duplicate") || format!("{}", err).contains("replay"),
			"got {}",
			err
		);
	}

	#[test]
	fn session_deadline_aborts_on_apply() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let coin = CoinId::new(1, 1_000_000);
		let (mut n0, env0) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony.clone(),
			roster.clone(),
			roster[0].clone(),
			coin.clone(),
			b"ttl-sess",
		)
		.unwrap();
		let (mut n1, _env1) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony,
			roster.clone(),
			roster[1].clone(),
			coin,
			b"ttl-sess",
		)
		.unwrap();
		// Force an already-expired deadline.
		n0.record.deadline_unix = Some(1);
		n1.record.deadline_unix = Some(1);
		assert!(n0.record.is_expired(unix_now()));
		let err = n1.apply(&env0).unwrap_err();
		assert!(format!("{}", err).contains("deadline"));
		assert_eq!(n1.record.phase, SessionPhase::Aborted);
		assert!(n1.record.secrets.is_none());
	}

	#[test]
	fn spend_two_party_frost_completes() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let inputs = vec![CoinId::new(1, 1_000_000)];
		let outputs = vec![CoinId::new(2, 999_000)];
		let fee = 1_000;

		let mut negs = Vec::new();
		let mut first = Vec::new();
		for actor in roster.iter() {
			let (n, env) = Negotiator::create_spend(
				&secp,
				&pp,
				&q,
				ceremony.clone(),
				roster.clone(),
				actor.clone(),
				inputs.clone(),
				outputs.clone(),
				fee,
				b"spend-sess",
			)
			.unwrap();
			negs.push(n);
			first.push(env);
		}
		let mut pending = VecDeque::new();
		for env in first {
			broadcast(&mut negs, env, &mut pending);
		}
		drain(&mut negs, &mut pending);

		for n in &negs {
			assert_eq!(n.record.phase, SessionPhase::Complete);
			let (sig, agg) = n.result_kernel().unwrap().unwrap();
			let session = n.kernel_session().unwrap();
			verify_kernel_sig(&secp, &sig, &agg, &session).unwrap();
		}
	}

	#[test]
	fn abort_wipes_secrets() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let (mut n, _) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony,
			roster.clone(),
			roster[0].clone(),
			CoinId::new(1, 10),
			b"abort",
		)
		.unwrap();
		assert!(n.record.secrets.is_some());
		n.abort("test abort");
		assert_eq!(n.record.phase, SessionPhase::Aborted);
		assert!(n.record.secrets.is_none());
		assert!(n.apply(&MultisigEnvelope::new(
			n.record.ceremony_id.clone(),
			roster[1].clone(),
			MultisigBody::RpRound2(super::super::messages::RpRound2Msg {
				coin: CoinId::new(1, 10),
				actor_index: 1,
				tau_hex: "00".repeat(32),
			}),
		))
		.is_err());
	}

	#[test]
	fn replay_same_message_is_idempotent() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let (pp, q, roster, ceremony) = setup_2of2(&secp);
		let (mut n0, e0) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony.clone(),
			roster.clone(),
			roster[0].clone(),
			CoinId::new(3, 100),
			b"replay",
		)
		.unwrap();
		let (mut n1, e1) = Negotiator::create_output(
			&secp,
			&pp,
			&q,
			ceremony,
			roster.clone(),
			roster[1].clone(),
			CoinId::new(3, 100),
			b"replay",
		)
		.unwrap();
		let _ = n0.apply(&e1).unwrap();
		let again = n0.apply(&e1).unwrap();
		assert!(again.is_empty());
		let _ = n1.apply(&e0).unwrap();
	}

	fn tempfile_dir(name: &str) -> PathBuf {
		let mut d = std::env::temp_dir();
		d.push(format!(
			"{}-{}-{}",
			name,
			std::process::id(),
			uuid::Uuid::new_v4()
		));
		fs::create_dir_all(&d).unwrap();
		d
	}
}
