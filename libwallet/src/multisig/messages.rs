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

//! Slatepack-carried message types for multisig multi-round protocols.
//!
//! Messages are JSON envelopes (versioned) that can be placed in a
//! [`Slatepack`](crate::Slatepack) `payload`. Sensitive bodies (DKG share
//! delivery, partial secrets) **must** be age-encrypted via
//! `Slatepack::try_encrypt_payload` to the intended recipients.
//!
//! ## Message families
//!
//! | Family | Rounds |
//! | --- | --- |
//! | DKG | contribution broadcast, private partial share |
//! | Rangeproof | round1 T1/T2, round2 τ, finalize proof |
//! | Kernel | FROST signing commit (D,E,X), partial sig, final sig |
//!
//! **Status:** experimental wire format; version field allows future changes.

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::{Secp256k1, Signature};
use crate::grin_util::{from_hex, ToHex};
use crate::slatepack::{Slatepack, SlatepackAddress, SlatepackArmor, SlatepackBin};
use crate::Error;
use ed25519_dalek::{
	ExpandedSecretKey, PublicKey as EdPublicKey, SecretKey as EdSecretKey, Signature as EdSignature,
};
use grin_wallet_util::byte_ser;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::coin::CoinId;
use super::dkg::{DealerContribution, PopProof};
use super::kernel::SigningCommitment;
use super::poly::PublicPoly;
use super::rangeproof::{AggregatedT, RangeproofParams, Round1Share};
use super::types::{ActorId, CeremonyId, ThresholdParams};

/// Wire format version for multisig envelopes.
pub const MULTISIG_MSG_VERSION: u16 = 1;

/// Magic prefix for payload identification (ASCII "GMS1").
pub const MULTISIG_PAYLOAD_MAGIC: &[u8] = b"GMS1";

/// Top-level envelope carried in a Slatepack payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MultisigEnvelope {
	/// Format version.
	pub version: u16,
	/// Ceremony / epoch this message belongs to.
	pub ceremony_id: Uuid,
	/// Optional session id (kernel / rangeproof session tag), hex.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub session_id_hex: Option<String>,
	/// Sender actor identity.
	pub sender: ActorId,
	/// Message body.
	pub body: MultisigBody,
	/// Detached ed25519 signature (hex) by the sender's Slatepack key over the
	/// canonical signing transcript (C-04). Absent on unsigned/dev envelopes.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub sig_hex: Option<String>,
}

/// All supported multisig message bodies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum MultisigBody {
	// --- DKG ---
	/// Public DKG contribution (commitments + PoP). Broadcast.
	DkgContribution(DkgContributionMsg),
	/// Private partial share for one recipient. **Encrypt to recipient.**
	DkgPartialShare(DkgPartialShareMsg),
	/// Announces joint public poly after all contributions (optional convening).
	DkgPublicPoly(DkgPublicPolyMsg),

	// --- Rangeproof ---
	/// Round-1 T1/T2 contribution.
	RpRound1(RpRound1Msg),
	/// Round-2 partial τ.
	RpRound2(RpRound2Msg),
	/// Finalized rangeproof (any actor may broadcast).
	RpFinal(RpFinalMsg),

	// --- Kernel (FROST) ---
	/// Round-1 FROST signing commitment `(D_j, E_j, X_j)`.
	KernelSigningCommit(KernelSigningCommitMsg),
	/// Partial kernel signature.
	KernelPartialSig(KernelPartialSigMsg),
	/// Aggregated final kernel signature.
	KernelFinal(KernelFinalMsg),
}

// ---------------------------------------------------------------------------
// DKG messages
// ---------------------------------------------------------------------------

/// Broadcast dealer contribution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DkgContributionMsg {
	/// Threshold parameters for this ceremony.
	pub params: ThresholdParams,
	/// Coefficient commitments (compressed pubkeys as hex).
	pub commitment_hexes: Vec<String>,
	/// PoP signatures (DER hex) aligned with coefficients.
	pub pop_sig_hexes: Vec<String>,
}

/// Encrypted-to-recipient partial evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DkgPartialShareMsg {
	/// Intended recipient actor id.
	pub recipient: ActorId,
	/// Share index for multi-share actors.
	pub share_index: usize,
	/// Secret share scalar (hex). Sensitive.
	pub share_hex: String,
	/// x-coordinate for this share (hex), for verification.
	pub x_hex: String,
}

/// Optional convening message with joint public polynomial.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DkgPublicPolyMsg {
	/// Public coefficients as compressed hex.
	pub coefficient_hexes: Vec<String>,
	/// Full actor roster.
	pub actors: Vec<ActorId>,
	/// Threshold params.
	pub params: ThresholdParams,
}

// ---------------------------------------------------------------------------
// Rangeproof messages
// ---------------------------------------------------------------------------

/// Shared RP session description (without secrets).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpSessionWire {
	/// Coin being proven.
	pub coin: CoinId,
	/// Full commitment hex.
	pub commit_hex: String,
	/// Shared BP nonce hex (view-derived; not the private nonce).
	pub shared_nonce_hex: String,
	/// Optional extra data hex.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub extra_data_hex: Option<String>,
}

/// Round 1: T1/T2.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpRound1Msg {
	/// Session descriptor.
	pub session: RpSessionWire,
	/// Actor index in the signing quorum (0..M-1).
	pub actor_index: usize,
	/// T1 compressed hex.
	pub t_one_hex: String,
	/// T2 compressed hex.
	pub t_two_hex: String,
}

/// Round 2: partial τ.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpRound2Msg {
	/// Session coin number (bind).
	pub coin: CoinId,
	/// Actor index.
	pub actor_index: usize,
	/// Partial τ_x hex.
	pub tau_hex: String,
}

/// Final rangeproof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpFinalMsg {
	/// Coin.
	pub coin: CoinId,
	/// Commitment hex.
	pub commit_hex: String,
	/// Rangeproof hex.
	pub proof_hex: String,
}

// ---------------------------------------------------------------------------
// Kernel messages
// ---------------------------------------------------------------------------

/// Kernel session wire (public fields).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KernelSessionWire {
	/// Session id hex.
	pub session_id_hex: String,
	/// Fee (nanogrins).
	pub fee: u64,
	/// Offset scalar hex.
	pub offset_hex: String,
	/// Inputs.
	pub inputs: Vec<CoinId>,
	/// Outputs.
	pub outputs: Vec<CoinId>,
}

/// FROST round-1 signing commitment (broadcast).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KernelSigningCommitMsg {
	/// Session (public fields; first committer typically embeds full session).
	pub session: KernelSessionWire,
	/// Actor index in the ordered quorum.
	pub actor_index: usize,
	/// Hiding-nonce commitment `D_j` hex (compressed pubkey).
	pub pub_d_hex: String,
	/// Binding-nonce commitment `E_j` hex (compressed pubkey).
	pub pub_e_hex: String,
	/// Public partial excess `X_j` hex (compressed pubkey).
	pub pub_excess_hex: String,
}

/// Partial signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KernelPartialSigMsg {
	/// Session id hex.
	pub session_id_hex: String,
	/// Actor index.
	pub actor_index: usize,
	/// Partial signature compact hex (64 bytes).
	pub partial_sig_hex: String,
	/// Public partial excess (for verify).
	pub pub_excess_hex: String,
}

/// Final aggregated signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KernelFinalMsg {
	/// Session id hex.
	pub session_id_hex: String,
	/// Final signature compact hex.
	pub sig_hex: String,
	/// Aggregated excess pubkey hex.
	pub excess_sum_hex: String,
	/// Aggregated nonce pubkey hex.
	pub nonce_sum_hex: String,
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode a public key as compressed hex.
pub fn pubkey_to_hex(secp: &Secp256k1, pk: &PublicKey) -> String {
	pk.serialize_vec(secp, true).to_vec().to_hex()
}

/// Decode a compressed public key from hex.
pub fn pubkey_from_hex(secp: &Secp256k1, hex: &str) -> Result<PublicKey, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("pubkey hex: {}", e)))?;
	Ok(PublicKey::from_slice(secp, &bytes)?)
}

/// Encode a secret key as hex.
pub fn seckey_to_hex(sk: &SecretKey) -> String {
	sk.0.to_vec().to_hex()
}

/// Decode a secret key from hex.
pub fn seckey_from_hex(secp: &Secp256k1, hex: &str) -> Result<SecretKey, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("seckey hex: {}", e)))?;
	Ok(SecretKey::from_slice(secp, &bytes)?)
}

/// Encode a commitment as hex.
pub fn commit_to_hex(c: &Commitment) -> String {
	c.0.to_vec().to_hex()
}

/// Decode a commitment from hex.
pub fn commit_from_hex(hex: &str) -> Result<Commitment, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("commit hex: {}", e)))?;
	if bytes.len() != 33 {
		return Err(Error::Multisig("commit must be 33 bytes".into()));
	}
	let mut a = [0u8; 33];
	a.copy_from_slice(&bytes);
	Ok(Commitment(a))
}

/// Encode signature as compact hex.
pub fn sig_to_hex(secp: &Secp256k1, sig: &Signature) -> String {
	sig.serialize_compact(secp).to_vec().to_hex()
}

/// Decode compact signature from hex.
pub fn sig_from_hex(secp: &Secp256k1, hex: &str) -> Result<Signature, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("sig hex: {}", e)))?;
	Ok(Signature::from_compact(secp, &bytes)?)
}

/// Encode rangeproof as hex.
pub fn proof_to_hex(proof: &RangeProof) -> String {
	proof.to_hex()
}

/// Decode rangeproof from hex.
pub fn proof_from_hex(hex: &str) -> Result<RangeProof, Error> {
	let bytes = from_hex(hex).map_err(|e| Error::Multisig(format!("proof hex: {}", e)))?;
	// RangeProof from bytes - check API
	Ok(RangeProof {
		proof: {
			let mut p = [0u8; crate::grin_util::secp::constants::MAX_PROOF_SIZE];
			if bytes.len() > p.len() {
				return Err(Error::Multisig("proof too large".into()));
			}
			p[..bytes.len()].copy_from_slice(&bytes);
			p
		},
		plen: bytes.len(),
	})
}

// ---------------------------------------------------------------------------
// Builders from crypto types
// ---------------------------------------------------------------------------

impl MultisigEnvelope {
	/// New envelope shell.
	pub fn new(ceremony_id: CeremonyId, sender: ActorId, body: MultisigBody) -> Self {
		Self {
			version: MULTISIG_MSG_VERSION,
			ceremony_id: ceremony_id.0,
			session_id_hex: None,
			sender,
			body,
			sig_hex: None,
		}
	}

	/// Canonical bytes signed/verified for authentication (C-04).
	///
	/// Binds magic, version, ceremony id, session id, the declared sender
	/// identity, and a hash of the body — everything except the signature
	/// itself. A signature is therefore useless if replayed under a different
	/// ceremony/session/sender or with a mutated body.
	fn signing_transcript(&self) -> Result<Vec<u8>, Error> {
		let mut m = Vec::new();
		m.extend_from_slice(MULTISIG_PAYLOAD_MAGIC);
		m.extend_from_slice(&self.version.to_be_bytes());
		m.extend_from_slice(self.ceremony_id.as_bytes());
		m.extend_from_slice(b"|sid|");
		match &self.session_id_hex {
			Some(s) => m.extend_from_slice(s.as_bytes()),
			None => m.extend_from_slice(b"none"),
		}
		m.extend_from_slice(b"|snd|");
		m.extend_from_slice(&self.sender.id);
		m.extend_from_slice(b"|body|");
		let body_json = serde_json::to_vec(&self.body)
			.map_err(|e| Error::Multisig(format!("sign body encode: {}", e)))?;
		let mut h = Sha256::new();
		h.update(&body_json);
		m.extend_from_slice(&h.finalize());
		Ok(m)
	}

	/// Sign this envelope with the sender's ed25519 Slatepack secret key.
	///
	/// The key must correspond to the declared `sender` address (checked), so a
	/// wallet cannot sign as an actor it is not.
	pub fn sign(&mut self, sec_key: &EdSecretKey) -> Result<(), Error> {
		let sender_addr = self.sender.slatepack_address()?;
		let public: EdPublicKey = sec_key.into();
		if public.to_bytes() != sender_addr.pub_key.to_bytes() {
			return Err(Error::Multisig(
				"signing key does not match sender address".into(),
			));
		}
		let msg = self.signing_transcript()?;
		let expanded = ExpandedSecretKey::from(sec_key);
		let sig = expanded.sign(&msg, &public);
		self.sig_hex = Some(sig.to_bytes().to_vec().to_hex());
		Ok(())
	}

	/// Verify the sender's signature over the transcript.
	///
	/// Errors if the envelope is unsigned, the sender is not address-backed, or
	/// the signature does not verify under the sender's Slatepack public key.
	pub fn verify_signature(&self) -> Result<(), Error> {
		let sig_hex = self
			.sig_hex
			.as_ref()
			.ok_or_else(|| Error::Multisig("envelope is not signed".into()))?;
		let sender_addr = self.sender.slatepack_address()?;
		let sig_bytes =
			from_hex(sig_hex).map_err(|e| Error::Multisig(format!("sig hex: {}", e)))?;
		let sig = EdSignature::from_bytes(&sig_bytes)
			.map_err(|e| Error::Multisig(format!("bad signature encoding: {}", e)))?;
		let msg = self.signing_transcript()?;
		sender_addr
			.pub_key
			.verify_strict(&msg, &sig)
			.map_err(|e| Error::Multisig(format!("signature verification failed: {}", e)))
	}

	/// True if the sender identity is address-backed (i.e. authentication is
	/// expected). Index-based dev actors cannot be authenticated.
	pub fn sender_is_addressable(&self) -> bool {
		self.sender.slatepack_address().is_ok()
	}

	/// Attach session id bytes.
	pub fn with_session_id(mut self, session_id: &[u8]) -> Self {
		self.session_id_hex = Some(session_id.to_hex());
		self
	}

	/// Serialize to JSON bytes with magic prefix.
	pub fn to_payload_bytes(&self) -> Result<Vec<u8>, Error> {
		let json = serde_json::to_vec(self)
			.map_err(|e| Error::Multisig(format!("envelope json: {}", e)))?;
		let mut out = MULTISIG_PAYLOAD_MAGIC.to_vec();
		out.extend_from_slice(&json);
		Ok(out)
	}

	/// Parse from payload bytes (magic + JSON).
	pub fn from_payload_bytes(data: &[u8]) -> Result<Self, Error> {
		if data.len() < MULTISIG_PAYLOAD_MAGIC.len() {
			return Err(Error::Multisig("payload too short".into()));
		}
		if &data[..MULTISIG_PAYLOAD_MAGIC.len()] != MULTISIG_PAYLOAD_MAGIC {
			return Err(Error::Multisig("missing GMS1 magic".into()));
		}
		let env: MultisigEnvelope =
			serde_json::from_slice(&data[MULTISIG_PAYLOAD_MAGIC.len()..])
				.map_err(|e| Error::Multisig(format!("envelope parse: {}", e)))?;
		if env.version != MULTISIG_MSG_VERSION {
			return Err(Error::Multisig(format!(
				"unsupported multisig msg version {}",
				env.version
			)));
		}
		Ok(env)
	}

	/// Wrap in a plaintext Slatepack (optionally encrypt afterward).
	pub fn to_slatepack(&self, sender: Option<SlatepackAddress>) -> Result<Slatepack, Error> {
		let mut sp = Slatepack::default();
		sp.sender = sender;
		sp.payload = self.to_payload_bytes()?;
		sp.mode = 0;
		Ok(sp)
	}

	/// Create slatepack and age-encrypt to recipients.
	pub fn to_encrypted_slatepack(
		&self,
		sender: Option<SlatepackAddress>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<Slatepack, Error> {
		let mut sp = self.to_slatepack(sender)?;
		sp.try_encrypt_payload(recipients)?;
		Ok(sp)
	}

	/// Extract envelope from a slatepack (decrypt if needed).
	pub fn from_slatepack(
		slatepack: &mut Slatepack,
		dec_key: Option<&EdSecretKey>,
	) -> Result<Self, Error> {
		slatepack.try_decrypt_payload(dec_key)?;
		Self::from_payload_bytes(&slatepack.payload)
	}

	/// Decode an armored Slatepack string and extract the envelope, decrypting
	/// the payload with `dec_key` when it was encrypted to a recipient.
	///
	/// This is the counterpart to [`MultisigEnvelope::to_armored_string`] and is
	/// how an actor ingests an age-encrypted DKG share delivery (C-02).
	pub fn from_armored_string(
		armored: &str,
		dec_key: Option<&EdSecretKey>,
	) -> Result<Self, Error> {
		let raw = SlatepackArmor::decode(armored.trim().as_bytes())
			.map_err(|e| Error::Multisig(format!("slatepack de-armor: {}", e)))?;
		let mut sp: Slatepack = byte_ser::from_bytes::<SlatepackBin>(&raw)
			.map_err(|e| Error::Multisig(format!("slatepack deser: {:?}", e)))?
			.0;
		Self::from_slatepack(&mut sp, dec_key)
	}

	/// Armor as slatepack string (optionally encrypted first).
	pub fn to_armored_string(
		&self,
		sender: Option<SlatepackAddress>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		let sp = if recipients.is_empty() {
			self.to_slatepack(sender)?
		} else {
			self.to_encrypted_slatepack(sender, recipients)?
		};
		SlatepackArmor::encode(&sp).map_err(|e| Error::Multisig(format!("armor: {}", e)))
	}
}

// ---------------------------------------------------------------------------
// Builders: crypto types → wire messages
// ---------------------------------------------------------------------------

/// Build DKG contribution message from a dealer contribution.
pub fn build_dkg_contribution(
	secp: &Secp256k1,
	ceremony_id: CeremonyId,
	sender: ActorId,
	params: ThresholdParams,
	contrib: &DealerContribution,
) -> Result<MultisigEnvelope, Error> {
	if contrib.commitments.coefficients.len() != contrib.pops.len() {
		return Err(Error::Multisig("contrib pops/coeffs mismatch".into()));
	}
	let commitment_hexes = contrib
		.commitments
		.coefficients
		.iter()
		.map(|c| c.to_hex())
		.collect();
	let pop_sig_hexes = contrib.pops.iter().map(|p| p.sig.to_hex()).collect();
	let _ = secp; // reserved for future PoP re-encode
	Ok(MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::DkgContribution(DkgContributionMsg {
			params,
			commitment_hexes,
			pop_sig_hexes,
		}),
	))
}

/// Parse dealer contribution from a DKG contribution message.
pub fn parse_dkg_contribution(
	msg: &DkgContributionMsg,
	actor: ActorId,
) -> Result<DealerContribution, Error> {
	if msg.commitment_hexes.len() != msg.pop_sig_hexes.len() {
		return Err(Error::Multisig("pops/coeffs length mismatch".into()));
	}
	let coefficients: Result<Vec<Vec<u8>>, Error> = msg
		.commitment_hexes
		.iter()
		.map(|h| from_hex(h).map_err(|e| Error::Multisig(format!("commit hex: {}", e))))
		.collect();
	let coefficients = coefficients?;
	let pops: Result<Vec<PopProof>, Error> = msg
		.pop_sig_hexes
		.iter()
		.enumerate()
		.map(|(i, h)| {
			let sig = from_hex(h).map_err(|e| Error::Multisig(format!("pop hex: {}", e)))?;
			Ok(PopProof {
				coeff_index: i,
				sig,
			})
		})
		.collect();
	Ok(DealerContribution {
		actor,
		commitments: PublicPoly { coefficients },
		pops: pops?,
	})
}

/// Build private DKG partial share message (encrypt to recipient!).
pub fn build_dkg_partial_share(
	ceremony_id: CeremonyId,
	sender: ActorId,
	recipient: ActorId,
	share_index: usize,
	share: &SecretKey,
	x: &SecretKey,
) -> MultisigEnvelope {
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::DkgPartialShare(DkgPartialShareMsg {
			recipient,
			share_index,
			share_hex: seckey_to_hex(share),
			x_hex: seckey_to_hex(x),
		}),
	)
}

/// Build rangeproof round-1 message.
pub fn build_rp_round1(
	secp: &Secp256k1,
	ceremony_id: CeremonyId,
	sender: ActorId,
	session: &RangeproofParams,
	coin: &CoinId,
	actor_index: usize,
	share: &Round1Share,
) -> MultisigEnvelope {
	let wire = RpSessionWire {
		coin: coin.clone(),
		commit_hex: commit_to_hex(&session.commit),
		shared_nonce_hex: seckey_to_hex(&session.shared_nonce),
		extra_data_hex: session.extra_data.as_ref().map(|d| d.to_hex()),
	};
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::RpRound1(RpRound1Msg {
			session: wire,
			actor_index,
			t_one_hex: pubkey_to_hex(secp, &share.t_one),
			t_two_hex: pubkey_to_hex(secp, &share.t_two),
		}),
	)
}

/// Parse round-1 share from wire.
pub fn parse_rp_round1(secp: &Secp256k1, msg: &RpRound1Msg) -> Result<Round1Share, Error> {
	Ok(Round1Share {
		t_one: pubkey_from_hex(secp, &msg.t_one_hex)?,
		t_two: pubkey_from_hex(secp, &msg.t_two_hex)?,
	})
}

/// Build rangeproof round-2 message.
pub fn build_rp_round2(
	ceremony_id: CeremonyId,
	sender: ActorId,
	coin: &CoinId,
	actor_index: usize,
	tau: &SecretKey,
) -> MultisigEnvelope {
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::RpRound2(RpRound2Msg {
			coin: coin.clone(),
			actor_index,
			tau_hex: seckey_to_hex(tau),
		}),
	)
}

/// Build final rangeproof message.
pub fn build_rp_final(
	ceremony_id: CeremonyId,
	sender: ActorId,
	coin: &CoinId,
	commit: &Commitment,
	proof: &RangeProof,
) -> MultisigEnvelope {
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::RpFinal(RpFinalMsg {
			coin: coin.clone(),
			commit_hex: commit_to_hex(commit),
			proof_hex: proof_to_hex(proof),
		}),
	)
}

/// Build FROST round-1 signing-commitment message.
pub fn build_kernel_signing_commit(
	secp: &Secp256k1,
	ceremony_id: CeremonyId,
	sender: ActorId,
	session: &super::kernel::KernelSession,
	actor_index: usize,
	commitment: &SigningCommitment,
) -> MultisigEnvelope {
	let wire = KernelSessionWire {
		session_id_hex: session.session_id.to_hex(),
		fee: match &session.features {
			crate::grin_core::core::transaction::KernelFeatures::Plain { fee } => u64::from(*fee),
			_ => 0,
		},
		offset_hex: seckey_to_hex(&session.offset),
		inputs: session.inputs.clone(),
		outputs: session.outputs.clone(),
	};
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::KernelSigningCommit(KernelSigningCommitMsg {
			session: wire,
			actor_index,
			pub_d_hex: pubkey_to_hex(secp, &commitment.pub_d),
			pub_e_hex: pubkey_to_hex(secp, &commitment.pub_e),
			pub_excess_hex: pubkey_to_hex(secp, &commitment.pub_excess),
		}),
	)
	.with_session_id(&session.session_id)
}

/// Parse FROST signing commitment from wire.
pub fn parse_kernel_signing_commit(
	secp: &Secp256k1,
	msg: &KernelSigningCommitMsg,
) -> Result<SigningCommitment, Error> {
	Ok(SigningCommitment {
		pub_d: pubkey_from_hex(secp, &msg.pub_d_hex)?,
		pub_e: pubkey_from_hex(secp, &msg.pub_e_hex)?,
		pub_excess: pubkey_from_hex(secp, &msg.pub_excess_hex)?,
	})
}

/// Build partial kernel sig message.
pub fn build_kernel_partial_sig(
	secp: &Secp256k1,
	ceremony_id: CeremonyId,
	sender: ActorId,
	session_id: &[u8],
	actor_index: usize,
	partial_sig: &Signature,
	pub_excess: &PublicKey,
) -> MultisigEnvelope {
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::KernelPartialSig(KernelPartialSigMsg {
			session_id_hex: session_id.to_hex(),
			actor_index,
			partial_sig_hex: sig_to_hex(secp, partial_sig),
			pub_excess_hex: pubkey_to_hex(secp, pub_excess),
		}),
	)
	.with_session_id(session_id)
}

/// Build final kernel sig message.
pub fn build_kernel_final(
	secp: &Secp256k1,
	ceremony_id: CeremonyId,
	sender: ActorId,
	session_id: &[u8],
	sig: &Signature,
	excess_sum: &PublicKey,
	nonce_sum: &PublicKey,
) -> MultisigEnvelope {
	MultisigEnvelope::new(
		ceremony_id,
		sender,
		MultisigBody::KernelFinal(KernelFinalMsg {
			session_id_hex: session_id.to_hex(),
			sig_hex: sig_to_hex(secp, sig),
			excess_sum_hex: pubkey_to_hex(secp, excess_sum),
			nonce_sum_hex: pubkey_to_hex(secp, nonce_sum),
		}),
	)
	.with_session_id(session_id)
}

/// Aggregate T1/T2 from several RpRound1 messages (ordered by actor_index).
pub fn aggregate_rp_round1_msgs(
	secp: &Secp256k1,
	msgs: &[RpRound1Msg],
) -> Result<AggregatedT, Error> {
	let mut ordered = msgs.to_vec();
	ordered.sort_by_key(|m| m.actor_index);
	let mut shares = Vec::new();
	for m in &ordered {
		shares.push(parse_rp_round1(secp, m)?);
	}
	super::rangeproof::aggregate_round1(secp, &shares)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_util::secp::{ContextFlag, Secp256k1};
	use crate::multisig::dkg::{generate_dealer_contribution, run_dkg_local};
	use crate::multisig::kernel::run_kernel_sign_local;
	use crate::multisig::rangeproof::run_rangeproof_local;
	use crate::multisig::share::ActorPoint;
	use crate::multisig::types::{ActorId, CeremonyId, ThresholdParams};

	#[test]
	fn envelope_json_roundtrip() {
		let env = MultisigEnvelope::new(
			CeremonyId::new(),
			ActorId::from_index(0),
			MultisigBody::DkgPublicPoly(DkgPublicPolyMsg {
				coefficient_hexes: vec!["aabb".into()],
				actors: vec![ActorId::from_index(0)],
				params: ThresholdParams::new_allow_low_degree(1, 1).unwrap(),
			}),
		);
		let bytes = env.to_payload_bytes().unwrap();
		assert!(bytes.starts_with(MULTISIG_PAYLOAD_MAGIC));
		let back = MultisigEnvelope::from_payload_bytes(&bytes).unwrap();
		assert_eq!(env, back);
	}

	#[test]
	fn dkg_contribution_wire_roundtrip() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let ceremony = CeremonyId::new();
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let actor = ActorId::from_index(0);
		let (_sec, contrib) =
			generate_dealer_contribution(&secp, &ceremony, actor.clone(), &params).unwrap();
		let env = build_dkg_contribution(&secp, ceremony, actor.clone(), params, &contrib).unwrap();
		let bytes = env.to_payload_bytes().unwrap();
		let parsed = MultisigEnvelope::from_payload_bytes(&bytes).unwrap();
		match parsed.body {
			MultisigBody::DkgContribution(m) => {
				let back = parse_dkg_contribution(&m, actor).unwrap();
				assert_eq!(
					back.commitments.coefficients,
					contrib.commitments.coefficients
				);
				assert_eq!(back.pops.len(), contrib.pops.len());
			}
			_ => panic!("wrong body"),
		}
	}

	#[test]
	fn rp_and_kernel_messages_roundtrip() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
		let ceremony = CeremonyId::new();
		let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
		let states = run_dkg_local(&secp, ceremony.clone(), params, actors).unwrap();
		let q: Vec<ActorPoint> = states
			.iter()
			.map(|s| ActorPoint::from(&s.shares[0]))
			.collect();
		let coin = CoinId::new(1, 1000);
		let (proof, rp_params) =
			run_rangeproof_local(&secp, &states[0].config.public_poly, &q, &coin, None).unwrap();

		// RP final message
		let env = build_rp_final(
			ceremony.clone(),
			ActorId::from_index(0),
			&coin,
			&rp_params.commit,
			&proof,
		);
		let back = MultisigEnvelope::from_payload_bytes(&env.to_payload_bytes().unwrap()).unwrap();
		match back.body {
			MultisigBody::RpFinal(m) => {
				assert_eq!(m.coin, coin);
				let p = proof_from_hex(&m.proof_hex).unwrap();
				assert_eq!(p.plen, proof.plen);
			}
			_ => panic!("expected RpFinal"),
		}

		// Kernel sign + final message
		let (sig, agg, session) = run_kernel_sign_local(
			&secp,
			&states[0].config.public_poly,
			&q,
			b"wire-sess",
			10,
			vec![CoinId::new(1, 1000)],
			vec![CoinId::new(2, 990)],
		)
		.unwrap();
		let env = build_kernel_final(
			&secp,
			ceremony,
			ActorId::from_index(0),
			&session.session_id,
			&sig,
			&agg.excess_sum,
			&agg.nonce_sum,
		);
		let back = MultisigEnvelope::from_payload_bytes(&env.to_payload_bytes().unwrap()).unwrap();
		match back.body {
			MultisigBody::KernelFinal(m) => {
				let s = sig_from_hex(&secp, &m.sig_hex).unwrap();
				// compact form should match
				assert_eq!(
					s.serialize_compact(&secp).to_vec(),
					sig.serialize_compact(&secp).to_vec()
				);
			}
			_ => panic!("expected KernelFinal"),
		}
	}

	#[test]
	fn slatepack_plaintext_roundtrip() {
		let env = MultisigEnvelope::new(
			CeremonyId::new(),
			ActorId::from_index(1),
			MultisigBody::KernelFinal(KernelFinalMsg {
				session_id_hex: "aa".into(),
				sig_hex: "bb".into(),
				excess_sum_hex: "cc".into(),
				nonce_sum_hex: "dd".into(),
			}),
		);
		let mut sp = env.to_slatepack(None).unwrap();
		let back = MultisigEnvelope::from_slatepack(&mut sp, None).unwrap();
		assert_eq!(env.ceremony_id, back.ceremony_id);
		assert_eq!(env.sender, back.sender);
	}

	#[test]
	fn encrypted_slatepack_roundtrip() {
		crate::grin_core::global::set_local_chain_type(
			crate::grin_core::global::ChainTypes::AutomatedTesting,
		);
		let recipient = crate::SlatepackAddress::random();
		// Need matching ed secret for decrypt — random address has no secret.
		// Just verify encrypt succeeds and mode flips.
		let env = MultisigEnvelope::new(
			CeremonyId::new(),
			ActorId::from_index(0),
			MultisigBody::DkgPartialShare(DkgPartialShareMsg {
				recipient: ActorId::from_index(1),
				share_index: 0,
				share_hex: "01".repeat(32),
				x_hex: "02".repeat(32),
			}),
		);
		let sp = env.to_encrypted_slatepack(None, vec![recipient]).unwrap();
		assert_eq!(sp.mode, 1);
		assert!(!sp.payload.is_empty());
	}

	#[test]
	fn encrypted_share_export_import_roundtrip() {
		use crate::grin_core::global;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		// Recipient address with a known ed25519 secret key (so we can decrypt).
		let seed = [7u8; 32];
		let rcpt_sk = EdSecretKey::from_bytes(&seed).unwrap();
		let rcpt_pk = ed25519_dalek::PublicKey::from(&rcpt_sk);
		let rcpt_addr = crate::SlatepackAddress::new(&rcpt_pk);
		let recipient = ActorId::from_slatepack_address(&rcpt_addr).unwrap();

		// Address-backed id resolves back to the same address.
		assert_eq!(
			String::try_from(&recipient.slatepack_address().unwrap()).unwrap(),
			String::try_from(&rcpt_addr).unwrap()
		);

		let share_hex = "ab".repeat(32);
		let env = MultisigEnvelope::new(
			CeremonyId::new(),
			ActorId::from_index(0),
			MultisigBody::DkgPartialShare(DkgPartialShareMsg {
				recipient: recipient.clone(),
				share_index: 0,
				share_hex: share_hex.clone(),
				x_hex: "02".repeat(32),
			}),
		);

		let armored = env
			.to_armored_string(None, vec![rcpt_addr.clone()])
			.unwrap();
		// The armored blob must not leak the plaintext share scalar.
		assert!(!armored.contains(&share_hex));

		// Recipient decrypts and recovers the exact share.
		let back = MultisigEnvelope::from_armored_string(&armored, Some(&rcpt_sk)).unwrap();
		match back.body {
			MultisigBody::DkgPartialShare(m) => {
				assert_eq!(m.share_hex, share_hex);
				assert_eq!(m.recipient.id, recipient.id);
			}
			_ => panic!("expected DkgPartialShare"),
		}
	}

	#[test]
	fn index_actor_has_no_slatepack_address() {
		// Index-based (dev) actors cannot be encrypted-share recipients.
		assert!(ActorId::from_index(3).slatepack_address().is_err());
	}

	fn addr_and_key(seed: u8) -> (crate::SlatepackAddress, EdSecretKey, ActorId) {
		let sk = EdSecretKey::from_bytes(&[seed; 32]).unwrap();
		let pk = ed25519_dalek::PublicKey::from(&sk);
		let addr = crate::SlatepackAddress::new(&pk);
		let actor = ActorId::from_slatepack_address(&addr).unwrap();
		(addr, sk, actor)
	}

	fn sample_body() -> MultisigBody {
		MultisigBody::KernelFinal(KernelFinalMsg {
			session_id_hex: "aa".into(),
			sig_hex: "bb".into(),
			excess_sum_hex: "cc".into(),
			nonce_sum_hex: "dd".into(),
		})
	}

	#[test]
	fn envelope_sign_and_verify() {
		use crate::grin_core::global;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (_addr, sk, sender) = addr_and_key(9);

		let mut env = MultisigEnvelope::new(CeremonyId::new(), sender.clone(), sample_body());
		assert!(env.verify_signature().is_err(), "unsigned must not verify");
		env.sign(&sk).unwrap();
		env.verify_signature().unwrap();
	}

	#[test]
	fn envelope_tamper_rejected() {
		use crate::grin_core::global;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (_addr, sk, sender) = addr_and_key(11);
		let mut env = MultisigEnvelope::new(CeremonyId::new(), sender, sample_body());
		env.sign(&sk).unwrap();

		// Mutating the body invalidates the signature.
		let mut tampered = env.clone();
		if let MultisigBody::KernelFinal(ref mut m) = tampered.body {
			m.excess_sum_hex = "ee".into();
		}
		assert!(tampered.verify_signature().is_err());
	}

	#[test]
	fn envelope_wrong_sender_rejected() {
		use crate::grin_core::global;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (_a1, sk1, sender1) = addr_and_key(12);
		let (_a2, sk2, sender2) = addr_and_key(13);

		let mut env = MultisigEnvelope::new(CeremonyId::new(), sender1, sample_body());
		env.sign(&sk1).unwrap();

		// Re-labelling the envelope as a different sender must not verify.
		let mut impostor = env.clone();
		impostor.sender = sender2;
		assert!(impostor.verify_signature().is_err());

		// Signing as an actor you are not (key != declared sender address) fails.
		let mut env2 = MultisigEnvelope::new(CeremonyId::new(), env.sender.clone(), sample_body());
		assert!(env2.sign(&sk2).is_err());
	}
}
