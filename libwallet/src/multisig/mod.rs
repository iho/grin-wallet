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

//! Threshold multisig wallet primitives (RFC-0023 style).
//!
//! ## Status
//!
//! Experimental cryptographic foundation only. Not production-ready for real funds.
//! Incorporates fixes from the design review:
//! - Polynomial **degree = threshold − 1** (not degree M with M shares).
//! - Honest documentation that the public view seed does **not** hide the
//!   polynomial from an adversary who learns full coin blinds.
//! - PoP-bound DKG commitments and domain-separated hash-to-scalar.
//!
//! ## Modules
//!
//! - [`types`] — ceremony / actor / wallet state
//! - [`scalar`] — hash-to-scalar and field helpers
//! - [`poly`] — secret & public polynomial evaluation
//! - [`dkg`] — joint Feldman DKG
//! - [`share`] — Lagrange partial keys, add-actor masking
//! - [`coin`] — coin blinding-factor derivation
//! - [`rangeproof`] — multiparty Bulletproof (T1/T2/τ path)
//! - [`kernel`] — multiparty threshold kernel signing (FROST)
//! - [`messages`] — slatepack wire format for multi-round protocols
//! - [`tx`] — end-to-end multisig transaction build (local quorum)
//! - [`store`] — LMDB / AEAD persistence helpers
//! - [`session`] — durable multiparty negotiator (WS4)

pub mod coin;
pub mod dkg;
pub mod kernel;
pub mod messages;
pub mod ops;
pub mod poly;
pub mod rangeproof;
pub mod scalar;
pub mod session;
pub mod share;
pub mod store;
pub mod tx;
pub mod types;
pub mod utxo;

pub use coin::{coin_blinding_factor, coin_commitment_components, coin_x, CoinId};
pub use dkg::{
	aggregate_public_poly, assemble_share, dealer_partial_share, generate_dealer_contribution,
	run_dkg_local, verify_pop, DealerContribution, DealerSecrets, PopProof,
};
pub use kernel::{
	aggregate_frost, binding_factor, create_cross_epoch_kernel_session, create_kernel_session,
	expected_pub_excess_for_actor, kernel_aggregate_sigs, kernel_partial_sign, kernel_round1,
	partial_excess_cross_epoch, partial_excess_for_actor, plain_features,
	run_kernel_sign_local, run_kernel_sign_local_cross_epoch, verify_kernel_partial,
	verify_kernel_sig, verify_partial_excess, ActorKernelSecrets, AggregatedKernelPubs,
	KernelSession, SigningCommitment,
};
pub use messages::{
	build_dkg_contribution, build_dkg_partial_share, build_kernel_final, build_kernel_partial_sig,
	build_kernel_signing_commit, build_rp_final, build_rp_round1, build_rp_round2,
	parse_dkg_contribution, parse_kernel_signing_commit, parse_rp_round1, MultisigBody,
	MultisigEnvelope, MAX_ENVELOPE_JSON_BYTES, MAX_LIST_LEN, MULTISIG_MSG_VERSION,
	MULTISIG_PAYLOAD_MAGIC,
};
pub use ops::{
	allocate_coin, assemble_tx_from_spend_session, clear_pending, delete_ceremony,
	derive_session_key, dkg_export_shares, dkg_finalize, dkg_import_contrib, dkg_import_share,
	dkg_start, expire_stale_sessions, export_state_json, export_state_sealed, get_state,
	import_state_json, import_state_sealed, init_local_sim, list_ceremonies, list_utxos,
	load_pending, plan_epoch_sweep, read_encrypted_share_file, read_envelope_file,
	recognize_and_register, refresh_multisig_utxos, register_utxo, scan_ceremony_utxos,
	select_spendable_utxos, session_abort, session_apply, session_apply_raw,
	session_create_output, session_create_output_raw, session_create_spend,
	session_apply_raw_with_key, session_apply_with_key, session_create_spend_raw,
	session_dkg_create_raw, session_dkg_export_shares_armored, session_dkg_finalize, session_list,
	session_status, set_utxo_status, wallet_data_dir, write_envelope_file, CeremonySummary,
	EpochSweepPlan, MultisigRefreshResult, MultisigSessionApplyResult,
	MultisigSessionStartResult, PendingDkg, PendingKey,
};
pub use poly::{eval_public_poly, eval_secret_poly, verify_share, PublicPoly, SecretPoly};
pub use rangeproof::{
	aggregate_round1, aggregate_tau, aggregate_tau_verified, coin_pedersen_commit,
	coin_pedersen_commit_public, derive_tau_challenges, expected_pub_blind_for_actor,
	partial_blind_for_actor, quorum_partial_blinds, rangeproof_finalize, rangeproof_params_for_coin,
	rangeproof_round1, rangeproof_round2, rewind_rangeproof, run_rangeproof_local, verify_rangeproof,
	verify_tau_share, ActorRpSecrets, AggregatedT, RangeproofParams, Round1Share, TauChallenges,
};
pub use scalar::{hash_to_scalar, sk_add, sk_from_bytes, sk_mul, sk_neg, sk_sub, HashDomain};
pub use session::{
	delete_session, ensure_sessions_dir, list_session_ids, load_session, quorum_points_from_state,
	save_session, unix_now, Negotiator, SessionKind, SessionKey, SessionPhase, SessionRecord,
	SessionStatus, DEFAULT_SESSION_TTL_SECS, MAX_ENVELOPE_BYTES, MAX_SESSION_ACTORS,
};
// MultisigSessionStartResult / ApplyResult exported via ops above
pub use share::{
	canonical_quorum, delta_mask, lagrange_coefficient, partial_key_at, quorum_transcript,
	reconstruct_secret_at, unmask_sum, ActorPoint,
};
pub use store::{
	ceremony_id_from_db_key, decrypt_from_storage, derive_pending_key, derive_state_key,
	encrypt_for_storage, multisig_db_key, open_pending, seal_pending, EncryptedMultisigState,
	MULTISIG_PREFIX, PENDING_KEY_SIZE, STATE_KEY_SIZE, STATE_SEAL_MAGIC, STATE_SEAL_VERSION,
};
pub use tx::{
	assemble_from_kernel_results, build_cross_epoch_spend, build_epoch_sweep_local,
	build_multisig_spend, build_self_send, create_multisig_output, demo_fund_and_spend,
	quorum_from_state, quorum_from_states, run_demo_tx, tx_from_hex, tx_to_hex,
	MultisigDemoTxResult, MultisigOutput, MultisigSpendResult,
};
pub use types::{
	ActorId, CeremonyId, MultisigConfig, MultisigWalletState, SecretShare, ThresholdParams,
	MIN_SHARES_FOR_DEGREE,
};
pub use utxo::{
	multisig_coin_meta_db_key, multisig_utxo_db_key, next_coin_number_from_list, parse_utxo_db_key,
	try_recognize_output, utxo_from_create_output, verify_utxo_commit, CoinNumberMeta, MultisigUtxo,
	MultisigUtxoStatus, RecognizedMultisigOutput, MULTISIG_COIN_META_PREFIX, MULTISIG_UTXO_PREFIX,
};
