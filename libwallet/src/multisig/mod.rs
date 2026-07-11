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
//! - [`kernel`] — multiparty threshold kernel signing (additive aggsig)
//! - [`messages`] — slatepack wire format for multi-round protocols
//! - [`tx`] — end-to-end multisig transaction build (local quorum)
//! - [`store`] — LMDB persistence helpers

pub mod coin;
pub mod dkg;
pub mod kernel;
pub mod messages;
pub mod ops;
pub mod poly;
pub mod rangeproof;
pub mod scalar;
pub mod share;
pub mod store;
pub mod tx;
pub mod types;

pub use coin::{coin_blinding_factor, coin_commitment_components, coin_x, CoinId};
pub use dkg::{
	aggregate_public_poly, assemble_share, dealer_partial_share, generate_dealer_contribution,
	run_dkg_local, verify_pop, DealerContribution, DealerSecrets, PopProof,
};
pub use kernel::{
	aggregate_kernel_pubs, commit_nonce, create_kernel_session, kernel_aggregate_sigs,
	kernel_partial_sign, kernel_prepare, partial_excess_for_actor, plain_features,
	run_kernel_sign_local, verify_kernel_partial, verify_kernel_sig, verify_nonce_commitment,
	ActorKernelSecrets, AggregatedKernelPubs, KernelSession, NonceCommitment, NonceReveal,
};
pub use messages::{
	build_dkg_contribution, build_dkg_partial_share, build_kernel_final, build_kernel_nonce_commit,
	build_kernel_nonce_reveal, build_kernel_partial_sig, build_rp_final, build_rp_round1,
	build_rp_round2, parse_dkg_contribution, parse_kernel_nonce_reveal, parse_rp_round1,
	MultisigBody, MultisigEnvelope, MULTISIG_MSG_VERSION, MULTISIG_PAYLOAD_MAGIC,
};
pub use ops::{
	clear_pending, delete_ceremony, dkg_export_shares, dkg_finalize, dkg_import_contrib,
	dkg_import_share, dkg_start, export_state_json, get_state, import_state_json, init_local_sim,
	list_ceremonies, load_pending, read_envelope_file, wallet_data_dir, write_envelope_file,
	CeremonySummary, PendingDkg, PendingKey,
};
pub use poly::{eval_public_poly, eval_secret_poly, verify_share, PublicPoly, SecretPoly};
pub use rangeproof::{
	aggregate_round1, aggregate_tau, coin_pedersen_commit, quorum_partial_blinds,
	rangeproof_finalize, rangeproof_params_for_coin, rangeproof_round1, rangeproof_round2,
	rewind_rangeproof, run_rangeproof_local, verify_rangeproof, ActorRpSecrets, AggregatedT,
	RangeproofParams, Round1Share,
};
pub use scalar::{hash_to_scalar, sk_add, sk_from_bytes, sk_mul, sk_neg, sk_sub, HashDomain};
pub use share::{
	add_actor_masked_share, delta_mask, lagrange_coefficient, partial_key_at, reconstruct_secret_at,
	unmask_sum, ActorPoint,
};
pub use store::{
	ceremony_id_from_db_key, decrypt_from_storage, derive_pending_key, encrypt_for_storage,
	multisig_db_key, open_pending, seal_pending, MULTISIG_PREFIX, PENDING_KEY_SIZE,
};
pub use tx::{
	build_multisig_spend, build_self_send, create_multisig_output, demo_fund_and_spend,
	quorum_from_state, quorum_from_states, run_demo_tx, tx_from_hex, tx_to_hex, MultisigDemoTxResult,
	MultisigOutput, MultisigSpendResult,
};
pub use types::{
	ActorId, CeremonyId, MultisigConfig, MultisigWalletState, SecretShare, ThresholdParams,
	MIN_SHARES_FOR_DEGREE,
};
