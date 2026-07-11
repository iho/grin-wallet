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

//! LMDB persistence tests for multisig wallet state.

use grin_core::global;
use grin_core::global::ChainTypes;
use grin_keychain::{ExtKeychain, Keychain};
use grin_util::secp::{ContextFlag, Secp256k1};
use grin_wallet_impls::test_framework::LocalWalletClient;
use grin_wallet_impls::LMDBBackend;
use grin_wallet_libwallet::multisig::{
	run_dkg_local, ActorId, CeremonyId, ThresholdParams,
};
use grin_wallet_libwallet::WalletBackend;
use std::fs;
use std::sync::mpsc;

fn setup_dir(dir: &str) {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let path = std::path::Path::new(dir);
	if path.exists() {
		let _ = remove_dir_all::remove_dir_all(dir);
	}
	fs::create_dir_all(dir).unwrap();
}

#[test]
fn multisig_state_lmdb_roundtrip() {
	let test_dir = "target/tmp/multisig_store_test";
	setup_dir(test_dir);

	// Dummy client (not used for DB ops)
	let (tx, _rx) = mpsc::channel();
	let client = LocalWalletClient::new("msig", tx);

	let mut wallet: LMDBBackend<'_, LocalWalletClient, ExtKeychain> =
		LMDBBackend::new(test_dir, client).unwrap();

	let keychain = ExtKeychain::from_random_seed(true).unwrap();
	wallet
		.set_keychain(Box::new(keychain), false, true)
		.unwrap();

	// Build a small multisig state
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let params = ThresholdParams::new_allow_low_degree(2, 2).unwrap();
	let ceremony = CeremonyId::new();
	let actors: Vec<_> = (0..2).map(ActorId::from_index).collect();
	let states = run_dkg_local(&secp, ceremony.clone(), params, actors).unwrap();
	let state = states[0].clone();
	let original_y = state.shares[0].y.0;

	// Save
	{
		let mut batch = wallet.batch(None).unwrap();
		batch.save_multisig_state(&state).unwrap();
		batch.commit().unwrap();
	}

	// List
	let ids = wallet.list_multisig_ceremonies().unwrap();
	assert_eq!(ids.len(), 1);
	assert_eq!(ids[0].0, ceremony.0);

	// Load and compare
	let loaded = wallet.get_multisig_state(None, &ceremony).unwrap();
	assert_eq!(loaded.shares[0].y.0, original_y);
	assert_eq!(loaded.config.ceremony_id.0, ceremony.0);
	assert_eq!(loaded.my_actor.label, state.my_actor.label);
	assert_eq!(
		loaded.config.public_poly.coefficients,
		state.config.public_poly.coefficients
	);

	// Delete
	{
		let mut batch = wallet.batch(None).unwrap();
		batch.delete_multisig_state(&ceremony).unwrap();
		batch.commit().unwrap();
	}
	assert!(wallet.list_multisig_ceremonies().unwrap().is_empty());
	assert!(wallet.get_multisig_state(None, &ceremony).is_err());

	let _ = remove_dir_all::remove_dir_all(test_dir);
}
